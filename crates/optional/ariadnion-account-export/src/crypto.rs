// crates/optional/ariadnion-account-export/src/crypto.rs - Authenticated account export sealing.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1

use super::{
    AccountExportPlan, ExportError, ExportErrorCode, ExportFields, ExportManifest, ExportRecord,
    ExportSignature, MAX_CIPHERTEXT_BYTES, MAX_EXPORT_RECORDS, OpaqueCiphertext, SealedExport,
    UtcSeconds, error, manifest_digest_from_parts, validate_records,
};
use ariadnion_account_domain::{
    AccountConfigVersion, AccountId, AccountVersion, SecretPath, SecretProvider, SecretPurpose,
    SecretRef, SecretVersion,
};
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use std::fmt::{self, Debug, Formatter};
use zeroize::Zeroizing;

const ENCRYPTION_KEY_BYTES: usize = 32;
const SIGNING_KEY_BYTES: usize = 32;
const VERIFICATION_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const AEAD_TAG_BYTES: usize = 16;
const ENVELOPE_MAGIC: &[u8; 8] = b"ARDEXP01";
const PAYLOAD_MAGIC: &[u8; 8] = b"ARDPAY01";
const FORMAT_VERSION: u16 = 1;
const ENVELOPE_PREFIX_BYTES: usize = ENVELOPE_MAGIC.len() + 2 + NONCE_BYTES;
const MAX_PLAINTEXT_BYTES: usize = MAX_CIPHERTEXT_BYTES - ENVELOPE_PREFIX_BYTES - AEAD_TAG_BYTES;
const MAX_MANIFEST_BYTES: usize = 1 << 10;
const SIGNATURE_DOMAIN: &[u8] = b"ariadnion-account-export-signature-v1\0";
const AAD_DOMAIN: &[u8] = b"ariadnion-account-export-aad-v1\0";

/// A dedicated XChaCha20-Poly1305 encryption key that is cleared on drop.
pub struct ExportEncryptionKey(Zeroizing<[u8; ENCRYPTION_KEY_BYTES]>);

impl ExportEncryptionKey {
    /// Takes ownership of a 256-bit encryption key.
    ///
    /// The caller must provision this key independently from every signing key.
    /// The owned bytes are cleared when this value is dropped.
    #[must_use]
    pub fn new(bytes: [u8; ENCRYPTION_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; ENCRYPTION_KEY_BYTES] {
        &self.0
    }
}

impl Debug for ExportEncryptionKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportEncryptionKey(<redacted>)")
    }
}

/// A dedicated Ed25519 signing key seed that is cleared on drop.
pub struct ExportSigningKey(Zeroizing<[u8; SIGNING_KEY_BYTES]>);

impl ExportSigningKey {
    /// Takes ownership of a 256-bit Ed25519 signing key seed.
    ///
    /// The caller must provision this key independently from every encryption
    /// key. The owned seed is cleared when this value is dropped.
    #[must_use]
    pub fn new(bytes: [u8; SIGNING_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Derives the public verification key.
    #[must_use]
    pub fn verification_key(&self) -> ExportVerificationKey {
        let signing_key = SigningKey::from_bytes(&self.0);
        ExportVerificationKey(signing_key.verifying_key())
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
}

impl Debug for ExportSigningKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportSigningKey(<redacted>)")
    }
}

/// An Ed25519 public key accepted by an account export verifier.
#[derive(Clone, Eq, PartialEq)]
pub struct ExportVerificationKey(VerifyingKey);

impl ExportVerificationKey {
    /// Parses a compressed Ed25519 verification key.
    ///
    /// # Errors
    /// Returns [`ExportErrorCode::InvalidArgument`] when the bytes do not
    /// represent a valid Ed25519 verification key.
    pub fn from_bytes(bytes: [u8; VERIFICATION_KEY_BYTES]) -> Result<Self, ExportError> {
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| error(ExportErrorCode::InvalidArgument))
    }

    /// Returns the compressed public-key bytes for durable key distribution.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; VERIFICATION_KEY_BYTES] {
        self.0.to_bytes()
    }
}

impl Debug for ExportVerificationKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportVerificationKey(<opaque>)")
    }
}

/// A caller-supplied 192-bit nonce for one export encryption operation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ExportNonce([u8; NONCE_BYTES]);

impl ExportNonce {
    /// Creates an explicit XChaCha20-Poly1305 nonce.
    ///
    /// The caller must guarantee that this nonce is never reused with the same
    /// [`ExportEncryptionKey`]. Use an injected operating-system entropy adapter
    /// or a durably allocated counter; this crate never substitutes a fixed nonce.
    #[must_use]
    pub const fn new(bytes: [u8; NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes for persistence alongside the ciphertext.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; NONCE_BYTES] {
        self.0
    }
}

impl Debug for ExportNonce {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportNonce(<opaque>)")
    }
}

/// SHA-256 digest of the canonical plaintext payload.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CanonicalPayloadDigest([u8; 32]);

impl CanonicalPayloadDigest {
    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Debug for CanonicalPayloadDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalPayloadDigest(<sha256>)")
    }
}

/// A verified manifest and its canonical account records.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedExport {
    manifest: ExportManifest,
    records: Box<[ExportRecord]>,
}

impl VerifiedExport {
    /// Returns the authenticated manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ExportManifest {
        &self.manifest
    }

    /// Returns canonical records sorted by account identity.
    #[must_use]
    pub fn records(&self) -> &[ExportRecord] {
        &self.records
    }
}

impl Debug for VerifiedExport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedExport")
            .field("manifest", &self.manifest)
            .field("record_count", &self.records.len())
            .finish()
    }
}

/// Concrete memory-bounded XChaCha20-Poly1305 and Ed25519 export sealer.
pub struct AccountExportSealer<'key> {
    encryption_key: &'key ExportEncryptionKey,
    signing_key: &'key ExportSigningKey,
}

impl<'key> AccountExportSealer<'key> {
    /// Borrows dedicated encryption and signing keys for sealing operations.
    #[must_use]
    pub const fn new(
        encryption_key: &'key ExportEncryptionKey,
        signing_key: &'key ExportSigningKey,
    ) -> Self {
        Self {
            encryption_key,
            signing_key,
        }
    }

    /// Encrypts and signs a validated export plan.
    ///
    /// The format version, complete manifest, manifest digest, nonce, and
    /// ciphertext are authenticated. The caller owns nonce uniqueness. Peak
    /// memory remains bounded by two copies of [`MAX_CIPHERTEXT_BYTES`], and all
    /// temporary plaintext storage is cleared on drop.
    ///
    /// # Errors
    /// Returns a stable error when the authorization expired, canonical payload
    /// exceeds its binary bound, or encryption fails.
    pub fn seal(
        &self,
        plan: AccountExportPlan,
        nonce: ExportNonce,
        now: UtcSeconds,
    ) -> Result<SealedExport, ExportError> {
        ensure_not_expired(plan.manifest(), now)?;
        let mut payload = Zeroizing::new(serialize_records(plan.records())?);
        let associated_data = associated_data(plan.manifest())?;
        encrypt_payload(self.encryption_key, nonce, &associated_data, &mut payload)?;
        let ciphertext = build_envelope(nonce, &payload)?;
        let signature = sign_artifact(self.signing_key, plan.manifest(), &ciphertext)?;
        Ok(SealedExport {
            manifest: plan.manifest().clone(),
            ciphertext,
            signature,
        })
    }

    /// Computes a digest of the exact canonical payload before encryption.
    ///
    /// This method exposes only a digest, not plaintext record bytes. It is
    /// suitable for deterministic idempotency and format compatibility checks.
    ///
    /// # Errors
    /// Returns [`ExportErrorCode::ArtifactTooLarge`] when serialization exceeds
    /// the fixed plaintext bound.
    pub fn canonical_payload_digest(
        plan: &AccountExportPlan,
    ) -> Result<CanonicalPayloadDigest, ExportError> {
        let payload = Zeroizing::new(serialize_records(plan.records())?);
        Ok(CanonicalPayloadDigest(Sha256::digest(&payload).into()))
    }
}

impl Debug for AccountExportSealer<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountExportSealer(<redacted-keys>)")
    }
}

/// Concrete signature-verifying and authenticated-decryption boundary.
pub struct AccountExportVerifier<'key> {
    encryption_key: &'key ExportEncryptionKey,
    verification_key: &'key ExportVerificationKey,
}

impl<'key> AccountExportVerifier<'key> {
    /// Borrows the encryption and public verification keys for opening exports.
    #[must_use]
    pub const fn new(
        encryption_key: &'key ExportEncryptionKey,
        verification_key: &'key ExportVerificationKey,
    ) -> Self {
        Self {
            encryption_key,
            verification_key,
        }
    }

    /// Verifies, decrypts, parses, and revalidates one export artifact.
    ///
    /// Signature verification occurs before decryption. The decrypted records
    /// must be in canonical order, match the authenticated manifest count and
    /// digest, and satisfy the original field and tenant constraints.
    ///
    /// # Errors
    /// Returns a stable redacted error for expiry, invalid signatures,
    /// authentication failures, malformed payloads, or manifest mismatches.
    pub fn verify_and_open(
        &self,
        sealed: &SealedExport,
        now: UtcSeconds,
    ) -> Result<VerifiedExport, ExportError> {
        ensure_not_expired(sealed.manifest(), now)?;
        verify_signature(self.verification_key, sealed)?;
        let (nonce, encrypted_payload) = parse_envelope(sealed.ciphertext())?;
        let associated_data = associated_data(sealed.manifest())?;
        let mut plaintext = Zeroizing::new(encrypted_payload.to_vec());
        decrypt_payload(self.encryption_key, nonce, &associated_data, &mut plaintext)?;
        let records = parse_records(&plaintext, sealed.manifest())?;
        validate_opened_records(sealed.manifest(), &records)?;
        Ok(VerifiedExport {
            manifest: sealed.manifest().clone(),
            records: records.into_boxed_slice(),
        })
    }
}

impl Debug for AccountExportVerifier<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountExportVerifier(<redacted-keys>)")
    }
}

fn ensure_not_expired(manifest: &ExportManifest, now: UtcSeconds) -> Result<(), ExportError> {
    if now >= manifest.expires_at() {
        return Err(error(ExportErrorCode::AuthorizationExpired));
    }
    Ok(())
}

fn serialize_records(records: &[ExportRecord]) -> Result<Vec<u8>, ExportError> {
    let mut ordered = records.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.account_id().cmp(right.account_id()));
    let mut writer = BoundedWriter::new(MAX_PLAINTEXT_BYTES);
    writer.write(PAYLOAD_MAGIC)?;
    writer.write_u16(FORMAT_VERSION)?;
    writer.write_u32(
        u32::try_from(ordered.len()).map_err(|_| error(ExportErrorCode::ArtifactTooLarge))?,
    )?;
    for record in ordered {
        write_record(&mut writer, record)?;
    }
    Ok(writer.finish())
}

fn write_record(writer: &mut BoundedWriter, record: &ExportRecord) -> Result<(), ExportError> {
    writer.write_text(record.account_id().as_str())?;
    writer.write_u64(record.account_version().get())?;
    writer.write_u64(record.config_version().get())?;
    match record.secret_ref() {
        Some(secret_ref) => write_secret_ref(writer, secret_ref),
        None => writer.write_u8(0),
    }
}

fn write_secret_ref(writer: &mut BoundedWriter, secret_ref: &SecretRef) -> Result<(), ExportError> {
    writer.write_u8(1)?;
    writer.write_text(secret_ref.provider().as_str())?;
    writer.write_text(secret_ref.path().as_str())?;
    writer.write_u64(secret_ref.version().get())?;
    writer.write_text(secret_ref.purpose().as_str())
}

fn associated_data(manifest: &ExportManifest) -> Result<Vec<u8>, ExportError> {
    let mut writer = BoundedWriter::new(MAX_MANIFEST_BYTES);
    writer.write(AAD_DOMAIN)?;
    writer.write(ENVELOPE_MAGIC)?;
    writer.write_u16(FORMAT_VERSION)?;
    write_manifest(&mut writer, manifest)?;
    Ok(writer.finish())
}

fn write_manifest(
    writer: &mut BoundedWriter,
    manifest: &ExportManifest,
) -> Result<(), ExportError> {
    writer.write_text(manifest.batch_id().as_str())?;
    writer.write_text(manifest.tenant_id().as_str())?;
    writer.write_u8(manifest.fields().tag())?;
    writer.write_text(manifest.watermark().as_str())?;
    writer.write_u32(manifest.record_count())?;
    writer.write_u64(manifest.expires_at().get())?;
    writer.write(&manifest.digest().as_bytes())
}

fn encrypt_payload(
    key: &ExportEncryptionKey,
    nonce: ExportNonce,
    associated_data: &[u8],
    payload: &mut Vec<u8>,
) -> Result<(), ExportError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))?;
    cipher
        .encrypt_in_place(&XNonce::from(nonce.as_bytes()), associated_data, payload)
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))
}

fn decrypt_payload(
    key: &ExportEncryptionKey,
    nonce: ExportNonce,
    associated_data: &[u8],
    payload: &mut Vec<u8>,
) -> Result<(), ExportError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))?;
    cipher
        .decrypt_in_place(&XNonce::from(nonce.as_bytes()), associated_data, payload)
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))
}

fn build_envelope(
    nonce: ExportNonce,
    encrypted_payload: &[u8],
) -> Result<OpaqueCiphertext, ExportError> {
    let total = ENVELOPE_PREFIX_BYTES
        .checked_add(encrypted_payload.len())
        .ok_or_else(|| error(ExportErrorCode::ArtifactTooLarge))?;
    if total > MAX_CIPHERTEXT_BYTES {
        return Err(error(ExportErrorCode::ArtifactTooLarge));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(ENVELOPE_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&nonce.as_bytes());
    bytes.extend_from_slice(encrypted_payload);
    OpaqueCiphertext::new(bytes)
}

fn parse_envelope(ciphertext: &[u8]) -> Result<(ExportNonce, &[u8]), ExportError> {
    let minimum = ENVELOPE_PREFIX_BYTES + AEAD_TAG_BYTES;
    if ciphertext.len() < minimum {
        return Err(error(ExportErrorCode::AuthenticationFailed));
    }
    let mut reader = CanonicalReader::new(ciphertext);
    require_exact(reader.read_exact(ENVELOPE_MAGIC.len())?, ENVELOPE_MAGIC)?;
    require_version(reader.read_u16()?)?;
    let nonce = ExportNonce::new(reader.read_array::<NONCE_BYTES>()?);
    Ok((nonce, reader.remaining()))
}

fn sign_artifact(
    signing_key: &ExportSigningKey,
    manifest: &ExportManifest,
    ciphertext: &OpaqueCiphertext,
) -> Result<ExportSignature, ExportError> {
    let digest = artifact_signature_digest(manifest, ciphertext.as_bytes())?;
    let signature = signing_key.signing_key().sign(&digest);
    Ok(ExportSignature::new(signature.to_bytes()))
}

fn verify_signature(
    verification_key: &ExportVerificationKey,
    sealed: &SealedExport,
) -> Result<(), ExportError> {
    let digest = artifact_signature_digest(sealed.manifest(), sealed.ciphertext())?;
    let signature = Signature::from_bytes(sealed.signature());
    verification_key
        .0
        .verify_strict(&digest, &signature)
        .map_err(|_| error(ExportErrorCode::SignatureInvalid))
}

fn artifact_signature_digest(
    manifest: &ExportManifest,
    ciphertext: &[u8],
) -> Result<[u8; 64], ExportError> {
    let manifest_bytes = associated_data(manifest)?;
    let mut hasher = Sha512::new();
    hasher.update(SIGNATURE_DOMAIN);
    hasher.update((manifest_bytes.len() as u64).to_be_bytes());
    hasher.update(&manifest_bytes);
    hasher.update((ciphertext.len() as u64).to_be_bytes());
    hasher.update(ciphertext);
    Ok(hasher.finalize().into())
}

fn parse_records(
    plaintext: &[u8],
    manifest: &ExportManifest,
) -> Result<Vec<ExportRecord>, ExportError> {
    let mut reader = CanonicalReader::new(plaintext);
    let count = parse_payload_header(&mut reader, manifest.record_count())?;
    let records = parse_record_sequence(&mut reader, manifest, count)?;
    ensure_payload_consumed(&reader)?;
    validate_canonical_order(&records)?;
    Ok(records)
}

fn parse_payload_header(
    reader: &mut CanonicalReader<'_>,
    expected_count: u32,
) -> Result<usize, ExportError> {
    require_exact(reader.read_exact(PAYLOAD_MAGIC.len())?, PAYLOAD_MAGIC)?;
    require_version(reader.read_u16()?)?;
    parse_record_count(reader.read_u32()?, expected_count)
}

fn parse_record_sequence(
    reader: &mut CanonicalReader<'_>,
    manifest: &ExportManifest,
    count: usize,
) -> Result<Vec<ExportRecord>, ExportError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(parse_record(reader, manifest)?);
    }
    Ok(records)
}

fn ensure_payload_consumed(reader: &CanonicalReader<'_>) -> Result<(), ExportError> {
    if !reader.remaining().is_empty() {
        return Err(error(ExportErrorCode::AuthenticationFailed));
    }
    Ok(())
}

fn parse_record(
    reader: &mut CanonicalReader<'_>,
    manifest: &ExportManifest,
) -> Result<ExportRecord, ExportError> {
    let account_id = AccountId::parse(reader.read_text()?)
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))?;
    let account_version = AccountVersion::new(reader.read_u64()?)
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))?;
    let config_version = AccountConfigVersion::new(reader.read_u64()?)
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))?;
    parse_record_fields(
        reader,
        manifest,
        account_id,
        account_version,
        config_version,
    )
}

fn parse_record_fields(
    reader: &mut CanonicalReader<'_>,
    manifest: &ExportManifest,
    account_id: AccountId,
    account_version: AccountVersion,
    config_version: AccountConfigVersion,
) -> Result<ExportRecord, ExportError> {
    match reader.read_u8()? {
        0 => Ok(ExportRecord::metadata_only(
            manifest.tenant_id().clone(),
            account_id,
            account_version,
            config_version,
        )),
        1 => Ok(ExportRecord::new(
            manifest.tenant_id().clone(),
            account_id,
            account_version,
            config_version,
            parse_secret_ref(reader)?,
        )),
        _ => Err(error(ExportErrorCode::AuthenticationFailed)),
    }
}

fn parse_secret_ref(reader: &mut CanonicalReader<'_>) -> Result<SecretRef, ExportError> {
    let provider = parse_secret_provider(reader)?;
    let path = parse_secret_path(reader)?;
    let version = parse_secret_version(reader)?;
    let purpose = parse_secret_purpose(reader)?;
    Ok(SecretRef::new(provider, path, version, purpose))
}

fn parse_secret_provider(reader: &mut CanonicalReader<'_>) -> Result<SecretProvider, ExportError> {
    SecretProvider::parse(reader.read_text()?)
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))
}

fn parse_secret_path(reader: &mut CanonicalReader<'_>) -> Result<SecretPath, ExportError> {
    SecretPath::parse(reader.read_text()?).map_err(|_| error(ExportErrorCode::AuthenticationFailed))
}

fn parse_secret_version(reader: &mut CanonicalReader<'_>) -> Result<SecretVersion, ExportError> {
    SecretVersion::new(reader.read_u64()?).map_err(|_| error(ExportErrorCode::AuthenticationFailed))
}

fn parse_secret_purpose(reader: &mut CanonicalReader<'_>) -> Result<SecretPurpose, ExportError> {
    SecretPurpose::parse(reader.read_text()?)
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))
}

fn parse_record_count(value: u32, expected: u32) -> Result<usize, ExportError> {
    let count = usize::try_from(value).map_err(|_| error(ExportErrorCode::AuthenticationFailed))?;
    if value != expected || count == 0 || count > MAX_EXPORT_RECORDS {
        return Err(error(ExportErrorCode::AuthenticationFailed));
    }
    Ok(count)
}

fn validate_canonical_order(records: &[ExportRecord]) -> Result<(), ExportError> {
    for pair in records.windows(2) {
        if pair[0].account_id() >= pair[1].account_id() {
            return Err(error(ExportErrorCode::AuthenticationFailed));
        }
    }
    Ok(())
}

fn validate_opened_records(
    manifest: &ExportManifest,
    records: &[ExportRecord],
) -> Result<(), ExportError> {
    validate_records(records, manifest.tenant_id(), manifest.fields())
        .map_err(|_| error(ExportErrorCode::AuthenticationFailed))?;
    if manifest_digest_from_parts(manifest, records) != manifest.digest() {
        return Err(error(ExportErrorCode::AuthenticationFailed));
    }
    validate_field_shape(manifest.fields(), records)
}

fn validate_field_shape(fields: ExportFields, records: &[ExportRecord]) -> Result<(), ExportError> {
    let valid = match fields {
        ExportFields::MetadataOnly => records.iter().all(|record| record.secret_ref().is_none()),
        ExportFields::MetadataAndSecretReferences => {
            records.iter().all(|record| record.secret_ref().is_some())
        }
    };
    if !valid {
        return Err(error(ExportErrorCode::AuthenticationFailed));
    }
    Ok(())
}

fn require_exact(actual: &[u8], expected: &[u8]) -> Result<(), ExportError> {
    if actual != expected {
        return Err(error(ExportErrorCode::AuthenticationFailed));
    }
    Ok(())
}

fn require_version(version: u16) -> Result<(), ExportError> {
    if version != FORMAT_VERSION {
        return Err(error(ExportErrorCode::AuthenticationFailed));
    }
    Ok(())
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn write(&mut self, value: &[u8]) -> Result<(), ExportError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or_else(|| error(ExportErrorCode::ArtifactTooLarge))?;
        if next > self.limit {
            return Err(error(ExportErrorCode::ArtifactTooLarge));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn write_text(&mut self, value: &str) -> Result<(), ExportError> {
        let length =
            u16::try_from(value.len()).map_err(|_| error(ExportErrorCode::ArtifactTooLarge))?;
        self.write_u16(length)?;
        self.write(value.as_bytes())
    }

    fn write_u8(&mut self, value: u8) -> Result<(), ExportError> {
        self.write(&[value])
    }

    fn write_u16(&mut self, value: u16) -> Result<(), ExportError> {
        self.write(&value.to_be_bytes())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), ExportError> {
        self.write(&value.to_be_bytes())
    }

    fn write_u64(&mut self, value: u64) -> Result<(), ExportError> {
        self.write(&value.to_be_bytes())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct CanonicalReader<'input> {
    input: &'input [u8],
    offset: usize,
}

impl<'input> CanonicalReader<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'input [u8], ExportError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| error(ExportErrorCode::AuthenticationFailed))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| error(ExportErrorCode::AuthenticationFailed))?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], ExportError> {
        self.read_exact(LENGTH)?
            .try_into()
            .map_err(|_| error(ExportErrorCode::AuthenticationFailed))
    }

    fn read_text(&mut self) -> Result<&'input str, ExportError> {
        let length = usize::from(self.read_u16()?);
        std::str::from_utf8(self.read_exact(length)?)
            .map_err(|_| error(ExportErrorCode::AuthenticationFailed))
    }

    fn read_u8(&mut self) -> Result<u8, ExportError> {
        self.read_array::<1>().map(|bytes| bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, ExportError> {
        self.read_array::<2>().map(u16::from_be_bytes)
    }

    fn read_u32(&mut self) -> Result<u32, ExportError> {
        self.read_array::<4>().map(u32::from_be_bytes)
    }

    fn read_u64(&mut self) -> Result<u64, ExportError> {
        self.read_array::<8>().map(u64::from_be_bytes)
    }

    fn remaining(&self) -> &'input [u8] {
        &self.input[self.offset..]
    }
}

// crates/optional/ariadnion-account-export/src/lib.rs - Account export contracts for Ariadnion.
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
//
//! Authorized, bounded, encrypted, and signed account export contracts.
//!
//! This crate validates tenant scope, approval state, record uniqueness, and
//! expiry before an adapter receives an immutable plan. It never accepts
//! plaintext credentials. A concrete memory-bounded XChaCha20-Poly1305 and
//! Ed25519 implementation produces transportable artifacts while preserving
//! the external adapter boundary for output storage and delivery.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_account_domain::{AccountConfigVersion, AccountId, AccountVersion, SecretRef};
use ariadnion_core::{PrincipalId, TenantId};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};

mod crypto;

pub use crypto::{
    AccountExportSealer, AccountExportVerifier, CanonicalPayloadDigest, ExportEncryptionKey,
    ExportNonce, ExportSigningKey, ExportVerificationKey, VerifiedExport,
};

/// Maximum number of account records in one export plan.
pub const MAX_EXPORT_RECORDS: usize = 1 << 17;
/// Number of records at which a second approval is mandatory.
pub const LARGE_EXPORT_THRESHOLD: usize = 1_000;
/// Maximum byte length of an export batch identifier.
pub const MAX_BATCH_ID_BYTES: usize = 128;
/// Maximum byte length of an operator watermark.
pub const MAX_WATERMARK_BYTES: usize = 160;
/// Maximum lifetime of an authorization window in seconds.
pub const MAX_AUTHORIZATION_LIFETIME: u64 = 3_600;
/// Maximum encrypted artifact size accepted by this contract.
pub const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024 * 1024;
/// Required length of an external signature.
pub const EXPORT_SIGNATURE_BYTES: usize = 64;

/// Stable machine-readable account-export failures.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ExportErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// An export contains no account records.
    EmptyBatch,
    /// An export exceeds its fixed record bound.
    TooManyRecords,
    /// An account occurs more than once in one export.
    DuplicateAccount,
    /// The authorization window is expired or otherwise invalid.
    AuthorizationExpired,
    /// The requested export requires an independent second approver.
    SecondaryApprovalRequired,
    /// A record belongs to a different tenant than the authorization.
    ScopeMismatch,
    /// An encrypted artifact exceeds its fixed byte bound.
    ArtifactTooLarge,
    /// A secret-reference export record omitted its external reference.
    MissingSecretReference,
    /// An artifact signature is absent, malformed, or invalid.
    SignatureInvalid,
    /// Authenticated decryption or canonical payload validation failed.
    AuthenticationFailed,
}

impl ExportErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument
            | Self::EmptyBatch
            | Self::TooManyRecords
            | Self::DuplicateAccount
            | Self::AuthorizationExpired => export_input_error_code(self),
            Self::SecondaryApprovalRequired
            | Self::ScopeMismatch
            | Self::ArtifactTooLarge
            | Self::MissingSecretReference
            | Self::SignatureInvalid
            | Self::AuthenticationFailed => export_security_error_code(self),
        }
    }
}

const fn export_input_error_code(code: ExportErrorCode) -> &'static str {
    match code {
        ExportErrorCode::InvalidArgument => "ACCOUNT_EXPORT_INVALID_ARGUMENT",
        ExportErrorCode::EmptyBatch => "ACCOUNT_EXPORT_EMPTY_BATCH",
        ExportErrorCode::TooManyRecords => "ACCOUNT_EXPORT_TOO_MANY_RECORDS",
        ExportErrorCode::DuplicateAccount => "ACCOUNT_EXPORT_DUPLICATE_ACCOUNT",
        ExportErrorCode::AuthorizationExpired => "ACCOUNT_EXPORT_AUTHORIZATION_EXPIRED",
        _ => "ACCOUNT_EXPORT_INVALID_ARGUMENT",
    }
}

const fn export_security_error_code(code: ExportErrorCode) -> &'static str {
    match code {
        ExportErrorCode::SecondaryApprovalRequired => "ACCOUNT_EXPORT_SECONDARY_APPROVAL_REQUIRED",
        ExportErrorCode::ScopeMismatch => "ACCOUNT_EXPORT_SCOPE_MISMATCH",
        ExportErrorCode::ArtifactTooLarge => "ACCOUNT_EXPORT_ARTIFACT_TOO_LARGE",
        ExportErrorCode::MissingSecretReference => "ACCOUNT_EXPORT_MISSING_SECRET_REFERENCE",
        ExportErrorCode::SignatureInvalid => "ACCOUNT_EXPORT_SIGNATURE_INVALID",
        ExportErrorCode::AuthenticationFailed => "ACCOUNT_EXPORT_AUTHENTICATION_FAILED",
        _ => "ACCOUNT_EXPORT_INVALID_ARGUMENT",
    }
}

impl Display for ExportErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted account-export failure containing only a stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportError {
    code: ExportErrorCode,
}

impl ExportError {
    const fn new(code: ExportErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ExportErrorCode {
        self.code
    }
}

impl Display for ExportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ExportError {}

/// UTC Unix time in whole seconds.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcSeconds(u64);

impl UtcSeconds {
    /// Creates a timestamp from seconds since the Unix epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A bounded opaque export batch identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExportBatchId(Box<str>);

impl ExportBatchId {
    /// Parses a visible ASCII batch identifier.
    ///
    /// # Errors
    /// Returns [`ExportErrorCode::InvalidArgument`] for empty, oversized,
    /// non-ASCII, or control-containing values.
    pub fn parse(value: &str) -> Result<Self, ExportError> {
        if !valid_visible(value, MAX_BATCH_ID_BYTES) {
            return Err(error(ExportErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ExportBatchId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportBatchId(<opaque>)")
    }
}

impl Display for ExportBatchId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded operator-provided watermark included in an export manifest.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExportWatermark(Box<str>);

impl ExportWatermark {
    /// Parses a visible ASCII watermark.
    ///
    /// # Errors
    /// Returns [`ExportErrorCode::InvalidArgument`] for empty, oversized,
    /// non-ASCII, or control-containing values.
    pub fn parse(value: &str) -> Result<Self, ExportError> {
        if !valid_visible(value, MAX_WATERMARK_BYTES) {
            return Err(error(ExportErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated watermark.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ExportWatermark {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportWatermark(<opaque>)")
    }
}

/// Fields that an authorized export may contain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExportFields {
    /// Account metadata and version references only.
    MetadataOnly,
    /// Account metadata plus references to externally held secrets.
    MetadataAndSecretReferences,
}

impl ExportFields {
    /// Returns a metadata-only field set.
    #[must_use]
    pub const fn metadata_only() -> Self {
        Self::MetadataOnly
    }

    /// Returns a field set that includes secret references but never values.
    #[must_use]
    pub const fn metadata_and_secret_references() -> Self {
        Self::MetadataAndSecretReferences
    }

    const fn requires_secondary(self) -> bool {
        matches!(self, Self::MetadataAndSecretReferences)
    }

    const fn includes_secret_references(self) -> bool {
        matches!(self, Self::MetadataAndSecretReferences)
    }

    const fn tag(self) -> u8 {
        match self {
            Self::MetadataOnly => 1,
            Self::MetadataAndSecretReferences => 2,
        }
    }
}

/// Approval evidence supplied by an authorization service.
#[derive(Clone, Eq, PartialEq)]
pub struct ExportApproval {
    primary: PrincipalId,
    secondary: Option<PrincipalId>,
}

impl ExportApproval {
    /// Creates approval evidence from one or two distinct principals.
    ///
    /// The constructor records authorization evidence; it does not grant any
    /// permission by itself. A caller must still satisfy the export scope and
    /// expiry checks performed by [`AccountExportPlan::prepare`].
    ///
    /// # Errors
    /// Returns [`ExportErrorCode::InvalidArgument`] when both approvers are the
    /// same principal.
    pub fn new(primary: PrincipalId, secondary: Option<PrincipalId>) -> Result<Self, ExportError> {
        if secondary.as_ref().is_some_and(|value| value == &primary) {
            return Err(error(ExportErrorCode::InvalidArgument));
        }
        Ok(Self { primary, secondary })
    }

    /// Returns the primary approver identity.
    #[must_use]
    pub const fn primary(&self) -> &PrincipalId {
        &self.primary
    }

    /// Returns the independent second approver when present.
    #[must_use]
    pub const fn secondary(&self) -> Option<&PrincipalId> {
        self.secondary.as_ref()
    }
}

impl Debug for ExportApproval {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportApproval")
            .field("primary", &"<redacted>")
            .field("secondary_present", &self.secondary.is_some())
            .finish()
    }
}

/// Tenant-scoped authorization for one export batch.
#[derive(Clone, Eq, PartialEq)]
pub struct ExportAuthorization {
    tenant_id: TenantId,
    batch_id: ExportBatchId,
    approval: ExportApproval,
    fields: ExportFields,
    issued_at: UtcSeconds,
    expires_at: UtcSeconds,
}

impl ExportAuthorization {
    /// Creates a bounded authorization window.
    ///
    /// # Errors
    /// Returns [`ExportErrorCode::AuthorizationExpired`] when the expiry is not
    /// after issuance or exceeds [`MAX_AUTHORIZATION_LIFETIME`].
    pub fn new(
        tenant_id: TenantId,
        batch_id: ExportBatchId,
        primary: PrincipalId,
        secondary: Option<PrincipalId>,
        fields: ExportFields,
        issued_at: UtcSeconds,
        expires_at: UtcSeconds,
    ) -> Result<Self, ExportError> {
        let lifetime = expires_at
            .get()
            .checked_sub(issued_at.get())
            .ok_or_else(|| error(ExportErrorCode::AuthorizationExpired))?;
        if lifetime == 0 || lifetime > MAX_AUTHORIZATION_LIFETIME {
            return Err(error(ExportErrorCode::AuthorizationExpired));
        }
        Ok(Self {
            tenant_id,
            batch_id,
            approval: ExportApproval::new(primary, secondary)?,
            fields,
            issued_at,
            expires_at,
        })
    }

    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the export batch identifier.
    #[must_use]
    pub const fn batch_id(&self) -> &ExportBatchId {
        &self.batch_id
    }

    /// Returns the approval evidence.
    #[must_use]
    pub const fn approval(&self) -> &ExportApproval {
        &self.approval
    }

    /// Returns the authorized field set.
    #[must_use]
    pub const fn fields(&self) -> ExportFields {
        self.fields
    }

    /// Returns the authorization issuance timestamp.
    #[must_use]
    pub const fn issued_at(&self) -> UtcSeconds {
        self.issued_at
    }

    /// Returns the authorization expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> UtcSeconds {
        self.expires_at
    }
}

impl Debug for ExportAuthorization {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportAuthorization")
            .field("tenant_id", &"<redacted>")
            .field("batch_id", &self.batch_id)
            .field("approval", &self.approval)
            .field("fields", &self.fields)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// One account record admitted to an export plan.
#[derive(Clone, Eq, PartialEq)]
pub struct ExportRecord {
    tenant_id: TenantId,
    account_id: AccountId,
    account_version: AccountVersion,
    config_version: AccountConfigVersion,
    secret_ref: Option<SecretRef>,
}

impl ExportRecord {
    /// Creates a record containing metadata and a reference to external secret
    /// storage. The secret value is never accepted.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        account_id: AccountId,
        account_version: AccountVersion,
        config_version: AccountConfigVersion,
        secret_ref: SecretRef,
    ) -> Self {
        Self {
            tenant_id,
            account_id,
            account_version,
            config_version,
            secret_ref: Some(secret_ref),
        }
    }

    /// Creates a metadata-only record without any secret locator.
    #[must_use]
    pub const fn metadata_only(
        tenant_id: TenantId,
        account_id: AccountId,
        account_version: AccountVersion,
        config_version: AccountConfigVersion,
    ) -> Self {
        Self {
            tenant_id,
            account_id,
            account_version,
            config_version,
            secret_ref: None,
        }
    }

    /// Returns the record tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the account aggregate version.
    #[must_use]
    pub const fn account_version(&self) -> AccountVersion {
        self.account_version
    }

    /// Returns the account configuration version.
    #[must_use]
    pub const fn config_version(&self) -> AccountConfigVersion {
        self.config_version
    }

    /// Returns the external secret reference when this record carries one.
    #[must_use]
    pub fn secret_ref(&self) -> Option<&SecretRef> {
        self.secret_ref.as_ref()
    }

    fn metadata_projection(&self) -> Self {
        Self::metadata_only(
            self.tenant_id.clone(),
            self.account_id.clone(),
            self.account_version,
            self.config_version,
        )
    }
}

impl Debug for ExportRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportRecord")
            .field("tenant_id", &"<redacted>")
            .field("account_id", &"<redacted>")
            .field("account_version", &self.account_version)
            .field("config_version", &self.config_version)
            .field("secret_ref", &self.secret_ref)
            .finish()
    }
}

/// Fixed-size digest of the canonical export manifest.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManifestDigest([u8; 32]);

impl ManifestDigest {
    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Debug for ManifestDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManifestDigest(<sha256>)")
    }
}

/// Immutable metadata describing one export plan.
#[derive(Clone, Eq, PartialEq)]
pub struct ExportManifest {
    batch_id: ExportBatchId,
    tenant_id: TenantId,
    fields: ExportFields,
    watermark: ExportWatermark,
    record_count: u32,
    expires_at: UtcSeconds,
    digest: ManifestDigest,
}

impl Debug for ExportManifest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportManifest")
            .field("batch_id", &self.batch_id)
            .field("tenant_id", &"<redacted>")
            .field("fields", &self.fields)
            .field("watermark", &self.watermark)
            .field("record_count", &self.record_count)
            .field("expires_at", &self.expires_at)
            .field("digest", &self.digest)
            .finish()
    }
}

impl ExportManifest {
    /// Returns the batch identifier.
    #[must_use]
    pub const fn batch_id(&self) -> &ExportBatchId {
        &self.batch_id
    }

    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the authorized fields.
    #[must_use]
    pub const fn fields(&self) -> ExportFields {
        self.fields
    }

    /// Returns the operator watermark.
    #[must_use]
    pub const fn watermark(&self) -> &ExportWatermark {
        &self.watermark
    }

    /// Returns the number of records in the plan.
    #[must_use]
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }

    /// Returns the authorization expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UtcSeconds {
        self.expires_at
    }

    /// Returns the canonical manifest digest.
    #[must_use]
    pub const fn digest(&self) -> ManifestDigest {
        self.digest
    }
}

/// Immutable, validated export plan handed to a sealing adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountExportPlan {
    authorization: ExportAuthorization,
    records: Box<[ExportRecord]>,
    manifest: ExportManifest,
}

impl AccountExportPlan {
    /// Validates an export request and constructs an immutable plan.
    ///
    /// The operation is pure: failures leave all caller-owned values untouched.
    /// Metadata-only authorizations project away all secret locators before the
    /// plan reaches a sealing adapter. Plaintext secret material cannot be passed
    /// to this API.
    ///
    /// # Errors
    /// Returns a stable error for expiry, missing dual approval, empty or
    /// oversized batches, duplicate accounts, or tenant scope mismatch.
    pub fn prepare(
        authorization: ExportAuthorization,
        records: Vec<ExportRecord>,
        now: UtcSeconds,
        watermark: ExportWatermark,
    ) -> Result<Self, ExportError> {
        validate_export_requirements(&authorization, records.len(), now)?;
        validate_records(&records, authorization.tenant_id(), authorization.fields())?;
        let records = project_records(authorization.fields(), records);
        let record_count =
            u32::try_from(records.len()).map_err(|_| error(ExportErrorCode::TooManyRecords))?;
        let digest = manifest_digest(&authorization, &records, &watermark, record_count);
        let manifest = ExportManifest {
            batch_id: authorization.batch_id().clone(),
            tenant_id: authorization.tenant_id().clone(),
            fields: authorization.fields(),
            watermark,
            record_count,
            expires_at: authorization.expires_at(),
            digest,
        };
        Ok(Self {
            authorization,
            records: records.into_boxed_slice(),
            manifest,
        })
    }

    /// Returns the authorization evidence bound to the plan.
    #[must_use]
    pub const fn authorization(&self) -> &ExportAuthorization {
        &self.authorization
    }

    /// Returns the immutable account records.
    #[must_use]
    pub fn records(&self) -> &[ExportRecord] {
        &self.records
    }

    /// Returns the immutable manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ExportManifest {
        &self.manifest
    }
}

/// Bounded encrypted bytes produced by an external sealing adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCiphertext(Vec<u8>);

impl OpaqueCiphertext {
    /// Creates a non-empty bounded ciphertext container.
    ///
    /// # Errors
    /// Returns [`ExportErrorCode::ArtifactTooLarge`] for an empty or oversized
    /// artifact. The empty case is rejected because a seal must carry data.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ExportError> {
        if bytes.is_empty() || bytes.len() > MAX_CIPHERTEXT_BYTES {
            return Err(error(ExportErrorCode::ArtifactTooLarge));
        }
        Ok(Self(bytes))
    }

    /// Returns the encrypted bytes for transport to the output adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the encrypted byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the ciphertext contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Debug for OpaqueCiphertext {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCiphertext")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Fixed-size signature supplied by an external signing adapter.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ExportSignature([u8; EXPORT_SIGNATURE_BYTES]);

impl ExportSignature {
    /// Creates a fixed-size signature container.
    #[must_use]
    pub const fn new(bytes: [u8; EXPORT_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the signature bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; EXPORT_SIGNATURE_BYTES] {
        self.0
    }
}

impl Debug for ExportSignature {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportSignature(<redacted>)")
    }
}

/// Opaque, encrypted, and signed export artifact.
#[derive(Clone, Eq, PartialEq)]
pub struct SealedExport {
    manifest: ExportManifest,
    ciphertext: OpaqueCiphertext,
    signature: ExportSignature,
}

impl SealedExport {
    /// Reconstructs an opaque artifact received through a transport adapter.
    ///
    /// This constructor makes no authenticity claim. Callers must pass the
    /// result to [`AccountExportVerifier::verify_and_open`] before using its
    /// payload. The ciphertext has already been bounded by [`OpaqueCiphertext`].
    #[must_use]
    pub const fn from_transport_parts(
        manifest: ExportManifest,
        ciphertext: OpaqueCiphertext,
        signature: [u8; EXPORT_SIGNATURE_BYTES],
    ) -> Self {
        Self {
            manifest,
            ciphertext,
            signature: ExportSignature::new(signature),
        }
    }

    /// Returns the manifest authenticated by the external signature.
    #[must_use]
    pub const fn manifest(&self) -> &ExportManifest {
        &self.manifest
    }

    /// Returns the encrypted artifact bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_bytes()
    }

    /// Returns the encrypted artifact length.
    #[must_use]
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }

    /// Returns the external signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; EXPORT_SIGNATURE_BYTES] {
        &self.signature.0
    }
}

impl Debug for SealedExport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedExport")
            .field("manifest", &self.manifest)
            .field("ciphertext", &self.ciphertext)
            .field("signature", &self.signature)
            .finish()
    }
}

/// Stateless sealing boundary for external encryption and signing adapters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExportSeal;

impl ExportSeal {
    /// Binds opaque ciphertext and a signature to a validated plan.
    ///
    /// This method does not claim to perform cryptography. The caller must
    /// provide bytes produced by an approved encryption/signing adapter, while
    /// this boundary enforces plan expiry and keeps the resulting artifact
    /// immutable.
    ///
    /// # Errors
    /// Returns [`ExportErrorCode::AuthorizationExpired`] when sealing occurs at
    /// or after the plan expiry.
    pub fn seal(
        plan: AccountExportPlan,
        ciphertext: OpaqueCiphertext,
        signature: ExportSignature,
        now: UtcSeconds,
    ) -> Result<SealedExport, ExportError> {
        if now >= plan.manifest().expires_at() {
            return Err(error(ExportErrorCode::AuthorizationExpired));
        }
        Ok(SealedExport {
            manifest: plan.manifest().clone(),
            ciphertext,
            signature,
        })
    }
}

fn validate_window(
    authorization: &ExportAuthorization,
    now: UtcSeconds,
) -> Result<(), ExportError> {
    if now < authorization.issued_at() || now >= authorization.expires_at() {
        return Err(error(ExportErrorCode::AuthorizationExpired));
    }
    Ok(())
}

fn validate_record_count(count: usize) -> Result<(), ExportError> {
    match count {
        0 => Err(error(ExportErrorCode::EmptyBatch)),
        value if value > MAX_EXPORT_RECORDS => Err(error(ExportErrorCode::TooManyRecords)),
        _ => Ok(()),
    }
}

fn validate_export_requirements(
    authorization: &ExportAuthorization,
    record_count: usize,
    now: UtcSeconds,
) -> Result<(), ExportError> {
    validate_window(authorization, now)?;
    validate_record_count(record_count)?;
    validate_secondary_approval(authorization, record_count)
}

fn validate_secondary_approval(
    authorization: &ExportAuthorization,
    record_count: usize,
) -> Result<(), ExportError> {
    let required =
        authorization.fields().requires_secondary() || record_count > LARGE_EXPORT_THRESHOLD;
    if required && authorization.approval().secondary().is_none() {
        return Err(error(ExportErrorCode::SecondaryApprovalRequired));
    }
    Ok(())
}

fn validate_records(
    records: &[ExportRecord],
    tenant_id: &TenantId,
    fields: ExportFields,
) -> Result<(), ExportError> {
    let mut seen = BTreeSet::new();
    for record in records {
        validate_record_scope(record, tenant_id)?;
        validate_record_fields(record, fields)?;
        insert_unique_account(&mut seen, record.account_id())?;
    }
    Ok(())
}

fn validate_record_fields(record: &ExportRecord, fields: ExportFields) -> Result<(), ExportError> {
    if fields.includes_secret_references() && record.secret_ref().is_none() {
        return Err(error(ExportErrorCode::MissingSecretReference));
    }
    Ok(())
}

fn project_records(fields: ExportFields, records: Vec<ExportRecord>) -> Vec<ExportRecord> {
    match fields {
        ExportFields::MetadataOnly => records
            .iter()
            .map(ExportRecord::metadata_projection)
            .collect(),
        ExportFields::MetadataAndSecretReferences => records,
    }
}

fn validate_record_scope(record: &ExportRecord, tenant_id: &TenantId) -> Result<(), ExportError> {
    if record.tenant_id() != tenant_id {
        return Err(error(ExportErrorCode::ScopeMismatch));
    }
    Ok(())
}

fn insert_unique_account(
    seen: &mut BTreeSet<AccountId>,
    account_id: &AccountId,
) -> Result<(), ExportError> {
    if !seen.insert(account_id.clone()) {
        return Err(error(ExportErrorCode::DuplicateAccount));
    }
    Ok(())
}

fn manifest_digest(
    authorization: &ExportAuthorization,
    records: &[ExportRecord],
    watermark: &ExportWatermark,
    record_count: u32,
) -> ManifestDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"ariadnion-account-export-v1\0");
    hash_text(&mut hasher, authorization.tenant_id().as_str());
    hash_text(&mut hasher, authorization.batch_id().as_str());
    hasher.update([authorization.fields().tag()]);
    hasher.update(authorization.expires_at().get().to_be_bytes());
    hash_text(&mut hasher, watermark.as_str());
    hasher.update(record_count.to_be_bytes());
    let mut ordered = records.to_vec();
    ordered.sort_by(|left, right| left.account_id().cmp(right.account_id()));
    for record in &ordered {
        hash_text(&mut hasher, record.tenant_id().as_str());
        hash_text(&mut hasher, record.account_id().as_str());
        hasher.update(record.account_version().get().to_be_bytes());
        hasher.update(record.config_version().get().to_be_bytes());
        match record.secret_ref() {
            Some(secret_ref) => {
                hasher.update([1]);
                hash_text(&mut hasher, secret_ref.provider().as_str());
                hash_text(&mut hasher, secret_ref.path().as_str());
                hasher.update(secret_ref.version().get().to_be_bytes());
                hash_text(&mut hasher, secret_ref.purpose().as_str());
            }
            None => hasher.update([0]),
        }
    }
    ManifestDigest(hasher.finalize().into())
}

fn manifest_digest_from_parts(
    manifest: &ExportManifest,
    records: &[ExportRecord],
) -> ManifestDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"ariadnion-account-export-v1\0");
    hash_text(&mut hasher, manifest.tenant_id().as_str());
    hash_text(&mut hasher, manifest.batch_id().as_str());
    hasher.update([manifest.fields().tag()]);
    hasher.update(manifest.expires_at().get().to_be_bytes());
    hash_text(&mut hasher, manifest.watermark().as_str());
    hasher.update(manifest.record_count().to_be_bytes());
    hash_ordered_records(&mut hasher, records);
    ManifestDigest(hasher.finalize().into())
}

fn hash_ordered_records(hasher: &mut Sha256, records: &[ExportRecord]) {
    let mut ordered = records.to_vec();
    ordered.sort_by(|left, right| left.account_id().cmp(right.account_id()));
    for record in &ordered {
        hash_record(hasher, record);
    }
}

fn hash_record(hasher: &mut Sha256, record: &ExportRecord) {
    hash_text(hasher, record.tenant_id().as_str());
    hash_text(hasher, record.account_id().as_str());
    hasher.update(record.account_version().get().to_be_bytes());
    hasher.update(record.config_version().get().to_be_bytes());
    match record.secret_ref() {
        Some(secret_ref) => {
            hasher.update([1]);
            hash_text(hasher, secret_ref.provider().as_str());
            hash_text(hasher, secret_ref.path().as_str());
            hasher.update(secret_ref.version().get().to_be_bytes());
            hash_text(hasher, secret_ref.purpose().as_str());
        }
        None => hasher.update([0]),
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn valid_visible(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.is_ascii()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

const fn error(code: ExportErrorCode) -> ExportError {
    ExportError::new(code)
}

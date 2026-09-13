// crates/optional/ariadnion-account-vault/src/secret.rs - Secret values for Ariadnion.
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
//! Zeroizing secret ownership and adapter-produced ciphertext envelopes.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;
use std::time::{Duration, SystemTime};

use ariadnion_account_domain::SecretRef;
use ariadnion_core::ModuleId;
use zeroize::{Zeroize, Zeroizing};

use crate::{VaultError, VaultErrorCode};

/// Maximum plaintext bytes that one vault lease may expose.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
/// Maximum ciphertext bytes retained by one encrypted envelope.
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_SECRET_BYTES + 4 * 1024;
/// Nonce width reserved for the reviewed vault adapter algorithm.
pub const ENVELOPE_NONCE_BYTES: usize = 24;
/// Maximum lifetime of a plaintext lease.
pub const MAX_LEASE_LIFETIME: Duration = Duration::from_secs(60);

/// A non-zero key version selected by a vault adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VaultKeyVersion(NonZeroU64);

impl VaultKeyVersion {
    /// Creates a key version greater than zero.
    ///
    /// # Errors
    ///
    /// Returns [`VaultErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, VaultError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| VaultError::new(VaultErrorCode::InvalidArgument))
    }

    /// Returns the numeric key version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// An adapter-owned ciphertext envelope with bounded storage.
///
/// The envelope contains no plaintext. Its algorithm, authenticated-data
/// layout, and key custody remain responsibilities of the concrete vault
/// adapter; this type only carries the bytes across a typed persistence port.
pub struct EncryptedSecretEnvelope {
    key_version: VaultKeyVersion,
    nonce: [u8; ENVELOPE_NONCE_BYTES],
    ciphertext: Box<[u8]>,
}

impl EncryptedSecretEnvelope {
    /// Creates a bounded envelope from adapter-produced ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`VaultErrorCode::InvalidArgument`] for an empty or oversized
    /// ciphertext. The input bytes are copied only after the bound is checked.
    pub fn new(
        key_version: VaultKeyVersion,
        nonce: [u8; ENVELOPE_NONCE_BYTES],
        ciphertext: &[u8],
    ) -> Result<Self, VaultError> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(VaultError::new(VaultErrorCode::InvalidArgument));
        }
        Ok(Self {
            key_version,
            nonce,
            ciphertext: ciphertext.into(),
        })
    }

    /// Returns the adapter-selected key version.
    #[must_use]
    pub const fn key_version(&self) -> VaultKeyVersion {
        self.key_version
    }

    /// Borrows the nonce for a trusted decryption adapter.
    ///
    /// The nonce is not a bearer credential, but callers must not combine it
    /// with plaintext or expose the envelope contents in diagnostics.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; ENVELOPE_NONCE_BYTES] {
        &self.nonce
    }

    /// Borrows ciphertext for a trusted decryption or durable-storage adapter.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the ciphertext byte length without exposing its contents.
    #[must_use]
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}

impl Debug for EncryptedSecretEnvelope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedSecretEnvelope")
            .field("key_version", &self.key_version)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

impl Zeroize for EncryptedSecretEnvelope {
    fn zeroize(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

impl Drop for EncryptedSecretEnvelope {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Owned plaintext secret material that is zeroized when dropped.
pub struct SecretMaterial(Zeroizing<Vec<u8>>);

impl SecretMaterial {
    /// Creates bounded secret material from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`VaultErrorCode::InvalidArgument`] for empty or oversized
    /// values. The rejected bytes are never retained by the error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            return Err(VaultError::new(VaultErrorCode::InvalidArgument));
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// Borrows plaintext only for the final, trusted provider-adapter call.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the plaintext length without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the material is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Moves the zeroizing buffer to a caller that owns the final use boundary.
    #[must_use]
    pub fn into_zeroizing_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A fixed-width opaque lease identity.
#[derive(Eq, PartialEq)]
pub struct SecretLeaseId([u8; Self::BYTE_LENGTH]);

impl SecretLeaseId {
    /// Exact byte width of one lease identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Creates a lease identity from trusted adapter entropy.
    #[must_use]
    pub const fn new(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the identity for an adapter-owned lookup or audit record.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

impl Debug for SecretLeaseId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretLeaseId(<redacted>)")
    }
}

impl Zeroize for SecretLeaseId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretLeaseId {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A positive, bounded lifetime for plaintext access.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecretLeaseLifetime(Duration);

impl SecretLeaseLifetime {
    /// Validates one positive lifetime no longer than one minute.
    ///
    /// Sub-microsecond precision is rejected so adapters can persist exact
    /// UTC bounds without silently rounding a security decision.
    pub fn new(value: Duration) -> Result<Self, VaultError> {
        if value.is_zero() || value > MAX_LEASE_LIFETIME {
            return Err(VaultError::new(if value > MAX_LEASE_LIFETIME {
                VaultErrorCode::LimitExceeded
            } else {
                VaultErrorCode::InvalidArgument
            }));
        }
        if !value.subsec_nanos().is_multiple_of(1_000) {
            return Err(VaultError::new(VaultErrorCode::InvalidArgument));
        }
        Ok(Self(value))
    }

    /// Returns the checked duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// A lease validity interval with an owned, zeroizing plaintext.
pub struct SecretLease {
    reference: SecretRef,
    module: ModuleId,
    lease_id: SecretLeaseId,
    issued_at: SystemTime,
    expires_at: SystemTime,
    material: SecretMaterial,
}

impl SecretLease {
    /// Issues a lease after validating its lifetime and representable expiry.
    ///
    /// The adapter must have already authenticated the tenant and authorized
    /// the module for the reference's purpose. This constructor does not make
    /// an authorization decision; it prevents malformed or overlong leases.
    pub fn issue(
        reference: SecretRef,
        module: ModuleId,
        lease_id: SecretLeaseId,
        issued_at: SystemTime,
        lifetime: SecretLeaseLifetime,
        material: SecretMaterial,
    ) -> Result<Self, VaultError> {
        let expires_at = issued_at
            .checked_add(lifetime.get())
            .ok_or_else(|| VaultError::new(VaultErrorCode::InvalidArgument))?;
        Ok(Self {
            reference,
            module,
            lease_id,
            issued_at,
            expires_at,
            material,
        })
    }

    /// Returns the secret locator bound to this lease.
    #[must_use]
    pub const fn reference(&self) -> &SecretRef {
        &self.reference
    }

    /// Returns the module identity to which this lease is bound.
    #[must_use]
    pub const fn module(&self) -> &ModuleId {
        &self.module
    }

    /// Borrows the opaque lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> &SecretLeaseId {
        &self.lease_id
    }

    /// Returns the inclusive issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// Returns the exclusive expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Reports whether the lease can authorize use at the supplied UTC time.
    #[must_use]
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        self.issued_at <= now && now < self.expires_at
    }

    /// Borrows plaintext for one final trusted adapter operation.
    ///
    /// Callers must check [`Self::is_valid_at`] immediately before use and must
    /// not copy, log, serialize, or retain the returned bytes.
    #[must_use]
    pub fn material(&self) -> &SecretMaterial {
        &self.material
    }
}

impl Debug for SecretLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretLease")
            .field("reference", &self.reference)
            .field("module", &self.module)
            .field("lease_id", &self.lease_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

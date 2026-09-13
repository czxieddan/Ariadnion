// crates/optional/ariadnion-account-vault/src/port.rs - Vault ports for Ariadnion.
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
//! Async, tenant-aware vault adapter contracts.

use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use ariadnion_account_domain::{SecretRef, SecretVersion};
use ariadnion_core::{ModuleId, RequestContext};

use crate::secret::{
    EncryptedSecretEnvelope, SecretLease, SecretLeaseId, SecretLeaseLifetime, VaultKeyVersion,
};
use crate::{VaultError, VaultErrorCode};

/// A boxed, sendable vault operation future.
pub type BoxVaultFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, VaultError>> + Send + 'a>>;

/// A bounded request for a short plaintext lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretReadRequest {
    reference: SecretRef,
    module: ModuleId,
    lifetime: SecretLeaseLifetime,
}

impl SecretReadRequest {
    /// Creates a read request for one module and secret purpose.
    #[must_use]
    pub const fn new(
        reference: SecretRef,
        module: ModuleId,
        lifetime: SecretLeaseLifetime,
    ) -> Self {
        Self {
            reference,
            module,
            lifetime,
        }
    }

    /// Returns the exact secret locator requested.
    #[must_use]
    pub const fn reference(&self) -> &SecretRef {
        &self.reference
    }

    /// Returns the module identity requesting the lease.
    #[must_use]
    pub const fn module(&self) -> &ModuleId {
        &self.module
    }

    /// Returns the bounded plaintext lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> SecretLeaseLifetime {
        self.lifetime
    }
}

/// A request to persist one adapter-produced encrypted secret version.
pub struct SecretStoreRequest {
    reference: SecretRef,
    envelope: EncryptedSecretEnvelope,
}

impl SecretStoreRequest {
    /// Creates a store request that contains ciphertext but no plaintext.
    #[must_use]
    pub const fn new(reference: SecretRef, envelope: EncryptedSecretEnvelope) -> Self {
        Self {
            reference,
            envelope,
        }
    }

    /// Returns the secret locator to be written.
    #[must_use]
    pub const fn reference(&self) -> &SecretRef {
        &self.reference
    }

    /// Borrows the ciphertext envelope for a trusted storage adapter.
    #[must_use]
    pub const fn envelope(&self) -> &EncryptedSecretEnvelope {
        &self.envelope
    }

    /// Consumes the request and returns its owned envelope.
    #[must_use]
    pub fn into_parts(self) -> (SecretRef, EncryptedSecretEnvelope) {
        (self.reference, self.envelope)
    }
}

impl std::fmt::Debug for SecretStoreRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretStoreRequest")
            .field("reference", &self.reference)
            .field("envelope", &self.envelope)
            .finish()
    }
}

/// A bounded reason for revoking a secret version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VaultRevokeReason {
    /// An operator deliberately revoked the version.
    Operator,
    /// A failed rotation made the version unsafe to use.
    RotationFailure,
    /// A policy or health event invalidated the version.
    RiskEvent,
}

/// A request to revoke one exact secret version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultRevokeRequest {
    reference: SecretRef,
    reason: VaultRevokeReason,
}

impl VaultRevokeRequest {
    /// Creates a revocation request.
    #[must_use]
    pub const fn new(reference: SecretRef, reason: VaultRevokeReason) -> Self {
        Self { reference, reason }
    }

    /// Returns the exact version to revoke.
    #[must_use]
    pub const fn reference(&self) -> &SecretRef {
        &self.reference
    }

    /// Returns the explicit revocation reason.
    #[must_use]
    pub const fn reason(&self) -> VaultRevokeReason {
        self.reason
    }
}

/// Durable evidence returned after a secret version is stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretStoreReceipt {
    version: SecretVersion,
    key_version: VaultKeyVersion,
    committed_at: SystemTime,
}

impl SecretStoreReceipt {
    /// Creates a receipt after the adapter confirms durable commit.
    #[must_use]
    pub const fn new(
        version: SecretVersion,
        key_version: VaultKeyVersion,
        committed_at: SystemTime,
    ) -> Self {
        Self {
            version,
            key_version,
            committed_at,
        }
    }

    /// Returns the committed secret version.
    #[must_use]
    pub const fn version(self) -> SecretVersion {
        self.version
    }

    /// Returns the encryption key version used by the adapter.
    #[must_use]
    pub const fn key_version(self) -> VaultKeyVersion {
        self.key_version
    }

    /// Returns the adapter-reported UTC commit time.
    #[must_use]
    pub const fn committed_at(self) -> SystemTime {
        self.committed_at
    }
}

/// Durable evidence returned after a revoke commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretRevokeReceipt {
    version: SecretVersion,
    committed_at: SystemTime,
}

impl SecretRevokeReceipt {
    /// Creates a revoke receipt after durable commit.
    #[must_use]
    pub const fn new(version: SecretVersion, committed_at: SystemTime) -> Self {
        Self {
            version,
            committed_at,
        }
    }

    /// Returns the revoked secret version.
    #[must_use]
    pub const fn version(self) -> SecretVersion {
        self.version
    }

    /// Returns the adapter-reported UTC commit time.
    #[must_use]
    pub const fn committed_at(self) -> SystemTime {
        self.committed_at
    }
}

/// Port implemented by a vault adapter backed by encrypted durable storage.
pub trait VaultPort: Send + Sync {
    /// Reads one secret through a short, module- and purpose-bound lease.
    ///
    /// The adapter must authenticate the tenant from `context`, verify the
    /// module and purpose against policy, check cancellation/deadline before
    /// decryption, and return a redacted [`VaultError`] on every failure.
    fn read<'a>(
        &'a self,
        request: SecretReadRequest,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, SecretLease>;

    /// Stores one encrypted secret version and returns durable evidence.
    ///
    /// A [`VaultErrorCode::CommitIndeterminate`] result requires reconciliation
    /// by the reference identity; callers must not blindly replay with a new
    /// version or idempotency identity.
    fn store<'a>(
        &'a self,
        request: SecretStoreRequest,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, SecretStoreReceipt>;

    /// Revokes one exact secret version without exposing its plaintext.
    fn revoke<'a>(
        &'a self,
        request: VaultRevokeRequest,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, SecretRevokeReceipt>;

    /// Reconciles a prior ambiguous store or revoke operation.
    ///
    /// Adapters should return [`VaultErrorCode::NotFound`] when authoritative
    /// state proves that the operation did not commit, rather than guessing.
    fn reconcile<'a>(
        &'a self,
        reference: SecretRef,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, Option<SecretStoreReceipt>>;

    /// Generates a lease identity using adapter-owned cryptographically secure
    /// randomness. This helper keeps entropy generation out of domain callers.
    fn new_lease_id(&self) -> Result<SecretLeaseId, VaultError> {
        Err(VaultError::new(VaultErrorCode::Unavailable))
    }
}

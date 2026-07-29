// crates/optional/ariadnion-auth-password/src/credential.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
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
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Tenant-bound password credential persistence contracts.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;

use ariadnion_core::TenantId;
use ariadnion_user_domain::UserId;

use crate::{Argon2idParameters, PasswordError, PasswordErrorCode, PasswordHashRecord};

/// Tenant and user identities owning one password credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordCredentialSubject {
    tenant_id: TenantId,
    user_id: UserId,
}

impl PasswordCredentialSubject {
    /// Creates a tenant-bound credential owner.
    #[must_use]
    pub const fn new(tenant_id: TenantId, user_id: UserId) -> Self {
        Self { tenant_id, user_id }
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the user identity within the tenant boundary.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

/// A non-zero optimistic version for one password credential.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PasswordCredentialVersion(NonZeroU64);

impl PasswordCredentialVersion {
    /// Returns the version assigned to a newly persisted credential.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic credential version.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidCredentialArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, PasswordError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(invalid_credential_argument)
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next optimistic credential version.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::CredentialVersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, PasswordError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| PasswordError::new(PasswordErrorCode::CredentialVersionExhausted))
    }
}

/// A non-zero version of the policy that produced a password hash.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PasswordHashPolicyVersion(NonZeroU64);

impl PasswordHashPolicyVersion {
    /// Creates a non-zero password-hash policy version.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidCredentialArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, PasswordError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(invalid_credential_argument)
    }

    /// Returns the numeric policy version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Every durable field required to reconstruct one password credential.
///
/// The PHC record is a one-way verifier that carries the Argon2id algorithm,
/// version, salt, output, and resource parameters. The separate policy version
/// retains the application policy identity that produced that record.
#[derive(Clone, Eq, PartialEq)]
pub struct PasswordCredentialSnapshot {
    /// Tenant and user identities owning the credential.
    pub subject: PasswordCredentialSubject,
    /// Non-zero optimistic credential version.
    pub version: PasswordCredentialVersion,
    /// Non-zero application hash-policy version.
    pub hash_policy_version: PasswordHashPolicyVersion,
    /// Validated self-describing Argon2id PHC record.
    pub hash_record: PasswordHashRecord,
}

impl Debug for PasswordCredentialSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordCredentialSnapshot")
            .field("subject", &self.subject)
            .field("version", &self.version)
            .field("hash_policy_version", &self.hash_policy_version)
            .field("hash_record", &"<redacted>")
            .finish()
    }
}

/// An immutable tenant-bound password credential.
#[derive(Clone, Eq, PartialEq)]
pub struct PasswordCredential {
    subject: PasswordCredentialSubject,
    version: PasswordCredentialVersion,
    hash_policy_version: PasswordHashPolicyVersion,
    hash_record: PasswordHashRecord,
    hash_parameters: Argon2idParameters,
}

impl PasswordCredential {
    /// Reconstructs a credential from one complete typed persistence snapshot.
    ///
    /// The boundary revalidates the PHC record and retains its parsed Argon2id
    /// parameters for deterministic rehash decisions. It never accepts a
    /// plaintext password.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidCredentialArgument`] when the PHC
    /// record cannot satisfy its validated construction invariant.
    pub fn from_snapshot(snapshot: PasswordCredentialSnapshot) -> Result<Self, PasswordError> {
        let hash_parameters = snapshot
            .hash_record
            .parameters()
            .map_err(|_| invalid_credential_argument())?;
        Ok(Self {
            subject: snapshot.subject,
            version: snapshot.version,
            hash_policy_version: snapshot.hash_policy_version,
            hash_record: snapshot.hash_record,
            hash_parameters,
        })
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.subject.tenant_id()
    }

    /// Returns the credential owner within the tenant boundary.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        self.subject.user_id()
    }

    /// Returns the current optimistic credential version.
    #[must_use]
    pub const fn version(&self) -> PasswordCredentialVersion {
        self.version
    }

    /// Returns the policy version that produced the current hash.
    #[must_use]
    pub const fn hash_policy_version(&self) -> PasswordHashPolicyVersion {
        self.hash_policy_version
    }

    /// Returns the redacted self-describing PHC record.
    #[must_use]
    pub const fn hash_record(&self) -> &PasswordHashRecord {
        &self.hash_record
    }

    /// Returns the Argon2id parameters parsed from the PHC record.
    #[must_use]
    pub const fn hash_parameters(&self) -> Argon2idParameters {
        self.hash_parameters
    }

    /// Returns every durable field needed for lossless reconstruction.
    #[must_use]
    pub fn snapshot_state(&self) -> PasswordCredentialSnapshot {
        PasswordCredentialSnapshot {
            subject: self.subject.clone(),
            version: self.version,
            hash_policy_version: self.hash_policy_version,
            hash_record: self.hash_record.clone(),
        }
    }
}

/// A complete credential replacement produced by a password-reset transition.
///
/// The expected version is the credential version immutably bound at reset
/// issuance. `credential` is the exact one-step successor for the same tenant
/// and user, with the replacement PHC record and its chosen hash-policy
/// version. The record remains redacted by the credential's `Debug`
/// implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordCredentialReplacement {
    expected_version: PasswordCredentialVersion,
    credential: PasswordCredential,
}

impl PasswordCredentialReplacement {
    pub(crate) fn new(
        subject: PasswordCredentialSubject,
        expected_version: PasswordCredentialVersion,
        resulting_hash_policy_version: PasswordHashPolicyVersion,
        hash_record: PasswordHashRecord,
    ) -> Result<Self, PasswordError> {
        let resulting_version = expected_version.next()?;
        let credential = PasswordCredential::from_snapshot(PasswordCredentialSnapshot {
            subject,
            version: resulting_version,
            hash_policy_version: resulting_hash_policy_version,
            hash_record,
        })?;
        Ok(Self {
            expected_version,
            credential,
        })
    }

    /// Returns the exact credential version observed at reset issuance.
    #[must_use]
    pub const fn expected_version(&self) -> PasswordCredentialVersion {
        self.expected_version
    }

    /// Returns the complete replacement credential for atomic persistence.
    #[must_use]
    pub const fn credential(&self) -> &PasswordCredential {
        &self.credential
    }

    /// Returns the exact one-step successor committed for the credential.
    #[must_use]
    pub const fn resulting_version(&self) -> PasswordCredentialVersion {
        self.credential.version()
    }

    /// Returns the policy version that produced the replacement PHC record.
    #[must_use]
    pub const fn resulting_hash_policy_version(&self) -> PasswordHashPolicyVersion {
        self.credential.hash_policy_version()
    }
}

impl Debug for PasswordCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordCredential")
            .field("subject", &self.subject)
            .field("version", &self.version)
            .field("hash_policy_version", &self.hash_policy_version)
            .field("hash_record", &"<redacted>")
            .field("hash_parameters", &self.hash_parameters)
            .finish()
    }
}

const fn invalid_credential_argument() -> PasswordError {
    PasswordError::new(PasswordErrorCode::InvalidCredentialArgument)
}

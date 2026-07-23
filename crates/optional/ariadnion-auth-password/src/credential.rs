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

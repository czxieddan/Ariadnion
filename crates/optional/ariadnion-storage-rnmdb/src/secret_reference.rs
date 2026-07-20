//! Bounded values for encrypted, tenant-owned secret references.

use std::fmt::{self, Debug, Display, Formatter};

use ariadnion_core::TenantId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_REFERENCE_ID_BYTES: usize = 128;
const MAX_REFERENCE_KIND_BYTES: usize = 64;
const MAX_SECRET_LOCATOR_BYTES: usize = 4_096;

/// A bounded identifier for one secret reference within a tenant.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretReferenceId(Box<str>);

impl SecretReferenceId {
    /// Parses an ASCII identifier with a 128-byte upper bound.
    ///
    /// Identifiers may contain ASCII letters, digits, dots, hyphens,
    /// underscores, and colons. Invalid values are never retained in errors.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_reference_id(value) {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for SecretReferenceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretReferenceId")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for SecretReferenceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded, stable category for a secret-reference locator.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretReferenceKind(Box<str>);

impl SecretReferenceKind {
    /// Parses a lower-case ASCII category with a 64-byte upper bound.
    ///
    /// Categories start with a letter and may then contain lower-case
    /// letters, digits, dots, hyphens, and underscores.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_reference_kind(value) {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated category.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for SecretReferenceKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretReferenceKind")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for SecretReferenceKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded secret locator that is redacted and cleared on drop.
pub struct SecretLocator(Box<str>);

impl SecretLocator {
    /// Takes ownership of a non-empty locator with a 4,096-byte upper bound.
    ///
    /// Leading or trailing whitespace and control characters are rejected.
    /// Callers must continue to treat the value returned by [`Self::as_str`]
    /// as sensitive data.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_secret_locator(value) {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Borrows the sensitive locator value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for SecretLocator {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretLocator(<redacted>)")
    }
}

impl Zeroize for SecretLocator {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretLocator {}

impl Drop for SecretLocator {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A positive key version representable by RNMDB's signed 64-bit integer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretKeyVersion(i64);

impl SecretKeyVersion {
    /// Creates a positive key version.
    pub fn new(value: i64) -> Result<Self, StorageError> {
        if value <= 0 {
            return Err(invalid_argument());
        }
        Ok(Self(value))
    }

    /// Returns the positive database representation.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Validated values required to create one tenant-owned secret reference.
#[derive(Debug)]
pub struct NewSecretReference {
    reference_id: SecretReferenceId,
    kind: SecretReferenceKind,
    locator: SecretLocator,
    key_version: SecretKeyVersion,
}

impl NewSecretReference {
    /// Creates a fully validated insert value.
    #[must_use]
    pub fn new(
        reference_id: SecretReferenceId,
        kind: SecretReferenceKind,
        locator: SecretLocator,
        key_version: SecretKeyVersion,
    ) -> Self {
        Self {
            reference_id,
            kind,
            locator,
            key_version,
        }
    }

    /// Returns the tenant-local reference identifier.
    #[must_use]
    pub const fn reference_id(&self) -> &SecretReferenceId {
        &self.reference_id
    }

    /// Returns the reference category.
    #[must_use]
    pub const fn kind(&self) -> &SecretReferenceKind {
        &self.kind
    }

    /// Borrows the sensitive locator.
    #[must_use]
    pub const fn locator(&self) -> &SecretLocator {
        &self.locator
    }

    /// Returns the locator key version.
    #[must_use]
    pub const fn key_version(&self) -> SecretKeyVersion {
        self.key_version
    }
}

/// Validated replacement values for an existing secret reference.
#[derive(Debug)]
pub struct SecretReferenceUpdate {
    reference_id: SecretReferenceId,
    kind: SecretReferenceKind,
    locator: SecretLocator,
    key_version: SecretKeyVersion,
}

impl SecretReferenceUpdate {
    /// Creates a fully validated update value.
    #[must_use]
    pub fn new(
        reference_id: SecretReferenceId,
        kind: SecretReferenceKind,
        locator: SecretLocator,
        key_version: SecretKeyVersion,
    ) -> Self {
        Self {
            reference_id,
            kind,
            locator,
            key_version,
        }
    }

    /// Returns the tenant-local reference identifier.
    #[must_use]
    pub const fn reference_id(&self) -> &SecretReferenceId {
        &self.reference_id
    }

    /// Returns the replacement category.
    #[must_use]
    pub const fn kind(&self) -> &SecretReferenceKind {
        &self.kind
    }

    /// Borrows the replacement locator.
    #[must_use]
    pub const fn locator(&self) -> &SecretLocator {
        &self.locator
    }

    /// Returns the replacement key version.
    #[must_use]
    pub const fn key_version(&self) -> SecretKeyVersion {
        self.key_version
    }
}

/// One decoded tenant-owned secret-reference record.
#[derive(Debug)]
pub struct SecretReference {
    tenant_id: TenantId,
    reference_id: SecretReferenceId,
    kind: SecretReferenceKind,
    locator: SecretLocator,
    key_version: SecretKeyVersion,
}

impl SecretReference {
    pub(crate) fn from_persisted(
        tenant_id: TenantId,
        reference_id: SecretReferenceId,
        kind: SecretReferenceKind,
        locator: SecretLocator,
        key_version: SecretKeyVersion,
    ) -> Self {
        Self {
            tenant_id,
            reference_id,
            kind,
            locator,
            key_version,
        }
    }

    /// Returns the tenant identity persisted with the reference.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the tenant-local reference identifier.
    #[must_use]
    pub const fn reference_id(&self) -> &SecretReferenceId {
        &self.reference_id
    }

    /// Returns the reference category.
    #[must_use]
    pub const fn kind(&self) -> &SecretReferenceKind {
        &self.kind
    }

    /// Borrows the decrypted locator.
    #[must_use]
    pub const fn locator(&self) -> &SecretLocator {
        &self.locator
    }

    /// Returns the locator key version.
    #[must_use]
    pub const fn key_version(&self) -> SecretKeyVersion {
        self.key_version
    }

    /// Moves the decrypted locator out for immediate secret resolution.
    #[must_use]
    pub fn into_locator(self) -> SecretLocator {
        self.locator
    }
}

fn valid_reference_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REFERENCE_ID_BYTES
        && value.is_ascii()
        && !value.bytes().any(disallowed_reference_id_byte)
}

fn disallowed_reference_id_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_' | b':')
}

fn valid_reference_kind(value: &str) -> bool {
    let starts_with_letter = value.as_bytes().first().is_some_and(u8::is_ascii_lowercase);
    starts_with_letter
        && value.len() <= MAX_REFERENCE_KIND_BYTES
        && value.bytes().all(valid_reference_kind_byte)
}

fn valid_reference_kind_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
}

fn valid_secret_locator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SECRET_LOCATOR_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

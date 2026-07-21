//! Bounded API-key identities and optimistic versions.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;

use crate::error::error;
use crate::{ApiKeyError, ApiKeyErrorCode};

const MAX_IDENTIFIER_BYTES: usize = 128;

/// A bounded path-free API-key aggregate identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApiKeyId(Box<str>);

impl ApiKeyId {
    /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyErrorCode::InvalidArgument`] without retaining the
    /// rejected value when its length or alphabet is invalid.
    pub fn parse(value: &str) -> Result<Self, ApiKeyError> {
        if !valid_identifier(value) {
            return Err(error(ApiKeyErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ApiKeyId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyId(<opaque>)")
    }
}

/// A non-zero optimistic version for one API-key aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApiKeyVersion(NonZeroU64);

impl ApiKeyVersion {
    /// Returns the version assigned during issuance.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic version.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, ApiKeyError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic version.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, ApiKeyError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(ApiKeyErrorCode::VersionExhausted))
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

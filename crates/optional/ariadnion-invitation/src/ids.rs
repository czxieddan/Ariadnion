//! Bounded invitation identities and optimistic versions.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;

use crate::error::error;
use crate::{InvitationError, InvitationErrorCode};

const MAX_IDENTIFIER_BYTES: usize = 128;

/// A bounded path-free invitation aggregate identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InvitationId(Box<str>);

impl InvitationId {
    /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
    ///
    /// # Errors
    /// Returns [`InvitationErrorCode::InvalidArgument`] without retaining the
    /// rejected value when its length or alphabet is invalid.
    pub fn parse(value: &str) -> Result<Self, InvitationError> {
        if !valid_identifier(value) {
            return Err(error(InvitationErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for InvitationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationId(<opaque>)")
    }
}

/// A non-zero optimistic version for one invitation aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InvitationVersion(NonZeroU64);

impl InvitationVersion {
    /// Returns the version assigned during issuance.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic version.
    ///
    /// # Errors
    /// Returns [`InvitationErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, InvitationError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(InvitationErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic version.
    ///
    /// # Errors
    /// Returns [`InvitationErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, InvitationError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(InvitationErrorCode::VersionExhausted))
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

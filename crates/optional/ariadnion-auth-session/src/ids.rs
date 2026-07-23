//! Bounded session identities and optimistic versions.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;

use crate::error::error;
use crate::{SessionError, SessionErrorCode};

const MAX_IDENTIFIER_BYTES: usize = 128;

/// A bounded path-free session-family aggregate identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionFamilyId(Box<str>);

impl SessionFamilyId {
    /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SessionErrorCode::InvalidArgument`] without retaining the
    /// rejected value when its length or alphabet is invalid.
    pub fn parse(value: &str) -> Result<Self, SessionError> {
        if !valid_identifier(value) {
            return Err(error(SessionErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for SessionFamilyId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionFamilyId(<opaque>)")
    }
}

/// A bounded path-free leaf session identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(Box<str>);

impl SessionId {
    /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SessionErrorCode::InvalidArgument`] without retaining the
    /// rejected value when its length or alphabet is invalid.
    pub fn parse(value: &str) -> Result<Self, SessionError> {
        if !valid_identifier(value) {
            return Err(error(SessionErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for SessionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId(<opaque>)")
    }
}

/// A non-zero optimistic version for one session family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionFamilyVersion(NonZeroU64);

impl SessionFamilyVersion {
    /// Returns the version assigned during family issuance.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic family version.
    ///
    /// # Errors
    ///
    /// Returns [`SessionErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, SessionError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(SessionErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic family version.
    ///
    /// # Errors
    ///
    /// Returns [`SessionErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, SessionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(SessionErrorCode::VersionExhausted))
    }
}

/// A non-zero optimistic version for one leaf session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionVersion(NonZeroU64);

impl SessionVersion {
    /// Returns the version assigned during leaf issuance or rotation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic session version.
    ///
    /// # Errors
    ///
    /// Returns [`SessionErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, SessionError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(SessionErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic leaf-session version.
    ///
    /// # Errors
    ///
    /// Returns [`SessionErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, SessionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(SessionErrorCode::VersionExhausted))
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

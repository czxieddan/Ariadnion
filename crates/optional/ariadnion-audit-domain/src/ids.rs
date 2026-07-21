//! Bounded audit identities and sequences.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;

use crate::error::error;
use crate::{AuditError, AuditErrorCode};

const MAX_IDENTIFIER_BYTES: usize = 128;

/// A bounded path-free audit-event identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditEventId(Box<str>);

impl AuditEventId {
    /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::InvalidArgument`] without retaining rejected input.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        if !valid_identifier(value) {
            return Err(error(AuditErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AuditEventId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditEventId(<opaque>)")
    }
}

/// A non-zero append-only audit sequence number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditSequence(NonZeroU64);

impl AuditSequence {
    /// Returns the first sequence number.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, AuditError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(AuditErrorCode::InvalidArgument))
    }

    /// Returns the numeric sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::SequenceExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, AuditError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AuditErrorCode::SequenceExhausted))
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

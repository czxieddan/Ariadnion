//! Stable redacted failures for audit-domain operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by audit-domain operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AuditErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The sequence cannot be incremented.
    SequenceExhausted,
    /// A persisted chain digest did not match canonical event material.
    DigestMismatch,
    /// A persisted event used an unsupported chain digest schema version.
    UnsupportedVersion,
}

impl AuditErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "AUDIT_INVALID_ARGUMENT",
            Self::SequenceExhausted => "AUDIT_SEQUENCE_EXHAUSTED",
            Self::DigestMismatch => "AUDIT_DIGEST_MISMATCH",
            Self::UnsupportedVersion => "AUDIT_UNSUPPORTED_VERSION",
        }
    }
}

/// A redacted audit-domain error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditError {
    code: AuditErrorCode,
}

impl AuditError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: AuditErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AuditErrorCode {
        self.code
    }
}

impl Display for AuditError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AuditError {}

/// Builds a redacted error without retaining rejected values.
#[must_use]
pub(crate) const fn error(code: AuditErrorCode) -> AuditError {
    AuditError::new(code)
}

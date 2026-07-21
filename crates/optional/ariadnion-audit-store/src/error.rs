//! Stable redacted failures for audit-store operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by audit-store operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AuditStoreErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The append crossed a different tenant boundary.
    TenantMismatch,
    /// The append sequence was not the exact next sequence.
    SequenceGap,
    /// The previous chain digest did not match the log tip.
    ChainBreak,
    /// The event identity was already present.
    DuplicateEvent,
    /// The requested export range was empty or inverted.
    EmptyRange,
}

impl AuditStoreErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "AUDIT_STORE_INVALID_ARGUMENT",
            Self::TenantMismatch => "AUDIT_STORE_TENANT_MISMATCH",
            Self::SequenceGap => "AUDIT_STORE_SEQUENCE_GAP",
            Self::ChainBreak => "AUDIT_STORE_CHAIN_BREAK",
            Self::DuplicateEvent => "AUDIT_STORE_DUPLICATE_EVENT",
            Self::EmptyRange => "AUDIT_STORE_EMPTY_RANGE",
        }
    }
}

/// A redacted audit-store error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditStoreError {
    code: AuditStoreErrorCode,
}

impl AuditStoreError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: AuditStoreErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AuditStoreErrorCode {
        self.code
    }
}

impl Display for AuditStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AuditStoreError {}

/// Builds a redacted error without retaining rejected values.
#[must_use]
pub(crate) const fn error(code: AuditStoreErrorCode) -> AuditStoreError {
    AuditStoreError::new(code)
}

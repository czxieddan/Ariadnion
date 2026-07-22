//! Stable redacted failures for audit-store operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by audit-store operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum AuditStoreErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument = 0,
    /// The append crossed a different tenant boundary.
    TenantMismatch = 1,
    /// The append sequence was not the exact next sequence.
    SequenceGap = 2,
    /// The previous chain digest did not match the log tip.
    ChainBreak = 3,
    /// The event identity was already present.
    DuplicateEvent = 4,
    /// The requested export range was empty or inverted.
    EmptyRange = 5,
    /// The stored event digest did not match canonical event material.
    DigestMismatch = 6,
    /// The in-memory verification boundary was exceeded.
    ResourceLimitExceeded = 7,
    /// A persisted chain component used an unsupported digest schema version.
    UnsupportedVersion = 8,
    /// The requested export range was only partially available.
    IncompleteRange = 9,
}

const AUDIT_STORE_ERROR_CODES: [&str; 10] = [
    "AUDIT_STORE_INVALID_ARGUMENT",
    "AUDIT_STORE_TENANT_MISMATCH",
    "AUDIT_STORE_SEQUENCE_GAP",
    "AUDIT_STORE_CHAIN_BREAK",
    "AUDIT_STORE_DUPLICATE_EVENT",
    "AUDIT_STORE_EMPTY_RANGE",
    "AUDIT_STORE_DIGEST_MISMATCH",
    "AUDIT_STORE_RESOURCE_LIMIT_EXCEEDED",
    "AUDIT_STORE_UNSUPPORTED_VERSION",
    "AUDIT_STORE_INCOMPLETE_RANGE",
];

impl AuditStoreErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        AUDIT_STORE_ERROR_CODES[self as usize]
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

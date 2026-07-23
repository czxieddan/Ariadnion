//! Stable redacted failures for browser session-family operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by session-family operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum SessionErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument = 0,
    /// The command expected a different optimistic family version.
    VersionConflict = 1,
    /// The monotonic family version cannot be incremented.
    VersionExhausted = 2,
    /// The bounded rotated-leaf history cannot accept another session.
    ResourceLimitExceeded = 3,
    /// The command crossed a different tenant boundary.
    TenantMismatch = 4,
    /// The command crossed a different user boundary.
    UserMismatch = 5,
    /// The presented family identity did not match the aggregate.
    FamilyMismatch = 6,
    /// The presented session identity did not match the active leaf.
    SessionMismatch = 7,
    /// The presented token digest did not match the active leaf.
    TokenMismatch = 8,
    /// The command arrived before the trusted session chronology.
    NotYetValid = 9,
    /// The exclusive absolute or idle expiry boundary was reached.
    Expired = 10,
    /// An explicit expiry transition was requested before the boundary.
    NotYetExpired = 11,
    /// The leaf is no longer active for rotation.
    InactiveLeaf = 12,
    /// The family is already terminal.
    FamilyTerminal = 13,
    /// A rotated token was presented again and the family was revoked.
    TokenReuseDetected = 14,
}

const SESSION_ERROR_CODES: [&str; 15] = [
    "SESSION_INVALID_ARGUMENT",
    "SESSION_VERSION_CONFLICT",
    "SESSION_VERSION_EXHAUSTED",
    "SESSION_RESOURCE_LIMIT_EXCEEDED",
    "SESSION_TENANT_MISMATCH",
    "SESSION_USER_MISMATCH",
    "SESSION_FAMILY_MISMATCH",
    "SESSION_SESSION_MISMATCH",
    "SESSION_TOKEN_MISMATCH",
    "SESSION_NOT_YET_VALID",
    "SESSION_EXPIRED",
    "SESSION_NOT_YET_EXPIRED",
    "SESSION_INACTIVE_LEAF",
    "SESSION_FAMILY_TERMINAL",
    "SESSION_TOKEN_REUSE_DETECTED",
];

impl SessionErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        SESSION_ERROR_CODES[self as usize]
    }
}

/// A redacted session-domain error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionError {
    code: SessionErrorCode,
}

impl SessionError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: SessionErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> SessionErrorCode {
        self.code
    }
}

impl Display for SessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for SessionError {}

/// Builds a redacted error without retaining rejected values.
#[must_use]
pub(crate) const fn error(code: SessionErrorCode) -> SessionError {
    SessionError::new(code)
}

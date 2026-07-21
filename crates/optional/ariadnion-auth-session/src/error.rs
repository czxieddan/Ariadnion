//! Stable redacted failures for browser session-family operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by session-family operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SessionErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The command expected a different optimistic family version.
    VersionConflict,
    /// The monotonic family version cannot be incremented.
    VersionExhausted,
    /// The command crossed a different tenant boundary.
    TenantMismatch,
    /// The command crossed a different user boundary.
    UserMismatch,
    /// The presented family identity did not match the aggregate.
    FamilyMismatch,
    /// The presented session identity did not match the active leaf.
    SessionMismatch,
    /// The presented token digest did not match the active leaf.
    TokenMismatch,
    /// The command arrived before the trusted issuance time.
    NotYetValid,
    /// The exclusive absolute or idle expiry boundary was reached.
    Expired,
    /// An explicit expiry transition was requested before the boundary.
    NotYetExpired,
    /// The leaf is no longer active for rotation.
    InactiveLeaf,
    /// The family is already terminal.
    FamilyTerminal,
    /// A rotated token was presented again and the family was revoked.
    TokenReuseDetected,
}

impl SessionErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "SESSION_INVALID_ARGUMENT",
            Self::VersionConflict => "SESSION_VERSION_CONFLICT",
            Self::VersionExhausted => "SESSION_VERSION_EXHAUSTED",
            Self::TenantMismatch => "SESSION_TENANT_MISMATCH",
            Self::UserMismatch => "SESSION_USER_MISMATCH",
            Self::FamilyMismatch => "SESSION_FAMILY_MISMATCH",
            Self::SessionMismatch => "SESSION_SESSION_MISMATCH",
            Self::TokenMismatch => "SESSION_TOKEN_MISMATCH",
            Self::NotYetValid => "SESSION_NOT_YET_VALID",
            Self::Expired => "SESSION_EXPIRED",
            Self::NotYetExpired => "SESSION_NOT_YET_EXPIRED",
            Self::InactiveLeaf => "SESSION_INACTIVE_LEAF",
            Self::FamilyTerminal => "SESSION_FAMILY_TERMINAL",
            Self::TokenReuseDetected => "SESSION_TOKEN_REUSE_DETECTED",
        }
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

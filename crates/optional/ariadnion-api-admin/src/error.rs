//! Stable redacted failures for administration commands.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by administration commands.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AdminErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The authoritative policy denied the command or trusted target state was
    /// incompatible with the requested action.
    AuthorizationDenied,
    /// The command crossed a different tenant boundary.
    TenantMismatch,
    /// The internally evaluated decision did not match its command binding.
    DecisionMismatch,
    /// The request has no authenticated principal.
    Unauthenticated,
    /// The request was cancelled before durable application.
    Cancelled,
    /// The request deadline expired before durable application.
    DeadlineExceeded,
    /// Mutable state or idempotent command material no longer matches.
    Conflict,
    /// A required authoritative adapter is unavailable.
    Unavailable,
    /// Durable commit may have completed and requires identity reconciliation.
    CommitIndeterminate,
    /// Trusted or durable facts failed closed integrity validation.
    IntegrityFailure,
}

impl AdminErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ADMIN_INVALID_ARGUMENT",
            Self::AuthorizationDenied => "ADMIN_AUTHORIZATION_DENIED",
            Self::TenantMismatch => "ADMIN_TENANT_MISMATCH",
            Self::DecisionMismatch => "ADMIN_DECISION_MISMATCH",
            Self::Unauthenticated => "ADMIN_UNAUTHENTICATED",
            Self::Cancelled => "ADMIN_CANCELLED",
            Self::DeadlineExceeded => "ADMIN_DEADLINE_EXCEEDED",
            Self::Conflict => "ADMIN_CONFLICT",
            Self::Unavailable => "ADMIN_UNAVAILABLE",
            Self::CommitIndeterminate => "ADMIN_COMMIT_INDETERMINATE",
            Self::IntegrityFailure => "ADMIN_INTEGRITY_FAILURE",
        }
    }
}

/// A redacted administration error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminError {
    code: AdminErrorCode,
}

impl AdminError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: AdminErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AdminErrorCode {
        self.code
    }
}

impl Display for AdminError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AdminError {}

/// Builds a redacted error without retaining rejected values.
#[must_use]
pub(crate) const fn error(code: AdminErrorCode) -> AdminError {
    AdminError::new(code)
}

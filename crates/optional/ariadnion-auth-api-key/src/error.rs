//! Stable redacted failures for API-key operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by API-key operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ApiKeyErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The command expected a different optimistic version.
    VersionConflict,
    /// The monotonic version cannot be incremented.
    VersionExhausted,
    /// The command crossed a different tenant boundary.
    TenantMismatch,
    /// The command crossed a different owner boundary.
    OwnerMismatch,
    /// The presented key identity did not match the aggregate.
    KeyMismatch,
    /// The presented prefix did not match the aggregate.
    PrefixMismatch,
    /// The presented secret digest did not match an active secret.
    SecretMismatch,
    /// The exclusive expiry boundary was reached.
    Expired,
    /// An explicit expiry transition was requested before the boundary.
    NotYetExpired,
    /// The API key is already terminal.
    Terminal,
    /// Presentation lacked a required scope.
    ScopeDenied,
    /// The command arrived before the trusted issuance time.
    NotYetValid,
}

impl ApiKeyErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "API_KEY_INVALID_ARGUMENT",
            Self::VersionConflict => "API_KEY_VERSION_CONFLICT",
            Self::VersionExhausted => "API_KEY_VERSION_EXHAUSTED",
            Self::TenantMismatch => "API_KEY_TENANT_MISMATCH",
            Self::OwnerMismatch => "API_KEY_OWNER_MISMATCH",
            Self::KeyMismatch => "API_KEY_KEY_MISMATCH",
            Self::PrefixMismatch => "API_KEY_PREFIX_MISMATCH",
            Self::SecretMismatch => "API_KEY_SECRET_MISMATCH",
            Self::Expired => "API_KEY_EXPIRED",
            Self::NotYetExpired => "API_KEY_NOT_YET_EXPIRED",
            Self::Terminal => "API_KEY_TERMINAL",
            Self::ScopeDenied => "API_KEY_SCOPE_DENIED",
            Self::NotYetValid => "API_KEY_NOT_YET_VALID",
        }
    }
}

/// A redacted API-key error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyError {
    code: ApiKeyErrorCode,
}

impl ApiKeyError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: ApiKeyErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ApiKeyErrorCode {
        self.code
    }
}

impl Display for ApiKeyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ApiKeyError {}

/// Builds a redacted error without retaining rejected values.
#[must_use]
pub(crate) const fn error(code: ApiKeyErrorCode) -> ApiKeyError {
    ApiKeyError::new(code)
}

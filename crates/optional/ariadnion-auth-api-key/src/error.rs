//! Stable redacted failures for API-key operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by API-key operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum ApiKeyErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument = 0,
    /// The command expected a different optimistic version.
    VersionConflict = 1,
    /// The monotonic version cannot be incremented.
    VersionExhausted = 2,
    /// A new rotation was requested while a previous secret is still overlapping.
    RotationInProgress = 3,
    /// A previously retired secret digest was submitted again.
    SecretReuseDetected = 4,
    /// The bounded retired-secret history cannot accept another digest.
    ResourceLimitExceeded = 5,
    /// The command crossed a different tenant boundary.
    TenantMismatch = 6,
    /// The command crossed a different owner boundary.
    OwnerMismatch = 7,
    /// The presented key identity did not match the aggregate.
    KeyMismatch = 8,
    /// The presented prefix did not match the aggregate.
    PrefixMismatch = 9,
    /// The presented secret digest did not match an active secret.
    SecretMismatch = 10,
    /// The exclusive expiry boundary was reached.
    Expired = 11,
    /// An explicit expiry transition was requested before the boundary.
    NotYetExpired = 12,
    /// The API key is already terminal.
    Terminal = 13,
    /// Presentation lacked a required scope.
    ScopeDenied = 14,
    /// The command arrived before the trusted issuance time.
    NotYetValid = 15,
}

const API_KEY_ERROR_CODES: [&str; 16] = [
    "API_KEY_INVALID_ARGUMENT",
    "API_KEY_VERSION_CONFLICT",
    "API_KEY_VERSION_EXHAUSTED",
    "API_KEY_ROTATION_IN_PROGRESS",
    "API_KEY_SECRET_REUSE_DETECTED",
    "API_KEY_RESOURCE_LIMIT_EXCEEDED",
    "API_KEY_TENANT_MISMATCH",
    "API_KEY_OWNER_MISMATCH",
    "API_KEY_KEY_MISMATCH",
    "API_KEY_PREFIX_MISMATCH",
    "API_KEY_SECRET_MISMATCH",
    "API_KEY_EXPIRED",
    "API_KEY_NOT_YET_EXPIRED",
    "API_KEY_TERMINAL",
    "API_KEY_SCOPE_DENIED",
    "API_KEY_NOT_YET_VALID",
];

impl ApiKeyErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        API_KEY_ERROR_CODES[self as usize]
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

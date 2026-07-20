//! Stable authorization construction errors.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Stable machine-readable failures returned while constructing policy data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorizationErrorCode {
    /// A value failed structural validation.
    InvalidArgument,
    /// A bounded collection exceeded its public limit.
    ResourceLimitExceeded,
    /// A policy contains duplicate stable identities.
    DuplicateIdentity,
    /// Policy data crosses a tenant boundary.
    TenantMismatch,
    /// An assignment refers to a role absent from the policy.
    UnknownRole,
}

impl AuthorizationErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "RBAC_INVALID_ARGUMENT",
            Self::ResourceLimitExceeded => "RBAC_RESOURCE_LIMIT_EXCEEDED",
            Self::DuplicateIdentity => "RBAC_DUPLICATE_IDENTITY",
            Self::TenantMismatch => "RBAC_TENANT_MISMATCH",
            Self::UnknownRole => "RBAC_UNKNOWN_ROLE",
        }
    }
}

/// A redacted authorization construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationError {
    code: AuthorizationErrorCode,
}

impl AuthorizationError {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> AuthorizationErrorCode {
        self.code
    }
}

impl Display for AuthorizationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for AuthorizationError {}

pub(crate) const fn error(code: AuthorizationErrorCode) -> AuthorizationError {
    AuthorizationError { code }
}

//! Stable redacted invitation-domain failures.

use std::fmt::{self, Display, Formatter};

const ERROR_CODES: [&str; 13] = [
    "INVITATION_INVALID_ARGUMENT",
    "INVITATION_VERSION_CONFLICT",
    "INVITATION_VERSION_EXHAUSTED",
    "INVITATION_TENANT_MISMATCH",
    "INVITATION_ORGANIZATION_MISMATCH",
    "INVITATION_SUBJECT_MISMATCH",
    "INVITATION_TOKEN_MISMATCH",
    "INVITATION_EXPIRED",
    "INVITATION_NOT_YET_EXPIRED",
    "INVITATION_ALREADY_CONSUMED",
    "INVITATION_REVOKED",
    "INVITATION_INVALID_TRANSITION",
    "INVITATION_RECIPIENT_PRINCIPAL_MISMATCH",
];

/// Stable machine-readable invitation-domain failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum InvitationErrorCode {
    /// An identifier, timestamp, digest, or bounded input is invalid.
    InvalidArgument,
    /// The caller supplied a stale optimistic aggregate version.
    VersionConflict,
    /// The aggregate version cannot advance beyond `u64::MAX`.
    VersionExhausted,
    /// Consumption evidence belongs to another tenant.
    TenantMismatch,
    /// Consumption evidence belongs to another organization.
    OrganizationMismatch,
    /// The intended recipient digest does not match.
    SubjectMismatch,
    /// The presented one-way token digest does not match.
    TokenMismatch,
    /// The invitation has expired or the expiry boundary was reached.
    Expired,
    /// Expiry was requested before the declared UTC boundary.
    NotYetExpired,
    /// A consumed invitation rejected another command.
    AlreadyConsumed,
    /// A revoked invitation rejected another command.
    Revoked,
    /// The requested transition is not valid from the current state.
    InvalidTransition,
    /// The command actor is not the authenticated invitation recipient.
    RecipientPrincipalMismatch,
}

impl InvitationErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        ERROR_CODES[self as usize]
    }
}

/// A redacted invitation-domain failure that retains no identifiers or proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationError {
    code: InvitationErrorCode,
}

impl InvitationError {
    /// Creates an error from one stable code.
    #[must_use]
    pub const fn new(code: InvitationErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable error code.
    #[must_use]
    pub const fn code(self) -> InvitationErrorCode {
        self.code
    }
}

impl Display for InvitationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for InvitationError {}

pub(crate) const fn error(code: InvitationErrorCode) -> InvitationError {
    InvitationError::new(code)
}

//! Stable organization-domain errors with redacted formatting.

use std::fmt::{self, Display, Formatter};

/// Stable machine-readable failures returned by organization operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum OrganizationErrorCode {
    /// A value is malformed or outside its documented bound.
    InvalidArgument = 0,
    /// The command expected a different optimistic organization version.
    VersionConflict = 1,
    /// The monotonic organization version cannot be incremented.
    VersionExhausted = 2,
    /// A bounded collection cannot accept another element.
    CapacityExceeded = 3,
    /// The requested membership does not exist.
    MembershipNotFound = 4,
    /// The requested team does not exist.
    TeamNotFound = 5,
    /// A stable identity is already present in the aggregate.
    DuplicateIdentity = 6,
    /// The requested transition is invalid from the current state.
    InvalidTransition = 7,
    /// The operation would leave no active owner.
    LastActiveOwner = 8,
    /// A membership is inactive, expired, or otherwise ineligible.
    MembershipIneligible = 9,
    /// Ownership evidence is bound to another tenant, organization, or version.
    TransferOrganizationMismatch = 10,
    /// Recipient reauthentication is absent, future-dated, or stale.
    TransferReauthenticationStale = 11,
    /// The transfer approver is not distinct from the initiating actor.
    TransferApproverConflict = 12,
    /// The transfer was attempted before its not-before boundary.
    TransferNotReady = 13,
    /// The transfer evidence has passed its expiry boundary.
    TransferExpired = 14,
    /// Ownership evidence is structurally invalid or binds invalid members.
    TransferEvidenceInvalid = 15,
}

const ERROR_CODES: [&str; 16] = [
    "ORGANIZATION_INVALID_ARGUMENT",
    "ORGANIZATION_VERSION_CONFLICT",
    "ORGANIZATION_VERSION_EXHAUSTED",
    "ORGANIZATION_CAPACITY_EXCEEDED",
    "ORGANIZATION_MEMBERSHIP_NOT_FOUND",
    "ORGANIZATION_TEAM_NOT_FOUND",
    "ORGANIZATION_DUPLICATE_IDENTITY",
    "ORGANIZATION_INVALID_TRANSITION",
    "ORGANIZATION_LAST_ACTIVE_OWNER",
    "ORGANIZATION_MEMBERSHIP_INELIGIBLE",
    "ORGANIZATION_TRANSFER_ORGANIZATION_MISMATCH",
    "ORGANIZATION_TRANSFER_REAUTHENTICATION_STALE",
    "ORGANIZATION_TRANSFER_APPROVER_CONFLICT",
    "ORGANIZATION_TRANSFER_NOT_READY",
    "ORGANIZATION_TRANSFER_EXPIRED",
    "ORGANIZATION_TRANSFER_EVIDENCE_INVALID",
];

impl OrganizationErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        ERROR_CODES[self as usize]
    }
}

/// A redacted organization-domain error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrganizationError {
    code: OrganizationErrorCode,
}

impl OrganizationError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: OrganizationErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> OrganizationErrorCode {
        self.code
    }
}

impl Display for OrganizationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for OrganizationError {}

pub(crate) const fn error(code: OrganizationErrorCode) -> OrganizationError {
    OrganizationError::new(code)
}

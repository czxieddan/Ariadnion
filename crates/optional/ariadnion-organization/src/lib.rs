//! Pure organization governance types and deterministic state transitions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
pub mod migrations;
mod model;
mod repository;
mod transition;

pub use error::{OrganizationError, OrganizationErrorCode};
pub use ids::{MembershipId, OrganizationId, OrganizationVersion, OwnershipTransferId, TeamId};
pub use model::{
    AuthenticatedUserBinding, MAX_MEMBERSHIPS, MAX_TEAM_ASSIGNMENTS, MAX_TEAMS, Membership,
    MembershipKind, MembershipOrigin, MembershipSnapshot, MembershipState, Organization,
    OrganizationEvent, OrganizationEventKind, OrganizationFounder, OrganizationSnapshot,
    OrganizationState, OrganizationTransition, OwnershipTransferEvidence,
    OwnershipTransferEvidenceInput, RecipientReauthenticationProof, Team, TeamSnapshot,
};
pub use repository::{
    OrganizationCommitReceipt, OrganizationRepositoryError, OrganizationRepositoryErrorCode,
    OrganizationRepositoryPort,
};
pub use transition::{
    CreateOrganizationCommand, MembershipAction, OrganizationAction, OrganizationCommand,
    TeamAction, create_organization, transition,
};

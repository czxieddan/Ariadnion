//! Pure organization governance types and deterministic state transitions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
mod model;
mod transition;

pub use error::{OrganizationError, OrganizationErrorCode};
pub use ids::{MembershipId, OrganizationId, OrganizationVersion, OwnershipTransferId, TeamId};
pub use model::{
    AuthenticatedUserBinding, Membership, MembershipKind, MembershipOrigin, MembershipState,
    Organization, OrganizationEvent, OrganizationEventKind, OrganizationFounder, OrganizationState,
    OrganizationTransition, OwnershipTransferEvidence, OwnershipTransferEvidenceInput,
    RecipientReauthenticationProof, Team,
};
pub use transition::{
    CreateOrganizationCommand, MembershipAction, OrganizationAction, OrganizationCommand,
    TeamAction, create_organization, transition,
};

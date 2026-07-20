//! Tenant-bound one-time organization invitation contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
mod model;
mod transition;

pub use error::{InvitationError, InvitationErrorCode};
pub use ids::{InvitationId, InvitationVersion};
pub use model::{
    Invitation, InvitationIssueRequest, InvitationState, InvitationSubjectDigest,
    InvitationTokenDigest, MAX_INVITATION_LIFETIME_SECONDS,
};
pub use transition::{
    InvitationAction, InvitationCommand, InvitationConsumption, InvitationEvent,
    InvitationEventKind, InvitationTransition, issue, transition,
};

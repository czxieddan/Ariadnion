//! Tenant-bound one-time organization invitation contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
pub mod migrations;
mod model;
mod repository;
mod transition;

pub use error::{InvitationError, InvitationErrorCode};
pub use ids::{InvitationId, InvitationVersion};
pub use model::{
    Invitation, InvitationIssueBinding, InvitationIssueRequest, InvitationProofDigests,
    InvitationSnapshotState, InvitationState, InvitationSubjectDigest, InvitationTokenDigest,
    InvitationValidityWindow, MAX_INVITATION_LIFETIME_SECONDS,
};
pub use repository::{
    InvitationCommitReceipt, InvitationRepositoryError, InvitationRepositoryErrorCode,
    InvitationRepositoryPort,
};
pub use transition::{
    AuthenticatedInvitationRecipient, InvitationAction, InvitationCommand, InvitationConsumption,
    InvitationEvent, InvitationEventKind, InvitationTransition, issue, transition,
};

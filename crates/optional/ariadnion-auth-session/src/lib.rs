//! Pure browser session-family types and deterministic state transitions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
mod model;
mod transition;

pub use error::{SessionError, SessionErrorCode};
pub use ids::{SessionFamilyId, SessionFamilyVersion, SessionId, SessionVersion};
pub use model::{
    MAX_ABSOLUTE_LIFETIME_SECONDS, MAX_IDLE_LIFETIME_SECONDS, MAX_SESSION_TOKEN_BYTES,
    MIN_SESSION_TOKEN_BYTES, Session, SessionFamily, SessionFamilyState, SessionIssueBinding,
    SessionIssueRequest, SessionProofDigest, SessionState, SessionSubject, SessionTokenDigest,
    SessionValidityWindow,
};
pub use transition::{
    SessionAction, SessionCommand, SessionEvent, SessionEventKind, SessionRotation,
    SessionTransition, issue_session, transition_session_family,
};

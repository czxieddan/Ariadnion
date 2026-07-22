//! Pure auditable security-event types.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
pub mod migrations;
mod model;

pub use error::{AuditError, AuditErrorCode};
pub use ids::{AuditEventId, AuditSequence};
pub use model::{
    AUDIT_CHAIN_DIGEST_VERSION, AuditChainDigest, AuditEvent, AuditEventBinding, AuditEventContent,
    AuditEventKind, AuditEventRequest, AuditPayloadDigest, AuditSubject, AuditSubjectDigest,
    AuditSubjectKind, MAX_PAYLOAD_BYTES, MAX_REASON_BYTES, build_audit_event,
    rehydrate_audit_event,
};

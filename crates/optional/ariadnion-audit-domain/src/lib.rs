//! Pure auditable security-event types.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
mod model;

pub use error::{AuditError, AuditErrorCode};
pub use ids::{AuditEventId, AuditSequence};
pub use model::{
    AuditChainDigest, AuditEvent, AuditEventBinding, AuditEventContent, AuditEventKind,
    AuditEventRequest, AuditPayloadDigest, AuditSubject, AuditSubjectKind, MAX_REASON_BYTES,
    build_audit_event,
};

//! Pure tamper-evident audit append and verification contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod store;

pub use error::{AuditStoreError, AuditStoreErrorCode};
pub use store::{
    AuditExportCursor, AuditLogSnapshot, MAX_AUDIT_EXPORT_EVENTS, append_audit_event,
    export_audit_range, verify_audit_chain,
};

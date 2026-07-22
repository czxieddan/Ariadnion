//! Pure tamper-evident audit append and verification contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod store;

pub use error::{AuditStoreError, AuditStoreErrorCode};
pub use store::{
    AuditChainHead, AuditExportCursor, AuditLogSnapshot, MAX_AUDIT_EXPORT_EVENTS,
    MAX_AUDIT_SNAPSHOT_EVENTS, append_audit_event, export_audit_batch, export_audit_range,
    verify_audit_batch, verify_audit_chain,
};

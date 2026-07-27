//! Trusted background administration execution and retry classification.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admin;

pub use admin::{
    AdminJobDisposition, AdminJobEnvelope, AdminJobLeaseId, AdminJobResult, AdminJobRunner,
    MAX_ADMIN_JOB_LEASE_ID_BYTES,
};

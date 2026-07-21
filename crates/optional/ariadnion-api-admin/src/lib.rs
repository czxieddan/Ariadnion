//! Pure initial administration command contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod model;

pub use error::{AdminError, AdminErrorCode};
pub use model::{
    AdminActionKind, AdminCommand, AdminCommandBinding, AdminCommandId, AdminCommandRequest,
    AdminDecision, AdminTarget, AdminTargetKind, accept_admin_command,
};

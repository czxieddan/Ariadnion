//! Authoritative administration command evaluation and durable execution.
//!
//! Protocol callers supply only bounded command intent. [`AdminCommandExecutor`]
//! loads policy, subject, membership, target state, and trusted time through
//! [`AuthoritativePolicyPort`], evaluates authorization internally, and is the
//! only public path that produces an accepted [`AdminCommand`]. Repository
//! adapters reconcile exact replays before policy I/O and apply accepted
//! commands under the guarantees documented by [`AdminCommandRepositoryPort`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod migrations;

mod error;
mod executor;
mod model;
mod port;

pub use error::{AdminError, AdminErrorCode};
pub use executor::{AdminCommandExecutor, AdminCommandIntent, AdminExecutionRequest};
pub use model::{AdminActionKind, AdminCommand, AdminCommandId, AdminTarget, AdminTargetKind};
pub use port::{
    AdminCommandExecution, AdminCommandReceipt, AdminCommandRepositoryPort, AdminExecutionPort,
    AuthoritativeAuthorizationSnapshot, AuthoritativePolicyPort,
};

//! Tenant-bound application services for existing user lifecycle transitions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod service;

pub use error::{
    UserRepositoryError, UserRepositoryErrorCode, UserServiceError, UserServiceErrorCode,
};
pub use service::{
    CommittedUserTransition, PreparedUserTransition, UserCommitReceipt, UserRepositoryPort,
    UserService, UserTransitionError,
};

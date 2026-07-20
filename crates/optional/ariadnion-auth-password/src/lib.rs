//! Bounded password authentication primitives for optional Ariadnion bundles.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod policy;
mod secret;

pub use error::{PasswordError, PasswordErrorCode};
pub use policy::{
    BreachAssessment, BreachStatus, PasswordFingerprint, PasswordPolicy, admit_password,
};
pub use secret::{PasswordLimits, PasswordSecret};

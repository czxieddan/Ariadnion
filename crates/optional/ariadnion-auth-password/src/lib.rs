//! Bounded password authentication primitives for optional Ariadnion bundles.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod hash;
mod policy;
mod secret;

pub use error::{PasswordError, PasswordErrorCode};
pub use hash::{
    Argon2idEngine, Argon2idParameters, PasswordHashRecord, PasswordSalt, PasswordVerification,
};
pub use policy::{
    BreachAssessment, BreachStatus, PasswordFingerprint, PasswordPolicy, admit_password,
};
pub use secret::{PasswordLimits, PasswordSecret};

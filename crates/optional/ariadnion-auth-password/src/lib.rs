//! Bounded password authentication primitives for optional Ariadnion bundles.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod secret;

pub use error::{PasswordError, PasswordErrorCode};
pub use secret::{PasswordLimits, PasswordSecret};

//! Bounded password authentication primitives for optional Ariadnion bundles.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod credential;
mod error;
mod hash;
pub mod migrations;
mod policy;
mod reset;
mod reset_debug;
mod secret;

pub use credential::{
    PasswordCredential, PasswordCredentialSnapshot, PasswordCredentialSubject,
    PasswordCredentialVersion, PasswordHashPolicyVersion,
};
pub use error::{PasswordError, PasswordErrorCode};
pub use hash::{
    Argon2idEngine, Argon2idParameters, PasswordHashRecord, PasswordSalt, PasswordVerification,
};
pub use policy::{
    BreachAssessment, BreachStatus, PasswordFingerprint, PasswordPolicy, admit_password,
};
pub use reset::{
    PasswordHashRecordDigest, PasswordReset, PasswordResetAction, PasswordResetCommand,
    PasswordResetConsumption, PasswordResetEvent, PasswordResetEventKind, PasswordResetId,
    PasswordResetIssueRequest, PasswordResetPurpose, PasswordResetSnapshot, PasswordResetState,
    PasswordResetSubject, PasswordResetTokenDigest, PasswordResetTransition,
    PasswordResetValidityWindow, PasswordResetVersion, issue_password_reset,
    transition_password_reset,
};
pub use secret::{PasswordLimits, PasswordSecret};

// crates/optional/ariadnion-auth-password/src/lib.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Bounded password authentication primitives for optional Ariadnion bundles.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod credential;
mod error;
mod hash;
pub mod migrations;
mod policy;
mod repository;
mod reset;
mod reset_debug;
mod secret;

pub use credential::{
    PasswordCredential, PasswordCredentialReplacement, PasswordCredentialSnapshot,
    PasswordCredentialSubject, PasswordCredentialVersion, PasswordHashPolicyVersion,
};
pub use error::{PasswordError, PasswordErrorCode};
pub use hash::{
    Argon2idEngine, Argon2idParameters, PasswordHashRecord, PasswordSalt, PasswordVerification,
};
pub use policy::{
    BreachAssessment, BreachStatus, PasswordFingerprint, PasswordPolicy, admit_password,
};
pub use repository::{
    PasswordCommitReceipt, PasswordCredentialReplacementCommit, PasswordRepositoryError,
    PasswordRepositoryErrorCode, PasswordRepositoryPort, PasswordResetCommit,
    PasswordResetIssuanceCommit, PasswordResetOnlyCommit,
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

// crates/optional/ariadnion-auth-session/src/lib.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Pure browser session-family types and deterministic state transitions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
pub mod migrations;
mod model;
mod repository;
mod transition;

pub use error::{SessionError, SessionErrorCode};
pub use ids::{SessionFamilyId, SessionFamilyVersion, SessionId, SessionVersion};
pub use model::{
    MAX_ABSOLUTE_LIFETIME_SECONDS, MAX_IDLE_LIFETIME_SECONDS, MAX_ROTATED_SESSIONS,
    MAX_SESSION_TOKEN_BYTES, MIN_SESSION_TOKEN_BYTES, Session, SessionFamily,
    SessionFamilySnapshot, SessionFamilyState, SessionIssueBinding, SessionIssueRequest,
    SessionProofDigest, SessionSnapshot, SessionState, SessionSubject, SessionTokenDigest,
    SessionValidityWindow,
};
pub use repository::{
    SessionCommitReceipt, SessionRepositoryError, SessionRepositoryErrorCode, SessionRepositoryPort,
};
pub use transition::{
    SessionAction, SessionCommand, SessionEvent, SessionEventKind, SessionRotation,
    SessionRotationEvidence, SessionTransition, issue_session, transition_session_family,
};

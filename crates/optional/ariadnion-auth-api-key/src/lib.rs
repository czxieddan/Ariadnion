// crates/optional/ariadnion-auth-api-key/src/lib.rs - Rust source for Ariadnion.
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
//! Pure scoped API-key types and deterministic lifecycle transitions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
pub mod migrations;
mod model;
mod repository;
mod transition;

pub use error::{ApiKeyError, ApiKeyErrorCode};
pub use ids::{ApiKeyId, ApiKeyVersion};
pub use model::{
    ApiKey, ApiKeyIssueBinding, ApiKeyIssueRequest, ApiKeyOwner, ApiKeyPrefix, ApiKeyScope,
    ApiKeySecretDigest, ApiKeySnapshot, ApiKeySnapshotState, ApiKeyState, ApiKeyValidityWindow,
    MAX_API_KEY_LIFETIME_SECONDS, MAX_API_KEY_SCOPES, MAX_OVERLAP_SECONDS, MAX_PREFIX_BYTES,
    MAX_RETIRED_SECRETS, MAX_SCOPE_BYTES, MAX_SECRET_BYTES, MIN_PREFIX_BYTES, MIN_SECRET_BYTES,
};
pub use repository::{
    ApiKeyCommitReceipt, ApiKeyRepositoryError, ApiKeyRepositoryErrorCode, ApiKeyRepositoryPort,
};
pub use transition::{
    ApiKeyAction, ApiKeyCommand, ApiKeyEvent, ApiKeyEventKind, ApiKeyPresentation, ApiKeyRotation,
    ApiKeyTransition, ApiKeyVerification, issue_api_key, transition_api_key,
    verify_api_key_presentation,
};

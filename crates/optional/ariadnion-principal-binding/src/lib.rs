// crates/optional/ariadnion-principal-binding/src/lib.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Tenant-bound durable principal identity bindings.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod authenticator_error;
mod authenticator_evidence;
mod authenticator_ids;
mod authenticator_model;
mod authenticator_repository;
mod authenticator_transition;
mod error;
mod ids;
pub mod migrations;
mod model;
mod repository;
mod transition;

pub use authenticator_error::{PrincipalAuthenticatorError, PrincipalAuthenticatorErrorCode};
pub use authenticator_evidence::{
    AuthenticatedPrincipalEvidence, AuthenticatedPrincipalEvidenceData,
};
pub use authenticator_ids::{
    PrincipalAuthenticatorId, PrincipalAuthenticatorKind, PrincipalAuthenticatorSourceCommitment,
    PrincipalAuthenticatorSourceId, PrincipalAuthenticatorVersion,
};
pub use authenticator_model::{
    PrincipalAuthenticatorEvent, PrincipalAuthenticatorEventData, PrincipalAuthenticatorEventKind,
    PrincipalAuthenticatorLink, PrincipalAuthenticatorSnapshot, PrincipalAuthenticatorSnapshotData,
    PrincipalAuthenticatorState, PrincipalAuthenticatorTransition,
};
pub use authenticator_repository::{
    PrincipalAuthenticatorCommitReceipt, PrincipalAuthenticatorRepositoryError,
    PrincipalAuthenticatorRepositoryErrorCode, PrincipalAuthenticatorRepositoryPort,
};
pub use authenticator_transition::{
    PrincipalAuthenticatorCommand, link_authenticator, revoke_authenticator,
};
pub use error::{PrincipalBindingError, PrincipalBindingErrorCode};
pub use ids::PrincipalBindingVersion;
pub use migrations::{
    IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_CANONICAL_V1_SHA256,
    IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_DOMAIN,
    IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_FROM_VERSION,
    IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_ID,
    IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_REQUIRES_BACKUP,
    IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_STATEMENTS,
    IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_TO_VERSION,
    IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_CANONICAL_V1_SHA256,
    IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_DOMAIN,
    IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_FROM_VERSION, IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_ID,
    IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_REQUIRES_BACKUP,
    IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_STATEMENTS,
    IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_TO_VERSION,
};
pub use model::{
    PrincipalBinding, PrincipalBindingEvent, PrincipalBindingEventData, PrincipalBindingEventKind,
    PrincipalBindingIdentity, PrincipalBindingSnapshot, PrincipalBindingSnapshotData,
    PrincipalBindingState, PrincipalBindingTransition, SubjectCommitment,
};
pub use repository::{
    PrincipalBindingCommitReceipt, PrincipalBindingRepositoryError,
    PrincipalBindingRepositoryErrorCode, PrincipalBindingRepositoryPort,
};
pub use transition::{PrincipalBindingCommand, erase, provision, revoke};

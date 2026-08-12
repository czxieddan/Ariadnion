// crates/optional/ariadnion-api-admin/src/lib.rs - Rust source for Ariadnion.
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
    AuthenticatedPrincipalPort, AuthoritativeAuthorizationSnapshot, AuthoritativePolicyPort,
};

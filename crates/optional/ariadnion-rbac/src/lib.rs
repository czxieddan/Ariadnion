// crates/optional/ariadnion-rbac/src/lib.rs - Rust source for Ariadnion.
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
//! Tenant-bound scoped role authorization contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod migrations;

mod binding;
mod error;
mod evaluate;
mod ids;
mod model;
mod repository;
mod transition;

pub use binding::{
    AuthorizationSubject, MembershipAuthorizationContext, MembershipAuthorizationIdentity,
    RoleAssignment,
};
pub use error::{AuthorizationError, AuthorizationErrorCode};
pub use evaluate::evaluate;
pub use ids::{
    AssignmentId, DecisionId, PermissionId, PolicyVersion, ResourceId, ResourceKind, RoleId,
};
pub use model::{
    AuthorizationAssignmentSnapshot, AuthorizationDecision, AuthorizationDecisionReason,
    AuthorizationIntent, AuthorizationPolicy, AuthorizationPolicySnapshot, AuthorizationRequest,
    AuthorizationRoleSnapshot, AuthorizationScope, AuthorizationTarget, MAX_ASSIGNMENTS, MAX_ROLES,
    MAX_RULES_PER_ROLE, MatchedRoleSummary, PermissionEffect, PermissionRule, ResourceState,
    RoleAssignmentSnapshot, RoleDefinition, RoleDefinitionSnapshot,
};
pub use repository::{
    AuthorizationPolicyCommitReceipt, AuthorizationPolicyRepositoryError,
    AuthorizationPolicyRepositoryErrorCode, AuthorizationPolicyRepositoryPort,
};
pub use transition::{
    AuthorizationPolicyChange, AuthorizationPolicyEvent, AuthorizationPolicyEventKind,
    AuthorizationPolicyTransition, publish_authorization_policy, replace_authorization_policy,
};

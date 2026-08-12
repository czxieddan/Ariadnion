// crates/optional/ariadnion-rbac/src/transition.rs - Rust source for Ariadnion.
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
//! Deterministic tenant-bound authorization-policy transitions.

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_user_domain::UtcTimestamp;

use crate::binding::RoleAssignment;
use crate::error::{AuthorizationError, AuthorizationErrorCode, error};
use crate::ids::PolicyVersion;
use crate::model::{AuthorizationPolicy, AuthorizationPolicySnapshot, RoleDefinition};

/// A complete authorization-policy replacement with trusted audit context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicyChange {
    tenant_id: TenantId,
    expected_version: PolicyVersion,
    roles: Vec<RoleDefinition>,
    assignments: Vec<RoleAssignment>,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
}

impl AuthorizationPolicyChange {
    /// Creates a deterministic policy change without consulting a clock.
    ///
    /// The actor must come from an authenticated request context and
    /// `occurred_at` must come from a trusted UTC clock at the application
    /// boundary. Construction does not perform I/O or authorize the actor.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        expected_version: PolicyVersion,
        roles: Vec<RoleDefinition>,
        assignments: Vec<RoleAssignment>,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            expected_version,
            roles,
            assignments,
            actor,
            occurred_at,
        }
    }

    /// Returns the explicit tenant boundary for the requested policy.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the optimistic policy version required by this change.
    #[must_use]
    pub const fn expected_version(&self) -> PolicyVersion {
        self.expected_version
    }

    /// Returns replacement roles in deterministic declaration order.
    #[must_use]
    pub fn roles(&self) -> &[RoleDefinition] {
        &self.roles
    }

    /// Returns replacement assignments in deterministic declaration order.
    #[must_use]
    pub fn assignments(&self) -> &[RoleAssignment] {
        &self.assignments
    }

    /// Returns the authenticated actor attributed to the change.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the trusted UTC instant attributed to the change.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }
}

/// Stable audit-ready authorization-policy event kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorizationPolicyEventKind {
    /// The tenant's first durable policy was published.
    Published,
    /// The tenant's existing durable policy was replaced.
    Replaced,
}

/// Immutable audit-ready event produced with every accepted policy change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicyEvent {
    tenant_id: TenantId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
}

impl AuthorizationPolicyEvent {
    /// Returns the tenant boundary captured by the event.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the authenticated actor attributed to the change.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the trusted UTC instant attributed to the change.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the resulting policy version.
    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// Returns the stable event kind.
    #[must_use]
    pub const fn kind(&self) -> AuthorizationPolicyEventKind {
        self.kind
    }
}

/// One accepted authorization policy coupled to its exact durable evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicyTransition {
    tenant_id: TenantId,
    expected_previous_version: PolicyVersion,
    previous_snapshot: Option<AuthorizationPolicySnapshot>,
    policy: AuthorizationPolicy,
    event: AuthorizationPolicyEvent,
}

impl AuthorizationPolicyTransition {
    /// Returns the explicit tenant boundary for this transition.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the version that a repository must compare atomically.
    #[must_use]
    pub const fn expected_previous_version(&self) -> PolicyVersion {
        self.expected_previous_version
    }

    /// Returns the exact durable state that this transition evolved from.
    ///
    /// Initial publication returns `None`; replacement retains every previous
    /// role, rule, assignment, and ordering fact for divergent-state checks.
    #[must_use]
    pub const fn previous_snapshot(&self) -> Option<&AuthorizationPolicySnapshot> {
        self.previous_snapshot.as_ref()
    }

    /// Returns the resulting immutable authorization policy.
    #[must_use]
    pub const fn policy(&self) -> &AuthorizationPolicy {
        &self.policy
    }

    /// Returns the audit-ready event corresponding exactly to the policy.
    #[must_use]
    pub const fn event(&self) -> &AuthorizationPolicyEvent {
        &self.event
    }
}

/// Publishes one tenant's initial authorization policy.
///
/// Every role and assignment scope must belong to the explicit tenant.
/// Publication produces policy version one, a `Published` event, and no
/// previous snapshot. The function performs no I/O and never persists an
/// authorization decision.
///
/// # Errors
/// Returns [`AuthorizationErrorCode::VersionConflict`] unless the requested
/// version is initial. Policy validation preserves stable bounded-collection,
/// identity, role-reference, and tenant errors.
pub fn publish_authorization_policy(
    change: AuthorizationPolicyChange,
) -> Result<AuthorizationPolicyTransition, AuthorizationError> {
    if change.expected_version != PolicyVersion::initial() {
        return Err(error(AuthorizationErrorCode::VersionConflict));
    }
    build_transition(
        None,
        change,
        PolicyVersion::initial(),
        AuthorizationPolicyEventKind::Published,
    )
}

/// Replaces one tenant's policy after an optimistic version comparison.
///
/// The input aggregate is not mutated. The resulting policy advances exactly
/// once, retains the complete previous snapshot, and emits a `Replaced` event.
///
/// # Errors
/// Returns [`AuthorizationErrorCode::VersionConflict`] when `change` is stale,
/// [`AuthorizationErrorCode::TenantMismatch`] for crossed policy material, or
/// [`AuthorizationErrorCode::VersionExhausted`] instead of wrapping at
/// `u64::MAX`. Other stable policy-construction errors are preserved.
pub fn replace_authorization_policy(
    current: &AuthorizationPolicy,
    change: AuthorizationPolicyChange,
) -> Result<AuthorizationPolicyTransition, AuthorizationError> {
    if current.version() != change.expected_version {
        return Err(error(AuthorizationErrorCode::VersionConflict));
    }
    if current.tenant_id() != &change.tenant_id {
        return Err(error(AuthorizationErrorCode::TenantMismatch));
    }
    let next_version = current.version().next()?;
    build_transition(
        Some(current.snapshot_state()),
        change,
        next_version,
        AuthorizationPolicyEventKind::Replaced,
    )
}

fn build_transition(
    previous_snapshot: Option<AuthorizationPolicySnapshot>,
    change: AuthorizationPolicyChange,
    version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
) -> Result<AuthorizationPolicyTransition, AuthorizationError> {
    let policy = AuthorizationPolicy::new(
        change.tenant_id.clone(),
        version,
        change.roles,
        change.assignments,
    )?;
    let event = AuthorizationPolicyEvent {
        tenant_id: change.tenant_id.clone(),
        actor: change.actor,
        occurred_at: change.occurred_at,
        version,
        kind,
    };
    Ok(AuthorizationPolicyTransition {
        tenant_id: change.tenant_id,
        expected_previous_version: change.expected_version,
        previous_snapshot,
        policy,
        event,
    })
}

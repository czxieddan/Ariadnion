//! Trusted subject, membership, and assignment bindings.

use std::collections::BTreeSet;

use ariadnion_core::{PrincipalContext, PrincipalId, TenantId};
use ariadnion_organization::{
    MembershipId, MembershipState, OrganizationId, OrganizationState, TeamId,
};
use ariadnion_user_domain::{UserId, UserLifecycleState, UtcTimestamp};

use crate::error::{AuthorizationError, AuthorizationErrorCode, error};
use crate::ids::{AssignmentId, RoleId};
use crate::model::AuthorizationScope;

const MAX_TEAM_IDS: usize = 256;

/// A bounded assignment of one role to one authenticated membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleAssignment {
    id: AssignmentId,
    principal_id: PrincipalId,
    membership_id: MembershipId,
    role_id: RoleId,
    scope: AuthorizationScope,
    expires_at: Option<UtcTimestamp>,
}

impl RoleAssignment {
    /// Creates an immutable membership-bound role assignment.
    ///
    /// Tenant-wide assignments remain membership-bound and therefore fail
    /// closed when the request has no matching active membership context.
    #[must_use]
    pub const fn new(
        id: AssignmentId,
        principal_id: PrincipalId,
        membership_id: MembershipId,
        role_id: RoleId,
        scope: AuthorizationScope,
        expires_at: Option<UtcTimestamp>,
    ) -> Self {
        Self {
            id,
            principal_id,
            membership_id,
            role_id,
            scope,
            expires_at,
        }
    }

    /// Returns the stable assignment identity.
    #[must_use]
    pub const fn id(&self) -> &AssignmentId {
        &self.id
    }

    /// Returns the assigned authenticated principal identity.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the organization membership authorized by this assignment.
    #[must_use]
    pub const fn membership_id(&self) -> &MembershipId {
        &self.membership_id
    }

    /// Returns the assigned role identity.
    #[must_use]
    pub const fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    /// Returns the maximum scope of this assignment.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    /// Returns the exclusive UTC expiry boundary, when present.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UtcTimestamp> {
        self.expires_at
    }

    pub(crate) fn is_active_at(&self, now: UtcTimestamp) -> bool {
        self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

/// Stable identities linking a membership to its tenant, organization, and user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipAuthorizationIdentity {
    tenant_id: TenantId,
    organization_id: OrganizationId,
    membership_id: MembershipId,
    user_id: UserId,
}

impl MembershipAuthorizationIdentity {
    /// Creates a trusted membership identity mapping.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        organization_id: OrganizationId,
        membership_id: MembershipId,
        user_id: UserId,
    ) -> Self {
        Self {
            tenant_id,
            organization_id,
            membership_id,
            user_id,
        }
    }
}

/// Trusted organization and membership facts supplied to authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipAuthorizationContext {
    identity: MembershipAuthorizationIdentity,
    organization_state: OrganizationState,
    membership_state: MembershipState,
    expires_at: Option<UtcTimestamp>,
    team_ids: Vec<TeamId>,
}

impl MembershipAuthorizationContext {
    /// Creates a membership context with at most 256 unique team identities.
    ///
    /// # Errors
    /// Returns a stable error when the team list exceeds its bound or repeats
    /// an identity.
    pub fn new(
        identity: MembershipAuthorizationIdentity,
        organization_state: OrganizationState,
        membership_state: MembershipState,
        expires_at: Option<UtcTimestamp>,
        team_ids: Vec<TeamId>,
    ) -> Result<Self, AuthorizationError> {
        validate_team_ids(&team_ids)?;
        Ok(Self {
            identity,
            organization_state,
            membership_state,
            expires_at,
            team_ids,
        })
    }

    /// Returns the tenant that owns the organization membership.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.identity.tenant_id
    }

    /// Returns the organization represented by the membership.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.identity.organization_id
    }

    /// Returns the stable membership identity.
    #[must_use]
    pub const fn membership_id(&self) -> &MembershipId {
        &self.identity.membership_id
    }

    /// Returns the user identity that owns the membership.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.identity.user_id
    }

    /// Returns the trusted organization lifecycle state.
    #[must_use]
    pub const fn organization_state(&self) -> OrganizationState {
        self.organization_state
    }

    /// Returns the trusted membership lifecycle state.
    #[must_use]
    pub const fn membership_state(&self) -> MembershipState {
        self.membership_state
    }

    /// Returns the exclusive UTC membership expiry boundary, when present.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UtcTimestamp> {
        self.expires_at
    }

    /// Returns bounded team identities in deterministic input order.
    #[must_use]
    pub fn team_ids(&self) -> &[TeamId] {
        &self.team_ids
    }

    pub(crate) fn is_active_at(&self, now: UtcTimestamp) -> bool {
        self.membership_state == MembershipState::Active
            && self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

/// Trusted authenticated identity and lifecycle facts evaluated for one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSubject {
    principal: PrincipalContext,
    user_id: UserId,
    user_state: UserLifecycleState,
    membership: Option<MembershipAuthorizationContext>,
}

impl AuthorizationSubject {
    /// Creates a subject from a core principal, its user mapping, and trusted state.
    #[must_use]
    pub const fn new(
        principal: PrincipalContext,
        user_id: UserId,
        user_state: UserLifecycleState,
        membership: Option<MembershipAuthorizationContext>,
    ) -> Self {
        Self {
            principal,
            user_id,
            user_state,
            membership,
        }
    }

    /// Returns the trusted core principal context.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalContext {
        &self.principal
    }

    /// Returns the authenticated user mapped from the principal.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the trusted user lifecycle state.
    #[must_use]
    pub const fn user_state(&self) -> UserLifecycleState {
        self.user_state
    }

    /// Returns trusted organization membership facts, when available.
    #[must_use]
    pub const fn membership(&self) -> Option<&MembershipAuthorizationContext> {
        self.membership.as_ref()
    }
}

fn validate_team_ids(team_ids: &[TeamId]) -> Result<(), AuthorizationError> {
    if team_ids.len() > MAX_TEAM_IDS {
        return Err(error(AuthorizationErrorCode::ResourceLimitExceeded));
    }
    let mut ids = BTreeSet::new();
    if team_ids.iter().any(|id| !ids.insert(id)) {
        return Err(error(AuthorizationErrorCode::DuplicateIdentity));
    }
    Ok(())
}

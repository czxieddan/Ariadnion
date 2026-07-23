//! Typed durable authorization-policy snapshots.

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_organization::MembershipId;
use ariadnion_user_domain::UtcTimestamp;

use super::{
    AuthorizationPolicy, AuthorizationScope, MAX_ASSIGNMENTS, MAX_ROLES, PermissionRule,
    RoleDefinition,
};
use crate::binding::RoleAssignment;
use crate::error::{AuthorizationError, AuthorizationErrorCode, error};
use crate::ids::{AssignmentId, PolicyVersion, RoleId};

/// Complete typed state for one persisted role definition.
///
/// Rules retain declaration order. Candidate snapshots are validated by
/// [`AuthorizationPolicy::from_snapshot`], including the existing per-role
/// bound and permission-identity uniqueness requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleDefinitionSnapshot {
    id: RoleId,
    tenant_id: TenantId,
    rules: Vec<PermissionRule>,
}

impl RoleDefinitionSnapshot {
    /// Creates a candidate persisted role definition.
    #[must_use]
    pub fn new(id: RoleId, tenant_id: TenantId, rules: Vec<PermissionRule>) -> Self {
        Self {
            id,
            tenant_id,
            rules,
        }
    }

    /// Returns the stable role identity.
    #[must_use]
    pub const fn id(&self) -> &RoleId {
        &self.id
    }

    /// Returns the tenant boundary stored with the role.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns permission rules in persisted declaration order.
    #[must_use]
    pub fn rules(&self) -> &[PermissionRule] {
        &self.rules
    }

    fn from_role(role: &RoleDefinition) -> Self {
        Self {
            id: role.id().clone(),
            tenant_id: role.tenant_id().clone(),
            rules: role.rules().to_vec(),
        }
    }

    fn into_role(self) -> Result<RoleDefinition, AuthorizationError> {
        RoleDefinition::new(self.id, self.tenant_id, self.rules)
    }
}

/// Complete typed state for one persisted role assignment.
///
/// The snapshot contains the principal and membership bindings owned by the
/// policy. The authoritative organization aggregate remains the source of the
/// membership-to-user binding; it is deliberately not duplicated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleAssignmentSnapshot {
    id: AssignmentId,
    principal_id: PrincipalId,
    membership_id: MembershipId,
    role_id: RoleId,
    scope: AuthorizationScope,
    expires_at: Option<UtcTimestamp>,
}

impl RoleAssignmentSnapshot {
    /// Creates a candidate persisted role assignment.
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

    /// Returns the organization membership bound to the assignment.
    #[must_use]
    pub const fn membership_id(&self) -> &MembershipId {
        &self.membership_id
    }

    /// Returns the referenced role identity.
    #[must_use]
    pub const fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    /// Returns the complete hierarchical authorization scope.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    /// Returns the exclusive UTC expiry boundary when configured.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UtcTimestamp> {
        self.expires_at
    }

    fn from_assignment(assignment: &RoleAssignment) -> Self {
        Self {
            id: assignment.id().clone(),
            principal_id: assignment.principal_id().clone(),
            membership_id: assignment.membership_id().clone(),
            role_id: assignment.role_id().clone(),
            scope: assignment.scope().clone(),
            expires_at: assignment.expires_at(),
        }
    }

    fn into_assignment(self) -> Result<RoleAssignment, AuthorizationError> {
        self.scope.validate()?;
        Ok(RoleAssignment::new(
            self.id,
            self.principal_id,
            self.membership_id,
            self.role_id,
            self.scope,
            self.expires_at,
        ))
    }
}

/// Complete lossless state required to reconstruct one authorization policy.
///
/// Roles, rules, and assignments retain persisted order. This type contains
/// policy facts only; authorization decisions are intentionally excluded and
/// cannot be reconstructed as reusable durable grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicySnapshot {
    version: PolicyVersion,
    roles: Vec<RoleDefinitionSnapshot>,
    assignments: Vec<RoleAssignmentSnapshot>,
}

impl AuthorizationPolicySnapshot {
    /// Creates a candidate policy snapshot for validated reconstruction.
    #[must_use]
    pub fn new(
        version: PolicyVersion,
        roles: Vec<RoleDefinitionSnapshot>,
        assignments: Vec<RoleAssignmentSnapshot>,
    ) -> Self {
        Self {
            version,
            roles,
            assignments,
        }
    }

    /// Returns the immutable persisted policy version.
    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// Returns role snapshots in persisted declaration order.
    #[must_use]
    pub fn roles(&self) -> &[RoleDefinitionSnapshot] {
        &self.roles
    }

    /// Returns assignment snapshots in persisted declaration order.
    #[must_use]
    pub fn assignments(&self) -> &[RoleAssignmentSnapshot] {
        &self.assignments
    }
}

/// Alias emphasizing that the snapshot represents an authorization role.
pub type AuthorizationRoleSnapshot = RoleDefinitionSnapshot;

/// Alias emphasizing that the snapshot represents an authorization assignment.
pub type AuthorizationAssignmentSnapshot = RoleAssignmentSnapshot;

impl AuthorizationPolicy {
    /// Reconstructs a policy from one complete typed persistence snapshot.
    ///
    /// The boundary revalidates collection and rule bounds, stable identity
    /// uniqueness, tenant consistency, hierarchical scope invariants, and every
    /// assignment role reference. Input order is preserved exactly and no
    /// authorization decision can enter the reconstructed policy.
    ///
    /// # Errors
    ///
    /// Returns the existing stable [`AuthorizationErrorCode`] for the first
    /// invariant rejected by the normal role or policy constructors.
    pub fn from_snapshot(
        snapshot: AuthorizationPolicySnapshot,
    ) -> Result<Self, AuthorizationError> {
        validate_snapshot_limits(&snapshot)?;
        let roles = snapshot
            .roles
            .into_iter()
            .map(RoleDefinitionSnapshot::into_role)
            .collect::<Result<Vec<_>, _>>()?;
        let assignments = snapshot
            .assignments
            .into_iter()
            .map(RoleAssignmentSnapshot::into_assignment)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(snapshot.version, roles, assignments)
    }

    /// Returns every durable policy field in deterministic declaration order.
    #[must_use]
    pub fn snapshot(&self) -> AuthorizationPolicySnapshot {
        AuthorizationPolicySnapshot {
            version: self.version(),
            roles: self
                .roles()
                .iter()
                .map(RoleDefinitionSnapshot::from_role)
                .collect(),
            assignments: self
                .assignments()
                .iter()
                .map(RoleAssignmentSnapshot::from_assignment)
                .collect(),
        }
    }

    /// Returns the complete durable snapshot using the naming convention of
    /// other identity aggregates.
    #[must_use]
    pub fn snapshot_state(&self) -> AuthorizationPolicySnapshot {
        self.snapshot()
    }
}

fn validate_snapshot_limits(
    snapshot: &AuthorizationPolicySnapshot,
) -> Result<(), AuthorizationError> {
    if snapshot.roles.len() > MAX_ROLES || snapshot.assignments.len() > MAX_ASSIGNMENTS {
        return Err(error(AuthorizationErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

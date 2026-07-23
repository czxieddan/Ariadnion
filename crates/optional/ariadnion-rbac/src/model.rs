//! Immutable scoped authorization policy and request models.

mod snapshot;

pub use snapshot::{
    AuthorizationAssignmentSnapshot, AuthorizationPolicySnapshot, AuthorizationRoleSnapshot,
    RoleAssignmentSnapshot, RoleDefinitionSnapshot,
};

use std::collections::BTreeSet;

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_organization::OrganizationId;
use ariadnion_user_domain::UtcTimestamp;

use crate::binding::{AuthorizationSubject, RoleAssignment};
use crate::error::{AuthorizationError, AuthorizationErrorCode, error};
use crate::ids::{DecisionId, PermissionId, PolicyVersion, ResourceId, ResourceKind, RoleId};

/// Maximum roles accepted in one durable authorization policy.
///
/// Persistence adapters must use this authoritative value when issuing a
/// `LIMIT` cap-plus-one query before allocating role rows.
pub const MAX_ROLES: usize = 256;
/// Maximum permission rules accepted for one durable role.
///
/// Persistence adapters must use this authoritative value when issuing a
/// `LIMIT` cap-plus-one query before allocating rule rows.
pub const MAX_RULES_PER_ROLE: usize = 256;
/// Maximum role assignments accepted in one durable authorization policy.
///
/// Persistence adapters must use this authoritative value when issuing a
/// `LIMIT` cap-plus-one query before allocating assignment rows.
pub const MAX_ASSIGNMENTS: usize = 4_096;

/// The effect of one permission rule.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PermissionEffect {
    /// Matching requests may proceed unless another matching rule denies them.
    Allow,
    /// Matching requests must be denied regardless of matching allows.
    Deny,
}

/// One exact permission and its authorization effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionRule {
    permission_id: PermissionId,
    effect: PermissionEffect,
}

impl PermissionRule {
    /// Creates an exact permission rule.
    #[must_use]
    pub const fn new(permission_id: PermissionId, effect: PermissionEffect) -> Self {
        Self {
            permission_id,
            effect,
        }
    }

    /// Returns the permission identity matched by this rule.
    #[must_use]
    pub const fn permission_id(&self) -> &PermissionId {
        &self.permission_id
    }

    /// Returns the effect applied by this rule.
    #[must_use]
    pub const fn effect(&self) -> PermissionEffect {
        self.effect
    }
}

/// A tenant-bound role with a bounded set of exact permission rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleDefinition {
    id: RoleId,
    tenant_id: TenantId,
    rules: Vec<PermissionRule>,
}

impl RoleDefinition {
    /// Creates a tenant-bound role with unique permissions.
    ///
    /// # Errors
    /// Returns a stable construction error when the rule set is empty,
    /// exceeds 256 entries, or repeats a permission identity.
    pub fn new(
        id: RoleId,
        tenant_id: TenantId,
        rules: Vec<PermissionRule>,
    ) -> Result<Self, AuthorizationError> {
        validate_rules(&rules)?;
        Ok(Self {
            id,
            tenant_id,
            rules,
        })
    }

    /// Returns the stable role identity.
    #[must_use]
    pub const fn id(&self) -> &RoleId {
        &self.id
    }

    /// Returns the tenant owning this role.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the bounded permission rules in declaration order.
    #[must_use]
    pub fn rules(&self) -> &[PermissionRule] {
        &self.rules
    }
}

/// A hierarchical tenant, organization, or resource authorization scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationScope {
    /// Every resource within one tenant.
    Tenant {
        /// Tenant boundary for the scope.
        tenant_id: TenantId,
    },
    /// One tenant-owned resource without an organization boundary.
    TenantResource {
        /// Tenant boundary for the resource.
        tenant_id: TenantId,
        /// Stable kind used to prevent identity collisions between domains.
        resource_kind: ResourceKind,
        /// Stable tenant-owned resource identity.
        resource_id: ResourceId,
    },
    /// Every resource within one organization.
    Organization {
        /// Tenant boundary for the scope.
        tenant_id: TenantId,
        /// Organization boundary for the scope.
        organization_id: OrganizationId,
    },
    /// One protected resource and, when used as an assignment, its direct child.
    Resource {
        /// Tenant boundary for the scope.
        tenant_id: TenantId,
        /// Organization boundary for the resource.
        organization_id: OrganizationId,
        /// Optional direct parent resource identity.
        parent_resource_id: Option<ResourceId>,
        /// Stable kind used to prevent identity collisions between domains.
        resource_kind: ResourceKind,
        /// Stable protected-resource identity.
        resource_id: ResourceId,
    },
}

impl AuthorizationScope {
    /// Creates a tenant-wide scope.
    #[must_use]
    pub const fn tenant(tenant_id: TenantId) -> Self {
        Self::Tenant { tenant_id }
    }

    /// Creates an exact tenant-owned resource scope.
    #[must_use]
    pub const fn tenant_resource(
        tenant_id: TenantId,
        resource_kind: ResourceKind,
        resource_id: ResourceId,
    ) -> Self {
        Self::TenantResource {
            tenant_id,
            resource_kind,
            resource_id,
        }
    }

    /// Creates an organization-wide scope.
    #[must_use]
    pub const fn organization(tenant_id: TenantId, organization_id: OrganizationId) -> Self {
        Self::Organization {
            tenant_id,
            organization_id,
        }
    }

    /// Creates an organization-owned resource scope.
    ///
    /// # Errors
    /// Returns [`AuthorizationErrorCode::InvalidArgument`] when a resource is
    /// its own parent.
    pub fn resource(
        tenant_id: TenantId,
        organization_id: OrganizationId,
        parent_resource_id: Option<ResourceId>,
        resource_kind: ResourceKind,
        resource_id: ResourceId,
    ) -> Result<Self, AuthorizationError> {
        let scope = Self::Resource {
            tenant_id,
            organization_id,
            parent_resource_id,
            resource_kind,
            resource_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub(crate) fn validate(&self) -> Result<(), AuthorizationError> {
        let Self::Resource {
            parent_resource_id,
            resource_id,
            ..
        } = self
        else {
            return Ok(());
        };
        if parent_resource_id.as_ref() == Some(resource_id) {
            return Err(error(AuthorizationErrorCode::InvalidArgument));
        }
        Ok(())
    }

    /// Returns the explicit tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        match self {
            Self::Tenant { tenant_id }
            | Self::TenantResource { tenant_id, .. }
            | Self::Organization { tenant_id, .. }
            | Self::Resource { tenant_id, .. } => tenant_id,
        }
    }

    /// Returns the organization boundary for organization-owned scopes.
    ///
    /// Tenant-wide and exact tenant-resource scopes do not carry one.
    #[must_use]
    pub const fn organization_id(&self) -> Option<&OrganizationId> {
        match self {
            Self::Tenant { .. } | Self::TenantResource { .. } => None,
            Self::Organization {
                organization_id, ..
            }
            | Self::Resource {
                organization_id, ..
            } => Some(organization_id),
        }
    }

    pub(crate) fn contains(&self, requested: &Self) -> bool {
        if self.tenant_id() != requested.tenant_id() {
            return false;
        }
        match self {
            Self::Tenant { .. } => true,
            Self::TenantResource {
                resource_kind,
                resource_id,
                ..
            } => tenant_resource_contains(resource_kind, resource_id, requested),
            Self::Organization {
                organization_id, ..
            } => requested.organization_id() == Some(organization_id),
            Self::Resource { .. } => resource_scope_contains(self, requested),
        }
    }
}

fn tenant_resource_contains(
    assigned_kind: &ResourceKind,
    assigned_id: &ResourceId,
    requested: &AuthorizationScope,
) -> bool {
    match requested {
        AuthorizationScope::TenantResource {
            resource_kind,
            resource_id,
            ..
        } => assigned_kind == resource_kind && assigned_id == resource_id,
        _ => false,
    }
}

/// The trusted availability state of a protected resource.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResourceState {
    /// The resource may participate in authorization decisions.
    Active,
    /// The resource is blocked from normal access but may be recovered.
    Restricted,
    /// The resource is retained but unavailable for access.
    Unavailable,
    /// The resource is in a terminal deleted state.
    Deleted,
}

/// The operation class evaluated against a protected resource state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorizationIntent {
    /// A normal operation that requires an active resource.
    Access,
    /// A lifecycle recovery that requires a restricted resource.
    Recovery,
}

/// Explicit protected-resource facts required by every authorization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationTarget {
    permission_id: PermissionId,
    scope: AuthorizationScope,
    resource_state: ResourceState,
    intent: AuthorizationIntent,
}

impl AuthorizationTarget {
    /// Creates a target from an exact permission, hierarchical scope, and
    /// trusted resource availability state.
    #[must_use]
    pub const fn new(
        permission_id: PermissionId,
        scope: AuthorizationScope,
        resource_state: ResourceState,
    ) -> Self {
        Self {
            permission_id,
            scope,
            resource_state,
            intent: AuthorizationIntent::Access,
        }
    }

    /// Creates a recovery target for a restricted resource.
    ///
    /// Recovery intent is separate from normal access so a suspended user or
    /// frozen organization cannot be treated as active merely to restore it.
    #[must_use]
    pub const fn for_recovery(permission_id: PermissionId, scope: AuthorizationScope) -> Self {
        Self {
            permission_id,
            scope,
            resource_state: ResourceState::Restricted,
            intent: AuthorizationIntent::Recovery,
        }
    }

    /// Returns the exact requested permission identity.
    #[must_use]
    pub const fn permission_id(&self) -> &PermissionId {
        &self.permission_id
    }

    /// Returns the requested hierarchical resource scope.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    /// Returns the trusted resource availability state.
    #[must_use]
    pub const fn resource_state(&self) -> ResourceState {
        self.resource_state
    }

    /// Returns whether evaluation is for normal access or lifecycle recovery.
    #[must_use]
    pub const fn intent(&self) -> AuthorizationIntent {
        self.intent
    }
}

/// Immutable inputs for one deterministic authorization decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    decision_id: DecisionId,
    policy_version: PolicyVersion,
    subject: AuthorizationSubject,
    target: AuthorizationTarget,
    now: UtcTimestamp,
}

impl AuthorizationRequest {
    /// Creates a request with an explicit trusted resource target.
    #[must_use]
    pub const fn new(
        decision_id: DecisionId,
        policy_version: PolicyVersion,
        subject: AuthorizationSubject,
        target: AuthorizationTarget,
        now: UtcTimestamp,
    ) -> Self {
        Self {
            decision_id,
            policy_version,
            subject,
            target,
            now,
        }
    }

    /// Returns the caller-supplied decision identity.
    #[must_use]
    pub const fn decision_id(&self) -> &DecisionId {
        &self.decision_id
    }

    /// Returns the policy version expected by the caller.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Returns the trusted subject facts.
    #[must_use]
    pub const fn subject(&self) -> &AuthorizationSubject {
        &self.subject
    }

    /// Returns the exact requested permission identity.
    #[must_use]
    pub const fn permission_id(&self) -> &PermissionId {
        self.target.permission_id()
    }

    /// Returns the requested resource scope.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        self.target.scope()
    }

    /// Returns the trusted resource availability state.
    #[must_use]
    pub const fn resource_state(&self) -> ResourceState {
        self.target.resource_state()
    }

    /// Returns the target operation class.
    #[must_use]
    pub const fn intent(&self) -> AuthorizationIntent {
        self.target.intent()
    }

    /// Returns the trusted UTC evaluation instant.
    #[must_use]
    pub const fn now(&self) -> UtcTimestamp {
        self.now
    }
}

/// A validated bounded authorization policy snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicy {
    version: PolicyVersion,
    tenant_id: Option<TenantId>,
    roles: Vec<RoleDefinition>,
    assignments: Vec<RoleAssignment>,
}

impl AuthorizationPolicy {
    /// Validates and creates an immutable policy snapshot.
    ///
    /// # Errors
    /// Returns a stable error for collection overflow, duplicate identities,
    /// unknown roles, or any tenant boundary mismatch.
    pub fn new(
        version: PolicyVersion,
        roles: Vec<RoleDefinition>,
        assignments: Vec<RoleAssignment>,
    ) -> Result<Self, AuthorizationError> {
        validate_policy_limits(&roles, &assignments)?;
        validate_unique_policy_ids(&roles, &assignments)?;
        let tenant_id = policy_tenant(&roles, &assignments)?;
        validate_assignments(&roles, &assignments)?;
        Ok(Self {
            version,
            tenant_id,
            roles,
            assignments,
        })
    }

    /// Returns the immutable policy version.
    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// Returns the single policy tenant when the snapshot contains data.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// Returns roles in deterministic declaration order.
    #[must_use]
    pub fn roles(&self) -> &[RoleDefinition] {
        &self.roles
    }

    /// Returns assignments in deterministic declaration order.
    #[must_use]
    pub fn assignments(&self) -> &[RoleAssignment] {
        &self.assignments
    }

    pub(crate) fn role(&self, id: &RoleId) -> Option<&RoleDefinition> {
        self.roles.iter().find(|role| role.id() == id)
    }
}

/// Stable reasons emitted by authorization evaluation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorizationDecisionReason {
    /// At least one matching explicit deny rule took precedence.
    ExplicitDeny,
    /// At least one matching allow and no matching deny authorized access.
    ExplicitAllow,
    /// No active matching assignment produced an allow rule.
    NoAllow,
    /// The request expected a different immutable policy version.
    PolicyVersionMismatch,
    /// Trusted policy, principal, or resource facts crossed tenant boundaries.
    TenantMismatch,
    /// The user lifecycle state does not allow activity.
    UserInactive,
    /// The target organization is administratively frozen.
    OrganizationFrozen,
    /// Required membership facts are absent, mismatched, or inactive.
    MembershipInactive,
    /// The protected resource is unavailable or deleted.
    ResourceInactive,
}

/// A safe summary of one role that affected a decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchedRoleSummary {
    role_id: RoleId,
    effect: PermissionEffect,
}

impl MatchedRoleSummary {
    pub(crate) const fn new(role_id: RoleId, effect: PermissionEffect) -> Self {
        Self { role_id, effect }
    }

    /// Returns the opaque matched role identity.
    #[must_use]
    pub const fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    /// Returns the matching rule effect.
    #[must_use]
    pub const fn effect(&self) -> PermissionEffect {
        self.effect
    }
}

/// A deterministic authorization result containing only authorization facts and no credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecision {
    binding: AuthorizationDecisionBinding,
    reason: AuthorizationDecisionReason,
    matched_roles: Vec<MatchedRoleSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizationDecisionBinding {
    decision_id: DecisionId,
    policy_version: PolicyVersion,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    target: AuthorizationTarget,
    evaluated_at: UtcTimestamp,
}

impl AuthorizationDecision {
    pub(crate) fn new(
        request: &AuthorizationRequest,
        policy_version: PolicyVersion,
        reason: AuthorizationDecisionReason,
        matched_roles: Vec<MatchedRoleSummary>,
    ) -> Self {
        Self {
            binding: AuthorizationDecisionBinding {
                decision_id: request.decision_id.clone(),
                policy_version,
                tenant_id: request.subject.principal().tenant_id().clone(),
                principal_id: request.subject.principal().principal_id().clone(),
                target: request.target.clone(),
                evaluated_at: request.now,
            },
            reason,
            matched_roles,
        }
    }

    /// Returns whether the stable reason represents an explicit allow.
    #[must_use]
    pub const fn allowed(&self) -> bool {
        matches!(self.reason, AuthorizationDecisionReason::ExplicitAllow)
    }

    /// Returns the caller-supplied decision identity.
    #[must_use]
    pub const fn decision_id(&self) -> &DecisionId {
        &self.binding.decision_id
    }

    /// Returns the policy version that produced this result.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.binding.policy_version
    }

    /// Returns the authenticated tenant evaluated for this result.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.binding.tenant_id
    }

    /// Returns the authenticated principal evaluated for this result.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.binding.principal_id
    }

    /// Returns the exact permission evaluated for this result.
    #[must_use]
    pub const fn permission_id(&self) -> &PermissionId {
        self.binding.target.permission_id()
    }

    /// Returns the exact resource scope evaluated for this result.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        self.binding.target.scope()
    }

    /// Returns the trusted resource state evaluated for this result.
    #[must_use]
    pub const fn resource_state(&self) -> ResourceState {
        self.binding.target.resource_state()
    }

    /// Returns the target operation class evaluated by the policy.
    #[must_use]
    pub const fn intent(&self) -> AuthorizationIntent {
        self.binding.target.intent()
    }

    /// Returns the trusted UTC evaluation instant.
    #[must_use]
    pub const fn evaluated_at(&self) -> UtcTimestamp {
        self.binding.evaluated_at
    }

    /// Returns the stable fail-closed decision reason.
    #[must_use]
    pub const fn reason(&self) -> AuthorizationDecisionReason {
        self.reason
    }

    /// Returns safe matched-role summaries in policy assignment order.
    #[must_use]
    pub fn matched_roles(&self) -> &[MatchedRoleSummary] {
        &self.matched_roles
    }
}

fn validate_rules(rules: &[PermissionRule]) -> Result<(), AuthorizationError> {
    if rules.is_empty() {
        return Err(error(AuthorizationErrorCode::InvalidArgument));
    }
    if rules.len() > MAX_RULES_PER_ROLE {
        return Err(error(AuthorizationErrorCode::ResourceLimitExceeded));
    }
    let mut ids = BTreeSet::new();
    if rules.iter().any(|rule| !ids.insert(rule.permission_id())) {
        return Err(error(AuthorizationErrorCode::DuplicateIdentity));
    }
    Ok(())
}

fn resource_scope_contains(assigned: &AuthorizationScope, requested: &AuthorizationScope) -> bool {
    let AuthorizationScope::Resource {
        organization_id,
        resource_kind,
        resource_id,
        ..
    } = assigned
    else {
        return false;
    };
    let AuthorizationScope::Resource {
        organization_id: requested_organization,
        parent_resource_id,
        resource_kind: requested_kind,
        resource_id: requested_id,
        ..
    } = requested
    else {
        return false;
    };
    organization_id == requested_organization
        && resource_kind == requested_kind
        && (resource_id == requested_id || parent_resource_id.as_ref() == Some(resource_id))
}

fn validate_policy_limits(
    roles: &[RoleDefinition],
    assignments: &[RoleAssignment],
) -> Result<(), AuthorizationError> {
    if roles.len() > MAX_ROLES || assignments.len() > MAX_ASSIGNMENTS {
        return Err(error(AuthorizationErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

fn validate_unique_policy_ids(
    roles: &[RoleDefinition],
    assignments: &[RoleAssignment],
) -> Result<(), AuthorizationError> {
    let mut role_ids = BTreeSet::new();
    if roles.iter().any(|role| !role_ids.insert(role.id())) {
        return Err(error(AuthorizationErrorCode::DuplicateIdentity));
    }
    let mut assignment_ids = BTreeSet::new();
    if assignments
        .iter()
        .any(|assignment| !assignment_ids.insert(assignment.id()))
    {
        return Err(error(AuthorizationErrorCode::DuplicateIdentity));
    }
    Ok(())
}

fn policy_tenant(
    roles: &[RoleDefinition],
    assignments: &[RoleAssignment],
) -> Result<Option<TenantId>, AuthorizationError> {
    let candidate = roles
        .first()
        .map(RoleDefinition::tenant_id)
        .or_else(|| assignments.first().map(|value| value.scope().tenant_id()));
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if roles.iter().any(|role| role.tenant_id() != candidate) {
        return Err(error(AuthorizationErrorCode::TenantMismatch));
    }
    if assignments
        .iter()
        .any(|assignment| assignment.scope().tenant_id() != candidate)
    {
        return Err(error(AuthorizationErrorCode::TenantMismatch));
    }
    Ok(Some(candidate.clone()))
}

fn validate_assignments(
    roles: &[RoleDefinition],
    assignments: &[RoleAssignment],
) -> Result<(), AuthorizationError> {
    if assignments
        .iter()
        .any(|assignment| !roles.iter().any(|role| role.id() == assignment.role_id()))
    {
        return Err(error(AuthorizationErrorCode::UnknownRole));
    }
    Ok(())
}

//! Deterministic fail-closed authorization evaluation.

use ariadnion_organization::OrganizationState;
use ariadnion_user_domain::UserLifecycleState;

use crate::binding::{MembershipAuthorizationContext, RoleAssignment};
use crate::model::{
    AuthorizationDecision, AuthorizationDecisionReason, AuthorizationIntent, AuthorizationPolicy,
    AuthorizationRequest, MatchedRoleSummary, PermissionEffect, ResourceState,
};

/// Evaluates one trusted request against an immutable policy snapshot.
///
/// Version and tenant checks run before lifecycle gates. Matching denies take
/// precedence over matching allows, and absence of an allow always fails closed.
/// The result retains the exact authorization inputs, a stable reason, the
/// policy version, and bounded matched-role summaries. The caller must obtain `policy` from the
/// authoritative active snapshot and build `request` from authenticated subject
/// and resource facts immediately before evaluation; decisions are not durable
/// or deserializable grants.
#[must_use]
pub fn evaluate(
    policy: &AuthorizationPolicy,
    request: &AuthorizationRequest,
) -> AuthorizationDecision {
    let reason = precondition_failure(policy, request);
    if let Some(reason) = reason {
        return decision(policy, request, reason, Vec::new());
    }
    let matched_roles = matching_roles(policy, request);
    let reason = permission_reason(&matched_roles);
    decision(policy, request, reason, matched_roles)
}

fn precondition_failure(
    policy: &AuthorizationPolicy,
    request: &AuthorizationRequest,
) -> Option<AuthorizationDecisionReason> {
    if request.policy_version() != policy.version() {
        return Some(AuthorizationDecisionReason::PolicyVersionMismatch);
    }
    if tenant_mismatch(policy, request) {
        return Some(AuthorizationDecisionReason::TenantMismatch);
    }
    if request.subject().user_state() != UserLifecycleState::Active {
        return Some(AuthorizationDecisionReason::UserInactive);
    }
    membership_failure(request).or_else(|| resource_failure(request))
}

fn tenant_mismatch(policy: &AuthorizationPolicy, request: &AuthorizationRequest) -> bool {
    let principal_tenant = request.subject().principal().tenant_id();
    policy
        .tenant_id()
        .is_some_and(|tenant| tenant != principal_tenant)
        || request.scope().tenant_id() != principal_tenant
        || request
            .subject()
            .membership()
            .is_some_and(|membership| membership.tenant_id() != principal_tenant)
}

fn membership_failure(request: &AuthorizationRequest) -> Option<AuthorizationDecisionReason> {
    if membership_user_mismatch(request) {
        return Some(AuthorizationDecisionReason::MembershipInactive);
    }
    match request.scope().organization_id() {
        Some(organization_id) => membership_context_failure(request, organization_id),
        None => None,
    }
}

fn membership_user_mismatch(request: &AuthorizationRequest) -> bool {
    request
        .subject()
        .membership()
        .is_some_and(|membership| membership.user_id() != request.subject().user_id())
}

fn membership_context_failure(
    request: &AuthorizationRequest,
    organization_id: &ariadnion_organization::OrganizationId,
) -> Option<AuthorizationDecisionReason> {
    match request.subject().membership() {
        Some(membership) => membership_state_failure(membership, organization_id, request.now()),
        None => Some(AuthorizationDecisionReason::MembershipInactive),
    }
}

fn membership_state_failure(
    membership: &MembershipAuthorizationContext,
    organization_id: &ariadnion_organization::OrganizationId,
    now: ariadnion_user_domain::UtcTimestamp,
) -> Option<AuthorizationDecisionReason> {
    match (
        membership.organization_id() == organization_id,
        membership.organization_state(),
        membership.is_active_at(now),
    ) {
        (false, _, _) => Some(AuthorizationDecisionReason::MembershipInactive),
        (true, OrganizationState::Frozen, _) => {
            Some(AuthorizationDecisionReason::OrganizationFrozen)
        }
        (true, OrganizationState::Active, true) => None,
        (true, OrganizationState::Active, false) => {
            Some(AuthorizationDecisionReason::MembershipInactive)
        }
    }
}

fn resource_failure(request: &AuthorizationRequest) -> Option<AuthorizationDecisionReason> {
    match (request.intent(), request.resource_state()) {
        (AuthorizationIntent::Access, ResourceState::Active)
        | (AuthorizationIntent::Recovery, ResourceState::Restricted) => None,
        _ => Some(AuthorizationDecisionReason::ResourceInactive),
    }
}

fn matching_roles(
    policy: &AuthorizationPolicy,
    request: &AuthorizationRequest,
) -> Vec<MatchedRoleSummary> {
    policy
        .assignments()
        .iter()
        .filter(|assignment| assignment_matches(assignment, request))
        .filter_map(|assignment| matching_role(policy, request, assignment))
        .collect()
}

fn assignment_matches(assignment: &RoleAssignment, request: &AuthorizationRequest) -> bool {
    assignment.principal_id() == request.subject().principal().principal_id()
        && assignment.is_active_at(request.now())
        && assignment.scope().contains(request.scope())
        && active_membership_matches(assignment, request)
}

fn active_membership_matches(assignment: &RoleAssignment, request: &AuthorizationRequest) -> bool {
    request.subject().membership().is_some_and(|membership| {
        assignment.membership_id() == membership.membership_id()
            && request.subject().user_id() == membership.user_id()
            && membership.organization_state() == OrganizationState::Active
            && membership.is_active_at(request.now())
    })
}

fn matching_role(
    policy: &AuthorizationPolicy,
    request: &AuthorizationRequest,
    assignment: &RoleAssignment,
) -> Option<MatchedRoleSummary> {
    let role = policy.role(assignment.role_id())?;
    let rule = role
        .rules()
        .iter()
        .find(|rule| rule.permission_id() == request.permission_id())?;
    Some(MatchedRoleSummary::new(role.id().clone(), rule.effect()))
}

fn permission_reason(matched_roles: &[MatchedRoleSummary]) -> AuthorizationDecisionReason {
    if matched_roles
        .iter()
        .any(|role| role.effect() == PermissionEffect::Deny)
    {
        return AuthorizationDecisionReason::ExplicitDeny;
    }
    if matched_roles
        .iter()
        .any(|role| role.effect() == PermissionEffect::Allow)
    {
        return AuthorizationDecisionReason::ExplicitAllow;
    }
    AuthorizationDecisionReason::NoAllow
}

fn decision(
    policy: &AuthorizationPolicy,
    request: &AuthorizationRequest,
    reason: AuthorizationDecisionReason,
    matched_roles: Vec<MatchedRoleSummary>,
) -> AuthorizationDecision {
    AuthorizationDecision::new(request, policy.version(), reason, matched_roles)
}

//! Tenant-bound scoped role authorization contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod migrations;

mod binding;
mod error;
mod evaluate;
mod ids;
mod model;

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

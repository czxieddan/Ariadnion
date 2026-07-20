//! Tenant-bound scoped role authorization contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

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
    AuthorizationDecision, AuthorizationDecisionReason, AuthorizationPolicy, AuthorizationRequest,
    AuthorizationScope, AuthorizationTarget, MatchedRoleSummary, PermissionEffect, PermissionRule,
    ResourceState, RoleDefinition,
};

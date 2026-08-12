// crates/optional/ariadnion-api-admin/src/model.rs - Rust source for Ariadnion.
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
//! Immutable initial administration command model.

use std::fmt::{self, Debug, Formatter};

use ariadnion_auth_api_key::ApiKeyId;
use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_invitation::InvitationId;
use ariadnion_organization::OrganizationId;
use ariadnion_rbac::{
    AuthorizationDecision, AuthorizationIntent, AuthorizationPolicy, AuthorizationRequest,
    AuthorizationScope, AuthorizationSubject, AuthorizationTarget, DecisionId, PermissionId,
    PolicyVersion, ResourceId, ResourceKind, ResourceState, evaluate,
};
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::error::error;
use crate::{AdminError, AdminErrorCode};

const MAX_COMMAND_ID_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 64;

/// A bounded path-free administration command identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdminCommandId(Box<str>);

impl AdminCommandId {
    /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AdminErrorCode::InvalidArgument`] without retaining rejected input.
    pub fn parse(value: &str) -> Result<Self, AdminError> {
        if !valid_identifier(value) {
            return Err(error(AdminErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AdminCommandId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminCommandId(<opaque>)")
    }
}

/// Stable category of the administration target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdminTargetKind {
    /// A user lifecycle action.
    User,
    /// An organization governance action.
    Organization,
    /// An invitation lifecycle action.
    Invitation,
    /// An API-key lifecycle action.
    ApiKey,
}

/// Stable initial administration action kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdminActionKind {
    /// Suspend a user from new authenticated activity.
    SuspendUser,
    /// Restore a suspended user.
    RestoreUser,
    /// Freeze an organization.
    FreezeOrganization,
    /// Unfreeze an organization.
    UnfreezeOrganization,
    /// Revoke an invitation.
    RevokeInvitation,
    /// Revoke an API key.
    RevokeApiKey,
}

/// One bounded administration target identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminTarget {
    /// A user target.
    User(UserId),
    /// An organization target.
    Organization(OrganizationId),
    /// An invitation target uniquely bound to its owning organization.
    Invitation {
        /// Organization that owns the invitation identity.
        organization_id: OrganizationId,
        /// Invitation identity within the organization.
        invitation_id: InvitationId,
    },
    /// An API-key target.
    ApiKey(ApiKeyId),
}

impl AdminTarget {
    /// Returns the stable target category.
    #[must_use]
    pub const fn kind(&self) -> AdminTargetKind {
        match self {
            Self::User(_) => AdminTargetKind::User,
            Self::Organization(_) => AdminTargetKind::Organization,
            Self::Invitation { .. } => AdminTargetKind::Invitation,
            Self::ApiKey(_) => AdminTargetKind::ApiKey,
        }
    }
}

/// One accepted administration command intent ready for adapter execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminCommand {
    id: AdminCommandId,
    tenant_id: TenantId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    action: AdminActionKind,
    target: AdminTarget,
    reason_code: Box<str>,
    decision_id: DecisionId,
    policy_version: PolicyVersion,
    authorization_subject: AuthorizationSubject,
}

impl AdminCommand {
    /// Returns the command identity.
    #[must_use]
    pub const fn id(&self) -> &AdminCommandId {
        &self.id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the trusted actor.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the trusted UTC command time.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the action kind.
    #[must_use]
    pub const fn action(&self) -> AdminActionKind {
        self.action
    }

    /// Returns the target aggregate.
    #[must_use]
    pub const fn target(&self) -> &AdminTarget {
        &self.target
    }

    /// Returns the stable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }

    /// Returns the authorizing decision identity.
    #[must_use]
    pub const fn decision_id(&self) -> &DecisionId {
        &self.decision_id
    }

    /// Returns the policy version that authorized this command.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Returns the trusted subject identity used for transactional fact reloads.
    ///
    /// Mutable lifecycle, membership, and team facts in this witness are not a
    /// reusable grant. Durable adapters must reload them inside the mutation
    /// transaction before calling [`Self::remains_authorized`].
    #[must_use]
    pub const fn authorization_subject(&self) -> &AuthorizationSubject {
        &self.authorization_subject
    }

    /// Evaluates this exact command against freshly loaded authorization facts.
    ///
    /// `subject` and `evaluated_at` must come from trusted adapters inside the
    /// same transaction that validates the current target and applies the
    /// mutation. The immutable principal, user, organization, and membership
    /// identities must match the accepted command witness. Policy changes,
    /// lifecycle changes, assignment expiry, and membership expiry fail closed.
    #[must_use]
    pub fn remains_authorized(
        &self,
        policy: &AuthorizationPolicy,
        subject: AuthorizationSubject,
        evaluated_at: UtcTimestamp,
    ) -> bool {
        if !same_subject_identity(&self.authorization_subject, &subject) {
            return false;
        }
        let Ok(target) = authorization_target(
            self.action,
            self.tenant_id.clone(),
            &self.target,
            expected_target_state(self.action).1,
        ) else {
            return false;
        };
        let request = AuthorizationRequest::new(
            self.decision_id.clone(),
            self.policy_version,
            subject,
            target,
            evaluated_at,
        );
        evaluate(policy, &request).allowed()
    }
}

/// Tenant-bound identity and expected authorization version for one command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdminCommandBinding {
    id: AdminCommandId,
    tenant_id: TenantId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    decision_id: DecisionId,
    policy_version: PolicyVersion,
}

impl AdminCommandBinding {
    /// Creates command identity metadata bound to one authorization decision.
    #[must_use]
    pub(crate) const fn new(
        id: AdminCommandId,
        tenant_id: TenantId,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
        decision_id: DecisionId,
        policy_version: PolicyVersion,
    ) -> Self {
        Self {
            id,
            tenant_id,
            actor,
            occurred_at,
            decision_id,
            policy_version,
        }
    }
}

/// Trusted inputs required to accept one administration command.
///
/// The decision must be evaluated just in time from the authoritative policy
/// snapshot and authenticated principal by the owning entrypoint. Protocol
/// adapters must never deserialize or persist decisions as reusable grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdminCommandRequest {
    binding: AdminCommandBinding,
    action: AdminActionKind,
    target: AdminTarget,
    reason_code: Box<str>,
    authorization_subject: AuthorizationSubject,
    decision: AuthorizationDecision,
}

impl AdminCommandRequest {
    /// Creates an administration command request after validating the reason code.
    ///
    /// # Errors
    ///
    /// Returns [`AdminErrorCode::InvalidArgument`] for invalid reason codes.
    pub(crate) fn new(
        binding: AdminCommandBinding,
        action: AdminActionKind,
        target: AdminTarget,
        reason_code: &str,
        authorization_subject: AuthorizationSubject,
        decision: AuthorizationDecision,
    ) -> Result<Self, AdminError> {
        Ok(Self {
            binding,
            action,
            target,
            reason_code: parse_reason_code(reason_code)?,
            authorization_subject,
            decision,
        })
    }
}

/// Accepts one administration command when authorization and target kinds align.
///
/// This pure contract does not execute domain transitions. Adapters must invoke
/// the corresponding domain crate after acceptance and append audit events.
///
/// # Errors
///
/// Returns stable redacted failures for tenant mismatch, denied authorization,
/// decision-binding mismatch, or incompatible action/target pairs.
pub(crate) fn accept_admin_command(
    request: AdminCommandRequest,
) -> Result<AdminCommand, AdminError> {
    validate_action_target(request.action, &request.target)?;
    validate_decision(
        &request.binding,
        request.action,
        &request.target,
        &request.decision,
    )?;
    validate_subject_binding(&request.binding, &request.authorization_subject)?;
    Ok(AdminCommand {
        id: request.binding.id,
        tenant_id: request.binding.tenant_id,
        actor: request.binding.actor,
        occurred_at: request.binding.occurred_at,
        action: request.action,
        target: request.target,
        reason_code: request.reason_code,
        decision_id: request.binding.decision_id,
        policy_version: request.binding.policy_version,
        authorization_subject: request.authorization_subject,
    })
}

fn validate_subject_binding(
    binding: &AdminCommandBinding,
    subject: &AuthorizationSubject,
) -> Result<(), AdminError> {
    let principal = subject.principal();
    if principal.tenant_id() != &binding.tenant_id {
        return Err(error(AdminErrorCode::TenantMismatch));
    }
    if principal.principal_id() != &binding.actor {
        return Err(error(AdminErrorCode::DecisionMismatch));
    }
    Ok(())
}

fn same_subject_identity(expected: &AuthorizationSubject, actual: &AuthorizationSubject) -> bool {
    expected.principal() == actual.principal()
        && expected.user_id() == actual.user_id()
        && same_membership_identity(expected, actual)
}

fn same_membership_identity(
    expected: &AuthorizationSubject,
    actual: &AuthorizationSubject,
) -> bool {
    match (expected.membership(), actual.membership()) {
        (None, None) => true,
        (Some(expected), Some(actual)) => {
            (
                expected.tenant_id(),
                expected.organization_id(),
                expected.membership_id(),
                expected.user_id(),
            ) == (
                actual.tenant_id(),
                actual.organization_id(),
                actual.membership_id(),
                actual.user_id(),
            )
        }
        _ => false,
    }
}

fn validate_decision(
    binding: &AdminCommandBinding,
    action: AdminActionKind,
    target: &AdminTarget,
    decision: &AuthorizationDecision,
) -> Result<(), AdminError> {
    validate_decision_identity(binding, decision)?;
    validate_decision_subject(binding, decision)?;
    validate_decision_result(action, decision)?;
    validate_decision_target(binding, action, target, decision)
}

fn validate_decision_identity(
    binding: &AdminCommandBinding,
    decision: &AuthorizationDecision,
) -> Result<(), AdminError> {
    if decision.decision_id() != &binding.decision_id {
        return Err(error(AdminErrorCode::DecisionMismatch));
    }
    if decision.policy_version() != binding.policy_version {
        return Err(error(AdminErrorCode::DecisionMismatch));
    }
    if decision.evaluated_at() != binding.occurred_at {
        return Err(error(AdminErrorCode::DecisionMismatch));
    }
    Ok(())
}

fn validate_decision_subject(
    binding: &AdminCommandBinding,
    decision: &AuthorizationDecision,
) -> Result<(), AdminError> {
    if decision.tenant_id() != &binding.tenant_id {
        return Err(error(AdminErrorCode::TenantMismatch));
    }
    if decision.principal_id() != &binding.actor {
        return Err(error(AdminErrorCode::DecisionMismatch));
    }
    Ok(())
}

fn validate_decision_result(
    action: AdminActionKind,
    decision: &AuthorizationDecision,
) -> Result<(), AdminError> {
    if !decision.allowed() {
        return Err(error(AdminErrorCode::AuthorizationDenied));
    }
    let (intent, state) = expected_target_state(action);
    if decision.intent() != intent || decision.resource_state() != state {
        return Err(error(AdminErrorCode::DecisionMismatch));
    }
    Ok(())
}

pub(crate) fn expected_target_state(
    action: AdminActionKind,
) -> (AuthorizationIntent, ResourceState) {
    match action {
        AdminActionKind::RestoreUser | AdminActionKind::UnfreezeOrganization => {
            (AuthorizationIntent::Recovery, ResourceState::Restricted)
        }
        _ => (AuthorizationIntent::Access, ResourceState::Active),
    }
}

pub(crate) fn authorization_target(
    action: AdminActionKind,
    tenant: TenantId,
    target: &AdminTarget,
    state: ResourceState,
) -> Result<AuthorizationTarget, AdminError> {
    let permission = PermissionId::parse(action_permission(action))
        .map_err(|_| error(AdminErrorCode::IntegrityFailure))?;
    let scope = expected_scope(tenant, target)?;
    let (intent, _) = expected_target_state(action);
    if matches!(intent, AuthorizationIntent::Recovery) {
        return Ok(AuthorizationTarget::for_recovery(permission, scope));
    }
    Ok(AuthorizationTarget::new(permission, scope, state))
}

fn validate_decision_target(
    binding: &AdminCommandBinding,
    action: AdminActionKind,
    target: &AdminTarget,
    decision: &AuthorizationDecision,
) -> Result<(), AdminError> {
    if decision.permission_id().as_str() != action_permission(action) {
        return Err(error(AdminErrorCode::DecisionMismatch));
    }
    let expected_scope = expected_scope(binding.tenant_id.clone(), target)?;
    if decision.scope() != &expected_scope {
        return Err(error(AdminErrorCode::DecisionMismatch));
    }
    Ok(())
}

pub(crate) fn action_permission(action: AdminActionKind) -> &'static str {
    match action {
        AdminActionKind::SuspendUser => "admin.user.suspend",
        AdminActionKind::RestoreUser => "admin.user.restore",
        AdminActionKind::FreezeOrganization => "admin.organization.freeze",
        AdminActionKind::UnfreezeOrganization => "admin.organization.unfreeze",
        AdminActionKind::RevokeInvitation => "admin.invitation.revoke",
        AdminActionKind::RevokeApiKey => "admin.api-key.revoke",
    }
}

pub(crate) fn expected_scope(
    tenant_id: TenantId,
    target: &AdminTarget,
) -> Result<AuthorizationScope, AdminError> {
    match target {
        AdminTarget::Organization(organization_id) => {
            tenant_resource_scope(tenant_id, "organization", organization_id.as_str())
        }
        AdminTarget::User(user_id) => tenant_resource_scope(tenant_id, "user", user_id.as_str()),
        AdminTarget::Invitation {
            organization_id,
            invitation_id,
        } => AuthorizationScope::resource(
            tenant_id,
            organization_id.clone(),
            None,
            ResourceKind::parse("invitation")
                .map_err(|_| error(AdminErrorCode::InvalidArgument))?,
            ResourceId::parse(invitation_id.as_str())
                .map_err(|_| error(AdminErrorCode::InvalidArgument))?,
        )
        .map_err(|_| error(AdminErrorCode::InvalidArgument)),
        AdminTarget::ApiKey(api_key_id) => {
            tenant_resource_scope(tenant_id, "api-key", api_key_id.as_str())
        }
    }
}

fn tenant_resource_scope(
    tenant_id: TenantId,
    kind: &str,
    id: &str,
) -> Result<AuthorizationScope, AdminError> {
    let resource_kind =
        ResourceKind::parse(kind).map_err(|_| error(AdminErrorCode::InvalidArgument))?;
    let resource_id = ResourceId::parse(id).map_err(|_| error(AdminErrorCode::InvalidArgument))?;
    Ok(AuthorizationScope::tenant_resource(
        tenant_id,
        resource_kind,
        resource_id,
    ))
}

pub(crate) fn validate_action_target(
    action: AdminActionKind,
    target: &AdminTarget,
) -> Result<(), AdminError> {
    let compatible = matches!(
        (action, target.kind()),
        (
            AdminActionKind::SuspendUser | AdminActionKind::RestoreUser,
            AdminTargetKind::User
        ) | (
            AdminActionKind::FreezeOrganization | AdminActionKind::UnfreezeOrganization,
            AdminTargetKind::Organization
        ) | (
            AdminActionKind::RevokeInvitation,
            AdminTargetKind::Invitation
        ) | (AdminActionKind::RevokeApiKey, AdminTargetKind::ApiKey)
    );
    if !compatible {
        return Err(error(AdminErrorCode::InvalidArgument));
    }
    Ok(())
}

pub(crate) fn parse_reason_code(value: &str) -> Result<Box<str>, AdminError> {
    if value.is_empty()
        || value.len() > MAX_REASON_BYTES
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(error(AdminErrorCode::InvalidArgument));
    }
    Ok(value.into())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COMMAND_ID_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

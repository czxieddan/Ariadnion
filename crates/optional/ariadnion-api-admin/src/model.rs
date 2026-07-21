//! Immutable initial administration command model.

use std::fmt::{self, Debug, Formatter};

use ariadnion_auth_api_key::ApiKeyId;
use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_invitation::InvitationId;
use ariadnion_organization::OrganizationId;
use ariadnion_rbac::DecisionId;
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
    /// An invitation target.
    Invitation(InvitationId),
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
            Self::Invitation(_) => AdminTargetKind::Invitation,
            Self::ApiKey(_) => AdminTargetKind::ApiKey,
        }
    }
}

/// Trusted precomputed authorization decision summary for one admin command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminDecision {
    decision_id: DecisionId,
    tenant_id: TenantId,
    allowed: bool,
}

impl AdminDecision {
    /// Creates a redacted authorization decision summary.
    #[must_use]
    pub const fn new(decision_id: DecisionId, tenant_id: TenantId, allowed: bool) -> Self {
        Self {
            decision_id,
            tenant_id,
            allowed,
        }
    }

    /// Returns the decision identity.
    #[must_use]
    pub const fn decision_id(&self) -> &DecisionId {
        &self.decision_id
    }

    /// Returns the tenant boundary evaluated by authorization.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns whether authorization explicitly allowed the command.
    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.allowed
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
}

/// Tenant-bound identity for one administration command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminCommandBinding {
    id: AdminCommandId,
    tenant_id: TenantId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
}

impl AdminCommandBinding {
    /// Creates identity metadata for one administration command.
    #[must_use]
    pub const fn new(
        id: AdminCommandId,
        tenant_id: TenantId,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
    ) -> Self {
        Self {
            id,
            tenant_id,
            actor,
            occurred_at,
        }
    }
}

/// Trusted inputs required to accept one administration command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminCommandRequest {
    binding: AdminCommandBinding,
    action: AdminActionKind,
    target: AdminTarget,
    reason_code: Box<str>,
    decision: AdminDecision,
}

impl AdminCommandRequest {
    /// Creates an administration command request after validating the reason code.
    ///
    /// # Errors
    ///
    /// Returns [`AdminErrorCode::InvalidArgument`] for invalid reason codes.
    pub fn new(
        binding: AdminCommandBinding,
        action: AdminActionKind,
        target: AdminTarget,
        reason_code: &str,
        decision: AdminDecision,
    ) -> Result<Self, AdminError> {
        Ok(Self {
            binding,
            action,
            target,
            reason_code: parse_reason_code(reason_code)?,
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
/// or incompatible action/target pairs.
pub fn accept_admin_command(request: AdminCommandRequest) -> Result<AdminCommand, AdminError> {
    validate_action_target(request.action, &request.target)?;
    validate_decision(&request.binding.tenant_id, &request.decision)?;
    Ok(AdminCommand {
        id: request.binding.id,
        tenant_id: request.binding.tenant_id,
        actor: request.binding.actor,
        occurred_at: request.binding.occurred_at,
        action: request.action,
        target: request.target,
        reason_code: request.reason_code,
        decision_id: request.decision.decision_id().clone(),
    })
}

fn validate_decision(tenant_id: &TenantId, decision: &AdminDecision) -> Result<(), AdminError> {
    if decision.tenant_id() != tenant_id {
        return Err(error(AdminErrorCode::TenantMismatch));
    }
    if !decision.allowed() {
        return Err(error(AdminErrorCode::AuthorizationDenied));
    }
    Ok(())
}

fn validate_action_target(action: AdminActionKind, target: &AdminTarget) -> Result<(), AdminError> {
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

fn parse_reason_code(value: &str) -> Result<Box<str>, AdminError> {
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

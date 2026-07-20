//! Deterministic invitation issuance and lifecycle transitions.

use ariadnion_core::{PrincipalContext, PrincipalId, TenantId};
use ariadnion_organization::OrganizationId;
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::error::error;
use crate::{
    Invitation, InvitationError, InvitationErrorCode, InvitationIssueRequest, InvitationState,
    InvitationSubjectDigest, InvitationTokenDigest, InvitationVersion,
    MAX_INVITATION_LIFETIME_SECONDS,
};

/// Trusted recipient identity and normalized subject proof for consumption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedInvitationRecipient {
    principal: PrincipalContext,
    user_id: UserId,
    subject_digest: InvitationSubjectDigest,
}

impl AuthenticatedInvitationRecipient {
    /// Creates a recipient identity established by a trusted authentication adapter.
    ///
    /// The adapter must prove that the principal maps to `user_id` and that the
    /// normalized subject digest belongs to that authenticated user. Raw caller
    /// identifiers do not constitute this evidence.
    #[must_use]
    pub const fn new(
        principal: PrincipalContext,
        user_id: UserId,
        subject_digest: InvitationSubjectDigest,
    ) -> Self {
        Self {
            principal,
            user_id,
            subject_digest,
        }
    }
}

/// Tenant- and organization-bound evidence presented during consumption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationConsumption {
    organization_id: OrganizationId,
    recipient: AuthenticatedInvitationRecipient,
    token_digest: InvitationTokenDigest,
}

impl InvitationConsumption {
    /// Creates immutable one-time consumption evidence.
    #[must_use]
    pub const fn new(
        organization_id: OrganizationId,
        recipient: AuthenticatedInvitationRecipient,
        token_digest: InvitationTokenDigest,
    ) -> Self {
        Self {
            organization_id,
            recipient,
            token_digest,
        }
    }
}

/// One requested invitation lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvitationAction {
    /// Consume the invitation exactly once with matching proof digests.
    Consume(InvitationConsumption),
    /// Revoke an unconsumed invitation.
    Revoke,
    /// Mark an issued invitation expired at or after its boundary.
    Expire,
}

/// Version-bound invitation command with trusted actor and UTC time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationCommand {
    expected_version: InvitationVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    action: InvitationAction,
}

impl InvitationCommand {
    /// Creates a deterministic command without consulting a clock.
    #[must_use]
    pub const fn new(
        expected_version: InvitationVersion,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
        action: InvitationAction,
    ) -> Self {
        Self {
            expected_version,
            actor,
            occurred_at,
            action,
        }
    }
}

/// Stable audit-ready invitation event kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvitationEventKind {
    /// An invitation was issued.
    Issued,
    /// An invitation was consumed.
    Consumed,
    /// An invitation was revoked.
    Revoked,
    /// An invitation reached its explicit expiry transition.
    Expired,
}

/// Immutable audit-ready event produced with every accepted transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationEvent {
    invitation_id: crate::InvitationId,
    tenant_id: TenantId,
    organization_id: OrganizationId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    version: InvitationVersion,
    kind: InvitationEventKind,
    user_id: Option<UserId>,
}

impl InvitationEvent {
    /// Returns the invitation identity.
    #[must_use]
    pub const fn invitation_id(&self) -> &crate::InvitationId {
        &self.invitation_id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the organization boundary.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the trusted actor.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the trusted UTC event time.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the resulting aggregate version.
    #[must_use]
    pub const fn version(&self) -> InvitationVersion {
        self.version
    }

    /// Returns the event kind.
    #[must_use]
    pub const fn kind(&self) -> InvitationEventKind {
        self.kind
    }

    /// Returns the consuming user for a consumption event.
    #[must_use]
    pub const fn user_id(&self) -> Option<&UserId> {
        self.user_id.as_ref()
    }
}

/// One accepted invitation aggregate coupled to its immutable event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationTransition {
    invitation: Invitation,
    event: InvitationEvent,
}

impl InvitationTransition {
    /// Returns the resulting aggregate.
    #[must_use]
    pub const fn invitation(&self) -> &Invitation {
        &self.invitation
    }

    /// Returns the exactly corresponding audit event.
    #[must_use]
    pub const fn event(&self) -> &InvitationEvent {
        &self.event
    }

    /// Consumes the result into aggregate and event.
    #[must_use]
    pub fn into_parts(self) -> (Invitation, InvitationEvent) {
        (self.invitation, self.event)
    }
}

/// Issues one bounded invitation and its version-one audit event.
///
/// # Errors
/// Returns [`InvitationErrorCode::InvalidArgument`] unless expiry is later
/// than issuance and no more than [`MAX_INVITATION_LIFETIME_SECONDS`] away.
pub fn issue(request: InvitationIssueRequest) -> Result<InvitationTransition, InvitationError> {
    validate_lifetime(request.issued_at, request.expires_at)?;
    let invitation = Invitation::issued(request);
    let event = event_from(
        &invitation,
        invitation.issuer().clone(),
        invitation.issued_at(),
        InvitationEventKind::Issued,
        None,
    );
    Ok(InvitationTransition { invitation, event })
}

/// Applies one deterministic optimistic invitation transition.
///
/// # Errors
/// Returns stable redacted failures for cross-boundary evidence, stale
/// versions, invalid proof digests, expiry, terminal state, or exhaustion.
pub fn transition(
    invitation: &Invitation,
    command: InvitationCommand,
) -> Result<InvitationTransition, InvitationError> {
    validate_consumption_scope(invitation, &command)?;
    validate_expected_version(invitation, command.expected_version)?;
    validate_command_time(invitation, command.occurred_at)?;
    validate_current_state(invitation.state())?;
    let (state, kind, user_id) = apply_action(invitation, &command)?;
    let version = invitation.version().next()?;
    let next = invitation.advance(version, state, user_id.clone());
    let event = event_from(&next, command.actor, command.occurred_at, kind, user_id);
    Ok(InvitationTransition {
        invitation: next,
        event,
    })
}

fn validate_lifetime(
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
) -> Result<(), InvitationError> {
    let lifetime = expires_at
        .unix_seconds()
        .checked_sub(issued_at.unix_seconds())
        .ok_or_else(|| error(InvitationErrorCode::InvalidArgument))?;
    if !(1..=MAX_INVITATION_LIFETIME_SECONDS).contains(&lifetime) {
        return Err(error(InvitationErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_consumption_scope(
    invitation: &Invitation,
    command: &InvitationCommand,
) -> Result<(), InvitationError> {
    let InvitationAction::Consume(consumption) = &command.action else {
        return Ok(());
    };
    validate_consumption_boundaries(invitation, consumption)?;
    validate_recipient_actor(command, consumption)
}

fn validate_consumption_boundaries(
    invitation: &Invitation,
    consumption: &InvitationConsumption,
) -> Result<(), InvitationError> {
    if consumption.recipient.principal.tenant_id() != invitation.tenant_id() {
        return Err(error(InvitationErrorCode::TenantMismatch));
    }
    if consumption.organization_id != *invitation.organization_id() {
        return Err(error(InvitationErrorCode::OrganizationMismatch));
    }
    Ok(())
}

fn validate_recipient_actor(
    command: &InvitationCommand,
    consumption: &InvitationConsumption,
) -> Result<(), InvitationError> {
    if consumption.recipient.principal.principal_id() != &command.actor {
        return Err(error(InvitationErrorCode::RecipientPrincipalMismatch));
    }
    Ok(())
}

fn validate_expected_version(
    invitation: &Invitation,
    expected: InvitationVersion,
) -> Result<(), InvitationError> {
    if invitation.version() != expected {
        return Err(error(InvitationErrorCode::VersionConflict));
    }
    Ok(())
}

fn validate_command_time(
    invitation: &Invitation,
    occurred_at: UtcTimestamp,
) -> Result<(), InvitationError> {
    if occurred_at < invitation.issued_at() {
        return Err(error(InvitationErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_current_state(state: InvitationState) -> Result<(), InvitationError> {
    match state {
        InvitationState::Issued => Ok(()),
        InvitationState::Consumed => Err(error(InvitationErrorCode::AlreadyConsumed)),
        InvitationState::Revoked => Err(error(InvitationErrorCode::Revoked)),
        InvitationState::Expired => Err(error(InvitationErrorCode::Expired)),
    }
}

fn apply_action(
    invitation: &Invitation,
    command: &InvitationCommand,
) -> Result<(InvitationState, InvitationEventKind, Option<UserId>), InvitationError> {
    match &command.action {
        InvitationAction::Consume(consumption) => {
            apply_consumption(invitation, consumption, command.occurred_at)
        }
        InvitationAction::Revoke => apply_revocation(invitation, command.occurred_at),
        InvitationAction::Expire => apply_expiry(invitation, command.occurred_at),
    }
}

fn apply_consumption(
    invitation: &Invitation,
    consumption: &InvitationConsumption,
    occurred_at: UtcTimestamp,
) -> Result<(InvitationState, InvitationEventKind, Option<UserId>), InvitationError> {
    require_not_expired(invitation, occurred_at)?;
    if consumption.recipient.subject_digest != invitation.subject_digest() {
        return Err(error(InvitationErrorCode::SubjectMismatch));
    }
    if !constant_time_digest_eq(
        consumption.token_digest.bytes(),
        invitation.token_digest().bytes(),
    ) {
        return Err(error(InvitationErrorCode::TokenMismatch));
    }
    Ok((
        InvitationState::Consumed,
        InvitationEventKind::Consumed,
        Some(consumption.recipient.user_id.clone()),
    ))
}

fn apply_revocation(
    invitation: &Invitation,
    occurred_at: UtcTimestamp,
) -> Result<(InvitationState, InvitationEventKind, Option<UserId>), InvitationError> {
    require_not_expired(invitation, occurred_at)?;
    Ok((InvitationState::Revoked, InvitationEventKind::Revoked, None))
}

fn apply_expiry(
    invitation: &Invitation,
    occurred_at: UtcTimestamp,
) -> Result<(InvitationState, InvitationEventKind, Option<UserId>), InvitationError> {
    if occurred_at < invitation.expires_at() {
        return Err(error(InvitationErrorCode::NotYetExpired));
    }
    Ok((InvitationState::Expired, InvitationEventKind::Expired, None))
}

fn require_not_expired(
    invitation: &Invitation,
    occurred_at: UtcTimestamp,
) -> Result<(), InvitationError> {
    if occurred_at >= invitation.expires_at() {
        return Err(error(InvitationErrorCode::Expired));
    }
    Ok(())
}

fn constant_time_digest_eq(left: [u8; 32], right: [u8; 32]) -> bool {
    left.into_iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn event_from(
    invitation: &Invitation,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    kind: InvitationEventKind,
    user_id: Option<UserId>,
) -> InvitationEvent {
    InvitationEvent {
        invitation_id: invitation.id().clone(),
        tenant_id: invitation.tenant_id().clone(),
        organization_id: invitation.organization_id().clone(),
        actor,
        occurred_at,
        version: invitation.version(),
        kind,
        user_id,
    }
}

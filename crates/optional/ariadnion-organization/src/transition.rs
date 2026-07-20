//! Version-checked organization commands and deterministic transitions.

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::error::{OrganizationError, OrganizationErrorCode, error};
use crate::ids::{MembershipId, OrganizationId, OrganizationVersion, TeamId};
use crate::model::{
    MAX_MEMBERSHIPS, MAX_REAUTHENTICATION_AGE_SECONDS, MAX_TEAM_ASSIGNMENTS, MAX_TEAMS, Membership,
    MembershipKind, MembershipOrigin, MembershipState, Organization, OrganizationEvent,
    OrganizationEventKind, OrganizationFounder, OrganizationState, OrganizationTransition,
    OwnershipTransferEvidence, Team,
};

/// A version-bound request to create one organization and founder owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateOrganizationCommand {
    organization_id: OrganizationId,
    tenant_id: TenantId,
    founder: OrganizationFounder,
    expected_version: OrganizationVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
}

impl CreateOrganizationCommand {
    /// Creates an organization-creation command with trusted audit context.
    #[must_use]
    pub const fn new(
        organization_id: OrganizationId,
        tenant_id: TenantId,
        founder: OrganizationFounder,
        expected_version: OrganizationVersion,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
    ) -> Self {
        Self {
            organization_id,
            tenant_id,
            founder,
            expected_version,
            actor,
            occurred_at,
        }
    }
}

/// A requested membership lifecycle or governance change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipAction {
    /// Adds one active membership.
    Add {
        /// Stable membership identity.
        membership_id: MembershipId,
        /// User represented by the membership.
        user_id: UserId,
        /// Initial governance kind.
        kind: MembershipKind,
        /// Audited membership origin.
        origin: MembershipOrigin,
        /// Optional expiry permitted only for non-owner memberships.
        expires_at: Option<UtcTimestamp>,
    },
    /// Suspends an active membership.
    Suspend {
        /// Stable membership identity.
        membership_id: MembershipId,
    },
    /// Reactivates a suspended, non-expired membership.
    Activate {
        /// Stable membership identity.
        membership_id: MembershipId,
    },
    /// Marks a membership as left and clears all team assignments.
    Leave {
        /// Stable membership identity.
        membership_id: MembershipId,
    },
}

/// A requested team registry or assignment change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TeamAction {
    /// Registers a new team.
    Create {
        /// Stable team identity.
        team_id: TeamId,
    },
    /// Assigns an eligible membership to a registered team.
    Assign {
        /// Stable membership identity.
        membership_id: MembershipId,
        /// Stable team identity.
        team_id: TeamId,
    },
}

/// A requested organization aggregate change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrganizationAction {
    /// Changes organization state without changing membership state.
    ChangeState {
        /// New operational organization state.
        state: OrganizationState,
    },
    /// Applies a membership lifecycle or governance action.
    Membership(MembershipAction),
    /// Applies a team registry or assignment action.
    Team(TeamAction),
    /// Applies an evidence-bound atomic ownership transfer.
    TransferOwnership {
        /// Short-lived authorization evidence bound to the current version.
        evidence: OwnershipTransferEvidence,
    },
}

/// An organization action coupled to version and trusted audit context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationCommand {
    expected_version: OrganizationVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    action: OrganizationAction,
}

impl OrganizationCommand {
    /// Creates a deterministic, optimistic-version-checked command.
    #[must_use]
    pub const fn new(
        expected_version: OrganizationVersion,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
        action: OrganizationAction,
    ) -> Self {
        Self {
            expected_version,
            actor,
            occurred_at,
            action,
        }
    }

    /// Returns the optimistic version required by this command.
    #[must_use]
    pub const fn expected_version(&self) -> OrganizationVersion {
        self.expected_version
    }

    /// Returns the authenticated actor attributed to this command.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the trusted UTC instant attributed to this command.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the requested aggregate action.
    #[must_use]
    pub const fn action(&self) -> &OrganizationAction {
        &self.action
    }
}

#[derive(Clone)]
struct AuditContext {
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
}

/// Creates an organization with exactly one active founder owner.
///
/// Creation accepts only [`OrganizationVersion::initial`] as its expected
/// version and returns that same version in the aggregate and audit event.
///
/// # Errors
/// Returns [`OrganizationErrorCode::VersionConflict`] when the command does
/// not target the initial version.
pub fn create_organization(
    command: CreateOrganizationCommand,
) -> Result<OrganizationTransition, OrganizationError> {
    if command.expected_version != OrganizationVersion::initial() {
        return Err(error(OrganizationErrorCode::VersionConflict));
    }
    let founder_id = command.founder.membership_id().clone();
    let organization = initial_organization(&command);
    let event = OrganizationEvent {
        tenant_id: command.tenant_id,
        organization_id: command.organization_id,
        actor: command.actor,
        occurred_at: command.occurred_at,
        version: OrganizationVersion::initial(),
        kind: OrganizationEventKind::Created {
            founder_membership_id: founder_id,
        },
    };
    Ok(OrganizationTransition {
        organization,
        event,
    })
}

/// Applies a version-checked command without mutating the input aggregate.
///
/// The caller supplies the authenticated actor and trusted UTC instant. This
/// pure function reads no clock, persistence, network, process-global state,
/// raw JSON, or secret material.
///
/// # Errors
/// Returns a stable [`OrganizationErrorCode`] for version conflicts, invalid
/// lifecycle changes, bounded-capacity failures, team ineligibility, final
/// owner protection, ownership evidence rejection, or version exhaustion.
pub fn transition(
    current: &Organization,
    command: OrganizationCommand,
) -> Result<OrganizationTransition, OrganizationError> {
    verify_expected_version(current, command.expected_version)?;
    let audit = AuditContext {
        actor: command.actor,
        occurred_at: command.occurred_at,
    };
    dispatch(current, &audit, command.action)
}

fn initial_organization(command: &CreateOrganizationCommand) -> Organization {
    let founder = Membership {
        id: command.founder.membership_id().clone(),
        user_id: command.founder.user_id().clone(),
        kind: MembershipKind::Owner,
        state: MembershipState::Active,
        origin: MembershipOrigin::Founder,
        expires_at: None,
        team_ids: Vec::new(),
    };
    Organization {
        id: command.organization_id.clone(),
        tenant_id: command.tenant_id.clone(),
        version: OrganizationVersion::initial(),
        state: OrganizationState::Active,
        memberships: vec![founder],
        teams: Vec::new(),
    }
}

fn verify_expected_version(
    current: &Organization,
    expected: OrganizationVersion,
) -> Result<(), OrganizationError> {
    if current.version != expected {
        return Err(error(OrganizationErrorCode::VersionConflict));
    }
    Ok(())
}

fn dispatch(
    current: &Organization,
    audit: &AuditContext,
    action: OrganizationAction,
) -> Result<OrganizationTransition, OrganizationError> {
    match action {
        OrganizationAction::ChangeState { state } => change_state(current, audit, state),
        OrganizationAction::Membership(action) => apply_membership_action(current, audit, action),
        OrganizationAction::Team(action) => apply_team_action(current, audit, action),
        OrganizationAction::TransferOwnership { evidence } => {
            transfer_ownership(current, audit, evidence)
        }
    }
}

fn change_state(
    current: &Organization,
    audit: &AuditContext,
    state: OrganizationState,
) -> Result<OrganizationTransition, OrganizationError> {
    if current.state == state {
        return Err(error(OrganizationErrorCode::InvalidTransition));
    }
    let mut next = current.clone();
    next.state = state;
    finish_evolution(
        current,
        next,
        audit,
        OrganizationEventKind::StateChanged { state },
    )
}

fn apply_membership_action(
    current: &Organization,
    audit: &AuditContext,
    action: MembershipAction,
) -> Result<OrganizationTransition, OrganizationError> {
    match action {
        MembershipAction::Add {
            membership_id,
            user_id,
            kind,
            origin,
            expires_at,
        } => add_membership(
            current,
            audit,
            NewMembership {
                membership_id,
                user_id,
                kind,
                origin,
                expires_at,
            },
        ),
        MembershipAction::Suspend { membership_id } => {
            suspend_membership(current, audit, &membership_id)
        }
        MembershipAction::Activate { membership_id } => {
            activate_membership(current, audit, &membership_id)
        }
        MembershipAction::Leave { membership_id } => {
            leave_membership(current, audit, &membership_id)
        }
    }
}

struct NewMembership {
    membership_id: MembershipId,
    user_id: UserId,
    kind: MembershipKind,
    origin: MembershipOrigin,
    expires_at: Option<UtcTimestamp>,
}

fn add_membership(
    current: &Organization,
    audit: &AuditContext,
    input: NewMembership,
) -> Result<OrganizationTransition, OrganizationError> {
    validate_new_membership(current, audit.occurred_at, &input)?;
    let kind = input.kind;
    let membership_id = input.membership_id.clone();
    let membership = Membership {
        id: input.membership_id,
        user_id: input.user_id,
        kind,
        state: MembershipState::Active,
        origin: input.origin,
        expires_at: input.expires_at,
        team_ids: Vec::new(),
    };
    let mut next = current.clone();
    next.memberships.push(membership);
    finish_evolution(
        current,
        next,
        audit,
        OrganizationEventKind::MembershipAdded {
            membership_id,
            kind,
        },
    )
}

fn validate_new_membership(
    current: &Organization,
    occurred_at: UtcTimestamp,
    input: &NewMembership,
) -> Result<(), OrganizationError> {
    ensure_membership_capacity(current)?;
    ensure_membership_identity_available(current, input)?;
    validate_membership_metadata(occurred_at, input)?;
    Ok(())
}

fn ensure_membership_capacity(current: &Organization) -> Result<(), OrganizationError> {
    if current.memberships.len() >= MAX_MEMBERSHIPS {
        return Err(error(OrganizationErrorCode::CapacityExceeded));
    }
    Ok(())
}

fn ensure_membership_identity_available(
    current: &Organization,
    input: &NewMembership,
) -> Result<(), OrganizationError> {
    let duplicate_id = current
        .memberships
        .iter()
        .any(|membership| membership.id == input.membership_id);
    let duplicate_user = current
        .memberships
        .iter()
        .any(|membership| membership.user_id == input.user_id);
    if duplicate_id || duplicate_user {
        return Err(error(OrganizationErrorCode::DuplicateIdentity));
    }
    Ok(())
}

fn validate_membership_metadata(
    occurred_at: UtcTimestamp,
    input: &NewMembership,
) -> Result<(), OrganizationError> {
    if input.origin == MembershipOrigin::Founder {
        return Err(error(OrganizationErrorCode::InvalidArgument));
    }
    if input.kind == MembershipKind::Owner && input.expires_at.is_some() {
        return Err(error(OrganizationErrorCode::InvalidArgument));
    }
    if input.expires_at.is_some_and(|expiry| expiry <= occurred_at) {
        return Err(error(OrganizationErrorCode::InvalidArgument));
    }
    Ok(())
}

fn suspend_membership(
    current: &Organization,
    audit: &AuditContext,
    membership_id: &MembershipId,
) -> Result<OrganizationTransition, OrganizationError> {
    let index = membership_index(current, membership_id)?;
    require_membership_state(current, index, MembershipState::Active)?;
    protect_last_active_owner(current, index)?;
    let mut next = current.clone();
    set_membership_state(&mut next, index, MembershipState::Suspended)?;
    finish_evolution(
        current,
        next,
        audit,
        OrganizationEventKind::MembershipSuspended {
            membership_id: membership_id.clone(),
        },
    )
}

fn activate_membership(
    current: &Organization,
    audit: &AuditContext,
    membership_id: &MembershipId,
) -> Result<OrganizationTransition, OrganizationError> {
    let index = membership_index(current, membership_id)?;
    require_membership_state(current, index, MembershipState::Suspended)?;
    let membership = membership_at(current, index)?;
    if membership
        .expires_at
        .is_some_and(|expires_at| audit.occurred_at >= expires_at)
    {
        return Err(error(OrganizationErrorCode::MembershipIneligible));
    }
    let mut next = current.clone();
    set_membership_state(&mut next, index, MembershipState::Active)?;
    finish_evolution(
        current,
        next,
        audit,
        OrganizationEventKind::MembershipActivated {
            membership_id: membership_id.clone(),
        },
    )
}

fn leave_membership(
    current: &Organization,
    audit: &AuditContext,
    membership_id: &MembershipId,
) -> Result<OrganizationTransition, OrganizationError> {
    let index = membership_index(current, membership_id)?;
    reject_left_membership(current, index)?;
    protect_last_active_owner(current, index)?;
    let mut next = current.clone();
    let removed = leave_and_clear_teams(&mut next, index)?;
    finish_evolution(
        current,
        next,
        audit,
        OrganizationEventKind::MembershipLeft {
            membership_id: membership_id.clone(),
            removed_team_assignments: removed,
        },
    )
}

fn reject_left_membership(current: &Organization, index: usize) -> Result<(), OrganizationError> {
    if membership_at(current, index)?.state == MembershipState::Left {
        return Err(error(OrganizationErrorCode::InvalidTransition));
    }
    Ok(())
}

fn protect_last_active_owner(
    current: &Organization,
    index: usize,
) -> Result<(), OrganizationError> {
    let membership = membership_at(current, index)?;
    let deactivates_owner =
        membership.kind == MembershipKind::Owner && membership.state == MembershipState::Active;
    if deactivates_owner && active_owner_count(current) == 1 {
        return Err(error(OrganizationErrorCode::LastActiveOwner));
    }
    Ok(())
}

fn active_owner_count(current: &Organization) -> usize {
    current
        .memberships
        .iter()
        .filter(|membership| {
            membership.kind == MembershipKind::Owner && membership.state == MembershipState::Active
        })
        .count()
}

fn leave_and_clear_teams(
    organization: &mut Organization,
    index: usize,
) -> Result<usize, OrganizationError> {
    let membership = membership_at_mut(organization, index)?;
    let removed = membership.team_ids.len();
    membership.team_ids.clear();
    membership.state = MembershipState::Left;
    Ok(removed)
}

fn apply_team_action(
    current: &Organization,
    audit: &AuditContext,
    action: TeamAction,
) -> Result<OrganizationTransition, OrganizationError> {
    match action {
        TeamAction::Create { team_id } => create_team(current, audit, team_id),
        TeamAction::Assign {
            membership_id,
            team_id,
        } => assign_team(current, audit, &membership_id, &team_id),
    }
}

fn create_team(
    current: &Organization,
    audit: &AuditContext,
    team_id: TeamId,
) -> Result<OrganizationTransition, OrganizationError> {
    if current.teams.len() >= MAX_TEAMS {
        return Err(error(OrganizationErrorCode::CapacityExceeded));
    }
    if current.teams.iter().any(|team| team.id == team_id) {
        return Err(error(OrganizationErrorCode::DuplicateIdentity));
    }
    let mut next = current.clone();
    next.teams.push(Team {
        id: team_id.clone(),
    });
    finish_evolution(
        current,
        next,
        audit,
        OrganizationEventKind::TeamCreated { team_id },
    )
}

fn assign_team(
    current: &Organization,
    audit: &AuditContext,
    membership_id: &MembershipId,
    team_id: &TeamId,
) -> Result<OrganizationTransition, OrganizationError> {
    ensure_team_exists(current, team_id)?;
    let index = membership_index(current, membership_id)?;
    let membership = membership_at(current, index)?;
    ensure_team_assignment_eligible(membership, audit.occurred_at, team_id)?;
    let mut next = current.clone();
    membership_at_mut(&mut next, index)?
        .team_ids
        .push(team_id.clone());
    finish_evolution(
        current,
        next,
        audit,
        OrganizationEventKind::TeamAssigned {
            membership_id: membership_id.clone(),
            team_id: team_id.clone(),
        },
    )
}

fn ensure_team_exists(current: &Organization, team_id: &TeamId) -> Result<(), OrganizationError> {
    if current.teams.iter().any(|team| team.id == *team_id) {
        return Ok(());
    }
    Err(error(OrganizationErrorCode::TeamNotFound))
}

fn ensure_team_assignment_eligible(
    membership: &Membership,
    observed_at: UtcTimestamp,
    team_id: &TeamId,
) -> Result<(), OrganizationError> {
    if !membership.is_eligible_at(observed_at) {
        return Err(error(OrganizationErrorCode::MembershipIneligible));
    }
    if membership
        .team_ids
        .iter()
        .any(|assigned| assigned == team_id)
    {
        return Err(error(OrganizationErrorCode::DuplicateIdentity));
    }
    if membership.team_ids.len() >= MAX_TEAM_ASSIGNMENTS {
        return Err(error(OrganizationErrorCode::CapacityExceeded));
    }
    Ok(())
}

fn transfer_ownership(
    current: &Organization,
    audit: &AuditContext,
    evidence: OwnershipTransferEvidence,
) -> Result<OrganizationTransition, OrganizationError> {
    validate_transfer_binding(current, &evidence)?;
    validate_transfer_timing(audit, &evidence)?;
    let initiating_index = membership_index_for_transfer(current, &evidence.initiating_owner_id)?;
    let recipient_index = membership_index_for_transfer(current, &evidence.recipient_id)?;
    validate_transfer_members(current, audit, &evidence, initiating_index, recipient_index)?;
    let mut next = current.clone();
    demote_owner(&mut next, initiating_index)?;
    promote_recipient(&mut next, recipient_index)?;
    let kind = OrganizationEventKind::OwnershipTransferred {
        transfer_id: evidence.transfer_id,
        previous_owner_id: evidence.initiating_owner_id,
        new_owner_id: evidence.recipient_id,
        approver: evidence.approver,
    };
    finish_evolution(current, next, audit, kind)
}

fn validate_transfer_binding(
    current: &Organization,
    evidence: &OwnershipTransferEvidence,
) -> Result<(), OrganizationError> {
    let wrong_tenant = evidence.tenant_id != current.tenant_id;
    let wrong_organization = evidence.organization_id != current.id;
    let wrong_version = evidence.organization_version != current.version;
    if wrong_tenant || wrong_organization || wrong_version {
        return Err(error(OrganizationErrorCode::TransferOrganizationMismatch));
    }
    Ok(())
}

fn validate_transfer_timing(
    audit: &AuditContext,
    evidence: &OwnershipTransferEvidence,
) -> Result<(), OrganizationError> {
    validate_transfer_actors(audit, evidence)?;
    validate_transfer_window(audit.occurred_at, evidence)?;
    validate_reauthentication_freshness(audit.occurred_at, evidence.recipient_reauthenticated_at)
}

fn validate_transfer_actors(
    audit: &AuditContext,
    evidence: &OwnershipTransferEvidence,
) -> Result<(), OrganizationError> {
    if evidence.initiating_actor != audit.actor {
        return Err(error(OrganizationErrorCode::TransferEvidenceInvalid));
    }
    if evidence.approver == evidence.initiating_actor {
        return Err(error(OrganizationErrorCode::TransferApproverConflict));
    }
    Ok(())
}

fn validate_transfer_window(
    observed_at: UtcTimestamp,
    evidence: &OwnershipTransferEvidence,
) -> Result<(), OrganizationError> {
    if observed_at < evidence.not_before {
        return Err(error(OrganizationErrorCode::TransferNotReady));
    }
    if observed_at > evidence.expires_at {
        return Err(error(OrganizationErrorCode::TransferExpired));
    }
    Ok(())
}

fn validate_reauthentication_freshness(
    observed_at: UtcTimestamp,
    reauthenticated_at: UtcTimestamp,
) -> Result<(), OrganizationError> {
    let age = observed_at
        .unix_seconds()
        .checked_sub(reauthenticated_at.unix_seconds());
    let stale =
        age.is_none_or(|seconds| !(0..=MAX_REAUTHENTICATION_AGE_SECONDS).contains(&seconds));
    if stale {
        return Err(error(OrganizationErrorCode::TransferReauthenticationStale));
    }
    Ok(())
}

fn membership_index_for_transfer(
    current: &Organization,
    membership_id: &MembershipId,
) -> Result<usize, OrganizationError> {
    membership_index(current, membership_id)
        .map_err(|_| error(OrganizationErrorCode::TransferEvidenceInvalid))
}

fn validate_transfer_members(
    current: &Organization,
    audit: &AuditContext,
    evidence: &OwnershipTransferEvidence,
    initiating_index: usize,
    recipient_index: usize,
) -> Result<(), OrganizationError> {
    let initiator = membership_at(current, initiating_index)?;
    let recipient = membership_at(current, recipient_index)?;
    let valid_initiator =
        initiator.kind == MembershipKind::Owner && initiator.state == MembershipState::Active;
    let valid_recipient = recipient.kind == MembershipKind::Member
        && recipient.user_id == evidence.recipient_user_id
        && recipient.is_eligible_at(audit.occurred_at);
    if !valid_initiator || !valid_recipient {
        return Err(error(OrganizationErrorCode::TransferEvidenceInvalid));
    }
    Ok(())
}

fn demote_owner(organization: &mut Organization, index: usize) -> Result<(), OrganizationError> {
    membership_at_mut(organization, index)?.kind = MembershipKind::Member;
    Ok(())
}

fn promote_recipient(
    organization: &mut Organization,
    index: usize,
) -> Result<(), OrganizationError> {
    let recipient = membership_at_mut(organization, index)?;
    recipient.kind = MembershipKind::Owner;
    recipient.expires_at = None;
    Ok(())
}

fn membership_index(
    current: &Organization,
    membership_id: &MembershipId,
) -> Result<usize, OrganizationError> {
    current
        .memberships
        .iter()
        .position(|membership| membership.id == *membership_id)
        .ok_or_else(|| error(OrganizationErrorCode::MembershipNotFound))
}

fn membership_at(current: &Organization, index: usize) -> Result<&Membership, OrganizationError> {
    current
        .memberships
        .get(index)
        .ok_or_else(|| error(OrganizationErrorCode::MembershipNotFound))
}

fn membership_at_mut(
    current: &mut Organization,
    index: usize,
) -> Result<&mut Membership, OrganizationError> {
    current
        .memberships
        .get_mut(index)
        .ok_or_else(|| error(OrganizationErrorCode::MembershipNotFound))
}

fn require_membership_state(
    current: &Organization,
    index: usize,
    required: MembershipState,
) -> Result<(), OrganizationError> {
    if membership_at(current, index)?.state != required {
        return Err(error(OrganizationErrorCode::InvalidTransition));
    }
    Ok(())
}

fn set_membership_state(
    current: &mut Organization,
    index: usize,
    state: MembershipState,
) -> Result<(), OrganizationError> {
    membership_at_mut(current, index)?.state = state;
    Ok(())
}

fn finish_evolution(
    current: &Organization,
    mut next: Organization,
    audit: &AuditContext,
    kind: OrganizationEventKind,
) -> Result<OrganizationTransition, OrganizationError> {
    let version = current.version.next()?;
    next.version = version;
    let event = OrganizationEvent {
        tenant_id: current.tenant_id.clone(),
        organization_id: current.id.clone(),
        actor: audit.actor.clone(),
        occurred_at: audit.occurred_at,
        version,
        kind,
    };
    Ok(OrganizationTransition {
        organization: next,
        event,
    })
}

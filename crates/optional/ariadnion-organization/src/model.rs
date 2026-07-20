//! Immutable organization aggregate state, evidence, and audit event models.

use ariadnion_core::{PrincipalContext, PrincipalId, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::error::{OrganizationError, OrganizationErrorCode, error};
use crate::ids::{MembershipId, OrganizationId, OrganizationVersion, OwnershipTransferId, TeamId};

pub(crate) const MAX_MEMBERSHIPS: usize = 1_024;
pub(crate) const MAX_TEAMS: usize = 256;
pub(crate) const MAX_TEAM_ASSIGNMENTS: usize = 64;
pub(crate) const MAX_REAUTHENTICATION_AGE_SECONDS: i64 = 300;
const MAX_TRANSFER_LIFETIME_SECONDS: i64 = 900;

/// The operational state of an organization independent of user state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OrganizationState {
    /// Organization activity is permitted by the domain state.
    Active,
    /// Organization activity is administratively frozen.
    Frozen,
}

/// The governance role held by one membership.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MembershipKind {
    /// The membership participates in organization ownership governance.
    Owner,
    /// The membership has no ownership governance authority.
    Member,
}

/// The lifecycle state of one organization membership.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MembershipState {
    /// The membership may participate subject to its optional expiry.
    Active,
    /// The membership is retained but cannot participate.
    Suspended,
    /// The membership has left and cannot be reactivated.
    Left,
}

/// The audited origin of one organization membership.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MembershipOrigin {
    /// The membership founded the organization.
    Founder,
    /// The membership was created from an accepted invitation.
    Invitation,
    /// The membership was created by an administrative action.
    Administrative,
}

/// The founder identity pair used during organization creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationFounder {
    membership_id: MembershipId,
    user_id: UserId,
}

impl OrganizationFounder {
    /// Creates a founder from its membership and user identities.
    #[must_use]
    pub const fn new(membership_id: MembershipId, user_id: UserId) -> Self {
        Self {
            membership_id,
            user_id,
        }
    }

    pub(crate) const fn membership_id(&self) -> &MembershipId {
        &self.membership_id
    }

    pub(crate) const fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

/// An immutable organization membership with bounded team assignments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Membership {
    pub(crate) id: MembershipId,
    pub(crate) user_id: UserId,
    pub(crate) kind: MembershipKind,
    pub(crate) state: MembershipState,
    pub(crate) origin: MembershipOrigin,
    pub(crate) expires_at: Option<UtcTimestamp>,
    pub(crate) team_ids: Vec<TeamId>,
}

impl Membership {
    /// Returns the stable membership identity.
    #[must_use]
    pub const fn id(&self) -> &MembershipId {
        &self.id
    }

    /// Returns the user represented by this membership.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the ownership governance kind.
    #[must_use]
    pub const fn kind(&self) -> MembershipKind {
        self.kind
    }

    /// Returns the stored membership lifecycle state.
    #[must_use]
    pub const fn state(&self) -> MembershipState {
        self.state
    }

    /// Returns the audited membership origin.
    #[must_use]
    pub const fn origin(&self) -> MembershipOrigin {
        self.origin
    }

    /// Returns the optional non-owner expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UtcTimestamp> {
        self.expires_at
    }

    /// Returns active team assignments observed at a trusted UTC instant.
    ///
    /// Suspended, left, or expired memberships expose no team assignments.
    /// Assignments are returned in deterministic insertion order.
    #[must_use]
    pub fn active_team_ids_at(&self, observed_at: UtcTimestamp) -> &[TeamId] {
        if self.is_eligible_at(observed_at) {
            &self.team_ids
        } else {
            &[]
        }
    }

    pub(crate) fn is_eligible_at(&self, observed_at: UtcTimestamp) -> bool {
        self.state == MembershipState::Active
            && self
                .expires_at
                .is_none_or(|expires_at| observed_at < expires_at)
    }
}

/// An immutable organization team identity registered in the aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Team {
    pub(crate) id: TeamId,
}

impl Team {
    /// Returns the stable team identity.
    #[must_use]
    pub const fn id(&self) -> &TeamId {
        &self.id
    }
}

/// An immutable tenant-bound organization aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Organization {
    pub(crate) id: OrganizationId,
    pub(crate) tenant_id: TenantId,
    pub(crate) version: OrganizationVersion,
    pub(crate) state: OrganizationState,
    pub(crate) memberships: Vec<Membership>,
    pub(crate) teams: Vec<Team>,
}

impl Organization {
    /// Returns the stable organization identity.
    #[must_use]
    pub const fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// Returns the explicit tenant mapping for this organization.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the current optimistic version.
    #[must_use]
    pub const fn version(&self) -> OrganizationVersion {
        self.version
    }

    /// Returns the organization state independent of membership state.
    #[must_use]
    pub const fn state(&self) -> OrganizationState {
        self.state
    }

    /// Returns all immutable memberships in deterministic insertion order.
    #[must_use]
    pub fn memberships(&self) -> &[Membership] {
        &self.memberships
    }

    /// Returns a membership by stable identity.
    #[must_use]
    pub fn membership(&self, id: &MembershipId) -> Option<&Membership> {
        self.memberships
            .iter()
            .find(|membership| membership.id == *id)
    }

    /// Returns all registered teams in deterministic insertion order.
    #[must_use]
    pub fn teams(&self) -> &[Team] {
        &self.teams
    }

    /// Returns a team by stable identity.
    #[must_use]
    pub fn team(&self, id: &TeamId) -> Option<&Team> {
        self.teams.iter().find(|team| team.id == *id)
    }
}

/// A trusted authentication adapter's principal-to-user identity binding.
///
/// This type is a trust boundary, not an authenticator. An adapter may create
/// it only after authenticating the principal and resolving the represented
/// user. Raw request fields must not be wrapped as an authenticated binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedUserBinding {
    principal: PrincipalContext,
    user_id: UserId,
}

impl AuthenticatedUserBinding {
    /// Creates a binding from identity facts established by authentication.
    ///
    /// The caller is responsible for ensuring an authentication adapter, rather
    /// than untrusted request data, established the principal-to-user mapping.
    #[must_use]
    pub const fn new(principal: PrincipalContext, user_id: UserId) -> Self {
        Self { principal, user_id }
    }

    /// Returns the authenticated tenant and principal context.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalContext {
        &self.principal
    }

    /// Returns the user identity authenticated for the principal.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

/// A recipient identity binding established by fresh reauthentication.
///
/// A trusted authentication adapter supplies both the authenticated binding
/// and the trusted UTC completion time. Caller-provided identities or clocks
/// do not constitute this proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientReauthenticationProof {
    authenticated_user: AuthenticatedUserBinding,
    authenticated_at: UtcTimestamp,
}

impl RecipientReauthenticationProof {
    /// Creates a proof from a successful reauthentication result.
    ///
    /// The caller is responsible for supplying an adapter-authenticated user
    /// binding and the adapter's trusted completion time.
    #[must_use]
    pub const fn new(
        authenticated_user: AuthenticatedUserBinding,
        authenticated_at: UtcTimestamp,
    ) -> Self {
        Self {
            authenticated_user,
            authenticated_at,
        }
    }

    /// Returns the recipient identity established by reauthentication.
    #[must_use]
    pub const fn authenticated_user(&self) -> &AuthenticatedUserBinding {
        &self.authenticated_user
    }

    /// Returns the trusted UTC completion time of reauthentication.
    #[must_use]
    pub const fn authenticated_at(&self) -> UtcTimestamp {
        self.authenticated_at
    }
}

/// Fields supplied to the ownership-evidence constructor.
///
/// Authentication adapters must supply the initiating user binding, recipient
/// reauthentication proof, and approving context. Raw principal, user, or time
/// values supplied by a caller cannot constitute transfer evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransferEvidenceInput {
    /// Stable evidence identity used to detect replay outside this domain.
    pub transfer_id: OwnershipTransferId,
    /// Tenant identity to which the evidence is bound.
    pub tenant_id: TenantId,
    /// Organization identity to which the evidence is bound.
    pub organization_id: OrganizationId,
    /// Aggregate version to which the evidence is bound.
    pub organization_version: OrganizationVersion,
    /// Active owner membership that will be demoted.
    pub initiating_owner_id: MembershipId,
    /// Authenticated principal-to-user binding that initiated the transfer.
    pub initiating_user: AuthenticatedUserBinding,
    /// Active recipient membership that will be promoted.
    pub recipient_id: MembershipId,
    /// Authenticated recipient identity and trusted reauthentication time.
    pub recipient_reauthentication: RecipientReauthenticationProof,
    /// Distinct core-authenticated principal context that approved the transfer.
    pub approving_principal: PrincipalContext,
    /// Earliest trusted UTC instant at which transfer may occur.
    pub not_before: UtcTimestamp,
    /// Final trusted UTC instant at which the evidence remains valid.
    pub expires_at: UtcTimestamp,
}

/// Short-lived, tenant- and organization-bound evidence for an ownership transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransferEvidence {
    pub(crate) transfer_id: OwnershipTransferId,
    pub(crate) tenant_id: TenantId,
    pub(crate) organization_id: OrganizationId,
    pub(crate) organization_version: OrganizationVersion,
    pub(crate) initiating_owner_id: MembershipId,
    pub(crate) initiating_user: AuthenticatedUserBinding,
    pub(crate) recipient_id: MembershipId,
    pub(crate) recipient_reauthentication: RecipientReauthenticationProof,
    pub(crate) approver: PrincipalId,
    pub(crate) not_before: UtcTimestamp,
    pub(crate) expires_at: UtcTimestamp,
}

impl OwnershipTransferEvidence {
    /// Validates authenticated identity bindings and creates immutable evidence.
    ///
    /// Both principal contexts must be produced by a trusted authentication
    /// adapter, belong to the evidence tenant, and identify distinct principals.
    /// Wrapping raw or caller-supplied principal identifiers is not approval.
    /// The not-before boundary must follow recipient reauthentication, and the
    /// expiry must follow not-before by no more than 15 minutes. Aggregate,
    /// actor, membership, freshness, and observation-time bindings are checked
    /// again when the command is applied.
    ///
    /// # Errors
    /// Returns [`OrganizationErrorCode::TransferOrganizationMismatch`] when an
    /// authenticated context belongs to another tenant,
    /// [`OrganizationErrorCode::TransferApproverConflict`] when both contexts
    /// identify the same principal, or
    /// [`OrganizationErrorCode::TransferEvidenceInvalid`] for an inverted,
    /// non-future, overlong, or self-directed transfer interval.
    pub fn new(input: OwnershipTransferEvidenceInput) -> Result<Self, OrganizationError> {
        validate_transfer_evidence_input(&input)?;
        let approver = input.approving_principal.principal_id().clone();
        Ok(Self {
            transfer_id: input.transfer_id,
            tenant_id: input.tenant_id,
            organization_id: input.organization_id,
            organization_version: input.organization_version,
            initiating_owner_id: input.initiating_owner_id,
            initiating_user: input.initiating_user,
            recipient_id: input.recipient_id,
            recipient_reauthentication: input.recipient_reauthentication,
            approver,
            not_before: input.not_before,
            expires_at: input.expires_at,
        })
    }
}

/// The stable domain facts emitted by one accepted organization command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrganizationEventKind {
    /// An organization was created with one active founder owner.
    Created {
        /// Founder membership created by the command.
        founder_membership_id: MembershipId,
    },
    /// The organization operational state changed.
    StateChanged {
        /// New organization state.
        state: OrganizationState,
    },
    /// A membership was added.
    MembershipAdded {
        /// Membership created by the command.
        membership_id: MembershipId,
        /// Governance kind assigned to the membership.
        kind: MembershipKind,
    },
    /// An active membership was suspended.
    MembershipSuspended {
        /// Membership affected by the command.
        membership_id: MembershipId,
        /// Number of team assignments removed atomically.
        removed_team_assignments: usize,
    },
    /// A suspended membership returned to active state.
    MembershipActivated {
        /// Membership affected by the command.
        membership_id: MembershipId,
    },
    /// A membership left and its team assignments were removed.
    MembershipLeft {
        /// Membership affected by the command.
        membership_id: MembershipId,
        /// Number of team assignments removed atomically.
        removed_team_assignments: usize,
    },
    /// A team was registered.
    TeamCreated {
        /// Team created by the command.
        team_id: TeamId,
    },
    /// An eligible membership was assigned to a team.
    TeamAssigned {
        /// Membership receiving the assignment.
        membership_id: MembershipId,
        /// Team assigned to the membership.
        team_id: TeamId,
    },
    /// Ownership was atomically transferred between two active memberships.
    OwnershipTransferred {
        /// Evidence identity authorizing the transfer.
        transfer_id: OwnershipTransferId,
        /// Owner membership demoted by the transfer.
        previous_owner_id: MembershipId,
        /// Recipient membership promoted by the transfer.
        new_owner_id: MembershipId,
        /// Distinct principal that approved the transfer.
        approver: PrincipalId,
    },
}

/// An immutable audit-ready event emitted after an accepted command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationEvent {
    pub(crate) tenant_id: TenantId,
    pub(crate) organization_id: OrganizationId,
    pub(crate) actor: PrincipalId,
    pub(crate) occurred_at: UtcTimestamp,
    pub(crate) version: OrganizationVersion,
    pub(crate) kind: OrganizationEventKind,
}

impl OrganizationEvent {
    /// Returns the explicit tenant mapping captured by this event.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the affected organization identity.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the authenticated principal attributed to the command.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the trusted UTC instant attributed to the command.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the new aggregate version produced by the command.
    #[must_use]
    pub const fn version(&self) -> OrganizationVersion {
        self.version
    }

    /// Returns the stable domain-specific event kind and facts.
    #[must_use]
    pub const fn kind(&self) -> &OrganizationEventKind {
        &self.kind
    }
}

/// The new immutable aggregate and its exactly corresponding audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationTransition {
    pub(crate) organization: Organization,
    pub(crate) event: OrganizationEvent,
}

impl OrganizationTransition {
    /// Returns the new immutable organization aggregate.
    #[must_use]
    pub const fn organization(&self) -> &Organization {
        &self.organization
    }

    /// Returns the audit-ready event describing the accepted command.
    #[must_use]
    pub const fn event(&self) -> &OrganizationEvent {
        &self.event
    }

    /// Consumes the result into its aggregate and event parts.
    #[must_use]
    pub fn into_parts(self) -> (Organization, OrganizationEvent) {
        (self.organization, self.event)
    }
}

fn validate_transfer_evidence_input(
    input: &OwnershipTransferEvidenceInput,
) -> Result<(), OrganizationError> {
    validate_transfer_principals(input)?;
    if input.initiating_owner_id == input.recipient_id {
        return Err(error(OrganizationErrorCode::TransferEvidenceInvalid));
    }
    let reauthentication = input
        .recipient_reauthentication
        .authenticated_at()
        .unix_seconds();
    let not_before = input.not_before.unix_seconds();
    let expires_at = input.expires_at.unix_seconds();
    let delay = not_before.checked_sub(reauthentication);
    let lifetime = expires_at.checked_sub(not_before);
    if delay.is_none_or(|seconds| seconds <= 0) || !valid_transfer_lifetime(lifetime) {
        return Err(error(OrganizationErrorCode::TransferEvidenceInvalid));
    }
    Ok(())
}

fn validate_transfer_principals(
    input: &OwnershipTransferEvidenceInput,
) -> Result<(), OrganizationError> {
    let initiator_tenant_matches =
        input.initiating_user.principal().tenant_id() == &input.tenant_id;
    let recipient_tenant_matches = input
        .recipient_reauthentication
        .authenticated_user()
        .principal()
        .tenant_id()
        == &input.tenant_id;
    let approver_tenant_matches = input.approving_principal.tenant_id() == &input.tenant_id;
    if !initiator_tenant_matches || !recipient_tenant_matches || !approver_tenant_matches {
        return Err(error(OrganizationErrorCode::TransferOrganizationMismatch));
    }
    if input.initiating_user.principal().principal_id() == input.approving_principal.principal_id()
    {
        return Err(error(OrganizationErrorCode::TransferApproverConflict));
    }
    Ok(())
}

fn valid_transfer_lifetime(lifetime: Option<i64>) -> bool {
    lifetime.is_some_and(|seconds| seconds > 0 && seconds <= MAX_TRANSFER_LIFETIME_SECONDS)
}

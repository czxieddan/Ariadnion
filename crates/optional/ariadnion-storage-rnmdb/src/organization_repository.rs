//! Atomic durable persistence for tenant-bound organization transitions.

mod decode;
mod evidence;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_organization::{
    MembershipKind, MembershipOrigin, MembershipSnapshot, MembershipState, Organization,
    OrganizationCommitReceipt, OrganizationEventKind, OrganizationId, OrganizationRepositoryError,
    OrganizationRepositoryErrorCode, OrganizationRepositoryPort, OrganizationState,
    OrganizationTransition, OrganizationVersion,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::LocalSession;

use crate::identity_transaction::run_identity_transaction;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Maximum number of organization events verified by one bounded read.
pub const MAX_ORGANIZATION_EVENT_HISTORY_ROWS: u64 = 65_536;

/// Persists exact organization snapshots and immutable transition evidence.
pub struct RnmdbOrganizationRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(ariadnion_storage_domain::StorageErrorCode::IntegrityFailure)
}

fn map_fresh_insert_error(error: StorageError) -> StorageError {
    use ariadnion_storage_domain::StorageErrorCode;

    match error.code() {
        StorageErrorCode::Unavailable
        | StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::ResourceExhausted => error,
        _ => integrity_failure(),
    }
}

impl RnmdbOrganizationRepository {
    /// Opens a repository over a newly created serialized RNMDB session.
    ///
    /// Use this constructor for read reconciliation after a prior commit
    /// returned an indeterminate outcome. The tainted repository must be
    /// discarded and reopened with fresh secret material.
    ///
    /// # Errors
    /// Returns a redacted storage error when the encrypted database cannot be
    /// opened with the supplied validated options.
    pub fn open(
        options: SessionOpenOptions,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let session = RnmdbSessionOwner::open(options).map(Arc::new)?;
        Ok(Self::new(session, audit_subject_key))
    }

    /// Creates a repository over one serialized session and subject key.
    ///
    /// Wrapping a tainted session does not make it reusable. Reopen with fresh
    /// options after an indeterminate commit.
    #[must_use]
    pub const fn new(
        session: Arc<RnmdbSessionOwner>,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Self {
        Self {
            session,
            audit_subject_key,
        }
    }
}

impl OrganizationRepositoryPort for RnmdbOrganizationRepository {
    fn load(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        context: &RequestContext,
    ) -> Result<Organization, OrganizationRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_organization(session, tenant_id, organization_id)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: OrganizationVersion,
        transition: &OrganizationTransition,
        context: &RequestContext,
    ) -> Result<OrganizationCommitReceipt, OrganizationRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            expected_previous_version,
            transition,
            context,
        };
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_transaction_session(context, tenant_id, |session| {
                run_identity_transaction(session, context, |session| {
                    commit_in_transaction(session, &request, &self.audit_subject_key)
                })
            })
            .map_err(map_storage_error)
    }

    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: OrganizationVersion,
        transition: &OrganizationTransition,
        context: &RequestContext,
    ) -> Result<OrganizationCommitReceipt, OrganizationRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            expected_previous_version,
            transition,
            context,
        };
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                reconcile_exact(session, &request, &self.audit_subject_key)
            })
            .map_err(map_storage_error)
    }
}

struct CommitRequest<'a> {
    tenant_id: &'a TenantId,
    expected_previous_version: OrganizationVersion,
    transition: &'a OrganizationTransition,
    context: &'a RequestContext,
}

fn commit_in_transaction(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<OrganizationCommitReceipt, StorageError> {
    validate_commit_request(request)?;
    match request.transition.previous_snapshot() {
        None => persist_creation(session, request)?,
        Some(previous) => persist_update(session, request, previous)?,
    }
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, key, committed_at)?;
    let organization = request.transition.organization();
    Ok(OrganizationCommitReceipt::new(
        request.tenant_id.clone(),
        organization.id().clone(),
        organization.version(),
        committed_at,
    ))
}

fn persist_update(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    previous: &ariadnion_organization::OrganizationSnapshot,
) -> Result<(), StorageError> {
    validate_update(request)?;
    let organization = request.transition.organization();
    let durable = decode::load_organization(session, request.tenant_id, organization.id())?;
    if durable.version() != request.expected_previous_version
        || durable.snapshot_state() != *previous
    {
        return Err(sql::conflict());
    }
    sql::update_header(
        session,
        request.tenant_id,
        organization.id(),
        request.expected_previous_version,
        organization.version(),
        organization_state_label(organization.state()),
    )?;
    let assignments = previous
        .memberships()
        .iter()
        .map(|membership| membership.team_ids().len())
        .sum();
    sql::delete_snapshot_rows(
        session,
        request.tenant_id,
        organization.id(),
        assignments,
        previous.memberships().len(),
        previous.teams().len(),
    )?;
    persist_snapshot_rows(session, organization)?;
    persist_event(session, request)
}

fn persist_creation(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    validate_creation(request)?;
    let organization = request.transition.organization();
    ensure_creation_absent(session, request.tenant_id, organization.id())?;
    insert_creation_header(
        session,
        request.tenant_id,
        organization.id(),
        organization.version(),
        organization_state_label(organization.state()),
    )?;
    persist_snapshot_rows(session, organization)?;
    persist_event(session, request)
}

fn insert_creation_header(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    version: OrganizationVersion,
    state: &str,
) -> Result<(), StorageError> {
    let result = sql::insert_header(session, tenant, organization, version, state);
    match result {
        Ok(()) => Ok(()),
        Err(error) => classify_creation_insert_error(session, tenant, organization, error),
    }
}

fn classify_creation_insert_error(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    original: StorageError,
) -> Result<(), StorageError> {
    match decode::load_organization(session, tenant, organization) {
        Ok(_) => Err(sql::conflict()),
        Err(_) => Err(original),
    }
}

fn ensure_creation_absent(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<(), StorageError> {
    match decode::load_organization(session, tenant, organization) {
        Ok(_) => Err(sql::conflict()),
        Err(error) if error.code() == StorageErrorCode::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn persist_snapshot_rows(
    session: &mut LocalSession,
    organization: &Organization,
) -> Result<(), StorageError> {
    let snapshot = organization.snapshot_state();
    for (ordinal, membership) in snapshot.memberships().iter().enumerate() {
        persist_membership(session, organization, ordinal, membership)?;
    }
    for (ordinal, team) in snapshot.teams().iter().enumerate() {
        sql::insert_team(
            session,
            organization.tenant_id(),
            organization.id(),
            ordinal,
            team.id().as_str(),
        )?;
    }
    Ok(())
}

fn persist_membership(
    session: &mut LocalSession,
    organization: &Organization,
    ordinal: usize,
    membership: &MembershipSnapshot,
) -> Result<(), StorageError> {
    sql::insert_membership(
        session,
        sql::MembershipInsert {
            tenant: organization.tenant_id(),
            organization: organization.id(),
            ordinal,
            membership_id: membership.id().as_str(),
            user_id: membership.user_id().as_str(),
            kind: membership_kind_label(membership.kind()),
            state: membership_state_label(membership.state()),
            origin: membership_origin_label(membership.origin()),
            expires_at: membership.expires_at().map(UtcTimestamp::unix_seconds),
        },
    )?;
    for (assignment_ordinal, team) in membership.team_ids().iter().enumerate() {
        sql::insert_assignment(
            session,
            organization.tenant_id(),
            organization.id(),
            membership.id().as_str(),
            assignment_ordinal,
            team.as_str(),
        )?;
    }
    Ok(())
}

fn persist_event(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let event = request.transition.event();
    let facts = EventFacts::from_kind(event.kind())?;
    let removed = facts
        .removed
        .map(|value| i64::try_from(value).map_err(|_| integrity_failure()))
        .transpose()?;
    let fields = [
        sql::SqlField::Text(event.tenant_id().as_str()),
        sql::SqlField::Text(event.organization_id().as_str()),
        sql::SqlField::Text(&sql::encode_version(event.version())),
        sql::SqlField::Text(facts.kind),
        sql::SqlField::Int(event.occurred_at().unix_seconds()),
        sql::SqlField::Text(event.actor().as_str()),
        sql::SqlField::Text(request.context.request_id().as_str()),
        optional_text_field(facts.organization_state),
        optional_text_field(facts.membership_id),
        optional_text_field(facts.membership_kind),
        optional_int_field(removed),
        optional_text_field(facts.team_id),
        optional_text_field(facts.transfer_id),
        optional_text_field(facts.previous_owner_id),
        optional_text_field(facts.new_owner_id),
        optional_text_field(facts.approver_id),
        optional_text_field(facts.membership_user_id),
        optional_text_field(facts.membership_origin),
        optional_int_field(facts.membership_expires_at),
    ];
    sql::insert_event(session, &fields)
}

struct EventFacts<'a> {
    kind: &'static str,
    organization_state: Option<&'static str>,
    membership_id: Option<&'a str>,
    membership_kind: Option<&'static str>,
    removed: Option<usize>,
    team_id: Option<&'a str>,
    transfer_id: Option<&'a str>,
    previous_owner_id: Option<&'a str>,
    new_owner_id: Option<&'a str>,
    approver_id: Option<&'a str>,
    membership_user_id: Option<&'a str>,
    membership_origin: Option<&'static str>,
    membership_expires_at: Option<i64>,
}

impl<'a> EventFacts<'a> {
    fn from_kind(kind: &'a OrganizationEventKind) -> Result<Self, StorageError> {
        if let Some(facts) = Self::from_organization_kind(kind) {
            return Ok(facts);
        }
        Self::from_membership_kind(kind).ok_or_else(integrity_failure)
    }

    fn from_organization_kind(kind: &'a OrganizationEventKind) -> Option<Self> {
        let mut facts = Self::empty();
        match kind {
            OrganizationEventKind::Created {
                founder_membership_id,
                founder_user_id,
            } => {
                facts.kind = "created";
                facts.membership_id = Some(founder_membership_id.as_str());
                facts.membership_user_id = Some(founder_user_id.as_str());
            }
            OrganizationEventKind::StateChanged { state } => {
                facts.kind = "state_changed";
                facts.organization_state = Some(organization_state_label(*state));
            }
            OrganizationEventKind::TeamCreated { team_id } => {
                facts.kind = "team_created";
                facts.team_id = Some(team_id.as_str());
            }
            OrganizationEventKind::TeamAssigned {
                membership_id,
                team_id,
            } => {
                facts.kind = "team_assigned";
                facts.membership_id = Some(membership_id.as_str());
                facts.team_id = Some(team_id.as_str());
            }
            OrganizationEventKind::OwnershipTransferred {
                transfer_id,
                previous_owner_id,
                new_owner_id,
                approver,
            } => {
                facts.kind = "ownership_transferred";
                facts.transfer_id = Some(transfer_id.as_str());
                facts.previous_owner_id = Some(previous_owner_id.as_str());
                facts.new_owner_id = Some(new_owner_id.as_str());
                facts.approver_id = Some(approver.as_str());
            }
            _ => return None,
        }
        Some(facts)
    }

    fn from_membership_kind(kind: &'a OrganizationEventKind) -> Option<Self> {
        let mut facts = Self::empty();
        match kind {
            OrganizationEventKind::MembershipAdded {
                membership_id,
                user_id,
                kind,
                origin,
                expires_at,
            } => {
                facts.kind = "membership_added";
                facts.membership_id = Some(membership_id.as_str());
                facts.membership_user_id = Some(user_id.as_str());
                facts.membership_kind = Some(membership_kind_label(*kind));
                facts.membership_origin = Some(membership_origin_label(*origin));
                facts.membership_expires_at = expires_at.map(UtcTimestamp::unix_seconds);
            }
            OrganizationEventKind::MembershipSuspended {
                membership_id,
                removed_team_assignments,
            } => {
                facts.kind = "membership_suspended";
                facts.membership_id = Some(membership_id.as_str());
                facts.removed = Some(*removed_team_assignments);
            }
            OrganizationEventKind::MembershipActivated { membership_id } => {
                facts.kind = "membership_activated";
                facts.membership_id = Some(membership_id.as_str());
            }
            OrganizationEventKind::MembershipLeft {
                membership_id,
                removed_team_assignments,
            } => {
                facts.kind = "membership_left";
                facts.membership_id = Some(membership_id.as_str());
                facts.removed = Some(*removed_team_assignments);
            }
            _ => return None,
        }
        Some(facts)
    }

    const fn empty() -> Self {
        Self {
            kind: "",
            organization_state: None,
            membership_id: None,
            membership_kind: None,
            removed: None,
            team_id: None,
            transfer_id: None,
            previous_owner_id: None,
            new_owner_id: None,
            approver_id: None,
            membership_user_id: None,
            membership_origin: None,
            membership_expires_at: None,
        }
    }
}

fn validate_commit_request(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    validate_authenticated_tenant(request.context, request.tenant_id)?;
    let principal = authenticated_principal(request.context)?;
    let organization = request.transition.organization();
    let event = request.transition.event();
    let valid = organization.tenant_id() == request.tenant_id
        && event.tenant_id() == request.tenant_id
        && event.organization_id() == organization.id()
        && event.version() == organization.version()
        && event.actor() == principal.principal_id();
    if !valid {
        return Err(integrity_failure());
    }
    validate_history_capacity(organization.version())
}

fn validate_history_capacity(version: OrganizationVersion) -> Result<(), StorageError> {
    if version.get() <= MAX_ORGANIZATION_EVENT_HISTORY_ROWS {
        return Ok(());
    }
    Err(StorageError::new(StorageErrorCode::ResourceExhausted))
}

fn validate_creation(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let initial = OrganizationVersion::initial();
    let valid = request.expected_previous_version == initial
        && request.transition.organization().version() == initial
        && matches!(
            request.transition.event().kind(),
            OrganizationEventKind::Created { .. }
        );
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_update(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let expected = request
        .expected_previous_version
        .next()
        .map_err(|_| integrity_failure())?;
    if request.transition.organization().version() != expected
        || matches!(
            request.transition.event().kind(),
            OrganizationEventKind::Created { .. }
        )
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_authenticated_tenant(
    context: &RequestContext,
    tenant: &TenantId,
) -> Result<(), StorageError> {
    if authenticated_principal(context)?.tenant_id() != tenant {
        return Err(integrity_failure());
    }
    Ok(())
}

fn authenticated_principal(context: &RequestContext) -> Result<&PrincipalContext, StorageError> {
    context.principal().ok_or_else(integrity_failure)
}

fn reconcile_exact(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<OrganizationCommitReceipt, StorageError> {
    validate_commit_request(request)?;
    let expected = request.transition.organization();
    let durable = decode::load_organization(session, request.tenant_id, expected.id())
        .map_err(map_reconcile_load_error)?;
    let later = reconcile_snapshot_history(session, expected, &durable)?;
    decode::verify_event_request(
        session,
        request.tenant_id,
        expected.id(),
        expected.version(),
        request.context.request_id(),
    )?;
    let committed_at = evidence::reconcile_transition_evidence(session, request, key)?;
    evidence::verify_later_transition_evidence(session, request, key, later)?;
    Ok(OrganizationCommitReceipt::new(
        request.tenant_id.clone(),
        expected.id().clone(),
        expected.version(),
        committed_at,
    ))
}

fn map_reconcile_load_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::Unavailable
        | StorageErrorCode::ResourceExhausted => error,
        _ => integrity_failure(),
    }
}

fn reconcile_snapshot_history(
    session: &mut LocalSession,
    expected: &Organization,
    durable: &Organization,
) -> Result<
    Vec<(
        ariadnion_core::RequestId,
        ariadnion_organization::OrganizationEvent,
    )>,
    StorageError,
> {
    if durable.version() < expected.version() {
        return Err(integrity_failure());
    }
    if durable.version() > expected.version() {
        return decode::verify_later_history(session, expected, durable);
    }
    if durable != expected {
        return Err(integrity_failure());
    }
    Ok(Vec::new())
}

fn trusted_commit_time() -> Result<UtcTimestamp, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure())?;
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| integrity_failure())?;
    Ok(UtcTimestamp::from_unix_seconds(seconds))
}

const fn organization_state_label(value: OrganizationState) -> &'static str {
    match value {
        OrganizationState::Active => "active",
        OrganizationState::Frozen => "frozen",
    }
}

const fn membership_kind_label(value: MembershipKind) -> &'static str {
    match value {
        MembershipKind::Owner => "owner",
        MembershipKind::Member => "member",
    }
}

const fn membership_state_label(value: MembershipState) -> &'static str {
    match value {
        MembershipState::Active => "active",
        MembershipState::Suspended => "suspended",
        MembershipState::Left => "left",
    }
}

const fn membership_origin_label(value: MembershipOrigin) -> &'static str {
    match value {
        MembershipOrigin::Founder => "founder",
        MembershipOrigin::Invitation => "invitation",
        MembershipOrigin::Administrative => "administrative",
    }
}

const fn optional_text_field(value: Option<&str>) -> sql::SqlField<'_> {
    match value {
        Some(value) => sql::SqlField::Text(value),
        None => sql::SqlField::Null,
    }
}

const fn optional_int_field(value: Option<i64>) -> sql::SqlField<'static> {
    match value {
        Some(value) => sql::SqlField::Int(value),
        None => sql::SqlField::Null,
    }
}

fn map_storage_error(error: StorageError) -> OrganizationRepositoryError {
    let code = match error.code() {
        StorageErrorCode::NotFound => OrganizationRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => OrganizationRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => OrganizationRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => OrganizationRepositoryErrorCode::DeadlineExceeded,
        StorageErrorCode::ResourceExhausted => OrganizationRepositoryErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => OrganizationRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => {
            OrganizationRepositoryErrorCode::CommitIndeterminate
        }
        _ => OrganizationRepositoryErrorCode::IntegrityFailure,
    };
    OrganizationRepositoryError::new(code)
}

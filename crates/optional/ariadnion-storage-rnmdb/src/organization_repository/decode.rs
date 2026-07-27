//! Strict bounded decoding for organization snapshots and event history.

mod event;

use std::collections::HashMap;

use ariadnion_core::TenantId;
use ariadnion_organization::{
    MAX_MEMBERSHIPS, MAX_TEAMS, MembershipId, MembershipKind, MembershipOrigin, MembershipSnapshot,
    MembershipState, Organization, OrganizationId, OrganizationSnapshot, OrganizationState,
    OrganizationVersion, TeamId, TeamSnapshot, replay_persisted_event,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use self::event::PersistedOrganizationEvent;
use super::{MAX_ORGANIZATION_EVENT_HISTORY_ROWS, integrity_failure, sql};

const VERSION_TEXT_BYTES: usize = 20;

pub(super) fn load_organization(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<Organization, StorageError> {
    let (version, state) = load_header(session, tenant, organization)?;
    let teams = load_teams(session, tenant, organization)?;
    let assignments = load_assignments(session, tenant, organization)?;
    let memberships = load_memberships(session, tenant, organization, assignments)?;
    let snapshot = OrganizationSnapshot::new(state, memberships, teams);
    let organization =
        Organization::from_snapshot(organization.clone(), tenant.clone(), version, snapshot)
            .map_err(|_| integrity_failure())?;
    verify_history(session, &organization)?;
    Ok(organization)
}

pub(super) fn verify_event_request(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    version: OrganizationVersion,
    request_id: &ariadnion_core::RequestId,
) -> Result<(), StorageError> {
    let events = load_events(session, tenant, organization)?;
    let index = event_index(version)?;
    let persisted = events.get(index).ok_or_else(integrity_failure)?;
    if persisted.request_id() != request_id {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn verify_later_history(
    session: &mut LocalSession,
    target: &Organization,
    durable: &Organization,
) -> Result<
    Vec<(
        ariadnion_core::RequestId,
        ariadnion_organization::OrganizationEvent,
    )>,
    StorageError,
> {
    let events = load_events(session, durable.tenant_id(), durable.id())?;
    if events.len() != expected_history_rows(durable.version())? {
        return Err(integrity_failure());
    }
    let start = event_index(target.version())?
        .checked_add(1)
        .ok_or_else(integrity_failure)?;
    let persisted = events.get(start..).ok_or_else(integrity_failure)?;
    replay_later_events(target, durable, persisted)
}

fn replay_later_events(
    target: &Organization,
    durable: &Organization,
    events: &[PersistedOrganizationEvent],
) -> Result<
    Vec<(
        ariadnion_core::RequestId,
        ariadnion_organization::OrganizationEvent,
    )>,
    StorageError,
> {
    let mut current = target.clone();
    let mut later = Vec::with_capacity(events.len());
    for persisted in events {
        current =
            replay_persisted_event(&current, persisted.event()).map_err(|_| integrity_failure())?;
        later.push((persisted.request_id().clone(), persisted.event().clone()));
    }
    if current != *durable {
        return Err(integrity_failure());
    }
    Ok(later)
}

fn event_index(version: OrganizationVersion) -> Result<usize, StorageError> {
    let index = version.get().checked_sub(1).ok_or_else(integrity_failure)?;
    usize::try_from(index).map_err(|_| integrity_failure())
}

fn load_header(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<(OrganizationVersion, OrganizationState), StorageError> {
    let batch = rows(sql::load_header(session, tenant, organization)?)?;
    validate_columns(batch.columns(), &header_columns())?;
    match batch.rows() {
        [] => Err(StorageError::new(StorageErrorCode::NotFound)),
        [row] => decode_header(row, tenant, organization),
        _ => Err(integrity_failure()),
    }
}

fn decode_header(
    row: &Row,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<(OrganizationVersion, OrganizationState), StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_organization),
        SqlValue::Text(version),
        SqlValue::Text(state),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_identity(found_tenant, found_organization, tenant, organization)?;
    Ok((decode_version(version)?, decode_organization_state(state)?))
}

fn load_teams(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<Vec<TeamSnapshot>, StorageError> {
    let batch = rows(sql::load_teams(session, tenant, organization)?)?;
    validate_columns(batch.columns(), &team_columns())?;
    if batch.rows().len() > MAX_TEAMS {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    batch
        .rows()
        .iter()
        .enumerate()
        .map(|(ordinal, row)| decode_team(row, tenant, organization, ordinal))
        .collect()
}

fn decode_team(
    row: &Row,
    tenant: &TenantId,
    organization: &OrganizationId,
    ordinal: usize,
) -> Result<TeamSnapshot, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_organization),
        SqlValue::Int64(found_ordinal),
        SqlValue::Text(team),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_identity(found_tenant, found_organization, tenant, organization)?;
    validate_ordinal(*found_ordinal, ordinal)?;
    Ok(TeamSnapshot::new(
        TeamId::parse(team).map_err(|_| integrity_failure())?,
    ))
}

fn load_assignments(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<HashMap<MembershipId, Vec<TeamId>>, StorageError> {
    let batch = rows(sql::load_assignments(session, tenant, organization)?)?;
    validate_columns(batch.columns(), &assignment_columns())?;
    if batch.rows().len() > MAX_MEMBERSHIPS * ariadnion_organization::MAX_TEAM_ASSIGNMENTS {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    let mut assignments = HashMap::new();
    for row in batch.rows() {
        decode_assignment(row, tenant, organization, &mut assignments)?;
    }
    Ok(assignments)
}

fn decode_assignment(
    row: &Row,
    tenant: &TenantId,
    organization: &OrganizationId,
    assignments: &mut HashMap<MembershipId, Vec<TeamId>>,
) -> Result<(), StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_organization),
        SqlValue::Text(membership),
        SqlValue::Int64(ordinal),
        SqlValue::Text(team),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_identity(found_tenant, found_organization, tenant, organization)?;
    let membership = MembershipId::parse(membership).map_err(|_| integrity_failure())?;
    let values = assignments.entry(membership).or_default();
    validate_ordinal(*ordinal, values.len())?;
    values.push(TeamId::parse(team).map_err(|_| integrity_failure())?);
    Ok(())
}

fn load_memberships(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    mut assignments: HashMap<MembershipId, Vec<TeamId>>,
) -> Result<Vec<MembershipSnapshot>, StorageError> {
    let batch = rows(sql::load_memberships(session, tenant, organization)?)?;
    validate_columns(batch.columns(), &membership_columns())?;
    if batch.rows().len() > MAX_MEMBERSHIPS {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    let memberships = decode_membership_rows(batch.rows(), tenant, organization, &mut assignments)?;
    reject_residual_assignments(&assignments)?;
    Ok(memberships)
}

fn decode_membership_rows(
    rows: &[Row],
    tenant: &TenantId,
    organization: &OrganizationId,
    assignments: &mut HashMap<MembershipId, Vec<TeamId>>,
) -> Result<Vec<MembershipSnapshot>, StorageError> {
    let mut memberships = Vec::with_capacity(rows.len());
    for (ordinal, row) in rows.iter().enumerate() {
        memberships.push(decode_membership(
            row,
            tenant,
            organization,
            ordinal,
            assignments,
        )?);
    }
    Ok(memberships)
}

fn reject_residual_assignments(
    assignments: &HashMap<MembershipId, Vec<TeamId>>,
) -> Result<(), StorageError> {
    if !assignments.is_empty() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn decode_membership(
    row: &Row,
    tenant: &TenantId,
    organization: &OrganizationId,
    ordinal: usize,
    assignments: &mut HashMap<MembershipId, Vec<TeamId>>,
) -> Result<MembershipSnapshot, StorageError> {
    let persisted = decode_membership_row(row, tenant, organization, ordinal)?;
    let teams = assignments.remove(&persisted.id).unwrap_or_default();
    persisted.into_snapshot(teams)
}

struct PersistedMembership {
    id: MembershipId,
    user_id: UserId,
    kind: MembershipKind,
    state: MembershipState,
    origin: MembershipOrigin,
    expires_at: Option<UtcTimestamp>,
}

impl PersistedMembership {
    fn into_snapshot(self, team_ids: Vec<TeamId>) -> Result<MembershipSnapshot, StorageError> {
        let base = (
            self.id,
            self.user_id,
            self.kind,
            self.origin,
            self.expires_at,
        );
        match self.state {
            MembershipState::Active => Ok(MembershipSnapshot::Active {
                membership_id: base.0,
                user_id: base.1,
                kind: base.2,
                origin: base.3,
                expires_at: base.4,
                team_ids,
            }),
            MembershipState::Suspended if team_ids.is_empty() => {
                Ok(MembershipSnapshot::Suspended {
                    membership_id: base.0,
                    user_id: base.1,
                    kind: base.2,
                    origin: base.3,
                    expires_at: base.4,
                })
            }
            MembershipState::Left if team_ids.is_empty() => Ok(MembershipSnapshot::Left {
                membership_id: base.0,
                user_id: base.1,
                kind: base.2,
                origin: base.3,
                expires_at: base.4,
            }),
            _ => Err(integrity_failure()),
        }
    }
}

fn decode_membership_row(
    row: &Row,
    tenant: &TenantId,
    organization: &OrganizationId,
    ordinal: usize,
) -> Result<PersistedMembership, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_organization),
        SqlValue::Int64(found_ordinal),
        SqlValue::Text(membership),
        SqlValue::Text(user),
        SqlValue::Text(kind),
        SqlValue::Text(state),
        SqlValue::Text(origin),
        expires_at,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_identity(found_tenant, found_organization, tenant, organization)?;
    validate_ordinal(*found_ordinal, ordinal)?;
    decode_membership_fields(membership, user, kind, state, origin, expires_at)
}

fn decode_membership_fields(
    membership: &str,
    user: &str,
    kind: &str,
    state: &str,
    origin: &str,
    expires_at: &SqlValue,
) -> Result<PersistedMembership, StorageError> {
    Ok(PersistedMembership {
        id: MembershipId::parse(membership).map_err(|_| integrity_failure())?,
        user_id: UserId::parse(user).map_err(|_| integrity_failure())?,
        kind: decode_membership_kind(kind)?,
        state: decode_membership_state(state)?,
        origin: decode_membership_origin(origin)?,
        expires_at: optional_i64(expires_at)?.map(UtcTimestamp::from_unix_seconds),
    })
}

fn verify_history(session: &mut LocalSession, snapshot: &Organization) -> Result<(), StorageError> {
    let expected = expected_history_rows(snapshot.version())?;
    let events = load_events(session, snapshot.tenant_id(), snapshot.id())?;
    if events.len() != expected {
        return Err(integrity_failure());
    }
    let replayed = replay_events(&events)?;
    if &replayed != snapshot {
        return Err(integrity_failure());
    }
    Ok(())
}

fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<Vec<PersistedOrganizationEvent>, StorageError> {
    let batch = rows(sql::load_events(session, tenant, organization)?)?;
    validate_columns(batch.columns(), &event::event_columns())?;
    event::decode_events(batch.rows(), tenant, organization)
}

fn expected_history_rows(version: OrganizationVersion) -> Result<usize, StorageError> {
    if version.get() > MAX_ORGANIZATION_EVENT_HISTORY_ROWS {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    usize::try_from(version.get()).map_err(|_| integrity_failure())
}

fn replay_events(events: &[PersistedOrganizationEvent]) -> Result<Organization, StorageError> {
    let first = events.first().ok_or_else(integrity_failure)?;
    let mut current = first.replay_creation()?;
    for persisted in &events[1..] {
        current =
            replay_persisted_event(&current, &persisted.event).map_err(|_| integrity_failure())?;
    }
    Ok(current)
}

pub(super) fn decode_version(value: &str) -> Result<OrganizationVersion, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let parsed = value.parse::<u64>().map_err(|_| integrity_failure())?;
    let version = OrganizationVersion::new(parsed).map_err(|_| integrity_failure())?;
    if sql::encode_version(version) != value {
        return Err(integrity_failure());
    }
    Ok(version)
}

fn validate_identity(
    found_tenant: &str,
    found_organization: &str,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<(), StorageError> {
    if found_tenant != tenant.as_str() || found_organization != organization.as_str() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_ordinal(found: i64, expected: usize) -> Result<(), StorageError> {
    if usize::try_from(found).ok() != Some(expected) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn decode_organization_state(value: &str) -> Result<OrganizationState, StorageError> {
    match value {
        "active" => Ok(OrganizationState::Active),
        "frozen" => Ok(OrganizationState::Frozen),
        _ => Err(integrity_failure()),
    }
}

fn decode_membership_kind(value: &str) -> Result<MembershipKind, StorageError> {
    match value {
        "owner" => Ok(MembershipKind::Owner),
        "member" => Ok(MembershipKind::Member),
        _ => Err(integrity_failure()),
    }
}

fn decode_membership_state(value: &str) -> Result<MembershipState, StorageError> {
    match value {
        "active" => Ok(MembershipState::Active),
        "suspended" => Ok(MembershipState::Suspended),
        "left" => Ok(MembershipState::Left),
        _ => Err(integrity_failure()),
    }
}

fn decode_membership_origin(value: &str) -> Result<MembershipOrigin, StorageError> {
    match value {
        "founder" => Ok(MembershipOrigin::Founder),
        "invitation" => Ok(MembershipOrigin::Invitation),
        "administrative" => Ok(MembershipOrigin::Administrative),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn optional_i64(value: &SqlValue) -> Result<Option<i64>, StorageError> {
    match value {
        SqlValue::Int64(value) => Ok(Some(*value)),
        SqlValue::Null => Ok(None),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn optional_text(value: &SqlValue) -> Result<Option<&str>, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(Some(value)),
        SqlValue::Null => Ok(None),
        _ => Err(integrity_failure()),
    }
}

fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn validate_columns(
    columns: &[ColumnSchema],
    expected: &[(&str, SqlType)],
) -> Result<(), StorageError> {
    let valid = columns.len() == expected.len()
        && columns.iter().zip(expected).all(|(column, expected)| {
            column.name() == expected.0 && column.data_type() == &expected.1
        });
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn header_columns() -> [(&'static str, SqlType); 4] {
    [
        ("tenant_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("version", SqlType::Text),
        ("state", SqlType::Text),
    ]
}

fn membership_columns() -> [(&'static str, SqlType); 9] {
    [
        ("tenant_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("membership_ordinal", SqlType::Int64),
        ("membership_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("kind", SqlType::Text),
        ("state", SqlType::Text),
        ("origin", SqlType::Text),
        ("expires_at", SqlType::Int64),
    ]
}

fn team_columns() -> [(&'static str, SqlType); 4] {
    [
        ("tenant_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("team_ordinal", SqlType::Int64),
        ("team_id", SqlType::Text),
    ]
}

fn assignment_columns() -> [(&'static str, SqlType); 5] {
    [
        ("tenant_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("membership_id", SqlType::Text),
        ("assignment_ordinal", SqlType::Int64),
        ("team_id", SqlType::Text),
    ]
}

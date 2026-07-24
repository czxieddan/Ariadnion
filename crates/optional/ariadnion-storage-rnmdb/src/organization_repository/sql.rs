//! Fixed tenant-bound SQL for durable organization state.

use ariadnion_core::TenantId;
use ariadnion_organization::{OrganizationId, OrganizationVersion};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};

use super::{integrity_failure, map_fresh_insert_error};
use crate::session::map_rnmdb_error;

pub(super) const HEADER_PROJECTION: &str = "tenant_id, organization_id, version, state";
pub(super) const MEMBERSHIP_PROJECTION: &str = "tenant_id, organization_id, membership_ordinal, membership_id, user_id, kind, state, origin, expires_at";
pub(super) const TEAM_PROJECTION: &str = "tenant_id, organization_id, team_ordinal, team_id";
pub(super) const ASSIGNMENT_PROJECTION: &str =
    "tenant_id, organization_id, membership_id, assignment_ordinal, team_id";
pub(super) const EVENT_PROJECTION: &str = "tenant_id, organization_id, version, kind, occurred_at, actor_id, request_id, organization_state, membership_id, membership_kind, removed_team_assignments, team_id, ownership_transfer_id, previous_owner_id, new_owner_id, approver_id, membership_user_id, membership_origin, membership_expires_at";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";

const MAX_SQL_BYTES: usize = 16_384;

pub(super) fn load_header(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<CommandOutput, StorageError> {
    select(
        session,
        HEADER_PROJECTION,
        "identity_organizations",
        tenant,
        organization,
        " LIMIT 2",
    )
}

pub(super) fn load_memberships(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<CommandOutput, StorageError> {
    select(
        session,
        MEMBERSHIP_PROJECTION,
        "identity_organization_memberships",
        tenant,
        organization,
        " ORDER BY membership_ordinal LIMIT 1025",
    )
}

pub(super) fn load_teams(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<CommandOutput, StorageError> {
    select(
        session,
        TEAM_PROJECTION,
        "identity_organization_teams",
        tenant,
        organization,
        " ORDER BY team_ordinal LIMIT 257",
    )
}

pub(super) fn load_assignments(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<CommandOutput, StorageError> {
    select(
        session,
        ASSIGNMENT_PROJECTION,
        "identity_organization_team_assignments",
        tenant,
        organization,
        " ORDER BY membership_id, assignment_ordinal LIMIT 65537",
    )
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<CommandOutput, StorageError> {
    select(
        session,
        EVENT_PROJECTION,
        "identity_organization_events",
        tenant,
        organization,
        " ORDER BY version LIMIT 65537",
    )
}

pub(super) fn load_outbox(
    session: &mut LocalSession,
    tenant: &TenantId,
    event_id: &str,
    idempotency_key: &str,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {OUTBOX_PROJECTION} FROM platform_outbox WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND (event_id = ");
    push_text(&mut sql, event_id);
    sql.push_str(" OR idempotency_key = ");
    push_text(&mut sql, idempotency_key);
    sql.push_str(") LIMIT 2;");
    execute(session, &finish(sql)?)
}

fn select(
    session: &mut LocalSession,
    projection: &str,
    table: &str,
    tenant: &TenantId,
    organization: &OrganizationId,
    suffix: &str,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {projection} FROM {table} WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND organization_id = ");
    push_text(&mut sql, organization.as_str());
    sql.push_str(suffix);
    sql.push(';');
    execute(session, &finish(sql)?)
}

pub(super) fn insert_header(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    version: OrganizationVersion,
    state: &str,
) -> Result<(), StorageError> {
    let mut sql = String::from(
        "INSERT INTO identity_organizations (tenant_id, organization_id, version, state) VALUES (",
    );
    push_text(&mut sql, tenant.as_str());
    push_value(&mut sql, organization.as_str());
    push_value(&mut sql, &encode_version(version));
    push_value(&mut sql, state);
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

pub(super) fn update_header(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    expected: OrganizationVersion,
    next: OrganizationVersion,
    state: &str,
) -> Result<(), StorageError> {
    let mut sql = String::from("UPDATE identity_organizations SET version = ");
    push_text(&mut sql, &encode_version(next));
    sql.push_str(", state = ");
    push_text(&mut sql, state);
    push_scope(&mut sql, tenant, organization);
    sql.push_str(" AND version = ");
    push_text(&mut sql, &encode_version(expected));
    sql.push(';');
    match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(conflict()),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn delete_snapshot_rows(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    expected_assignments: usize,
    expected_memberships: usize,
    expected_teams: usize,
) -> Result<(), StorageError> {
    delete_rows(
        session,
        "identity_organization_team_assignments",
        tenant,
        organization,
        expected_assignments,
    )?;
    delete_rows(
        session,
        "identity_organization_memberships",
        tenant,
        organization,
        expected_memberships,
    )?;
    delete_rows(
        session,
        "identity_organization_teams",
        tenant,
        organization,
        expected_teams,
    )
}

fn delete_rows(
    session: &mut LocalSession,
    table: &str,
    tenant: &TenantId,
    organization: &OrganizationId,
    expected: usize,
) -> Result<(), StorageError> {
    let mut sql = format!("DELETE FROM {table}");
    push_scope(&mut sql, tenant, organization);
    sql.push(';');
    let changed = match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(value) => {
            usize::try_from(value).map_err(|_| integrity_failure())?
        }
        _ => return Err(integrity_failure()),
    };
    if changed != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

fn push_scope(sql: &mut String, tenant: &TenantId, organization: &OrganizationId) {
    sql.push_str(" WHERE tenant_id = ");
    push_text(sql, tenant.as_str());
    sql.push_str(" AND organization_id = ");
    push_text(sql, organization.as_str());
}

pub(super) struct MembershipInsert<'a> {
    pub(super) tenant: &'a TenantId,
    pub(super) organization: &'a OrganizationId,
    pub(super) ordinal: usize,
    pub(super) membership_id: &'a str,
    pub(super) user_id: &'a str,
    pub(super) kind: &'a str,
    pub(super) state: &'a str,
    pub(super) origin: &'a str,
    pub(super) expires_at: Option<i64>,
}

pub(super) fn insert_membership(
    session: &mut LocalSession,
    value: MembershipInsert<'_>,
) -> Result<(), StorageError> {
    let mut sql = String::from(
        "INSERT INTO identity_organization_memberships (tenant_id, organization_id, membership_ordinal, membership_id, user_id, kind, state, origin, expires_at) VALUES (",
    );
    push_text(&mut sql, value.tenant.as_str());
    push_value(&mut sql, value.organization.as_str());
    push_usize_value(&mut sql, value.ordinal)?;
    push_value(&mut sql, value.membership_id);
    push_value(&mut sql, value.user_id);
    push_value(&mut sql, value.kind);
    push_value(&mut sql, value.state);
    push_value(&mut sql, value.origin);
    push_optional_i64_value(&mut sql, value.expires_at);
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

pub(super) fn insert_team(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    ordinal: usize,
    team_id: &str,
) -> Result<(), StorageError> {
    let mut sql = String::from(
        "INSERT INTO identity_organization_teams (tenant_id, organization_id, team_ordinal, team_id) VALUES (",
    );
    push_text(&mut sql, tenant.as_str());
    push_value(&mut sql, organization.as_str());
    push_usize_value(&mut sql, ordinal)?;
    push_value(&mut sql, team_id);
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

pub(super) fn insert_assignment(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    membership_id: &str,
    ordinal: usize,
    team_id: &str,
) -> Result<(), StorageError> {
    let mut sql = String::from(
        "INSERT INTO identity_organization_team_assignments (tenant_id, organization_id, membership_id, assignment_ordinal, team_id) VALUES (",
    );
    push_text(&mut sql, tenant.as_str());
    push_value(&mut sql, organization.as_str());
    push_value(&mut sql, membership_id);
    push_usize_value(&mut sql, ordinal)?;
    push_value(&mut sql, team_id);
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

pub(super) fn insert_event(
    session: &mut LocalSession,
    values: &[SqlField<'_>],
) -> Result<(), StorageError> {
    if values.len() != 19 {
        return Err(integrity_failure());
    }
    let mut sql = format!("INSERT INTO identity_organization_events ({EVENT_PROJECTION}) VALUES (");
    push_field(&mut sql, values[0]);
    for value in &values[1..] {
        sql.push_str(", ");
        push_field(&mut sql, *value);
    }
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

#[derive(Clone, Copy)]
pub(super) enum SqlField<'a> {
    Text(&'a str),
    Int(i64),
    Null,
}

fn push_field(sql: &mut String, value: SqlField<'_>) {
    match value {
        SqlField::Text(value) => push_text(sql, value),
        SqlField::Int(value) => sql.push_str(&value.to_string()),
        SqlField::Null => sql.push_str("NULL"),
    }
}

fn require_fresh_insert(session: &mut LocalSession, sql: String) -> Result<(), StorageError> {
    let output = execute(session, &finish(sql)?).map_err(map_fresh_insert_error)?;
    if output != CommandOutput::RowsAffected(1) {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn encode_version(version: OrganizationVersion) -> String {
    format!("{:020}", version.get())
}

fn push_value(sql: &mut String, value: &str) {
    sql.push_str(", ");
    push_text(sql, value);
}

fn push_usize_value(sql: &mut String, value: usize) -> Result<(), StorageError> {
    let value = i64::try_from(value).map_err(|_| integrity_failure())?;
    sql.push_str(", ");
    sql.push_str(&value.to_string());
    Ok(())
}

fn push_optional_i64_value(sql: &mut String, value: Option<i64>) {
    sql.push_str(", ");
    match value {
        Some(value) => sql.push_str(&value.to_string()),
        None => sql.push_str("NULL"),
    }
}

fn push_text(sql: &mut String, value: &str) {
    sql.push('\'');
    for character in value.chars() {
        if character == '\'' {
            sql.push_str("''");
        } else {
            sql.push(character);
        }
    }
    sql.push('\'');
}

fn finish(sql: String) -> Result<String, StorageError> {
    if sql.len() > MAX_SQL_BYTES || !sql.is_ascii() {
        return Err(integrity_failure());
    }
    Ok(sql)
}

fn execute(session: &mut LocalSession, sql: &str) -> Result<CommandOutput, StorageError> {
    session.execute(sql).map_err(map_rnmdb_error)
}

pub(super) fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

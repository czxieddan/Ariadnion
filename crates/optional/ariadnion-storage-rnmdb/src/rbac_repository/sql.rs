//! Fixed tenant-bound SQL for durable authorization policies.

use ariadnion_core::TenantId;
use ariadnion_rbac::PolicyVersion;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};

use super::{integrity_failure, map_fresh_insert_error};
use crate::UtcTimestampMicros;
use crate::session::map_rnmdb_error;

pub(super) const HEADER_PROJECTION: &str = "tenant_id, version";
pub(super) const ROLE_PROJECTION: &str = "tenant_id, role_ordinal, role_id";
pub(super) const RULE_PROJECTION: &str = "tenant_id, role_id, rule_ordinal, permission_id, effect";
pub(super) const ASSIGNMENT_PROJECTION: &str = "tenant_id, assignment_ordinal, assignment_id, principal_id, membership_id, role_id, scope_kind, scope_organization_id, scope_parent_resource_id, scope_resource_kind, scope_resource_id, expires_at";
pub(super) const EVENT_PROJECTION: &str =
    "tenant_id, version, kind, occurred_at, actor_id, request_id";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";

const MAX_SQL_BYTES: usize = 16_384;
const OUTBOX_TOPIC: &str = "identity.rbac.policy.v1";
pub(super) const OUTBOX_HISTORY_PAGE_ROWS: usize = 64;

#[derive(Clone, Copy)]
pub(super) struct OutboxHistoryCursor<'a> {
    created_at: UtcTimestampMicros,
    event_id: &'a str,
}

impl<'a> OutboxHistoryCursor<'a> {
    pub(super) const fn new(created_at: UtcTimestampMicros, event_id: &'a str) -> Self {
        Self {
            created_at,
            event_id,
        }
    }
}

pub(super) fn load_header(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<CommandOutput, StorageError> {
    select_tenant(
        session,
        HEADER_PROJECTION,
        "identity_rbac_policies",
        tenant,
        " LIMIT 2",
    )
}

pub(super) fn load_roles(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<CommandOutput, StorageError> {
    select_tenant(
        session,
        ROLE_PROJECTION,
        "identity_rbac_roles",
        tenant,
        " ORDER BY role_ordinal LIMIT 257",
    )
}

pub(super) fn load_rules(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<CommandOutput, StorageError> {
    select_tenant(
        session,
        RULE_PROJECTION,
        "identity_rbac_role_rules",
        tenant,
        " ORDER BY role_id, rule_ordinal LIMIT 65537",
    )
}

pub(super) fn load_assignments(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<CommandOutput, StorageError> {
    select_tenant(
        session,
        ASSIGNMENT_PROJECTION,
        "identity_rbac_assignments",
        tenant,
        " ORDER BY assignment_ordinal LIMIT 4097",
    )
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<CommandOutput, StorageError> {
    select_tenant(
        session,
        EVENT_PROJECTION,
        "identity_rbac_policy_events",
        tenant,
        " ORDER BY version LIMIT 65537",
    )
}

pub(super) fn load_presence(
    session: &mut LocalSession,
    table: &str,
    tenant: &TenantId,
) -> Result<CommandOutput, StorageError> {
    select_tenant(session, "tenant_id", table, tenant, " LIMIT 1")
}

pub(super) fn load_outbox_presence(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = String::from("SELECT tenant_id FROM platform_outbox WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND topic = ");
    push_text(&mut sql, OUTBOX_TOPIC);
    sql.push_str(" LIMIT 1;");
    execute(session, &finish(sql)?)
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

pub(super) fn load_outbox_history_page(
    session: &mut LocalSession,
    tenant: &TenantId,
    cursor: Option<OutboxHistoryCursor<'_>>,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {OUTBOX_PROJECTION} FROM platform_outbox WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND topic = ");
    push_text(&mut sql, OUTBOX_TOPIC);
    if let Some(cursor) = cursor {
        push_outbox_history_cursor(&mut sql, cursor);
    }
    sql.push_str(" ORDER BY created_at, event_id LIMIT ");
    sql.push_str(&OUTBOX_HISTORY_PAGE_ROWS.to_string());
    sql.push(';');
    execute(session, &finish(sql)?)
}

fn push_outbox_history_cursor(sql: &mut String, cursor: OutboxHistoryCursor<'_>) {
    sql.push_str(" AND (created_at > ");
    push_timestamp(sql, cursor.created_at);
    sql.push_str(" OR (created_at = ");
    push_timestamp(sql, cursor.created_at);
    sql.push_str(" AND event_id > ");
    push_text(sql, cursor.event_id);
    sql.push_str("))");
}

fn select_tenant(
    session: &mut LocalSession,
    projection: &str,
    table: &str,
    tenant: &TenantId,
    suffix: &str,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {projection} FROM {table} WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(suffix);
    sql.push(';');
    execute(session, &finish(sql)?)
}

pub(super) fn insert_header(
    session: &mut LocalSession,
    tenant: &TenantId,
    version: PolicyVersion,
) -> Result<(), StorageError> {
    let mut sql = String::from("INSERT INTO identity_rbac_policies (tenant_id, version) VALUES (");
    push_text(&mut sql, tenant.as_str());
    push_value(&mut sql, &encode_version(version));
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

pub(super) fn update_header(
    session: &mut LocalSession,
    tenant: &TenantId,
    expected: PolicyVersion,
    next: PolicyVersion,
) -> Result<(), StorageError> {
    let mut sql = String::from("UPDATE identity_rbac_policies SET version = ");
    push_text(&mut sql, &encode_version(next));
    push_tenant_scope(&mut sql, tenant);
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
    expected_rules: usize,
    expected_roles: usize,
    expected_assignments: usize,
) -> Result<(), StorageError> {
    delete_rows(
        session,
        "identity_rbac_assignments",
        tenant,
        expected_assignments,
    )?;
    delete_rows(session, "identity_rbac_role_rules", tenant, expected_rules)?;
    delete_rows(session, "identity_rbac_roles", tenant, expected_roles)
}

fn delete_rows(
    session: &mut LocalSession,
    table: &str,
    tenant: &TenantId,
    expected: usize,
) -> Result<(), StorageError> {
    let mut sql = format!("DELETE FROM {table}");
    push_tenant_scope(&mut sql, tenant);
    sql.push(';');
    let output = execute(session, &finish(sql)?)?;
    require_exact_rows_affected(output, expected)
}

fn require_exact_rows_affected(output: CommandOutput, expected: usize) -> Result<(), StorageError> {
    let changed = match output {
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

pub(super) fn insert_role(
    session: &mut LocalSession,
    tenant: &TenantId,
    ordinal: usize,
    role_id: &str,
) -> Result<(), StorageError> {
    let mut sql =
        String::from("INSERT INTO identity_rbac_roles (tenant_id, role_ordinal, role_id) VALUES (");
    push_text(&mut sql, tenant.as_str());
    push_usize_value(&mut sql, ordinal)?;
    push_value(&mut sql, role_id);
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

pub(super) fn insert_rule(
    session: &mut LocalSession,
    tenant: &TenantId,
    role_id: &str,
    ordinal: usize,
    permission_id: &str,
    effect: &str,
) -> Result<(), StorageError> {
    let mut sql = String::from(
        "INSERT INTO identity_rbac_role_rules (tenant_id, role_id, rule_ordinal, permission_id, effect) VALUES (",
    );
    push_text(&mut sql, tenant.as_str());
    push_value(&mut sql, role_id);
    push_usize_value(&mut sql, ordinal)?;
    push_value(&mut sql, permission_id);
    push_value(&mut sql, effect);
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

pub(super) struct AssignmentInsert<'a> {
    pub(super) tenant: &'a TenantId,
    pub(super) ordinal: usize,
    pub(super) assignment_id: &'a str,
    pub(super) principal_id: &'a str,
    pub(super) membership_id: &'a str,
    pub(super) role_id: &'a str,
    pub(super) scope_kind: &'a str,
    pub(super) organization_id: Option<&'a str>,
    pub(super) parent_resource_id: Option<&'a str>,
    pub(super) resource_kind: Option<&'a str>,
    pub(super) resource_id: Option<&'a str>,
    pub(super) expires_at: Option<i64>,
}

pub(super) fn insert_assignment(
    session: &mut LocalSession,
    value: AssignmentInsert<'_>,
) -> Result<(), StorageError> {
    let mut sql =
        format!("INSERT INTO identity_rbac_assignments ({ASSIGNMENT_PROJECTION}) VALUES (");
    push_text(&mut sql, value.tenant.as_str());
    push_usize_value(&mut sql, value.ordinal)?;
    for field in [
        value.assignment_id,
        value.principal_id,
        value.membership_id,
        value.role_id,
        value.scope_kind,
    ] {
        push_value(&mut sql, field);
    }
    push_optional_text_value(&mut sql, value.organization_id);
    push_optional_text_value(&mut sql, value.parent_resource_id);
    push_optional_text_value(&mut sql, value.resource_kind);
    push_optional_text_value(&mut sql, value.resource_id);
    push_optional_i64_value(&mut sql, value.expires_at);
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

pub(super) struct EventInsert<'a> {
    pub(super) tenant: &'a TenantId,
    pub(super) version: PolicyVersion,
    pub(super) kind: &'a str,
    pub(super) occurred_at: i64,
    pub(super) actor_id: &'a str,
    pub(super) request_id: &'a str,
}

pub(super) fn insert_event(
    session: &mut LocalSession,
    value: EventInsert<'_>,
) -> Result<(), StorageError> {
    let mut sql = format!("INSERT INTO identity_rbac_policy_events ({EVENT_PROJECTION}) VALUES (");
    push_text(&mut sql, value.tenant.as_str());
    push_value(&mut sql, &encode_version(value.version));
    push_value(&mut sql, value.kind);
    push_i64_value(&mut sql, value.occurred_at);
    push_value(&mut sql, value.actor_id);
    push_value(&mut sql, value.request_id);
    sql.push_str(");");
    require_fresh_insert(session, sql)
}

fn require_fresh_insert(session: &mut LocalSession, sql: String) -> Result<(), StorageError> {
    let output = execute(session, &finish(sql)?).map_err(map_fresh_insert_error)?;
    if output != CommandOutput::RowsAffected(1) {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn encode_version(version: PolicyVersion) -> String {
    format!("{:020}", version.get())
}

fn push_tenant_scope(sql: &mut String, tenant: &TenantId) {
    sql.push_str(" WHERE tenant_id = ");
    push_text(sql, tenant.as_str());
}

fn push_value(sql: &mut String, value: &str) {
    sql.push_str(", ");
    push_text(sql, value);
}

fn push_i64_value(sql: &mut String, value: i64) {
    sql.push_str(", ");
    sql.push_str(&value.to_string());
}

fn push_usize_value(sql: &mut String, value: usize) -> Result<(), StorageError> {
    let value = i64::try_from(value).map_err(|_| integrity_failure())?;
    push_i64_value(sql, value);
    Ok(())
}

fn push_optional_text_value(sql: &mut String, value: Option<&str>) {
    sql.push_str(", ");
    match value {
        Some(value) => push_text(sql, value),
        None => sql.push_str("NULL"),
    }
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

fn push_timestamp(sql: &mut String, value: UtcTimestampMicros) {
    sql.push_str("CAST(");
    push_text(sql, &value.to_sql_timestamp().to_rfc3339_string());
    sql.push_str(" AS TIMESTAMP)");
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

pub(super) const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

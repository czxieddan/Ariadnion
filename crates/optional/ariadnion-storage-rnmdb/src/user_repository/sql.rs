//! Fixed tenant-bound SQL builders for durable user evidence.

use ariadnion_core::TenantId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{User, UserId, UserVersion};
use rnmdb_cli::{CommandOutput, LocalSession};

use super::evidence::{SnapshotRecord, TransitionIdentity};
use super::integrity_failure;
use crate::session::map_rnmdb_error;

pub(super) const USER_PROJECTION: &str = "tenant_id, user_id, version, state, deletion_requested_at, deletion_not_before, recovery_state";
pub(super) const LIFECYCLE_PROJECTION: &str = "tenant_id, user_id, version, kind, occurred_at, actor_id, request_id, deletion_not_before, recovery_state";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";

const USER_TABLE: &str = "identity_users";
const LIFECYCLE_TABLE: &str = "identity_user_events";
const OUTBOX_TABLE: &str = "platform_outbox";
const MAX_USER_SQL_BYTES: usize = 16_384;
pub(super) const MAX_RECONCILIATION_HISTORY_ROWS: u64 = 65_536;

pub(super) fn compare_and_update_user(
    session: &mut LocalSession,
    identity: &TransitionIdentity,
) -> Result<(), StorageError> {
    let sql = user_update_sql(identity)?;
    match execute(session, &sql)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn insert_lifecycle_event(
    session: &mut LocalSession,
    identity: &TransitionIdentity,
) -> Result<(), StorageError> {
    let sql = lifecycle_insert_sql(identity)?;
    let output = execute(session, &sql).map_err(map_fresh_insert_error)?;
    if output != CommandOutput::RowsAffected(1) {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn load_user(
    session: &mut LocalSession,
    tenant_id: &ariadnion_core::TenantId,
    user_id: &UserId,
) -> Result<CommandOutput, StorageError> {
    execute(session, &user_select_sql(tenant_id, user_id)?)
}

pub(super) fn load_lifecycle(
    session: &mut LocalSession,
    identity: &TransitionIdentity,
) -> Result<CommandOutput, StorageError> {
    execute(session, &lifecycle_select_sql(identity)?)
}

pub(super) fn load_current_lifecycle(
    session: &mut LocalSession,
    user: &User,
) -> Result<CommandOutput, StorageError> {
    execute(
        session,
        &lifecycle_by_version_select_sql(user.tenant_id(), user.id(), user.version())?,
    )
}

pub(super) fn load_lifecycle_range(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    user_id: &UserId,
    first_version: UserVersion,
    last_version: UserVersion,
) -> Result<CommandOutput, StorageError> {
    execute(
        session,
        &lifecycle_range_select_sql(tenant_id, user_id, first_version, last_version)?,
    )
}

pub(super) fn load_later_lifecycle(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    user_id: &UserId,
    version: UserVersion,
) -> Result<CommandOutput, StorageError> {
    execute(
        session,
        &later_lifecycle_select_sql(tenant_id, user_id, version)?,
    )
}

pub(super) fn load_outbox(
    session: &mut LocalSession,
    identity: &TransitionIdentity,
) -> Result<CommandOutput, StorageError> {
    execute(session, &outbox_select_sql(identity)?)
}

fn user_update_sql(identity: &TransitionIdentity) -> Result<String, StorageError> {
    let snapshot = identity.snapshot();
    let mut sql = format!("UPDATE {USER_TABLE} SET version = ");
    push_text_literal(&mut sql, &encode_version(identity.new_version()));
    sql.push_str(", state = ");
    push_text_literal(&mut sql, snapshot.state);
    push_snapshot_assignments(&mut sql, snapshot);
    sql.push_str(" WHERE tenant_id = ");
    push_text_literal(&mut sql, identity.tenant_id().as_str());
    sql.push_str(" AND user_id = ");
    push_text_literal(&mut sql, identity.user_id().as_str());
    sql.push_str(" AND version = ");
    push_text_literal(&mut sql, &encode_version(identity.previous_version()));
    sql.push(';');
    finish_sql(sql)
}

fn push_snapshot_assignments(sql: &mut String, snapshot: SnapshotRecord) {
    sql.push_str(", deletion_requested_at = ");
    push_optional_i64(sql, snapshot.requested_at);
    sql.push_str(", deletion_not_before = ");
    push_optional_i64(sql, snapshot.not_before);
    sql.push_str(", recovery_state = ");
    push_optional_text(sql, snapshot.recovery_state);
}

fn lifecycle_insert_sql(identity: &TransitionIdentity) -> Result<String, StorageError> {
    let event = identity.lifecycle();
    let mut sql = format!("INSERT INTO {LIFECYCLE_TABLE} ({LIFECYCLE_PROJECTION}) VALUES (");
    push_text_literal(&mut sql, identity.tenant_id().as_str());
    push_text_value(&mut sql, identity.user_id().as_str());
    push_text_value(&mut sql, &encode_version(identity.new_version()));
    push_text_value(&mut sql, event.kind);
    push_i64_value(&mut sql, event.occurred_at);
    push_text_value(&mut sql, identity.actor().as_str());
    push_text_value(&mut sql, identity.request_id().as_str());
    push_optional_i64_value(&mut sql, event.not_before);
    push_optional_text_value(&mut sql, event.recovery_state);
    sql.push_str(");");
    finish_sql(sql)
}

fn user_select_sql(tenant_id: &TenantId, user_id: &UserId) -> Result<String, StorageError> {
    let mut sql = format!("SELECT {USER_PROJECTION} FROM {USER_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND user_id = ");
    push_text_literal(&mut sql, user_id.as_str());
    sql.push_str(" LIMIT 2;");
    finish_sql(sql)
}

fn lifecycle_select_sql(identity: &TransitionIdentity) -> Result<String, StorageError> {
    lifecycle_by_version_select_sql(
        identity.tenant_id(),
        identity.user_id(),
        identity.new_version(),
    )
}

fn lifecycle_by_version_select_sql(
    tenant_id: &TenantId,
    user_id: &UserId,
    version: UserVersion,
) -> Result<String, StorageError> {
    let mut sql =
        format!("SELECT {LIFECYCLE_PROJECTION} FROM {LIFECYCLE_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND user_id = ");
    push_text_literal(&mut sql, user_id.as_str());
    sql.push_str(" AND version = ");
    push_text_literal(&mut sql, &encode_version(version));
    sql.push_str(" LIMIT 2;");
    finish_sql(sql)
}

fn later_lifecycle_select_sql(
    tenant_id: &TenantId,
    user_id: &UserId,
    version: UserVersion,
) -> Result<String, StorageError> {
    let mut sql = format!("SELECT version FROM {LIFECYCLE_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND user_id = ");
    push_text_literal(&mut sql, user_id.as_str());
    sql.push_str(" AND version > ");
    push_text_literal(&mut sql, &encode_version(version));
    sql.push_str(" ORDER BY version LIMIT 2;");
    finish_sql(sql)
}

fn lifecycle_range_select_sql(
    tenant_id: &TenantId,
    user_id: &UserId,
    first_version: UserVersion,
    last_version: UserVersion,
) -> Result<String, StorageError> {
    let mut sql =
        format!("SELECT {LIFECYCLE_PROJECTION} FROM {LIFECYCLE_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND user_id = ");
    push_text_literal(&mut sql, user_id.as_str());
    sql.push_str(" AND version >= ");
    push_text_literal(&mut sql, &encode_version(first_version));
    sql.push_str(" AND version <= ");
    push_text_literal(&mut sql, &encode_version(last_version));
    sql.push_str(" ORDER BY version LIMIT ");
    sql.push_str(&(MAX_RECONCILIATION_HISTORY_ROWS + 1).to_string());
    sql.push(';');
    finish_sql(sql)
}

fn outbox_select_sql(identity: &TransitionIdentity) -> Result<String, StorageError> {
    let mut sql = format!("SELECT {OUTBOX_PROJECTION} FROM {OUTBOX_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, identity.tenant_id().as_str());
    sql.push_str(" AND (event_id = ");
    push_text_literal(&mut sql, identity.outbox_event_id().as_str());
    sql.push_str(" OR idempotency_key = ");
    push_text_literal(&mut sql, identity.outbox_key().as_str());
    sql.push_str(") LIMIT 2;");
    finish_sql(sql)
}

pub(super) fn encode_version(version: UserVersion) -> String {
    format!("{:020}", version.get())
}

fn push_text_value(sql: &mut String, value: &str) {
    sql.push_str(", ");
    push_text_literal(sql, value);
}

fn push_i64_value(sql: &mut String, value: i64) {
    sql.push_str(", ");
    sql.push_str(&value.to_string());
}

fn push_optional_i64_value(sql: &mut String, value: Option<i64>) {
    sql.push_str(", ");
    push_optional_i64(sql, value);
}

fn push_optional_text_value(sql: &mut String, value: Option<&str>) {
    sql.push_str(", ");
    push_optional_text(sql, value);
}

fn push_optional_i64(sql: &mut String, value: Option<i64>) {
    match value {
        Some(value) => sql.push_str(&value.to_string()),
        None => sql.push_str("NULL"),
    }
}

fn push_optional_text(sql: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_text_literal(sql, value),
        None => sql.push_str("NULL"),
    }
}

fn push_text_literal(sql: &mut String, value: &str) {
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

fn finish_sql(sql: String) -> Result<String, StorageError> {
    if sql.len() > MAX_USER_SQL_BYTES || !sql.is_ascii() {
        return Err(integrity_failure());
    }
    Ok(sql)
}

fn execute(session: &mut LocalSession, sql: &str) -> Result<CommandOutput, StorageError> {
    session.execute(sql).map_err(map_rnmdb_error)
}

fn map_fresh_insert_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Unavailable
        | StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::ResourceExhausted => error,
        _ => integrity_failure(),
    }
}

//! Fixed tenant-bound SQL for durable browser session families.

use ariadnion_auth_session::{
    SessionEvent, SessionEventKind, SessionFamily, SessionFamilyId, SessionFamilyState,
    SessionFamilyVersion, SessionSnapshot, SessionState, SessionTokenDigest, SessionVersion,
};
use ariadnion_core::TenantId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UserId;
use rnmdb_cli::{CommandOutput, LocalSession};

use super::{CommitRequest, integrity_failure};
use crate::session::map_rnmdb_error;

pub(super) const FAMILY_PROJECTION: &str = "tenant_id, user_id, family_id, current_session_id, issued_at, absolute_expires_at, version, state";
pub(super) const LEAF_PROJECTION: &str = "tenant_id, user_id, family_id, session_id, ordinal, predecessor_session_id, token_digest_hex, issued_at, last_seen_at, idle_expires_at, version, state";
pub(super) const EVENT_PROJECTION: &str =
    "tenant_id, user_id, family_id, session_id, version, kind, occurred_at, actor_id";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";
const TOKEN_OWNER_PROJECTION: &str = "user_id, family_id, session_id, token_digest_hex";
const FAMILY_OWNER_PROJECTION: &str = "user_id, family_id";
const MAX_SQL_BYTES: usize = 1_048_576;

pub(super) fn load_family(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<CommandOutput, StorageError> {
    let mut sql =
        format!("SELECT {FAMILY_PROJECTION} FROM identity_session_families WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    push_scope(&mut sql, user, family);
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_leaves(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<CommandOutput, StorageError> {
    let mut sql =
        format!("SELECT {LEAF_PROJECTION} FROM identity_session_leaves WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    push_scope(&mut sql, user, family);
    sql.push_str(" ORDER BY ordinal LIMIT 4098;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<CommandOutput, StorageError> {
    let mut sql =
        format!("SELECT {EVENT_PROJECTION} FROM identity_session_events WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    push_scope(&mut sql, user, family);
    sql.push_str(" ORDER BY version LIMIT 4098;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_token_owners(
    session: &mut LocalSession,
    tenant: &TenantId,
    digest: SessionTokenDigest,
) -> Result<CommandOutput, StorageError> {
    let mut sql =
        format!("SELECT {TOKEN_OWNER_PROJECTION} FROM identity_session_leaves WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND token_digest_hex = ");
    push_text(&mut sql, &encode_digest(digest.bytes()));
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_family_owner(
    session: &mut LocalSession,
    tenant: &TenantId,
    family: &SessionFamilyId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!(
        "SELECT {FAMILY_OWNER_PROJECTION} FROM identity_session_families WHERE tenant_id = "
    );
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND family_id = ");
    push_text(&mut sql, family.as_str());
    sql.push_str(" LIMIT 2;");
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
    sql.push_str(" AND event_id = ");
    push_text(&mut sql, event_id);
    sql.push_str(" AND idempotency_key = ");
    push_text(&mut sql, idempotency_key);
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn insert_family(
    session: &mut LocalSession,
    family: &SessionFamily,
) -> Result<(), StorageError> {
    let mut sql = String::from(
        "INSERT INTO identity_session_families (tenant_id, user_id, family_id, current_session_id, issued_at, absolute_expires_at, version, state) VALUES (",
    );
    push_text(&mut sql, family.tenant_id().as_str());
    push_value(&mut sql, family.user_id().as_str());
    push_value(&mut sql, family.id().as_str());
    push_value(&mut sql, family.current().id().as_str());
    push_i64_value(&mut sql, family.issued_at().unix_seconds());
    push_i64_value(&mut sql, family.absolute_expires_at().unix_seconds());
    push_value(&mut sql, &encode_family_version(family.version()));
    push_value(&mut sql, family_state_label(family.state()));
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn insert_leaves(
    session: &mut LocalSession,
    family: &SessionFamily,
) -> Result<(), StorageError> {
    let snapshot = family.snapshot_state();
    for (ordinal, leaf) in snapshot
        .rotated
        .iter()
        .chain(std::iter::once(&snapshot.current))
        .enumerate()
    {
        insert_leaf(session, leaf, ordinal)?;
    }
    Ok(())
}

pub(super) fn update_family(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &SessionFamily,
) -> Result<(), StorageError> {
    let target = request.transition.family();
    let mut sql = String::from("UPDATE identity_session_families SET current_session_id = ");
    push_text(&mut sql, target.current().id().as_str());
    sql.push_str(", version = ");
    push_text(&mut sql, &encode_family_version(target.version()));
    sql.push_str(", state = ");
    push_text(&mut sql, family_state_label(target.state()));
    sql.push_str(" WHERE tenant_id = ");
    push_text(&mut sql, request.tenant_id.as_str());
    push_scope(&mut sql, request.user_id, durable.id());
    sql.push_str(" AND current_session_id = ");
    push_text(&mut sql, durable.current().id().as_str());
    sql.push_str(" AND version = ");
    push_text(
        &mut sql,
        &encode_family_version(request.expected_previous_version),
    );
    sql.push(';');
    require_single_update(session, sql)
}

pub(super) fn replace_leaves(
    session: &mut LocalSession,
    target: &SessionFamily,
    durable: &SessionFamily,
) -> Result<(), StorageError> {
    delete_leaves(session, durable)?;
    insert_leaves(session, target)
}

fn delete_leaves(session: &mut LocalSession, family: &SessionFamily) -> Result<(), StorageError> {
    let mut sql = String::from("DELETE FROM identity_session_leaves WHERE tenant_id = ");
    push_text(&mut sql, family.tenant_id().as_str());
    push_scope(&mut sql, family.user_id(), family.id());
    sql.push(';');
    let expected = u64::try_from(family.rotated().len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or_else(integrity_failure)?;
    require_affected(session, sql, expected)
}

fn insert_leaf(
    session: &mut LocalSession,
    leaf: &SessionSnapshot,
    ordinal: usize,
) -> Result<(), StorageError> {
    let ordinal = i64::try_from(ordinal).map_err(|_| integrity_failure())?;
    let mut sql = format!("INSERT INTO identity_session_leaves ({LEAF_PROJECTION}) VALUES (");
    push_leaf_binding(&mut sql, leaf, ordinal);
    push_leaf_timing(&mut sql, leaf);
    push_value(&mut sql, &encode_session_version(leaf.version));
    push_value(&mut sql, session_state_label(leaf.state));
    sql.push_str(");");
    require_single_insert(session, sql)
}

fn push_leaf_binding(sql: &mut String, leaf: &SessionSnapshot, ordinal: i64) {
    push_text(sql, leaf.subject.tenant_id().as_str());
    push_value(sql, leaf.subject.user_id().as_str());
    push_value(sql, leaf.family_id.as_str());
    push_value(sql, leaf.id.as_str());
    push_i64_value(sql, ordinal);
    sql.push_str(", ");
    push_optional_text(sql, leaf.predecessor_id.as_ref().map(|id| id.as_str()));
    push_value(sql, &encode_digest(leaf.token_digest.bytes()));
}

fn push_leaf_timing(sql: &mut String, leaf: &SessionSnapshot) {
    push_i64_value(sql, leaf.issued_at.unix_seconds());
    push_i64_value(sql, leaf.last_seen_at.unix_seconds());
    push_i64_value(sql, leaf.idle_expires_at.unix_seconds());
}

pub(super) fn insert_event(
    session: &mut LocalSession,
    event: &SessionEvent,
) -> Result<(), StorageError> {
    let mut sql = format!("INSERT INTO identity_session_events ({EVENT_PROJECTION}) VALUES (");
    push_text(&mut sql, event.tenant_id().as_str());
    push_value(&mut sql, event.user_id().as_str());
    push_value(&mut sql, event.family_id().as_str());
    push_value(&mut sql, event.session_id().as_str());
    push_value(&mut sql, &encode_family_version(event.version()));
    push_value(&mut sql, event_kind_label(event.kind()));
    push_i64_value(&mut sql, event.occurred_at().unix_seconds());
    push_value(&mut sql, event.actor().as_str());
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn encode_family_version(version: SessionFamilyVersion) -> String {
    format!("{:020}", version.get())
}

pub(super) fn encode_session_version(version: SessionVersion) -> String {
    format!("{:020}", version.get())
}

pub(super) fn encode_digest(bytes: [u8; 32]) -> String {
    hex(&bytes)
}

fn push_scope(sql: &mut String, user: &UserId, family: &SessionFamilyId) {
    sql.push_str(" AND user_id = ");
    push_text(sql, user.as_str());
    sql.push_str(" AND family_id = ");
    push_text(sql, family.as_str());
}

fn require_single_insert(session: &mut LocalSession, sql: String) -> Result<(), StorageError> {
    match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

fn require_single_update(session: &mut LocalSession, sql: String) -> Result<(), StorageError> {
    match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

fn require_affected(
    session: &mut LocalSession,
    sql: String,
    expected: u64,
) -> Result<(), StorageError> {
    match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(actual) if actual == expected => Ok(()),
        _ => Err(integrity_failure()),
    }
}

fn push_value(sql: &mut String, value: &str) {
    sql.push_str(", ");
    push_text(sql, value);
}

fn push_i64_value(sql: &mut String, value: i64) {
    sql.push_str(", ");
    sql.push_str(&value.to_string());
}

fn push_optional_text(sql: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_text(sql, value),
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

pub(super) const fn family_state_label(state: SessionFamilyState) -> &'static str {
    match state {
        SessionFamilyState::Active => "active",
        SessionFamilyState::Revoked => "revoked",
        SessionFamilyState::Expired => "expired",
    }
}

pub(super) const fn session_state_label(state: SessionState) -> &'static str {
    match state {
        SessionState::Active => "active",
        SessionState::Rotated => "rotated",
        SessionState::Revoked => "revoked",
        SessionState::Expired => "expired",
    }
}

pub(super) const fn event_kind_label(kind: SessionEventKind) -> &'static str {
    match kind {
        SessionEventKind::Issued => "issued",
        SessionEventKind::Rotated => "rotated",
        SessionEventKind::ReuseRevoked => "reuse_revoked",
        SessionEventKind::Revoked => "revoked",
        SessionEventKind::Expired => "expired",
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

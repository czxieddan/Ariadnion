//! Fixed tenant-bound SQL for durable scoped API keys.

use ariadnion_auth_api_key::{
    ApiKey, ApiKeyEvent, ApiKeyEventKind, ApiKeyId, ApiKeyPrefix, ApiKeyState, ApiKeyVersion,
};
use ariadnion_core::TenantId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UserId;
use rnmdb_cli::{CommandOutput, LocalSession};

use super::{CommitRequest, MAX_API_KEY_EVENT_ROWS, integrity_failure};
use crate::session::map_rnmdb_error;

pub(super) const KEY_PROJECTION: &str = "tenant_id, user_id, api_key_id, prefix, current_secret_digest, previous_secret_digest, rotation_started_at, previous_secret_expires_at, issued_at, expires_at, version, state";
pub(super) const SCOPE_PROJECTION: &str = "tenant_id, api_key_id, scope";
pub(super) const RETIRED_PROJECTION: &str = "tenant_id, api_key_id, ordinal, secret_digest";
pub(super) const EVENT_PROJECTION: &str = "tenant_id, api_key_id, user_id, version, kind, occurred_at, actor_id, state, current_secret_digest, previous_secret_digest, rotation_started_at, previous_secret_expires_at";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";
const OWNER_PROJECTION: &str = "tenant_id, user_id, api_key_id, prefix";
const MAX_SQL_BYTES: usize = 1_048_576;

pub(super) fn load_key(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    key: &ApiKeyId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {KEY_PROJECTION} FROM identity_api_keys WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND user_id = ");
    push_text(&mut sql, user.as_str());
    sql.push_str(" AND api_key_id = ");
    push_text(&mut sql, key.as_str());
    sql.push_str(" LIMIT 2;");
    execute(session, finish(sql)?)
}

pub(super) fn load_key_by_id(
    session: &mut LocalSession,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {KEY_PROJECTION} FROM identity_api_keys WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND api_key_id = ");
    push_text(&mut sql, key.as_str());
    sql.push_str(" LIMIT 2;");
    execute(session, finish(sql)?)
}

pub(super) fn load_key_by_prefix(
    session: &mut LocalSession,
    tenant: &TenantId,
    prefix: &ApiKeyPrefix,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {KEY_PROJECTION} FROM identity_api_keys WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND prefix = ");
    push_text(&mut sql, prefix.as_str());
    sql.push_str(" LIMIT 2;");
    execute(session, finish(sql)?)
}

pub(super) fn load_scopes(
    session: &mut LocalSession,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<CommandOutput, StorageError> {
    companion_query(session, scope_query(), tenant, key)
}

pub(super) fn load_retired(
    session: &mut LocalSession,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<CommandOutput, StorageError> {
    companion_query(session, retired_query(), tenant, key)
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<CommandOutput, StorageError> {
    companion_query(session, event_query(), tenant, key)
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
    execute(session, finish(sql)?)
}

struct CompanionQuery {
    projection: &'static str,
    table: &'static str,
    order: &'static str,
    limit: usize,
}

fn companion_query(
    session: &mut LocalSession,
    query: CompanionQuery,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!(
        "SELECT {} FROM {} WHERE tenant_id = ",
        query.projection, query.table
    );
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND api_key_id = ");
    push_text(&mut sql, key.as_str());
    sql.push_str(" ORDER BY ");
    sql.push_str(query.order);
    sql.push_str(" LIMIT ");
    sql.push_str(&query.limit.to_string());
    sql.push(';');
    execute(session, finish(sql)?)
}

const fn scope_query() -> CompanionQuery {
    CompanionQuery {
        projection: SCOPE_PROJECTION,
        table: "identity_api_key_scopes",
        order: "scope",
        limit: 33,
    }
}

const fn retired_query() -> CompanionQuery {
    CompanionQuery {
        projection: RETIRED_PROJECTION,
        table: "identity_api_key_retired_secrets",
        order: "ordinal",
        limit: 4_097,
    }
}

const fn event_query() -> CompanionQuery {
    CompanionQuery {
        projection: EVENT_PROJECTION,
        table: "identity_api_key_events",
        order: "version",
        limit: MAX_API_KEY_EVENT_ROWS + 1,
    }
}

pub(super) fn load_key_owners(
    session: &mut LocalSession,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<CommandOutput, StorageError> {
    owner_query(session, tenant, "api_key_id", key.as_str())
}

pub(super) fn load_prefix_owners(
    session: &mut LocalSession,
    tenant: &TenantId,
    prefix: &ApiKeyPrefix,
) -> Result<CommandOutput, StorageError> {
    owner_query(session, tenant, "prefix", prefix.as_str())
}

fn owner_query(
    session: &mut LocalSession,
    tenant: &TenantId,
    column: &str,
    value: &str,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {OWNER_PROJECTION} FROM identity_api_keys WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND ");
    sql.push_str(column);
    sql.push_str(" = ");
    push_text(&mut sql, value);
    sql.push_str(" LIMIT 2;");
    execute(session, finish(sql)?)
}

pub(super) fn insert_key(session: &mut LocalSession, key: &ApiKey) -> Result<(), StorageError> {
    let mut sql = format!("INSERT INTO identity_api_keys ({KEY_PROJECTION}) VALUES (");
    push_text(&mut sql, key.tenant_id().as_str());
    push_value(&mut sql, key.user_id().as_str());
    push_value(&mut sql, key.id().as_str());
    push_value(&mut sql, key.prefix().as_str());
    push_value(&mut sql, &encode_digest(key.current_secret().bytes()));
    push_optional_digest(&mut sql, key.previous_secret());
    push_optional_time(&mut sql, key.rotation_started_at());
    push_optional_time(&mut sql, key.previous_secret_expires_at());
    push_i64_value(&mut sql, key.issued_at().unix_seconds());
    push_optional_time(&mut sql, key.expires_at());
    push_value(&mut sql, &encode_version(key.version()));
    push_value(&mut sql, state_label(key.state()));
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn insert_scopes(session: &mut LocalSession, key: &ApiKey) -> Result<(), StorageError> {
    for scope in key.scopes() {
        let mut sql = format!("INSERT INTO identity_api_key_scopes ({SCOPE_PROJECTION}) VALUES (");
        push_text(&mut sql, key.tenant_id().as_str());
        push_value(&mut sql, key.id().as_str());
        push_value(&mut sql, scope.as_str());
        sql.push_str(");");
        require_single_insert(session, sql)?;
    }
    Ok(())
}

pub(super) fn insert_retired(session: &mut LocalSession, key: &ApiKey) -> Result<(), StorageError> {
    for (ordinal, digest) in key.retired_secrets().iter().enumerate() {
        let ordinal = i64::try_from(ordinal).map_err(|_| integrity_failure())?;
        let mut sql =
            format!("INSERT INTO identity_api_key_retired_secrets ({RETIRED_PROJECTION}) VALUES (");
        push_text(&mut sql, key.tenant_id().as_str());
        push_value(&mut sql, key.id().as_str());
        push_i64_value(&mut sql, ordinal);
        push_value(&mut sql, &encode_digest(digest.bytes()));
        sql.push_str(");");
        require_single_insert(session, sql)?;
    }
    Ok(())
}

pub(super) fn insert_retired_at(
    session: &mut LocalSession,
    key: &ApiKey,
    ordinal: usize,
) -> Result<(), StorageError> {
    let digest = key
        .retired_secrets()
        .get(ordinal)
        .ok_or_else(integrity_failure)?;
    let ordinal = i64::try_from(ordinal).map_err(|_| integrity_failure())?;
    let mut sql =
        format!("INSERT INTO identity_api_key_retired_secrets ({RETIRED_PROJECTION}) VALUES (");
    push_text(&mut sql, key.tenant_id().as_str());
    push_value(&mut sql, key.id().as_str());
    push_i64_value(&mut sql, ordinal);
    push_value(&mut sql, &encode_digest(digest.bytes()));
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn insert_event(
    session: &mut LocalSession,
    event: &ApiKeyEvent,
    key: &ApiKey,
) -> Result<(), StorageError> {
    let mut sql = format!("INSERT INTO identity_api_key_events ({EVENT_PROJECTION}) VALUES (");
    push_text(&mut sql, event.tenant_id().as_str());
    push_value(&mut sql, event.key_id().as_str());
    push_value(&mut sql, event.user_id().as_str());
    push_value(&mut sql, &encode_version(event.version()));
    push_value(&mut sql, event_kind_label(event.kind()));
    push_i64_value(&mut sql, event.occurred_at().unix_seconds());
    push_value(&mut sql, event.actor().as_str());
    push_value(&mut sql, state_label(key.state()));
    push_value(&mut sql, &encode_digest(key.current_secret().bytes()));
    push_optional_digest(&mut sql, key.previous_secret());
    push_optional_time(&mut sql, key.rotation_started_at());
    push_optional_time(&mut sql, key.previous_secret_expires_at());
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn update_rotation(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    let target = request.transition.key();
    let mut sql = String::from("UPDATE identity_api_keys SET current_secret_digest = ");
    push_text(&mut sql, &encode_digest(target.current_secret().bytes()));
    sql.push_str(", previous_secret_digest = ");
    push_text(
        &mut sql,
        &encode_digest(
            target
                .previous_secret()
                .ok_or_else(integrity_failure)?
                .bytes(),
        ),
    );
    sql.push_str(", rotation_started_at = ");
    push_time(&mut sql, target.rotation_started_at())?;
    sql.push_str(", previous_secret_expires_at = ");
    push_time(&mut sql, target.previous_secret_expires_at())?;
    sql.push_str(", version = ");
    push_text(&mut sql, &encode_version(target.version()));
    sql.push_str(", state = ");
    push_text(&mut sql, state_label(target.state()));
    push_rotation_cas(&mut sql, request, durable);
    require_single_update(session, sql)
}

pub(super) fn update_rotation_completion(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    let target = request.transition.key();
    let mut sql = String::from(
        "UPDATE identity_api_keys SET previous_secret_digest = NULL, rotation_started_at = NULL, previous_secret_expires_at = NULL, version = ",
    );
    push_text(&mut sql, &encode_version(target.version()));
    sql.push_str(", state = ");
    push_text(&mut sql, state_label(target.state()));
    push_completion_cas(&mut sql, request, durable)?;
    require_single_update(session, sql)
}

pub(super) fn update_terminal(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    let target = request.transition.key();
    let mut sql = String::from(
        "UPDATE identity_api_keys SET previous_secret_digest = NULL, rotation_started_at = NULL, previous_secret_expires_at = NULL, version = ",
    );
    push_text(&mut sql, &encode_version(target.version()));
    sql.push_str(", state = ");
    push_text(&mut sql, state_label(target.state()));
    push_terminal_cas(&mut sql, request, durable);
    require_single_update(session, sql)
}

fn push_rotation_cas(sql: &mut String, request: &CommitRequest<'_>, durable: &ApiKey) {
    sql.push_str(" WHERE tenant_id = ");
    push_text(sql, request.tenant_id.as_str());
    sql.push_str(" AND user_id = ");
    push_text(sql, request.user_id.as_str());
    sql.push_str(" AND api_key_id = ");
    push_text(sql, durable.id().as_str());
    sql.push_str(" AND version = ");
    push_text(sql, &encode_version(request.expected_previous_version));
    sql.push_str(" AND current_secret_digest = ");
    push_text(sql, &encode_digest(durable.current_secret().bytes()));
    sql.push_str(" AND previous_secret_digest IS NULL");
    sql.push_str(" AND rotation_started_at IS NULL");
    sql.push_str(" AND previous_secret_expires_at IS NULL");
    sql.push_str(" AND state = 'active';");
}

fn push_completion_cas(
    sql: &mut String,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    sql.push_str(" WHERE tenant_id = ");
    push_text(sql, request.tenant_id.as_str());
    sql.push_str(" AND user_id = ");
    push_text(sql, request.user_id.as_str());
    sql.push_str(" AND api_key_id = ");
    push_text(sql, durable.id().as_str());
    sql.push_str(" AND version = ");
    push_text(sql, &encode_version(request.expected_previous_version));
    sql.push_str(" AND current_secret_digest = ");
    push_text(sql, &encode_digest(durable.current_secret().bytes()));
    sql.push_str(" AND previous_secret_digest = ");
    push_text(
        sql,
        &encode_digest(
            durable
                .previous_secret()
                .ok_or_else(integrity_failure)?
                .bytes(),
        ),
    );
    sql.push_str(" AND rotation_started_at = ");
    push_time(sql, durable.rotation_started_at())?;
    sql.push_str(" AND previous_secret_expires_at = ");
    push_time(sql, durable.previous_secret_expires_at())?;
    sql.push_str(" AND state = 'rotating';");
    Ok(())
}

fn push_terminal_cas(sql: &mut String, request: &CommitRequest<'_>, durable: &ApiKey) {
    sql.push_str(" WHERE tenant_id = ");
    push_text(sql, request.tenant_id.as_str());
    sql.push_str(" AND user_id = ");
    push_text(sql, request.user_id.as_str());
    sql.push_str(" AND api_key_id = ");
    push_text(sql, durable.id().as_str());
    sql.push_str(" AND version = ");
    push_text(sql, &encode_version(request.expected_previous_version));
    sql.push_str(" AND current_secret_digest = ");
    push_text(sql, &encode_digest(durable.current_secret().bytes()));
    push_optional_digest_cas(sql, durable.previous_secret());
    push_optional_time_cas(sql, "rotation_started_at", durable.rotation_started_at());
    push_optional_time_cas(
        sql,
        "previous_secret_expires_at",
        durable.previous_secret_expires_at(),
    );
    sql.push_str(" AND state = ");
    push_text(sql, state_label(durable.state()));
    sql.push(';');
}

fn push_optional_digest_cas(
    sql: &mut String,
    value: Option<ariadnion_auth_api_key::ApiKeySecretDigest>,
) {
    sql.push_str(" AND previous_secret_digest");
    match value {
        Some(value) => {
            sql.push_str(" = ");
            push_text(sql, &encode_digest(value.bytes()));
        }
        None => sql.push_str(" IS NULL"),
    }
}

fn push_optional_time_cas(
    sql: &mut String,
    column: &str,
    value: Option<ariadnion_user_domain::UtcTimestamp>,
) {
    sql.push_str(" AND ");
    sql.push_str(column);
    match value {
        Some(value) => {
            sql.push_str(" = ");
            sql.push_str(&value.unix_seconds().to_string());
        }
        None => sql.push_str(" IS NULL"),
    }
}

pub(super) fn encode_version(version: ApiKeyVersion) -> String {
    format!("{:020}", version.get())
}

pub(super) fn encode_digest(bytes: [u8; 32]) -> String {
    hex(&bytes)
}

pub(super) const fn state_label(state: ApiKeyState) -> &'static str {
    match state {
        ApiKeyState::Active => "active",
        ApiKeyState::Rotating => "rotating",
        ApiKeyState::Revoked => "revoked",
        ApiKeyState::Expired => "expired",
    }
}

pub(super) const fn event_kind_label(kind: ApiKeyEventKind) -> &'static str {
    match kind {
        ApiKeyEventKind::Issued => "issued",
        ApiKeyEventKind::Rotated => "rotated",
        ApiKeyEventKind::RotationCompleted => "rotation_completed",
        ApiKeyEventKind::Revoked => "revoked",
        ApiKeyEventKind::Expired => "expired",
    }
}

fn require_single_insert(session: &mut LocalSession, sql: String) -> Result<(), StorageError> {
    match execute(session, finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

fn require_single_update(session: &mut LocalSession, sql: String) -> Result<(), StorageError> {
    match execute(session, finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
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

fn push_optional_digest(
    sql: &mut String,
    value: Option<ariadnion_auth_api_key::ApiKeySecretDigest>,
) {
    match value {
        Some(value) => push_value(sql, &encode_digest(value.bytes())),
        None => sql.push_str(", NULL"),
    }
}

fn push_optional_time(sql: &mut String, value: Option<ariadnion_user_domain::UtcTimestamp>) {
    match value {
        Some(value) => push_i64_value(sql, value.unix_seconds()),
        None => sql.push_str(", NULL"),
    }
}

fn push_time(
    sql: &mut String,
    value: Option<ariadnion_user_domain::UtcTimestamp>,
) -> Result<(), StorageError> {
    let value = value.ok_or_else(integrity_failure)?;
    sql.push_str(&value.unix_seconds().to_string());
    Ok(())
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

fn execute(session: &mut LocalSession, sql: String) -> Result<CommandOutput, StorageError> {
    session.execute(&sql).map_err(map_rnmdb_error)
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

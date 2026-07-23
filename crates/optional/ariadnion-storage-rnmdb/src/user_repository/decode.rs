//! Exact persisted projections for user, lifecycle, and outbox evidence.

mod history;

use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_storage_outbox::{
    OutboxEventId, OutboxIdempotencyKey, OutboxLeaseToken, OutboxTopic, OutboxWorkerId,
};
use ariadnion_user_domain::{
    DeletionNotBefore, DeletionRecoveryState, User, UserId, UserSnapshotState, UserVersion,
    UtcTimestamp,
};
use rnmdb_cli::CommandOutput;
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};
use zeroize::Zeroizing;

use super::evidence::TransitionIdentity;
use super::integrity_failure;
use super::sql;
use crate::UtcTimestampMicros;

pub(super) struct VerifiedLifecycle {
    pub(super) version: UserVersion,
    pub(super) actor: PrincipalId,
    pub(super) request_id: RequestId,
    pub(super) snapshot: super::evidence::SnapshotRecord,
    pub(super) lifecycle: super::evidence::LifecycleRecord,
}

const VERSION_TEXT_BYTES: usize = 20;
const MAX_OUTBOX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MICROS_PER_SECOND: i64 = 1_000_000;

pub(super) fn load_user(
    session: &mut rnmdb_cli::LocalSession,
    tenant_id: &TenantId,
    user_id: &UserId,
) -> Result<User, StorageError> {
    let batch = rows(sql::load_user(session, tenant_id, user_id)?)?;
    validate_columns(batch.columns(), &user_columns())?;
    match batch.rows() {
        [] => Err(StorageError::new(StorageErrorCode::NotFound)),
        [row] => decode_user_row(row, tenant_id, user_id),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn verify_lifecycle(
    session: &mut rnmdb_cli::LocalSession,
    identity: &TransitionIdentity,
) -> Result<(), StorageError> {
    let batch = rows(sql::load_lifecycle(session, identity)?)?;
    validate_columns(batch.columns(), &lifecycle_columns())?;
    match batch.rows() {
        [row] => decode_lifecycle_row(row, identity),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn verify_current_lifecycle(
    session: &mut rnmdb_cli::LocalSession,
    user: &User,
) -> Result<(), StorageError> {
    let batch = rows(sql::load_current_lifecycle(session, user)?)?;
    validate_columns(batch.columns(), &lifecycle_columns())?;
    match batch.rows() {
        [row] => verify_current_lifecycle_row(row, user),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn has_later_lifecycle(
    session: &mut rnmdb_cli::LocalSession,
    tenant_id: &TenantId,
    user_id: &UserId,
    version: UserVersion,
) -> Result<bool, StorageError> {
    let batch = rows(sql::load_later_lifecycle(
        session, tenant_id, user_id, version,
    )?)?;
    validate_later_columns(batch.columns())?;
    for row in batch.rows() {
        validate_later_row(row, version)?;
    }
    Ok(!batch.rows().is_empty())
}

pub(super) fn verify_lifecycle_range(
    session: &mut rnmdb_cli::LocalSession,
    identity: &TransitionIdentity,
    current: &User,
) -> Result<Box<[VerifiedLifecycle]>, StorageError> {
    let expected_rows = history_row_count(identity.new_version(), current.version())?;
    let batch = rows(sql::load_lifecycle_range(
        session,
        identity.tenant_id(),
        identity.user_id(),
        identity.new_version(),
        current.version(),
    )?)?;
    validate_columns(batch.columns(), &lifecycle_columns())?;
    if batch.rows().len() != expected_rows {
        return Err(integrity_failure());
    }
    history::verify_history_rows(batch.rows(), identity, current)
}

fn history_row_count(first: UserVersion, last: UserVersion) -> Result<usize, StorageError> {
    let distance = last
        .get()
        .checked_sub(first.get())
        .ok_or_else(integrity_failure)?;
    let count = distance.checked_add(1).ok_or_else(integrity_failure)?;
    if count > sql::MAX_RECONCILIATION_HISTORY_ROWS {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    usize::try_from(count).map_err(|_| integrity_failure())
}

fn validate_later_columns(columns: &[ColumnSchema]) -> Result<(), StorageError> {
    let valid = columns.len() == 1
        && columns[0].name() == "version"
        && columns[0].data_type() == &SqlType::Text;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_later_row(row: &Row, current: UserVersion) -> Result<(), StorageError> {
    let [SqlValue::Text(value)] = row.values() else {
        return Err(integrity_failure());
    };
    if decode_version(value)? <= current {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) struct PersistedOutbox {
    committed_at: UtcTimestamp,
    payload: Zeroizing<Vec<u8>>,
}

impl PersistedOutbox {
    pub(super) const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub(super) fn load_outbox(
    session: &mut rnmdb_cli::LocalSession,
    identity: &TransitionIdentity,
) -> Result<PersistedOutbox, StorageError> {
    let batch = rows(sql::load_outbox(session, identity)?)?;
    validate_columns(batch.columns(), &outbox_columns())?;
    match batch.rows() {
        [row] => decode_outbox_row(row, identity),
        _ => Err(integrity_failure()),
    }
}

fn decode_user_row(
    row: &Row,
    expected_tenant: &TenantId,
    expected_user: &UserId,
) -> Result<User, StorageError> {
    let persisted = decode_persisted_user(row)?;
    validate_user_identity(
        &persisted.tenant_id,
        &persisted.user_id,
        expected_tenant,
        expected_user,
    )?;
    let state = decode_snapshot_state(persisted.state, persisted.deletion)?;
    User::from_snapshot(
        persisted.user_id,
        persisted.tenant_id,
        persisted.version,
        state,
    )
    .map_err(|_| integrity_failure())
}

struct PersistedUser<'a> {
    tenant_id: TenantId,
    user_id: UserId,
    version: UserVersion,
    state: &'a str,
    deletion: DeletionTuple<'a>,
}

fn decode_persisted_user(row: &Row) -> Result<PersistedUser<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(user),
        SqlValue::Text(version),
        SqlValue::Text(state),
        requested_at,
        not_before,
        recovery_state,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    let tenant_id = TenantId::parse(tenant).map_err(|_| integrity_failure())?;
    let user_id = UserId::parse(user).map_err(|_| integrity_failure())?;
    let version = decode_version(version)?;
    let deletion = decode_deletion_tuple(requested_at, not_before, recovery_state)?;
    Ok(PersistedUser {
        tenant_id,
        user_id,
        version,
        state,
        deletion,
    })
}

fn decode_deletion_tuple<'a>(
    requested_at: &'a SqlValue,
    not_before: &'a SqlValue,
    recovery_state: &'a SqlValue,
) -> Result<DeletionTuple<'a>, StorageError> {
    Ok(DeletionTuple {
        requested_at: optional_i64(requested_at)?,
        not_before: optional_i64(not_before)?,
        recovery_state: optional_text(recovery_state)?,
    })
}

fn validate_user_identity(
    tenant_id: &TenantId,
    user_id: &UserId,
    expected_tenant: &TenantId,
    expected_user: &UserId,
) -> Result<(), StorageError> {
    if tenant_id != expected_tenant || user_id != expected_user {
        return Err(integrity_failure());
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DeletionTuple<'a> {
    requested_at: Option<i64>,
    not_before: Option<i64>,
    recovery_state: Option<&'a str>,
}

fn decode_snapshot_state(
    state: &str,
    tuple: DeletionTuple<'_>,
) -> Result<UserSnapshotState, StorageError> {
    match state {
        "invited" => simple_snapshot(tuple, UserSnapshotState::Invited),
        "active" => simple_snapshot(tuple, UserSnapshotState::Active),
        "suspended" => simple_snapshot(tuple, UserSnapshotState::Suspended),
        "deleted" => simple_snapshot(tuple, UserSnapshotState::Deleted),
        "deletion_pending" => pending_snapshot(tuple),
        _ => Err(integrity_failure()),
    }
}

fn simple_snapshot(
    tuple: DeletionTuple<'_>,
    state: UserSnapshotState,
) -> Result<UserSnapshotState, StorageError> {
    if tuple.requested_at.is_some() || tuple.not_before.is_some() || tuple.recovery_state.is_some()
    {
        return Err(integrity_failure());
    }
    Ok(state)
}

fn pending_snapshot(tuple: DeletionTuple<'_>) -> Result<UserSnapshotState, StorageError> {
    let (Some(requested), Some(boundary), Some(recovery)) =
        (tuple.requested_at, tuple.not_before, tuple.recovery_state)
    else {
        return Err(integrity_failure());
    };
    let requested_at = UtcTimestamp::from_unix_seconds(requested);
    let not_before =
        DeletionNotBefore::new(requested_at, UtcTimestamp::from_unix_seconds(boundary))
            .map_err(|_| integrity_failure())?;
    let recovery_state = decode_recovery_state(recovery)?;
    Ok(UserSnapshotState::DeletionPending {
        requested_at,
        not_before,
        recovery_state,
    })
}

fn decode_lifecycle_row(row: &Row, identity: &TransitionIdentity) -> Result<(), StorageError> {
    let persisted = decode_persisted_lifecycle(row)?;
    validate_lifecycle_identity(&persisted, identity)?;
    validate_lifecycle_facts(&persisted, identity)
}

fn decode_persisted_lifecycle(row: &Row) -> Result<PersistedLifecycle<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(user),
        SqlValue::Text(version),
        SqlValue::Text(kind),
        SqlValue::Int64(occurred_at),
        SqlValue::Text(actor),
        SqlValue::Text(request),
        not_before,
        recovery_state,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    let (tenant_id, user_id, version, actor, request_id) =
        decode_lifecycle_identity(tenant, user, version, actor, request)?;
    Ok(PersistedLifecycle {
        tenant_id,
        user_id,
        version,
        kind,
        occurred_at: *occurred_at,
        actor,
        request_id,
        not_before: optional_i64(not_before)?,
        recovery_state: optional_text(recovery_state)?,
    })
}

type LifecycleIdentity = (TenantId, UserId, UserVersion, PrincipalId, RequestId);

fn decode_lifecycle_identity(
    tenant: &str,
    user: &str,
    version: &str,
    actor: &str,
    request: &str,
) -> Result<LifecycleIdentity, StorageError> {
    Ok((
        TenantId::parse(tenant).map_err(|_| integrity_failure())?,
        UserId::parse(user).map_err(|_| integrity_failure())?,
        decode_version(version)?,
        PrincipalId::parse(actor).map_err(|_| integrity_failure())?,
        RequestId::parse(request).map_err(|_| integrity_failure())?,
    ))
}

struct PersistedLifecycle<'a> {
    tenant_id: TenantId,
    user_id: UserId,
    version: UserVersion,
    kind: &'a str,
    occurred_at: i64,
    actor: PrincipalId,
    request_id: RequestId,
    not_before: Option<i64>,
    recovery_state: Option<&'a str>,
}

fn validate_lifecycle_identity(
    persisted: &PersistedLifecycle<'_>,
    identity: &TransitionIdentity,
) -> Result<(), StorageError> {
    let valid = &persisted.tenant_id == identity.tenant_id()
        && &persisted.user_id == identity.user_id()
        && persisted.version == identity.new_version()
        && &persisted.actor == identity.actor()
        && &persisted.request_id == identity.request_id();
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_lifecycle_facts(
    persisted: &PersistedLifecycle<'_>,
    identity: &TransitionIdentity,
) -> Result<(), StorageError> {
    let expected = identity.lifecycle();
    let valid = persisted.kind == expected.kind
        && persisted.occurred_at == expected.occurred_at
        && persisted.not_before == expected.not_before
        && persisted.recovery_state == expected.recovery_state;
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn verify_current_lifecycle_row(row: &Row, user: &User) -> Result<(), StorageError> {
    let persisted = decode_persisted_lifecycle(row)?;
    validate_current_lifecycle_identity(&persisted, user)?;
    validate_current_lifecycle_facts(&persisted, user.snapshot_state())
}

fn validate_current_lifecycle_identity(
    persisted: &PersistedLifecycle<'_>,
    user: &User,
) -> Result<(), StorageError> {
    let valid = &persisted.tenant_id == user.tenant_id()
        && &persisted.user_id == user.id()
        && persisted.version == user.version();
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_current_lifecycle_facts(
    persisted: &PersistedLifecycle<'_>,
    state: UserSnapshotState,
) -> Result<(), StorageError> {
    let valid = match state {
        UserSnapshotState::Invited => false,
        UserSnapshotState::Active => current_active_lifecycle_is_valid(persisted),
        UserSnapshotState::Suspended => current_suspended_lifecycle_is_valid(persisted),
        UserSnapshotState::DeletionPending {
            requested_at,
            not_before,
            recovery_state,
        } => {
            current_pending_lifecycle_is_valid(persisted, requested_at, not_before, recovery_state)
        }
        UserSnapshotState::Deleted => current_deleted_lifecycle_is_valid(persisted),
    };
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn current_active_lifecycle_is_valid(persisted: &PersistedLifecycle<'_>) -> bool {
    match persisted.kind {
        "activated" => persisted.version.get() == 2 && has_no_lifecycle_metadata(persisted),
        "resumed" => persisted.version.get() > 2 && has_no_lifecycle_metadata(persisted),
        "deletion_recovered" => {
            persisted.version.get() > 2 && has_recovery_metadata(persisted, "active")
        }
        _ => false,
    }
}

fn current_suspended_lifecycle_is_valid(persisted: &PersistedLifecycle<'_>) -> bool {
    match persisted.kind {
        "suspended" => persisted.version.get() >= 3 && has_no_lifecycle_metadata(persisted),
        "deletion_recovered" => {
            persisted.version.get() >= 5 && has_recovery_metadata(persisted, "suspended")
        }
        _ => false,
    }
}

fn current_pending_lifecycle_is_valid(
    persisted: &PersistedLifecycle<'_>,
    requested_at: UtcTimestamp,
    not_before: DeletionNotBefore,
    recovery_state: DeletionRecoveryState,
) -> bool {
    persisted.kind == "deletion_requested"
        && persisted.occurred_at == requested_at.unix_seconds()
        && persisted.not_before == Some(not_before.timestamp().unix_seconds())
        && persisted.recovery_state == Some(recovery_label(recovery_state))
}

fn current_deleted_lifecycle_is_valid(persisted: &PersistedLifecycle<'_>) -> bool {
    persisted.kind == "deleted" && has_no_lifecycle_metadata(persisted)
}

fn has_no_lifecycle_metadata(persisted: &PersistedLifecycle<'_>) -> bool {
    persisted.not_before.is_none() && persisted.recovery_state.is_none()
}

fn has_recovery_metadata(persisted: &PersistedLifecycle<'_>, expected: &str) -> bool {
    persisted.not_before.is_none() && persisted.recovery_state == Some(expected)
}

const fn recovery_label(state: DeletionRecoveryState) -> &'static str {
    match state {
        DeletionRecoveryState::Active => "active",
        DeletionRecoveryState::Suspended => "suspended",
    }
}

fn decode_outbox_row(
    row: &Row,
    identity: &TransitionIdentity,
) -> Result<PersistedOutbox, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(event_id),
        SqlValue::Text(topic),
        SqlValue::Text(key),
        SqlValue::Text(payload),
        created_at,
        available_at,
        SqlValue::Int64(attempt),
        SqlValue::Text(state),
        lease_token,
        lease_worker,
        lease_expires_at,
        delivered_at,
        failed_at,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_outbox_identity(tenant, event_id, topic, key, identity)?;
    let created = decode_timestamp(created_at)?;
    let available = decode_timestamp(available_at)?;
    let mutable = OutboxMutableFields {
        lease_token,
        lease_worker,
        lease_expires_at,
        delivered_at,
        failed_at,
    };
    validate_outbox_lifecycle(*attempt, state, created, available, &mutable)?;
    let committed_at = decode_receipt_time(created)?;
    Ok(PersistedOutbox {
        committed_at,
        payload: decode_hex_payload(payload)?,
    })
}

struct OutboxMutableFields<'a> {
    lease_token: &'a SqlValue,
    lease_worker: &'a SqlValue,
    lease_expires_at: &'a SqlValue,
    delivered_at: &'a SqlValue,
    failed_at: &'a SqlValue,
}

fn validate_outbox_identity(
    tenant: &str,
    event_id: &str,
    topic: &str,
    key: &str,
    identity: &TransitionIdentity,
) -> Result<(), StorageError> {
    let persisted = decode_outbox_identity(tenant, event_id, topic, key)?;
    let valid = &persisted.tenant == identity.tenant_id()
        && &persisted.event_id == identity.outbox_event_id()
        && persisted.topic.as_str() == "identity.user.lifecycle.v1"
        && &persisted.key == identity.outbox_key();
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

struct PersistedOutboxIdentity {
    tenant: TenantId,
    event_id: OutboxEventId,
    topic: OutboxTopic,
    key: OutboxIdempotencyKey,
}

fn decode_outbox_identity(
    tenant: &str,
    event_id: &str,
    topic: &str,
    key: &str,
) -> Result<PersistedOutboxIdentity, StorageError> {
    Ok(PersistedOutboxIdentity {
        tenant: TenantId::parse(tenant).map_err(|_| integrity_failure())?,
        event_id: OutboxEventId::parse(event_id).map_err(|_| integrity_failure())?,
        topic: OutboxTopic::parse(topic).map_err(|_| integrity_failure())?,
        key: OutboxIdempotencyKey::parse(key).map_err(|_| integrity_failure())?,
    })
}

fn validate_outbox_lifecycle(
    attempt: i64,
    state: &str,
    created: i64,
    available: i64,
    mutable: &OutboxMutableFields<'_>,
) -> Result<(), StorageError> {
    match state {
        "pending" => validate_pending_outbox(
            attempt,
            created,
            available,
            [
                mutable.lease_token,
                mutable.lease_worker,
                mutable.lease_expires_at,
                mutable.delivered_at,
                mutable.failed_at,
            ],
        ),
        "leased" => validate_leased_outbox(
            attempt,
            mutable.lease_token,
            mutable.lease_worker,
            mutable.lease_expires_at,
            mutable.delivered_at,
            mutable.failed_at,
        ),
        "delivered" => validate_delivered_outbox(
            attempt,
            mutable.lease_token,
            mutable.lease_worker,
            mutable.lease_expires_at,
            mutable.delivered_at,
            mutable.failed_at,
        ),
        "dead" => validate_dead_outbox(
            attempt,
            mutable.lease_token,
            mutable.lease_worker,
            mutable.lease_expires_at,
            mutable.delivered_at,
            mutable.failed_at,
        ),
        _ => Err(integrity_failure()),
    }
}

fn validate_pending_outbox(
    attempt: i64,
    created: i64,
    available: i64,
    nullable: [&SqlValue; 5],
) -> Result<(), StorageError> {
    validate_attempt(attempt, true)?;
    if attempt == 0 && available != created {
        return Err(integrity_failure());
    }
    require_all_null(nullable)
}

fn validate_leased_outbox(
    attempt: i64,
    lease_token: &SqlValue,
    lease_worker: &SqlValue,
    lease_expires_at: &SqlValue,
    delivered_at: &SqlValue,
    failed_at: &SqlValue,
) -> Result<(), StorageError> {
    validate_attempt(attempt, false)?;
    validate_lease_fields(lease_token, lease_worker, lease_expires_at)?;
    require_null(delivered_at)?;
    require_null(failed_at)
}

fn validate_delivered_outbox(
    attempt: i64,
    lease_token: &SqlValue,
    lease_worker: &SqlValue,
    lease_expires_at: &SqlValue,
    delivered_at: &SqlValue,
    failed_at: &SqlValue,
) -> Result<(), StorageError> {
    validate_attempt(attempt, false)?;
    require_all_null([lease_token, lease_worker, lease_expires_at])?;
    require_timestamp(delivered_at)?;
    require_null(failed_at)
}

fn validate_dead_outbox(
    attempt: i64,
    lease_token: &SqlValue,
    lease_worker: &SqlValue,
    lease_expires_at: &SqlValue,
    delivered_at: &SqlValue,
    failed_at: &SqlValue,
) -> Result<(), StorageError> {
    validate_attempt(attempt, false)?;
    require_all_null([lease_token, lease_worker, lease_expires_at])?;
    require_null(delivered_at)?;
    require_timestamp(failed_at)
}

fn validate_attempt(attempt: i64, allow_zero: bool) -> Result<(), StorageError> {
    let valid = attempt >= 0 && u32::try_from(attempt).is_ok() && (allow_zero || attempt > 0);
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_lease_fields(
    lease_token: &SqlValue,
    lease_worker: &SqlValue,
    lease_expires_at: &SqlValue,
) -> Result<(), StorageError> {
    decode_lease_token(lease_token)?;
    let worker = required_text(lease_worker)?;
    OutboxWorkerId::parse(worker).map_err(|_| integrity_failure())?;
    require_timestamp(lease_expires_at)
}

fn decode_lease_token(value: &SqlValue) -> Result<(), StorageError> {
    let value = required_text(value)?;
    if value.len() > 512 || !value.len().is_multiple_of(2) {
        return Err(integrity_failure());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    OutboxLeaseToken::new(&bytes).map_err(|_| integrity_failure())?;
    Ok(())
}

fn require_all_null<const N: usize>(values: [&SqlValue; N]) -> Result<(), StorageError> {
    if values.iter().any(|value| !matches!(value, SqlValue::Null)) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_null(value: &SqlValue) -> Result<(), StorageError> {
    if !matches!(value, SqlValue::Null) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_timestamp(value: &SqlValue) -> Result<(), StorageError> {
    decode_timestamp(value).map(|_| ())
}

fn required_text(value: &SqlValue) -> Result<&str, StorageError> {
    match value {
        SqlValue::Text(value) if !value.is_empty() => Ok(value),
        _ => Err(integrity_failure()),
    }
}

fn decode_timestamp(value: &SqlValue) -> Result<i64, StorageError> {
    UtcTimestampMicros::try_from_sql_value(value)
        .map_err(|_| integrity_failure())
        .map(|timestamp| timestamp.epoch_micros())
}

fn decode_receipt_time(created: i64) -> Result<UtcTimestamp, StorageError> {
    if created.rem_euclid(MICROS_PER_SECOND) != 0 {
        return Err(integrity_failure());
    }
    Ok(UtcTimestamp::from_unix_seconds(
        created.div_euclid(MICROS_PER_SECOND),
    ))
}

fn decode_version(value: &str) -> Result<UserVersion, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let number = value.parse::<u64>().map_err(|_| integrity_failure())?;
    let version = UserVersion::new(number).map_err(|_| integrity_failure())?;
    if sql::encode_version(version) != value {
        return Err(integrity_failure());
    }
    Ok(version)
}

fn decode_recovery_state(value: &str) -> Result<DeletionRecoveryState, StorageError> {
    match value {
        "active" => Ok(DeletionRecoveryState::Active),
        "suspended" => Ok(DeletionRecoveryState::Suspended),
        _ => Err(integrity_failure()),
    }
}

fn decode_hex_payload(value: &str) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if value.is_empty()
        || value.len() > MAX_OUTBOX_PAYLOAD_BYTES * 2
        || !value.len().is_multiple_of(2)
    {
        return Err(integrity_failure());
    }
    let mut output = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(integrity_failure()),
    }
}

fn optional_i64(value: &SqlValue) -> Result<Option<i64>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Int64(value) => Ok(Some(*value)),
        _ => Err(integrity_failure()),
    }
}

fn optional_text(value: &SqlValue) -> Result<Option<&str>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(value) => Ok(Some(value)),
        _ => Err(integrity_failure()),
    }
}

fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity_failure()),
    }
}

fn validate_columns(
    columns: &[ColumnSchema],
    expected: &[(&str, SqlType)],
) -> Result<(), StorageError> {
    if columns.len() != expected.len() {
        return Err(integrity_failure());
    }
    for (column, (name, data_type)) in columns.iter().zip(expected) {
        if column.name() != *name || column.data_type() != data_type {
            return Err(integrity_failure());
        }
    }
    Ok(())
}

fn user_columns() -> [(&'static str, SqlType); 7] {
    [
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("version", SqlType::Text),
        ("state", SqlType::Text),
        ("deletion_requested_at", SqlType::Int64),
        ("deletion_not_before", SqlType::Int64),
        ("recovery_state", SqlType::Text),
    ]
}

fn lifecycle_columns() -> [(&'static str, SqlType); 9] {
    [
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
        ("request_id", SqlType::Text),
        ("deletion_not_before", SqlType::Int64),
        ("recovery_state", SqlType::Text),
    ]
}

fn outbox_columns() -> [(&'static str, SqlType); 14] {
    [
        ("tenant_id", SqlType::Text),
        ("event_id", SqlType::Text),
        ("topic", SqlType::Text),
        ("idempotency_key", SqlType::Text),
        ("payload_hex", SqlType::Text),
        ("created_at", SqlType::Timestamp),
        ("available_at", SqlType::Timestamp),
        ("attempt", SqlType::Int64),
        ("state", SqlType::Text),
        ("lease_token", SqlType::Text),
        ("lease_worker", SqlType::Text),
        ("lease_expires_at", SqlType::Timestamp),
        ("delivered_at", SqlType::Timestamp),
        ("failed_at", SqlType::Timestamp),
    ]
}

//! Transactional outbox persistence on one serialized RNMDB session.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::{
    StorageError, StorageErrorCode, TransactionAccess, TransactionPort,
};
use ariadnion_storage_outbox::{
    EnqueueStatus, NewOutboxMessage, OutboxEventId, OutboxLease, OutboxLeaseRequest,
    OutboxLeaseToken, OutboxMessage, OutboxPayload, OutboxPort, OutboxTopic,
};
use hmac::{Hmac, Mac};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::session::map_rnmdb_error;
use crate::{RnmdbSessionOwner, UtcTimestampMicros};

const OUTBOX_TABLE: &str = "platform_outbox";
const CLAIM_PROJECTION: &str = "tenant_id, event_id, topic, payload_hex, created_at, attempt";
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_RENDERED_SQL_BYTES: usize = 2_100_000;
const LEASE_DOMAIN: &[u8] = b"ariadnion-outbox-lease-v1";

type HmacSha256 = Hmac<Sha256>;

/// Secret key material used to derive unguessable outbox lease capabilities.
pub struct OutboxLeaseKeyMaterial {
    bytes: [u8; 32],
}

impl OutboxLeaseKeyMaterial {
    /// Takes ownership of exactly 32 secret bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Debug for OutboxLeaseKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OutboxLeaseKeyMaterial(<redacted>)")
    }
}

impl Zeroize for OutboxLeaseKeyMaterial {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for OutboxLeaseKeyMaterial {}

impl Drop for OutboxLeaseKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Persists and settles tenant-scoped outbox events in caller transactions.
pub struct RnmdbOutboxRepository {
    session: Arc<RnmdbSessionOwner>,
    lease_key: OutboxLeaseKeyMaterial,
}

impl RnmdbOutboxRepository {
    /// Creates a repository bound to one session and one lease-key generation.
    #[must_use]
    pub const fn new(session: Arc<RnmdbSessionOwner>, lease_key: OutboxLeaseKeyMaterial) -> Self {
        Self { session, lease_key }
    }

    /// Returns the serialized session used by this repository.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }

    fn settle(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        action: SettlementAction,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let tenant = authenticated_tenant(context)?;
        validate_write_transaction(&self.session, transaction)?;
        self.session.with_storage_session(context, |session| {
            require_active_transaction(session)?;
            let sql = settlement_sql(tenant, token, action)?;
            require_settled(execute(session, &sql)?)
        })
    }
}

impl OutboxPort for RnmdbOutboxRepository {
    fn enqueue(
        &self,
        transaction: &mut dyn TransactionPort,
        message: NewOutboxMessage,
        context: &RequestContext,
    ) -> Result<EnqueueStatus, StorageError> {
        let tenant = authenticated_tenant(context)?;
        validate_write_transaction(&self.session, transaction)?;
        if message.tenant_id() != tenant {
            return Err(integrity_failure());
        }
        self.session.with_storage_session(context, |session| {
            require_active_transaction(session)?;
            enqueue_message(session, tenant, &message)
        })
    }

    fn claim(
        &self,
        transaction: &mut dyn TransactionPort,
        request: &OutboxLeaseRequest,
        now: SystemTime,
        context: &RequestContext,
    ) -> Result<Vec<OutboxLease>, StorageError> {
        let tenant = authenticated_tenant(context)?;
        validate_write_transaction(&self.session, transaction)?;
        let expires_at = request.expires_at(now)?;
        self.session.with_storage_session(context, |session| {
            require_active_transaction(session)?;
            claim_messages(session, tenant, request, now, expires_at, &self.lease_key)
        })
    }

    fn mark_delivered(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        delivered_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.settle(
            transaction,
            token,
            SettlementAction::Delivered(delivered_at),
            context,
        )
    }

    fn release_for_retry(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        available_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.settle(
            transaction,
            token,
            SettlementAction::Retry(available_at),
            context,
        )
    }

    fn dead_letter(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        failed_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.settle(
            transaction,
            token,
            SettlementAction::DeadLetter(failed_at),
            context,
        )
    }
}

#[derive(Clone, Copy)]
enum SettlementAction {
    Delivered(SystemTime),
    Retry(SystemTime),
    DeadLetter(SystemTime),
}

struct ClaimCandidate {
    event_id: OutboxEventId,
    topic: OutboxTopic,
    payload: OutboxPayload,
    created_at: SystemTime,
    attempt: NonZeroU32,
}

fn authenticated_tenant(context: &RequestContext) -> Result<&TenantId, StorageError> {
    context
        .principal()
        .map(|principal| principal.tenant_id())
        .ok_or_else(integrity_failure)
}

fn validate_write_transaction(
    session: &RnmdbSessionOwner,
    transaction: &dyn TransactionPort,
) -> Result<(), StorageError> {
    let same_instance = transaction.instance() == session.instance();
    let same_scope = transaction.scope().same_scope(session.transaction_scope());
    if !same_instance || !same_scope {
        return Err(integrity_failure());
    }
    if transaction.options().access() != TransactionAccess::ReadWrite {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn require_active_transaction(session: &LocalSession) -> Result<(), StorageError> {
    if !session.in_transaction() {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn enqueue_message(
    session: &mut LocalSession,
    tenant: &TenantId,
    message: &NewOutboxMessage,
) -> Result<EnqueueStatus, StorageError> {
    let lookup = enqueue_lookup_sql(tenant, message)?;
    let collision = decode_enqueue_collision(execute(session, &lookup)?, message)?;
    match collision {
        EnqueueCollision::None => insert_message(session, tenant, message),
        EnqueueCollision::Idempotent => Ok(EnqueueStatus::AlreadyExists),
        EnqueueCollision::Conflict => Err(StorageError::new(StorageErrorCode::Conflict)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnqueueCollision {
    None,
    Idempotent,
    Conflict,
}

fn insert_message(
    session: &mut LocalSession,
    tenant: &TenantId,
    message: &NewOutboxMessage,
) -> Result<EnqueueStatus, StorageError> {
    let insert = insert_sql(tenant, message)?;
    require_single_change(execute(session, &insert)?)?;
    Ok(EnqueueStatus::Inserted)
}

fn decode_enqueue_collision(
    output: CommandOutput,
    message: &NewOutboxMessage,
) -> Result<EnqueueCollision, StorageError> {
    let batch = rows(output)?;
    validate_columns(
        batch.columns(),
        &[
            ("event_id", SqlType::Text),
            ("idempotency_key", SqlType::Text),
        ],
    )?;
    match batch.rows() {
        [] => Ok(EnqueueCollision::None),
        [row] if enqueue_row_matches(row, message) => Ok(EnqueueCollision::Idempotent),
        _ => Ok(EnqueueCollision::Conflict),
    }
}

fn enqueue_row_matches(row: &Row, message: &NewOutboxMessage) -> bool {
    matches!(
        row.values(),
        [SqlValue::Text(event), SqlValue::Text(key)]
            if event == message.event_id().as_str()
                && key == message.idempotency_key().as_str()
    )
}

fn claim_messages(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &OutboxLeaseRequest,
    now: SystemTime,
    expires_at: SystemTime,
    lease_key: &OutboxLeaseKeyMaterial,
) -> Result<Vec<OutboxLease>, StorageError> {
    let query = claim_sql(tenant, request, now)?;
    let candidates = decode_claim_candidates(execute(session, &query)?, tenant, request)?;
    let mut leases = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        leases.push(claim_candidate(
            session, tenant, request, candidate, now, expires_at, lease_key,
        )?);
    }
    Ok(leases)
}

fn claim_candidate(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &OutboxLeaseRequest,
    candidate: ClaimCandidate,
    now: SystemTime,
    expires_at: SystemTime,
    lease_key: &OutboxLeaseKeyMaterial,
) -> Result<OutboxLease, StorageError> {
    let token = derive_lease_token(tenant, request, &candidate, expires_at, lease_key)?;
    let update = claim_update_sql(tenant, request, &candidate, &token, now, expires_at)?;
    require_single_change(execute(session, &update)?)?;
    let message = OutboxMessage::from_persisted(
        tenant.clone(),
        candidate.event_id,
        candidate.topic,
        candidate.payload,
        candidate.created_at,
        candidate.attempt,
    );
    Ok(OutboxLease::new(
        message,
        token,
        request.worker_id().clone(),
        expires_at,
    ))
}

fn decode_claim_candidates(
    output: CommandOutput,
    tenant: &TenantId,
    request: &OutboxLeaseRequest,
) -> Result<Vec<ClaimCandidate>, StorageError> {
    let batch = rows(output)?;
    validate_claim_columns(batch.columns())?;
    if batch.rows().len() > request.limit().get() {
        return Err(integrity_failure());
    }
    batch
        .rows()
        .iter()
        .map(|row| decode_claim_row(row, tenant))
        .collect()
}

fn validate_claim_columns(columns: &[ColumnSchema]) -> Result<(), StorageError> {
    validate_columns(
        columns,
        &[
            ("tenant_id", SqlType::Text),
            ("event_id", SqlType::Text),
            ("topic", SqlType::Text),
            ("payload_hex", SqlType::Text),
            ("created_at", SqlType::Timestamp),
            ("attempt", SqlType::Int64),
        ],
    )
}

fn decode_claim_row(row: &Row, expected_tenant: &TenantId) -> Result<ClaimCandidate, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(event_id),
        SqlValue::Text(topic),
        SqlValue::Text(payload_hex),
        created_at,
        SqlValue::Int64(attempt),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    if tenant != expected_tenant.as_str() {
        return Err(integrity_failure());
    }
    Ok(ClaimCandidate {
        event_id: OutboxEventId::parse(event_id).map_err(|_| integrity_failure())?,
        topic: OutboxTopic::parse(topic).map_err(|_| integrity_failure())?,
        payload: decode_payload(payload_hex)?,
        created_at: decode_system_time(created_at)?,
        attempt: next_attempt(*attempt)?,
    })
}

fn next_attempt(current: i64) -> Result<NonZeroU32, StorageError> {
    let current = u32::try_from(current).map_err(|_| integrity_failure())?;
    current
        .checked_add(1)
        .and_then(NonZeroU32::new)
        .ok_or_else(integrity_failure)
}

fn derive_lease_token(
    tenant: &TenantId,
    request: &OutboxLeaseRequest,
    candidate: &ClaimCandidate,
    expires_at: SystemTime,
    key: &OutboxLeaseKeyMaterial,
) -> Result<OutboxLeaseToken, StorageError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| internal_error())?;
    mac.update(LEASE_DOMAIN);
    update_mac_field(&mut mac, tenant.as_str().as_bytes())?;
    update_mac_field(&mut mac, candidate.event_id.as_str().as_bytes())?;
    update_mac_field(&mut mac, request.worker_id().as_str().as_bytes())?;
    mac.update(&candidate.attempt.get().to_be_bytes());
    mac.update(&encode_system_time(expires_at)?.to_be_bytes());
    OutboxLeaseToken::new(&mac.finalize().into_bytes()).map_err(|_| internal_error())
}

fn update_mac_field(mac: &mut HmacSha256, value: &[u8]) -> Result<(), StorageError> {
    let length = u64::try_from(value.len()).map_err(|_| internal_error())?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn enqueue_lookup_sql(
    tenant: &TenantId,
    message: &NewOutboxMessage,
) -> Result<Zeroizing<String>, StorageError> {
    let mut sql = Zeroizing::new(format!(
        "SELECT event_id, idempotency_key FROM {OUTBOX_TABLE} WHERE tenant_id = "
    ));
    push_text_literal(&mut sql, tenant.as_str());
    sql.push_str(" AND (event_id = ");
    push_text_literal(&mut sql, message.event_id().as_str());
    sql.push_str(" OR idempotency_key = ");
    push_text_literal(&mut sql, message.idempotency_key().as_str());
    sql.push_str(");");
    ensure_sql_bound(sql)
}

fn insert_sql(
    tenant: &TenantId,
    message: &NewOutboxMessage,
) -> Result<Zeroizing<String>, StorageError> {
    let mut sql = Zeroizing::new(format!(
        "INSERT INTO {OUTBOX_TABLE} (tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state) VALUES ("
    ));
    push_text_literal(&mut sql, tenant.as_str());
    sql.push_str(", ");
    push_text_literal(&mut sql, message.event_id().as_str());
    sql.push_str(", ");
    push_text_literal(&mut sql, message.topic().as_str());
    sql.push_str(", ");
    push_text_literal(&mut sql, message.idempotency_key().as_str());
    sql.push_str(", ");
    push_hex_literal(&mut sql, message.payload().as_bytes());
    sql.push_str(", ");
    push_timestamp_literal(&mut sql, message.created_at())?;
    sql.push_str(", ");
    push_timestamp_literal(&mut sql, message.created_at())?;
    sql.push_str(", 0, 'pending');");
    ensure_sql_bound(sql)
}

fn claim_sql(
    tenant: &TenantId,
    request: &OutboxLeaseRequest,
    now: SystemTime,
) -> Result<Zeroizing<String>, StorageError> {
    let mut sql = Zeroizing::new(format!(
        "SELECT {CLAIM_PROJECTION} FROM {OUTBOX_TABLE} WHERE tenant_id = "
    ));
    push_text_literal(&mut sql, tenant.as_str());
    sql.push_str(" AND ((state = 'pending' AND available_at <= ");
    push_timestamp_literal(&mut sql, now)?;
    sql.push_str(") OR (state = 'leased' AND lease_expires_at <= ");
    push_timestamp_literal(&mut sql, now)?;
    sql.push_str(")) ORDER BY created_at, event_id LIMIT ");
    sql.push_str(&request.limit().get().to_string());
    sql.push(';');
    ensure_sql_bound(sql)
}

fn claim_update_sql(
    tenant: &TenantId,
    request: &OutboxLeaseRequest,
    candidate: &ClaimCandidate,
    token: &OutboxLeaseToken,
    now: SystemTime,
    expires_at: SystemTime,
) -> Result<Zeroizing<String>, StorageError> {
    let mut sql = Zeroizing::new(format!(
        "UPDATE {OUTBOX_TABLE} SET state = 'leased', lease_token = "
    ));
    push_hex_literal(&mut sql, token.as_bytes());
    sql.push_str(", lease_worker = ");
    push_text_literal(&mut sql, request.worker_id().as_str());
    sql.push_str(", lease_expires_at = ");
    push_timestamp_literal(&mut sql, expires_at)?;
    sql.push_str(", attempt = ");
    sql.push_str(&candidate.attempt.get().to_string());
    sql.push_str(" WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant.as_str());
    sql.push_str(" AND event_id = ");
    push_text_literal(&mut sql, candidate.event_id.as_str());
    sql.push_str(" AND ((state = 'pending' AND available_at <= ");
    push_timestamp_literal(&mut sql, now)?;
    sql.push_str(") OR (state = 'leased' AND lease_expires_at <= ");
    push_timestamp_literal(&mut sql, now)?;
    sql.push_str("));");
    ensure_sql_bound(sql)
}

fn settlement_sql(
    tenant: &TenantId,
    token: &OutboxLeaseToken,
    action: SettlementAction,
) -> Result<Zeroizing<String>, StorageError> {
    let mut sql = Zeroizing::new(format!("UPDATE {OUTBOX_TABLE} SET "));
    push_settlement_assignment(&mut sql, action)?;
    sql.push_str(
        ", lease_token = NULL, lease_worker = NULL, lease_expires_at = NULL WHERE tenant_id = ",
    );
    push_text_literal(&mut sql, tenant.as_str());
    sql.push_str(" AND lease_token = ");
    push_hex_literal(&mut sql, token.as_bytes());
    sql.push_str(" AND state = 'leased';");
    ensure_sql_bound(sql)
}

fn push_settlement_assignment(
    sql: &mut String,
    action: SettlementAction,
) -> Result<(), StorageError> {
    match action {
        SettlementAction::Delivered(at) => {
            sql.push_str("state = 'delivered', delivered_at = ");
            push_timestamp_literal(sql, at)
        }
        SettlementAction::Retry(at) => {
            sql.push_str("state = 'pending', available_at = ");
            push_timestamp_literal(sql, at)
        }
        SettlementAction::DeadLetter(at) => {
            sql.push_str("state = 'dead', failed_at = ");
            push_timestamp_literal(sql, at)
        }
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

fn push_hex_literal(sql: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    sql.push('\'');
    for byte in bytes {
        sql.push(char::from(HEX[usize::from(byte >> 4)]));
        sql.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    sql.push('\'');
}

fn push_timestamp_literal(sql: &mut String, value: SystemTime) -> Result<(), StorageError> {
    let timestamp = UtcTimestampMicros::new(encode_system_time(value)?)?
        .to_sql_timestamp()
        .to_rfc3339_string();
    sql.push_str("CAST(");
    push_text_literal(sql, &timestamp);
    sql.push_str(" AS TIMESTAMP)");
    Ok(())
}

fn ensure_sql_bound(sql: Zeroizing<String>) -> Result<Zeroizing<String>, StorageError> {
    if sql.len() > MAX_RENDERED_SQL_BYTES {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(sql)
}

fn encode_system_time(value: SystemTime) -> Result<i64, StorageError> {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration_to_i64_micros(duration),
        Err(error) => duration_to_i64_micros(error.duration())?
            .checked_neg()
            .ok_or_else(invalid_argument),
    }
}

fn duration_to_i64_micros(duration: Duration) -> Result<i64, StorageError> {
    i64::try_from(duration.as_micros()).map_err(|_| invalid_argument())
}

fn decode_system_time(value: &SqlValue) -> Result<SystemTime, StorageError> {
    let micros = UtcTimestampMicros::try_from_sql_value(value)
        .map_err(|_| integrity_failure())?
        .epoch_micros();
    let value = if micros >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_micros(micros.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_micros(micros.unsigned_abs()))
    };
    value.ok_or_else(integrity_failure)
}

fn decode_payload(value: &str) -> Result<OutboxPayload, StorageError> {
    if value.is_empty() || value.len() > MAX_PAYLOAD_BYTES * 2 || !value.len().is_multiple_of(2) {
        return Err(integrity_failure());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    OutboxPayload::new(&bytes).map_err(|_| integrity_failure())
}

fn decode_hex_nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
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

fn execute(session: &mut LocalSession, sql: &str) -> Result<CommandOutput, StorageError> {
    session.execute(sql).map_err(map_rnmdb_error)
}

fn require_single_change(output: CommandOutput) -> Result<(), StorageError> {
    if output != CommandOutput::RowsAffected(1) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_settled(output: CommandOutput) -> Result<(), StorageError> {
    match output {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::NotFound)),
        _ => Err(integrity_failure()),
    }
}

const fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn internal_error() -> StorageError {
    StorageError::new(StorageErrorCode::Internal)
}

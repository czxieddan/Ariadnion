//! Deterministic audit and outbox evidence for API-key lifecycle transitions.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_audit_domain::{
    AuditEventBinding, AuditEventContent, AuditEventId, AuditEventKind, AuditEventRequest,
    AuditPayloadDigest, AuditSequence, AuditSubject, AuditSubjectDigest, AuditSubjectKind,
    build_audit_event,
};
use ariadnion_auth_api_key::{ApiKey, ApiKeyEventKind};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_storage_outbox::{
    EnqueueStatus, NewOutboxMessage, OutboxEventId, OutboxIdempotencyKey, OutboxLeaseToken,
    OutboxPayload, OutboxTopic, OutboxWorkerId,
};
use ariadnion_user_domain::UtcTimestamp;
use hmac::{Hmac, Mac};
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{CommitRequest, authenticated_principal, integrity_failure};
use crate::AuditSubjectKeyMaterial;
use crate::UtcTimestampMicros;
use crate::audit_repository::{
    append_in_transaction, load_durable_event_with_head, load_event_by_id, load_head_from_session,
};
use crate::outbox::enqueue_message;

const SUBJECT_DOMAIN: &[u8] = b"ariadnion.api-key.audit-subject.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"ariadnion.api-key.transition.identity.v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"ariadnion.api-key.snapshot.v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.api-key.transition.payload.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"ariadnion.api-key.audit-event-id.v1\0";
const OUTBOX_ID_DOMAIN: &[u8] = b"ariadnion.api-key.outbox-event-id.v1\0";
const OUTBOX_KEY_DOMAIN: &[u8] = b"ariadnion.api-key.outbox-idempotency.v1\0";
const OUTBOX_TOPIC: &str = "identity.api-key.lifecycle.v1";

type HmacSha256 = Hmac<Sha256>;

pub(super) fn persist_transition_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    let evidence = TransitionEvidence::new(request, key, committed_at)?;
    append_audit(session, request, &evidence)?;
    enqueue_outbox(session, request, &evidence)
}

pub(super) fn reconcile_transition_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<UtcTimestamp, StorageError> {
    let identity = reconciliation_identity(request)?;
    let outbox = load_outbox(session, request, &identity.outbox_id, &identity.outbox_key)?;
    let evidence = TransitionEvidence::new(request, key, outbox.committed_at)?;
    validate_reconciled_evidence(&evidence, &outbox, &identity)?;
    reconcile_audit(session, &evidence, request.context)?;
    Ok(outbox.committed_at)
}

struct ReconciliationIdentity {
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
}

fn reconciliation_identity(
    request: &CommitRequest<'_>,
) -> Result<ReconciliationIdentity, StorageError> {
    let canonical = canonical_identity(request)?;
    Ok(ReconciliationIdentity {
        audit_id: derive_audit_id(&canonical)?,
        outbox_id: derive_outbox_id(&canonical)?,
        outbox_key: derive_outbox_key(&canonical)?,
    })
}

fn validate_reconciled_evidence(
    evidence: &TransitionEvidence,
    outbox: &PersistedOutbox,
    identity: &ReconciliationIdentity,
) -> Result<(), StorageError> {
    let matches = evidence.audit_id == identity.audit_id
        && evidence.payload.as_slice() == outbox.payload.as_slice();
    if matches {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn reconcile_audit(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
    context: &ariadnion_core::RequestContext,
) -> Result<(), StorageError> {
    let (persisted, _) =
        load_durable_event_with_head(session, &evidence.tenant, &evidence.audit_id, context)
            .map_err(map_reconcile_error)?;
    let expected =
        evidence.audit_event_at(persisted.sequence(), persisted.previous_chain_digest())?;
    if persisted == expected {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn append_audit(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    let head = load_head_from_session(session, request.tenant_id)?;
    let event = evidence.audit_event(&head)?;
    if load_event_by_id(session, request.tenant_id, event.id())?.is_some() {
        return Err(integrity_failure());
    }
    append_in_transaction(
        session,
        authenticated_principal(request.context)?,
        &head,
        &event,
    )
    .map(|_| ())
}

fn enqueue_outbox(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    match enqueue_message(session, request.tenant_id, &evidence.outbox_message()?) {
        Ok(EnqueueStatus::Inserted) => Ok(()),
        Ok(EnqueueStatus::AlreadyExists) => Err(integrity_failure()),
        Err(error) => Err(map_fresh_collision(error)),
    }
}

struct TransitionEvidence {
    tenant: ariadnion_core::TenantId,
    actor: ariadnion_core::PrincipalId,
    event_kind: ApiKeyEventKind,
    occurred_at: UtcTimestamp,
    subject: AuditSubjectDigest,
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
    payload: Zeroizing<Vec<u8>>,
    committed_at: UtcTimestamp,
}

impl TransitionEvidence {
    fn new(
        request: &CommitRequest<'_>,
        key: &AuditSubjectKeyMaterial,
        committed_at: UtcTimestamp,
    ) -> Result<Self, StorageError> {
        let canonical = canonical_identity(request)?;
        let event = request.transition.event();
        Ok(Self {
            tenant: request.tenant_id.clone(),
            actor: event.actor().clone(),
            event_kind: event.kind(),
            occurred_at: event.occurred_at(),
            subject: subject_digest(request, key)?,
            audit_id: derive_audit_id(&canonical)?,
            outbox_id: derive_outbox_id(&canonical)?,
            outbox_key: derive_outbox_key(&canonical)?,
            payload: canonical_payload(&canonical, committed_at)?,
            committed_at,
        })
    }

    fn audit_event(
        &self,
        head: &ariadnion_audit_store::AuditChainHead,
    ) -> Result<ariadnion_audit_domain::AuditEvent, StorageError> {
        self.audit_event_at(next_sequence(head)?, head.chain_digest())
    }

    fn audit_event_at(
        &self,
        sequence: AuditSequence,
        previous: Option<ariadnion_audit_domain::AuditChainDigest>,
    ) -> Result<ariadnion_audit_domain::AuditEvent, StorageError> {
        let (kind, reason) = audit_descriptor(self.event_kind)?;
        let binding = AuditEventBinding::new(
            self.audit_id.clone(),
            self.tenant.clone(),
            self.actor.clone(),
            self.occurred_at,
            sequence,
        );
        let content = AuditEventContent::new(
            kind,
            AuditSubject::from_digest(AuditSubjectKind::ApiKey, self.subject),
            reason,
            AuditPayloadDigest::from_payload(&self.payload).map_err(|_| integrity_failure())?,
            previous,
        )
        .map_err(|_| integrity_failure())?;
        build_audit_event(AuditEventRequest::new(binding, content)).map_err(|_| integrity_failure())
    }

    fn outbox_message(&self) -> Result<NewOutboxMessage, StorageError> {
        Ok(NewOutboxMessage::new(
            self.tenant.clone(),
            self.outbox_id.clone(),
            OutboxTopic::parse(OUTBOX_TOPIC).map_err(|_| integrity_failure())?,
            self.outbox_key.clone(),
            OutboxPayload::new(&self.payload).map_err(|_| integrity_failure())?,
            system_time(self.committed_at)?,
        ))
    }
}

struct PersistedOutbox {
    committed_at: UtcTimestamp,
    payload: Zeroizing<Vec<u8>>,
}

fn load_outbox(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    event_id: &OutboxEventId,
    key: &OutboxIdempotencyKey,
) -> Result<PersistedOutbox, StorageError> {
    let output =
        super::sql::load_outbox(session, request.tenant_id, event_id.as_str(), key.as_str())?;
    let batch = rows(output)?;
    validate_columns(batch.columns(), &outbox_columns())?;
    let [row] = batch.rows() else {
        return Err(integrity_failure());
    };
    decode_outbox_row(row, request, event_id, key)
}

fn decode_outbox_row(
    row: &Row,
    request: &CommitRequest<'_>,
    expected_event: &OutboxEventId,
    expected_key: &OutboxIdempotencyKey,
) -> Result<PersistedOutbox, StorageError> {
    let fields = persisted_outbox_fields(row)?;
    let identity = PersistedOutboxIdentity {
        tenant: fields.tenant,
        event_id: fields.event_id,
        topic: fields.topic,
        key: fields.key,
    };
    validate_outbox_identity(&identity, request, expected_event, expected_key)?;
    let created = decode_timestamp(fields.created_at)?;
    let available = decode_timestamp(fields.available_at)?;
    validate_outbox_lifecycle(
        fields.attempt,
        fields.state,
        created,
        available,
        &[
            fields.lease_token,
            fields.lease_worker,
            fields.lease_expires_at,
            fields.delivered_at,
            fields.failed_at,
        ],
    )?;
    let committed_at = decode_receipt_time(created)?;
    let payload = decode_hex(fields.payload)?;
    Ok(PersistedOutbox {
        committed_at,
        payload,
    })
}

struct PersistedOutboxFields<'a> {
    tenant: &'a str,
    event_id: &'a str,
    topic: &'a str,
    key: &'a str,
    payload: &'a str,
    created_at: &'a SqlValue,
    available_at: &'a SqlValue,
    attempt: i64,
    state: &'a str,
    lease_token: &'a SqlValue,
    lease_worker: &'a SqlValue,
    lease_expires_at: &'a SqlValue,
    delivered_at: &'a SqlValue,
    failed_at: &'a SqlValue,
}

fn persisted_outbox_fields(row: &Row) -> Result<PersistedOutboxFields<'_>, StorageError> {
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
    Ok(PersistedOutboxFields {
        tenant,
        event_id,
        topic,
        key,
        payload,
        created_at,
        available_at,
        attempt: *attempt,
        state,
        lease_token,
        lease_worker,
        lease_expires_at,
        delivered_at,
        failed_at,
    })
}

struct PersistedOutboxIdentity<'a> {
    tenant: &'a str,
    event_id: &'a str,
    topic: &'a str,
    key: &'a str,
}

fn validate_outbox_identity(
    actual: &PersistedOutboxIdentity<'_>,
    request: &CommitRequest<'_>,
    event: &OutboxEventId,
    key: &OutboxIdempotencyKey,
) -> Result<(), StorageError> {
    let matches = actual.tenant == request.tenant_id.as_str()
        && actual.event_id == event.as_str()
        && actual.topic == OUTBOX_TOPIC
        && actual.key == key.as_str();
    matches.then_some(()).ok_or_else(integrity_failure)
}

fn validate_outbox_lifecycle(
    attempt: i64,
    state: &str,
    created: i64,
    available: i64,
    mutable: &[&SqlValue; 5],
) -> Result<(), StorageError> {
    match state {
        "pending" => validate_pending(attempt, created, available, mutable),
        "leased" => validate_leased(attempt, mutable),
        "delivered" => validate_terminal(attempt, mutable, true),
        "dead" => validate_terminal(attempt, mutable, false),
        _ => Err(integrity_failure()),
    }
}

fn validate_pending(
    attempt: i64,
    created: i64,
    available: i64,
    mutable: &[&SqlValue; 5],
) -> Result<(), StorageError> {
    if !valid_attempt(attempt, true) || (attempt == 0 && created != available) {
        return Err(integrity_failure());
    }
    require_all_null(mutable)
}

fn validate_leased(attempt: i64, mutable: &[&SqlValue; 5]) -> Result<(), StorageError> {
    if !valid_attempt(attempt, false) {
        return Err(integrity_failure());
    }
    decode_lease_token(mutable[0])?;
    let worker = required_text(mutable[1])?;
    OutboxWorkerId::parse(worker).map_err(|_| integrity_failure())?;
    decode_timestamp(mutable[2])?;
    require_all_null(&[mutable[3], mutable[4]])
}

fn validate_terminal(
    attempt: i64,
    mutable: &[&SqlValue; 5],
    delivered: bool,
) -> Result<(), StorageError> {
    if !valid_attempt(attempt, false) {
        return Err(integrity_failure());
    }
    require_all_null(&[mutable[0], mutable[1], mutable[2]])?;
    let terminal = if delivered {
        [mutable[3], mutable[4]]
    } else {
        [mutable[4], mutable[3]]
    };
    decode_timestamp(terminal[0])?;
    require_all_null(&[terminal[1]])
}

fn valid_attempt(attempt: i64, allow_zero: bool) -> bool {
    attempt >= 0 && u32::try_from(attempt).is_ok() && (allow_zero || attempt > 0)
}

fn require_all_null(values: &[&SqlValue]) -> Result<(), StorageError> {
    values
        .iter()
        .all(|value| matches!(value, SqlValue::Null))
        .then_some(())
        .ok_or_else(integrity_failure)
}

fn decode_lease_token(value: &SqlValue) -> Result<(), StorageError> {
    let bytes = decode_hex(required_text(value)?)?;
    OutboxLeaseToken::new(&bytes)
        .map(|_| ())
        .map_err(|_| integrity_failure())
}

fn required_text(value: &SqlValue) -> Result<&str, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(value),
        _ => Err(integrity_failure()),
    }
}

fn decode_timestamp(value: &SqlValue) -> Result<i64, StorageError> {
    UtcTimestampMicros::try_from_sql_value(value)
        .map(UtcTimestampMicros::epoch_micros)
        .map_err(|_| integrity_failure())
}

fn decode_receipt_time(micros: i64) -> Result<UtcTimestamp, StorageError> {
    if micros.rem_euclid(1_000_000) != 0 {
        return Err(integrity_failure());
    }
    Ok(UtcTimestamp::from_unix_seconds(
        micros.div_euclid(1_000_000),
    ))
}

fn decode_hex(value: &str) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if value.is_empty() || value.len() > 2 * 1024 * 1024 || !value.len().is_multiple_of(2) {
        return Err(integrity_failure());
    }
    let mut output = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        output.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(integrity_failure()),
    }
}

fn rows(output: rnmdb_cli::CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        rnmdb_cli::CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity_failure()),
    }
}

fn validate_columns(
    columns: &[ColumnSchema],
    expected: &[(&str, SqlType)],
) -> Result<(), StorageError> {
    let valid = columns.len() == expected.len()
        && columns.iter().zip(expected).all(|(column, expected)| {
            column.name() == expected.0 && column.data_type() == &expected.1
        });
    valid.then_some(()).ok_or_else(integrity_failure)
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

fn map_reconcile_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::ResourceExhausted
        | StorageErrorCode::Unavailable => error,
        _ => integrity_failure(),
    }
}

fn audit_descriptor(kind: ApiKeyEventKind) -> Result<(AuditEventKind, &'static str), StorageError> {
    match kind {
        ApiKeyEventKind::Issued => Ok((AuditEventKind::Issued, "API_KEY_ISSUED")),
        ApiKeyEventKind::Rotated => Ok((AuditEventKind::Rotated, "API_KEY_ROTATED")),
        ApiKeyEventKind::RotationCompleted => {
            Ok((AuditEventKind::Rotated, "API_KEY_ROTATION_COMPLETED"))
        }
        ApiKeyEventKind::Revoked => Ok((AuditEventKind::Revoked, "API_KEY_REVOKED")),
        ApiKeyEventKind::Expired => Ok((AuditEventKind::Expired, "API_KEY_EXPIRED")),
    }
}

fn canonical_identity(request: &CommitRequest<'_>) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(IDENTITY_DOMAIN.to_vec());
    push_identity_boundary(&mut output, request)?;
    push_event_identity(&mut output, request)?;
    push_field(&mut output, &snapshot_digest(request.transition.key())?)?;
    Ok(output)
}

fn push_identity_boundary(
    output: &mut Vec<u8>,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    push_text(output, request.tenant_id.as_str())?;
    push_text(output, request.user_id.as_str())?;
    push_text(output, request.transition.key().id().as_str())
}

fn push_event_identity(
    output: &mut Vec<u8>,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    push_u64(output, request.expected_previous_version.get())?;
    push_text(output, request.transition.event().actor().as_str())?;
    push_text(output, request.context.request_id().as_str())?;
    push_i64(
        output,
        request.transition.event().occurred_at().unix_seconds(),
    )?;
    push_text(output, event_kind_label(request.transition.event().kind()))
}

fn snapshot_digest(key: &ApiKey) -> Result<[u8; 32], StorageError> {
    let mut output = Zeroizing::new(SNAPSHOT_DOMAIN.to_vec());
    push_snapshot_identity(&mut output, key)?;
    push_snapshot_secrets(&mut output, key)?;
    push_snapshot_lifecycle(&mut output, key)?;
    push_scopes(&mut output, key)?;
    push_retired(&mut output, key)?;
    Ok(Sha256::digest(&output).into())
}

fn push_snapshot_identity(output: &mut Vec<u8>, key: &ApiKey) -> Result<(), StorageError> {
    push_text(output, key.tenant_id().as_str())?;
    push_text(output, key.user_id().as_str())?;
    push_text(output, key.id().as_str())?;
    push_text(output, key.prefix().as_str())
}

fn push_snapshot_secrets(output: &mut Vec<u8>, key: &ApiKey) -> Result<(), StorageError> {
    push_field(output, &key.current_secret().bytes())?;
    push_optional_digest(output, key.previous_secret())?;
    push_optional_time(output, key.rotation_started_at())?;
    push_optional_time(output, key.previous_secret_expires_at())
}

fn push_snapshot_lifecycle(output: &mut Vec<u8>, key: &ApiKey) -> Result<(), StorageError> {
    push_i64(output, key.issued_at().unix_seconds())?;
    push_optional_time(output, key.expires_at())?;
    push_u64(output, key.version().get())?;
    push_text(output, super::sql::state_label(key.state()))
}

fn push_scopes(output: &mut Vec<u8>, key: &ApiKey) -> Result<(), StorageError> {
    push_u64(
        output,
        u64::try_from(key.scopes().len()).map_err(|_| integrity_failure())?,
    )?;
    for scope in key.scopes() {
        push_text(output, scope.as_str())?;
    }
    Ok(())
}

fn push_retired(output: &mut Vec<u8>, key: &ApiKey) -> Result<(), StorageError> {
    push_u64(
        output,
        u64::try_from(key.retired_secrets().len()).map_err(|_| integrity_failure())?,
    )?;
    for digest in key.retired_secrets() {
        push_field(output, &digest.bytes())?;
    }
    Ok(())
}

fn canonical_payload(
    canonical: &[u8],
    committed_at: UtcTimestamp,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(PAYLOAD_DOMAIN.to_vec());
    push_field(&mut output, &Sha256::digest(canonical))?;
    push_i64(&mut output, committed_at.unix_seconds())?;
    Ok(output)
}

fn subject_digest(
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<AuditSubjectDigest, StorageError> {
    let mut material = Zeroizing::new(SUBJECT_DOMAIN.to_vec());
    push_text(&mut material, request.tenant_id.as_str())?;
    push_text(&mut material, request.user_id.as_str())?;
    push_text(&mut material, request.transition.key().id().as_str())?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| integrity_failure())?;
    mac.update(&material);
    Ok(AuditSubjectDigest::new(mac.finalize().into_bytes().into()))
}

fn derive_audit_id(canonical: &[u8]) -> Result<AuditEventId, StorageError> {
    let value = derived_id(AUDIT_ID_DOMAIN, "api-key-audit-v1-", canonical)?;
    AuditEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_id(canonical: &[u8]) -> Result<OutboxEventId, StorageError> {
    let value = derived_id(OUTBOX_ID_DOMAIN, "api-key-outbox-v1-", canonical)?;
    OutboxEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_key(canonical: &[u8]) -> Result<OutboxIdempotencyKey, StorageError> {
    let value = derived_id(OUTBOX_KEY_DOMAIN, "api-key-transition-v1-", canonical)?;
    OutboxIdempotencyKey::parse(&value).map_err(|_| integrity_failure())
}

fn derived_id(domain: &[u8], prefix: &str, canonical: &[u8]) -> Result<String, StorageError> {
    let mut material = Zeroizing::new(domain.to_vec());
    push_field(&mut material, canonical)?;
    Ok(format!("{prefix}{}", hex(&Sha256::digest(&material))))
}

fn next_sequence(
    head: &ariadnion_audit_store::AuditChainHead,
) -> Result<AuditSequence, StorageError> {
    match head.last_sequence() {
        Some(sequence) => sequence.next().map_err(|_| integrity_failure()),
        None => Ok(AuditSequence::initial()),
    }
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), StorageError> {
    let length = u64::try_from(value.len()).map_err(|_| integrity_failure())?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_text(output: &mut Vec<u8>, value: &str) -> Result<(), StorageError> {
    push_field(output, value.as_bytes())
}

fn push_u64(output: &mut Vec<u8>, value: u64) -> Result<(), StorageError> {
    push_field(output, &value.to_be_bytes())
}

fn push_i64(output: &mut Vec<u8>, value: i64) -> Result<(), StorageError> {
    push_field(output, &value.to_be_bytes())
}

fn push_optional_digest(
    output: &mut Vec<u8>,
    value: Option<ariadnion_auth_api_key::ApiKeySecretDigest>,
) -> Result<(), StorageError> {
    match value {
        Some(value) => {
            push_field(output, &[1])?;
            push_field(output, &value.bytes())
        }
        None => push_field(output, &[0]),
    }
}

fn push_optional_time(
    output: &mut Vec<u8>,
    value: Option<UtcTimestamp>,
) -> Result<(), StorageError> {
    match value {
        Some(value) => {
            push_field(output, &[1])?;
            push_i64(output, value.unix_seconds())
        }
        None => push_field(output, &[0]),
    }
}

const fn event_kind_label(kind: ApiKeyEventKind) -> &'static str {
    super::sql::event_kind_label(kind)
}

fn system_time(value: UtcTimestamp) -> Result<SystemTime, StorageError> {
    let seconds = value.unix_seconds();
    if seconds >= 0 {
        return UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds.unsigned_abs()))
            .ok_or_else(integrity_failure);
    }
    UNIX_EPOCH
        .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
        .ok_or_else(integrity_failure)
}

fn map_fresh_collision(error: StorageError) -> StorageError {
    if error.code() == StorageErrorCode::Conflict {
        integrity_failure()
    } else {
        error
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

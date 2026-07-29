// crates/optional/ariadnion-storage-rnmdb/src/password_repository/evidence.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Deterministic audit and outbox evidence for password-reset commits.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_audit_domain::{
    AuditChainDigest, AuditEventBinding, AuditEventContent, AuditEventId, AuditEventKind,
    AuditEventRequest, AuditPayloadDigest, AuditSequence, AuditSubject, AuditSubjectDigest,
    AuditSubjectKind, build_audit_event,
};
use ariadnion_auth_password::{
    PasswordHashRecordDigest, PasswordReset, PasswordResetEventKind, PasswordResetVersion,
};
use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_storage_outbox::{
    EnqueueStatus, NewOutboxMessage, OutboxEventId, OutboxIdempotencyKey, OutboxLeaseToken,
    OutboxPayload, OutboxTopic, OutboxWorkerId,
};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use hmac::{Hmac, Mac};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AuditSubjectKeyMaterial, CommitRequest, authenticated_principal, integrity_failure};
use crate::UtcTimestampMicros;
use crate::audit_repository::{
    append_in_transaction, load_durable_event_with_head, load_event_by_id, load_head_from_session,
};
use crate::outbox::enqueue_message;

const SUBJECT_DOMAIN: &[u8] = b"ariadnion.password-reset.audit-subject.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"ariadnion.password-reset.transition.identity.v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"ariadnion.password-reset.snapshot.v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.password-reset.transition.payload.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"ariadnion.password-reset.audit-event-id.v1\0";
const OUTBOX_ID_DOMAIN: &[u8] = b"ariadnion.password-reset.outbox-event-id.v1\0";
const OUTBOX_KEY_DOMAIN: &[u8] = b"ariadnion.password-reset.outbox-idempotency.v1\0";
const OUTBOX_TOPIC: &str = "identity.password-reset.lifecycle.v1";

type HmacSha256 = Hmac<Sha256>;

pub(super) fn persist_transition_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    let evidence =
        TransitionEvidence::new(EvidenceRecord::from_request(request), key, committed_at)?;
    append_audit(session, request, &evidence)?;
    enqueue_outbox(session, request, &evidence)
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

pub(super) fn reconcile_transition_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<UtcTimestamp, StorageError> {
    let identity = EvidenceIdentity::new(EvidenceRecord::from_request(request), key)?;
    let outbox = load_outbox(session, &identity)?;
    let evidence = TransitionEvidence::from_identity(identity, outbox.committed_at)?;
    if evidence.payload.as_slice() != outbox.payload.as_slice() {
        return Err(integrity_failure());
    }
    reconcile_audit(session, &evidence, request.context)?;
    Ok(outbox.committed_at)
}

fn reconcile_audit(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
    context: &ariadnion_core::RequestContext,
) -> Result<(), StorageError> {
    let result =
        load_durable_event_with_head(session, &evidence.tenant, &evidence.audit_id, context)
            .map_err(map_reconcile_error)?;
    let persisted = result.0;
    let expected =
        evidence.audit_event_at(persisted.sequence(), persisted.previous_chain_digest())?;
    if persisted == expected {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

struct EvidenceRecord {
    tenant: TenantId,
    user: UserId,
    reset: PasswordReset,
    expected_previous_version: PasswordResetVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    kind: PasswordResetEventKind,
    request_id: RequestId,
    event_hash_digest: Option<PasswordHashRecordDigest>,
    replacement: Option<ReplacementRecord>,
}

impl EvidenceRecord {
    fn from_request(request: &CommitRequest<'_>) -> Self {
        let transition = request.transition();
        let event = transition.event();
        Self {
            tenant: request.tenant_id.clone(),
            user: request.user_id.clone(),
            reset: transition.reset().clone(),
            expected_previous_version: request.expected_previous_reset_version,
            actor: event.actor().clone(),
            occurred_at: event.occurred_at(),
            kind: event.kind(),
            request_id: request.context.request_id().clone(),
            event_hash_digest: event.password_hash_digest(),
            replacement: request
                .commit
                .credential_replacement()
                .map(ReplacementRecord::from_replacement),
        }
    }
}

#[derive(Clone, Copy)]
struct ReplacementRecord {
    expected_version: u64,
    resulting_version: u64,
    hash_policy_version: u64,
    hash_digest: PasswordHashRecordDigest,
}

impl ReplacementRecord {
    fn from_replacement(
        replacement: &ariadnion_auth_password::PasswordCredentialReplacement,
    ) -> Self {
        Self {
            expected_version: replacement.expected_version().get(),
            resulting_version: replacement.resulting_version().get(),
            hash_policy_version: replacement.resulting_hash_policy_version().get(),
            hash_digest: PasswordHashRecordDigest::from_record(
                replacement.credential().hash_record(),
            ),
        }
    }
}

struct TransitionEvidence {
    tenant: TenantId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    kind: PasswordResetEventKind,
    subject: AuditSubjectDigest,
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
    payload: Zeroizing<Vec<u8>>,
    committed_at: UtcTimestamp,
}

struct EvidenceIdentity {
    record: EvidenceRecord,
    canonical: Zeroizing<Vec<u8>>,
    subject: AuditSubjectDigest,
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
}

impl EvidenceIdentity {
    fn new(record: EvidenceRecord, key: &AuditSubjectKeyMaterial) -> Result<Self, StorageError> {
        let canonical = canonical_identity(&record)?;
        Ok(Self {
            subject: subject_digest(&record, key)?,
            audit_id: derive_audit_id(&canonical)?,
            outbox_id: derive_outbox_id(&canonical)?,
            outbox_key: derive_outbox_key(&canonical)?,
            record,
            canonical,
        })
    }
}

impl TransitionEvidence {
    fn new(
        record: EvidenceRecord,
        key: &AuditSubjectKeyMaterial,
        committed_at: UtcTimestamp,
    ) -> Result<Self, StorageError> {
        Self::from_identity(EvidenceIdentity::new(record, key)?, committed_at)
    }

    fn from_identity(
        identity: EvidenceIdentity,
        committed_at: UtcTimestamp,
    ) -> Result<Self, StorageError> {
        Ok(Self {
            tenant: identity.record.tenant,
            actor: identity.record.actor,
            occurred_at: identity.record.occurred_at,
            kind: identity.record.kind,
            subject: identity.subject,
            audit_id: identity.audit_id,
            outbox_id: identity.outbox_id,
            outbox_key: identity.outbox_key,
            payload: canonical_payload(&identity.canonical, committed_at)?,
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
        previous: Option<AuditChainDigest>,
    ) -> Result<ariadnion_audit_domain::AuditEvent, StorageError> {
        let binding = AuditEventBinding::new(
            self.audit_id.clone(),
            self.tenant.clone(),
            self.actor.clone(),
            self.occurred_at,
            sequence,
        );
        let content = AuditEventContent::new(
            audit_event_kind(self.kind),
            AuditSubject::from_digest(AuditSubjectKind::PasswordReset, self.subject),
            self.kind.as_str(),
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

fn canonical_identity(record: &EvidenceRecord) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(IDENTITY_DOMAIN.to_vec());
    push_identity_boundary(&mut output, record)?;
    push_identity_transition(&mut output, record)?;
    push_field(&mut output, &snapshot_digest(&record.reset)?)?;
    push_replacement(&mut output, record.replacement)?;
    Ok(output)
}

fn push_identity_boundary(
    output: &mut Vec<u8>,
    record: &EvidenceRecord,
) -> Result<(), StorageError> {
    push_text(output, record.tenant.as_str())?;
    push_text(output, record.user.as_str())?;
    push_text(output, record.reset.id().as_str())
}

fn push_identity_transition(
    output: &mut Vec<u8>,
    record: &EvidenceRecord,
) -> Result<(), StorageError> {
    push_u64(output, record.expected_previous_version.get())?;
    push_u64(output, record.reset.version().get())?;
    push_text(output, record.actor.as_str())?;
    push_text(output, record.request_id.as_str())?;
    push_i64(output, record.occurred_at.unix_seconds())?;
    push_text(output, super::sql::event_kind_label(record.kind))?;
    push_optional_digest(output, record.event_hash_digest)
}

fn snapshot_digest(reset: &PasswordReset) -> Result<[u8; 32], StorageError> {
    let mut snapshot = Zeroizing::new(SNAPSHOT_DOMAIN.to_vec());
    push_snapshot_binding(&mut snapshot, reset)?;
    push_snapshot_lifecycle(&mut snapshot, reset)?;
    Ok(Sha256::digest(&snapshot).into())
}

fn push_snapshot_binding(
    snapshot: &mut Vec<u8>,
    reset: &PasswordReset,
) -> Result<(), StorageError> {
    push_text(snapshot, reset.tenant_id().as_str())?;
    push_text(snapshot, reset.user_id().as_str())?;
    push_text(snapshot, reset.id().as_str())?;
    push_field(snapshot, &reset.token_digest().bytes())?;
    push_u64(snapshot, reset.issued_credential_version().get())
}

fn push_snapshot_lifecycle(
    snapshot: &mut Vec<u8>,
    reset: &PasswordReset,
) -> Result<(), StorageError> {
    push_i64(snapshot, reset.issued_at().unix_seconds())?;
    push_i64(snapshot, reset.expires_at().unix_seconds())?;
    push_u64(snapshot, reset.version().get())?;
    push_text(snapshot, super::sql::purpose_label(reset.purpose()))?;
    push_text(snapshot, super::sql::state_label(reset.state()))?;
    push_optional_digest(snapshot, reset.password_hash_digest())
}

fn push_replacement(
    output: &mut Vec<u8>,
    replacement: Option<ReplacementRecord>,
) -> Result<(), StorageError> {
    let Some(replacement) = replacement else {
        return push_field(output, &[0]);
    };
    push_field(output, &[1])?;
    push_u64(output, replacement.expected_version)?;
    push_u64(output, replacement.resulting_version)?;
    push_u64(output, replacement.hash_policy_version)?;
    push_field(output, &replacement.hash_digest.bytes())
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
    record: &EvidenceRecord,
    key: &AuditSubjectKeyMaterial,
) -> Result<AuditSubjectDigest, StorageError> {
    let mut material = Zeroizing::new(SUBJECT_DOMAIN.to_vec());
    push_text(&mut material, record.tenant.as_str())?;
    push_text(&mut material, record.user.as_str())?;
    push_text(&mut material, record.reset.id().as_str())?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| integrity_failure())?;
    mac.update(&material);
    Ok(AuditSubjectDigest::new(mac.finalize().into_bytes().into()))
}

fn derive_audit_id(canonical: &[u8]) -> Result<AuditEventId, StorageError> {
    let value = derived_id(AUDIT_ID_DOMAIN, "password-reset-audit-v1-", canonical)?;
    AuditEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_id(canonical: &[u8]) -> Result<OutboxEventId, StorageError> {
    let value = derived_id(OUTBOX_ID_DOMAIN, "password-reset-outbox-v1-", canonical)?;
    OutboxEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_key(canonical: &[u8]) -> Result<OutboxIdempotencyKey, StorageError> {
    let value = derived_id(
        OUTBOX_KEY_DOMAIN,
        "password-reset-transition-v1-",
        canonical,
    )?;
    OutboxIdempotencyKey::parse(&value).map_err(|_| integrity_failure())
}

fn derived_id(domain: &[u8], prefix: &str, canonical: &[u8]) -> Result<String, StorageError> {
    let mut material = Zeroizing::new(domain.to_vec());
    push_field(&mut material, canonical)?;
    Ok(format!("{prefix}{}", hex(&Sha256::digest(&material))))
}

struct PersistedOutbox {
    committed_at: UtcTimestamp,
    payload: Zeroizing<Vec<u8>>,
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

fn load_outbox(
    session: &mut LocalSession,
    identity: &EvidenceIdentity,
) -> Result<PersistedOutbox, StorageError> {
    let output = super::sql::load_outbox(
        session,
        &identity.record.tenant,
        identity.outbox_id.as_str(),
        identity.outbox_key.as_str(),
    )?;
    let batch = rows(output)?;
    validate_columns(batch.columns(), &outbox_columns())?;
    let [row] = batch.rows() else {
        return Err(integrity_failure());
    };
    decode_outbox_row(row, identity)
}

fn decode_outbox_row(
    row: &Row,
    identity: &EvidenceIdentity,
) -> Result<PersistedOutbox, StorageError> {
    let fields = persisted_outbox_fields(row)?;
    validate_outbox_identity(
        fields.tenant,
        fields.event_id,
        fields.topic,
        fields.key,
        identity,
    )?;
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

fn validate_outbox_identity(
    tenant: &str,
    event_id: &str,
    topic: &str,
    key: &str,
    identity: &EvidenceIdentity,
) -> Result<(), StorageError> {
    let actual = (tenant, event_id, topic, key);
    let expected = (
        identity.record.tenant.as_str(),
        identity.outbox_id.as_str(),
        OUTBOX_TOPIC,
        identity.outbox_key.as_str(),
    );
    if actual == expected {
        Ok(())
    } else {
        Err(integrity_failure())
    }
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
    if values.iter().all(|value| matches!(value, SqlValue::Null)) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
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
    value: Option<PasswordHashRecordDigest>,
) -> Result<(), StorageError> {
    match value {
        Some(value) => {
            push_field(output, &[1])?;
            push_field(output, &value.bytes())
        }
        None => push_field(output, &[0]),
    }
}

const fn audit_event_kind(kind: PasswordResetEventKind) -> AuditEventKind {
    match kind {
        PasswordResetEventKind::Issued => AuditEventKind::Issued,
        PasswordResetEventKind::Consumed => AuditEventKind::Consumed,
        PasswordResetEventKind::Revoked => AuditEventKind::Revoked,
        PasswordResetEventKind::Expired => AuditEventKind::Expired,
    }
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

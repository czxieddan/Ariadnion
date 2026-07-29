// crates/optional/ariadnion-storage-rnmdb/src/organization_repository/evidence.rs - Rust source for Ariadnion.
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
//! Deterministic audit and outbox evidence for organization transitions.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_audit_domain::{
    AuditEventBinding, AuditEventContent, AuditEventId, AuditEventKind, AuditEventRequest,
    AuditPayloadDigest, AuditSequence, AuditSubject, AuditSubjectDigest, AuditSubjectKind,
    build_audit_event,
};
use ariadnion_storage_domain::StorageError;
use ariadnion_storage_outbox::{
    EnqueueStatus, NewOutboxMessage, OutboxEventId, OutboxIdempotencyKey, OutboxLeaseToken,
    OutboxPayload, OutboxTopic, OutboxWorkerId,
};
use ariadnion_user_domain::UtcTimestamp;
use hmac::{Hmac, Mac};
use rnmdb_cli::CommandOutput;
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AuditSubjectKeyMaterial, CommitRequest, authenticated_principal, integrity_failure};
use crate::UtcTimestampMicros;
use crate::audit_repository::{append_in_transaction, load_event_by_id, load_head_from_session};
use crate::organization_repository::sql;
use crate::outbox::enqueue_message;

const SUBJECT_DOMAIN: &[u8] = b"ariadnion.organization.audit-subject.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"ariadnion.organization.transition.identity.v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.organization.transition.payload.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"ariadnion.organization.audit-event-id.v1\0";
const OUTBOX_ID_DOMAIN: &[u8] = b"ariadnion.organization.outbox-event-id.v1\0";
const OUTBOX_KEY_DOMAIN: &[u8] = b"ariadnion.organization.outbox-idempotency.v1\0";
const OUTBOX_TOPIC: &str = "identity.organization.lifecycle.v1";
const AUDIT_REASON: &str = "ORGANIZATION_TRANSITION";

type HmacSha256 = Hmac<Sha256>;

pub(super) fn persist_transition_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    let evidence = TransitionEvidence::new(request, key, committed_at)?;
    let head = load_head_from_session(session, request.tenant_id)?;
    let event = evidence.audit_event(&head)?;
    reject_existing_audit_event(session, request, &event)?;
    append_in_transaction(
        session,
        authenticated_principal(request.context)?,
        &head,
        &event,
    )?;
    persist_outbox(session, request, &evidence)
}

fn reject_existing_audit_event(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    event: &ariadnion_audit_domain::AuditEvent,
) -> Result<(), StorageError> {
    if load_event_by_id(session, request.tenant_id, event.id())?.is_some() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn persist_outbox(
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
    let identity = EvidenceIdentity::new(request, key)?;
    let outbox = load_outbox(session, &identity)?;
    let evidence = TransitionEvidence::from_identity(identity, outbox.committed_at)?;
    validate_outbox_payload(&outbox, &evidence)?;
    reconcile_chain_bound_audit(session, request, &evidence)?;
    Ok(outbox.committed_at)
}

fn validate_outbox_payload(
    outbox: &PersistedOutbox,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    if outbox.payload.as_slice() != evidence.payload.as_slice() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn reconcile_chain_bound_audit(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    let (persisted, _) = crate::audit_repository::load_durable_event_with_head(
        session,
        request.tenant_id,
        &evidence.audit_id,
        request.context,
    )?;
    let expected = evidence
        .audit_event_with_boundary(persisted.sequence(), persisted.previous_chain_digest())?;
    if persisted != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn verify_later_transition_evidence(
    session: &mut LocalSession,
    origin: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    later: Vec<(
        ariadnion_core::RequestId,
        ariadnion_organization::OrganizationEvent,
    )>,
) -> Result<(), StorageError> {
    let mut previous = origin.transition.organization().clone();
    for (request_id, event) in later {
        let transition = ariadnion_organization::replay_persisted_transition(&previous, &event)
            .map_err(|_| integrity_failure())?;
        let context = ariadnion_core::RequestContext::new(
            request_id,
            origin.context.trace_id().clone(),
            Some(ariadnion_core::PrincipalContext::new(
                origin.tenant_id.clone(),
                event.actor().clone(),
            )),
            origin.context.deadline(),
            origin.context.cancellation(),
        );
        let request = CommitRequest {
            tenant_id: origin.tenant_id,
            expected_previous_version: previous.version(),
            transition: &transition,
            context: &context,
        };
        let _ = reconcile_transition_evidence(session, &request, key)?;
        previous = transition.organization().clone();
    }
    Ok(())
}

struct TransitionEvidence {
    tenant: ariadnion_core::TenantId,
    actor: ariadnion_core::PrincipalId,
    occurred_at: UtcTimestamp,
    payload: Zeroizing<Vec<u8>>,
    subject: AuditSubjectDigest,
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
    committed_at: UtcTimestamp,
}

struct EvidenceIdentity {
    tenant: ariadnion_core::TenantId,
    actor: ariadnion_core::PrincipalId,
    occurred_at: UtcTimestamp,
    canonical: Zeroizing<Vec<u8>>,
    subject: AuditSubjectDigest,
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
}

impl EvidenceIdentity {
    fn new(
        request: &CommitRequest<'_>,
        key: &AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let organization = request.transition.organization();
        let event = request.transition.event();
        let canonical = canonical_identity(request)?;
        let identifiers = EvidenceIdentifiers::new(&canonical)?;
        Ok(Self {
            tenant: request.tenant_id.clone(),
            actor: event.actor().clone(),
            occurred_at: event.occurred_at(),
            subject: subject_digest(key, request.tenant_id, organization.id().as_str())?,
            audit_id: identifiers.audit_id,
            outbox_id: identifiers.outbox_id,
            outbox_key: identifiers.outbox_key,
            canonical,
        })
    }
}

struct EvidenceIdentifiers {
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
}

impl EvidenceIdentifiers {
    fn new(canonical: &[u8]) -> Result<Self, StorageError> {
        Ok(Self {
            audit_id: derive_audit_id(canonical)?,
            outbox_id: derive_outbox_id(canonical)?,
            outbox_key: derive_outbox_key(canonical)?,
        })
    }
}

fn derive_audit_id(canonical: &[u8]) -> Result<AuditEventId, StorageError> {
    let value = derived_id(AUDIT_ID_DOMAIN, "organization-audit-v1-", canonical)?;
    AuditEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_id(canonical: &[u8]) -> Result<OutboxEventId, StorageError> {
    let value = derived_id(OUTBOX_ID_DOMAIN, "organization-outbox-v1-", canonical)?;
    OutboxEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_key(canonical: &[u8]) -> Result<OutboxIdempotencyKey, StorageError> {
    let value = derived_id(OUTBOX_KEY_DOMAIN, "organization-transition-v1-", canonical)?;
    OutboxIdempotencyKey::parse(&value).map_err(|_| integrity_failure())
}

impl TransitionEvidence {
    fn new(
        request: &CommitRequest<'_>,
        key: &AuditSubjectKeyMaterial,
        committed_at: UtcTimestamp,
    ) -> Result<Self, StorageError> {
        let identity = EvidenceIdentity::new(request, key)?;
        Self::from_identity(identity, committed_at)
    }

    fn from_identity(
        identity: EvidenceIdentity,
        committed_at: UtcTimestamp,
    ) -> Result<Self, StorageError> {
        let payload = canonical_payload(&identity.canonical, committed_at)?;
        Ok(Self {
            tenant: identity.tenant,
            actor: identity.actor,
            occurred_at: identity.occurred_at,
            audit_id: identity.audit_id,
            outbox_id: identity.outbox_id,
            outbox_key: identity.outbox_key,
            payload,
            subject: identity.subject,
            committed_at,
        })
    }

    fn audit_event(
        &self,
        head: &ariadnion_audit_store::AuditChainHead,
    ) -> Result<ariadnion_audit_domain::AuditEvent, StorageError> {
        let sequence = next_sequence(head)?;
        let binding = AuditEventBinding::new(
            self.audit_id.clone(),
            self.tenant.clone(),
            self.actor.clone(),
            self.occurred_at,
            sequence,
        );
        let payload_digest =
            AuditPayloadDigest::from_payload(&self.payload).map_err(|_| integrity_failure())?;
        let content = AuditEventContent::new(
            AuditEventKind::Administered,
            AuditSubject::from_digest(AuditSubjectKind::Organization, self.subject),
            AUDIT_REASON,
            payload_digest,
            head.chain_digest(),
        )
        .map_err(|_| integrity_failure())?;
        build_audit_event(AuditEventRequest::new(binding, content)).map_err(|_| integrity_failure())
    }

    fn audit_event_with_boundary(
        &self,
        sequence: AuditSequence,
        previous: Option<ariadnion_audit_domain::AuditChainDigest>,
    ) -> Result<ariadnion_audit_domain::AuditEvent, StorageError> {
        let binding = AuditEventBinding::new(
            self.audit_id.clone(),
            self.tenant.clone(),
            self.actor.clone(),
            self.occurred_at,
            sequence,
        );
        let payload_digest =
            AuditPayloadDigest::from_payload(&self.payload).map_err(|_| integrity_failure())?;
        let content = AuditEventContent::new(
            AuditEventKind::Administered,
            AuditSubject::from_digest(AuditSubjectKind::Organization, self.subject),
            AUDIT_REASON,
            payload_digest,
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
    identity: &EvidenceIdentity,
) -> Result<PersistedOutbox, StorageError> {
    let batch = query_outbox(session, identity)?;
    let row = one_outbox_row(&batch)?;
    decode_outbox_row(row, identity)
}

fn query_outbox(
    session: &mut LocalSession,
    identity: &EvidenceIdentity,
) -> Result<VectorBatch, StorageError> {
    rows(sql::load_outbox(
        session,
        &identity.tenant,
        identity.outbox_id.as_str(),
        identity.outbox_key.as_str(),
    )?)
}

fn one_outbox_row(batch: &VectorBatch) -> Result<&Row, StorageError> {
    validate_columns(batch.columns(), &outbox_columns())?;
    let [row] = batch.rows() else {
        return Err(integrity_failure());
    };
    Ok(row)
}

fn decode_outbox_row(
    row: &Row,
    identity: &EvidenceIdentity,
) -> Result<PersistedOutbox, StorageError> {
    let fields = persisted_outbox_fields(row)?;
    let created = decode_timestamp(fields.created_at)?;
    let available = decode_timestamp(fields.available_at)?;
    validate_outbox_identity(
        fields.tenant,
        fields.event_id,
        fields.topic,
        fields.key,
        identity,
    )?;
    validate_outbox_lifecycle(
        fields.attempt,
        fields.state,
        created,
        available,
        &OutboxMutableFields {
            lease_token: fields.lease_token,
            lease_worker: fields.lease_worker,
            lease_expires_at: fields.lease_expires_at,
            delivered_at: fields.delivered_at,
            failed_at: fields.failed_at,
        },
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

fn validate_outbox_identity(
    tenant: &str,
    event_id: &str,
    topic: &str,
    key: &str,
    identity: &EvidenceIdentity,
) -> Result<(), StorageError> {
    let actual = (tenant, event_id, topic, key);
    let expected = (
        identity.tenant.as_str(),
        identity.outbox_id.as_str(),
        OUTBOX_TOPIC,
        identity.outbox_key.as_str(),
    );
    if actual != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

struct OutboxMutableFields<'a> {
    lease_token: &'a SqlValue,
    lease_worker: &'a SqlValue,
    lease_expires_at: &'a SqlValue,
    delivered_at: &'a SqlValue,
    failed_at: &'a SqlValue,
}

fn validate_outbox_lifecycle(
    attempt: i64,
    state: &str,
    created: i64,
    available: i64,
    mutable: &OutboxMutableFields<'_>,
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
    mutable: &OutboxMutableFields<'_>,
) -> Result<(), StorageError> {
    validate_attempt(attempt, true)?;
    if attempt == 0 && created != available {
        return Err(integrity_failure());
    }
    require_all_null(mutable_values(mutable))
}

fn validate_leased(attempt: i64, mutable: &OutboxMutableFields<'_>) -> Result<(), StorageError> {
    validate_attempt(attempt, false)?;
    decode_lease_token(mutable.lease_token)?;
    let worker = required_text(mutable.lease_worker)?;
    OutboxWorkerId::parse(worker).map_err(|_| integrity_failure())?;
    require_timestamp(mutable.lease_expires_at)?;
    require_all_null([mutable.delivered_at, mutable.failed_at])
}

fn validate_terminal(
    attempt: i64,
    mutable: &OutboxMutableFields<'_>,
    delivered: bool,
) -> Result<(), StorageError> {
    validate_attempt(attempt, false)?;
    require_all_null([
        mutable.lease_token,
        mutable.lease_worker,
        mutable.lease_expires_at,
    ])?;
    let terminal = if delivered {
        [mutable.delivered_at, mutable.failed_at]
    } else {
        [mutable.failed_at, mutable.delivered_at]
    };
    require_timestamp(terminal[0])?;
    require_null(terminal[1])
}

fn validate_attempt(attempt: i64, allow_zero: bool) -> Result<(), StorageError> {
    let valid = attempt >= 0 && u32::try_from(attempt).is_ok() && (allow_zero || attempt > 0);
    if valid {
        return Ok(());
    }
    Err(integrity_failure())
}

fn mutable_values<'a>(mutable: &'a OutboxMutableFields<'a>) -> [&'a SqlValue; 5] {
    [
        mutable.lease_token,
        mutable.lease_worker,
        mutable.lease_expires_at,
        mutable.delivered_at,
        mutable.failed_at,
    ]
}

fn require_all_null<const N: usize>(values: [&SqlValue; N]) -> Result<(), StorageError> {
    if values.iter().all(|value| matches!(value, SqlValue::Null)) {
        return Ok(());
    }
    Err(integrity_failure())
}

fn require_null(value: &SqlValue) -> Result<(), StorageError> {
    require_all_null([value])
}

fn require_timestamp(value: &SqlValue) -> Result<(), StorageError> {
    decode_timestamp(value).map(|_| ())
}

fn required_text(value: &SqlValue) -> Result<&str, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(value),
        _ => Err(integrity_failure()),
    }
}

fn decode_lease_token(value: &SqlValue) -> Result<(), StorageError> {
    let value = required_text(value)?;
    if value.len() > 512 || !value.len().is_multiple_of(2) {
        return Err(integrity_failure());
    }
    let bytes = decode_hex(value)?;
    OutboxLeaseToken::new(&bytes)
        .map(|_| ())
        .map_err(|_| integrity_failure())
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

fn decode_timestamp(value: &SqlValue) -> Result<i64, StorageError> {
    UtcTimestampMicros::try_from_sql_value(value)
        .map(|value| value.epoch_micros())
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
    if value.len() > 2 * 1024 * 1024 || !value.len().is_multiple_of(2) {
        return Err(integrity_failure());
    }
    let mut output = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output.push((high << 4) | low);
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

fn canonical_identity(request: &CommitRequest<'_>) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(IDENTITY_DOMAIN.to_vec());
    push_identity_boundary(&mut output, request)?;
    push_identity_transition(&mut output, request)?;
    push_optional_snapshot_digest(&mut output, request.transition.previous_snapshot())?;
    let snapshot = request.transition.organization().snapshot_state();
    push_snapshot_digest(&mut output, &snapshot)?;
    Ok(output)
}

fn push_identity_boundary(
    output: &mut Vec<u8>,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    push_text(output, request.tenant_id.as_str())?;
    push_text(output, request.transition.organization().id().as_str())
}

fn push_identity_transition(
    output: &mut Vec<u8>,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let organization = request.transition.organization();
    let event = request.transition.event();
    push_u64(output, request.expected_previous_version.get())?;
    push_u64(output, organization.version().get())?;
    push_text(output, event.actor().as_str())?;
    push_text(output, request.context.request_id().as_str())?;
    push_i64(output, event.occurred_at().unix_seconds())?;
    push_event_kind(output, event.kind())
}

fn push_optional_snapshot_digest(
    output: &mut Vec<u8>,
    snapshot: Option<&ariadnion_organization::OrganizationSnapshot>,
) -> Result<(), StorageError> {
    match snapshot {
        Some(snapshot) => {
            push_field(output, &[1])?;
            push_snapshot_digest(output, snapshot)
        }
        None => push_field(output, &[0]),
    }
}

fn push_snapshot_digest(
    output: &mut Vec<u8>,
    snapshot: &ariadnion_organization::OrganizationSnapshot,
) -> Result<(), StorageError> {
    let mut canonical = Zeroizing::new(Vec::new());
    push_snapshot(&mut canonical, snapshot)?;
    push_field(output, &Sha256::digest(&canonical))
}

fn push_event_kind(
    output: &mut Vec<u8>,
    kind: &ariadnion_organization::OrganizationEventKind,
) -> Result<(), StorageError> {
    use ariadnion_organization::OrganizationEventKind;
    match kind {
        OrganizationEventKind::Created {
            founder_membership_id,
            founder_user_id,
        } => push_created_event(
            output,
            founder_membership_id.as_str(),
            founder_user_id.as_str(),
        ),
        OrganizationEventKind::StateChanged { state } => push_state_event(output, *state),
        OrganizationEventKind::MembershipAdded {
            membership_id,
            user_id,
            kind,
            origin,
            expires_at,
        } => push_membership_added_event(
            output,
            membership_id.as_str(),
            user_id.as_str(),
            *kind,
            *origin,
            *expires_at,
        ),
        OrganizationEventKind::MembershipSuspended {
            membership_id,
            removed_team_assignments,
        } => push_membership_removal(
            output,
            "membership_suspended",
            membership_id.as_str(),
            *removed_team_assignments,
        ),
        OrganizationEventKind::MembershipActivated { .. }
        | OrganizationEventKind::MembershipLeft { .. }
        | OrganizationEventKind::TeamCreated { .. }
        | OrganizationEventKind::TeamAssigned { .. }
        | OrganizationEventKind::OwnershipTransferred { .. } => {
            push_remaining_event_kind(output, kind)
        }
    }
}

fn push_created_event(
    output: &mut Vec<u8>,
    founder_membership_id: &str,
    founder_user_id: &str,
) -> Result<(), StorageError> {
    push_text(output, "created")?;
    push_text(output, founder_membership_id)?;
    push_text(output, founder_user_id)
}

fn push_state_event(
    output: &mut Vec<u8>,
    state: ariadnion_organization::OrganizationState,
) -> Result<(), StorageError> {
    push_text(output, "state_changed")?;
    push_text(output, organization_state_label(state))
}

fn push_membership_added_event(
    output: &mut Vec<u8>,
    membership_id: &str,
    user_id: &str,
    kind: ariadnion_organization::MembershipKind,
    origin: ariadnion_organization::MembershipOrigin,
    expires_at: Option<UtcTimestamp>,
) -> Result<(), StorageError> {
    push_text(output, "membership_added")?;
    push_text(output, membership_id)?;
    push_text(output, user_id)?;
    push_text(output, membership_kind_label(kind))?;
    push_text(output, membership_origin_label(origin))?;
    push_optional_i64(output, expires_at.map(UtcTimestamp::unix_seconds))
}

fn push_remaining_event_kind(
    output: &mut Vec<u8>,
    kind: &ariadnion_organization::OrganizationEventKind,
) -> Result<(), StorageError> {
    use ariadnion_organization::OrganizationEventKind;
    match kind {
        OrganizationEventKind::MembershipActivated { membership_id } => {
            push_labeled_id_event(output, "membership_activated", membership_id.as_str())
        }
        OrganizationEventKind::MembershipLeft {
            membership_id,
            removed_team_assignments,
        } => push_membership_removal(
            output,
            "membership_left",
            membership_id.as_str(),
            *removed_team_assignments,
        ),
        OrganizationEventKind::TeamCreated { team_id } => {
            push_labeled_id_event(output, "team_created", team_id.as_str())
        }
        OrganizationEventKind::TeamAssigned {
            membership_id,
            team_id,
        } => push_team_assigned_event(output, membership_id.as_str(), team_id.as_str()),
        OrganizationEventKind::OwnershipTransferred {
            transfer_id,
            previous_owner_id,
            new_owner_id,
            approver,
        } => push_ownership_event(
            output,
            transfer_id.as_str(),
            previous_owner_id.as_str(),
            new_owner_id.as_str(),
            approver.as_str(),
        ),
        OrganizationEventKind::Created { .. }
        | OrganizationEventKind::StateChanged { .. }
        | OrganizationEventKind::MembershipAdded { .. }
        | OrganizationEventKind::MembershipSuspended { .. } => Err(integrity_failure()),
    }
}

fn push_labeled_id_event(output: &mut Vec<u8>, label: &str, id: &str) -> Result<(), StorageError> {
    push_text(output, label)?;
    push_text(output, id)
}

fn push_team_assigned_event(
    output: &mut Vec<u8>,
    membership_id: &str,
    team_id: &str,
) -> Result<(), StorageError> {
    push_text(output, "team_assigned")?;
    push_text(output, membership_id)?;
    push_text(output, team_id)
}

fn push_ownership_event(
    output: &mut Vec<u8>,
    transfer_id: &str,
    previous_owner_id: &str,
    new_owner_id: &str,
    approver: &str,
) -> Result<(), StorageError> {
    push_text(output, "ownership_transferred")?;
    push_text(output, transfer_id)?;
    push_text(output, previous_owner_id)?;
    push_text(output, new_owner_id)?;
    push_text(output, approver)
}

fn push_membership_removal(
    output: &mut Vec<u8>,
    label: &str,
    membership: &str,
    removed: usize,
) -> Result<(), StorageError> {
    push_text(output, label)?;
    push_text(output, membership)?;
    push_u64(
        output,
        u64::try_from(removed).map_err(|_| integrity_failure())?,
    )
}

const fn organization_state_label(
    value: ariadnion_organization::OrganizationState,
) -> &'static str {
    match value {
        ariadnion_organization::OrganizationState::Active => "active",
        ariadnion_organization::OrganizationState::Frozen => "frozen",
    }
}

const fn membership_kind_label(value: ariadnion_organization::MembershipKind) -> &'static str {
    match value {
        ariadnion_organization::MembershipKind::Owner => "owner",
        ariadnion_organization::MembershipKind::Member => "member",
    }
}

const fn membership_origin_label(value: ariadnion_organization::MembershipOrigin) -> &'static str {
    match value {
        ariadnion_organization::MembershipOrigin::Founder => "founder",
        ariadnion_organization::MembershipOrigin::Invitation => "invitation",
        ariadnion_organization::MembershipOrigin::Administrative => "administrative",
    }
}

const fn membership_state_label(value: ariadnion_organization::MembershipState) -> &'static str {
    match value {
        ariadnion_organization::MembershipState::Active => "active",
        ariadnion_organization::MembershipState::Suspended => "suspended",
        ariadnion_organization::MembershipState::Left => "left",
    }
}

fn push_snapshot(
    output: &mut Vec<u8>,
    snapshot: &ariadnion_organization::OrganizationSnapshot,
) -> Result<(), StorageError> {
    push_text(output, organization_state_label(snapshot.state()))?;
    push_snapshot_memberships(output, snapshot.memberships())?;
    push_snapshot_teams(output, snapshot.teams())
}

fn push_snapshot_memberships(
    output: &mut Vec<u8>,
    memberships: &[ariadnion_organization::MembershipSnapshot],
) -> Result<(), StorageError> {
    push_u64(
        output,
        u64::try_from(memberships.len()).map_err(|_| integrity_failure())?,
    )?;
    for membership in memberships {
        push_membership_snapshot(output, membership)?;
    }
    Ok(())
}

fn push_snapshot_teams(
    output: &mut Vec<u8>,
    teams: &[ariadnion_organization::TeamSnapshot],
) -> Result<(), StorageError> {
    push_u64(
        output,
        u64::try_from(teams.len()).map_err(|_| integrity_failure())?,
    )?;
    for team in teams {
        push_text(output, team.id().as_str())?;
    }
    Ok(())
}

fn push_membership_snapshot(
    output: &mut Vec<u8>,
    membership: &ariadnion_organization::MembershipSnapshot,
) -> Result<(), StorageError> {
    push_text(output, membership.id().as_str())?;
    push_text(output, membership.user_id().as_str())?;
    push_text(output, membership_kind_label(membership.kind()))?;
    push_text(output, membership_state_label(membership.state()))?;
    push_text(output, membership_origin_label(membership.origin()))?;
    push_optional_i64(
        output,
        membership.expires_at().map(UtcTimestamp::unix_seconds),
    )?;
    push_membership_assignments(output, membership.team_ids())
}

fn push_membership_assignments(
    output: &mut Vec<u8>,
    teams: &[ariadnion_organization::TeamId],
) -> Result<(), StorageError> {
    push_u64(
        output,
        u64::try_from(teams.len()).map_err(|_| integrity_failure())?,
    )?;
    for team in teams {
        push_text(output, team.as_str())?;
    }
    Ok(())
}

fn canonical_payload(
    identity: &[u8],
    committed_at: UtcTimestamp,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(PAYLOAD_DOMAIN.to_vec());
    push_field(&mut output, identity)?;
    push_i64(&mut output, committed_at.unix_seconds())?;
    Ok(output)
}

fn subject_digest(
    key: &AuditSubjectKeyMaterial,
    tenant: &ariadnion_core::TenantId,
    organization: &str,
) -> Result<AuditSubjectDigest, StorageError> {
    let mut material = Zeroizing::new(SUBJECT_DOMAIN.to_vec());
    push_text(&mut material, tenant.as_str())?;
    push_text(&mut material, organization)?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| integrity_failure())?;
    mac.update(&material);
    Ok(AuditSubjectDigest::new(mac.finalize().into_bytes().into()))
}

fn derived_id(domain: &[u8], prefix: &str, identity: &[u8]) -> Result<String, StorageError> {
    let mut material = Zeroizing::new(domain.to_vec());
    push_field(&mut material, identity)?;
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

fn push_optional_i64(output: &mut Vec<u8>, value: Option<i64>) -> Result<(), StorageError> {
    match value {
        Some(value) => push_i64(output, value),
        None => push_field(output, &[]),
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
    if error.code() == ariadnion_storage_domain::StorageErrorCode::Conflict {
        return integrity_failure();
    }
    error
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

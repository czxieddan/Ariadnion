// crates/optional/ariadnion-storage-rnmdb/src/principal_authenticator_repository/evidence.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Deterministic audit and outbox evidence for authenticator-link transitions.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_audit_domain::{
    AuditChainDigest, AuditEventBinding, AuditEventContent, AuditEventId, AuditEventKind,
    AuditEventRequest, AuditPayloadDigest, AuditSequence, AuditSubject, AuditSubjectDigest,
    AuditSubjectKind, build_audit_event,
};
use ariadnion_core::{PrincipalId, RequestContext, TenantId};
use ariadnion_principal_binding::{
    PrincipalAuthenticatorEvent, PrincipalAuthenticatorEventKind, PrincipalAuthenticatorId,
    PrincipalAuthenticatorKind, PrincipalAuthenticatorSnapshot, PrincipalAuthenticatorState,
    PrincipalAuthenticatorTransition,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_storage_outbox::{
    EnqueueStatus, NewOutboxMessage, OutboxEventId, OutboxIdempotencyKey, OutboxLeaseToken,
    OutboxPayload, OutboxTopic, OutboxWorkerId,
};
use ariadnion_user_domain::UtcTimestamp;
use hmac::{Hmac, Mac};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{authenticated_principal, integrity_failure};
use crate::UtcTimestampMicros;
use crate::audit_repository::{
    append_in_transaction, load_durable_event_with_head, load_event_by_id, load_head_from_session,
};
use crate::outbox::enqueue_message;
use crate::user_repository::AuditSubjectKeyMaterial;

const SUBJECT_DOMAIN: &[u8] = b"ariadnion.principal-authenticator.audit-subject.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"ariadnion.principal-authenticator.transition.identity.v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"ariadnion.principal-authenticator.snapshot.v1\0";
const EVENT_DOMAIN: &[u8] = b"ariadnion.principal-authenticator.event.v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.principal-authenticator.transition.payload.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"ariadnion.principal-authenticator.audit-event-id.v1\0";
const OUTBOX_ID_DOMAIN: &[u8] = b"ariadnion.principal-authenticator.outbox-event-id.v1\0";
const OUTBOX_KEY_DOMAIN: &[u8] = b"ariadnion.principal-authenticator.outbox-idempotency.v1\0";
const OUTBOX_TOPIC: &str = "identity.principal-authenticator.lifecycle.v1";

type HmacSha256 = Hmac<Sha256>;

pub(super) fn persist_transition_evidence(
    session: &mut LocalSession,
    transition: &PrincipalAuthenticatorTransition,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
    context: &RequestContext,
) -> Result<(), StorageError> {
    let evidence = TransitionEvidence::new(transition, key, committed_at)?;
    append_audit(session, &evidence, context)?;
    enqueue_outbox(session, &evidence)
}

pub(super) fn reconcile_transition_evidence(
    session: &mut LocalSession,
    transition: &PrincipalAuthenticatorTransition,
    key: &AuditSubjectKeyMaterial,
    context: &RequestContext,
) -> Result<ReconciledTransitionEvidence, StorageError> {
    let identity = EvidenceIdentity::new(transition, key)?;
    let outbox = load_outbox(session, &identity)?;
    let evidence = TransitionEvidence::from_identity(identity, outbox.committed_at)?;
    if evidence.payload.as_slice() != outbox.payload.as_slice() {
        return Err(integrity_failure());
    }
    let (audit_sequence, durable_head_sequence) = reconcile_audit(session, &evidence, context)?;
    Ok(ReconciledTransitionEvidence {
        committed_at: outbox.committed_at,
        audit_sequence,
        durable_head_sequence,
    })
}

pub(super) struct ReconciledTransitionEvidence {
    committed_at: UtcTimestamp,
    audit_sequence: AuditSequence,
    durable_head_sequence: AuditSequence,
}

impl ReconciledTransitionEvidence {
    pub(super) const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }

    pub(super) const fn audit_sequence(&self) -> AuditSequence {
        self.audit_sequence
    }

    pub(super) const fn durable_head_sequence(&self) -> AuditSequence {
        self.durable_head_sequence
    }
}

pub(super) fn validate_later_audit_order(
    evidence: &ReconciledTransitionEvidence,
    previous_sequence: AuditSequence,
    durable_head_sequence: AuditSequence,
) -> Result<(), StorageError> {
    let valid = evidence.audit_sequence() > previous_sequence
        && evidence.audit_sequence() <= durable_head_sequence;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn append_audit(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
    context: &RequestContext,
) -> Result<(), StorageError> {
    let head = load_head_from_session(session, &evidence.tenant)?;
    let event = evidence.audit_event(&head)?;
    if load_event_by_id(session, &evidence.tenant, event.id())?.is_some() {
        return Err(integrity_failure());
    }
    append_in_transaction(session, authenticated_principal(context)?, &head, &event).map(|_| ())
}

fn enqueue_outbox(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    match enqueue_message(session, &evidence.tenant, &evidence.outbox_message()?) {
        Ok(EnqueueStatus::Inserted) => Ok(()),
        Ok(EnqueueStatus::AlreadyExists) => Err(integrity_failure()),
        Err(error) if error.code() == StorageErrorCode::Conflict => Err(integrity_failure()),
        Err(error) => Err(error),
    }
}

fn reconcile_audit(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
    context: &RequestContext,
) -> Result<(AuditSequence, AuditSequence), StorageError> {
    let (persisted, head) =
        load_durable_event_with_head(session, &evidence.tenant, &evidence.audit_id, context)
            .map_err(map_reconcile_error)?;
    let expected =
        evidence.audit_event_at(persisted.sequence(), persisted.previous_chain_digest())?;
    let durable_head_sequence = head.last_sequence().ok_or_else(integrity_failure)?;
    if persisted != expected || persisted.sequence() > durable_head_sequence {
        return Err(integrity_failure());
    }
    Ok((persisted.sequence(), durable_head_sequence))
}

struct EvidenceIdentity {
    tenant: TenantId,
    authenticator_id: PrincipalAuthenticatorId,
    authenticator_kind: PrincipalAuthenticatorKind,
    version: u64,
    state: PrincipalAuthenticatorState,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    kind: PrincipalAuthenticatorEventKind,
    snapshot_digest: [u8; 32],
    event_digest: [u8; 32],
    subject: AuditSubjectDigest,
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
}

impl EvidenceIdentity {
    fn new(
        transition: &PrincipalAuthenticatorTransition,
        key: &AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let snapshot_digest = snapshot_digest(&transition.new_snapshot())?;
        let event_digest = event_digest(transition.event())?;
        let canonical = canonical_identity(transition, &snapshot_digest, &event_digest)?;
        let audit_id = derive_audit_id(&canonical)?;
        let outbox_id = derive_outbox_id(&canonical)?;
        let outbox_key = derive_outbox_key(&canonical)?;
        let event = transition.event();
        Ok(Self {
            tenant: transition.tenant_id().clone(),
            authenticator_id: transition.authenticator_id().clone(),
            authenticator_kind: transition.link().kind(),
            version: transition.link().version().get(),
            state: transition.link().state(),
            actor: event.actor().clone(),
            occurred_at: event.occurred_at(),
            kind: event.kind(),
            snapshot_digest,
            event_digest,
            subject: subject_digest(transition.authenticator_id(), key)?,
            audit_id,
            outbox_id,
            outbox_key,
        })
    }
}

struct TransitionEvidence {
    tenant: TenantId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    kind: PrincipalAuthenticatorEventKind,
    subject: AuditSubjectDigest,
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
    payload: Zeroizing<Vec<u8>>,
    committed_at: UtcTimestamp,
}

impl TransitionEvidence {
    fn new(
        transition: &PrincipalAuthenticatorTransition,
        key: &AuditSubjectKeyMaterial,
        committed_at: UtcTimestamp,
    ) -> Result<Self, StorageError> {
        let identity = EvidenceIdentity::new(transition, key)?;
        Self::from_identity(identity, committed_at)
    }

    fn from_identity(
        identity: EvidenceIdentity,
        committed_at: UtcTimestamp,
    ) -> Result<Self, StorageError> {
        let payload = canonical_payload(&identity, committed_at)?;
        Ok(Self {
            tenant: identity.tenant,
            actor: identity.actor,
            occurred_at: identity.occurred_at,
            kind: identity.kind,
            subject: identity.subject,
            audit_id: identity.audit_id,
            outbox_id: identity.outbox_id,
            outbox_key: identity.outbox_key,
            payload,
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
            AuditSubject::from_digest(AuditSubjectKind::PrincipalAuthenticator, self.subject),
            audit_reason(self.kind),
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

fn canonical_identity(
    transition: &PrincipalAuthenticatorTransition,
    snapshot_digest: &[u8; 32],
    event_digest: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(IDENTITY_DOMAIN.to_vec());
    push_identity_link_fields(&mut output, transition)?;
    push_identity_digests(&mut output, snapshot_digest, event_digest)?;
    Ok(output)
}

fn push_identity_link_fields(
    output: &mut Vec<u8>,
    transition: &PrincipalAuthenticatorTransition,
) -> Result<(), StorageError> {
    push_text(output, transition.tenant_id().as_str())?;
    push_text(output, transition.authenticator_id().as_str())?;
    push_text(output, transition.link().kind().as_str())?;
    push_u64(output, transition.link().version().get())?;
    push_text(output, state_label(transition.link().state()))?;
    push_text(
        output,
        super::sql::event_kind_label(transition.event().kind()),
    )
}

fn push_identity_digests(
    output: &mut Vec<u8>,
    snapshot_digest: &[u8; 32],
    event_digest: &[u8; 32],
) -> Result<(), StorageError> {
    push_field(output, snapshot_digest)?;
    push_field(output, event_digest)
}

fn snapshot_digest(snapshot: &PrincipalAuthenticatorSnapshot) -> Result<[u8; 32], StorageError> {
    let mut output = Zeroizing::new(SNAPSHOT_DOMAIN.to_vec());
    push_snapshot_identity(&mut output, snapshot)?;
    push_snapshot_lifecycle(&mut output, snapshot)?;
    Ok(Sha256::digest(&output).into())
}

fn push_snapshot_identity(
    output: &mut Vec<u8>,
    snapshot: &PrincipalAuthenticatorSnapshot,
) -> Result<(), StorageError> {
    push_text(output, snapshot.tenant_id().as_str())?;
    push_text(output, snapshot.authenticator_id().as_str())?;
    push_text(output, snapshot.authenticator_kind().as_str())?;
    push_text(output, snapshot.source_id().as_str())?;
    push_text(output, snapshot.principal_id().as_str())?;
    push_u64(output, snapshot.principal_binding_version().get())
}

fn push_snapshot_lifecycle(
    output: &mut Vec<u8>,
    snapshot: &PrincipalAuthenticatorSnapshot,
) -> Result<(), StorageError> {
    push_u64(output, snapshot.version().get())?;
    push_text(output, state_label(snapshot.state()))?;
    push_i64(output, snapshot.linked_at().unix_seconds())?;
    push_optional_i64(
        output,
        snapshot.revoked_at().map(|value| value.unix_seconds()),
    )
}

fn event_digest(event: &PrincipalAuthenticatorEvent) -> Result<[u8; 32], StorageError> {
    let mut output = Zeroizing::new(EVENT_DOMAIN.to_vec());
    push_event_identity(&mut output, event)?;
    push_event_lifecycle(&mut output, event)?;
    Ok(Sha256::digest(&output).into())
}

fn push_event_identity(
    output: &mut Vec<u8>,
    event: &PrincipalAuthenticatorEvent,
) -> Result<(), StorageError> {
    push_text(output, event.tenant_id().as_str())?;
    push_text(output, event.authenticator_id().as_str())?;
    push_text(output, event.authenticator_kind().as_str())?;
    push_field(output, event.source_commitment().as_bytes())?;
    push_text(output, event.principal_id().as_str())?;
    push_u64(output, event.principal_binding_version().get())
}

fn push_event_lifecycle(
    output: &mut Vec<u8>,
    event: &PrincipalAuthenticatorEvent,
) -> Result<(), StorageError> {
    push_u64(output, event.version().get())?;
    push_text(output, super::sql::event_kind_label(event.kind()))?;
    push_i64(output, event.occurred_at().unix_seconds())?;
    push_text(output, event.actor().as_str())?;
    push_text(output, event.request_id().as_str())
}

fn canonical_payload(
    identity: &EvidenceIdentity,
    committed_at: UtcTimestamp,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(PAYLOAD_DOMAIN.to_vec());
    push_payload_identity(&mut output, identity)?;
    push_payload_evidence(&mut output, identity, committed_at)?;
    Ok(output)
}

fn push_payload_identity(
    output: &mut Vec<u8>,
    identity: &EvidenceIdentity,
) -> Result<(), StorageError> {
    push_text(output, identity.authenticator_id.as_str())?;
    push_text(output, identity.authenticator_kind.as_str())?;
    push_u64(output, identity.version)?;
    push_text(output, state_label(identity.state))?;
    push_text(output, super::sql::event_kind_label(identity.kind))
}

fn push_payload_evidence(
    output: &mut Vec<u8>,
    identity: &EvidenceIdentity,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    push_field(output, &identity.snapshot_digest)?;
    push_field(output, &identity.event_digest)?;
    push_i64(output, committed_at.unix_seconds())
}

fn subject_digest(
    authenticator: &PrincipalAuthenticatorId,
    key: &AuditSubjectKeyMaterial,
) -> Result<AuditSubjectDigest, StorageError> {
    let mut material = Zeroizing::new(SUBJECT_DOMAIN.to_vec());
    push_text(&mut material, authenticator.as_str())?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| integrity_failure())?;
    mac.update(&material);
    Ok(AuditSubjectDigest::new(mac.finalize().into_bytes().into()))
}

fn derive_audit_id(canonical: &[u8]) -> Result<AuditEventId, StorageError> {
    let value = derived_id(
        AUDIT_ID_DOMAIN,
        "principal-authenticator-audit-v1-",
        canonical,
    )?;
    AuditEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_id(canonical: &[u8]) -> Result<OutboxEventId, StorageError> {
    let value = derived_id(
        OUTBOX_ID_DOMAIN,
        "principal-authenticator-outbox-v1-",
        canonical,
    )?;
    OutboxEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_key(canonical: &[u8]) -> Result<OutboxIdempotencyKey, StorageError> {
    let value = derived_id(
        OUTBOX_KEY_DOMAIN,
        "principal-authenticator-transition-v1-",
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

fn load_outbox(
    session: &mut LocalSession,
    identity: &EvidenceIdentity,
) -> Result<PersistedOutbox, StorageError> {
    let output = super::sql::load_outbox(
        session,
        &identity.tenant,
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
    validate_outbox_identity(&fields, identity)?;
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
    Ok(PersistedOutbox {
        committed_at: decode_receipt_time(created)?,
        payload: decode_hex(fields.payload)?,
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
    fields: &PersistedOutboxFields<'_>,
    identity: &EvidenceIdentity,
) -> Result<(), StorageError> {
    let actual = (fields.tenant, fields.event_id, fields.topic, fields.key);
    let expected = (
        identity.tenant.as_str(),
        identity.outbox_id.as_str(),
        OUTBOX_TOPIC,
        identity.outbox_key.as_str(),
    );
    (actual == expected)
        .then_some(())
        .ok_or_else(integrity_failure)
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
    OutboxWorkerId::parse(required_text(mutable[1])?).map_err(|_| integrity_failure())?;
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
        Some(value) => {
            push_field(output, &[1])?;
            push_i64(output, value)
        }
        None => push_field(output, &[0]),
    }
}

const fn state_label(state: PrincipalAuthenticatorState) -> &'static str {
    match state {
        PrincipalAuthenticatorState::Active => "active",
        PrincipalAuthenticatorState::Revoked => "revoked",
    }
}

const fn audit_event_kind(kind: PrincipalAuthenticatorEventKind) -> AuditEventKind {
    match kind {
        PrincipalAuthenticatorEventKind::Linked => AuditEventKind::Issued,
        PrincipalAuthenticatorEventKind::Revoked => AuditEventKind::Revoked,
    }
}

const fn audit_reason(kind: PrincipalAuthenticatorEventKind) -> &'static str {
    match kind {
        PrincipalAuthenticatorEventKind::Linked => "PRINCIPAL_AUTHENTICATOR_LINKED",
        PrincipalAuthenticatorEventKind::Revoked => "PRINCIPAL_AUTHENTICATOR_REVOKED",
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

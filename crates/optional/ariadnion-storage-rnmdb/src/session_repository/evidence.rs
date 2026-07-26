//! Deterministic audit and outbox evidence for browser session issuance.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_audit_domain::{
    AuditEventBinding, AuditEventContent, AuditEventId, AuditEventKind, AuditEventRequest,
    AuditPayloadDigest, AuditSequence, AuditSubject, AuditSubjectDigest, AuditSubjectKind,
    build_audit_event,
};
use ariadnion_auth_session::{SessionEventKind, SessionFamily, SessionSnapshot};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_storage_outbox::{
    EnqueueStatus, NewOutboxMessage, OutboxEventId, OutboxIdempotencyKey, OutboxPayload,
    OutboxTopic,
};
use ariadnion_user_domain::UtcTimestamp;
use hmac::{Hmac, Mac};
use rnmdb_cli::LocalSession;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{CommitRequest, authenticated_principal, integrity_failure};
use crate::AuditSubjectKeyMaterial;
use crate::audit_repository::{append_in_transaction, load_event_by_id, load_head_from_session};
use crate::outbox::enqueue_message;

const SUBJECT_DOMAIN: &[u8] = b"ariadnion.browser-session.audit-subject.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"ariadnion.browser-session.transition.identity.v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"ariadnion.browser-session.snapshot.v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.browser-session.transition.payload.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"ariadnion.browser-session.audit-event-id.v1\0";
const OUTBOX_ID_DOMAIN: &[u8] = b"ariadnion.browser-session.outbox-event-id.v1\0";
const OUTBOX_KEY_DOMAIN: &[u8] = b"ariadnion.browser-session.outbox-idempotency.v1\0";
const OUTBOX_TOPIC: &str = "identity.browser-session.lifecycle.v1";

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
    occurred_at: UtcTimestamp,
    kind: SessionEventKind,
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
            occurred_at: event.occurred_at(),
            kind: event.kind(),
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
        let binding = AuditEventBinding::new(
            self.audit_id.clone(),
            self.tenant.clone(),
            self.actor.clone(),
            self.occurred_at,
            next_sequence(head)?,
        );
        let content = AuditEventContent::new(
            audit_event_kind(self.kind),
            AuditSubject::from_digest(AuditSubjectKind::SessionFamily, self.subject),
            audit_reason(self.kind),
            AuditPayloadDigest::from_payload(&self.payload).map_err(|_| integrity_failure())?,
            head.chain_digest(),
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

fn canonical_identity(request: &CommitRequest<'_>) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let family = request.transition.family();
    let event = request.transition.event();
    let mut output = Zeroizing::new(IDENTITY_DOMAIN.to_vec());
    push_text(&mut output, request.tenant_id.as_str())?;
    push_text(&mut output, request.user_id.as_str())?;
    push_text(&mut output, family.id().as_str())?;
    push_u64(&mut output, request.expected_previous_version.get())?;
    push_u64(&mut output, family.version().get())?;
    push_text(&mut output, event.session_id().as_str())?;
    push_text(&mut output, event.actor().as_str())?;
    push_text(&mut output, request.context.request_id().as_str())?;
    push_i64(&mut output, event.occurred_at().unix_seconds())?;
    push_text(&mut output, super::sql::event_kind_label(event.kind()))?;
    push_field(&mut output, &snapshot_digest(family)?)?;
    Ok(output)
}

fn snapshot_digest(family: &SessionFamily) -> Result<[u8; 32], StorageError> {
    let snapshot = family.snapshot_state();
    let mut output = Zeroizing::new(SNAPSHOT_DOMAIN.to_vec());
    push_text(&mut output, snapshot.subject.tenant_id().as_str())?;
    push_text(&mut output, snapshot.subject.user_id().as_str())?;
    push_text(&mut output, snapshot.id.as_str())?;
    push_i64(&mut output, snapshot.issued_at.unix_seconds())?;
    push_i64(&mut output, snapshot.absolute_expires_at.unix_seconds())?;
    push_u64(&mut output, snapshot.version.get())?;
    push_text(&mut output, super::sql::family_state_label(snapshot.state))?;
    for leaf in snapshot
        .rotated
        .iter()
        .chain(std::iter::once(&snapshot.current))
    {
        push_leaf(&mut output, leaf)?;
    }
    Ok(Sha256::digest(&output).into())
}

fn push_leaf(output: &mut Vec<u8>, leaf: &SessionSnapshot) -> Result<(), StorageError> {
    push_text(output, leaf.id.as_str())?;
    push_field(output, &leaf.token_digest.bytes())?;
    push_i64(output, leaf.issued_at.unix_seconds())?;
    push_i64(output, leaf.last_seen_at.unix_seconds())?;
    push_i64(output, leaf.idle_expires_at.unix_seconds())?;
    push_u64(output, leaf.version.get())?;
    push_text(output, super::sql::session_state_label(leaf.state))?;
    push_optional_text(
        output,
        leaf.predecessor_id.as_ref().map(|value| value.as_str()),
    )
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
    push_text(&mut material, request.transition.family().id().as_str())?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| integrity_failure())?;
    mac.update(&material);
    Ok(AuditSubjectDigest::new(mac.finalize().into_bytes().into()))
}

fn derive_audit_id(canonical: &[u8]) -> Result<AuditEventId, StorageError> {
    let value = derived_id(AUDIT_ID_DOMAIN, "session-audit-v1-", canonical)?;
    AuditEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_id(canonical: &[u8]) -> Result<OutboxEventId, StorageError> {
    let value = derived_id(OUTBOX_ID_DOMAIN, "session-outbox-v1-", canonical)?;
    OutboxEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derive_outbox_key(canonical: &[u8]) -> Result<OutboxIdempotencyKey, StorageError> {
    let value = derived_id(OUTBOX_KEY_DOMAIN, "session-transition-v1-", canonical)?;
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

fn push_optional_text(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), StorageError> {
    match value {
        Some(value) => {
            push_field(output, &[1])?;
            push_text(output, value)
        }
        None => push_field(output, &[0]),
    }
}

const fn audit_event_kind(kind: SessionEventKind) -> AuditEventKind {
    match kind {
        SessionEventKind::Issued => AuditEventKind::Issued,
        SessionEventKind::Rotated => AuditEventKind::Rotated,
        SessionEventKind::ReuseRevoked => AuditEventKind::ReuseDetected,
        SessionEventKind::Revoked => AuditEventKind::Revoked,
        SessionEventKind::Expired => AuditEventKind::Expired,
    }
}

const fn audit_reason(kind: SessionEventKind) -> &'static str {
    match kind {
        SessionEventKind::Issued => "SESSION_ISSUED",
        SessionEventKind::Rotated => "SESSION_ROTATED",
        SessionEventKind::ReuseRevoked => "SESSION_REUSE_REVOKED",
        SessionEventKind::Revoked => "SESSION_REVOKED",
        SessionEventKind::Expired => "SESSION_EXPIRED",
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

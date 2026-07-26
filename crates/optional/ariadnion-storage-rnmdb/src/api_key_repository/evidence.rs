//! Deterministic audit and outbox evidence for API-key issuance.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_audit_domain::{
    AuditEventBinding, AuditEventContent, AuditEventId, AuditEventKind, AuditEventRequest,
    AuditPayloadDigest, AuditSequence, AuditSubject, AuditSubjectDigest, AuditSubjectKind,
    build_audit_event,
};
use ariadnion_auth_api_key::{ApiKey, ApiKeyEventKind};
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
            AuditEventKind::Issued,
            AuditSubject::from_digest(AuditSubjectKind::ApiKey, self.subject),
            "API_KEY_ISSUED",
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

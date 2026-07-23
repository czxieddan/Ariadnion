//! Canonical identities and payloads for one durable user transition.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_audit_domain::{
    AuditChainDigest, AuditEvent, AuditEventBinding, AuditEventContent, AuditEventId,
    AuditEventKind, AuditEventRequest, AuditPayloadDigest, AuditSequence, AuditSubject,
    AuditSubjectDigest, AuditSubjectKind, build_audit_event,
};
use ariadnion_audit_store::AuditChainHead;
use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_storage_domain::StorageError;
use ariadnion_storage_outbox::{
    NewOutboxMessage, OutboxEventId, OutboxIdempotencyKey, OutboxPayload, OutboxTopic,
};
use ariadnion_user_domain::{
    DeletionRecoveryState, UserId, UserLifecycleEvent, UserLifecycleEventKind, UserSnapshotState,
    UserVersion, UtcTimestamp,
};
use ariadnion_user_service::UserCommitReceipt;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AuditSubjectKeyMaterial, integrity_failure};

const SUBJECT_DOMAIN: &[u8] = b"ariadnion.user.audit-subject.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"ariadnion.user.transition.identity.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"ariadnion.user.audit-event-id.v1\0";
const OUTBOX_ID_DOMAIN: &[u8] = b"ariadnion.user.outbox-event-id.v1\0";
const OUTBOX_KEY_DOMAIN: &[u8] = b"ariadnion.user.outbox-idempotency.v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.user.transition.payload.v1\0";
const AUDIT_ID_PREFIX: &str = "user-audit-v1-";
const OUTBOX_ID_PREFIX: &str = "user-outbox-v1-";
const OUTBOX_KEY_PREFIX: &str = "user-transition-v1-";
const OUTBOX_TOPIC: &str = "identity.user.lifecycle.v1";
const AUDIT_REASON: &str = "USER_LIFECYCLE_TRANSITION";

type HmacSha256 = Hmac<Sha256>;

pub(super) struct TransitionIdentity {
    tenant_id: TenantId,
    user_id: ariadnion_user_domain::UserId,
    previous_version: UserVersion,
    new_version: UserVersion,
    actor: PrincipalId,
    request_id: RequestId,
    snapshot: SnapshotRecord,
    lifecycle: LifecycleRecord,
    canonical: Zeroizing<Vec<u8>>,
    subject_digest: AuditSubjectDigest,
    audit_event_id: AuditEventId,
    outbox_event_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
}

pub(super) struct TransitionIdentityRecord {
    pub(super) tenant_id: TenantId,
    pub(super) user_id: UserId,
    pub(super) previous_version: UserVersion,
    pub(super) new_version: UserVersion,
    pub(super) actor: PrincipalId,
    pub(super) request_id: RequestId,
    pub(super) snapshot: SnapshotRecord,
    pub(super) lifecycle: LifecycleRecord,
}

impl TransitionIdentity {
    pub(super) const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub(super) const fn user_id(&self) -> &ariadnion_user_domain::UserId {
        &self.user_id
    }

    pub(super) const fn previous_version(&self) -> UserVersion {
        self.previous_version
    }

    pub(super) const fn new_version(&self) -> UserVersion {
        self.new_version
    }

    pub(super) const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub(super) const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub(super) const fn snapshot(&self) -> SnapshotRecord {
        self.snapshot
    }

    pub(super) const fn lifecycle(&self) -> LifecycleRecord {
        self.lifecycle
    }

    pub(super) const fn audit_event_id(&self) -> &AuditEventId {
        &self.audit_event_id
    }

    pub(super) const fn outbox_event_id(&self) -> &OutboxEventId {
        &self.outbox_event_id
    }

    pub(super) const fn outbox_key(&self) -> &OutboxIdempotencyKey {
        &self.outbox_key
    }
}

pub(super) struct TransitionEvidence {
    identity: TransitionIdentity,
    committed_at: UtcTimestamp,
    payload: Zeroizing<Vec<u8>>,
    payload_digest: AuditPayloadDigest,
}

impl TransitionEvidence {
    pub(super) fn new(
        identity: TransitionIdentity,
        committed_at: UtcTimestamp,
    ) -> Result<Self, StorageError> {
        let payload = canonical_payload(&identity.canonical, committed_at)?;
        let payload_digest =
            AuditPayloadDigest::from_payload(&payload).map_err(|_| integrity_failure())?;
        Ok(Self {
            identity,
            committed_at,
            payload,
            payload_digest,
        })
    }

    pub(super) const fn identity(&self) -> &TransitionIdentity {
        &self.identity
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(super) fn audit_event_after(
        &self,
        head: &AuditChainHead,
    ) -> Result<AuditEvent, StorageError> {
        let sequence = next_sequence(head)?;
        self.audit_event(sequence, head.chain_digest())
    }

    pub(super) fn audit_event(
        &self,
        sequence: AuditSequence,
        previous: Option<AuditChainDigest>,
    ) -> Result<AuditEvent, StorageError> {
        let binding = AuditEventBinding::new(
            self.identity.audit_event_id.clone(),
            self.identity.tenant_id.clone(),
            self.identity.actor.clone(),
            UtcTimestamp::from_unix_seconds(self.identity.lifecycle.occurred_at),
            sequence,
        );
        let subject =
            AuditSubject::from_digest(AuditSubjectKind::User, self.identity.subject_digest);
        let content = AuditEventContent::new(
            AuditEventKind::Administered,
            subject,
            AUDIT_REASON,
            self.payload_digest,
            previous,
        )
        .map_err(|_| integrity_failure())?;
        build_audit_event(AuditEventRequest::new(binding, content)).map_err(|_| integrity_failure())
    }

    pub(super) fn outbox_message(&self) -> Result<NewOutboxMessage, StorageError> {
        Ok(NewOutboxMessage::new(
            self.identity.tenant_id.clone(),
            self.identity.outbox_event_id.clone(),
            OutboxTopic::parse(OUTBOX_TOPIC).map_err(|_| integrity_failure())?,
            self.identity.outbox_key.clone(),
            OutboxPayload::new(&self.payload).map_err(|_| integrity_failure())?,
            system_time(self.committed_at)?,
        ))
    }

    pub(super) fn receipt(&self) -> UserCommitReceipt {
        UserCommitReceipt::new(
            self.identity.tenant_id.clone(),
            self.identity.user_id.clone(),
            self.identity.new_version,
            self.committed_at,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct SnapshotRecord {
    pub(super) state: &'static str,
    pub(super) requested_at: Option<i64>,
    pub(super) not_before: Option<i64>,
    pub(super) recovery_state: Option<&'static str>,
}

impl SnapshotRecord {
    pub(super) fn from_state(state: UserSnapshotState) -> Self {
        match state {
            UserSnapshotState::Invited => Self::simple("invited"),
            UserSnapshotState::Active => Self::simple("active"),
            UserSnapshotState::Suspended => Self::simple("suspended"),
            UserSnapshotState::Deleted => Self::simple("deleted"),
            UserSnapshotState::DeletionPending {
                requested_at,
                not_before,
                recovery_state,
            } => Self {
                state: "deletion_pending",
                requested_at: Some(requested_at.unix_seconds()),
                not_before: Some(not_before.timestamp().unix_seconds()),
                recovery_state: Some(recovery_label(recovery_state)),
            },
        }
    }

    const fn simple(state: &'static str) -> Self {
        Self {
            state,
            requested_at: None,
            not_before: None,
            recovery_state: None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct LifecycleRecord {
    pub(super) kind: &'static str,
    pub(super) occurred_at: i64,
    pub(super) not_before: Option<i64>,
    pub(super) recovery_state: Option<&'static str>,
}

impl LifecycleRecord {
    pub(super) fn from_event(event: &UserLifecycleEvent) -> Self {
        let occurred_at = event.occurred_at().unix_seconds();
        match event.kind() {
            UserLifecycleEventKind::Activated => Self::simple("activated", occurred_at),
            UserLifecycleEventKind::Suspended => Self::simple("suspended", occurred_at),
            UserLifecycleEventKind::Resumed => Self::simple("resumed", occurred_at),
            UserLifecycleEventKind::DeletionRequested {
                not_before,
                recovery_state,
                ..
            } => Self {
                kind: "deletion_requested",
                occurred_at,
                not_before: Some(not_before.timestamp().unix_seconds()),
                recovery_state: Some(recovery_label(recovery_state)),
            },
            UserLifecycleEventKind::DeletionRecovered { restored_state, .. } => Self {
                kind: "deletion_recovered",
                occurred_at,
                not_before: None,
                recovery_state: Some(recovery_label(restored_state)),
            },
            UserLifecycleEventKind::Deleted { .. } => Self::simple("deleted", occurred_at),
        }
    }

    const fn simple(kind: &'static str, occurred_at: i64) -> Self {
        Self {
            kind,
            occurred_at,
            not_before: None,
            recovery_state: None,
        }
    }
}

fn canonical_identity(
    input: &TransitionIdentityRecord,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(IDENTITY_DOMAIN.to_vec());
    push_identity_versions(&mut output, input)?;
    push_identity_action(&mut output, input)?;
    push_snapshot_state(&mut output, input.snapshot)?;
    Ok(output)
}

fn push_identity_versions(
    output: &mut Vec<u8>,
    input: &TransitionIdentityRecord,
) -> Result<(), StorageError> {
    push_text(output, input.tenant_id.as_str())?;
    push_text(output, input.user_id.as_str())?;
    push_u64(output, input.previous_version.get())?;
    push_u64(output, input.new_version.get())?;
    Ok(())
}

fn push_identity_action(
    output: &mut Vec<u8>,
    input: &TransitionIdentityRecord,
) -> Result<(), StorageError> {
    push_text(output, input.snapshot.state)?;
    push_text(output, input.lifecycle.kind)?;
    push_text(output, input.actor.as_str())?;
    push_text(output, input.request_id.as_str())?;
    push_i64(output, input.lifecycle.occurred_at)?;
    Ok(())
}

fn push_snapshot_state(output: &mut Vec<u8>, snapshot: SnapshotRecord) -> Result<(), StorageError> {
    push_optional_i64(output, snapshot.requested_at)?;
    push_optional_i64(output, snapshot.not_before)?;
    push_optional_text(output, snapshot.recovery_state)?;
    Ok(())
}

fn canonical_payload(
    identity: &[u8],
    committed_at: UtcTimestamp,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let fields = identity
        .get(IDENTITY_DOMAIN.len()..)
        .ok_or_else(integrity_failure)?;
    let mut output = Zeroizing::new(PAYLOAD_DOMAIN.to_vec());
    output.extend_from_slice(fields);
    push_i64(&mut output, committed_at.unix_seconds())?;
    Ok(output)
}

fn subject_digest(
    key: &AuditSubjectKeyMaterial,
    tenant_id: &TenantId,
    user_id: &ariadnion_user_domain::UserId,
) -> Result<AuditSubjectDigest, StorageError> {
    let mut material = Zeroizing::new(SUBJECT_DOMAIN.to_vec());
    push_text(&mut material, tenant_id.as_str())?;
    push_text(&mut material, user_id.as_str())?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| integrity_failure())?;
    mac.update(&material);
    Ok(AuditSubjectDigest::new(mac.finalize().into_bytes().into()))
}

fn derived_audit_id(identity: &[u8]) -> Result<AuditEventId, StorageError> {
    let value = derived_id(AUDIT_ID_DOMAIN, AUDIT_ID_PREFIX, identity)?;
    AuditEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derived_outbox_id(identity: &[u8]) -> Result<OutboxEventId, StorageError> {
    let value = derived_id(OUTBOX_ID_DOMAIN, OUTBOX_ID_PREFIX, identity)?;
    OutboxEventId::parse(&value).map_err(|_| integrity_failure())
}

fn derived_outbox_key(identity: &[u8]) -> Result<OutboxIdempotencyKey, StorageError> {
    let value = derived_id(OUTBOX_KEY_DOMAIN, OUTBOX_KEY_PREFIX, identity)?;
    OutboxIdempotencyKey::parse(&value).map_err(|_| integrity_failure())
}

fn derived_id(domain: &[u8], prefix: &str, identity: &[u8]) -> Result<String, StorageError> {
    let mut material = Zeroizing::new(domain.to_vec());
    push_field(&mut material, identity)?;
    Ok(format!("{prefix}{}", hex(&Sha256::digest(&material))))
}

fn next_sequence(head: &AuditChainHead) -> Result<AuditSequence, StorageError> {
    match head.last_sequence() {
        Some(sequence) => sequence.next().map_err(|_| integrity_failure()),
        None => Ok(AuditSequence::initial()),
    }
}

fn recovery_label(state: DeletionRecoveryState) -> &'static str {
    match state {
        DeletionRecoveryState::Active => "active",
        DeletionRecoveryState::Suspended => "suspended",
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

fn push_optional_text(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), StorageError> {
    match value {
        Some(value) => push_field(output, value.as_bytes()),
        None => push_field(output, &[]),
    }
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn identity_from_record(
    record: TransitionIdentityRecord,
    key: &AuditSubjectKeyMaterial,
) -> Result<TransitionIdentity, StorageError> {
    let canonical = canonical_identity(&record)?;
    let subject_digest = subject_digest(key, &record.tenant_id, &record.user_id)?;
    Ok(TransitionIdentity {
        tenant_id: record.tenant_id,
        user_id: record.user_id,
        previous_version: record.previous_version,
        new_version: record.new_version,
        actor: record.actor,
        request_id: record.request_id,
        snapshot: record.snapshot,
        lifecycle: record.lifecycle,
        audit_event_id: derived_audit_id(&canonical)?,
        outbox_event_id: derived_outbox_id(&canonical)?,
        outbox_key: derived_outbox_key(&canonical)?,
        canonical,
        subject_digest,
    })
}

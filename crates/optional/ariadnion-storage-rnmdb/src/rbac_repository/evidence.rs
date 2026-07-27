//! Canonical audit and outbox evidence for authorization-policy transitions.

mod history;
mod snapshot;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_audit_domain::{
    AuditEventBinding, AuditEventContent, AuditEventId, AuditEventKind, AuditEventRequest,
    AuditPayloadDigest, AuditSequence, AuditSubject, AuditSubjectDigest, AuditSubjectKind,
    build_audit_event,
};
use ariadnion_core::{PrincipalContext, PrincipalId, RequestContext, RequestId, TenantId};
use ariadnion_rbac::{AuthorizationPolicy, AuthorizationPolicyEventKind, PolicyVersion};
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

pub(super) use history::verify_complete_history;

use self::snapshot::snapshot_digest;
#[cfg(feature = "test-hooks")]
use super::HistoryTestHooks;
use super::decode::PersistedPolicyEvent;
use super::{
    AuditSubjectKeyMaterial, CommitRequest, authenticated_principal, integrity_failure,
    map_fresh_insert_error, sql,
};
use crate::UtcTimestampMicros;
use crate::audit_repository::{append_in_transaction, load_event_by_id, load_head_from_session};
use crate::outbox::enqueue_message;
use crate::session::check_context;

const SUBJECT_DOMAIN: &[u8] = b"ariadnion.rbac.audit-subject.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"ariadnion.rbac.policy-identity.v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.rbac.policy-payload.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"ariadnion.rbac.audit-event-id.v1\0";
const OUTBOX_ID_DOMAIN: &[u8] = b"ariadnion.rbac.outbox-event-id.v1\0";
const OUTBOX_KEY_DOMAIN: &[u8] = b"ariadnion.rbac.outbox-idempotency.v1\0";
const OUTBOX_TOPIC: &str = "identity.rbac.policy.v1";
const AUDIT_REASON: &str = "AUTHORIZATION_POLICY_TRANSITION";
const MAX_CANONICAL_BYTES: usize = 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

pub(super) fn persist_transition_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    let identity = EvidenceIdentity::from_request(request, key)?;
    let evidence = TransitionEvidence::new(identity, committed_at)?;
    let head = load_head_from_session(session, request.tenant_id)?;
    let event = evidence.audit_event(&head)?;
    reject_existing_audit(session, request.tenant_id, &event)?;
    append_in_transaction(
        session,
        authenticated_principal(request.context)?,
        &head,
        &event,
    )
    .map_err(map_fresh_insert_error)?;
    persist_outbox(session, request.tenant_id, &evidence)
}

fn reject_existing_audit(
    session: &mut LocalSession,
    tenant: &TenantId,
    event: &ariadnion_audit_domain::AuditEvent,
) -> Result<(), StorageError> {
    if load_event_by_id(session, tenant, event.id())?.is_some() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn persist_outbox(
    session: &mut LocalSession,
    tenant: &TenantId,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    match enqueue_message(session, tenant, &evidence.outbox_message()?) {
        Ok(EnqueueStatus::Inserted) => Ok(()),
        Ok(EnqueueStatus::AlreadyExists) => Err(integrity_failure()),
        Err(error) => Err(map_fresh_insert_error(error)),
    }
}

pub(super) fn verify_snapshot_evidence(
    session: &mut LocalSession,
    event: &PersistedPolicyEvent,
    policy: &AuthorizationPolicy,
    key: &AuditSubjectKeyMaterial,
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<UtcTimestamp, StorageError> {
    let digest = snapshot_digest(&policy.snapshot_state())?;
    let identity = EvidenceIdentity::from_event(event, digest, key)?;
    let evidence = load_exact_evidence(
        session,
        identity,
        key,
        context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    verify_audit(
        session,
        &evidence,
        context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    Ok(evidence.committed_at)
}

fn load_exact_evidence(
    session: &mut LocalSession,
    identity: EvidenceIdentity,
    key: &AuditSubjectKeyMaterial,
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<TransitionEvidence, StorageError> {
    check_context(context)?;
    let output = sql::load_outbox(
        session,
        &identity.tenant,
        identity.outbox_id.as_str(),
        identity.outbox_key.as_str(),
    )?;
    #[cfg(feature = "test-hooks")]
    history_test_hooks.cancel_after_exact_outbox_query_if_armed(context);
    check_context(context)?;
    let batch = rows(output)?;
    let row = require_exact_outbox_row(validated_outbox_rows(&batch)?)?;
    let evidence = decode_outbox_row(row, key)?;
    require_exact_identity(evidence, &identity)
}

fn require_exact_identity(
    evidence: TransitionEvidence,
    expected: &EvidenceIdentity,
) -> Result<TransitionEvidence, StorageError> {
    if evidence.identity.canonical.as_slice() != expected.canonical.as_slice() {
        return Err(integrity_failure());
    }
    Ok(evidence)
}

fn validated_outbox_rows(batch: &VectorBatch) -> Result<&[Row], StorageError> {
    validate_columns(batch.columns(), &outbox_columns())?;
    Ok(batch.rows())
}

fn require_exact_outbox_row(rows: &[Row]) -> Result<&Row, StorageError> {
    if rows.len() != 1 {
        return Err(integrity_failure());
    }
    rows.first().ok_or_else(integrity_failure)
}

fn decode_outbox_row(
    row: &Row,
    key: &AuditSubjectKeyMaterial,
) -> Result<TransitionEvidence, StorageError> {
    let values = OutboxValues::from_row(row)?;
    let (identity, committed_at) = decode_outbox_identity(&values, key)?;
    values.validate_lifecycle()?;
    let evidence = TransitionEvidence::new(identity, committed_at)?;
    validate_outbox_payload(&evidence, values.payload)?;
    Ok(evidence)
}

fn decode_outbox_identity(
    values: &OutboxValues<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<(EvidenceIdentity, UtcTimestamp), StorageError> {
    let (canonical, payload_committed_at) = decode_payload(values.payload)?;
    let committed_at = values.committed_at()?;
    validate_payload_commit_time(payload_committed_at, committed_at)?;
    let identity = EvidenceIdentity::from_canonical(canonical, key)?;
    values.validate_identity(&identity)?;
    Ok((identity, committed_at))
}

fn validate_payload_commit_time(
    payload_committed_at: UtcTimestamp,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    if payload_committed_at != committed_at {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_outbox_payload(
    evidence: &TransitionEvidence,
    payload: &str,
) -> Result<(), StorageError> {
    if evidence.payload.as_slice() != decode_hex(payload)?.as_slice() {
        return Err(integrity_failure());
    }
    Ok(())
}

struct OutboxValues<'a> {
    tenant: &'a str,
    event_id: &'a str,
    topic: &'a str,
    idempotency_key: &'a str,
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

struct OutboxTextValues<'a> {
    tenant: &'a str,
    event_id: &'a str,
    topic: &'a str,
    idempotency_key: &'a str,
    payload: &'a str,
    state: &'a str,
}

impl<'a> OutboxValues<'a> {
    fn from_row(row: &'a Row) -> Result<Self, StorageError> {
        let values = fixed_outbox_values(row)?;
        let text = decode_outbox_text_values(values)?;
        Ok(Self {
            tenant: text.tenant,
            event_id: text.event_id,
            topic: text.topic,
            idempotency_key: text.idempotency_key,
            payload: text.payload,
            created_at: &values[5],
            available_at: &values[6],
            attempt: required_i64(&values[7])?,
            state: text.state,
            lease_token: &values[9],
            lease_worker: &values[10],
            lease_expires_at: &values[11],
            delivered_at: &values[12],
            failed_at: &values[13],
        })
    }

    fn validate_identity(&self, identity: &EvidenceIdentity) -> Result<(), StorageError> {
        let actual = (self.tenant, self.event_id, self.topic, self.idempotency_key);
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

    fn committed_at(&self) -> Result<UtcTimestamp, StorageError> {
        decode_receipt_time(decode_timestamp(self.created_at)?)
    }

    fn validate_lifecycle(&self) -> Result<(), StorageError> {
        let created = decode_timestamp(self.created_at)?;
        let available = decode_timestamp(self.available_at)?;
        let mutable = MutableOutboxValues {
            lease_token: self.lease_token,
            lease_worker: self.lease_worker,
            lease_expires_at: self.lease_expires_at,
            delivered_at: self.delivered_at,
            failed_at: self.failed_at,
        };
        match self.state {
            "pending" => validate_pending(self.attempt, created, available, &mutable),
            "leased" => validate_leased(self.attempt, &mutable),
            "delivered" => validate_terminal(self.attempt, &mutable, true),
            "dead" => validate_terminal(self.attempt, &mutable, false),
            _ => Err(integrity_failure()),
        }
    }
}

fn fixed_outbox_values(row: &Row) -> Result<&[SqlValue], StorageError> {
    let values = row.values();
    if values.len() != 14 {
        return Err(integrity_failure());
    }
    Ok(values)
}

fn decode_outbox_text_values(values: &[SqlValue]) -> Result<OutboxTextValues<'_>, StorageError> {
    Ok(OutboxTextValues {
        tenant: required_text(&values[0])?,
        event_id: required_text(&values[1])?,
        topic: required_text(&values[2])?,
        idempotency_key: required_text(&values[3])?,
        payload: required_text(&values[4])?,
        state: required_text(&values[8])?,
    })
}

struct MutableOutboxValues<'a> {
    lease_token: &'a SqlValue,
    lease_worker: &'a SqlValue,
    lease_expires_at: &'a SqlValue,
    delivered_at: &'a SqlValue,
    failed_at: &'a SqlValue,
}

fn validate_pending(
    attempt: i64,
    created: i64,
    available: i64,
    mutable: &MutableOutboxValues<'_>,
) -> Result<(), StorageError> {
    validate_attempt(attempt, true)?;
    if attempt == 0 && created != available {
        return Err(integrity_failure());
    }
    require_all_null(mutable_values(mutable))
}

fn validate_leased(attempt: i64, mutable: &MutableOutboxValues<'_>) -> Result<(), StorageError> {
    validate_attempt(attempt, false)?;
    decode_lease_token(mutable.lease_token)?;
    let worker = required_text(mutable.lease_worker)?;
    OutboxWorkerId::parse(worker).map_err(|_| integrity_failure())?;
    require_timestamp(mutable.lease_expires_at)?;
    require_all_null([mutable.delivered_at, mutable.failed_at])
}

fn validate_terminal(
    attempt: i64,
    mutable: &MutableOutboxValues<'_>,
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
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn mutable_values<'a>(mutable: &'a MutableOutboxValues<'a>) -> [&'a SqlValue; 5] {
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

fn required_i64(value: &SqlValue) -> Result<i64, StorageError> {
    match value {
        SqlValue::Int64(value) => Ok(*value),
        _ => Err(integrity_failure()),
    }
}

fn decode_lease_token(value: &SqlValue) -> Result<(), StorageError> {
    let value = required_text(value)?;
    if value.len() > 512 || !value.len().is_multiple_of(2) {
        return Err(integrity_failure());
    }
    OutboxLeaseToken::new(&decode_hex(value)?)
        .map(|_| ())
        .map_err(|_| integrity_failure())
}

fn verify_audit(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<(), StorageError> {
    check_context(context)?;
    let event_context = event_context(context, &evidence.identity);
    #[cfg(feature = "test-hooks")]
    let (persisted, _) = crate::audit_repository::load_durable_event_with_head_observed(
        session,
        &evidence.identity.tenant,
        &evidence.identity.audit_id,
        &event_context,
        history_test_hooks,
    )?;
    #[cfg(not(feature = "test-hooks"))]
    let (persisted, _) = crate::audit_repository::load_durable_event_with_head(
        session,
        &evidence.identity.tenant,
        &evidence.identity.audit_id,
        &event_context,
    )?;
    check_context(context)?;
    #[cfg(feature = "test-hooks")]
    history_test_hooks.record_exact_audit_verification();
    verify_exact_audit(evidence, &persisted)
}

fn verify_exact_audit(
    evidence: &TransitionEvidence,
    persisted: &ariadnion_audit_domain::AuditEvent,
) -> Result<(), StorageError> {
    let expected = evidence
        .audit_event_with_boundary(persisted.sequence(), persisted.previous_chain_digest())?;
    if persisted != &expected {
        return Err(integrity_failure());
    }
    Ok(())
}

fn event_context(context: &RequestContext, identity: &EvidenceIdentity) -> RequestContext {
    RequestContext::new(
        identity.request_id.clone(),
        context.trace_id().clone(),
        Some(PrincipalContext::new(
            identity.tenant.clone(),
            identity.actor.clone(),
        )),
        context.deadline(),
        context.cancellation(),
    )
}

struct TransitionEvidence {
    identity: EvidenceIdentity,
    payload: Zeroizing<Vec<u8>>,
    committed_at: UtcTimestamp,
}

impl TransitionEvidence {
    fn new(identity: EvidenceIdentity, committed_at: UtcTimestamp) -> Result<Self, StorageError> {
        let payload = canonical_payload(&identity.canonical, committed_at)?;
        Ok(Self {
            identity,
            payload,
            committed_at,
        })
    }

    fn audit_event(
        &self,
        head: &ariadnion_audit_store::AuditChainHead,
    ) -> Result<ariadnion_audit_domain::AuditEvent, StorageError> {
        let sequence = match head.last_sequence() {
            Some(sequence) => sequence.next().map_err(|_| integrity_failure())?,
            None => AuditSequence::initial(),
        };
        self.audit_event_with_boundary(sequence, head.chain_digest())
    }

    fn audit_event_with_boundary(
        &self,
        sequence: AuditSequence,
        previous: Option<ariadnion_audit_domain::AuditChainDigest>,
    ) -> Result<ariadnion_audit_domain::AuditEvent, StorageError> {
        let binding = AuditEventBinding::new(
            self.identity.audit_id.clone(),
            self.identity.tenant.clone(),
            self.identity.actor.clone(),
            self.identity.occurred_at,
            sequence,
        );
        let digest =
            AuditPayloadDigest::from_payload(&self.payload).map_err(|_| integrity_failure())?;
        let content = AuditEventContent::new(
            AuditEventKind::Administered,
            AuditSubject::from_digest(AuditSubjectKind::Administration, self.identity.subject),
            AUDIT_REASON,
            digest,
            previous,
        )
        .map_err(|_| integrity_failure())?;
        build_audit_event(AuditEventRequest::new(binding, content)).map_err(|_| integrity_failure())
    }

    fn outbox_message(&self) -> Result<NewOutboxMessage, StorageError> {
        Ok(NewOutboxMessage::new(
            self.identity.tenant.clone(),
            self.identity.outbox_id.clone(),
            OutboxTopic::parse(OUTBOX_TOPIC).map_err(|_| integrity_failure())?,
            self.identity.outbox_key.clone(),
            OutboxPayload::new(&self.payload).map_err(|_| integrity_failure())?,
            system_time(self.committed_at)?,
        ))
    }
}

struct EvidenceIdentity {
    request_id: RequestId,
    tenant: TenantId,
    expected_version: PolicyVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    new_version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
    snapshot_digest: [u8; 32],
    canonical: Zeroizing<Vec<u8>>,
    subject: AuditSubjectDigest,
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
}

impl EvidenceIdentity {
    fn from_request(
        request: &CommitRequest<'_>,
        key: &AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let event = request.transition.event();
        let digest = snapshot_digest(&request.transition.policy().snapshot_state())?;
        Self::new(
            IdentityParts {
                request_id: request.context.request_id().clone(),
                tenant: request.tenant_id.clone(),
                expected_version: request.expected_previous_version,
                actor: event.actor().clone(),
                occurred_at: event.occurred_at(),
                new_version: event.version(),
                kind: event.kind(),
                snapshot_digest: digest,
            },
            key,
        )
    }

    fn from_event(
        event: &PersistedPolicyEvent,
        digest: [u8; 32],
        key: &AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        Self::new(
            IdentityParts {
                request_id: event.request_id().clone(),
                tenant: event.tenant_id().clone(),
                expected_version: expected_version(event.version(), event.kind())?,
                actor: event.actor().clone(),
                occurred_at: event.occurred_at(),
                new_version: event.version(),
                kind: event.kind(),
                snapshot_digest: digest,
            },
            key,
        )
    }

    fn new(parts: IdentityParts, key: &AuditSubjectKeyMaterial) -> Result<Self, StorageError> {
        validate_version_shape(parts.expected_version, parts.new_version, parts.kind)?;
        let canonical = canonical_identity(IdentityFields {
            request_id: &parts.request_id,
            tenant: &parts.tenant,
            expected_version: parts.expected_version,
            actor: &parts.actor,
            occurred_at: parts.occurred_at,
            new_version: parts.new_version,
            kind: parts.kind,
            snapshot_digest: parts.snapshot_digest,
        })?;
        let identifiers = EvidenceIdentifiers::new(&canonical)?;
        let subject = subject_digest(key, &parts.tenant)?;
        Ok(Self {
            request_id: parts.request_id,
            subject,
            tenant: parts.tenant,
            expected_version: parts.expected_version,
            actor: parts.actor,
            occurred_at: parts.occurred_at,
            new_version: parts.new_version,
            kind: parts.kind,
            snapshot_digest: parts.snapshot_digest,
            audit_id: identifiers.audit_id,
            outbox_id: identifiers.outbox_id,
            outbox_key: identifiers.outbox_key,
            canonical,
        })
    }

    fn from_canonical(
        canonical: Zeroizing<Vec<u8>>,
        key: &AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let decoded = decode_identity(&canonical)?;
        let identity = Self::new(
            IdentityParts {
                request_id: decoded.request_id,
                tenant: decoded.tenant,
                expected_version: decoded.expected_version,
                actor: decoded.actor,
                occurred_at: decoded.occurred_at,
                new_version: decoded.new_version,
                kind: decoded.kind,
                snapshot_digest: decoded.snapshot_digest,
            },
            key,
        )?;
        if identity.canonical.as_slice() != canonical.as_slice() {
            return Err(integrity_failure());
        }
        Ok(identity)
    }

    fn matches_event(&self, event: &PersistedPolicyEvent) -> bool {
        self.request_id == *event.request_id()
            && self.tenant == *event.tenant_id()
            && self.new_version == event.version()
            && self.actor == *event.actor()
            && self.occurred_at == event.occurred_at()
            && self.kind == event.kind()
            && expected_version(event.version(), event.kind()).ok() == Some(self.expected_version)
    }
}

struct IdentityParts {
    request_id: RequestId,
    tenant: TenantId,
    expected_version: PolicyVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    new_version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
    snapshot_digest: [u8; 32],
}

struct EvidenceIdentifiers {
    audit_id: AuditEventId,
    outbox_id: OutboxEventId,
    outbox_key: OutboxIdempotencyKey,
}

impl EvidenceIdentifiers {
    fn new(canonical: &[u8]) -> Result<Self, StorageError> {
        Ok(Self {
            audit_id: AuditEventId::parse(&derived_id(
                AUDIT_ID_DOMAIN,
                "rbac-policy-audit-v1-",
                canonical,
            )?)
            .map_err(|_| integrity_failure())?,
            outbox_id: OutboxEventId::parse(&derived_id(
                OUTBOX_ID_DOMAIN,
                "rbac-policy-outbox-v1-",
                canonical,
            )?)
            .map_err(|_| integrity_failure())?,
            outbox_key: OutboxIdempotencyKey::parse(&derived_id(
                OUTBOX_KEY_DOMAIN,
                "rbac-policy-transition-v1-",
                canonical,
            )?)
            .map_err(|_| integrity_failure())?,
        })
    }
}

struct IdentityFields<'a> {
    request_id: &'a RequestId,
    tenant: &'a TenantId,
    expected_version: PolicyVersion,
    actor: &'a PrincipalId,
    occurred_at: UtcTimestamp,
    new_version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
    snapshot_digest: [u8; 32],
}

fn canonical_identity(fields: IdentityFields<'_>) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let mut output = Zeroizing::new(IDENTITY_DOMAIN.to_vec());
    push_identity_binding(&mut output, &fields)?;
    push_identity_transition(&mut output, &fields)?;
    enforce_canonical_bound(output)
}

fn push_identity_binding(
    output: &mut Vec<u8>,
    fields: &IdentityFields<'_>,
) -> Result<(), StorageError> {
    push_text(output, fields.request_id.as_str())?;
    push_text(output, fields.tenant.as_str())?;
    push_u64(output, fields.expected_version.get())?;
    push_text(output, fields.actor.as_str())?;
    Ok(())
}

fn push_identity_transition(
    output: &mut Vec<u8>,
    fields: &IdentityFields<'_>,
) -> Result<(), StorageError> {
    push_i64(output, fields.occurred_at.unix_seconds())?;
    push_u64(output, fields.new_version.get())?;
    push_marker(output, event_kind_marker(fields.kind))?;
    push_field(output, &fields.snapshot_digest)?;
    Ok(())
}

struct DecodedIdentity {
    request_id: RequestId,
    tenant: TenantId,
    expected_version: PolicyVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    new_version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
    snapshot_digest: [u8; 32],
}

struct DecodedIdentityBinding {
    request_id: RequestId,
    tenant: TenantId,
    expected_version: PolicyVersion,
    actor: PrincipalId,
}

struct DecodedIdentityTransition {
    occurred_at: UtcTimestamp,
    new_version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
    snapshot_digest: [u8; 32],
}

fn decode_identity(canonical: &[u8]) -> Result<DecodedIdentity, StorageError> {
    let remaining = canonical
        .strip_prefix(IDENTITY_DOMAIN)
        .ok_or_else(integrity_failure)?;
    let mut reader = CanonicalReader::new(remaining);
    let binding = decode_identity_binding(&mut reader)?;
    let transition = decode_identity_transition(&mut reader)?;
    reader.finish()?;
    validate_version_shape(
        binding.expected_version,
        transition.new_version,
        transition.kind,
    )?;
    Ok(DecodedIdentity {
        request_id: binding.request_id,
        tenant: binding.tenant,
        expected_version: binding.expected_version,
        actor: binding.actor,
        occurred_at: transition.occurred_at,
        new_version: transition.new_version,
        kind: transition.kind,
        snapshot_digest: transition.snapshot_digest,
    })
}

fn decode_identity_binding(
    reader: &mut CanonicalReader<'_>,
) -> Result<DecodedIdentityBinding, StorageError> {
    Ok(DecodedIdentityBinding {
        request_id: decode_request_id(reader)?,
        tenant: decode_tenant_id(reader)?,
        expected_version: decode_policy_version(reader)?,
        actor: decode_principal_id(reader)?,
    })
}

fn decode_identity_transition(
    reader: &mut CanonicalReader<'_>,
) -> Result<DecodedIdentityTransition, StorageError> {
    Ok(DecodedIdentityTransition {
        occurred_at: UtcTimestamp::from_unix_seconds(reader.i64()?),
        new_version: decode_policy_version(reader)?,
        kind: decode_event_kind_marker(reader.marker()?)?,
        snapshot_digest: reader.digest()?,
    })
}

fn decode_request_id(reader: &mut CanonicalReader<'_>) -> Result<RequestId, StorageError> {
    RequestId::parse(reader.text()?).map_err(|_| integrity_failure())
}

fn decode_tenant_id(reader: &mut CanonicalReader<'_>) -> Result<TenantId, StorageError> {
    TenantId::parse(reader.text()?).map_err(|_| integrity_failure())
}

fn decode_policy_version(reader: &mut CanonicalReader<'_>) -> Result<PolicyVersion, StorageError> {
    PolicyVersion::new(reader.u64()?).map_err(|_| integrity_failure())
}

fn decode_principal_id(reader: &mut CanonicalReader<'_>) -> Result<PrincipalId, StorageError> {
    PrincipalId::parse(reader.text()?).map_err(|_| integrity_failure())
}

fn expected_version(
    new_version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
) -> Result<PolicyVersion, StorageError> {
    match kind {
        AuthorizationPolicyEventKind::Published if new_version == PolicyVersion::initial() => {
            Ok(PolicyVersion::initial())
        }
        AuthorizationPolicyEventKind::Replaced => new_version
            .get()
            .checked_sub(1)
            .ok_or_else(integrity_failure)
            .and_then(|value| PolicyVersion::new(value).map_err(|_| integrity_failure())),
        _ => Err(integrity_failure()),
    }
}

fn validate_version_shape(
    expected: PolicyVersion,
    new: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
) -> Result<(), StorageError> {
    if expected_version(new, kind)? != expected {
        return Err(integrity_failure());
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
    enforce_canonical_bound(output)
}

fn decode_payload(value: &str) -> Result<(Zeroizing<Vec<u8>>, UtcTimestamp), StorageError> {
    let bytes = decode_hex(value)?;
    let remaining = bytes
        .strip_prefix(PAYLOAD_DOMAIN)
        .ok_or_else(integrity_failure)?;
    let mut reader = CanonicalReader::new(remaining);
    let identity = Zeroizing::new(reader.field()?.to_vec());
    let committed_at = UtcTimestamp::from_unix_seconds(reader.i64()?);
    reader.finish()?;
    if canonical_payload(&identity, committed_at)?.as_slice() != bytes.as_slice() {
        return Err(integrity_failure());
    }
    Ok((identity, committed_at))
}

struct CanonicalReader<'a> {
    remaining: &'a [u8],
}

impl<'a> CanonicalReader<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn field(&mut self) -> Result<&'a [u8], StorageError> {
        let length_bytes = self.remaining.get(..8).ok_or_else(integrity_failure)?;
        let length_array: [u8; 8] = length_bytes.try_into().map_err(|_| integrity_failure())?;
        let length =
            usize::try_from(u64::from_be_bytes(length_array)).map_err(|_| integrity_failure())?;
        let end = 8_usize.checked_add(length).ok_or_else(integrity_failure)?;
        let value = self.remaining.get(8..end).ok_or_else(integrity_failure)?;
        self.remaining = self.remaining.get(end..).ok_or_else(integrity_failure)?;
        Ok(value)
    }

    fn text(&mut self) -> Result<&'a str, StorageError> {
        std::str::from_utf8(self.field()?).map_err(|_| integrity_failure())
    }

    fn u64(&mut self) -> Result<u64, StorageError> {
        let value: [u8; 8] = self.field()?.try_into().map_err(|_| integrity_failure())?;
        Ok(u64::from_be_bytes(value))
    }

    fn i64(&mut self) -> Result<i64, StorageError> {
        let value: [u8; 8] = self.field()?.try_into().map_err(|_| integrity_failure())?;
        Ok(i64::from_be_bytes(value))
    }

    fn marker(&mut self) -> Result<u8, StorageError> {
        let value = self.field()?;
        if value.len() != 1 {
            return Err(integrity_failure());
        }
        value.first().copied().ok_or_else(integrity_failure)
    }

    fn digest(&mut self) -> Result<[u8; 32], StorageError> {
        self.field()?.try_into().map_err(|_| integrity_failure())
    }

    fn finish(self) -> Result<(), StorageError> {
        if !self.remaining.is_empty() {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

fn subject_digest(
    key: &AuditSubjectKeyMaterial,
    tenant: &TenantId,
) -> Result<AuditSubjectDigest, StorageError> {
    let mut material = Zeroizing::new(SUBJECT_DOMAIN.to_vec());
    push_text(&mut material, tenant.as_str())?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| integrity_failure())?;
    mac.update(&material);
    Ok(AuditSubjectDigest::new(mac.finalize().into_bytes().into()))
}

fn derived_id(domain: &[u8], prefix: &str, identity: &[u8]) -> Result<String, StorageError> {
    let mut material = Zeroizing::new(domain.to_vec());
    push_field(&mut material, identity)?;
    Ok(format!("{prefix}{}", hex(&Sha256::digest(&material))))
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

fn push_marker(output: &mut Vec<u8>, value: u8) -> Result<(), StorageError> {
    push_field(output, &[value])
}

fn enforce_canonical_bound(output: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if output.len() > MAX_CANONICAL_BYTES {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(output)
}

const fn event_kind_marker(kind: AuthorizationPolicyEventKind) -> u8 {
    match kind {
        AuthorizationPolicyEventKind::Published => 0,
        AuthorizationPolicyEventKind::Replaced => 1,
    }
}

fn decode_event_kind_marker(value: u8) -> Result<AuthorizationPolicyEventKind, StorageError> {
    match value {
        0 => Ok(AuthorizationPolicyEventKind::Published),
        1 => Ok(AuthorizationPolicyEventKind::Replaced),
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
    if value.len() > MAX_CANONICAL_BYTES * 2 || !value.len().is_multiple_of(2) {
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
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

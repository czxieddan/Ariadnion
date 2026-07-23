//! Read-only reconciliation of one exact durable user transition.

use ariadnion_audit_domain::{AuditEvent, AuditSequence};
use ariadnion_audit_store::AuditChainHead;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_service::UserCommitReceipt;
use rnmdb_cli::LocalSession;

use super::decode;
use super::evidence::{
    TransitionEvidence, TransitionIdentity, TransitionIdentityRecord, identity_from_record,
};
use super::{AuditSubjectKeyMaterial, CommitRequest, integrity_failure, validate_commit_request};
use crate::audit_repository::{load_durable_event_with_head, load_event_by_id};
use crate::session::check_context;

#[derive(Clone, Copy)]
struct AuditBoundary<'a> {
    target: &'a AuditEvent,
    head: &'a AuditChainHead,
}

pub(super) fn reconcile_commit(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<UserCommitReceipt, StorageError> {
    validate_commit_request(request)?;
    let identity = reconciliation_target_identity(request, key)?;
    let later = verify_snapshot(
        session,
        request.transition.user(),
        request.context,
        &identity,
    )?;
    decode::verify_lifecycle(session, &identity).map_err(reconciliation_error)?;
    let evidence = load_transition_evidence(session, identity)?;
    let (target_event, head) = verify_audit(session, &evidence, request.context)?;
    verify_later_evidence(
        session,
        evidence.identity(),
        &later,
        key,
        request.context,
        AuditBoundary {
            target: &target_event,
            head: &head,
        },
    )?;
    Ok(evidence.receipt())
}

fn load_transition_evidence(
    session: &mut LocalSession,
    identity: TransitionIdentity,
) -> Result<TransitionEvidence, StorageError> {
    let outbox = decode::load_outbox(session, &identity).map_err(reconciliation_error)?;
    let evidence = TransitionEvidence::new(identity, outbox.committed_at())?;
    ensure_payload_matches(&outbox, &evidence)?;
    Ok(evidence)
}

fn ensure_payload_matches(
    outbox: &decode::PersistedOutbox,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    if outbox.payload() == evidence.payload() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_snapshot(
    session: &mut LocalSession,
    target: &ariadnion_user_domain::User,
    context: &ariadnion_core::RequestContext,
    identity: &TransitionIdentity,
) -> Result<Box<[decode::VerifiedLifecycle]>, StorageError> {
    let user = decode::load_user(session, identity.tenant_id(), identity.user_id())
        .map_err(reconciliation_error)?;
    validate_snapshot_identity(&user, target)?;
    validate_snapshot_state(session, identity, target, context, &user)
}

fn validate_snapshot_identity(
    user: &ariadnion_user_domain::User,
    target: &ariadnion_user_domain::User,
) -> Result<(), StorageError> {
    if user.tenant_id() != target.tenant_id() || user.id() != target.id() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_snapshot_version(
    user: &ariadnion_user_domain::User,
    target: &ariadnion_user_domain::User,
    current: ariadnion_user_domain::UserVersion,
    expected: ariadnion_user_domain::UserVersion,
) -> Result<(), StorageError> {
    if current == expected && user != target {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_snapshot_state(
    session: &mut LocalSession,
    identity: &TransitionIdentity,
    target: &ariadnion_user_domain::User,
    context: &ariadnion_core::RequestContext,
    user: &ariadnion_user_domain::User,
) -> Result<Box<[decode::VerifiedLifecycle]>, StorageError> {
    let target_version = target.version();
    let current_version = user.version();
    if current_version < target_version {
        return Err(integrity_failure());
    }
    validate_snapshot_version(user, target, current_version, target_version)?;
    reject_rewound_snapshot(session, identity, current_version)?;
    if current_version > target_version {
        return verify_later_lifecycle(session, identity, user, context);
    }
    Ok(Box::default())
}

fn verify_later_lifecycle(
    session: &mut LocalSession,
    identity: &TransitionIdentity,
    user: &ariadnion_user_domain::User,
    context: &ariadnion_core::RequestContext,
) -> Result<Box<[decode::VerifiedLifecycle]>, StorageError> {
    // The lifecycle range decoder has no internal cancellation point.
    check_context(context).map_err(reconciliation_error)?;
    let later =
        decode::verify_lifecycle_range(session, identity, user).map_err(reconciliation_error)?;
    check_context(context).map_err(reconciliation_error)?;
    decode::verify_current_lifecycle(session, user).map_err(reconciliation_error)?;
    Ok(later)
}

fn reject_rewound_snapshot(
    session: &mut LocalSession,
    identity: &TransitionIdentity,
    current_version: ariadnion_user_domain::UserVersion,
) -> Result<(), StorageError> {
    if decode::has_later_lifecycle(
        session,
        identity.tenant_id(),
        identity.user_id(),
        current_version,
    )
    .map_err(reconciliation_error)?
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn verify_audit(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
    context: &ariadnion_core::RequestContext,
) -> Result<(AuditEvent, AuditChainHead), StorageError> {
    let identity = evidence.identity();
    let (persisted, head) = load_durable_event_with_head(
        session,
        identity.tenant_id(),
        identity.audit_event_id(),
        context,
    )
    .map_err(reconciliation_error)?;
    verify_audit_event(evidence, &persisted)?;
    Ok((persisted, head))
}

fn verify_audit_event(
    evidence: &TransitionEvidence,
    persisted: &AuditEvent,
) -> Result<(), StorageError> {
    let expected = evidence.audit_event(persisted.sequence(), persisted.previous_chain_digest())?;
    if persisted == &expected {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_later_evidence(
    session: &mut LocalSession,
    origin: &TransitionIdentity,
    later: &[decode::VerifiedLifecycle],
    key: &AuditSubjectKeyMaterial,
    context: &ariadnion_core::RequestContext,
    boundary: AuditBoundary<'_>,
) -> Result<(), StorageError> {
    let mut previous_sequence = boundary.target.sequence();
    // The lifecycle range is capped at 65,536 total rows, leaving at most 65,535 later rows.
    // Each later row performs one indexed outbox lookup and one indexed audit lookup while the
    // serialized session is held; context is checked before and after every row.
    for record in later {
        check_context(context).map_err(reconciliation_error)?;
        let persisted = load_later_evidence(session, origin, record, key, context)?;
        validate_later_audit_order(
            &persisted,
            boundary.target,
            previous_sequence,
            boundary.head,
        )?;
        previous_sequence = persisted.sequence();
        check_context(context).map_err(reconciliation_error)?;
    }
    check_context(context).map_err(reconciliation_error)
}

fn later_identity(
    origin: &TransitionIdentity,
    record: &decode::VerifiedLifecycle,
    key: &AuditSubjectKeyMaterial,
) -> Result<TransitionIdentity, StorageError> {
    let previous = record
        .version
        .get()
        .checked_sub(1)
        .ok_or_else(integrity_failure)
        .and_then(|value| {
            ariadnion_user_domain::UserVersion::new(value).map_err(|_| integrity_failure())
        })?;
    identity_from_record(
        TransitionIdentityRecord {
            tenant_id: origin.tenant_id().clone(),
            user_id: origin.user_id().clone(),
            previous_version: previous,
            new_version: record.version,
            actor: record.actor.clone(),
            request_id: record.request_id.clone(),
            snapshot: record.snapshot,
            lifecycle: record.lifecycle,
        },
        key,
    )
}

fn reconciliation_target_identity(
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<TransitionIdentity, StorageError> {
    let principal = super::authenticated_principal(request.context)?;
    let user = request.transition.user();
    identity_from_record(
        TransitionIdentityRecord {
            tenant_id: request.tenant_id.clone(),
            user_id: user.id().clone(),
            previous_version: request.expected_previous_version,
            new_version: user.version(),
            actor: principal.principal_id().clone(),
            request_id: request.context.request_id().clone(),
            snapshot: super::evidence::SnapshotRecord::from_state(user.snapshot_state()),
            lifecycle: super::evidence::LifecycleRecord::from_event(request.transition.event()),
        },
        key,
    )
}

fn load_later_audit(
    session: &mut LocalSession,
    identity: &TransitionIdentity,
    context: &ariadnion_core::RequestContext,
) -> Result<AuditEvent, StorageError> {
    check_context(context).map_err(reconciliation_error)?;
    load_event_by_id(session, identity.tenant_id(), identity.audit_event_id())
        .map_err(reconciliation_error)?
        .ok_or_else(integrity_failure)
}

fn load_later_evidence(
    session: &mut LocalSession,
    origin: &TransitionIdentity,
    record: &decode::VerifiedLifecycle,
    key: &AuditSubjectKeyMaterial,
    context: &ariadnion_core::RequestContext,
) -> Result<AuditEvent, StorageError> {
    let identity = later_identity(origin, record, key)?;
    let evidence = load_transition_evidence(session, identity)?;
    let persisted = load_later_audit(session, evidence.identity(), context)?;
    verify_audit_event(&evidence, &persisted)?;
    Ok(persisted)
}

fn validate_later_audit_order(
    event: &AuditEvent,
    target: &AuditEvent,
    previous_sequence: AuditSequence,
    head: &AuditChainHead,
) -> Result<(), StorageError> {
    let last = head.last_sequence().ok_or_else(integrity_failure)?;
    if event.tenant_id() != target.tenant_id()
        || event.sequence() <= previous_sequence
        || event.sequence() > last
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn reconciliation_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Unavailable
        | StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::ResourceExhausted => error,
        _ => integrity_failure(),
    }
}

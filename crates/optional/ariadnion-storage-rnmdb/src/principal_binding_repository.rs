// crates/optional/ariadnion-storage-rnmdb/src/principal_binding_repository.rs - Rust source for Ariadnion.
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
//! Atomic durable persistence for tenant-bound principal bindings.

mod decode;
mod evidence;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_core::{PrincipalContext, PrincipalId, RequestContext, TenantId};
use ariadnion_principal_binding::{
    PrincipalBinding, PrincipalBindingCommand, PrincipalBindingCommitReceipt,
    PrincipalBindingEventKind, PrincipalBindingRepositoryError,
    PrincipalBindingRepositoryErrorCode, PrincipalBindingRepositoryPort,
    PrincipalBindingTransition, PrincipalBindingVersion, erase, provision, revoke,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::LocalSession;

use crate::identity_transaction::run_identity_transaction;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Persists exact principal-binding snapshots and immutable lifecycle evidence.
pub struct RnmdbPrincipalBindingRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbPrincipalBindingRepository {
    /// Opens a repository over a newly created serialized RNMDB session.
    ///
    /// Callers must discard a repository whose prior commit outcome was
    /// indeterminate. Reconciliation must use a separately reopened repository,
    /// which makes the underlying session fresh and read-only for that operation.
    ///
    /// # Errors
    /// Returns a redacted storage error when the encrypted database cannot be
    /// opened with the supplied validated options.
    pub fn open(
        options: SessionOpenOptions,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let session = RnmdbSessionOwner::open(options).map(Arc::new)?;
        Ok(Self::new(session, audit_subject_key))
    }

    /// Creates a repository over one serialized session and audit subject key.
    ///
    /// Wrapping a tainted session does not make it reusable. Reopen the database
    /// after any indeterminate commit result.
    #[must_use]
    pub const fn new(
        session: Arc<RnmdbSessionOwner>,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Self {
        Self {
            session,
            audit_subject_key,
        }
    }
}

impl PrincipalBindingRepositoryPort for RnmdbPrincipalBindingRepository {
    fn load(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        context: &RequestContext,
    ) -> Result<PrincipalBinding, PrincipalBindingRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_binding(session, tenant_id, principal_id)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        expected_previous_version: Option<PrincipalBindingVersion>,
        transition: &PrincipalBindingTransition,
        context: &RequestContext,
    ) -> Result<PrincipalBindingCommitReceipt, PrincipalBindingRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            principal_id,
            expected_previous_version,
            transition,
            context,
        };
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_transaction_session(context, tenant_id, |session| {
                run_identity_transaction(session, context, |session| {
                    commit_transition(session, &request, &self.audit_subject_key)
                })
            })
            .map_err(map_storage_error)
    }

    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        expected_previous_version: Option<PrincipalBindingVersion>,
        transition: &PrincipalBindingTransition,
        context: &RequestContext,
    ) -> Result<PrincipalBindingCommitReceipt, PrincipalBindingRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            principal_id,
            expected_previous_version,
            transition,
            context,
        };
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                reconcile_exact(session, &request, &self.audit_subject_key)
            })
            .map_err(map_storage_error)
    }
}

pub(super) struct CommitRequest<'a> {
    pub(super) tenant_id: &'a TenantId,
    pub(super) principal_id: &'a PrincipalId,
    pub(super) expected_previous_version: Option<PrincipalBindingVersion>,
    pub(super) transition: &'a PrincipalBindingTransition,
    pub(super) context: &'a RequestContext,
}

fn commit_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<PrincipalBindingCommitReceipt, StorageError> {
    if request.expected_previous_version.is_none() {
        persist_creation(session, request)?;
    } else {
        persist_update(session, request)?;
    }
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(
        session,
        request.transition,
        key,
        committed_at,
        request.context,
    )?;
    Ok(PrincipalBindingCommitReceipt::from_transition(
        request.transition,
        committed_at,
    ))
}

fn persist_creation(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    decode::ensure_creation_absent(session, request.tenant_id, request.principal_id)?;
    if let Err(error) = sql::insert_snapshot(session, request.transition.binding()) {
        return Err(decode::classify_creation_insert_error(
            session,
            request.tenant_id,
            request.principal_id,
            error,
        ));
    }
    sql::insert_event(session, request.transition.event()).map_err(map_fresh_evidence_error)
}

fn persist_update(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let expected = request
        .expected_previous_version
        .ok_or_else(integrity_failure)?;
    let previous = request
        .transition
        .previous_snapshot()
        .ok_or_else(integrity_failure)?;
    let durable =
        match decode::load_binding_with_history(session, request.tenant_id, request.principal_id) {
            Err(error) if error.code() == StorageErrorCode::NotFound => {
                return Err(StorageError::new(StorageErrorCode::Conflict));
            }
            result => result?.binding,
        };
    validate_durable_precondition(&durable, previous, expected)?;
    sql::update_snapshot(session, request.transition.binding(), expected)?;
    sql::insert_event(session, request.transition.event()).map_err(map_fresh_evidence_error)
}

fn validate_durable_precondition(
    durable: &PrincipalBinding,
    previous: &ariadnion_principal_binding::PrincipalBindingSnapshot,
    expected: PrincipalBindingVersion,
) -> Result<(), StorageError> {
    if durable.version() != expected {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    if &durable.snapshot() != previous {
        return Err(integrity_failure());
    }
    Ok(())
}

fn reconcile_exact(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<PrincipalBindingCommitReceipt, StorageError> {
    let loaded =
        decode::load_binding_with_history(session, request.tenant_id, request.principal_id)
            .map_err(map_reconcile_error)?;
    verify_target_event(request.transition, &loaded.events)?;
    let target_evidence =
        evidence::reconcile_transition_evidence(session, request.transition, key, request.context)?;
    verify_later_state_and_evidence(session, request, key, &loaded, &target_evidence)?;
    Ok(PrincipalBindingCommitReceipt::from_transition(
        request.transition,
        target_evidence.committed_at(),
    ))
}

fn verify_target_event(
    transition: &PrincipalBindingTransition,
    events: &[decode::PersistedPrincipalBindingEvent],
) -> Result<(), StorageError> {
    let index = transition
        .binding()
        .version()
        .get()
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(integrity_failure)?;
    events
        .get(index)
        .filter(|event| event.matches_transition(transition))
        .map(|_| ())
        .ok_or_else(integrity_failure)
}

fn verify_later_state_and_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    loaded: &decode::LoadedPrincipalBinding,
    target_evidence: &evidence::ReconciledTransitionEvidence,
) -> Result<(), StorageError> {
    let start = usize::try_from(request.transition.binding().version().get())
        .map_err(|_| integrity_failure())?;
    let mut current = request.transition.binding().clone();
    let mut previous_audit_sequence = target_evidence.audit_sequence();
    let durable_head_sequence = target_evidence.durable_head_sequence();
    for persisted in loaded.events.iter().skip(start) {
        let transition = replay_later_transition(&current, persisted.event())?;
        if !persisted.matches_transition(&transition) {
            return Err(integrity_failure());
        }
        let later_evidence =
            evidence::reconcile_transition_evidence(session, &transition, key, request.context)?;
        evidence::validate_later_audit_order(
            &later_evidence,
            previous_audit_sequence,
            durable_head_sequence,
        )?;
        previous_audit_sequence = later_evidence.audit_sequence();
        current = transition.into_binding();
    }
    if current != loaded.binding {
        return Err(integrity_failure());
    }
    Ok(())
}

fn replay_later_transition(
    current: &PrincipalBinding,
    event: &ariadnion_principal_binding::PrincipalBindingEvent,
) -> Result<PrincipalBindingTransition, StorageError> {
    let command = PrincipalBindingCommand::new(
        current.version(),
        event.actor().clone(),
        event.request_id().clone(),
        event.occurred_at(),
    );
    match event.kind() {
        PrincipalBindingEventKind::Revoked => revoke(current, command),
        PrincipalBindingEventKind::Erased => erase(current, command),
        PrincipalBindingEventKind::Provisioned => return Err(integrity_failure()),
    }
    .map_err(|_| integrity_failure())
}

fn validate_commit_request(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let principal = validate_authenticated_tenant(request.context, request.tenant_id)?;
    validate_request_boundary(request, principal)?;
    validate_reconstructed_transition(request)
}

fn validate_request_boundary(
    request: &CommitRequest<'_>,
    actor: &PrincipalContext,
) -> Result<(), StorageError> {
    let event = request.transition.event();
    let valid = request.transition.tenant_id() == request.tenant_id
        && request.transition.principal_id() == request.principal_id
        && request.transition.expected_previous_version() == request.expected_previous_version
        && event.tenant_id() == request.tenant_id
        && event.principal_id() == request.principal_id
        && event.actor() == actor.principal_id()
        && event.request_id() == request.context.request_id();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_reconstructed_transition(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let event = request.transition.event();
    let reconstructed = match request.transition.previous_snapshot() {
        None => reconstruct_provision(request)?,
        Some(previous) => {
            let current =
                PrincipalBinding::rehydrate(previous.clone()).map_err(|_| integrity_failure())?;
            let command = PrincipalBindingCommand::new(
                current.version(),
                event.actor().clone(),
                event.request_id().clone(),
                event.occurred_at(),
            );
            reconstruct_update(&current, command, event.kind())?
        }
    };
    if &reconstructed == request.transition {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn reconstruct_provision(
    request: &CommitRequest<'_>,
) -> Result<PrincipalBindingTransition, StorageError> {
    if request.expected_previous_version.is_some() {
        return Err(integrity_failure());
    }
    let event = request.transition.event();
    let identity = request
        .transition
        .binding()
        .identity()
        .cloned()
        .ok_or_else(integrity_failure)?;
    provision(
        identity,
        event.actor().clone(),
        event.request_id().clone(),
        event.occurred_at(),
    )
    .map_err(|_| integrity_failure())
}

fn reconstruct_update(
    current: &PrincipalBinding,
    command: PrincipalBindingCommand,
    kind: PrincipalBindingEventKind,
) -> Result<PrincipalBindingTransition, StorageError> {
    match kind {
        PrincipalBindingEventKind::Revoked => revoke(current, command),
        PrincipalBindingEventKind::Erased => erase(current, command),
        PrincipalBindingEventKind::Provisioned => return Err(integrity_failure()),
    }
    .map_err(|_| integrity_failure())
}

pub(super) fn authenticated_principal(
    context: &RequestContext,
) -> Result<&PrincipalContext, StorageError> {
    context.principal().ok_or_else(integrity_failure)
}

fn validate_authenticated_tenant<'a>(
    context: &'a RequestContext,
    tenant_id: &TenantId,
) -> Result<&'a PrincipalContext, StorageError> {
    let principal = authenticated_principal(context)?;
    if principal.tenant_id() == tenant_id {
        Ok(principal)
    } else {
        Err(integrity_failure())
    }
}

fn trusted_commit_time() -> Result<UtcTimestamp, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure())?;
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| integrity_failure())?;
    Ok(UtcTimestamp::from_unix_seconds(seconds))
}

fn map_fresh_evidence_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::ResourceExhausted
        | StorageErrorCode::Unavailable => error,
        _ => integrity_failure(),
    }
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

fn map_storage_error(error: StorageError) -> PrincipalBindingRepositoryError {
    PrincipalBindingRepositoryError::new(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(code: StorageErrorCode) -> PrincipalBindingRepositoryErrorCode {
    match code {
        StorageErrorCode::NotFound => PrincipalBindingRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => PrincipalBindingRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => PrincipalBindingRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => PrincipalBindingRepositoryErrorCode::DeadlineExceeded,
        StorageErrorCode::ResourceExhausted => {
            PrincipalBindingRepositoryErrorCode::ResourceExhausted
        }
        StorageErrorCode::Unavailable => PrincipalBindingRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => {
            PrincipalBindingRepositoryErrorCode::CommitIndeterminate
        }
        _ => PrincipalBindingRepositoryErrorCode::IntegrityFailure,
    }
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

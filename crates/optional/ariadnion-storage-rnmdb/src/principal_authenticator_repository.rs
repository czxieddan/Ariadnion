// crates/optional/ariadnion-storage-rnmdb/src/principal_authenticator_repository.rs - Rust source for Ariadnion.
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
//! Atomic durable persistence for tenant-bound principal authenticators.

mod decode;
mod evidence;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_principal_binding::{
    PrincipalAuthenticatorCommand, PrincipalAuthenticatorCommitReceipt,
    PrincipalAuthenticatorEventKind, PrincipalAuthenticatorId, PrincipalAuthenticatorKind,
    PrincipalAuthenticatorLink, PrincipalAuthenticatorRepositoryError,
    PrincipalAuthenticatorRepositoryErrorCode, PrincipalAuthenticatorRepositoryPort,
    PrincipalAuthenticatorSourceId, PrincipalAuthenticatorTransition,
    PrincipalAuthenticatorVersion, link_authenticator, revoke_authenticator,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::LocalSession;

use crate::identity_transaction::{require_active_identity_transaction, run_identity_transaction};
use crate::principal_binding_repository::load_principal_binding_in_session;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Persists exact authenticator-link snapshots and immutable lifecycle evidence.
pub struct RnmdbPrincipalAuthenticatorRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbPrincipalAuthenticatorRepository {
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

impl PrincipalAuthenticatorRepositoryPort for RnmdbPrincipalAuthenticatorRepository {
    fn load(
        &self,
        tenant_id: &TenantId,
        authenticator_id: &PrincipalAuthenticatorId,
        context: &RequestContext,
    ) -> Result<PrincipalAuthenticatorLink, PrincipalAuthenticatorRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                load_principal_authenticator_by_id_in_session(session, tenant_id, authenticator_id)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        authenticator_id: &PrincipalAuthenticatorId,
        expected_previous_version: Option<PrincipalAuthenticatorVersion>,
        transition: &PrincipalAuthenticatorTransition,
        context: &RequestContext,
    ) -> Result<PrincipalAuthenticatorCommitReceipt, PrincipalAuthenticatorRepositoryError> {
        let request = PrincipalAuthenticatorCommitRequest::new(
            tenant_id,
            authenticator_id,
            expected_previous_version,
            transition,
            context,
        );
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_transaction_session(context, tenant_id, |session| {
                run_identity_transaction(session, context, |session| {
                    let committed_at = trusted_commit_time()?;
                    commit_principal_authenticator_in_session(
                        session,
                        &request,
                        &self.audit_subject_key,
                        committed_at,
                    )
                })
            })
            .map_err(map_storage_error)
    }

    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        authenticator_id: &PrincipalAuthenticatorId,
        expected_previous_version: Option<PrincipalAuthenticatorVersion>,
        transition: &PrincipalAuthenticatorTransition,
        context: &RequestContext,
    ) -> Result<PrincipalAuthenticatorCommitReceipt, PrincipalAuthenticatorRepositoryError> {
        let request = PrincipalAuthenticatorCommitRequest::new(
            tenant_id,
            authenticator_id,
            expected_previous_version,
            transition,
            context,
        );
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                reconcile_principal_authenticator_in_session(
                    session,
                    &request,
                    &self.audit_subject_key,
                )
            })
            .map_err(map_storage_error)
    }
}

pub(crate) fn load_principal_authenticator_by_id_in_session(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    authenticator_id: &PrincipalAuthenticatorId,
) -> Result<PrincipalAuthenticatorLink, StorageError> {
    decode::load_link_by_id(session, tenant_id, authenticator_id)
}

pub(crate) fn load_principal_authenticator_by_source_in_session(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    kind: PrincipalAuthenticatorKind,
    source_id: &PrincipalAuthenticatorSourceId,
) -> Result<PrincipalAuthenticatorLink, StorageError> {
    decode::load_link_by_source(session, tenant_id, kind, source_id)
}

pub(crate) fn commit_principal_authenticator_in_session(
    session: &mut LocalSession,
    request: &PrincipalAuthenticatorCommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<PrincipalAuthenticatorCommitReceipt, StorageError> {
    require_active_identity_transaction(session)?;
    validate_commit_request(request)?;
    commit_transition(session, request, key, committed_at)
}

pub(crate) fn reconcile_principal_authenticator_in_session(
    session: &mut LocalSession,
    request: &PrincipalAuthenticatorCommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<PrincipalAuthenticatorCommitReceipt, StorageError> {
    validate_commit_request(request)?;
    reconcile_exact(session, request, key)
}

pub(crate) struct PrincipalAuthenticatorCommitRequest<'a> {
    pub(super) tenant_id: &'a TenantId,
    pub(super) authenticator_id: &'a PrincipalAuthenticatorId,
    pub(super) expected_previous_version: Option<PrincipalAuthenticatorVersion>,
    pub(super) transition: &'a PrincipalAuthenticatorTransition,
    pub(super) context: &'a RequestContext,
}

impl<'a> PrincipalAuthenticatorCommitRequest<'a> {
    pub(crate) const fn new(
        tenant_id: &'a TenantId,
        authenticator_id: &'a PrincipalAuthenticatorId,
        expected_previous_version: Option<PrincipalAuthenticatorVersion>,
        transition: &'a PrincipalAuthenticatorTransition,
        context: &'a RequestContext,
    ) -> Self {
        Self {
            tenant_id,
            authenticator_id,
            expected_previous_version,
            transition,
            context,
        }
    }
}

fn commit_transition(
    session: &mut LocalSession,
    request: &PrincipalAuthenticatorCommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<PrincipalAuthenticatorCommitReceipt, StorageError> {
    if request.expected_previous_version.is_none() {
        persist_creation(session, request)?;
    } else {
        persist_update(session, request)?;
    }
    evidence::persist_transition_evidence(
        session,
        request.transition,
        key,
        committed_at,
        request.context,
    )?;
    Ok(PrincipalAuthenticatorCommitReceipt::from_transition(
        request.transition,
        committed_at,
    ))
}

fn persist_creation(
    session: &mut LocalSession,
    request: &PrincipalAuthenticatorCommitRequest<'_>,
) -> Result<(), StorageError> {
    validate_required_principal_binding(session, request)?;
    ensure_creation_absent(session, request.transition.link())?;
    if let Err(error) = sql::insert_snapshot(session, request.transition.link()) {
        return Err(decode::classify_creation_insert_error(
            session,
            request.transition.link(),
            error,
        ));
    }
    sql::insert_event(session, request.transition.event()).map_err(map_fresh_evidence_error)
}

fn ensure_creation_absent(
    session: &mut LocalSession,
    link: &PrincipalAuthenticatorLink,
) -> Result<(), StorageError> {
    let by_id = load_principal_authenticator_by_id_in_session(
        session,
        link.tenant_id(),
        link.authenticator_id(),
    );
    require_missing(by_id)?;
    let by_source = load_principal_authenticator_by_source_in_session(
        session,
        link.tenant_id(),
        link.kind(),
        link.source_id(),
    );
    require_missing(by_source)
}

fn require_missing(
    result: Result<PrincipalAuthenticatorLink, StorageError>,
) -> Result<(), StorageError> {
    match result {
        Err(error) if error.code() == StorageErrorCode::NotFound => Ok(()),
        Ok(_) => Err(StorageError::new(StorageErrorCode::Conflict)),
        Err(error) => Err(error),
    }
}

fn validate_required_principal_binding(
    session: &mut LocalSession,
    request: &PrincipalAuthenticatorCommitRequest<'_>,
) -> Result<(), StorageError> {
    let link = request.transition.link();
    let binding =
        load_principal_binding_in_session(session, request.tenant_id, link.principal_id())
            .map_err(map_required_binding_error)?;
    let event = request.transition.event();
    let reconstructed = link_authenticator(
        &binding,
        link.kind(),
        link.source_id().clone(),
        event.actor().clone(),
        event.request_id().clone(),
        event.occurred_at(),
    )
    .map_err(|_| integrity_failure())?;
    (&reconstructed == request.transition)
        .then_some(())
        .ok_or_else(integrity_failure)
}

fn persist_update(
    session: &mut LocalSession,
    request: &PrincipalAuthenticatorCommitRequest<'_>,
) -> Result<(), StorageError> {
    let expected = request
        .expected_previous_version
        .ok_or_else(integrity_failure)?;
    let previous = request
        .transition
        .previous_snapshot()
        .ok_or_else(integrity_failure)?;
    let durable = load_update_precondition(session, request)?;
    validate_durable_precondition(&durable, previous, expected)?;
    sql::update_snapshot(session, request.transition.link(), expected)?;
    sql::insert_event(session, request.transition.event()).map_err(map_fresh_evidence_error)
}

fn load_update_precondition(
    session: &mut LocalSession,
    request: &PrincipalAuthenticatorCommitRequest<'_>,
) -> Result<PrincipalAuthenticatorLink, StorageError> {
    let durable = match decode::load_link_with_history_by_id(
        session,
        request.tenant_id,
        request.authenticator_id,
    ) {
        Err(error) if error.code() == StorageErrorCode::NotFound => {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        result => result?.link,
    };
    Ok(durable)
}

fn validate_durable_precondition(
    durable: &PrincipalAuthenticatorLink,
    previous: &ariadnion_principal_binding::PrincipalAuthenticatorSnapshot,
    expected: PrincipalAuthenticatorVersion,
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
    request: &PrincipalAuthenticatorCommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<PrincipalAuthenticatorCommitReceipt, StorageError> {
    let loaded =
        decode::load_link_with_history_by_id(session, request.tenant_id, request.authenticator_id)
            .map_err(map_reconcile_error)?;
    verify_target_event(request.transition, &loaded.events)?;
    let target_evidence =
        evidence::reconcile_transition_evidence(session, request.transition, key, request.context)?;
    verify_later_state_and_evidence(session, request, key, &loaded, &target_evidence)?;
    Ok(PrincipalAuthenticatorCommitReceipt::from_transition(
        request.transition,
        target_evidence.committed_at(),
    ))
}

fn verify_target_event(
    transition: &PrincipalAuthenticatorTransition,
    events: &[decode::PersistedPrincipalAuthenticatorEvent],
) -> Result<(), StorageError> {
    let index = transition
        .link()
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
    request: &PrincipalAuthenticatorCommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    loaded: &decode::LoadedPrincipalAuthenticator,
    target_evidence: &evidence::ReconciledTransitionEvidence,
) -> Result<(), StorageError> {
    let start = usize::try_from(request.transition.link().version().get())
        .map_err(|_| integrity_failure())?;
    let mut state = LaterReconciliationState {
        current: request.transition.link().clone(),
        previous_audit_sequence: target_evidence.audit_sequence(),
        durable_head_sequence: target_evidence.durable_head_sequence(),
    };
    for persisted in loaded.events.iter().skip(start) {
        apply_later_transition(session, persisted, key, request.context, &mut state)?;
    }
    if state.current != loaded.link {
        return Err(integrity_failure());
    }
    Ok(())
}

struct LaterReconciliationState {
    current: PrincipalAuthenticatorLink,
    previous_audit_sequence: ariadnion_audit_domain::AuditSequence,
    durable_head_sequence: ariadnion_audit_domain::AuditSequence,
}

fn apply_later_transition(
    session: &mut LocalSession,
    persisted: &decode::PersistedPrincipalAuthenticatorEvent,
    key: &AuditSubjectKeyMaterial,
    context: &RequestContext,
    state: &mut LaterReconciliationState,
) -> Result<(), StorageError> {
    let transition = replay_later_transition(&state.current, persisted.event())?;
    if !persisted.matches_transition(&transition) {
        return Err(integrity_failure());
    }
    let later_evidence =
        evidence::reconcile_transition_evidence(session, &transition, key, context)?;
    evidence::validate_later_audit_order(
        &later_evidence,
        state.previous_audit_sequence,
        state.durable_head_sequence,
    )?;
    state.previous_audit_sequence = later_evidence.audit_sequence();
    state.current = transition.into_link();
    Ok(())
}

fn replay_later_transition(
    current: &PrincipalAuthenticatorLink,
    event: &ariadnion_principal_binding::PrincipalAuthenticatorEvent,
) -> Result<PrincipalAuthenticatorTransition, StorageError> {
    let command = PrincipalAuthenticatorCommand::new(
        current.version(),
        event.actor().clone(),
        event.request_id().clone(),
        event.occurred_at(),
    );
    match event.kind() {
        PrincipalAuthenticatorEventKind::Revoked => revoke_authenticator(current, command),
        PrincipalAuthenticatorEventKind::Linked => return Err(integrity_failure()),
    }
    .map_err(|_| integrity_failure())
}

fn validate_commit_request(
    request: &PrincipalAuthenticatorCommitRequest<'_>,
) -> Result<(), StorageError> {
    let principal = validate_authenticated_tenant(request.context, request.tenant_id)?;
    validate_request_boundary(request, principal)?;
    validate_transition_shape(request)
}

fn validate_request_boundary(
    request: &PrincipalAuthenticatorCommitRequest<'_>,
    actor: &PrincipalContext,
) -> Result<(), StorageError> {
    let event = request.transition.event();
    let valid = request.transition.tenant_id() == request.tenant_id
        && request.transition.authenticator_id() == request.authenticator_id
        && request.transition.expected_previous_version() == request.expected_previous_version
        && event.tenant_id() == request.tenant_id
        && event.authenticator_id() == request.authenticator_id
        && event.actor() == actor.principal_id()
        && event.request_id() == request.context.request_id();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_transition_shape(
    request: &PrincipalAuthenticatorCommitRequest<'_>,
) -> Result<(), StorageError> {
    let snapshot = request.transition.new_snapshot();
    let rehydrated =
        PrincipalAuthenticatorLink::rehydrate(snapshot.clone()).map_err(|_| integrity_failure())?;
    if &rehydrated != request.transition.link() {
        return Err(integrity_failure());
    }
    request
        .transition
        .event()
        .validate_against(&snapshot)
        .map_err(|_| integrity_failure())?;
    match request.transition.previous_snapshot() {
        None => validate_initial_shape(request),
        Some(previous) => validate_reconstructed_update(request, previous),
    }
}

fn validate_initial_shape(
    request: &PrincipalAuthenticatorCommitRequest<'_>,
) -> Result<(), StorageError> {
    let valid = request.expected_previous_version.is_none()
        && request.transition.event().kind() == PrincipalAuthenticatorEventKind::Linked;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_reconstructed_update(
    request: &PrincipalAuthenticatorCommitRequest<'_>,
    previous: &ariadnion_principal_binding::PrincipalAuthenticatorSnapshot,
) -> Result<(), StorageError> {
    let current =
        PrincipalAuthenticatorLink::rehydrate(previous.clone()).map_err(|_| integrity_failure())?;
    let event = request.transition.event();
    let command = PrincipalAuthenticatorCommand::new(
        current.version(),
        event.actor().clone(),
        event.request_id().clone(),
        event.occurred_at(),
    );
    let reconstructed = match event.kind() {
        PrincipalAuthenticatorEventKind::Revoked => revoke_authenticator(&current, command),
        PrincipalAuthenticatorEventKind::Linked => return Err(integrity_failure()),
    }
    .map_err(|_| integrity_failure())?;
    (&reconstructed == request.transition)
        .then_some(())
        .ok_or_else(integrity_failure)
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

fn map_required_binding_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::ResourceExhausted
        | StorageErrorCode::Unavailable => error,
        _ => integrity_failure(),
    }
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

fn map_storage_error(error: StorageError) -> PrincipalAuthenticatorRepositoryError {
    PrincipalAuthenticatorRepositoryError::new(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(
    code: StorageErrorCode,
) -> PrincipalAuthenticatorRepositoryErrorCode {
    match code {
        StorageErrorCode::NotFound => PrincipalAuthenticatorRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => PrincipalAuthenticatorRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => PrincipalAuthenticatorRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => {
            PrincipalAuthenticatorRepositoryErrorCode::DeadlineExceeded
        }
        _ => map_durability_error_code(code),
    }
}

const fn map_durability_error_code(
    code: StorageErrorCode,
) -> PrincipalAuthenticatorRepositoryErrorCode {
    match code {
        StorageErrorCode::ResourceExhausted => {
            PrincipalAuthenticatorRepositoryErrorCode::ResourceExhausted
        }
        StorageErrorCode::Unavailable => PrincipalAuthenticatorRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => {
            PrincipalAuthenticatorRepositoryErrorCode::CommitIndeterminate
        }
        _ => PrincipalAuthenticatorRepositoryErrorCode::IntegrityFailure,
    }
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

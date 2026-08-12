// crates/optional/ariadnion-storage-rnmdb/src/session_repository.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Atomic durable persistence for tenant-bound browser session families.

mod decode;
mod evidence;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_auth_session::{
    SessionAction, SessionCommand, SessionCommitReceipt, SessionEventKind, SessionFamily,
    SessionFamilyVersion, SessionRepositoryError, SessionRepositoryErrorCode,
    SessionRepositoryPort, SessionRotation, SessionRotationEvidence, SessionSubject,
    SessionTransition, transition_session_family,
};
use ariadnion_core::{PrincipalContext, PrincipalId, RequestContext, TenantId};
use ariadnion_principal_binding::{
    AuthenticatedPrincipalEvidence, PrincipalAuthenticatorCommand, PrincipalAuthenticatorEventKind,
    PrincipalAuthenticatorKind, PrincipalAuthenticatorLink, PrincipalAuthenticatorSourceId,
    PrincipalAuthenticatorState, PrincipalAuthenticatorTransition, PrincipalAuthenticatorVersion,
    PrincipalBinding, link_authenticator, revoke_authenticator,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::LocalSession;

use crate::identity_transaction::run_identity_transaction;
use crate::principal_authenticator_repository::{
    PrincipalAuthenticatorCommitRequest, ReconciledPrincipalAuthenticatorFact,
    ReconciledPrincipalAuthenticatorHistory, commit_principal_authenticator_in_session,
    reconcile_principal_authenticator_history_by_source_in_session,
};
use crate::principal_binding_repository::load_principal_binding_in_session;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Persists complete browser session families and immutable issuance evidence.
pub struct RnmdbSessionRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbSessionRepository {
    /// Opens a repository over a newly created serialized RNMDB session.
    ///
    /// Callers must discard a repository after an indeterminate commit and
    /// reopen the database with fresh key material.
    ///
    /// # Errors
    ///
    /// Returns a redacted storage error when the encrypted database cannot be
    /// opened with the supplied validated options.
    pub fn open(
        options: SessionOpenOptions,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let session = RnmdbSessionOwner::open(options).map(Arc::new)?;
        Ok(Self::new(session, audit_subject_key))
    }

    /// Creates a repository over one serialized session and subject key.
    ///
    /// Wrapping a tainted session does not make it reusable. Reopen the
    /// database after any indeterminate commit result.
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

impl SessionRepositoryPort for RnmdbSessionRepository {
    fn load(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        family_id: &ariadnion_auth_session::SessionFamilyId,
        context: &RequestContext,
    ) -> Result<SessionFamily, SessionRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_family(session, tenant_id, user_id, family_id)
            })
            .map_err(map_storage_error)
    }

    fn load_by_token_digest(
        &self,
        tenant_id: &TenantId,
        token_digest: ariadnion_auth_session::SessionTokenDigest,
        context: &RequestContext,
    ) -> Result<SessionFamily, SessionRepositoryError> {
        validate_routed_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_family_by_token(session, tenant_id, token_digest)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_version: SessionFamilyVersion,
        transition: &SessionTransition,
        context: &RequestContext,
    ) -> Result<SessionCommitReceipt, SessionRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            user_id,
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
        user_id: &UserId,
        expected_previous_version: SessionFamilyVersion,
        transition: &SessionTransition,
        context: &RequestContext,
    ) -> Result<SessionCommitReceipt, SessionRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            user_id,
            expected_previous_version,
            transition,
            context,
        };
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                reconcile_read_only(session, &request, &self.audit_subject_key)
            })
            .map_err(map_storage_error)
    }
}

pub(super) struct CommitRequest<'a> {
    pub(super) tenant_id: &'a TenantId,
    pub(super) user_id: &'a UserId,
    pub(super) expected_previous_version: SessionFamilyVersion,
    pub(super) transition: &'a SessionTransition,
    pub(super) context: &'a RequestContext,
}

fn commit_issuance(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<SessionCommitReceipt, StorageError> {
    let authenticator = issuance_authenticator_transition(session, request)?;
    persist_issued_session(session, request)?;
    let committed_at = trusted_commit_time()?;
    persist_paired_issuance_evidence(session, request, &authenticator, key, committed_at)?;
    Ok(commit_receipt(request, committed_at))
}

fn persist_issued_session(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    decode::ensure_issuance_absent(session, request)?;
    sql::insert_family(session, request.transition.family())?;
    sql::insert_leaves(session, request.transition.family())?;
    sql::insert_event(session, request.transition.event())
}

fn persist_paired_issuance_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    authenticator: &PrincipalAuthenticatorTransition,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    evidence::persist_transition_evidence(session, request, key, committed_at)?;
    persist_authenticator_transition(session, request, authenticator, key, committed_at)
}

fn issuance_authenticator_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<PrincipalAuthenticatorTransition, StorageError> {
    let principal = authenticated_principal(request.context)?;
    let binding =
        load_principal_binding_in_session(session, request.tenant_id, principal.principal_id())
            .map_err(map_linkage_dependency_error)?;
    validate_issuance_binding_user(&binding, request.user_id)?;
    link_authenticator(
        &binding,
        PrincipalAuthenticatorKind::SessionFamily,
        session_authenticator_source(request.transition.family().id())?,
        request.transition.event().actor().clone(),
        request.context.request_id().clone(),
        request.transition.event().occurred_at(),
    )
    .map_err(|_| integrity_failure())
}

fn validate_issuance_binding_user(
    binding: &ariadnion_principal_binding::PrincipalBinding,
    user_id: &UserId,
) -> Result<(), StorageError> {
    let identity = binding.identity().ok_or_else(integrity_failure)?;
    if identity.user_id() == user_id {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn session_authenticator_source(
    family_id: &ariadnion_auth_session::SessionFamilyId,
) -> Result<PrincipalAuthenticatorSourceId, StorageError> {
    PrincipalAuthenticatorSourceId::parse(family_id.as_str()).map_err(|_| integrity_failure())
}

fn persist_authenticator_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    transition: &PrincipalAuthenticatorTransition,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    let authenticator_request = PrincipalAuthenticatorCommitRequest::new(
        request.tenant_id,
        transition.authenticator_id(),
        transition.expected_previous_version(),
        transition,
        request.context,
    );
    commit_principal_authenticator_in_session(session, &authenticator_request, key, committed_at)
        .map(|_| ())
}

fn commit_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<SessionCommitReceipt, StorageError> {
    if is_issuance(request) {
        return commit_issuance(session, request, key);
    }
    commit_update(session, request, key)
}

fn commit_update(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<SessionCommitReceipt, StorageError> {
    let loaded = decode::load_family_with_history(
        session,
        request.tenant_id,
        request.user_id,
        request.transition.family().id(),
    )?;
    validate_expected_version(&loaded.family, request)?;
    let replayed = replay_transition(&loaded.family, request)?;
    validate_replayed_transition(&replayed, request)?;
    persist_update(session, request, key, &loaded)
}

fn validate_replayed_transition(
    replayed: &SessionTransition,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    if replayed == request.transition {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn persist_update(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    loaded: &decode::LoadedSessionFamily,
) -> Result<SessionCommitReceipt, StorageError> {
    let issuance = issuance_event(&loaded.events)?;
    let authenticator = terminal_authenticator_transition(session, request, loaded, issuance, key)?;
    persist_session_update_rows(session, request, &loaded.family)?;
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, key, committed_at)?;
    persist_optional_authenticator_transition(
        session,
        request,
        authenticator.as_ref(),
        key,
        committed_at,
    )?;
    Ok(commit_receipt(request, committed_at))
}

fn persist_session_update_rows(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &SessionFamily,
) -> Result<(), StorageError> {
    sql::update_family(session, request, durable)?;
    sql::replace_leaves(session, request.transition.family(), durable)?;
    sql::insert_event(session, request.transition.event())
}

fn persist_optional_authenticator_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    transition: Option<&PrincipalAuthenticatorTransition>,
    key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    match transition {
        Some(transition) => {
            persist_authenticator_transition(session, request, transition, key, committed_at)
        }
        None => Ok(()),
    }
}

fn terminal_authenticator_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    loaded: &decode::LoadedSessionFamily,
    issuance: &decode::PersistedSessionEvent,
    key: &AuditSubjectKeyMaterial,
) -> Result<Option<PrincipalAuthenticatorTransition>, StorageError> {
    match request.transition.event().kind() {
        SessionEventKind::Rotated => {
            active_session_authenticator(session, request, loaded, issuance, key).map(|_| None)
        }
        SessionEventKind::ReuseRevoked | SessionEventKind::Revoked | SessionEventKind::Expired => {
            revoke_session_authenticator(session, request, loaded, issuance, key).map(Some)
        }
        SessionEventKind::Issued => Err(integrity_failure()),
    }
}

fn revoke_session_authenticator(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    loaded: &decode::LoadedSessionFamily,
    issuance: &decode::PersistedSessionEvent,
    key: &AuditSubjectKeyMaterial,
) -> Result<PrincipalAuthenticatorTransition, StorageError> {
    let authenticator =
        paired_active_session_authenticator(session, request, loaded, issuance, key)?;
    let event = request.transition.event();
    let command = PrincipalAuthenticatorCommand::new(
        authenticator.version(),
        event.actor().clone(),
        request.context.request_id().clone(),
        event.occurred_at(),
    );
    revoke_authenticator(&authenticator, command).map_err(|_| integrity_failure())
}

fn active_session_authenticator(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    loaded: &decode::LoadedSessionFamily,
    issuance: &decode::PersistedSessionEvent,
    key: &AuditSubjectKeyMaterial,
) -> Result<PrincipalAuthenticatorLink, StorageError> {
    let authenticator =
        paired_active_session_authenticator(session, request, loaded, issuance, key)?;
    validate_rotation_event_actor(
        request.transition.event().kind(),
        request.transition.event().actor(),
        &authenticator,
    )?;
    let binding = load_authenticator_binding(session, request, &authenticator)?;
    AuthenticatedPrincipalEvidence::from_active_link(&authenticator, &binding)
        .map_err(|_| integrity_failure())?;
    validate_authenticator_binding_user(&binding, request.user_id)?;
    Ok(authenticator)
}

fn paired_active_session_authenticator(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    loaded: &decode::LoadedSessionFamily,
    issuance: &decode::PersistedSessionEvent,
    key: &AuditSubjectKeyMaterial,
) -> Result<PrincipalAuthenticatorLink, StorageError> {
    let issuance_family = decode::family_at_version(
        &loaded.family,
        ariadnion_auth_session::SessionFamilyVersion::initial(),
    )?;
    let session_evidence = evidence::verify_persisted_transition_evidence(
        session,
        evidence::PersistedTransitionEvidence::new(
            request.tenant_id,
            request.user_id,
            SessionFamilyVersion::initial(),
            &issuance_family,
            issuance,
        ),
        key,
        request.context,
    )
    .map_err(map_reconcile_error)?;
    let history = reconcile_session_authenticator_history(session, request, key)?;
    validate_issuance_principal(history.link(), issuance)?;
    validate_reconciled_active_link(&history)?;
    validate_paired_issuance_fact(issuance, session_evidence.committed_at(), &history)?;
    Ok(history.link().clone())
}

fn reconcile_session_authenticator_history(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<ReconciledPrincipalAuthenticatorHistory, StorageError> {
    let source = session_authenticator_source(request.transition.family().id())?;
    reconcile_principal_authenticator_history_by_source_in_session(
        session,
        request.tenant_id,
        PrincipalAuthenticatorKind::SessionFamily,
        &source,
        key,
        request.context,
    )
    .map_err(map_reconcile_error)
}

fn validate_paired_issuance_fact(
    issuance: &decode::PersistedSessionEvent,
    committed_at: UtcTimestamp,
    history: &ReconciledPrincipalAuthenticatorHistory,
) -> Result<(), StorageError> {
    let linked = history.facts().first().ok_or_else(integrity_failure)?;
    let valid = linked.kind() == PrincipalAuthenticatorEventKind::Linked
        && linked.actor() == issuance.actor()
        && linked.occurred_at() == issuance.occurred_at()
        && linked.committed_at() == committed_at;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn load_authenticator_binding(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    authenticator: &PrincipalAuthenticatorLink,
) -> Result<PrincipalBinding, StorageError> {
    load_principal_binding_in_session(session, request.tenant_id, authenticator.principal_id())
        .map_err(map_linkage_dependency_error)
}

fn validate_issuance_principal(
    authenticator: &PrincipalAuthenticatorLink,
    issuance: &decode::PersistedSessionEvent,
) -> Result<(), StorageError> {
    if authenticator.principal_id() == issuance.actor() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_authenticator_binding_user(
    binding: &PrincipalBinding,
    user_id: &UserId,
) -> Result<(), StorageError> {
    if binding
        .identity()
        .is_some_and(|identity| identity.user_id() == user_id)
    {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn issuance_event(
    events: &[decode::PersistedSessionEvent],
) -> Result<&decode::PersistedSessionEvent, StorageError> {
    let event = event_at(events, SessionFamilyVersion::initial())?;
    if event.kind() == SessionEventKind::Issued {
        Ok(event)
    } else {
        Err(integrity_failure())
    }
}

fn validate_expected_version(
    durable: &SessionFamily,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    if durable.version() == request.expected_previous_version {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorCode::Conflict))
    }
}

fn replay_transition(
    durable: &SessionFamily,
    request: &CommitRequest<'_>,
) -> Result<SessionTransition, StorageError> {
    let event = request.transition.event();
    let action = replay_action(durable, request)?;
    let command = SessionCommand::new(
        request.expected_previous_version,
        event.actor().clone(),
        event.occurred_at(),
        action,
    );
    transition_session_family(durable, command).map_err(|_| integrity_failure())
}

fn replay_action(
    durable: &SessionFamily,
    request: &CommitRequest<'_>,
) -> Result<SessionAction, StorageError> {
    match request.transition.event().kind() {
        SessionEventKind::Rotated => Ok(rotation_action(durable, request)),
        SessionEventKind::ReuseRevoked => reuse_action(durable, request),
        SessionEventKind::Revoked => Ok(SessionAction::Revoke {
            subject: request_subject(request),
        }),
        SessionEventKind::Expired => Ok(SessionAction::Expire {
            subject: request_subject(request),
        }),
        SessionEventKind::Issued => Err(integrity_failure()),
    }
}

fn rotation_action(durable: &SessionFamily, request: &CommitRequest<'_>) -> SessionAction {
    let target = request.transition.family();
    let evidence = SessionRotationEvidence::new(
        durable.id().clone(),
        durable.current().id().clone(),
        request_subject(request),
        durable.current().token_digest(),
    );
    SessionAction::Rotate(SessionRotation::new(
        evidence,
        target.current().id().clone(),
        target.current().token_digest(),
        target.current().idle_expires_at(),
    ))
}

fn reuse_action(
    durable: &SessionFamily,
    request: &CommitRequest<'_>,
) -> Result<SessionAction, StorageError> {
    let reused = durable.rotated().first().ok_or_else(integrity_failure)?;
    Ok(SessionAction::DetectReuse {
        family_id: durable.id().clone(),
        session_id: reused.id().clone(),
        subject: request_subject(request),
        presented_token: reused.token_digest(),
    })
}

fn request_subject(request: &CommitRequest<'_>) -> SessionSubject {
    SessionSubject::new(request.tenant_id.clone(), request.user_id.clone())
}

fn commit_receipt(request: &CommitRequest<'_>, committed_at: UtcTimestamp) -> SessionCommitReceipt {
    let family = request.transition.family();
    SessionCommitReceipt::new(
        request.tenant_id.clone(),
        request.user_id.clone(),
        family.id().clone(),
        family.current().id().clone(),
        family.version(),
        committed_at,
    )
}

fn reconcile_read_only(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<SessionCommitReceipt, StorageError> {
    let loaded = decode::load_family_with_history(
        session,
        request.tenant_id,
        request.user_id,
        request.transition.family().id(),
    )
    .map_err(map_reconcile_error)?;
    let target = authenticate_reconciliation_target(&loaded, request)?;
    let target_evidence = evidence::reconcile_transition_evidence(session, request, key)
        .map_err(map_reconcile_error)?;
    let successor =
        verify_optional_successor(session, &loaded, &target, request, &target_evidence, key)?;
    reconcile_session_authenticator(
        session,
        &loaded,
        request,
        &target_evidence,
        successor.as_ref(),
        key,
    )?;
    Ok(commit_receipt(request, target_evidence.committed_at()))
}

fn authenticate_reconciliation_target(
    loaded: &decode::LoadedSessionFamily,
    request: &CommitRequest<'_>,
) -> Result<SessionFamily, StorageError> {
    validate_reconciliation_distance(loaded, request)?;
    let version = request.transition.family().version();
    let target = decode::family_at_version(&loaded.family, version)?;
    let event = event_at(&loaded.events, version)?;
    if target == *request.transition.family() && event.matches_transition(request.transition) {
        Ok(target)
    } else {
        Err(integrity_failure())
    }
}

fn validate_reconciliation_distance(
    loaded: &decode::LoadedSessionFamily,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let target = request.transition.family().version();
    let one_later = target.next().ok();
    if loaded.family.version() == target || one_later == Some(loaded.family.version()) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

struct VerifiedSessionSuccessor<'a> {
    event: &'a decode::PersistedSessionEvent,
    evidence: evidence::ReconciledTransitionEvidence,
}

fn verify_optional_successor<'a>(
    session: &mut LocalSession,
    loaded: &'a decode::LoadedSessionFamily,
    target: &SessionFamily,
    request: &CommitRequest<'_>,
    target_evidence: &evidence::ReconciledTransitionEvidence,
    key: &AuditSubjectKeyMaterial,
) -> Result<Option<VerifiedSessionSuccessor<'a>>, StorageError> {
    if loaded.family.version() == target.version() {
        return Ok(None);
    }
    let successor_version = target.version().next().map_err(|_| integrity_failure())?;
    let successor = decode::family_at_version(&loaded.family, successor_version)?;
    let event = event_at(&loaded.events, successor_version)?;
    let successor_evidence = evidence::verify_persisted_transition_evidence(
        session,
        evidence::PersistedTransitionEvidence::new(
            request.tenant_id,
            request.user_id,
            target.version(),
            &successor,
            event,
        ),
        key,
        request.context,
    )
    .map_err(map_reconcile_error)?;
    evidence::validate_later_transition_evidence(target_evidence, &successor_evidence)?;
    Ok(Some(VerifiedSessionSuccessor {
        event,
        evidence: successor_evidence,
    }))
}

fn reconcile_session_authenticator(
    session: &mut LocalSession,
    loaded: &decode::LoadedSessionFamily,
    request: &CommitRequest<'_>,
    target_evidence: &evidence::ReconciledTransitionEvidence,
    successor: Option<&VerifiedSessionSuccessor<'_>>,
    key: &AuditSubjectKeyMaterial,
) -> Result<(), StorageError> {
    let history = reconcile_session_authenticator_history(session, request, key)?;
    let issuance = issuance_event(&loaded.events)?;
    let issuance_committed_at = reconcile_initial_issuance_evidence(
        session,
        loaded,
        request,
        issuance,
        target_evidence,
        key,
    )?;
    validate_reconciled_rotation_actors(&loaded.events, history.link())?;
    validate_reconciled_authenticator_history(
        request,
        successor,
        issuance,
        issuance_committed_at,
        target_evidence.committed_at(),
        &history,
    )
}

fn validate_reconciled_authenticator_history(
    request: &CommitRequest<'_>,
    successor: Option<&VerifiedSessionSuccessor<'_>>,
    issuance: &decode::PersistedSessionEvent,
    issuance_committed_at: UtcTimestamp,
    target_committed_at: UtcTimestamp,
    history: &ReconciledPrincipalAuthenticatorHistory,
) -> Result<(), StorageError> {
    validate_reconciled_authenticator_identity(issuance, history)?;
    validate_paired_issuance_fact(issuance, issuance_committed_at, history)?;
    let terminal = terminal_reconciliation_fact(request, target_committed_at, successor)?;
    validate_reconciled_authenticator_lifecycle(history, terminal.as_ref())
}

fn validate_reconciled_rotation_actors(
    events: &[decode::PersistedSessionEvent],
    link: &PrincipalAuthenticatorLink,
) -> Result<(), StorageError> {
    for event in events {
        validate_rotation_event_actor(event.kind(), event.actor(), link)?;
    }
    Ok(())
}

fn validate_rotation_event_actor(
    kind: SessionEventKind,
    actor: &PrincipalId,
    link: &PrincipalAuthenticatorLink,
) -> Result<(), StorageError> {
    if kind != SessionEventKind::Rotated || actor == link.principal_id() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn reconcile_initial_issuance_evidence(
    session: &mut LocalSession,
    loaded: &decode::LoadedSessionFamily,
    request: &CommitRequest<'_>,
    issuance: &decode::PersistedSessionEvent,
    target_evidence: &evidence::ReconciledTransitionEvidence,
    key: &AuditSubjectKeyMaterial,
) -> Result<UtcTimestamp, StorageError> {
    if request.transition.event().kind() == SessionEventKind::Issued {
        return Ok(target_evidence.committed_at());
    }
    let family = decode::family_at_version(&loaded.family, SessionFamilyVersion::initial())?;
    let issuance_evidence = evidence::verify_persisted_transition_evidence(
        session,
        evidence::PersistedTransitionEvidence::new(
            request.tenant_id,
            request.user_id,
            SessionFamilyVersion::initial(),
            &family,
            issuance,
        ),
        key,
        request.context,
    )
    .map_err(map_reconcile_error)?;
    evidence::validate_later_transition_evidence(&issuance_evidence, target_evidence)?;
    Ok(issuance_evidence.committed_at())
}

fn validate_reconciled_authenticator_identity(
    issuance: &decode::PersistedSessionEvent,
    history: &ReconciledPrincipalAuthenticatorHistory,
) -> Result<(), StorageError> {
    validate_issuance_principal(history.link(), issuance)
}

struct VerifiedTerminalSession {
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    committed_at: UtcTimestamp,
}

fn terminal_reconciliation_fact(
    request: &CommitRequest<'_>,
    committed_at: UtcTimestamp,
    successor: Option<&VerifiedSessionSuccessor<'_>>,
) -> Result<Option<VerifiedTerminalSession>, StorageError> {
    match request.transition.event().kind() {
        SessionEventKind::ReuseRevoked | SessionEventKind::Revoked | SessionEventKind::Expired => {
            if successor.is_some() {
                return Err(integrity_failure());
            }
            Ok(Some(terminal_from_target(request, committed_at)))
        }
        SessionEventKind::Issued | SessionEventKind::Rotated => terminal_from_successor(successor),
    }
}

fn terminal_from_target(
    request: &CommitRequest<'_>,
    committed_at: UtcTimestamp,
) -> VerifiedTerminalSession {
    let event = request.transition.event();
    VerifiedTerminalSession {
        actor: event.actor().clone(),
        occurred_at: event.occurred_at(),
        committed_at,
    }
}

fn terminal_from_successor(
    successor: Option<&VerifiedSessionSuccessor<'_>>,
) -> Result<Option<VerifiedTerminalSession>, StorageError> {
    let Some(successor) = successor else {
        return Ok(None);
    };
    match successor.event.kind() {
        SessionEventKind::ReuseRevoked | SessionEventKind::Revoked | SessionEventKind::Expired => {
            Ok(Some(VerifiedTerminalSession {
                actor: successor.event.actor().clone(),
                occurred_at: successor.event.occurred_at(),
                committed_at: successor.evidence.committed_at(),
            }))
        }
        SessionEventKind::Rotated => Ok(None),
        SessionEventKind::Issued => Err(integrity_failure()),
    }
}

fn validate_reconciled_authenticator_lifecycle(
    history: &ReconciledPrincipalAuthenticatorHistory,
    terminal: Option<&VerifiedTerminalSession>,
) -> Result<(), StorageError> {
    match terminal {
        Some(terminal) => validate_reconciled_revocation(history, terminal),
        None => validate_reconciled_active_link(history),
    }
}

fn validate_reconciled_active_link(
    history: &ReconciledPrincipalAuthenticatorHistory,
) -> Result<(), StorageError> {
    let link = history.link();
    let valid = link.version() == PrincipalAuthenticatorVersion::initial()
        && link.state() == PrincipalAuthenticatorState::Active
        && link.revoked_at().is_none()
        && history.facts().len() == 1;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_reconciled_revocation(
    history: &ReconciledPrincipalAuthenticatorHistory,
    terminal: &VerifiedTerminalSession,
) -> Result<(), StorageError> {
    let link = history.link();
    let revoked = history.facts().get(1).ok_or_else(integrity_failure)?;
    let valid = link.version().get() == 2
        && link.state() == PrincipalAuthenticatorState::Revoked
        && link.revoked_at() == Some(terminal.occurred_at)
        && history.facts().len() == 2;
    if !valid {
        return Err(integrity_failure());
    }
    validate_revoked_fact(revoked, terminal)
}

fn validate_revoked_fact(
    revoked: &ReconciledPrincipalAuthenticatorFact,
    terminal: &VerifiedTerminalSession,
) -> Result<(), StorageError> {
    let valid = revoked.kind() == PrincipalAuthenticatorEventKind::Revoked
        && revoked.actor() == &terminal.actor
        && revoked.occurred_at() == terminal.occurred_at
        && revoked.committed_at() == terminal.committed_at;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn event_at(
    events: &[decode::PersistedSessionEvent],
    version: SessionFamilyVersion,
) -> Result<&decode::PersistedSessionEvent, StorageError> {
    let index = version
        .get()
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(integrity_failure)?;
    events.get(index).ok_or_else(integrity_failure)
}

fn validate_commit_request(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let principal = validate_authenticated_tenant(request.context, request.tenant_id)?;
    validate_family_binding(request)?;
    validate_leaf_bindings(request)?;
    validate_event_binding(request, principal)?;
    validate_version_shape(request)
}

fn validate_family_binding(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let family = request.transition.family();
    if family.tenant_id() == request.tenant_id && family.user_id() == request.user_id {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_leaf_bindings(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let snapshot = request.transition.family().snapshot_state();
    let invalid = std::iter::once(&snapshot.current)
        .chain(snapshot.rotated.iter())
        .any(|leaf| {
            leaf.family_id != snapshot.id
                || leaf.subject.tenant_id() != request.tenant_id
                || leaf.subject.user_id() != request.user_id
        });
    if invalid {
        Err(integrity_failure())
    } else {
        Ok(())
    }
}

fn validate_event_binding(
    request: &CommitRequest<'_>,
    principal: &PrincipalContext,
) -> Result<(), StorageError> {
    let family = request.transition.family();
    let event = request.transition.event();
    let valid = event.tenant_id() == request.tenant_id
        && event.user_id() == request.user_id
        && event.family_id() == family.id()
        && event.session_id() == family.current().id()
        && event.version() == family.version()
        && event.actor() == principal.principal_id();
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_version_shape(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let family = request.transition.family();
    let valid = if is_issuance(request) {
        family.rotated().is_empty()
    } else {
        request
            .expected_previous_version
            .next()
            .is_ok_and(|version| version == family.version())
    };
    if valid {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorCode::Conflict))
    }
}

fn is_issuance(request: &CommitRequest<'_>) -> bool {
    request.expected_previous_version == SessionFamilyVersion::initial()
        && request.transition.family().version() == SessionFamilyVersion::initial()
        && request.transition.event().kind() == SessionEventKind::Issued
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

fn validate_routed_tenant(
    context: &RequestContext,
    tenant_id: &TenantId,
) -> Result<(), StorageError> {
    match context.principal() {
        Some(principal) if principal.tenant_id() != tenant_id => Err(integrity_failure()),
        Some(_) | None => Ok(()),
    }
}

fn trusted_commit_time() -> Result<UtcTimestamp, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure())?;
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| integrity_failure())?;
    Ok(UtcTimestamp::from_unix_seconds(seconds))
}

fn map_storage_error(error: StorageError) -> SessionRepositoryError {
    repository_error(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(code: StorageErrorCode) -> SessionRepositoryErrorCode {
    match code {
        StorageErrorCode::NotFound => SessionRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => SessionRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => SessionRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => SessionRepositoryErrorCode::DeadlineExceeded,
        remaining => map_storage_durability_error_code(remaining),
    }
}

const fn map_storage_durability_error_code(code: StorageErrorCode) -> SessionRepositoryErrorCode {
    match code {
        StorageErrorCode::ResourceExhausted => SessionRepositoryErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => SessionRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => SessionRepositoryErrorCode::CommitIndeterminate,
        _ => SessionRepositoryErrorCode::IntegrityFailure,
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

fn map_linkage_dependency_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::ResourceExhausted
        | StorageErrorCode::Unavailable => error,
        _ => integrity_failure(),
    }
}

const fn repository_error(code: SessionRepositoryErrorCode) -> SessionRepositoryError {
    SessionRepositoryError::new(code)
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

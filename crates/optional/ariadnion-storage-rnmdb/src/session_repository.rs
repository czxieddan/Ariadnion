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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
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
use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::LocalSession;

use crate::identity_transaction::run_identity_transaction;
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
    decode::ensure_issuance_absent(session, request)?;
    sql::insert_family(session, request.transition.family())?;
    sql::insert_leaves(session, request.transition.family())?;
    sql::insert_event(session, request.transition.event())?;
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, key, committed_at)?;
    Ok(commit_receipt(request, committed_at))
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
    let durable = decode::load_family(
        session,
        request.tenant_id,
        request.user_id,
        request.transition.family().id(),
    )?;
    validate_expected_version(&durable, request)?;
    let replayed = replay_transition(&durable, request)?;
    validate_replayed_transition(&replayed, request)?;
    persist_update(session, request, key, &durable)
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
    durable: &SessionFamily,
) -> Result<SessionCommitReceipt, StorageError> {
    sql::update_family(session, request, durable)?;
    sql::replace_leaves(session, request.transition.family(), durable)?;
    sql::insert_event(session, request.transition.event())?;
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, key, committed_at)?;
    Ok(commit_receipt(request, committed_at))
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
    let committed_at = evidence::reconcile_transition_evidence(session, request, key)
        .map_err(map_reconcile_error)?;
    verify_optional_successor(session, &loaded, &target, request, key)?;
    Ok(commit_receipt(request, committed_at))
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

fn verify_optional_successor(
    session: &mut LocalSession,
    loaded: &decode::LoadedSessionFamily,
    target: &SessionFamily,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<(), StorageError> {
    if loaded.family.version() == target.version() {
        return Ok(());
    }
    let successor_version = target.version().next().map_err(|_| integrity_failure())?;
    let successor = decode::family_at_version(&loaded.family, successor_version)?;
    let event = event_at(&loaded.events, successor_version)?;
    evidence::verify_persisted_transition_evidence(
        session,
        (request.tenant_id, request.user_id),
        target.version(),
        &successor,
        event,
        key,
        request.context,
    )
    .map_err(map_reconcile_error)
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

const fn repository_error(code: SessionRepositoryErrorCode) -> SessionRepositoryError {
    SessionRepositoryError::new(code)
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

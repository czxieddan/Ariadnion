// crates/optional/ariadnion-storage-rnmdb/src/invitation_repository.rs - Rust source for Ariadnion.
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
//! Atomic durable persistence for tenant-bound invitation transitions.

mod decode;
mod evidence;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_invitation::{
    Invitation, InvitationCommitReceipt, InvitationEventKind, InvitationId,
    InvitationRepositoryError, InvitationRepositoryErrorCode, InvitationRepositoryPort,
    InvitationState, InvitationTokenDigest, InvitationTransition, InvitationVersion,
};
use ariadnion_organization::OrganizationId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::LocalSession;

use crate::identity_transaction::{require_active_identity_transaction, run_identity_transaction};
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Persists invitation snapshots and immutable issuance evidence in RNMDB.
pub struct RnmdbInvitationRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbInvitationRepository {
    /// Opens a repository over a newly created serialized RNMDB session.
    ///
    /// Callers must discard a repository whose prior commit outcome was
    /// indeterminate and reopen it with fresh key material.
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

impl InvitationRepositoryPort for RnmdbInvitationRepository {
    fn load(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        invitation_id: &InvitationId,
        context: &RequestContext,
    ) -> Result<Invitation, InvitationRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_invitation(session, tenant_id, organization_id, invitation_id)
            })
            .map_err(map_storage_error)
    }

    fn load_by_token_digest(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        token_digest: InvitationTokenDigest,
        context: &RequestContext,
    ) -> Result<Invitation, InvitationRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_invitation_by_token(session, tenant_id, organization_id, token_digest)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        expected_previous_version: InvitationVersion,
        transition: &InvitationTransition,
        context: &RequestContext,
    ) -> Result<InvitationCommitReceipt, InvitationRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            organization_id,
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
        organization_id: &OrganizationId,
        expected_previous_version: InvitationVersion,
        transition: &InvitationTransition,
        context: &RequestContext,
    ) -> Result<InvitationCommitReceipt, InvitationRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            organization_id,
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
    pub(super) organization_id: &'a OrganizationId,
    pub(super) expected_previous_version: InvitationVersion,
    pub(super) transition: &'a InvitationTransition,
    pub(super) context: &'a RequestContext,
}

pub(crate) fn load_invitation_in_session(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    organization_id: &OrganizationId,
    invitation_id: &InvitationId,
) -> Result<Invitation, StorageError> {
    decode::load_invitation(session, tenant_id, organization_id, invitation_id)
}

pub(crate) fn commit_invitation_in_session(
    session: &mut LocalSession,
    expected_previous_version: InvitationVersion,
    transition: &InvitationTransition,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<InvitationCommitReceipt, StorageError> {
    require_active_identity_transaction(session)?;
    let invitation = transition.invitation();
    let request = CommitRequest {
        tenant_id: invitation.tenant_id(),
        organization_id: invitation.organization_id(),
        expected_previous_version,
        transition,
        context,
    };
    validate_commit_request(&request)?;
    commit_transition(session, &request, key)
}

fn commit_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<InvitationCommitReceipt, StorageError> {
    if is_creation(request) {
        decode::ensure_creation_absent(session, request)?;
        persist_creation(session, request)?;
    } else {
        persist_update(session, request)?;
    }
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, key, committed_at)?;
    let invitation = request.transition.invitation();
    Ok(InvitationCommitReceipt::new(
        request.tenant_id.clone(),
        request.organization_id.clone(),
        invitation.id().clone(),
        invitation.version(),
        committed_at,
    ))
}

fn persist_update(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let target = request.transition.invitation();
    let durable = decode::load_invitation(
        session,
        request.tenant_id,
        request.organization_id,
        target.id(),
    )?;
    validate_expected_issued_snapshot(&durable, request)?;
    sql::update_snapshot(session, request)?;
    sql::insert_event(session, request).map_err(map_fresh_evidence_error)
}

fn validate_expected_issued_snapshot(
    durable: &Invitation,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let target = request.transition.invitation();
    let matches = durable.version() == request.expected_previous_version
        && durable.state() == InvitationState::Issued
        && durable.consumed_by().is_none()
        && immutable_snapshot_matches(durable, target);
    if matches {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorCode::Conflict))
    }
}

fn immutable_snapshot_matches(previous: &Invitation, target: &Invitation) -> bool {
    (
        previous.id(),
        previous.tenant_id(),
        previous.organization_id(),
        previous.issuer(),
        previous.subject_digest(),
        previous.token_digest(),
        previous.issued_at(),
        previous.expires_at(),
    ) == (
        target.id(),
        target.tenant_id(),
        target.organization_id(),
        target.issuer(),
        target.subject_digest(),
        target.token_digest(),
        target.issued_at(),
        target.expires_at(),
    )
}

fn reconcile_exact(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<InvitationCommitReceipt, StorageError> {
    let target = request.transition.invitation();
    let loaded = decode::load_invitation_with_history(
        session,
        request.tenant_id,
        request.organization_id,
        target.id(),
    )
    .map_err(map_reconcile_error)?;
    let later = reconcile_snapshot(target, &loaded.invitation, &loaded.events)?;
    verify_target_event(request, &loaded.events)?;
    let committed_at = evidence::reconcile_transition_evidence(session, request, key)?;
    if let Some(later) = later {
        evidence::verify_later_transition_evidence(
            session,
            request,
            key,
            &loaded.invitation,
            later,
        )?;
    }
    Ok(InvitationCommitReceipt::new(
        request.tenant_id.clone(),
        request.organization_id.clone(),
        target.id().clone(),
        target.version(),
        committed_at,
    ))
}

fn reconcile_snapshot<'a>(
    target: &Invitation,
    durable: &Invitation,
    events: &'a [decode::event::PersistedInvitationEvent],
) -> Result<Option<&'a decode::event::PersistedInvitationEvent>, StorageError> {
    if durable.version() == target.version() {
        return if durable == target {
            Ok(None)
        } else {
            Err(integrity_failure())
        };
    }
    reconcile_later_snapshot(target, durable, events).map(Some)
}

fn reconcile_later_snapshot<'a>(
    target: &Invitation,
    durable: &Invitation,
    events: &'a [decode::event::PersistedInvitationEvent],
) -> Result<&'a decode::event::PersistedInvitationEvent, StorageError> {
    let version_two = InvitationVersion::new(2).map_err(|_| integrity_failure())?;
    let valid = target.version() == InvitationVersion::initial()
        && target.state() == InvitationState::Issued
        && durable.version() == version_two
        && immutable_snapshot_matches(target, durable);
    if !valid {
        return Err(integrity_failure());
    }
    events.get(1).ok_or_else(integrity_failure)
}

fn verify_target_event(
    request: &CommitRequest<'_>,
    events: &[decode::event::PersistedInvitationEvent],
) -> Result<(), StorageError> {
    let index = request
        .transition
        .invitation()
        .version()
        .get()
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(integrity_failure)?;
    let matches = events.get(index).is_some_and(|event| {
        event.matches_transition(request.transition, request.context.request_id())
    });
    if matches {
        Ok(())
    } else {
        Err(integrity_failure())
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

fn persist_creation(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let invitation = request.transition.invitation();
    if let Err(error) = sql::insert_snapshot(session, invitation) {
        return decode::classify_creation_insert_error(session, request, error);
    }
    sql::insert_event(session, request).map_err(map_fresh_evidence_error)
}

fn validate_commit_request(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let principal = validate_authenticated_tenant(request.context, request.tenant_id)?;
    validate_snapshot_binding(request)?;
    validate_event_binding(request, principal)?;
    validate_version_shape(request)
}

fn validate_snapshot_binding(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let invitation = request.transition.invitation();
    let valid = invitation.tenant_id() == request.tenant_id
        && invitation.organization_id() == request.organization_id;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_event_binding(
    request: &CommitRequest<'_>,
    principal: &PrincipalContext,
) -> Result<(), StorageError> {
    let invitation = request.transition.invitation();
    let event = request.transition.event();
    let valid = event.tenant_id() == request.tenant_id
        && event.organization_id() == request.organization_id
        && event.invitation_id() == invitation.id()
        && event.version() == invitation.version()
        && event.actor() == principal.principal_id();
    if valid {
        validate_issuer_actor_rule(invitation, event)
    } else {
        Err(integrity_failure())
    }
}

fn validate_issuer_actor_rule(
    invitation: &Invitation,
    event: &ariadnion_invitation::InvitationEvent,
) -> Result<(), StorageError> {
    if event.kind() != InvitationEventKind::Issued || invitation.issuer() == event.actor() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_version_shape(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let valid = (valid_creation_shape(request) || valid_update_shape(request))
        && valid_lifecycle_matrix(request);
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn valid_creation_shape(request: &CommitRequest<'_>) -> bool {
    let invitation = request.transition.invitation();
    let event = request.transition.event();
    (
        request.expected_previous_version,
        invitation.version(),
        invitation.state(),
        event.kind(),
        event.occurred_at(),
        event.user_id().is_none(),
        invitation.consumed_by().is_none(),
    ) == (
        InvitationVersion::initial(),
        InvitationVersion::initial(),
        InvitationState::Issued,
        InvitationEventKind::Issued,
        invitation.issued_at(),
        true,
        true,
    )
}

fn valid_update_shape(request: &CommitRequest<'_>) -> bool {
    let invitation = request.transition.invitation();
    let event = request.transition.event();
    request
        .expected_previous_version
        .next()
        .is_ok_and(|version| version == invitation.version())
        && event.kind() != InvitationEventKind::Issued
}

fn valid_lifecycle_matrix(request: &CommitRequest<'_>) -> bool {
    let invitation = request.transition.invitation();
    let event = request.transition.event();
    match (event.kind(), invitation.state()) {
        (InvitationEventKind::Issued, InvitationState::Issued) => {
            event.user_id().is_none() && invitation.consumed_by().is_none()
        }
        (InvitationEventKind::Consumed, InvitationState::Consumed) => {
            event.user_id() == invitation.consumed_by()
        }
        (InvitationEventKind::Revoked, InvitationState::Revoked)
        | (InvitationEventKind::Expired, InvitationState::Expired) => {
            event.user_id().is_none() && invitation.consumed_by().is_none()
        }
        _ => false,
    }
}

fn is_creation(request: &CommitRequest<'_>) -> bool {
    request.expected_previous_version == InvitationVersion::initial()
        && request.transition.invitation().version() == InvitationVersion::initial()
        && request.transition.event().kind() == InvitationEventKind::Issued
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
    if principal.tenant_id() != tenant_id {
        return Err(integrity_failure());
    }
    Ok(principal)
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

fn map_storage_error(error: StorageError) -> InvitationRepositoryError {
    repository_error(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(code: StorageErrorCode) -> InvitationRepositoryErrorCode {
    match code {
        StorageErrorCode::NotFound => InvitationRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => InvitationRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => InvitationRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => InvitationRepositoryErrorCode::DeadlineExceeded,
        remaining => map_storage_durability_error_code(remaining),
    }
}

const fn map_storage_durability_error_code(
    code: StorageErrorCode,
) -> InvitationRepositoryErrorCode {
    match code {
        StorageErrorCode::ResourceExhausted => InvitationRepositoryErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => InvitationRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => InvitationRepositoryErrorCode::CommitIndeterminate,
        _ => InvitationRepositoryErrorCode::IntegrityFailure,
    }
}

const fn repository_error(code: InvitationRepositoryErrorCode) -> InvitationRepositoryError {
    InvitationRepositoryError::new(code)
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

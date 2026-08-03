// crates/optional/ariadnion-storage-rnmdb/src/api_key_repository.rs - Rust source for Ariadnion.
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
//! Atomic durable persistence for tenant-bound scoped API keys.

mod decode;
mod evidence;
mod reconcile;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_auth_api_key::{
    ApiKey, ApiKeyCommitReceipt, ApiKeyEventKind, ApiKeyId, ApiKeyPrefix, ApiKeyRepositoryError,
    ApiKeyRepositoryErrorCode, ApiKeyRepositoryPort, ApiKeyState, ApiKeyTransition, ApiKeyVersion,
    MAX_RETIRED_SECRETS,
};
use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_principal_binding::{
    AuthenticatedPrincipalEvidence, PrincipalAuthenticatorCommand, PrincipalAuthenticatorEventKind,
    PrincipalAuthenticatorKind, PrincipalAuthenticatorLink, PrincipalAuthenticatorSourceId,
    PrincipalAuthenticatorState, PrincipalAuthenticatorTransition, PrincipalAuthenticatorVersion,
    PrincipalBinding, link_authenticator, revoke_authenticator,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::LocalSession;

use crate::identity_transaction::{require_active_identity_transaction, run_identity_transaction};
use crate::principal_authenticator_repository::{
    PrincipalAuthenticatorCommitRequest, ReconciledPrincipalAuthenticatorHistory,
    commit_principal_authenticator_in_session,
    reconcile_principal_authenticator_history_by_source_in_session,
};
use crate::principal_binding_repository::load_principal_binding_in_session;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

pub(super) const MAX_API_KEY_EVENT_ROWS: usize = MAX_RETIRED_SECRETS * 2 + 2;

/// Persists complete API-key snapshots and immutable lifecycle evidence.
pub struct RnmdbApiKeyRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbApiKeyRepository {
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

impl ApiKeyRepositoryPort for RnmdbApiKeyRepository {
    fn load(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        api_key_id: &ApiKeyId,
        context: &RequestContext,
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_key(session, tenant_id, user_id, api_key_id)
            })
            .map_err(map_storage_error)
    }

    fn load_by_prefix(
        &self,
        tenant_id: &TenantId,
        prefix: &ApiKeyPrefix,
        context: &RequestContext,
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        validate_routed_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_key_by_prefix(session, tenant_id, prefix)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_version: ApiKeyVersion,
        transition: &ApiKeyTransition,
        context: &RequestContext,
    ) -> Result<ApiKeyCommitReceipt, ApiKeyRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            user_id,
            expected_previous_version,
            transition,
            context,
        };
        validate_commit_binding(&request).map_err(map_storage_error)?;
        let kind = commit_kind(&request).map_err(map_storage_error)?;
        validate_commit_shape(&request, kind).map_err(map_storage_error)?;
        self.session
            .with_identity_transaction_session(context, tenant_id, |session| {
                run_identity_transaction(session, context, |session| {
                    commit_transition(session, &request, &self.audit_subject_key, kind)
                })
            })
            .map_err(map_storage_error)
    }

    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_version: ApiKeyVersion,
        transition: &ApiKeyTransition,
        context: &RequestContext,
    ) -> Result<ApiKeyCommitReceipt, ApiKeyRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            user_id,
            expected_previous_version,
            transition,
            context,
        };
        validate_commit_binding(&request).map_err(map_storage_error)?;
        let kind = commit_kind(&request).map_err(map_storage_error)?;
        validate_commit_shape(&request, kind).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                reconcile::reconcile_exact(session, &request, &self.audit_subject_key)
            })
            .map_err(map_storage_error)
    }
}

pub(super) struct CommitRequest<'a> {
    pub(super) tenant_id: &'a TenantId,
    pub(super) user_id: &'a UserId,
    pub(super) expected_previous_version: ApiKeyVersion,
    pub(super) transition: &'a ApiKeyTransition,
    pub(super) context: &'a RequestContext,
}

pub(crate) fn load_api_key_in_session(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    api_key_id: &ApiKeyId,
) -> Result<ApiKey, StorageError> {
    decode::load_key_by_id(session, tenant_id, api_key_id)
}

pub(crate) fn commit_api_key_in_session(
    session: &mut LocalSession,
    expected_previous_version: ApiKeyVersion,
    transition: &ApiKeyTransition,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<ApiKeyCommitReceipt, StorageError> {
    require_active_identity_transaction(session)?;
    let api_key = transition.key();
    let request = CommitRequest {
        tenant_id: api_key.tenant_id(),
        user_id: api_key.user_id(),
        expected_previous_version,
        transition,
        context,
    };
    validate_commit_binding(&request)?;
    let kind = commit_kind(&request)?;
    validate_commit_shape(&request, kind)?;
    commit_transition(session, &request, key, kind)
}

#[derive(Clone, Copy)]
enum CommitKind {
    Issuance,
    Rotation,
    RotationCompletion,
    Revocation,
    Expiry,
}

fn commit_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
    kind: CommitKind,
) -> Result<ApiKeyCommitReceipt, StorageError> {
    match kind {
        CommitKind::Issuance => commit_issuance(session, request, subject_key),
        CommitKind::Rotation => commit_rotation(session, request, subject_key),
        CommitKind::RotationCompletion => commit_rotation_completion(session, request, subject_key),
        CommitKind::Revocation | CommitKind::Expiry => {
            commit_terminal(session, request, subject_key)
        }
    }
}

fn commit_issuance(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ApiKeyCommitReceipt, StorageError> {
    let authenticator = issuance_authenticator_transition(session, request)?;
    persist_issued_key(session, request)?;
    let committed_at = trusted_commit_time()?;
    persist_paired_issuance_evidence(session, request, &authenticator, subject_key, committed_at)?;
    Ok(commit_receipt(request, committed_at))
}

fn persist_issued_key(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let key = request.transition.key();
    decode::ensure_issuance_absent(session, request)?;
    sql::insert_key(session, key)?;
    sql::insert_scopes(session, key)?;
    sql::insert_retired(session, key)?;
    sql::insert_event(session, request)
}

fn persist_paired_issuance_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    authenticator: &PrincipalAuthenticatorTransition,
    subject_key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    evidence::persist_transition_evidence(session, request, subject_key, committed_at)?;
    persist_authenticator_transition(session, request, authenticator, subject_key, committed_at)
}

fn issuance_authenticator_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<PrincipalAuthenticatorTransition, StorageError> {
    let principal = authenticated_principal(request.context)?;
    let binding =
        load_principal_binding_in_session(session, request.tenant_id, principal.principal_id())
            .map_err(map_linkage_dependency_error)?;
    link_authenticator(
        &binding,
        PrincipalAuthenticatorKind::ApiKey,
        api_key_authenticator_source(request.transition.key().id())?,
        request.transition.event().actor().clone(),
        request.context.request_id().clone(),
        request.transition.event().occurred_at(),
    )
    .map_err(|_| integrity_failure())
}

fn api_key_authenticator_source(
    api_key_id: &ApiKeyId,
) -> Result<PrincipalAuthenticatorSourceId, StorageError> {
    PrincipalAuthenticatorSourceId::parse(api_key_id.as_str()).map_err(|_| integrity_failure())
}

fn persist_authenticator_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    transition: &PrincipalAuthenticatorTransition,
    subject_key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    let authenticator_request = PrincipalAuthenticatorCommitRequest::new(
        request.tenant_id,
        transition.authenticator_id(),
        transition.expected_previous_version(),
        transition,
        request.context,
    );
    commit_principal_authenticator_in_session(
        session,
        &authenticator_request,
        subject_key,
        committed_at,
    )
    .map(|_| ())
}

fn commit_rotation(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ApiKeyCommitReceipt, StorageError> {
    let durable = decode::load_key(
        session,
        request.tenant_id,
        request.user_id,
        request.transition.key().id(),
    )?;
    validate_rotation_precondition(request, &durable)?;
    validate_active_api_key_authenticator(session, request, &durable, subject_key)?;
    sql::update_rotation(session, request, &durable)?;
    sql::insert_event(session, request)?;
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, subject_key, committed_at)?;
    Ok(commit_receipt(request, committed_at))
}

fn commit_rotation_completion(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ApiKeyCommitReceipt, StorageError> {
    let durable = decode::load_key(
        session,
        request.tenant_id,
        request.user_id,
        request.transition.key().id(),
    )?;
    validate_completion_precondition(request, &durable)?;
    validate_active_api_key_authenticator(session, request, &durable, subject_key)?;
    persist_rotation_completion_rows(session, request, &durable)?;
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, subject_key, committed_at)?;
    Ok(commit_receipt(request, committed_at))
}

fn persist_rotation_completion_rows(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    sql::update_rotation_completion(session, request, durable)?;
    sql::insert_retired_at(
        session,
        request.transition.key(),
        durable.retired_secrets().len(),
    )?;
    sql::insert_event(session, request)
}

fn validate_active_api_key_authenticator(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<(), StorageError> {
    let history = reconcile_api_key_authenticator_history(session, request, subject_key)?;
    validate_active_link_history(&history)?;
    let issuance_actor = decode::issuance_actor(session, durable)?;
    validate_update_principal(request, history.link(), &issuance_actor)?;
    let binding = load_authenticator_binding(session, request, history.link())?;
    AuthenticatedPrincipalEvidence::from_active_link(history.link(), &binding)
        .map(|_| ())
        .map_err(|_| integrity_failure())
}

fn reconcile_api_key_authenticator_history(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ReconciledPrincipalAuthenticatorHistory, StorageError> {
    let source = api_key_authenticator_source(request.transition.key().id())?;
    reconcile_principal_authenticator_history_by_source_in_session(
        session,
        request.tenant_id,
        PrincipalAuthenticatorKind::ApiKey,
        &source,
        subject_key,
        request.context,
    )
    .map_err(map_reconcile_error)
}

fn validate_active_link_history(
    history: &ReconciledPrincipalAuthenticatorHistory,
) -> Result<(), StorageError> {
    let link = history.link();
    let linked = history.facts().first().ok_or_else(integrity_failure)?;
    let valid = link.version() == PrincipalAuthenticatorVersion::initial()
        && link.state() == PrincipalAuthenticatorState::Active
        && link.revoked_at().is_none()
        && history.facts().len() == 1
        && linked.kind() == PrincipalAuthenticatorEventKind::Linked;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_update_principal(
    request: &CommitRequest<'_>,
    link: &PrincipalAuthenticatorLink,
    issuance_actor: &ariadnion_core::PrincipalId,
) -> Result<(), StorageError> {
    let actor = request.transition.event().actor();
    let valid = link.principal_id() == issuance_actor && actor == link.principal_id();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn load_authenticator_binding(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    link: &PrincipalAuthenticatorLink,
) -> Result<PrincipalBinding, StorageError> {
    load_principal_binding_in_session(session, request.tenant_id, link.principal_id())
        .map_err(map_linkage_dependency_error)
}

fn commit_terminal(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ApiKeyCommitReceipt, StorageError> {
    let durable = decode::load_key(
        session,
        request.tenant_id,
        request.user_id,
        request.transition.key().id(),
    )?;
    validate_terminal_precondition(request, &durable)?;
    let authenticator = terminal_authenticator_transition(session, request, &durable, subject_key)?;
    persist_terminal_rows(session, request, &durable)?;
    let committed_at = trusted_commit_time()?;
    persist_paired_terminal_evidence(session, request, &authenticator, subject_key, committed_at)?;
    Ok(commit_receipt(request, committed_at))
}

fn persist_terminal_rows(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    sql::update_terminal(session, request, durable)?;
    persist_terminal_retirement(session, request.transition.key(), durable)?;
    sql::insert_event(session, request)
}

fn terminal_authenticator_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<PrincipalAuthenticatorTransition, StorageError> {
    let history = reconcile_api_key_authenticator_history(session, request, subject_key)?;
    validate_active_link_history(&history)?;
    let issuance_actor = decode::issuance_actor(session, durable)?;
    if history.link().principal_id() != &issuance_actor {
        return Err(integrity_failure());
    }
    let event = request.transition.event();
    revoke_authenticator(
        history.link(),
        PrincipalAuthenticatorCommand::new(
            history.link().version(),
            event.actor().clone(),
            request.context.request_id().clone(),
            event.occurred_at(),
        ),
    )
    .map_err(|_| integrity_failure())
}

fn persist_paired_terminal_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    authenticator: &PrincipalAuthenticatorTransition,
    subject_key: &AuditSubjectKeyMaterial,
    committed_at: UtcTimestamp,
) -> Result<(), StorageError> {
    evidence::persist_transition_evidence(session, request, subject_key, committed_at)?;
    persist_authenticator_transition(session, request, authenticator, subject_key, committed_at)
}

fn persist_terminal_retirement(
    session: &mut LocalSession,
    target: &ApiKey,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    if target.retired_secrets().len() == durable.retired_secrets().len() {
        return Ok(());
    }
    sql::insert_retired_at(session, target, durable.retired_secrets().len())
}

fn commit_receipt(request: &CommitRequest<'_>, committed_at: UtcTimestamp) -> ApiKeyCommitReceipt {
    let key = request.transition.key();
    ApiKeyCommitReceipt::new(
        request.tenant_id.clone(),
        request.user_id.clone(),
        key.id().clone(),
        key.version(),
        committed_at,
    )
}

fn validate_commit_binding(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let principal = validate_authenticated_tenant(request.context, request.tenant_id)?;
    validate_key_binding(request)?;
    validate_event_binding(request, principal)
}

fn validate_key_binding(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let key = request.transition.key();
    if key.tenant_id() == request.tenant_id && key.user_id() == request.user_id {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_event_binding(
    request: &CommitRequest<'_>,
    principal: &PrincipalContext,
) -> Result<(), StorageError> {
    let key = request.transition.key();
    let event = request.transition.event();
    let valid = event.tenant_id() == request.tenant_id
        && event.user_id() == request.user_id
        && event.key_id() == key.id()
        && event.version() == key.version()
        && event.actor() == principal.principal_id();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_issuance_shape(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    validate_initial_version(request)?;
    validate_initial_state(request)
}

fn validate_commit_shape(
    request: &CommitRequest<'_>,
    kind: CommitKind,
) -> Result<(), StorageError> {
    match kind {
        CommitKind::Issuance => validate_issuance_shape(request),
        CommitKind::Rotation => validate_rotation_shape(request),
        CommitKind::RotationCompletion => validate_completion_shape(request),
        CommitKind::Revocation => {
            validate_terminal_shape(request, ApiKeyEventKind::Revoked, ApiKeyState::Revoked)
        }
        CommitKind::Expiry => {
            validate_terminal_shape(request, ApiKeyEventKind::Expired, ApiKeyState::Expired)
        }
    }
}

fn validate_rotation_shape(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let key = request.transition.key();
    let event = request.transition.event();
    let next = request
        .expected_previous_version
        .get()
        .checked_add(1)
        .ok_or_else(integrity_failure)?;
    let valid = key.version().get() == next
        && event.kind() == ApiKeyEventKind::Rotated
        && key.state() == ApiKeyState::Rotating
        && key.previous_secret().is_some()
        && key.rotation_started_at() == Some(event.occurred_at())
        && key.previous_secret_expires_at().is_some();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_completion_shape(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let key = request.transition.key();
    let event = request.transition.event();
    let next = request
        .expected_previous_version
        .get()
        .checked_add(1)
        .ok_or_else(integrity_failure)?;
    let valid = key.version().get() == next
        && event.kind() == ApiKeyEventKind::RotationCompleted
        && key.state() == ApiKeyState::Active
        && key.previous_secret().is_none()
        && key.rotation_started_at().is_none()
        && key.previous_secret_expires_at().is_none();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_terminal_shape(
    request: &CommitRequest<'_>,
    event_kind: ApiKeyEventKind,
    state: ApiKeyState,
) -> Result<(), StorageError> {
    let key = request.transition.key();
    let event = request.transition.event();
    let next = request
        .expected_previous_version
        .get()
        .checked_add(1)
        .ok_or_else(integrity_failure)?;
    let valid = key.version().get() == next
        && event.kind() == event_kind
        && key.state() == state
        && key.previous_secret().is_none()
        && key.rotation_started_at().is_none()
        && key.previous_secret_expires_at().is_none();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_rotation_precondition(
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    if durable.version() != request.expected_previous_version {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    validate_rotation_snapshot(durable, request.transition.key())
}

fn validate_rotation_snapshot(durable: &ApiKey, target: &ApiKey) -> Result<(), StorageError> {
    if !immutable_fields_match(durable, target) {
        return Err(integrity_failure());
    }
    let matches = durable.retired_secrets() == target.retired_secrets()
        && rotation_state_matches(durable, target);
    matches
        .then_some(())
        .ok_or_else(|| StorageError::new(StorageErrorCode::Conflict))
}

fn immutable_fields_match(durable: &ApiKey, target: &ApiKey) -> bool {
    durable.id() == target.id()
        && durable.tenant_id() == target.tenant_id()
        && durable.user_id() == target.user_id()
        && durable.prefix() == target.prefix()
        && durable.scopes() == target.scopes()
        && durable.issued_at() == target.issued_at()
        && durable.expires_at() == target.expires_at()
}

fn rotation_state_matches(durable: &ApiKey, target: &ApiKey) -> bool {
    durable.state() == ApiKeyState::Active
        && durable.previous_secret().is_none()
        && durable.rotation_started_at().is_none()
        && durable.previous_secret_expires_at().is_none()
        && target.previous_secret() == Some(durable.current_secret())
}

fn validate_completion_precondition(
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    if durable.version() != request.expected_previous_version {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    let target = request.transition.key();
    if !immutable_fields_match(durable, target) {
        return Err(integrity_failure());
    }
    completion_state_matches(durable, target)
        .then_some(())
        .ok_or_else(|| StorageError::new(StorageErrorCode::Conflict))
}

fn completion_state_matches(durable: &ApiKey, target: &ApiKey) -> bool {
    let expected_retired = durable
        .previous_secret()
        .and_then(|previous| appended_retired_matches(durable, target, previous));
    durable.state() == ApiKeyState::Rotating
        && durable.rotation_started_at().is_some()
        && durable.previous_secret_expires_at().is_some()
        && target.current_secret() == durable.current_secret()
        && expected_retired.is_some()
}

fn appended_retired_matches(
    durable: &ApiKey,
    target: &ApiKey,
    previous: ariadnion_auth_api_key::ApiKeySecretDigest,
) -> Option<()> {
    let expected_len = durable.retired_secrets().len().checked_add(1)?;
    let (last, prefix) = target.retired_secrets().split_last()?;
    (target.retired_secrets().len() == expected_len
        && prefix == durable.retired_secrets()
        && *last == previous)
        .then_some(())
}

fn validate_terminal_precondition(
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    if durable.version() != request.expected_previous_version {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    let target = request.transition.key();
    if !immutable_fields_match(durable, target) {
        return Err(integrity_failure());
    }
    terminal_state_matches(durable, target)
        .then_some(())
        .ok_or_else(|| StorageError::new(StorageErrorCode::Conflict))
}

fn terminal_state_matches(durable: &ApiKey, target: &ApiKey) -> bool {
    let source_is_usable = matches!(durable.state(), ApiKeyState::Active | ApiKeyState::Rotating);
    source_is_usable
        && target.current_secret() == durable.current_secret()
        && terminal_retirement_matches(durable, target)
}

fn terminal_retirement_matches(durable: &ApiKey, target: &ApiKey) -> bool {
    match durable.previous_secret() {
        Some(previous) => appended_retired_matches(durable, target, previous).is_some(),
        None => target.retired_secrets() == durable.retired_secrets(),
    }
}

fn validate_initial_version(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let key = request.transition.key();
    let event = request.transition.event();
    let valid = request.expected_previous_version == ApiKeyVersion::initial()
        && key.version() == ApiKeyVersion::initial()
        && event.kind() == ApiKeyEventKind::Issued
        && event.occurred_at() == key.issued_at();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_initial_state(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let key = request.transition.key();
    let valid = key.state() == ApiKeyState::Active
        && key.previous_secret().is_none()
        && key.rotation_started_at().is_none()
        && key.previous_secret_expires_at().is_none()
        && key.retired_secrets().is_empty();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn is_issuance(request: &CommitRequest<'_>) -> bool {
    request.expected_previous_version == ApiKeyVersion::initial()
        && request.transition.key().version() == ApiKeyVersion::initial()
        && request.transition.event().kind() == ApiKeyEventKind::Issued
}

fn commit_kind(request: &CommitRequest<'_>) -> Result<CommitKind, StorageError> {
    match request.transition.event().kind() {
        ApiKeyEventKind::Issued if is_issuance(request) => Ok(CommitKind::Issuance),
        ApiKeyEventKind::Rotated => Ok(CommitKind::Rotation),
        ApiKeyEventKind::RotationCompleted => Ok(CommitKind::RotationCompletion),
        ApiKeyEventKind::Revoked => Ok(CommitKind::Revocation),
        ApiKeyEventKind::Expired => Ok(CommitKind::Expiry),
        _ => Err(StorageError::new(StorageErrorCode::Unavailable)),
    }
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

fn map_storage_error(error: StorageError) -> ApiKeyRepositoryError {
    repository_error(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(code: StorageErrorCode) -> ApiKeyRepositoryErrorCode {
    match code {
        StorageErrorCode::NotFound => ApiKeyRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => ApiKeyRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => ApiKeyRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => ApiKeyRepositoryErrorCode::DeadlineExceeded,
        remaining => map_storage_durability_error_code(remaining),
    }
}

const fn map_storage_durability_error_code(code: StorageErrorCode) -> ApiKeyRepositoryErrorCode {
    match code {
        StorageErrorCode::ResourceExhausted => ApiKeyRepositoryErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => ApiKeyRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => ApiKeyRepositoryErrorCode::CommitIndeterminate,
        _ => ApiKeyRepositoryErrorCode::IntegrityFailure,
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

const fn repository_error(code: ApiKeyRepositoryErrorCode) -> ApiKeyRepositoryError {
    ApiKeyRepositoryError::new(code)
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

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

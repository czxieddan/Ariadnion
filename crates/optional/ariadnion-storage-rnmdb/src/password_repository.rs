// crates/optional/ariadnion-storage-rnmdb/src/password_repository.rs - Rust source for Ariadnion.
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
//! Atomic durable persistence for tenant-bound password recovery.

mod decode;
mod evidence;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_auth_password::{
    PasswordCommitReceipt, PasswordCredential, PasswordRepositoryError,
    PasswordRepositoryErrorCode, PasswordRepositoryPort, PasswordReset, PasswordResetCommit,
    PasswordResetEventKind, PasswordResetState, PasswordResetTokenDigest, PasswordResetVersion,
};
use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::LocalSession;

use crate::identity_transaction::run_identity_transaction;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Persists password credentials, resets, and their atomic security evidence.
pub struct RnmdbPasswordRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbPasswordRepository {
    /// Opens a repository over a newly created serialized RNMDB session.
    ///
    /// A repository whose commit outcome was indeterminate must be discarded.
    /// Reconciliation uses a freshly opened repository with the same database
    /// and audit-subject key material.
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

impl PasswordRepositoryPort for RnmdbPasswordRepository {
    fn load_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        context: &RequestContext,
    ) -> Result<PasswordCredential, PasswordRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_credential(session, tenant_id, user_id)
            })
            .map_err(map_storage_error)
    }

    fn load_reset(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        reset_id: &ariadnion_auth_password::PasswordResetId,
        context: &RequestContext,
    ) -> Result<PasswordReset, PasswordRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_reset(session, tenant_id, user_id, reset_id)
            })
            .map_err(map_storage_error)
    }

    fn load_reset_by_token_digest(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        token_digest: PasswordResetTokenDigest,
        context: &RequestContext,
    ) -> Result<PasswordReset, PasswordRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                decode::load_reset_by_token(session, tenant_id, user_id, token_digest)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_reset_version: PasswordResetVersion,
        commit: &PasswordResetCommit<'_>,
        context: &RequestContext,
    ) -> Result<PasswordCommitReceipt, PasswordRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            user_id,
            expected_previous_reset_version,
            commit,
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
        expected_previous_reset_version: PasswordResetVersion,
        commit: &PasswordResetCommit<'_>,
        context: &RequestContext,
    ) -> Result<PasswordCommitReceipt, PasswordRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            user_id,
            expected_previous_reset_version,
            commit,
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
    pub(super) user_id: &'a UserId,
    pub(super) expected_previous_reset_version: PasswordResetVersion,
    pub(super) commit: &'a PasswordResetCommit<'a>,
    pub(super) context: &'a RequestContext,
}

impl CommitRequest<'_> {
    pub(super) const fn transition(&self) -> &ariadnion_auth_password::PasswordResetTransition {
        self.commit.transition()
    }
}

fn commit_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<PasswordCommitReceipt, StorageError> {
    persist_commit_state(session, request)?;
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, key, committed_at)?;
    Ok(receipt(request, committed_at))
}

fn persist_commit_state(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    match request.commit {
        PasswordResetCommit::Issuance(issuance) => persist_issuance(session, request, issuance),
        PasswordResetCommit::ResetOnly(_) => persist_reset_update(session, request),
        PasswordResetCommit::CredentialReplacement(_) => persist_consumption(session, request),
    }
}

fn persist_issuance(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    issuance: &ariadnion_auth_password::PasswordResetIssuanceCommit<'_>,
) -> Result<(), StorageError> {
    let current = optional_credential(session, request.tenant_id, request.user_id)?;
    issuance
        .verify_current_credential(current.as_ref())
        .map_err(map_repository_error)?;
    decode::ensure_issuance_absent(session, request)?;
    sql::insert_reset(session, request.transition().reset())?;
    persist_reset_records(session, request)
}

fn persist_reset_update(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    validate_durable_reset(session, request)?;
    sql::update_reset(session, request)?;
    persist_reset_records(session, request)
}

fn persist_consumption(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    validate_durable_reset(session, request)?;
    let replacement = request
        .commit
        .credential_replacement()
        .ok_or_else(integrity_failure)?;
    let current = decode::load_credential(session, request.tenant_id, request.user_id)?;
    validate_replacement_source(&current, replacement)?;
    sql::update_credential(session, request, replacement)?;
    sql::update_reset(session, request)?;
    persist_reset_records(session, request)
}

fn persist_reset_records(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    sql::insert_event(session, request).map_err(map_fresh_evidence_error)?;
    sql::insert_commit_evidence(session, request).map_err(map_fresh_evidence_error)
}

fn optional_credential(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
) -> Result<Option<PasswordCredential>, StorageError> {
    match decode::load_credential(session, tenant, user) {
        Ok(credential) => Ok(Some(credential)),
        Err(error) if error.code() == StorageErrorCode::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_durable_reset(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let durable = decode::load_reset(
        session,
        request.tenant_id,
        request.user_id,
        request.transition().reset().id(),
    )?;
    let target = request.transition().reset();
    let valid = durable.version() == request.expected_previous_reset_version
        && durable.state() == PasswordResetState::Issued
        && immutable_reset_matches(&durable, target);
    if valid { Ok(()) } else { Err(conflict()) }
}

fn validate_replacement_source(
    current: &PasswordCredential,
    replacement: &ariadnion_auth_password::PasswordCredentialReplacement,
) -> Result<(), StorageError> {
    let target = replacement.credential();
    let valid = current.version() == replacement.expected_version()
        && current.tenant_id() == target.tenant_id()
        && current.user_id() == target.user_id();
    if valid { Ok(()) } else { Err(conflict()) }
}

fn reconcile_exact(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<PasswordCommitReceipt, StorageError> {
    let target = request.transition().reset();
    let loaded =
        decode::load_reset_with_history(session, request.tenant_id, request.user_id, target.id())
            .map_err(map_reconcile_error)?;
    validate_reconciled_reset(target, &loaded.reset)?;
    decode::verify_target_records(request, &loaded)?;
    verify_reconciled_credential(session, request)?;
    let committed_at = evidence::reconcile_transition_evidence(session, request, key)?;
    Ok(receipt(request, committed_at))
}

fn validate_reconciled_reset(
    target: &PasswordReset,
    durable: &PasswordReset,
) -> Result<(), StorageError> {
    if durable == target || valid_later_reset(target, durable) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn valid_later_reset(target: &PasswordReset, durable: &PasswordReset) -> bool {
    target.state() == PasswordResetState::Issued
        && target.version() == PasswordResetVersion::initial()
        && target
            .version()
            .next()
            .is_ok_and(|version| durable.version() == version)
        && durable.state() != PasswordResetState::Issued
        && immutable_reset_matches(target, durable)
}

fn verify_reconciled_credential(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let Some(replacement) = request.commit.credential_replacement() else {
        return Ok(());
    };
    let durable = decode::load_credential(session, request.tenant_id, request.user_id)?;
    if durable == *replacement.credential() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn receipt(request: &CommitRequest<'_>, committed_at: UtcTimestamp) -> PasswordCommitReceipt {
    let reset = request.transition().reset();
    PasswordCommitReceipt::new(
        request.tenant_id.clone(),
        request.user_id.clone(),
        reset.id().clone(),
        reset.version(),
        request
            .commit
            .credential_replacement()
            .map(|replacement| replacement.resulting_version()),
        committed_at,
    )
}

fn validate_commit_request(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let principal = validate_authenticated_tenant(request.context, request.tenant_id)?;
    validate_transition_boundary(request, principal)?;
    validate_version_shape(request)
}

fn validate_transition_boundary(
    request: &CommitRequest<'_>,
    principal: &PrincipalContext,
) -> Result<(), StorageError> {
    let reset = request.transition().reset();
    let event = request.transition().event();
    let valid =
        reset_boundary_matches(request, reset) && event_boundary_matches(request, event, principal);
    if valid {
        validate_replacement_boundary(request)
    } else {
        Err(integrity_failure())
    }
}

fn reset_boundary_matches(request: &CommitRequest<'_>, reset: &PasswordReset) -> bool {
    reset.tenant_id() == request.tenant_id && reset.user_id() == request.user_id
}

fn event_boundary_matches(
    request: &CommitRequest<'_>,
    event: &ariadnion_auth_password::PasswordResetEvent,
    principal: &PrincipalContext,
) -> bool {
    let reset = request.transition().reset();
    event.tenant_id() == request.tenant_id
        && event.user_id() == request.user_id
        && event.reset_id() == reset.id()
        && event.version() == reset.version()
        && event.issued_credential_version() == reset.issued_credential_version()
        && event.actor() == principal.principal_id()
}

fn validate_replacement_boundary(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let Some(replacement) = request.commit.credential_replacement() else {
        return Ok(());
    };
    let target = replacement.credential();
    let reset = request.transition().reset();
    let valid = replacement.expected_version() == reset.issued_credential_version()
        && target.tenant_id() == request.tenant_id
        && target.user_id() == request.user_id;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_version_shape(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let reset = request.transition().reset();
    let event = request.transition().event();
    let valid = match request.commit {
        PasswordResetCommit::Issuance(_) => {
            request.expected_previous_reset_version == PasswordResetVersion::initial()
                && reset.version() == PasswordResetVersion::initial()
                && event.kind() == PasswordResetEventKind::Issued
        }
        PasswordResetCommit::ResetOnly(_) | PasswordResetCommit::CredentialReplacement(_) => {
            request
                .expected_previous_reset_version
                .next()
                .is_ok_and(|version| version == reset.version())
                && event.kind() != PasswordResetEventKind::Issued
        }
    };
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn immutable_reset_matches(previous: &PasswordReset, target: &PasswordReset) -> bool {
    (
        previous.id(),
        previous.tenant_id(),
        previous.user_id(),
        previous.token_digest(),
        previous.issued_credential_version(),
        previous.issued_at(),
        previous.expires_at(),
        previous.purpose(),
    ) == (
        target.id(),
        target.tenant_id(),
        target.user_id(),
        target.token_digest(),
        target.issued_credential_version(),
        target.issued_at(),
        target.expires_at(),
        target.purpose(),
    )
}

pub(super) fn authenticated_principal(
    context: &RequestContext,
) -> Result<&PrincipalContext, StorageError> {
    context.principal().ok_or_else(integrity_failure)
}

fn validate_authenticated_tenant<'a>(
    context: &'a RequestContext,
    tenant: &TenantId,
) -> Result<&'a PrincipalContext, StorageError> {
    let principal = authenticated_principal(context)?;
    if principal.tenant_id() == tenant {
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

fn map_repository_error(error: PasswordRepositoryError) -> StorageError {
    match error.code() {
        PasswordRepositoryErrorCode::Conflict => conflict(),
        _ => integrity_failure(),
    }
}

fn map_storage_error(error: StorageError) -> PasswordRepositoryError {
    PasswordRepositoryError::new(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(code: StorageErrorCode) -> PasswordRepositoryErrorCode {
    match code {
        StorageErrorCode::NotFound => PasswordRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => PasswordRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => PasswordRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => PasswordRepositoryErrorCode::DeadlineExceeded,
        remaining => map_storage_durability_error_code(remaining),
    }
}

const fn map_storage_durability_error_code(code: StorageErrorCode) -> PasswordRepositoryErrorCode {
    match code {
        StorageErrorCode::ResourceExhausted => PasswordRepositoryErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => PasswordRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => PasswordRepositoryErrorCode::CommitIndeterminate,
        _ => PasswordRepositoryErrorCode::IntegrityFailure,
    }
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

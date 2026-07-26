//! Atomic durable persistence for tenant-bound scoped API keys.

mod decode;
mod evidence;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_auth_api_key::{
    ApiKey, ApiKeyCommitReceipt, ApiKeyEventKind, ApiKeyId, ApiKeyPrefix, ApiKeyRepositoryError,
    ApiKeyRepositoryErrorCode, ApiKeyRepositoryPort, ApiKeyState, ApiKeyTransition, ApiKeyVersion,
    MAX_RETIRED_SECRETS,
};
use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::LocalSession;

use crate::identity_transaction::run_identity_transaction;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

pub(super) const MAX_API_KEY_EVENT_ROWS: usize = MAX_RETIRED_SECRETS * 2 + 2;

/// Persists complete API-key snapshots and immutable issuance evidence.
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
            .with_storage_session(context, |session| {
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
            .with_storage_session(context, |session| {
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
        if !is_issuance(&request) {
            return Err(repository_error(ApiKeyRepositoryErrorCode::Unavailable));
        }
        validate_issuance_shape(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_session(context, |session| {
                run_identity_transaction(session, context, |session| {
                    commit_issuance(session, &request, &self.audit_subject_key)
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
        Err(repository_error(ApiKeyRepositoryErrorCode::Unavailable))
    }
}

pub(super) struct CommitRequest<'a> {
    pub(super) tenant_id: &'a TenantId,
    pub(super) user_id: &'a UserId,
    pub(super) expected_previous_version: ApiKeyVersion,
    pub(super) transition: &'a ApiKeyTransition,
    pub(super) context: &'a RequestContext,
}

fn commit_issuance(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ApiKeyCommitReceipt, StorageError> {
    let key = request.transition.key();
    decode::ensure_issuance_absent(session, request)?;
    sql::insert_key(session, key)?;
    sql::insert_scopes(session, key)?;
    sql::insert_retired(session, key)?;
    sql::insert_event(session, request.transition.event(), key)?;
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, subject_key, committed_at)?;
    Ok(commit_receipt(request, committed_at))
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
    let code = match error.code() {
        StorageErrorCode::NotFound => ApiKeyRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => ApiKeyRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => ApiKeyRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => ApiKeyRepositoryErrorCode::DeadlineExceeded,
        StorageErrorCode::ResourceExhausted => ApiKeyRepositoryErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => ApiKeyRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => ApiKeyRepositoryErrorCode::CommitIndeterminate,
        _ => ApiKeyRepositoryErrorCode::IntegrityFailure,
    };
    repository_error(code)
}

const fn repository_error(code: ApiKeyRepositoryErrorCode) -> ApiKeyRepositoryError {
    ApiKeyRepositoryError::new(code)
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

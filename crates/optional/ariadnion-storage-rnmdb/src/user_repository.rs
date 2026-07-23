//! Atomic durable persistence for tenant-bound user lifecycle transitions.

mod decode;
mod evidence;
mod reconcile;
mod sql;

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_storage_outbox::EnqueueStatus;
use ariadnion_user_domain::{User, UserId, UserTransition, UserVersion, UtcTimestamp};
use ariadnion_user_service::{
    UserCommitReceipt, UserRepositoryError, UserRepositoryErrorCode, UserRepositoryPort,
};
use rnmdb_cli::LocalSession;
use zeroize::{Zeroize, ZeroizeOnDrop};

use self::evidence::{
    LifecycleRecord, SnapshotRecord, TransitionEvidence, TransitionIdentity,
    TransitionIdentityRecord, identity_from_record,
};
use crate::audit_repository::{append_in_transaction, load_event_by_id, load_head_from_session};
use crate::identity_transaction::run_identity_transaction;
use crate::outbox::enqueue_message;
use crate::{RnmdbSessionOwner, SessionOpenOptions};

/// Secret key material used to pseudonymize durable audit subjects.
pub struct AuditSubjectKeyMaterial {
    bytes: [u8; 32],
}

impl AuditSubjectKeyMaterial {
    /// Takes ownership of exactly 32 secret bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Zeroize for AuditSubjectKeyMaterial {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for AuditSubjectKeyMaterial {}

impl Drop for AuditSubjectKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Persists exact user snapshots and their immutable transition evidence.
pub struct RnmdbUserRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbUserRepository {
    /// Opens a repository over a newly created serialized RNMDB session.
    ///
    /// Use this constructor for read reconciliation after a prior commit
    /// returned `USER_REPOSITORY_COMMIT_INDETERMINATE`. The prior repository
    /// and its tainted session owner must be discarded; callers must provide
    /// the same database and audit-subject keys through fresh secret material.
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
    /// Wrapping a tainted session owner does not recover it; use [`Self::open`]
    /// with fresh open options after an indeterminate commit.
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

impl UserRepositoryPort for RnmdbUserRepository {
    fn load(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        context: &RequestContext,
    ) -> Result<User, UserRepositoryError> {
        self.session
            .with_storage_session(context, |session| {
                validate_authenticated_tenant(context, tenant_id)?;
                decode::load_user(session, tenant_id, user_id)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: UserVersion,
        transition: &UserTransition,
        context: &RequestContext,
    ) -> Result<UserCommitReceipt, UserRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            expected_previous_version,
            transition,
            context,
        };
        self.session
            .with_identity_session(context, |session| {
                run_identity_transaction(session, context, |session| {
                    commit_in_transaction(session, &request, &self.audit_subject_key)
                })
            })
            .map_err(map_storage_error)
    }

    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: UserVersion,
        transition: &UserTransition,
        context: &RequestContext,
    ) -> Result<UserCommitReceipt, UserRepositoryError> {
        let request = CommitRequest {
            tenant_id,
            expected_previous_version,
            transition,
            context,
        };
        self.session
            .with_storage_session(context, |session| {
                reconcile::reconcile_commit(session, &request, &self.audit_subject_key)
            })
            .map_err(map_storage_error)
    }
}

pub(super) struct CommitRequest<'a> {
    tenant_id: &'a TenantId,
    expected_previous_version: UserVersion,
    transition: &'a UserTransition,
    context: &'a RequestContext,
}

fn commit_in_transaction(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<UserCommitReceipt, StorageError> {
    let identity = apply_transition(session, request, key)?;
    persist_transition_evidence(session, request, identity)
}

fn apply_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<TransitionIdentity, StorageError> {
    validate_commit_request(request)?;
    let identity = transition_identity(request, key)?;
    sql::compare_and_update_user(session, &identity)?;
    sql::insert_lifecycle_event(session, &identity)?;
    Ok(identity)
}

fn transition_identity(
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
) -> Result<TransitionIdentity, StorageError> {
    let principal = authenticated_principal(request.context)?;
    let user = request.transition.user();
    identity_from_record(
        TransitionIdentityRecord {
            tenant_id: request.tenant_id.clone(),
            user_id: user.id().clone(),
            previous_version: request.expected_previous_version,
            new_version: user.version(),
            actor: principal.principal_id().clone(),
            request_id: request.context.request_id().clone(),
            snapshot: SnapshotRecord::from_state(user.snapshot_state()),
            lifecycle: LifecycleRecord::from_event(request.transition.event()),
        },
        key,
    )
}

fn persist_transition_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    identity: TransitionIdentity,
) -> Result<UserCommitReceipt, StorageError> {
    let committed_at = trusted_commit_time()?;
    let evidence = TransitionEvidence::new(identity, committed_at)?;
    append_fresh_audit(session, request, &evidence)?;
    enqueue_fresh_outbox(session, &evidence)?;
    Ok(evidence.receipt())
}

fn append_fresh_audit(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    let head = load_head_from_session(session, request.tenant_id)?;
    let event = evidence.audit_event_after(&head)?;
    if load_event_by_id(session, request.tenant_id, event.id())?.is_some() {
        return Err(integrity_failure());
    }
    let principal = authenticated_principal(request.context)?;
    append_in_transaction(session, principal, &head, &event)
        .map(|_| ())
        .map_err(map_fresh_collision)
}

fn enqueue_fresh_outbox(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
) -> Result<(), StorageError> {
    let message = evidence.outbox_message()?;
    match enqueue_message(session, evidence.identity().tenant_id(), &message) {
        Ok(EnqueueStatus::Inserted) => Ok(()),
        Ok(EnqueueStatus::AlreadyExists) => Err(integrity_failure()),
        Err(error) => Err(map_fresh_collision(error)),
    }
}

pub(super) fn validate_commit_request(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    validate_authenticated_tenant(request.context, request.tenant_id)?;
    validate_user_binding(request)?;
    validate_event_binding(request)?;
    validate_version_step(request)
}

fn validate_user_binding(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let user = request.transition.user();
    if user.tenant_id() != request.tenant_id {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_event_binding(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let user = request.transition.user();
    let event = request.transition.event();
    let valid = event.tenant_id() == request.tenant_id
        && event.user_id() == user.id()
        && event.version() == user.version();
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_version_step(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let expected = request
        .expected_previous_version
        .next()
        .map_err(|_| integrity_failure())?;
    if request.transition.user().version() != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn authenticated_principal(
    context: &RequestContext,
) -> Result<&PrincipalContext, StorageError> {
    context.principal().ok_or_else(integrity_failure)
}

fn validate_authenticated_tenant(
    context: &RequestContext,
    tenant_id: &TenantId,
) -> Result<(), StorageError> {
    if authenticated_principal(context)?.tenant_id() != tenant_id {
        return Err(integrity_failure());
    }
    Ok(())
}

fn trusted_commit_time() -> Result<UtcTimestamp, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure())?;
    let wall_clock = i64::try_from(duration.as_secs()).map_err(|_| integrity_failure())?;
    Ok(UtcTimestamp::from_unix_seconds(wall_clock))
}

fn map_fresh_collision(error: StorageError) -> StorageError {
    if error.code() == StorageErrorCode::Conflict {
        return integrity_failure();
    }
    error
}

fn map_storage_error(error: StorageError) -> UserRepositoryError {
    let code = match error.code() {
        StorageErrorCode::NotFound => UserRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => UserRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => UserRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => UserRepositoryErrorCode::DeadlineExceeded,
        StorageErrorCode::ResourceExhausted => UserRepositoryErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => UserRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => UserRepositoryErrorCode::CommitIndeterminate,
        _ => UserRepositoryErrorCode::IntegrityFailure,
    };
    UserRepositoryError::new(code)
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

impl Debug for AuditSubjectKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditSubjectKeyMaterial(<redacted>)")
    }
}

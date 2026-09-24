// crates/optional/ariadnion-storage-rnmdb/src/account_import_repository.rs - Durable account import persistence for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Tenant-scoped RNMDB publication and reconciliation for account imports.

mod codec;
mod effective_window;
mod fingerprint;
mod routing_policy;
mod sql;

use std::fmt::{self, Debug, Formatter};
use std::future::{Future, ready};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::SystemTime;

use ariadnion_account_import::{
    AccountCredentialReference, AccountCredentialReferencePort, AccountCredentialReferenceRequest,
    AccountImportPort, AccountProjectionPort, AccountProjectionRequest, AccountProjectionSnapshot,
    BoxImportFuture, DurablePublishReceipt, DurablePublishRequest, ImportGeneration,
    ImportMutationId, ImportPortError, ImportPortErrorCode,
};
use ariadnion_core::{ErrorCode, RequestContext, TenantId};
use ariadnion_rbac::migrations::IDENTITY_RUNTIME_ROLE;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_security::ColumnKeyMaterial as UpstreamColumnKeyMaterial;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::RnmdbSessionOwner;
use crate::identity_transaction::run_identity_transaction;
use crate::session::ColumnEncryptionTarget;

const WORK_QUEUE_CAPACITY: usize = 1 << 8;
const SECRET_PATH_TARGET: ColumnEncryptionTarget =
    ColumnEncryptionTarget::new("public", "account_registry_accounts", "secret_path");

/// Single-consumption key material for encrypted imported secret paths.
///
/// Ariadnion-owned bytes are zeroized on drop. RNMDB retains its own key copy
/// for the lifetime of the embedded session. Callers must supply the same key
/// after reopening the database; the key is never persisted by this adapter.
pub struct AccountImportSecretPathKeyMaterial {
    bytes: [u8; 32],
}

impl AccountImportSecretPathKeyMaterial {
    /// Takes ownership of exactly 32 key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    fn into_upstream_key(self) -> UpstreamColumnKeyMaterial {
        UpstreamColumnKeyMaterial::from_bytes(self.bytes)
    }
}

impl Debug for AccountImportSecretPathKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountImportSecretPathKeyMaterial(<redacted>)")
    }
}

impl Zeroize for AccountImportSecretPathKeyMaterial {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for AccountImportSecretPathKeyMaterial {}

impl Drop for AccountImportSecretPathKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Independent key material for tenant- and mutation-bound HMAC fingerprints.
///
/// The key is never persisted, formatted, or shared with column encryption.
/// Callers must reinject the same key after reopening the account store.
/// Replacing it requires a separate migration of the mutation journal.
pub struct AccountImportFingerprintKeyMaterial(Zeroizing<[u8; 32]>);

impl AccountImportFingerprintKeyMaterial {
    /// Takes ownership of exactly 32 externally managed key bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Debug for AccountImportFingerprintKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountImportFingerprintKeyMaterial(<redacted>)")
    }
}

/// One account-store access requiring an explicit current authorization decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountImportAccess {
    /// Publishes or exactly replays the supplied immutable request.
    Publish,
    /// Reads durable evidence for the supplied tenant-local mutation.
    Reconcile,
    /// Reads the authenticated tenant's publication generation.
    Generation,
    /// Reads a complete secret-free account projection snapshot.
    Projection,
    /// Resolves one active account's metadata-only credential reference.
    CredentialReference,
}

/// Trusted, fail-closed authorization boundary for account-store access.
///
/// Implementations evaluate the authenticated principal, tenant, and requested
/// access against authoritative policy. Authentication alone is not permission.
/// The bounded storage worker invokes this synchronous port before each access
/// and rechecks publication after account effects, before final evidence writes.
/// Request cancellation and deadlines are checked immediately before and after
/// this call; a context failure observed after the decision takes precedence.
/// The publication recheck holds this owner's session lock: implementations must
/// not reenter the same owner or acquire locks in the opposite order. Policy
/// snapshots or independently synchronized authority state must remain valid for
/// the returned decision through the final evidence writes and durable commit.
/// Implementations must return a redacted stable error when authorization cannot
/// be established; denied publication should return `PermissionDenied`.
pub trait AccountImportAuthorizationPort: Send + Sync {
    /// Authorizes exactly this access and context without exposing rejected data.
    fn authorize(
        &self,
        access: AccountImportAccess,
        context: &RequestContext,
    ) -> Result<(), ImportPortError>;
}

/// Trusted UTC clock for the final account-publication evidence boundary.
///
/// RNMDB does not supply a physical commit timestamp. The returned time is
/// sampled after all account effects, before final event stamps, generation,
/// mutation receipt writes, and RNMDB's durable `COMMIT`. Receipt `committed_at`
/// therefore denotes this publication time, not the physical commit instant.
/// Replay and reconciliation return the original stored publication time.
/// Storage truncates the value to whole UTC seconds. Clock implementations must
/// not reenter the session owner while the transaction holds its session lock.
pub trait AccountImportClock: Send + Sync {
    /// Returns trusted UTC publication time or a redacted availability error.
    fn publication_time(&self) -> Result<SystemTime, ImportPortError>;
}

struct ImportEnvironment {
    fingerprint_key: AccountImportFingerprintKeyMaterial,
    authorization: Arc<dyn AccountImportAuthorizationPort>,
    clock: Arc<dyn AccountImportClock>,
}

/// Durable account-import adapter over one serialized embedded RNMDB session.
///
/// New entries are deliberately persisted as a minimal provisioning baseline:
/// labels derive from the validated account and provider identities, optional
/// external/model values are absent, configuration and account versions start
/// at one, concurrency starts at one, and lifecycle status is `provisioning`.
/// A replacement preserves lifecycle status and advances both monotonic versions.
/// An indeterminate commit permanently quarantines the underlying session owner;
/// callers must reopen it with the same database and keys, then reconcile the
/// original tenant-local mutation identity instead of publishing a new mutation.
pub struct RnmdbAccountImportRepository {
    session: Arc<RnmdbSessionOwner>,
    worker: ImportWorker,
}

impl RnmdbAccountImportRepository {
    /// Configures encrypted secret paths and starts one bounded storage worker.
    ///
    /// The worker keeps blocking embedded database I/O off async executor
    /// threads. Construction fails closed when the schema, key configuration,
    /// request context, or worker resource is unavailable.
    ///
    /// At most `1 << 8` jobs wait in the worker queue. Overflow is rejected with
    /// `ResourceExhausted`. Request cancellation and deadlines are checked before
    /// queue admission, before and after authorization, before transaction entry,
    /// between imported accounts, and before durable commit. Cancellation has
    /// precedence over an expired deadline whenever both are observable.
    /// Dropping a future does not cancel its admitted request; callers cancel its
    /// context token and reconcile the original mutation if no receipt arrives.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted account-import adapter error.
    pub fn new(
        session: Arc<RnmdbSessionOwner>,
        secret_path_key: AccountImportSecretPathKeyMaterial,
        fingerprint_key: AccountImportFingerprintKeyMaterial,
        authorization: Arc<dyn AccountImportAuthorizationPort>,
        clock: Arc<dyn AccountImportClock>,
        context: &RequestContext,
    ) -> Result<Self, ImportPortError> {
        let environment = ImportEnvironment {
            fingerprint_key,
            authorization,
            clock,
        };
        let worker = ImportWorker::start(session.clone(), environment)?;
        session
            .configure_column_encryption_once(
                SECRET_PATH_TARGET,
                secret_path_key.into_upstream_key(),
                Some(IDENTITY_RUNTIME_ROLE),
                context,
            )
            .map_err(map_storage_error)?;
        Ok(Self { session, worker })
    }

    /// Returns the underlying serialized embedded session owner.
    ///
    /// Drop this repository to stop and join its worker before final owner
    /// shutdown. A commit-indeterminate error requires discarding this owner and
    /// reopening the same durable database before reconciliation.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }
}

impl Debug for RnmdbAccountImportRepository {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbAccountImportRepository")
            .field("instance", self.session.instance())
            .field("worker_started", &self.worker.started())
            .finish()
    }
}

impl AccountImportPort for RnmdbAccountImportRepository {
    fn publish<'a>(
        &'a self,
        request: DurablePublishRequest,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, DurablePublishReceipt> {
        let tenant = match admitted_tenant(context) {
            Ok(tenant) => tenant,
            Err(error) => return Box::pin(ready(Err(error))),
        };
        self.worker.publish(request, context.clone(), tenant)
    }

    fn reconcile<'a>(
        &'a self,
        mutation_id: &'a ImportMutationId,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, Option<DurablePublishReceipt>> {
        let tenant = match admitted_tenant(context) {
            Ok(tenant) => tenant,
            Err(error) => return Box::pin(ready(Err(error))),
        };
        self.worker
            .reconcile(mutation_id.clone(), context.clone(), tenant)
    }

    fn generation<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, ImportGeneration> {
        let tenant = match admitted_tenant(context) {
            Ok(tenant) => tenant,
            Err(error) => return Box::pin(ready(Err(error))),
        };
        self.worker.generation(context.clone(), tenant)
    }
}

impl AccountProjectionPort for RnmdbAccountImportRepository {
    fn account_projection<'a>(
        &'a self,
        request: AccountProjectionRequest,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, AccountProjectionSnapshot> {
        let tenant = match admitted_tenant(context) {
            Ok(tenant) => tenant,
            Err(error) => return Box::pin(ready(Err(error))),
        };
        self.worker.projection(request, context.clone(), tenant)
    }
}

impl AccountCredentialReferencePort for RnmdbAccountImportRepository {
    fn account_credential_reference<'a>(
        &'a self,
        request: AccountCredentialReferenceRequest,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, AccountCredentialReference> {
        let tenant = match admitted_tenant(context) {
            Ok(tenant) => tenant,
            Err(error) => return Box::pin(ready(Err(error))),
        };
        self.worker
            .credential_reference(request, context.clone(), tenant)
    }
}

fn authenticated_tenant(context: &RequestContext) -> Result<TenantId, ImportPortError> {
    context
        .principal()
        .map(|principal| principal.tenant_id().clone())
        .ok_or_else(|| import_error(ImportPortErrorCode::Unauthenticated))
}

fn admitted_tenant(context: &RequestContext) -> Result<TenantId, ImportPortError> {
    check_request_context(context)?;
    authenticated_tenant(context)
}

fn check_request_context(context: &RequestContext) -> Result<(), ImportPortError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => import_error(ImportPortErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => import_error(ImportPortErrorCode::DeadlineExceeded),
        _ => import_error(ImportPortErrorCode::CorruptState),
    })
}

fn execute_job(
    session: &Arc<RnmdbSessionOwner>,
    environment: &ImportEnvironment,
    kind: ImportJobKind,
) -> ImportJobResponse {
    match kind {
        ImportJobKind::Publish {
            request,
            context,
            tenant,
        } => ImportJobResponse::Publish(execute_publish(
            session,
            environment,
            request,
            context,
            tenant,
        )),
        ImportJobKind::Reconcile {
            mutation_id,
            context,
            tenant,
        } => ImportJobResponse::Reconcile(execute_reconcile(
            session,
            environment,
            mutation_id,
            context,
            tenant,
        )),
        ImportJobKind::Generation { context, tenant } => {
            ImportJobResponse::Generation(execute_generation(session, environment, context, tenant))
        }
        ImportJobKind::Projection {
            request,
            context,
            tenant,
        } => ImportJobResponse::Projection(execute_projection(
            session,
            environment,
            request,
            context,
            tenant,
        )),
        ImportJobKind::CredentialReference {
            request,
            context,
            tenant,
        } => ImportJobResponse::CredentialReference(execute_credential_reference(
            session,
            environment,
            request,
            context,
            tenant,
        )),
    }
}

fn execute_publish(
    session: &Arc<RnmdbSessionOwner>,
    environment: &ImportEnvironment,
    request: DurablePublishRequest,
    context: RequestContext,
    tenant: TenantId,
) -> Result<DurablePublishReceipt, ImportPortError> {
    authorize_current(environment, AccountImportAccess::Publish, &context)?;
    let mut boundary_error = None;
    let result = session.with_identity_transaction_session(&context, &tenant, |local| {
        run_identity_transaction(local, &context, |local| {
            codec::publish(
                local,
                &tenant,
                &request,
                &context,
                environment.fingerprint_key.bytes(),
                || {
                    publication_boundary(environment, &context).map_err(|error| {
                        boundary_error = Some(error);
                        StorageError::new(StorageErrorCode::InvalidArgument)
                    })
                },
            )
        })
    });
    project_publish_result(result, boundary_error)
}

fn publication_boundary(
    environment: &ImportEnvironment,
    context: &RequestContext,
) -> Result<SystemTime, ImportPortError> {
    authorize_current(environment, AccountImportAccess::Publish, context)?;
    let publication_time = environment.clock.publication_time();
    check_request_context(context)?;
    publication_time
}

fn authorize_current(
    environment: &ImportEnvironment,
    access: AccountImportAccess,
    context: &RequestContext,
) -> Result<(), ImportPortError> {
    check_request_context(context)?;
    let decision = environment.authorization.authorize(access, context);
    check_request_context(context)?;
    decision
}

fn project_publish_result(
    result: Result<DurablePublishReceipt, StorageError>,
    boundary_error: Option<ImportPortError>,
) -> Result<DurablePublishReceipt, ImportPortError> {
    // Preserve a precommit port failure only after a confirmed ordinary rollback.
    // Cancellation or a tainted rollback must keep the transaction's own error.
    match result {
        Err(error) if error.code() == StorageErrorCode::InvalidArgument => {
            Err(boundary_error.unwrap_or_else(|| map_storage_error(error)))
        }
        result => result.map_err(map_storage_error),
    }
}

fn execute_reconcile(
    session: &Arc<RnmdbSessionOwner>,
    environment: &ImportEnvironment,
    mutation_id: ImportMutationId,
    context: RequestContext,
    tenant: TenantId,
) -> Result<Option<DurablePublishReceipt>, ImportPortError> {
    authorize_current(environment, AccountImportAccess::Reconcile, &context)?;
    session
        .with_identity_storage_session(&context, &tenant, |local| {
            codec::load_mutation(local, &tenant, &mutation_id)?
                .map(codec::StoredMutation::into_receipt)
                .transpose()
        })
        .map_err(map_storage_error)
}

fn execute_generation(
    session: &Arc<RnmdbSessionOwner>,
    environment: &ImportEnvironment,
    context: RequestContext,
    tenant: TenantId,
) -> Result<ImportGeneration, ImportPortError> {
    authorize_current(environment, AccountImportAccess::Generation, &context)?;
    session
        .with_identity_storage_session(&context, &tenant, |local| {
            codec::load_generation(local, &tenant)
        })
        .map_err(map_storage_error)
}

fn execute_projection(
    session: &Arc<RnmdbSessionOwner>,
    environment: &ImportEnvironment,
    request: AccountProjectionRequest,
    context: RequestContext,
    tenant: TenantId,
) -> Result<AccountProjectionSnapshot, ImportPortError> {
    authorize_current(environment, AccountImportAccess::Projection, &context)?;
    session
        .with_identity_transaction_session(&context, &tenant, |local| {
            run_identity_transaction(local, &context, |local| {
                codec::load_projection_snapshot(local, &tenant, &request, &context)
            })
        })
        .map_err(map_projection_error)
}

fn execute_credential_reference(
    session: &Arc<RnmdbSessionOwner>,
    environment: &ImportEnvironment,
    request: AccountCredentialReferenceRequest,
    context: RequestContext,
    tenant: TenantId,
) -> Result<AccountCredentialReference, ImportPortError> {
    authorize_current(
        environment,
        AccountImportAccess::CredentialReference,
        &context,
    )?;
    session
        .with_identity_transaction_session(&context, &tenant, |local| {
            run_identity_transaction(local, &context, |local| {
                codec::load_credential_reference(local, &tenant, &request, &context)
            })
        })
        .map_err(map_credential_reference_error)
}

fn map_projection_error(error: StorageError) -> ImportPortError {
    if error.code() == StorageErrorCode::Conflict {
        import_error(ImportPortErrorCode::ProjectionConflict)
    } else if error.code() == StorageErrorCode::CommitIndeterminate {
        import_error(ImportPortErrorCode::Unavailable)
    } else {
        map_storage_error(error)
    }
}

fn map_credential_reference_error(error: StorageError) -> ImportPortError {
    match error.code() {
        StorageErrorCode::Conflict => import_error(ImportPortErrorCode::ProjectionConflict),
        StorageErrorCode::NotFound => import_error(ImportPortErrorCode::Conflict),
        StorageErrorCode::CommitIndeterminate => import_error(ImportPortErrorCode::Unavailable),
        _ => map_storage_error(error),
    }
}

fn map_storage_error(error: StorageError) -> ImportPortError {
    import_error(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(code: StorageErrorCode) -> ImportPortErrorCode {
    match code {
        StorageErrorCode::InvalidArgument => ImportPortErrorCode::InvalidArgument,
        StorageErrorCode::Conflict => ImportPortErrorCode::Conflict,
        StorageErrorCode::DeadlineExceeded => ImportPortErrorCode::DeadlineExceeded,
        StorageErrorCode::Cancelled => ImportPortErrorCode::Cancelled,
        StorageErrorCode::ResourceExhausted => ImportPortErrorCode::ResourceExhausted,
        other => map_adapter_error_code(other),
    }
}

const fn map_adapter_error_code(code: StorageErrorCode) -> ImportPortErrorCode {
    match code {
        StorageErrorCode::Unavailable => ImportPortErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => ImportPortErrorCode::CommitIndeterminate,
        StorageErrorCode::NotFound | StorageErrorCode::MigrationRequired => {
            ImportPortErrorCode::Unavailable
        }
        StorageErrorCode::IntegrityFailure | StorageErrorCode::Internal => {
            ImportPortErrorCode::CorruptState
        }
        _ => ImportPortErrorCode::CorruptState,
    }
}

const fn import_error(code: ImportPortErrorCode) -> ImportPortError {
    ImportPortError::new(code)
}

struct ImportWorker {
    sender: SyncSender<ImportWorkerMessage>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ImportWorker {
    fn start(
        session: Arc<RnmdbSessionOwner>,
        environment: ImportEnvironment,
    ) -> Result<Self, ImportPortError> {
        let (sender, receiver) = mpsc::sync_channel(WORK_QUEUE_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let handle = thread::Builder::new()
            .name("ariadnion-account-import".to_owned())
            .spawn(move || worker_loop(session, environment, receiver, worker_stop))
            .map_err(|_| import_error(ImportPortErrorCode::Unavailable))?;
        Ok(Self {
            sender,
            stop,
            handle: Some(handle),
        })
    }

    fn started(&self) -> bool {
        self.handle.is_some() && !self.stop.load(Ordering::Acquire)
    }

    fn publish<'a>(
        &'a self,
        request: DurablePublishRequest,
        context: RequestContext,
        tenant: TenantId,
    ) -> BoxImportFuture<'a, DurablePublishReceipt> {
        let kind = ImportJobKind::Publish {
            request,
            context,
            tenant,
        };
        self.submit(kind, project_publish)
    }

    fn reconcile<'a>(
        &'a self,
        mutation_id: ImportMutationId,
        context: RequestContext,
        tenant: TenantId,
    ) -> BoxImportFuture<'a, Option<DurablePublishReceipt>> {
        let kind = ImportJobKind::Reconcile {
            mutation_id,
            context,
            tenant,
        };
        self.submit(kind, project_reconcile)
    }

    fn generation<'a>(
        &'a self,
        context: RequestContext,
        tenant: TenantId,
    ) -> BoxImportFuture<'a, ImportGeneration> {
        self.submit(
            ImportJobKind::Generation { context, tenant },
            project_generation,
        )
    }

    fn projection<'a>(
        &'a self,
        request: AccountProjectionRequest,
        context: RequestContext,
        tenant: TenantId,
    ) -> BoxImportFuture<'a, AccountProjectionSnapshot> {
        let kind = ImportJobKind::Projection {
            request,
            context,
            tenant,
        };
        self.submit(kind, project_projection)
    }

    fn credential_reference<'a>(
        &'a self,
        request: AccountCredentialReferenceRequest,
        context: RequestContext,
        tenant: TenantId,
    ) -> BoxImportFuture<'a, AccountCredentialReference> {
        let kind = ImportJobKind::CredentialReference {
            request,
            context,
            tenant,
        };
        self.submit(kind, project_credential_reference)
    }

    fn submit<'a, T>(
        &'a self,
        kind: ImportJobKind,
        project: fn(ImportJobResponse) -> Result<T, ImportPortError>,
    ) -> BoxImportFuture<'a, T>
    where
        T: Send + 'a,
    {
        let admission_context = kind.context().clone();
        if let Err(error) = check_request_context(&admission_context) {
            return Box::pin(ready(Err(error)));
        }
        if self.stop.load(Ordering::Acquire) {
            return Box::pin(ready(Err(current_or(
                &admission_context,
                ImportPortErrorCode::Unavailable,
            ))));
        }
        let cell = Arc::new(ImportResultCell::new());
        let job = ImportJob {
            kind,
            result: cell.clone(),
        };
        match self.sender.try_send(ImportWorkerMessage::Job(job)) {
            Ok(()) => Box::pin(ImportResultFuture::new(cell, project)),
            Err(TrySendError::Full(_)) => Box::pin(ready(Err(current_or(
                &admission_context,
                ImportPortErrorCode::ResourceExhausted,
            )))),
            Err(TrySendError::Disconnected(_)) => Box::pin(ready(Err(current_or(
                &admission_context,
                ImportPortErrorCode::Unavailable,
            )))),
        }
    }
}

impl Drop for ImportWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.sender.try_send(ImportWorkerMessage::Wake);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

enum ImportWorkerMessage {
    Job(ImportJob),
    Wake,
}

struct ImportJob {
    kind: ImportJobKind,
    result: Arc<ImportResultCell>,
}

enum ImportJobKind {
    Publish {
        request: DurablePublishRequest,
        context: RequestContext,
        tenant: TenantId,
    },
    Reconcile {
        mutation_id: ImportMutationId,
        context: RequestContext,
        tenant: TenantId,
    },
    Generation {
        context: RequestContext,
        tenant: TenantId,
    },
    Projection {
        request: AccountProjectionRequest,
        context: RequestContext,
        tenant: TenantId,
    },
    CredentialReference {
        request: AccountCredentialReferenceRequest,
        context: RequestContext,
        tenant: TenantId,
    },
}

impl ImportJobKind {
    fn context(&self) -> &RequestContext {
        match self {
            Self::Publish { context, .. }
            | Self::Reconcile { context, .. }
            | Self::Generation { context, .. }
            | Self::Projection { context, .. }
            | Self::CredentialReference { context, .. } => context,
        }
    }
}

enum ImportJobResponse {
    Publish(Result<DurablePublishReceipt, ImportPortError>),
    Reconcile(Result<Option<DurablePublishReceipt>, ImportPortError>),
    Generation(Result<ImportGeneration, ImportPortError>),
    Projection(Result<AccountProjectionSnapshot, ImportPortError>),
    CredentialReference(Result<AccountCredentialReference, ImportPortError>),
}

fn project_publish(response: ImportJobResponse) -> Result<DurablePublishReceipt, ImportPortError> {
    match response {
        ImportJobResponse::Publish(result) => result,
        _ => Err(import_error(ImportPortErrorCode::CorruptState)),
    }
}

fn project_reconcile(
    response: ImportJobResponse,
) -> Result<Option<DurablePublishReceipt>, ImportPortError> {
    match response {
        ImportJobResponse::Reconcile(result) => result,
        _ => Err(import_error(ImportPortErrorCode::CorruptState)),
    }
}

fn project_generation(response: ImportJobResponse) -> Result<ImportGeneration, ImportPortError> {
    match response {
        ImportJobResponse::Generation(result) => result,
        _ => Err(import_error(ImportPortErrorCode::CorruptState)),
    }
}

fn project_projection(
    response: ImportJobResponse,
) -> Result<AccountProjectionSnapshot, ImportPortError> {
    match response {
        ImportJobResponse::Projection(result) => result,
        _ => Err(import_error(ImportPortErrorCode::CorruptState)),
    }
}

fn project_credential_reference(
    response: ImportJobResponse,
) -> Result<AccountCredentialReference, ImportPortError> {
    match response {
        ImportJobResponse::CredentialReference(result) => result,
        _ => Err(import_error(ImportPortErrorCode::CorruptState)),
    }
}

fn worker_loop(
    session: Arc<RnmdbSessionOwner>,
    environment: ImportEnvironment,
    receiver: Receiver<ImportWorkerMessage>,
    stop: Arc<AtomicBool>,
) {
    loop {
        match next_worker_action(&receiver, &stop) {
            ImportWorkerAction::Job(job) => run_job(&session, &environment, job),
            ImportWorkerAction::Wake => {}
            ImportWorkerAction::Stop => return,
        }
    }
}

enum ImportWorkerAction {
    Job(ImportJob),
    Wake,
    Stop,
}

fn next_worker_action(
    receiver: &Receiver<ImportWorkerMessage>,
    stop: &AtomicBool,
) -> ImportWorkerAction {
    if stop.load(Ordering::Acquire) {
        drain_jobs(receiver);
        return ImportWorkerAction::Stop;
    }
    match receiver.recv() {
        Ok(ImportWorkerMessage::Job(job)) => {
            if stop.load(Ordering::Acquire) {
                reject_job(job, ImportPortErrorCode::Unavailable);
                drain_jobs(receiver);
                ImportWorkerAction::Stop
            } else {
                ImportWorkerAction::Job(job)
            }
        }
        Ok(ImportWorkerMessage::Wake) => ImportWorkerAction::Wake,
        Err(_) => ImportWorkerAction::Stop,
    }
}

fn run_job(session: &Arc<RnmdbSessionOwner>, environment: &ImportEnvironment, job: ImportJob) {
    let response_kind = ImportResponseKind::from(&job.kind);
    let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_job(session, environment, job.kind)
    }));
    match response {
        Ok(response) => job.result.complete(response),
        Err(_) => {
            session.quarantine_after_worker_panic();
            job.result
                .complete(response_kind.error(ImportPortErrorCode::CorruptState));
        }
    }
}

fn drain_jobs(receiver: &Receiver<ImportWorkerMessage>) {
    loop {
        match receiver.try_recv() {
            Ok(ImportWorkerMessage::Job(job)) => reject_job(job, ImportPortErrorCode::Unavailable),
            Ok(ImportWorkerMessage::Wake) => {}
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn reject_job(job: ImportJob, fallback: ImportPortErrorCode) {
    let response_kind = ImportResponseKind::from(&job.kind);
    let error = current_or(job.kind.context(), fallback);
    job.result.complete(response_kind.error(error.code()));
}

fn current_or(context: &RequestContext, fallback: ImportPortErrorCode) -> ImportPortError {
    match check_request_context(context) {
        Ok(()) => import_error(fallback),
        Err(error) => error,
    }
}

#[derive(Clone, Copy)]
enum ImportResponseKind {
    Publish,
    Reconcile,
    Generation,
    Projection,
    CredentialReference,
}

impl From<&ImportJobKind> for ImportResponseKind {
    fn from(kind: &ImportJobKind) -> Self {
        match kind {
            ImportJobKind::Publish { .. } => Self::Publish,
            ImportJobKind::Reconcile { .. } => Self::Reconcile,
            ImportJobKind::Generation { .. } => Self::Generation,
            ImportJobKind::Projection { .. } => Self::Projection,
            ImportJobKind::CredentialReference { .. } => Self::CredentialReference,
        }
    }
}

impl ImportResponseKind {
    fn error(self, code: ImportPortErrorCode) -> ImportJobResponse {
        match self {
            Self::Publish => ImportJobResponse::Publish(Err(import_error(code))),
            Self::Reconcile => ImportJobResponse::Reconcile(Err(import_error(code))),
            Self::Generation => ImportJobResponse::Generation(Err(import_error(code))),
            Self::Projection => ImportJobResponse::Projection(Err(import_error(code))),
            Self::CredentialReference => {
                ImportJobResponse::CredentialReference(Err(import_error(code)))
            }
        }
    }
}

struct ImportResultCell {
    state: Mutex<ImportResultState>,
}

impl ImportResultCell {
    fn new() -> Self {
        Self {
            state: Mutex::new(ImportResultState {
                response: None,
                waker: None,
            }),
        }
    }

    fn complete(&self, response: ImportJobResponse) {
        let waker = {
            let mut state = lock_result(&self.state);
            state.response = Some(response);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct ImportResultState {
    response: Option<ImportJobResponse>,
    waker: Option<Waker>,
}

struct ImportResultFuture<T> {
    cell: Arc<ImportResultCell>,
    project: fn(ImportJobResponse) -> Result<T, ImportPortError>,
    output: PhantomData<fn() -> T>,
}

impl<T> ImportResultFuture<T> {
    fn new(
        cell: Arc<ImportResultCell>,
        project: fn(ImportJobResponse) -> Result<T, ImportPortError>,
    ) -> Self {
        Self {
            cell,
            project,
            output: PhantomData,
        }
    }
}

impl<T> Future for ImportResultFuture<T> {
    type Output = Result<T, ImportPortError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = lock_result(&this.cell.state);
        if let Some(response) = state.response.take() {
            return Poll::Ready((this.project)(response));
        }
        state.waker = Some(context.waker().clone());
        Poll::Pending
    }
}

fn lock_result(state: &Mutex<ImportResultState>) -> MutexGuard<'_, ImportResultState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

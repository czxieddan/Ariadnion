// crates/optional/ariadnion-file-service/src/worker.rs - Rust source for Ariadnion.
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

use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;

use ariadnion_api_files::ApiFilesError;
use ariadnion_core::{CancellationToken, RequestContext};
use ariadnion_storage_asset::{
    AssetCommitReceipt, AssetDescriptor, AssetKey, AssetQuarantineReason, AssetQuarantineReceipt,
    AssetStageRequest, LocalVolumeAssetStoragePort, StagedAsset, StorageError,
};

use crate::pipe::PipeWriter;

mod operation {
    include!("worker/operation.rs");
}
mod cleanup {
    include!("worker/cleanup.rs");
}

pub(crate) use cleanup::OperationGuard;
use cleanup::{
    QuarantineJob, abandon_retained_stage, contain_inflight_commit_stage,
    contain_pre_call_commit_stage, contain_unresolved_stage, release_running_reservation,
    retain_running_reservation,
};
use operation::{
    JobCell, JobFuture, OperationContext, assign_state, classify_commit_error, current_phase,
    dispose_rejected_job, fail_and_drop_job, fail_worker, finish_worker_failure, internal_error,
    lock_recover, lock_worker, mark_failed, project_pipe_error, project_storage_error,
    recover_wait, spawn_worker, take_worker_failure, unavailable_error,
};

const WORKER_NAME: &str = "ariadnion-file-transfer";

/// One fail-fast blocking executor for synchronous asset operations.
pub(crate) struct TransferWorker {
    runtime: Arc<WorkerRuntime>,
}

/// Observable lifecycle of the single worker slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerPhase {
    Cold,
    Assigned,
    Running,
    Idle,
    Failed,
    Stopping,
    Stopped,
}

struct WorkerRuntime {
    assets: Arc<dyn LocalVolumeAssetStoragePort>,
    shared: Arc<WorkerShared>,
    // Acquire this mutex before WorkerShared::state whenever both are required.
    handle: Mutex<Option<JoinHandle<()>>>,
}

struct WorkerShared {
    // Critical sections only inspect or move state. They never invoke jobs, wakers,
    // cancellation methods, storage values, closures, or thread handles, and they
    // never destroy caller-owned dynamic values.
    state: Mutex<WorkerState>,
    changed: Condvar,
}

struct WorkerState {
    phase: WorkerPhase,
    next_reservation: u64,
    reservation: Option<u64>,
    job: Option<Box<dyn WorkerJob>>,
    active_cancellation: Option<CancellationToken>,
    // A failed lifecycle retains at most one opaque stage without claiming recovery.
    unresolved_stage: Option<StagedAsset>,
}

#[derive(Default)]
struct WorkerFailure {
    cancellation: Option<CancellationToken>,
    pending: Option<Box<dyn WorkerJob>>,
}

struct AssignmentOutcome {
    result: Result<(), ApiFilesError>,
    rejected: Option<Box<dyn WorkerJob>>,
    failure: WorkerFailure,
}

struct StopPreparation {
    failed: bool,
    cancellation: Option<CancellationToken>,
    failure: WorkerFailure,
}

impl WorkerState {
    const fn new() -> Self {
        Self {
            phase: WorkerPhase::Cold,
            next_reservation: 1,
            reservation: None,
            job: None,
            active_cancellation: None,
            unresolved_stage: None,
        }
    }
}

impl WorkerShared {
    fn new() -> Self {
        Self {
            state: Mutex::new(WorkerState::new()),
            changed: Condvar::new(),
        }
    }
}

impl TransferWorker {
    /// Creates a cold worker without starting an operating-system thread.
    pub(crate) fn new(assets: Arc<dyn LocalVolumeAssetStoragePort>) -> Self {
        Self {
            runtime: Arc::new(WorkerRuntime {
                assets,
                shared: Arc::new(WorkerShared::new()),
                handle: Mutex::new(None),
            }),
        }
    }

    /// Returns the current lifecycle phase without exposing retained job data.
    pub(crate) fn phase(&self) -> WorkerPhase {
        current_phase(&self.runtime.shared)
    }

    /// Submits one staging operation that retains admission until final disposition.
    pub(crate) fn submit_stage(
        &self,
        request: AssetStageRequest,
        source: Box<dyn Read + Send>,
        context: &RequestContext,
    ) -> JobFuture<OperationGuard> {
        let operation = OperationContext::child(context);
        let cell = Arc::new(JobCell::new(self.runtime.shared.clone()));
        let job = StageJob {
            cell: cell.clone(),
            context: operation.context.clone(),
            request: Some(request),
            source: Some(source),
        };
        JobFuture::new(
            self.runtime.clone(),
            cell,
            Box::new(job),
            Assignment::Fresh,
            operation,
        )
    }

    /// Commits the staged asset retained by an operation guard.
    pub(crate) fn submit_commit(
        &self,
        guard: OperationGuard,
        context: &RequestContext,
    ) -> JobFuture<CommitDisposition> {
        match guard.into_staged_with_cleanup(&self.runtime.shared) {
            Ok((reservation, staged, cleanup)) => self.make_commit_job(
                reservation,
                staged,
                cleanup,
                OperationContext::child(context),
            ),
            Err(error) => JobFuture::ready(
                self.runtime.clone(),
                OperationContext::child(context),
                error,
            ),
        }
    }

    /// Quarantines the staged asset retained by an operation guard.
    pub(crate) fn submit_quarantine(
        &self,
        guard: OperationGuard,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> JobFuture<AssetQuarantineReceipt> {
        match guard.into_staged_with_cleanup(&self.runtime.shared) {
            Ok((reservation, staged, cleanup)) => {
                let operation = OperationContext::owned(cleanup);
                self.make_submitted_quarantine_job(reservation, staged, reason, operation)
            }
            Err(error) => {
                let operation = OperationContext::child(context);
                JobFuture::ready(self.runtime.clone(), operation, error)
            }
        }
    }

    /// Loads committed asset metadata on the dedicated blocking thread.
    pub(crate) fn submit_metadata(
        &self,
        key: AssetKey,
        context: &RequestContext,
    ) -> JobFuture<Option<AssetDescriptor>> {
        self.fresh_job(context, move |assets, context| {
            assets.metadata(&key, context)
        })
    }

    /// Loads committed metadata while returning the retained staging guard.
    pub(crate) fn submit_reserved_metadata(
        &self,
        guard: OperationGuard,
        key: AssetKey,
        context: &RequestContext,
    ) -> JobFuture<ReservedVerification<Option<AssetDescriptor>>> {
        self.reserved_verification_job(guard, context, move |assets, context| {
            assets.metadata(&key, context)
        })
    }

    /// Streams committed asset bytes into an owned blocking destination.
    pub(crate) fn submit_read(
        &self,
        key: AssetKey,
        mut destination: Box<dyn Write + Send>,
        context: &RequestContext,
    ) -> JobFuture<AssetDescriptor> {
        self.fresh_job(context, move |assets, context| {
            assets.read_into(&key, destination.as_mut(), context)
        })
    }

    /// Streams committed bytes while returning the retained staging guard.
    pub(crate) fn submit_reserved_read(
        &self,
        guard: OperationGuard,
        key: AssetKey,
        mut destination: Box<dyn Write + Send>,
        context: &RequestContext,
    ) -> JobFuture<ReservedVerification<AssetDescriptor>> {
        self.reserved_verification_job(guard, context, move |assets, context| {
            assets.read_into(&key, destination.as_mut(), context)
        })
    }

    /// Streams committed bytes into the acknowledged pipe and publishes EOF on success.
    pub(crate) fn submit_streaming_read(
        &self,
        key: AssetKey,
        mut destination: PipeWriter,
        context: &RequestContext,
    ) -> JobFuture<AssetDescriptor> {
        self.fresh_job(context, move |assets, context| {
            let descriptor = assets.read_into(&key, &mut destination, context)?;
            destination.finish().map_err(project_pipe_error)?;
            Ok(descriptor)
        })
    }

    /// Stops admission, cancels active blocking work, and joins the worker thread.
    pub(crate) fn shutdown(&self) -> Result<(), ApiFilesError> {
        self.runtime.shutdown()
    }

    fn fresh_job<T, F>(&self, context: &RequestContext, operation: F) -> JobFuture<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>
            + Send
            + 'static,
    {
        self.make_job(
            Assignment::Fresh,
            OperationContext::child(context),
            operation,
        )
    }

    fn reserved_job<T, F>(
        &self,
        reservation: u64,
        operation_context: OperationContext,
        operation: F,
    ) -> JobFuture<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>
            + Send
            + 'static,
    {
        self.make_job(
            Assignment::Reserved(reservation),
            operation_context,
            operation,
        )
    }

    fn reserved_verification_job<T, F>(
        &self,
        guard: OperationGuard,
        context: &RequestContext,
        operation: F,
    ) -> JobFuture<ReservedVerification<T>>
    where
        T: Send + 'static,
        F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>
            + Send
            + 'static,
    {
        let operation_context = OperationContext::child(context);
        match guard.into_staged_with_cleanup(&self.runtime.shared) {
            Ok((reservation, staged, cleanup)) => self.make_reserved_verification_job(
                reservation,
                staged,
                cleanup,
                operation_context,
                operation,
            ),
            Err(error) => JobFuture::ready(self.runtime.clone(), operation_context, error),
        }
    }

    fn make_reserved_verification_job<T, F>(
        &self,
        reservation: u64,
        staged: StagedAsset,
        cleanup: RequestContext,
        operation_context: OperationContext,
        operation: F,
    ) -> JobFuture<ReservedVerification<T>>
    where
        T: Send + 'static,
        F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>
            + Send
            + 'static,
    {
        let cell = Arc::new(JobCell::new(self.runtime.shared.clone()));
        let job = ReservedJob {
            cell: cell.clone(),
            context: operation_context.context.clone(),
            operation: Some(operation),
            staged: Some(staged),
            cleanup: Some(cleanup),
        };
        JobFuture::deferred(
            self.runtime.clone(),
            cell,
            Box::new(job),
            Assignment::Reserved(reservation),
            operation_context,
        )
    }

    fn make_commit_job(
        &self,
        reservation: u64,
        staged: StagedAsset,
        cleanup: RequestContext,
        operation_context: OperationContext,
    ) -> JobFuture<CommitDisposition> {
        let cell = Arc::new(JobCell::new(self.runtime.shared.clone()));
        cell.install_stage_cleanup(cleanup);
        let job = CommitJob {
            cell: cell.clone(),
            context: operation_context.context.clone(),
            staged: Some(staged),
        };
        JobFuture::deferred(
            self.runtime.clone(),
            cell,
            Box::new(job),
            Assignment::Reserved(reservation),
            operation_context,
        )
    }

    fn make_submitted_quarantine_job(
        &self,
        reservation: u64,
        staged: StagedAsset,
        reason: AssetQuarantineReason,
        operation_context: OperationContext,
    ) -> JobFuture<AssetQuarantineReceipt> {
        let cell = Arc::new(JobCell::new(self.runtime.shared.clone()));
        let job = QuarantineJob::new(
            cell.clone(),
            operation_context.context.clone(),
            staged,
            reason,
            self.runtime.shared.clone(),
        );
        JobFuture::submit_now(
            self.runtime.clone(),
            cell,
            Box::new(job),
            Assignment::Reserved(reservation),
            operation_context,
        )
    }

    fn make_job<T, F>(
        &self,
        assignment: Assignment,
        operation_context: OperationContext,
        operation: F,
    ) -> JobFuture<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>
            + Send
            + 'static,
    {
        let cell = Arc::new(JobCell::new(self.runtime.shared.clone()));
        let job = TypedJob {
            cell: cell.clone(),
            context: operation_context.context.clone(),
            operation: Some(operation),
        };
        JobFuture::new(
            self.runtime.clone(),
            cell,
            Box::new(job),
            assignment,
            operation_context,
        )
    }
}

impl Drop for TransferWorker {
    fn drop(&mut self) {
        self.runtime.detach();
    }
}

/// The durable disposition of one staged-asset commit attempt.
pub(crate) enum CommitDisposition {
    /// Storage confirmed a durable committed result.
    Committed(AssetCommitReceipt),
    /// Storage rejected the attempt before an ambiguous durable boundary.
    Determinate {
        /// The still-valid staging capability.
        guard: OperationGuard,
        /// The redacted determinate failure.
        error: ApiFilesError,
    },
    /// Storage could not determine whether durable commit completed.
    Indeterminate(ApiFilesError),
}

/// One determinate verification result paired with the still-retained stage.
pub(crate) struct ReservedVerification<T> {
    guard: OperationGuard,
    result: Result<T, ApiFilesError>,
}

impl<T> ReservedVerification<T> {
    /// Consumes the verification and returns its reusable guard and result.
    pub(crate) fn into_parts(self) -> (OperationGuard, Result<T, ApiFilesError>) {
        (self.guard, self.result)
    }
}

#[derive(Clone, Copy)]
enum Assignment {
    Fresh,
    Reserved(u64),
}

trait WorkerJob: Send {
    fn execute(
        &mut self,
        assets: &dyn LocalVolumeAssetStoragePort,
        shared: &Arc<WorkerShared>,
        reservation: u64,
    );

    fn fail(&mut self, error: ApiFilesError);

    fn cancellation(&self) -> CancellationToken;

    fn abandon(&mut self, _shared: &Arc<WorkerShared>, _reservation: u64) -> bool {
        false
    }
}

struct TypedJob<T, F> {
    cell: Arc<JobCell<T>>,
    context: RequestContext,
    operation: Option<F>,
}

impl<T, F> WorkerJob for TypedJob<T, F>
where
    T: Send + 'static,
    F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>
        + Send
        + 'static,
{
    fn execute(
        &mut self,
        assets: &dyn LocalVolumeAssetStoragePort,
        shared: &Arc<WorkerShared>,
        reservation: u64,
    ) {
        let result = self.run(assets);
        let accepting = release_running_reservation(shared, reservation);
        self.cell.complete(if accepting {
            result
        } else {
            Err(unavailable_error())
        });
    }

    fn fail(&mut self, error: ApiFilesError) {
        self.cell.complete(Err(error));
    }

    fn cancellation(&self) -> CancellationToken {
        self.context.cancellation()
    }
}

impl<T, F> TypedJob<T, F>
where
    F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>,
{
    fn run(&mut self, assets: &dyn LocalVolumeAssetStoragePort) -> Result<T, ApiFilesError> {
        self.context.check_active().map_err(ApiFilesError::from)?;
        let Some(operation) = self.operation.take() else {
            return Err(internal_error());
        };
        operation(assets, &self.context).map_err(project_storage_error)
    }
}

struct ReservedJob<T, F> {
    cell: Arc<JobCell<ReservedVerification<T>>>,
    context: RequestContext,
    operation: Option<F>,
    staged: Option<StagedAsset>,
    cleanup: Option<RequestContext>,
}

enum CommitAttempt {
    Committed(AssetCommitReceipt),
    Determinate(ApiFilesError),
    Indeterminate(ApiFilesError),
    Unknown(ApiFilesError),
}

struct CommitJob {
    cell: Arc<JobCell<CommitDisposition>>,
    context: RequestContext,
    staged: Option<StagedAsset>,
}

impl WorkerJob for CommitJob {
    fn execute(
        &mut self,
        assets: &dyn LocalVolumeAssetStoragePort,
        shared: &Arc<WorkerShared>,
        reservation: u64,
    ) {
        let attempt = self.run(assets);
        self.publish(shared, reservation, attempt);
    }

    fn fail(&mut self, error: ApiFilesError) {
        let crossed_boundary = self.cell.crossed_commit_boundary();
        if crossed_boundary {
            contain_inflight_commit_stage(&self.cell.worker, self.staged.take());
        } else {
            contain_pre_call_commit_stage(&self.cell.worker, self.staged.take());
        }
        self.cell.take_stage_cleanup();
        self.cell.complete(Err(error));
    }

    fn cancellation(&self) -> CancellationToken {
        self.context.cancellation()
    }

    fn abandon(&mut self, shared: &Arc<WorkerShared>, reservation: u64) -> bool {
        if self.cell.crossed_commit_boundary() {
            return false;
        }
        let mut cleanup = self.cell.take_stage_cleanup();
        abandon_retained_stage(shared, reservation, &mut self.staged, &mut cleanup)
    }
}

impl CommitJob {
    fn run(&mut self, assets: &dyn LocalVolumeAssetStoragePort) -> CommitAttempt {
        if let Err(error) = self.context.check_active() {
            return CommitAttempt::Determinate(error.into());
        }
        let Some(staged) = self.staged.as_ref() else {
            return CommitAttempt::Unknown(internal_error());
        };
        self.commit_ready_stage(assets, staged)
    }

    fn commit_ready_stage(
        &self,
        assets: &dyn LocalVolumeAssetStoragePort,
        staged: &StagedAsset,
    ) -> CommitAttempt {
        if !self.cell.enter_commit_boundary() {
            return CommitAttempt::Unknown(internal_error());
        }
        match assets.commit(staged, &self.context) {
            Ok(receipt) => CommitAttempt::Committed(receipt),
            Err(error) => classify_commit_error(error),
        }
    }

    fn publish(&mut self, shared: &Arc<WorkerShared>, reservation: u64, attempt: CommitAttempt) {
        match attempt {
            CommitAttempt::Committed(receipt) => {
                self.publish_terminal(shared, reservation, CommitDisposition::Committed(receipt))
            }
            CommitAttempt::Determinate(error) => {
                self.publish_determinate(shared, reservation, error);
            }
            CommitAttempt::Indeterminate(error) => {
                self.publish_terminal(shared, reservation, CommitDisposition::Indeterminate(error))
            }
            CommitAttempt::Unknown(error) => self.publish_unknown(shared, error),
        }
    }

    fn publish_terminal(
        &mut self,
        shared: &Arc<WorkerShared>,
        reservation: u64,
        disposition: CommitDisposition,
    ) {
        self.staged.take();
        self.cell.take_stage_cleanup();
        let accepting = release_running_reservation(shared, reservation);
        self.cell.complete(if accepting {
            Ok(disposition)
        } else {
            Err(unavailable_error())
        });
    }

    fn publish_determinate(
        &mut self,
        shared: &Arc<WorkerShared>,
        reservation: u64,
        error: ApiFilesError,
    ) {
        let Some(staged) = self.staged.take() else {
            self.publish_unknown(shared, internal_error());
            return;
        };
        let Some(cleanup) = self.cell.take_stage_cleanup() else {
            contain_unresolved_stage(shared, Some(staged));
            self.publish_unknown(shared, internal_error());
            return;
        };
        if !retain_running_reservation(shared, reservation) {
            contain_unresolved_stage(shared, Some(staged));
            fail_worker(shared);
            self.cell.complete(Err(unavailable_error()));
            return;
        }
        let guard = OperationGuard::from_retained(shared.clone(), reservation, staged, cleanup);
        self.cell
            .complete(Ok(CommitDisposition::Determinate { guard, error }));
    }

    fn publish_unknown(&mut self, shared: &Arc<WorkerShared>, error: ApiFilesError) {
        contain_unresolved_stage(shared, self.staged.take());
        self.cell.take_stage_cleanup();
        fail_worker(shared);
        self.cell.complete(Err(error));
    }
}

impl<T, F> WorkerJob for ReservedJob<T, F>
where
    T: Send + 'static,
    F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>
        + Send
        + 'static,
{
    fn execute(
        &mut self,
        assets: &dyn LocalVolumeAssetStoragePort,
        shared: &Arc<WorkerShared>,
        reservation: u64,
    ) {
        let result = self.run(assets);
        self.publish(shared, reservation, result);
    }

    fn fail(&mut self, error: ApiFilesError) {
        contain_unresolved_stage(&self.cell.worker, self.staged.take());
        self.cleanup.take();
        self.cell.complete(Err(error));
    }

    fn cancellation(&self) -> CancellationToken {
        self.context.cancellation()
    }

    fn abandon(&mut self, shared: &Arc<WorkerShared>, reservation: u64) -> bool {
        abandon_retained_stage(shared, reservation, &mut self.staged, &mut self.cleanup)
    }
}

impl<T, F> ReservedJob<T, F>
where
    F: FnOnce(&dyn LocalVolumeAssetStoragePort, &RequestContext) -> Result<T, StorageError>,
{
    fn run(&mut self, assets: &dyn LocalVolumeAssetStoragePort) -> Result<T, ApiFilesError> {
        self.context.check_active().map_err(ApiFilesError::from)?;
        let Some(operation) = self.operation.take() else {
            return Err(internal_error());
        };
        operation(assets, &self.context).map_err(project_storage_error)
    }

    fn publish(
        &mut self,
        shared: &Arc<WorkerShared>,
        reservation: u64,
        result: Result<T, ApiFilesError>,
    ) {
        let Some(staged) = self.staged.take() else {
            release_running_reservation(shared, reservation);
            self.cell.complete(Err(internal_error()));
            return;
        };
        let Some(cleanup) = self.cleanup.take() else {
            contain_unresolved_stage(shared, Some(staged));
            fail_worker(shared);
            self.cell.complete(Err(internal_error()));
            return;
        };
        if !retain_running_reservation(shared, reservation) {
            contain_unresolved_stage(shared, Some(staged));
            fail_worker(shared);
            self.cell.complete(Err(unavailable_error()));
            return;
        }
        let guard = OperationGuard::from_retained(shared.clone(), reservation, staged, cleanup);
        self.cell
            .complete(Ok(ReservedVerification { guard, result }));
    }
}

struct StageJob {
    cell: Arc<JobCell<OperationGuard>>,
    context: RequestContext,
    request: Option<AssetStageRequest>,
    source: Option<Box<dyn Read + Send>>,
}

impl WorkerJob for StageJob {
    fn execute(
        &mut self,
        assets: &dyn LocalVolumeAssetStoragePort,
        shared: &Arc<WorkerShared>,
        reservation: u64,
    ) {
        let result = self.run(assets);
        match result {
            Ok(staged) => self.publish_stage(shared, reservation, staged),
            Err(error) => {
                release_running_reservation(shared, reservation);
                self.cell.complete(Err(error));
            }
        }
    }

    fn fail(&mut self, error: ApiFilesError) {
        self.cell.complete(Err(error));
    }

    fn cancellation(&self) -> CancellationToken {
        self.context.cancellation()
    }
}

impl StageJob {
    fn run(
        &mut self,
        assets: &dyn LocalVolumeAssetStoragePort,
    ) -> Result<StagedAsset, ApiFilesError> {
        self.context.check_active().map_err(ApiFilesError::from)?;
        let Some(request) = self.request.take() else {
            return Err(internal_error());
        };
        let Some(mut source) = self.source.take() else {
            return Err(internal_error());
        };
        assets
            .stage(request, source.as_mut(), &self.context)
            .map_err(project_storage_error)
    }

    fn publish_stage(&self, shared: &Arc<WorkerShared>, reservation: u64, staged: StagedAsset) {
        if retain_running_reservation(shared, reservation) {
            let guard = OperationGuard::new(shared.clone(), reservation, staged, &self.context);
            self.cell.complete(Ok(guard));
        } else {
            contain_unresolved_stage(shared, Some(staged));
            fail_worker(shared);
            self.cell.complete(Err(unavailable_error()));
        }
    }
}

impl WorkerRuntime {
    fn assign(&self, job: Box<dyn WorkerJob>, assignment: Assignment) -> Result<(), ApiFilesError> {
        let cancellation = job.cancellation();
        let (mut handle, handle_poisoned) = lock_recover(&self.handle);
        if handle_poisoned {
            drop(handle);
            fail_worker(&self.shared);
            self.handle.clear_poison();
            let _ = dispose_rejected_job(job, assignment, &self.shared, internal_error());
            return Err(internal_error());
        }
        let mut outcome = self.assign_locked(&mut handle, job, cancellation, assignment);
        drop(handle);
        finish_worker_failure(&self.shared, outcome.failure);
        let rejection_error = match outcome.result {
            Ok(()) => internal_error(),
            Err(error) => error,
        };
        if outcome.rejected.take().is_some_and(|job| {
            !dispose_rejected_job(job, assignment, &self.shared, rejection_error)
        }) {
            fail_worker(&self.shared);
            return Err(internal_error());
        }
        outcome.result
    }

    fn assign_locked(
        &self,
        handle: &mut Option<JoinHandle<()>>,
        job: Box<dyn WorkerJob>,
        cancellation: CancellationToken,
        assignment: Assignment,
    ) -> AssignmentOutcome {
        let (mut state, poisoned) = lock_recover(&self.shared.state);
        if poisoned {
            let failure = take_worker_failure(&mut state);
            self.shared.state.clear_poison();
            drop(state);
            return AssignmentOutcome {
                result: Err(internal_error()),
                rejected: Some(job),
                failure,
            };
        }
        self.assign_healthy_locked(handle, state, job, cancellation, assignment)
    }

    fn assign_healthy_locked(
        &self,
        handle: &mut Option<JoinHandle<()>>,
        mut state: MutexGuard<'_, WorkerState>,
        job: Box<dyn WorkerJob>,
        cancellation: CancellationToken,
        assignment: Assignment,
    ) -> AssignmentOutcome {
        let starts_thread = match assign_state(&mut state, job, cancellation, assignment) {
            Ok(starts_thread) => starts_thread,
            Err((error, job)) => {
                drop(state);
                return AssignmentOutcome {
                    result: Err(error),
                    rejected: Some(job),
                    failure: WorkerFailure::default(),
                };
            }
        };
        if starts_thread && spawn_worker(handle, self).is_err() {
            let rejected = state.job.take();
            let cancellation = state.active_cancellation.take();
            mark_failed(&mut state);
            drop(state);
            return AssignmentOutcome {
                result: Err(unavailable_error()),
                rejected,
                failure: WorkerFailure {
                    cancellation,
                    pending: None,
                },
            };
        }
        drop(state);
        self.shared.changed.notify_one();
        AssignmentOutcome {
            result: Ok(()),
            rejected: None,
            failure: WorkerFailure::default(),
        }
    }

    fn shutdown(&self) -> Result<(), ApiFilesError> {
        let (mut handle, poisoned) = lock_recover(&self.handle);
        let prepared = (!poisoned).then(|| prepare_stop(&self.shared));
        let joining = handle.take();
        drop(handle);
        let prepared = match prepared {
            Some(prepared) => prepared,
            None => {
                fail_worker(&self.shared);
                self.handle.clear_poison();
                prepare_stop(&self.shared)
            }
        };
        let failed_before = prepared.failed;
        complete_stop(&self.shared, prepared);
        let join_failed = joining
            .map(JoinHandle::join)
            .is_some_and(|result| result.is_err());
        if poisoned
            || failed_before
            || join_failed
            || current_phase(&self.shared) == WorkerPhase::Failed
        {
            return Err(internal_error());
        }
        Ok(())
    }

    fn detach(&self) {
        let (mut handle, poisoned) = lock_recover(&self.handle);
        let prepared = (!poisoned).then(|| prepare_stop(&self.shared));
        let detached = handle.take();
        drop(handle);
        let prepared = match prepared {
            Some(prepared) => prepared,
            None => {
                fail_worker(&self.shared);
                self.handle.clear_poison();
                prepare_stop(&self.shared)
            }
        };
        complete_stop(&self.shared, prepared);
        drop(detached);
    }
}

fn worker_entry(shared: Arc<WorkerShared>, assets: Arc<dyn LocalVolumeAssetStoragePort>) {
    let result = catch_unwind(AssertUnwindSafe(|| worker_loop(&shared, assets.as_ref())));
    if result.is_err() {
        fail_worker(&shared);
    }
}

fn worker_loop(shared: &Arc<WorkerShared>, assets: &dyn LocalVolumeAssetStoragePort) {
    loop {
        if !run_action(wait_for_action(shared), shared, assets) {
            return;
        }
    }
}

fn run_action(
    action: WorkerAction,
    shared: &Arc<WorkerShared>,
    assets: &dyn LocalVolumeAssetStoragePort,
) -> bool {
    match action {
        WorkerAction::Run(job, reservation) => run_job(job, reservation, shared, assets),
        WorkerAction::Fail(job, error) => {
            if !fail_and_drop_job(job, error) {
                fail_worker(shared);
            }
            false
        }
        WorkerAction::Stop => false,
    }
}

fn run_job(
    mut job: Box<dyn WorkerJob>,
    reservation: u64,
    shared: &Arc<WorkerShared>,
    assets: &dyn LocalVolumeAssetStoragePort,
) -> bool {
    let result = catch_unwind(AssertUnwindSafe(|| {
        job.execute(assets, shared, reservation);
    }));
    if result.is_ok() {
        return true;
    }
    fail_worker(shared);
    let _ = fail_and_drop_job(job, internal_error());
    false
}

enum WorkerAction {
    Run(Box<dyn WorkerJob>, u64),
    Fail(Box<dyn WorkerJob>, ApiFilesError),
    Stop,
}

fn wait_for_action(shared: &Arc<WorkerShared>) -> WorkerAction {
    let (mut state, poisoned) = lock_worker(shared);
    if poisoned {
        return failed_action(&mut state);
    }
    loop {
        if let Some(action) = next_action(&mut state) {
            return action;
        }
        let waited = shared.changed.wait(state);
        let (next, wait_poisoned) = recover_wait(waited);
        state = next;
        if wait_poisoned {
            return recover_poisoned_wait(shared, state);
        }
    }
}

fn recover_poisoned_wait(
    shared: &Arc<WorkerShared>,
    mut state: MutexGuard<'_, WorkerState>,
) -> WorkerAction {
    let failure = take_worker_failure(&mut state);
    shared.state.clear_poison();
    drop(state);
    finish_worker_failure(shared, failure);
    let (mut state, _) = lock_worker(shared);
    failed_action(&mut state)
}

fn next_action(state: &mut WorkerState) -> Option<WorkerAction> {
    match state.phase {
        WorkerPhase::Assigned => take_assigned_job(state),
        WorkerPhase::Failed => Some(failed_action(state)),
        WorkerPhase::Stopping => Some(stopping_action(state)),
        WorkerPhase::Stopped => Some(WorkerAction::Stop),
        WorkerPhase::Cold | WorkerPhase::Running | WorkerPhase::Idle => None,
    }
}

fn take_assigned_job(state: &mut WorkerState) -> Option<WorkerAction> {
    let job = state.job.take()?;
    let Some(reservation) = state.reservation else {
        state.job = Some(job);
        mark_failed(state);
        return Some(failed_action(state));
    };
    state.phase = WorkerPhase::Running;
    Some(WorkerAction::Run(job, reservation))
}

fn failed_action(state: &mut WorkerState) -> WorkerAction {
    match state.job.take() {
        Some(job) => WorkerAction::Fail(job, internal_error()),
        None => WorkerAction::Stop,
    }
}

fn stopping_action(state: &mut WorkerState) -> WorkerAction {
    state.phase = WorkerPhase::Stopped;
    match state.job.take() {
        Some(job) => WorkerAction::Fail(job, unavailable_error()),
        None => WorkerAction::Stop,
    }
}

fn prepare_stop(shared: &WorkerShared) -> StopPreparation {
    let (mut state, poisoned) = lock_recover(&shared.state);
    let failure = if poisoned {
        shared.state.clear_poison();
        take_worker_failure(&mut state)
    } else {
        WorkerFailure::default()
    };
    let failed = poisoned || state.phase == WorkerPhase::Failed;
    let cancellation = state.active_cancellation.take();
    match state.phase {
        WorkerPhase::Cold => state.phase = WorkerPhase::Stopped,
        WorkerPhase::Failed | WorkerPhase::Stopped => {}
        WorkerPhase::Assigned
        | WorkerPhase::Running
        | WorkerPhase::Idle
        | WorkerPhase::Stopping => {
            state.phase = WorkerPhase::Stopping;
        }
    }
    state.reservation = None;
    drop(state);
    StopPreparation {
        failed,
        cancellation,
        failure,
    }
}

fn complete_stop(shared: &WorkerShared, prepared: StopPreparation) {
    finish_worker_failure(shared, prepared.failure);
    if let Some(cancellation) = prepared.cancellation {
        cancellation.cancel();
    }
    shared.changed.notify_all();
}

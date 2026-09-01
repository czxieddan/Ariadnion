// crates/optional/ariadnion-file-service/src/worker/operation.rs - Rust source for Ariadnion.
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

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, LockResult, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use ariadnion_api_files::{ApiFilesError, ApiFilesErrorCode};
use ariadnion_core::{CancellationToken, RequestContext};
use ariadnion_storage_asset::{StorageError, StorageErrorCode};

use super::{
    Assignment, CommitAttempt, WorkerFailure, WorkerJob, WorkerPhase, WorkerRuntime, WorkerShared,
    WorkerState, release_retained_reservation,
};

/// One child request context owned by a submitted worker operation.
pub(super) struct OperationContext {
    /// The context presented to blocking storage.
    pub(super) context: RequestContext,
    cancellation: CancellationToken,
}

impl OperationContext {
    /// Derives an independently cancellable child from the caller context.
    pub(super) fn child(parent: &RequestContext) -> Self {
        let cancellation = parent.cancellation().child();
        let context = RequestContext::new(
            parent.request_id().clone(),
            parent.trace_id().clone(),
            parent.principal().cloned(),
            parent.deadline(),
            cancellation.clone(),
        );
        Self {
            context,
            cancellation,
        }
    }
}

#[derive(Clone, Copy)]
enum Preflight {
    RequireActive,
    Deferred,
}

#[derive(Clone, Copy)]
pub(super) enum CommitCodeClass {
    Determinate,
    Indeterminate,
    Unknown,
}

pub(super) fn classify_commit_error(error: StorageError) -> CommitAttempt {
    let class = classify_commit_machine_code(error.code().as_str());
    let projected = project_storage_error(error);
    commit_attempt_from_class(class, projected)
}

pub(super) fn classify_commit_machine_code(code: &str) -> CommitCodeClass {
    match code {
        "STORAGE_COMMIT_INDETERMINATE" => CommitCodeClass::Indeterminate,
        "STORAGE_INVALID_ARGUMENT"
        | "STORAGE_NOT_FOUND"
        | "STORAGE_CONFLICT"
        | "STORAGE_DEADLINE_EXCEEDED"
        | "STORAGE_CANCELLED"
        | "STORAGE_RESOURCE_EXHAUSTED"
        | "STORAGE_UNAVAILABLE"
        | "STORAGE_INTEGRITY_FAILURE"
        | "STORAGE_MIGRATION_REQUIRED"
        | "STORAGE_INTERNAL" => CommitCodeClass::Determinate,
        _ => CommitCodeClass::Unknown,
    }
}

pub(super) fn commit_attempt_from_class(
    class: CommitCodeClass,
    projected: ApiFilesError,
) -> CommitAttempt {
    match class {
        CommitCodeClass::Determinate => CommitAttempt::Determinate(projected),
        CommitCodeClass::Indeterminate => CommitAttempt::Indeterminate(projected),
        CommitCodeClass::Unknown => CommitAttempt::Unknown(projected),
    }
}

pub(super) fn project_storage_error(error: StorageError) -> ApiFilesError {
    ApiFilesError::new(match error.code() {
        StorageErrorCode::InvalidArgument
        | StorageErrorCode::IntegrityFailure
        | StorageErrorCode::MigrationRequired
        | StorageErrorCode::Internal => ApiFilesErrorCode::IntegrityFailure,
        StorageErrorCode::NotFound => ApiFilesErrorCode::NotFound,
        StorageErrorCode::Conflict => ApiFilesErrorCode::Conflict,
        code => project_storage_execution_error(code),
    })
}

fn project_storage_execution_error(code: StorageErrorCode) -> ApiFilesErrorCode {
    match code {
        StorageErrorCode::DeadlineExceeded => ApiFilesErrorCode::DeadlineExceeded,
        StorageErrorCode::Cancelled => ApiFilesErrorCode::Cancelled,
        StorageErrorCode::ResourceExhausted => ApiFilesErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => ApiFilesErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => ApiFilesErrorCode::CommitIndeterminate,
        _ => ApiFilesErrorCode::IntegrityFailure,
    }
}

/// A runtime-neutral one-shot future for one blocking worker result.
pub(crate) struct JobFuture<T> {
    runtime: Arc<WorkerRuntime>,
    cell: Arc<JobCell<T>>,
    job: Option<Box<dyn WorkerJob>>,
    assignment: Assignment,
    operation: OperationContext,
    preflight: Preflight,
    submitted: bool,
    finished: bool,
}

impl<T> JobFuture<T>
where
    T: Send + 'static,
{
    /// Creates a future that rejects inactive requests before worker admission.
    pub(super) fn new(
        runtime: Arc<WorkerRuntime>,
        cell: Arc<JobCell<T>>,
        job: Box<dyn WorkerJob>,
        assignment: Assignment,
        operation: OperationContext,
    ) -> Self {
        Self {
            runtime,
            cell,
            job: Some(job),
            assignment,
            operation,
            preflight: Preflight::RequireActive,
            submitted: false,
            finished: false,
        }
    }

    /// Creates a future whose job classifies inactive requests with retained state.
    pub(super) fn deferred(
        runtime: Arc<WorkerRuntime>,
        cell: Arc<JobCell<T>>,
        job: Box<dyn WorkerJob>,
        assignment: Assignment,
        operation: OperationContext,
    ) -> Self {
        Self {
            runtime,
            cell,
            job: Some(job),
            assignment,
            operation,
            preflight: Preflight::Deferred,
            submitted: false,
            finished: false,
        }
    }

    /// Creates an already-completed outer failure without worker admission.
    pub(super) fn ready(
        runtime: Arc<WorkerRuntime>,
        operation: OperationContext,
        error: ApiFilesError,
    ) -> Self {
        let cell = Arc::new(JobCell::new(runtime.shared.clone()));
        cell.complete(Err(error));
        Self {
            runtime,
            cell,
            job: None,
            assignment: Assignment::Fresh,
            operation,
            preflight: Preflight::RequireActive,
            submitted: true,
            finished: false,
        }
    }

    fn submit(&mut self) -> Result<(), ApiFilesError> {
        let Some(job) = self.job.take() else {
            return Err(internal_error());
        };
        self.runtime.assign(job, self.assignment)?;
        self.submitted = true;
        Ok(())
    }

    fn release_unsubmitted_reservation(&mut self) {
        if self.submitted {
            return;
        }
        if let Assignment::Reserved(reservation) = self.assignment {
            release_retained_reservation(&self.runtime.shared, reservation);
        }
    }

    fn prepare_poll(&mut self, waker: &Waker) -> Result<(), ApiFilesError> {
        if self.finished {
            return Err(internal_error());
        }
        self.check_before_submission()?;
        self.cell.register_waker(waker)?;
        self.submit_if_needed()
    }

    fn check_before_submission(&self) -> Result<(), ApiFilesError> {
        if self.submitted || matches!(self.preflight, Preflight::Deferred) {
            return Ok(());
        }
        self.operation
            .context
            .check_active()
            .map_err(ApiFilesError::from)
    }

    fn submit_if_needed(&mut self) -> Result<(), ApiFilesError> {
        if self.submitted {
            return Ok(());
        }
        self.submit()
    }

    fn resolve_poll_error(&mut self, error: ApiFilesError) -> Poll<Result<T, ApiFilesError>> {
        self.release_unsubmitted_reservation();
        self.finished = true;
        Poll::Ready(Err(error))
    }
}

impl<T> Future for JobFuture<T>
where
    T: Send + 'static,
{
    type Output = Result<T, ApiFilesError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<T, ApiFilesError>> {
        let result = match self.prepare_poll(context.waker()) {
            Ok(()) => self.cell.poll_ready(),
            Err(error) => return self.resolve_poll_error(error),
        };
        if result.is_ready() {
            self.finished = true;
        }
        result
    }
}

impl<T> Drop for JobFuture<T> {
    fn drop(&mut self) {
        self.operation.cancellation.cancel();
        self.release_reservation_on_drop();
    }
}

impl<T> JobFuture<T> {
    fn release_reservation_on_drop(&self) {
        if self.submitted {
            return;
        }
        if let Assignment::Reserved(reservation) = self.assignment {
            release_retained_reservation(&self.runtime.shared, reservation);
        }
    }
}

/// A poison-aware one-shot result cell with panic-contained waker delivery.
/// Its mutex is released before worker failure, waker delivery, or retained-value destruction.
pub(super) struct JobCell<T> {
    state: Mutex<CellState<T>>,
    /// The worker failed closed if result delivery cannot remain contained.
    pub(super) worker: Arc<WorkerShared>,
}

struct CellState<T> {
    result: Option<Result<T, ApiFilesError>>,
    waker: Option<Waker>,
    completing: bool,
    failed: bool,
}

enum CellReadiness<T> {
    Pending,
    Ready {
        result: Result<T, ApiFilesError>,
        waker: Option<Waker>,
        failed: bool,
    },
}

type CompletionStep<T> = Result<Option<Waker>, (Option<Result<T, ApiFilesError>>, Option<Waker>)>;

impl<T> JobCell<T> {
    /// Creates an empty result cell tied to one worker lifecycle.
    pub(super) fn new(worker: Arc<WorkerShared>) -> Self {
        Self {
            state: Mutex::new(CellState {
                result: None,
                waker: None,
                completing: false,
                failed: false,
            }),
            worker,
        }
    }

    /// Registers a replacement waker without allowing clone or drop panics to escape.
    pub(super) fn register_waker(&self, waker: &Waker) -> Result<(), ApiFilesError> {
        let cloned = clone_waker(waker).map_err(|error| self.fail(error))?;
        let replaced = {
            let (mut state, poisoned) = lock_cell(&self.state);
            if poisoned || state.failed {
                drop(state);
                let _ = drop_caught(cloned);
                return Err(self.fail(internal_error()));
            }
            state.waker.replace(cloned)
        };
        if drop_caught(replaced).is_err() {
            return Err(self.fail(internal_error()));
        }
        Ok(())
    }

    /// Polls and consumes the completed result when it is ready.
    pub(super) fn poll_ready(&self) -> Poll<Result<T, ApiFilesError>> {
        match self.take_readiness() {
            CellReadiness::Pending => Poll::Pending,
            CellReadiness::Ready {
                result,
                waker,
                failed,
            } => self.deliver_ready(result, waker, failed),
        }
    }

    fn take_readiness(&self) -> CellReadiness<T> {
        let (mut state, poisoned) = lock_cell(&self.state);
        if state.completing {
            return CellReadiness::Pending;
        }
        if poisoned || state.failed {
            state.failed = true;
            return CellReadiness::Ready {
                result: Err(internal_error()),
                waker: state.waker.take(),
                failed: true,
            };
        }
        match state.result.take() {
            Some(result) => CellReadiness::Ready {
                result,
                waker: state.waker.take(),
                failed: false,
            },
            None => CellReadiness::Pending,
        }
    }

    fn deliver_ready(
        &self,
        result: Result<T, ApiFilesError>,
        waker: Option<Waker>,
        failed: bool,
    ) -> Poll<Result<T, ApiFilesError>> {
        if drop_caught(waker).is_err() {
            let _ = drop_caught(result);
            fail_worker(&self.worker);
            return Poll::Ready(Err(internal_error()));
        }
        if failed {
            fail_worker(&self.worker);
        }
        Poll::Ready(result)
    }

    /// Completes the cell once and contains every retained-waker operation.
    pub(super) fn complete(&self, result: Result<T, ApiFilesError>) {
        let Some(waker) = self.begin_completion(result) else {
            return;
        };
        self.drive_completion(waker);
    }

    fn begin_completion(&self, result: Result<T, ApiFilesError>) -> Option<Option<Waker>> {
        let waker = {
            let (mut state, poisoned) = lock_cell(&self.state);
            if state.completing || state.result.is_some() {
                return None;
            }
            state.failed |= poisoned;
            state.completing = true;
            state.result = Some(if state.failed {
                Err(internal_error())
            } else {
                result
            });
            state.waker.take()
        };
        Some(waker)
    }

    fn drive_completion(&self, mut waker: Option<Waker>) {
        loop {
            let wake_failed = wake_waker(waker).is_err();
            match self.next_completion_step(wake_failed) {
                Ok(Some(retry)) => waker = Some(retry),
                Ok(None) => return,
                Err((discarded, waker)) => {
                    self.finish_failed_completion(discarded, waker);
                    return;
                }
            }
        }
    }

    fn next_completion_step(&self, wake_failed: bool) -> CompletionStep<T> {
        let (mut state, poisoned) = lock_cell(&self.state);
        if wake_failed || poisoned || state.failed {
            state.failed = true;
            let discarded = state.result.replace(Err(internal_error()));
            return Err((discarded, state.waker.take()));
        }
        match state.waker.take() {
            Some(waker) => Ok(Some(waker)),
            None => {
                state.completing = false;
                Ok(None)
            }
        }
    }

    fn finish_failed_completion(
        &self,
        discarded: Option<Result<T, ApiFilesError>>,
        waker: Option<Waker>,
    ) {
        let _ = drop_caught(discarded);
        fail_worker(&self.worker);
        let (mut state, _) = lock_cell(&self.state);
        state.failed = true;
        state.completing = false;
        drop(state);
        let _ = wake_waker(waker);
    }

    /// Fails the cell and worker while containing retained-value destruction.
    pub(super) fn fail(&self, error: ApiFilesError) -> ApiFilesError {
        let (waker, discarded) = {
            let (mut state, _) = lock_cell(&self.state);
            state.failed = true;
            state.completing = false;
            let discarded = state.result.replace(Err(error));
            (state.waker.take(), discarded)
        };
        let waker_failed = drop_caught(waker).is_err();
        let result_failed = drop_caught(discarded).is_err();
        let disposal_failed = waker_failed || result_failed;
        fail_worker(&self.worker);
        if disposal_failed {
            internal_error()
        } else {
            error
        }
    }
}

impl<T> Drop for JobCell<T> {
    fn drop(&mut self) {
        let waker = match self.state.get_mut() {
            Ok(state) => state.waker.take(),
            Err(poisoned) => poisoned.into_inner().waker.take(),
        };
        if drop_caught(waker).is_err() {
            fail_worker(&self.worker);
        }
    }
}

fn lock_cell<T>(state: &Mutex<T>) -> (MutexGuard<'_, T>, bool) {
    let (guard, poisoned) = lock_recover(state);
    if poisoned {
        state.clear_poison();
    }
    (guard, poisoned)
}

fn clone_waker(waker: &Waker) -> Result<Waker, ApiFilesError> {
    catch_unwind(AssertUnwindSafe(|| waker.clone())).map_err(|_| internal_error())
}

fn wake_waker(waker: Option<Waker>) -> Result<(), ()> {
    let Some(waker) = waker else {
        return Ok(());
    };
    catch_unwind(AssertUnwindSafe(|| waker.wake())).map_err(|_| ())
}

pub(super) fn fail_and_drop_job(mut job: Box<dyn WorkerJob>, error: ApiFilesError) -> bool {
    let failure_contained = catch_unwind(AssertUnwindSafe(|| job.fail(error))).is_ok();
    let drop_contained = drop_caught(job).is_ok();
    failure_contained && drop_contained
}

fn drop_caught<T>(value: T) -> Result<(), ()> {
    catch_unwind(AssertUnwindSafe(|| drop(value))).map_err(|_| ())
}

pub(super) fn fail_worker(shared: &Arc<WorkerShared>) {
    let (mut state, _) = lock_worker(shared);
    let failure = take_worker_failure(&mut state);
    drop(state);
    finish_worker_failure(shared, failure);
}

pub(super) fn take_worker_failure(state: &mut WorkerState) -> WorkerFailure {
    let failure = WorkerFailure {
        cancellation: state.active_cancellation.take(),
        pending: state.job.take(),
    };
    mark_failed(state);
    failure
}

pub(super) fn finish_worker_failure(shared: &WorkerShared, failure: WorkerFailure) {
    if let Some(cancellation) = failure.cancellation {
        cancellation.cancel();
    }
    shared.changed.notify_all();
    if let Some(job) = failure.pending {
        let _ = fail_and_drop_job(job, internal_error());
    }
}

pub(super) fn mark_failed(state: &mut WorkerState) {
    state.phase = WorkerPhase::Failed;
    state.reservation = None;
    state.active_cancellation = None;
}

pub(super) fn current_phase(shared: &Arc<WorkerShared>) -> WorkerPhase {
    let (state, poisoned) = lock_worker(shared);
    if poisoned {
        WorkerPhase::Failed
    } else {
        state.phase
    }
}

pub(super) fn lock_worker(shared: &WorkerShared) -> (MutexGuard<'_, WorkerState>, bool) {
    let mut recovered = false;
    loop {
        match shared.state.lock() {
            Ok(state) => return (state, recovered),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                let failure = take_worker_failure(&mut state);
                drop(state);
                shared.state.clear_poison();
                finish_worker_failure(shared, failure);
                recovered = true;
            }
        }
    }
}

pub(super) fn lock_recover<T>(mutex: &Mutex<T>) -> (MutexGuard<'_, T>, bool) {
    match mutex.lock() {
        Ok(guard) => (guard, false),
        Err(poisoned) => (poisoned.into_inner(), true),
    }
}

pub(super) fn recover_wait<T>(result: LockResult<T>) -> (T, bool) {
    match result {
        Ok(value) => (value, false),
        Err(poisoned) => (poisoned.into_inner(), true),
    }
}

pub(super) fn project_pipe_error(error: std::io::Error) -> StorageError {
    let code = match error.kind() {
        std::io::ErrorKind::Interrupted => StorageErrorCode::Cancelled,
        std::io::ErrorKind::TimedOut => StorageErrorCode::DeadlineExceeded,
        std::io::ErrorKind::BrokenPipe => StorageErrorCode::Unavailable,
        _ => StorageErrorCode::Internal,
    };
    StorageError::new(code)
}

pub(super) const fn internal_error() -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::Internal)
}

pub(super) const fn unavailable_error() -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::Unavailable)
}

pub(super) const fn resource_error() -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::ResourceExhausted)
}

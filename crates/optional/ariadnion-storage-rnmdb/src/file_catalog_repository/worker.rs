// crates/optional/ariadnion-storage-rnmdb/src/file_catalog_repository/worker.rs - Rust source for Ariadnion.
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
//! Bounded lazy execution for durable file-catalog operations.

#[cfg(feature = "test-hooks")]
use std::cell::Cell;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(feature = "test-hooks")]
use std::sync::{Condvar, LockResult};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
#[cfg(feature = "test-hooks")]
use std::time::Duration;

use ariadnion_api_files::{ApiFilesError, ApiFilesErrorCode};
use ariadnion_core::{CancellationToken, RequestContext};

use super::{CatalogSecrets, api_error};
use crate::RnmdbSessionOwner;

const WORKER_NAME: &str = "ariadnion-file-catalog";

#[cfg(feature = "test-hooks")]
std::thread_local! {
    static INJECT_NEXT_RESULT_WAKER_CLONE_PANIC: Cell<bool> = const { Cell::new(false) };
}

pub(super) struct CatalogWorker {
    session: Arc<RnmdbSessionOwner>,
    secrets: Arc<CatalogSecrets>,
    shutdown: Arc<AtomicBool>,
    control: Mutex<WorkerControl>,
}

struct WorkerControl {
    capacity: usize,
    sender: Option<SyncSender<Box<dyn WorkerJob>>>,
    handle: Option<JoinHandle<()>>,
    failed: bool,
    probe: WorkerProbe,
}

impl CatalogWorker {
    pub(super) fn new(
        session: Arc<RnmdbSessionOwner>,
        secrets: Arc<CatalogSecrets>,
        capacity: usize,
    ) -> Self {
        Self {
            session,
            secrets,
            shutdown: Arc::new(AtomicBool::new(false)),
            control: Mutex::new(WorkerControl {
                capacity,
                sender: None,
                handle: None,
                failed: false,
                probe: WorkerProbe::new(),
            }),
        }
    }

    pub(super) async fn execute<T, F>(
        &self,
        context: RequestContext,
        operation: F,
    ) -> Result<T, ApiFilesError>
    where
        T: Send + 'static,
        F: FnOnce(
                &Arc<RnmdbSessionOwner>,
                &CatalogSecrets,
                &RequestContext,
            ) -> Result<T, ApiFilesError>
            + Send
            + 'static,
    {
        JobFuture::new(
            &self.control,
            self.session.clone(),
            self.shutdown.clone(),
            self.secrets.clone(),
            context,
            operation,
        )
        .await
    }

    pub(super) fn started(&self) -> bool {
        lock_worker(&self.control).sender.is_some()
    }

    #[cfg(feature = "test-hooks")]
    pub(super) fn inject_next_result_waker_clone_panic(&self) -> Result<(), ApiFilesError> {
        INJECT_NEXT_RESULT_WAKER_CLONE_PANIC.with(|injection| {
            if injection.replace(true) {
                return Err(api_error(ApiFilesErrorCode::Conflict));
            }
            Ok(())
        })
    }

    #[cfg(feature = "test-hooks")]
    pub(super) fn pause_next_job(&self) -> Result<FileCatalogWorkerPause, ApiFilesError> {
        lock_worker(&self.control).probe.pause_next_job()
    }
}

impl Drop for CatalogWorker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let (sender, handle) = {
            let mut control = lock_worker(&self.control);
            (control.sender.take(), control.handle.take())
        };
        drop(sender);
        if let Some(handle) = handle {
            let _join_result = handle.join();
        }
    }
}

trait WorkerJob: Send {
    fn execute(self: Box<Self>, session: &Arc<RnmdbSessionOwner>);
    fn cancel(self: Box<Self>, error: ApiFilesError);
}

struct TypedJob<T, F> {
    cell: Arc<ResultCell<T>>,
    secrets: Arc<CatalogSecrets>,
    context: RequestContext,
    operation: F,
}

impl<T, F> WorkerJob for TypedJob<T, F>
where
    T: Send + 'static,
    F: FnOnce(
            &Arc<RnmdbSessionOwner>,
            &CatalogSecrets,
            &RequestContext,
        ) -> Result<T, ApiFilesError>
        + Send
        + 'static,
{
    fn execute(self: Box<Self>, session: &Arc<RnmdbSessionOwner>) {
        let Self {
            cell,
            secrets,
            context,
            operation,
        } = *self;
        let result = catch_unwind(AssertUnwindSafe(|| operation(session, &secrets, &context)));
        match result {
            Ok(result) => cell.complete(result),
            Err(_) => {
                session.quarantine_after_worker_panic();
                cell.complete(Err(api_error(ApiFilesErrorCode::Internal)));
            }
        }
    }

    fn cancel(self: Box<Self>, error: ApiFilesError) {
        let error = prefer_context_error(&self.context, error);
        self.context.cancellation().cancel();
        self.cell.complete(Err(error));
    }
}

fn worker_loop(
    receiver: &Receiver<Box<dyn WorkerJob>>,
    shutdown: &AtomicBool,
    session: &Arc<RnmdbSessionOwner>,
    probe: &WorkerProbe,
) {
    while let Ok(job) = receiver.recv() {
        if shutdown.load(Ordering::Acquire) {
            job.cancel(api_error(ApiFilesErrorCode::Unavailable));
            drain_jobs(receiver, ApiFilesErrorCode::Unavailable);
            return;
        }
        probe.before_execute();
        job.execute(session);
    }
    drain_jobs(receiver, ApiFilesErrorCode::Unavailable);
}

fn drain_jobs(receiver: &Receiver<Box<dyn WorkerJob>>, code: ApiFilesErrorCode) {
    for job in receiver.try_iter() {
        let _cancelled = catch_unwind(AssertUnwindSafe(|| job.cancel(api_error(code))));
    }
}

struct JobFuture<'a, T> {
    worker: &'a Mutex<WorkerControl>,
    session: Arc<RnmdbSessionOwner>,
    shutdown: Arc<AtomicBool>,
    cell: Arc<ResultCell<T>>,
    job: Option<Box<dyn WorkerJob>>,
    cancellation: CancellationToken,
    status_context: RequestContext,
    submitted: bool,
}

impl<'a, T> JobFuture<'a, T>
where
    T: Send + 'static,
{
    fn new<F>(
        worker: &'a Mutex<WorkerControl>,
        session: Arc<RnmdbSessionOwner>,
        shutdown: Arc<AtomicBool>,
        secrets: Arc<CatalogSecrets>,
        context: RequestContext,
        operation: F,
    ) -> Self
    where
        F: FnOnce(
                &Arc<RnmdbSessionOwner>,
                &CatalogSecrets,
                &RequestContext,
            ) -> Result<T, ApiFilesError>
            + Send
            + 'static,
    {
        let cancellation = context.cancellation();
        let status_context = RequestContext::new(
            context.request_id().clone(),
            context.trace_id().clone(),
            context.principal().cloned(),
            context.deadline(),
            cancellation.clone(),
        );
        let cell = Arc::new(ResultCell::new());
        let job = TypedJob {
            cell: cell.clone(),
            secrets,
            context,
            operation,
        };
        Self {
            worker,
            session,
            shutdown,
            cell,
            job: Some(Box::new(job)),
            cancellation,
            status_context,
            submitted: false,
        }
    }

    fn submit_if_needed(&mut self) -> Option<Result<T, ApiFilesError>> {
        if self.submitted {
            return None;
        }
        match self.submit_pending_job() {
            Ok(()) => {
                self.submitted = true;
                None
            }
            Err(error) => Some(Err(error)),
        }
    }

    fn submit_pending_job(&mut self) -> Result<(), ApiFilesError> {
        let job = self.job.take().ok_or_else(|| {
            prefer_context_error(&self.status_context, api_error(ApiFilesErrorCode::Internal))
        })?;
        submit_job(self.worker, &self.session, &self.shutdown, job)
            .map_err(|error| prefer_context_error(&self.status_context, error))
    }
}

impl<T> Future for JobFuture<'_, T>
where
    T: Send + 'static,
{
    type Output = Result<T, ApiFilesError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(result) = self.submit_if_needed() {
            return Poll::Ready(result);
        }
        self.cell.poll(context)
    }
}

impl<T> Drop for JobFuture<'_, T> {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn submit_job(
    worker: &Mutex<WorkerControl>,
    session: &Arc<RnmdbSessionOwner>,
    shutdown: &Arc<AtomicBool>,
    job: Box<dyn WorkerJob>,
) -> Result<(), ApiFilesError> {
    ensure_worker_available(shutdown)?;
    let mut control = lock_worker(worker);
    ensure_worker_started(&mut control, session, shutdown)?;
    send_job(&mut control, job)
}

fn ensure_worker_available(shutdown: &AtomicBool) -> Result<(), ApiFilesError> {
    if shutdown.load(Ordering::Acquire) {
        Err(api_error(ApiFilesErrorCode::Unavailable))
    } else {
        Ok(())
    }
}

fn send_job(control: &mut WorkerControl, job: Box<dyn WorkerJob>) -> Result<(), ApiFilesError> {
    let Some(sender) = control.sender.as_ref() else {
        return Err(api_error(ApiFilesErrorCode::Unavailable));
    };
    match sender.try_send(job) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(api_error(ApiFilesErrorCode::ResourceExhausted)),
        Err(TrySendError::Disconnected(_)) => {
            control.failed = true;
            control.sender = None;
            Err(api_error(ApiFilesErrorCode::Unavailable))
        }
    }
}

fn ensure_worker_started(
    control: &mut WorkerControl,
    session: &Arc<RnmdbSessionOwner>,
    shutdown: &Arc<AtomicBool>,
) -> Result<(), ApiFilesError> {
    if control.failed {
        return Err(api_error(ApiFilesErrorCode::Unavailable));
    }
    if control.sender.is_some() {
        return Ok(());
    }
    let (sender, receiver) = mpsc::sync_channel(control.capacity);
    let worker_session = session.clone();
    let worker_shutdown = shutdown.clone();
    let probe = control.probe.clone();
    let result = thread::Builder::new()
        .name(WORKER_NAME.into())
        .spawn(move || run_worker(receiver, worker_shutdown, worker_session, probe));
    let handle = match result {
        Ok(handle) => handle,
        Err(_) => {
            control.failed = true;
            return Err(api_error(ApiFilesErrorCode::Unavailable));
        }
    };
    control.sender = Some(sender);
    control.handle = Some(handle);
    Ok(())
}

fn run_worker(
    receiver: Receiver<Box<dyn WorkerJob>>,
    shutdown: Arc<AtomicBool>,
    session: Arc<RnmdbSessionOwner>,
    probe: WorkerProbe,
) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        worker_loop(&receiver, &shutdown, &session, &probe);
    }));
    if result.is_err() {
        drain_jobs(&receiver, ApiFilesErrorCode::Internal);
    }
}

fn lock_worker(worker: &Mutex<WorkerControl>) -> MutexGuard<'_, WorkerControl> {
    match worker.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.failed = true;
            guard.sender = None;
            guard
        }
    }
}

struct ResultCell<T> {
    state: Mutex<CellState<T>>,
}

struct CellState<T> {
    result: Option<Result<T, ApiFilesError>>,
    waker: Option<Waker>,
    completing: bool,
    poisoned: bool,
}

impl<T> ResultCell<T> {
    fn new() -> Self {
        Self {
            state: Mutex::new(CellState {
                result: None,
                waker: None,
                completing: false,
                poisoned: false,
            }),
        }
    }

    fn poll(&self, context: &mut Context<'_>) -> Poll<Result<T, ApiFilesError>> {
        let mut state = lock_result(&self.state);
        if let Some(result) = take_ready_result(&mut state) {
            return Poll::Ready(result);
        }
        if let Err(error) = refresh_result_waker(&mut state, context.waker()) {
            state.poisoned = true;
            return Poll::Ready(Err(error));
        }
        Poll::Pending
    }

    fn complete(&self, result: Result<T, ApiFilesError>) {
        let mut state = lock_result(&self.state);
        if state.result.is_some() || state.completing {
            return;
        }
        state.completing = true;
        state.result = Some(if state.poisoned {
            Err(api_error(ApiFilesErrorCode::Internal))
        } else {
            result
        });
        let waker = state.waker.take();
        drop(state);
        let wake_failed = wake_result_waker(waker).is_err();
        let retry_waker = {
            let mut state = lock_result(&self.state);
            if wake_failed || state.poisoned {
                state.poisoned = true;
                state.result = Some(Err(api_error(ApiFilesErrorCode::Internal)));
            }
            state.completing = false;
            state.waker.take()
        };
        if wake_result_waker(retry_waker).is_err() {
            self.fail_after_wake_panic();
        }
    }

    fn fail_after_wake_panic(&self) {
        let mut state = lock_result(&self.state);
        state.poisoned = true;
        state.completing = false;
        state.result = Some(Err(api_error(ApiFilesErrorCode::Internal)));
        state.waker = None;
    }
}

fn take_ready_result<T>(state: &mut CellState<T>) -> Option<Result<T, ApiFilesError>> {
    if state.poisoned {
        return Some(Err(api_error(ApiFilesErrorCode::Internal)));
    }
    if state.completing {
        return None;
    }
    state.result.take()
}

fn refresh_result_waker<T>(state: &mut CellState<T>, waker: &Waker) -> Result<(), ApiFilesError> {
    let replace = state
        .waker
        .as_ref()
        .is_none_or(|registered| !registered.will_wake(waker));
    if replace {
        state.waker = Some(clone_result_waker(waker)?);
    }
    Ok(())
}

fn wake_result_waker(waker: Option<Waker>) -> Result<(), ()> {
    let Some(waker) = waker else {
        return Ok(());
    };
    catch_unwind(AssertUnwindSafe(|| waker.wake())).map_err(|_| ())
}

fn clone_result_waker(waker: &Waker) -> Result<Waker, ApiFilesError> {
    catch_unwind(AssertUnwindSafe(|| {
        inject_result_waker_clone_panic();
        waker.clone()
    }))
    .map_err(|_| api_error(ApiFilesErrorCode::Internal))
}

#[cfg(feature = "test-hooks")]
fn inject_result_waker_clone_panic() {
    INJECT_NEXT_RESULT_WAKER_CLONE_PANIC.with(|injection| {
        if injection.replace(false) {
            std::panic::resume_unwind(Box::new("injected result-waker clone panic"));
        }
    });
}

#[cfg(not(feature = "test-hooks"))]
const fn inject_result_waker_clone_panic() {}

fn lock_result<T>(state: &Mutex<CellState<T>>) -> MutexGuard<'_, CellState<T>> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.poisoned = true;
            guard
        }
    }
}

fn prefer_context_error(context: &RequestContext, fallback: ApiFilesError) -> ApiFilesError {
    match context.check_active() {
        Ok(()) => fallback,
        Err(error) => ApiFilesError::from(error),
    }
}

#[derive(Clone)]
struct WorkerProbe {
    #[cfg(feature = "test-hooks")]
    pause: Arc<WorkerPauseState>,
}

impl WorkerProbe {
    fn new() -> Self {
        Self {
            #[cfg(feature = "test-hooks")]
            pause: Arc::new(WorkerPauseState::new()),
        }
    }

    fn before_execute(&self) {
        #[cfg(feature = "test-hooks")]
        self.pause.before_execute();
    }

    #[cfg(feature = "test-hooks")]
    fn pause_next_job(&self) -> Result<FileCatalogWorkerPause, ApiFilesError> {
        self.pause.arm()?;
        Ok(FileCatalogWorkerPause {
            state: self.pause.clone(),
        })
    }
}

#[cfg(feature = "test-hooks")]
struct WorkerPauseState {
    state: Mutex<WorkerPauseStatus>,
    changed: Condvar,
}

#[cfg(feature = "test-hooks")]
#[derive(Clone, Copy)]
struct WorkerPauseStatus {
    armed: bool,
    paused: bool,
    released: bool,
}

#[cfg(feature = "test-hooks")]
impl WorkerPauseState {
    fn new() -> Self {
        Self {
            state: Mutex::new(WorkerPauseStatus {
                armed: false,
                paused: false,
                released: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn arm(&self) -> Result<(), ApiFilesError> {
        let mut state = recover_lock(self.state.lock());
        if state.armed || state.paused {
            return Err(api_error(ApiFilesErrorCode::Conflict));
        }
        state.armed = true;
        state.released = false;
        Ok(())
    }

    fn before_execute(&self) {
        let mut state = recover_lock(self.state.lock());
        if !state.armed {
            return;
        }
        state.armed = false;
        state.paused = true;
        self.changed.notify_all();
        while !state.released {
            state = recover_lock(self.changed.wait(state));
        }
        state.paused = false;
        state.released = false;
        self.changed.notify_all();
    }

    fn wait_until_paused(&self, timeout: Duration) -> bool {
        let state = recover_lock(self.state.lock());
        if state.paused {
            return true;
        }
        let result = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.paused);
        let (state, _) = recover_lock(result);
        state.paused
    }

    fn release(&self) {
        let mut state = recover_lock(self.state.lock());
        state.released = true;
        state.armed = false;
        self.changed.notify_all();
    }
}

#[cfg(feature = "test-hooks")]
fn recover_lock<T>(result: LockResult<T>) -> T {
    match result {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Controller for one test-only pause before a catalog worker executes a job.
#[cfg(feature = "test-hooks")]
pub struct FileCatalogWorkerPause {
    state: Arc<WorkerPauseState>,
}

#[cfg(feature = "test-hooks")]
impl FileCatalogWorkerPause {
    /// Waits until the worker reaches the armed pause, bounded by `timeout`.
    #[must_use]
    pub fn wait_until_paused(&self, timeout: Duration) -> bool {
        self.state.wait_until_paused(timeout)
    }

    /// Releases the paused worker or disarms a pause that has not been reached.
    pub fn release(&self) {
        self.state.release();
    }
}

#[cfg(feature = "test-hooks")]
impl Drop for FileCatalogWorkerPause {
    fn drop(&mut self) {
        self.state.release();
    }
}

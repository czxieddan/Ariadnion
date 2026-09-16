// crates/optional/ariadnion-storage-rnmdb/src/vault_repository/worker.rs - Bounded vault worker for Ariadnion.
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
//! Bounded dedicated worker and cancellation-aware future ownership.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

use ariadnion_account_vault::{BoxVaultFuture, VaultError, VaultErrorCode};
use ariadnion_core::CancellationToken;

use super::error;
use crate::RnmdbSessionOwner;

const QUEUE_CAPACITY: usize = 1 << 8;

type Job = Box<dyn FnOnce(&RnmdbSessionOwner) + Send>;

pub(super) struct VaultWorker {
    sender: SyncSender<Job>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl VaultWorker {
    pub(super) fn start(owner: Arc<RnmdbSessionOwner>) -> Result<Self, VaultError> {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let handle = thread::Builder::new()
            .name("ariadnion-vault".to_owned())
            .spawn(move || run(owner, receiver, worker_stop))
            .map_err(|_| error(VaultErrorCode::Unavailable))?;
        Ok(Self {
            sender,
            stop,
            handle: Some(handle),
        })
    }

    pub(super) fn submit<T: Send + 'static>(
        &self,
        cancellation: CancellationToken,
        action: impl FnOnce(&RnmdbSessionOwner) -> Result<T, VaultError> + Send + 'static,
    ) -> BoxVaultFuture<'_, T> {
        if self.stop.load(Ordering::Acquire) {
            return Box::pin(std::future::ready(Err(error(VaultErrorCode::Unavailable))));
        }
        let cell = Arc::new(Cell::new());
        let worker_cell = cell.clone();
        let worker_stop = self.stop.clone();
        let job = Box::new(move |owner: &RnmdbSessionOwner| {
            execute(owner, worker_cell, worker_stop, action);
        });
        match self.sender.try_send(job) {
            Ok(()) => Box::pin(ResultFuture { cell, cancellation }),
            Err(TrySendError::Full(_)) => Box::pin(std::future::ready(Err(error(
                VaultErrorCode::ResourceExhausted,
            )))),
            Err(TrySendError::Disconnected(_)) => {
                Box::pin(std::future::ready(Err(error(VaultErrorCode::Unavailable))))
            }
        }
    }
}

impl Drop for VaultWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _wake = self.sender.try_send(Box::new(|_| {}));
        if let Some(handle) = self.handle.take() {
            let _joined = handle.join();
        }
    }
}

fn run(owner: Arc<RnmdbSessionOwner>, receiver: Receiver<Job>, stop: Arc<AtomicBool>) {
    loop {
        let received = receiver.recv();
        match received {
            Ok(job) => job(&owner),
            Err(_) => return,
        }
        if stop.load(Ordering::Acquire) {
            drain(&owner, &receiver);
            return;
        }
    }
}

fn drain(owner: &RnmdbSessionOwner, receiver: &Receiver<Job>) {
    while let Ok(job) = receiver.try_recv() {
        job(owner);
    }
}

fn execute<T: Send + 'static>(
    owner: &RnmdbSessionOwner,
    cell: Arc<Cell<T>>,
    stop: Arc<AtomicBool>,
    action: impl FnOnce(&RnmdbSessionOwner) -> Result<T, VaultError>,
) {
    if stop.load(Ordering::Acquire) {
        cell.complete(Err(error(VaultErrorCode::Unavailable)));
        return;
    }
    if cell.abandoned.load(Ordering::Acquire) {
        cell.complete(Err(error(VaultErrorCode::Cancelled)));
        return;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(owner)));
    let result = match result {
        Ok(result) => result,
        Err(_) => {
            owner.quarantine_after_worker_panic();
            Err(error(VaultErrorCode::IntegrityFailure))
        }
    };
    cell.complete(result);
}

struct Cell<T> {
    state: Mutex<State<T>>,
    abandoned: AtomicBool,
}

impl<T> Cell<T> {
    fn new() -> Self {
        Self {
            state: Mutex::new(State {
                result: None,
                waker: None,
            }),
            abandoned: AtomicBool::new(false),
        }
    }

    fn complete(&self, result: Result<T, VaultError>) {
        let waker = {
            let mut state = lock(&self.state);
            state.result = Some(result);
            state.waker.take()
        };
        if let Some(waker) = waker {
            let _wake = catch_unwind(AssertUnwindSafe(|| waker.wake()));
        }
    }
}

struct State<T> {
    result: Option<Result<T, VaultError>>,
    waker: Option<Waker>,
}

struct ResultFuture<T> {
    cell: Arc<Cell<T>>,
    cancellation: CancellationToken,
}

impl<T> Future for ResultFuture<T> {
    type Output = Result<T, VaultError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match poll_result(&this.cell, context.waker()) {
            Ok(Some(result)) => return Poll::Ready(result),
            Ok(None) => {}
            Err(()) => return Poll::Ready(fail_result_future(this)),
        }
        let cancelled = match cancellation_observed(&this.cancellation, context.waker()) {
            Ok(cancelled) => cancelled,
            Err(()) => return Poll::Ready(fail_result_future(this)),
        };
        if cancelled {
            if let Some(result) = take_result(&this.cell) {
                return Poll::Ready(result);
            }
            clear_result_waker(&this.cell);
            this.cell.abandoned.store(true, Ordering::Release);
            return Poll::Ready(Err(error(VaultErrorCode::Cancelled)));
        }
        Poll::Pending
    }
}

impl<T> Drop for ResultFuture<T> {
    fn drop(&mut self) {
        // An unstarted job is abandoned. An in-flight durable mutation still
        // completes its commit protocol and must be reconciled by request ID.
        self.cell.abandoned.store(true, Ordering::Release);
        self.cancellation.cancel();
    }
}

fn lock<T>(state: &Mutex<State<T>>) -> MutexGuard<'_, State<T>> {
    // This lock protects only owned result slots and wakers, never database or
    // policy state. Recovering poison cannot grant access or change a commit.
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn take_result<T>(cell: &Cell<T>) -> Option<Result<T, VaultError>> {
    lock(&cell.state).result.take()
}

fn poll_result<T>(cell: &Cell<T>, waker: &Waker) -> Result<Option<Result<T, VaultError>>, ()> {
    let replacement = catch_unwind(AssertUnwindSafe(|| waker.clone())).map_err(|_| ())?;
    let mut state = lock(&cell.state);
    if let Some(result) = state.result.take() {
        return Ok(Some(result));
    }
    let replace = state
        .waker
        .as_ref()
        .is_none_or(|registered| !registered.will_wake(waker));
    if replace {
        state.waker = Some(replacement);
    }
    Ok(None)
}

fn cancellation_observed(cancellation: &CancellationToken, waker: &Waker) -> Result<bool, ()> {
    catch_unwind(AssertUnwindSafe(|| cancellation.register_waker(waker))).map_err(|_| ())
}

fn clear_result_waker<T>(cell: &Cell<T>) {
    lock(&cell.state).waker = None;
}

fn fail_result_future<T>(future: &ResultFuture<T>) -> Result<T, VaultError> {
    future.cell.abandoned.store(true, Ordering::Release);
    future.cancellation.cancel();
    Err(error(VaultErrorCode::IntegrityFailure))
}

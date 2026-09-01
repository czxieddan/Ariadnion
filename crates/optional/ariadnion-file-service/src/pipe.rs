// crates/optional/ariadnion-file-service/src/pipe.rs - Rust source for Ariadnion.
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

use std::cmp;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ariadnion_api_files::{ApiFilesError, ApiFilesErrorCode, FileChunk, MAX_FILE_CHUNK_BYTES};
use ariadnion_core::{ErrorCode, RequestContext};

const WAIT_QUANTUM: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Eq, PartialEq)]
enum TerminalState {
    Open,
    PublishingEof,
    Eof,
    Aborted,
}

enum BlockingFinishStep {
    Deliver(Waker),
    Recheck,
    Published,
    Aborted(io::Error),
}

enum ReceivePollStep {
    Ready(ReceiveReady),
    RegisterWaker,
}

struct ReceiveReady {
    result: Result<Option<PipeReceivedChunk>, ApiFilesError>,
    notification: Option<Waker>,
}

struct ReceiverWakerInstallation {
    step: ReceivePollStep,
    discarded: Option<Waker>,
    failed: bool,
}

struct PipeState {
    retained: Option<(u64, Box<[u8]>)>,
    in_flight: Option<u64>,
    terminal: TerminalState,
    async_waker: Option<Waker>,
    receiver_waker_updates: usize,
    io_fault_observed: bool,
}

impl PipeState {
    const fn new() -> Self {
        Self {
            retained: None,
            in_flight: None,
            terminal: TerminalState::Open,
            async_waker: None,
            receiver_waker_updates: 0,
            io_fault_observed: false,
        }
    }

    fn abort(&mut self, io_fault_observed: bool) -> Option<Waker> {
        if self.terminal == TerminalState::Eof {
            return None;
        }
        self.terminal = TerminalState::Aborted;
        self.retained = None;
        self.in_flight = None;
        self.io_fault_observed |= io_fault_observed;
        self.async_waker.take()
    }

    const fn aborted_error(&self) -> ApiFilesError {
        if self.io_fault_observed {
            ApiFilesError::new(ApiFilesErrorCode::Unavailable)
        } else {
            ApiFilesError::new(ApiFilesErrorCode::Internal)
        }
    }
}

struct PipeShared {
    state: Mutex<PipeState>,
    changed: Condvar,
}

impl PipeShared {
    fn new() -> Self {
        Self {
            state: Mutex::new(PipeState::new()),
            changed: Condvar::new(),
        }
    }
}

/// Asynchronous producer used while an upload worker reads blocking bytes.
pub(crate) struct PipeAsyncSender {
    shared: Arc<PipeShared>,
    next_sequence: u64,
}

/// Asynchronous consumer used while a download worker writes blocking bytes.
pub(crate) struct PipeAsyncReceiver {
    shared: Arc<PipeShared>,
}

/// Blocking upload reader that acknowledges a chunk after its final byte is read.
pub(crate) struct PipeReader {
    shared: Arc<PipeShared>,
    context: RequestContext,
    offset: usize,
}

/// Blocking download writer that returns only after the asynchronous sink acknowledges.
pub(crate) struct PipeWriter {
    shared: Arc<PipeShared>,
    context: RequestContext,
    next_sequence: u64,
}

/// Cloneable handle that terminates both sides of one transfer pipe.
#[derive(Clone)]
pub(crate) struct PipeAbortHandle {
    shared: Arc<PipeShared>,
}

/// One download chunk paired with the sequence that must be acknowledged.
pub(crate) struct PipeReceivedChunk {
    sequence: u64,
    chunk: FileChunk,
}

/// A redacted state view used by internal diagnostics and bounded-memory contracts.
pub(crate) struct PipeSnapshot {
    retained_length: Option<usize>,
    retained_capacity: Option<usize>,
}

/// Creates the asynchronous-producer and blocking-reader upload bridge.
pub(crate) fn upload_pipe(
    context: RequestContext,
) -> (PipeAsyncSender, PipeReader, PipeAbortHandle) {
    let shared = Arc::new(PipeShared::new());
    (
        PipeAsyncSender {
            shared: shared.clone(),
            next_sequence: 0,
        },
        PipeReader {
            shared: shared.clone(),
            context,
            offset: 0,
        },
        PipeAbortHandle { shared },
    )
}

/// Creates the blocking-writer and asynchronous-consumer download bridge.
pub(crate) fn download_pipe(
    context: RequestContext,
) -> (PipeWriter, PipeAsyncReceiver, PipeAbortHandle) {
    let shared = Arc::new(PipeShared::new());
    (
        PipeWriter {
            shared: shared.clone(),
            context,
            next_sequence: 0,
        },
        PipeAsyncReceiver {
            shared: shared.clone(),
        },
        PipeAbortHandle { shared },
    )
}

impl PipeAsyncSender {
    /// Offers one normalized chunk and completes only after blocking acknowledgement.
    pub(crate) async fn offer(
        &mut self,
        chunk: FileChunk,
        context: &RequestContext,
    ) -> Result<(), ApiFilesError> {
        let sequence = next_sequence(&mut self.next_sequence, &self.shared)?;
        let mut retained = Some(chunk.into_bytes().into_boxed_slice());
        poll_fn(|task| self.poll_offer(sequence, &mut retained, context, task)).await
    }

    /// Publishes terminal EOF after the last offered chunk is acknowledged.
    pub(crate) async fn finish(&mut self, context: &RequestContext) -> Result<(), ApiFilesError> {
        poll_fn(|task| self.poll_finish(context, task)).await
    }

    fn poll_offer(
        &self,
        sequence: u64,
        retained: &mut Option<Box<[u8]>>,
        context: &RequestContext,
        task: &Context<'_>,
    ) -> Poll<Result<(), ApiFilesError>> {
        if let Err(error) = context.check_active() {
            abort_shared(&self.shared, true);
            return Poll::Ready(Err(error.into()));
        }
        let waker = match clone_waker(task.waker(), &self.shared) {
            Ok(waker) => waker,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let (mut state, poisoned) = lock_state(&self.shared);
        if poisoned {
            return Poll::Ready(Err(internal_error()));
        }
        poll_offered_state(&mut state, sequence, retained, waker, &self.shared)
    }

    fn poll_finish(
        &self,
        context: &RequestContext,
        task: &Context<'_>,
    ) -> Poll<Result<(), ApiFilesError>> {
        if let Err(error) = context.check_active() {
            abort_shared(&self.shared, true);
            return Poll::Ready(Err(error.into()));
        }
        let waker = match clone_waker(task.waker(), &self.shared) {
            Ok(waker) => waker,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let (mut state, poisoned) = lock_state(&self.shared);
        if poisoned {
            return Poll::Ready(Err(internal_error()));
        }
        poll_finish_state(&mut state, waker, &self.shared)
    }
}

impl Drop for PipeAsyncSender {
    fn drop(&mut self) {
        abort_if_unpublished(&self.shared);
    }
}

impl PipeAsyncReceiver {
    /// Receives one chunk or terminal EOF without admitting a following chunk.
    pub(crate) async fn receive(
        &mut self,
        context: &RequestContext,
    ) -> Result<Option<PipeReceivedChunk>, ApiFilesError> {
        poll_fn(|task| self.poll_receive(context, task)).await
    }

    /// Acknowledges that the asynchronous sink accepted the exact sequence.
    pub(crate) fn acknowledge(&mut self, sequence: u64) -> Result<(), ApiFilesError> {
        let (mut state, poisoned) = lock_state(&self.shared);
        if poisoned {
            return Err(internal_error());
        }
        if state.in_flight != Some(sequence) || state.retained.is_some() {
            drop(state);
            abort_shared(&self.shared, false);
            return Err(internal_error());
        }
        state.in_flight = None;
        let waker = state.async_waker.take();
        drop(state);
        self.shared.changed.notify_all();
        wake_or_abort(&self.shared, waker)
    }

    fn poll_receive(
        &self,
        context: &RequestContext,
        task: &Context<'_>,
    ) -> Poll<Result<Option<PipeReceivedChunk>, ApiFilesError>> {
        if let Err(error) = context.check_active() {
            abort_shared(&self.shared, true);
            return Poll::Ready(Err(error.into()));
        }
        match begin_receive_poll(&self.shared) {
            ReceivePollStep::Ready(ready) => finish_receive_ready(&self.shared, ready),
            ReceivePollStep::RegisterWaker => register_receiver_waker(&self.shared, task.waker()),
        }
    }
}

impl Drop for PipeAsyncReceiver {
    fn drop(&mut self) {
        abort_if_unpublished(&self.shared);
    }
}

impl PipeReceivedChunk {
    /// Returns the sequence that must be acknowledged after sink acceptance.
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Consumes the receipt and returns its chunk.
    pub(crate) fn into_chunk(self) -> FileChunk {
        self.chunk
    }
}

impl PipeAbortHandle {
    /// Aborts the pipe without classifying the termination as an I/O sideband fault.
    pub(crate) fn abort(&self) {
        abort_shared(&self.shared, false);
    }

    /// Aborts the pipe and records that a source, sink, or context fault was observed.
    pub(crate) fn abort_io_fault(&self) {
        abort_shared(&self.shared, true);
    }

    /// Reports whether a source, sink, or context fault caused termination.
    pub(crate) fn io_fault_observed(&self) -> bool {
        let (state, poisoned) = lock_state(&self.shared);
        poisoned || state.io_fault_observed
    }

    /// Returns retained-memory measurements without exposing byte contents.
    pub(crate) fn snapshot(&self) -> PipeSnapshot {
        let (state, _) = lock_state(&self.shared);
        let retained_length = state.retained.as_ref().map(|(_, bytes)| bytes.len());
        PipeSnapshot {
            retained_length,
            retained_capacity: retained_length,
        }
    }
}

impl PipeSnapshot {
    /// Returns the retained chunk length when a chunk is offered.
    pub(crate) const fn retained_length(&self) -> Option<usize> {
        self.retained_length
    }

    /// Returns the exact retained allocation capacity when a chunk is offered.
    pub(crate) const fn retained_capacity(&self) -> Option<usize> {
        self.retained_capacity
    }
}

impl Read for PipeReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        self.read_non_empty(output)
    }
}

impl PipeReader {
    fn read_non_empty(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            check_blocking_context(&self.shared, &self.context)?;
            let (mut state, poisoned) = lock_state(&self.shared);
            if poisoned {
                return Err(internal_io_error());
            }
            let step = read_step(&mut state, &mut self.offset, output);
            if let Some(count) = resolve_read_step(&self.shared, &self.context, state, step)? {
                return Ok(count);
            }
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        abort_if_unpublished(&self.shared);
    }
}

impl Write for PipeWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let accepted = cmp::min(input.len(), MAX_FILE_CHUNK_BYTES);
        self.write_chunk(&input[..accepted])?;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        wait_until_empty(&self.shared, &self.context)
    }
}

impl PipeWriter {
    /// Publishes terminal EOF only after every accepted write is acknowledged.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        wait_until_empty(&self.shared, &self.context)?;
        let (mut state, poisoned) = lock_state(&self.shared);
        if poisoned {
            return Err(internal_io_error());
        }
        let step = begin_blocking_finish(&mut state);
        drop(state);
        drive_blocking_finish(&self.shared, &self.context, step)
    }

    fn write_chunk(&mut self, input: &[u8]) -> io::Result<()> {
        wait_until_empty(&self.shared, &self.context)?;
        let sequence = next_blocking_sequence(&mut self.next_sequence, &self.shared)?;
        let waker = retain_blocking_chunk(&self.shared, sequence, input)?;
        self.shared.changed.notify_all();
        wake_or_abort(&self.shared, waker).map_err(api_to_io)?;
        wait_for_acknowledgement(&self.shared, &self.context, sequence)
    }
}

fn begin_blocking_finish(state: &mut PipeState) -> BlockingFinishStep {
    match state.terminal {
        TerminalState::Open => {
            state.terminal = TerminalState::PublishingEof;
            next_blocking_finish_step(state)
        }
        TerminalState::Eof => BlockingFinishStep::Published,
        TerminalState::PublishingEof => BlockingFinishStep::Aborted(internal_io_error()),
        TerminalState::Aborted => BlockingFinishStep::Aborted(aborted_io_error(state)),
    }
}

fn next_blocking_finish_step(state: &mut PipeState) -> BlockingFinishStep {
    match state.terminal {
        TerminalState::PublishingEof => publishing_finish_step(state),
        TerminalState::Eof => BlockingFinishStep::Published,
        TerminalState::Aborted => BlockingFinishStep::Aborted(aborted_io_error(state)),
        TerminalState::Open => BlockingFinishStep::Aborted(internal_io_error()),
    }
}

fn publishing_finish_step(state: &mut PipeState) -> BlockingFinishStep {
    if state.receiver_waker_updates != 0 {
        return BlockingFinishStep::Recheck;
    }
    match state.async_waker.take() {
        Some(waker) => BlockingFinishStep::Deliver(waker),
        None => {
            state.terminal = TerminalState::Eof;
            BlockingFinishStep::Published
        }
    }
}

fn drive_blocking_finish(
    shared: &Arc<PipeShared>,
    context: &RequestContext,
    mut step: BlockingFinishStep,
) -> io::Result<()> {
    loop {
        step = match step {
            BlockingFinishStep::Deliver(waker) => deliver_blocking_finish_waker(shared, waker),
            BlockingFinishStep::Recheck => recheck_blocking_finish(shared, context),
            BlockingFinishStep::Published => {
                shared.changed.notify_all();
                return Ok(());
            }
            BlockingFinishStep::Aborted(error) => return Err(error),
        };
    }
}

fn deliver_blocking_finish_waker(shared: &Arc<PipeShared>, waker: Waker) -> BlockingFinishStep {
    if wake_caught(Some(waker)) {
        BlockingFinishStep::Recheck
    } else {
        abort_shared(shared, false);
        BlockingFinishStep::Aborted(internal_io_error())
    }
}

fn recheck_blocking_finish(
    shared: &Arc<PipeShared>,
    context: &RequestContext,
) -> BlockingFinishStep {
    if let Err(error) = check_blocking_context(shared, context) {
        return BlockingFinishStep::Aborted(error);
    }
    let (mut state, poisoned) = lock_state(shared);
    let step = if poisoned {
        BlockingFinishStep::Aborted(internal_io_error())
    } else {
        next_blocking_finish_step(&mut state)
    };
    match step {
        BlockingFinishStep::Recheck => match wait_for_change(shared, state, context) {
            Ok(()) => BlockingFinishStep::Recheck,
            Err(error) => BlockingFinishStep::Aborted(error),
        },
        step => step,
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        abort_if_unpublished(&self.shared);
    }
}

enum ReadStep {
    Data(usize, Option<Waker>),
    Wait,
    Eof,
    Aborted(io::Error),
}

fn resolve_read_step(
    shared: &Arc<PipeShared>,
    context: &RequestContext,
    state: MutexGuard<'_, PipeState>,
    step: ReadStep,
) -> io::Result<Option<usize>> {
    match step {
        ReadStep::Data(count, waker) => {
            drop(state);
            shared.changed.notify_all();
            let _ = wake_or_abort(shared, waker);
            Ok(Some(count))
        }
        ReadStep::Eof => Ok(Some(0)),
        ReadStep::Aborted(error) => Err(error),
        ReadStep::Wait => wait_for_change(shared, state, context).map(|()| None),
    }
}

fn read_step(state: &mut PipeState, offset: &mut usize, output: &mut [u8]) -> ReadStep {
    let Some((sequence, bytes)) = state.retained.as_ref() else {
        return empty_read_step(state);
    };
    if state.in_flight.is_none() {
        state.in_flight = Some(*sequence);
    }
    if state.in_flight != Some(*sequence) || *offset >= bytes.len() {
        state.abort(false);
        return ReadStep::Aborted(internal_io_error());
    }
    let count = cmp::min(output.len(), bytes.len() - *offset);
    output[..count].copy_from_slice(&bytes[*offset..*offset + count]);
    *offset += count;
    let waker = finish_blocking_read(state, offset);
    ReadStep::Data(count, waker)
}

fn empty_read_step(state: &PipeState) -> ReadStep {
    match state.terminal {
        TerminalState::Open => ReadStep::Wait,
        TerminalState::Eof => ReadStep::Eof,
        TerminalState::PublishingEof => ReadStep::Aborted(internal_io_error()),
        TerminalState::Aborted => ReadStep::Aborted(aborted_io_error(state)),
    }
}

fn finish_blocking_read(state: &mut PipeState, offset: &mut usize) -> Option<Waker> {
    let completed = state
        .retained
        .as_ref()
        .is_some_and(|(_, bytes)| *offset == bytes.len());
    if !completed {
        return None;
    }
    state.retained = None;
    state.in_flight = None;
    *offset = 0;
    state.async_waker.take()
}

fn poll_offered_state(
    state: &mut PipeState,
    sequence: u64,
    retained: &mut Option<Box<[u8]>>,
    waker: Waker,
    shared: &PipeShared,
) -> Poll<Result<(), ApiFilesError>> {
    if state.terminal == TerminalState::Aborted {
        return Poll::Ready(Err(state.aborted_error()));
    }
    if matches!(
        state.terminal,
        TerminalState::PublishingEof | TerminalState::Eof
    ) {
        return Poll::Ready(Err(internal_error()));
    }
    if retained.is_some() {
        return begin_offer(state, sequence, retained, waker, shared);
    }
    finish_offer_poll(state, sequence, waker, shared)
}

fn begin_offer(
    state: &mut PipeState,
    sequence: u64,
    retained: &mut Option<Box<[u8]>>,
    waker: Waker,
    shared: &PipeShared,
) -> Poll<Result<(), ApiFilesError>> {
    if state.retained.is_some() || state.in_flight.is_some() {
        state.async_waker = Some(waker);
        return Poll::Pending;
    }
    state.retained = retained.take().map(|bytes| (sequence, bytes));
    state.async_waker = Some(waker);
    shared.changed.notify_all();
    Poll::Pending
}

fn finish_offer_poll(
    state: &mut PipeState,
    sequence: u64,
    waker: Waker,
    shared: &PipeShared,
) -> Poll<Result<(), ApiFilesError>> {
    if state.retained.is_none() && state.in_flight.is_none() {
        return Poll::Ready(Ok(()));
    }
    if retained_sequence(state) == Some(sequence) || state.in_flight == Some(sequence) {
        state.async_waker = Some(waker);
        return Poll::Pending;
    }
    state.abort(false);
    shared.changed.notify_all();
    Poll::Ready(Err(internal_error()))
}

fn poll_finish_state(
    state: &mut PipeState,
    waker: Waker,
    shared: &PipeShared,
) -> Poll<Result<(), ApiFilesError>> {
    if let Some(result) = finished_terminal_poll(state) {
        return result;
    }
    if state.retained.is_some() || state.in_flight.is_some() {
        state.async_waker = Some(waker);
        return Poll::Pending;
    }
    state.terminal = TerminalState::Eof;
    shared.changed.notify_all();
    Poll::Ready(Ok(()))
}

fn finished_terminal_poll(state: &PipeState) -> Option<Poll<Result<(), ApiFilesError>>> {
    match state.terminal {
        TerminalState::Open => None,
        TerminalState::Eof => Some(Poll::Ready(Ok(()))),
        TerminalState::PublishingEof => Some(Poll::Ready(Err(internal_error()))),
        TerminalState::Aborted => Some(Poll::Ready(Err(state.aborted_error()))),
    }
}

fn begin_receive_poll(shared: &Arc<PipeShared>) -> ReceivePollStep {
    let (mut state, poisoned) = lock_state(shared);
    if poisoned {
        return receive_error(internal_error(), None);
    }
    receive_poll_step(&mut state)
}

fn receive_poll_step(state: &mut PipeState) -> ReceivePollStep {
    if state.in_flight.is_some() {
        return begin_receiver_waker_update(state);
    }
    if let Some((sequence, retained)) = state.retained.take() {
        return ReceivePollStep::Ready(receive_retained(state, sequence, retained));
    }
    terminal_receive_poll_step(state)
}

fn terminal_receive_poll_step(state: &mut PipeState) -> ReceivePollStep {
    match state.terminal {
        TerminalState::Open | TerminalState::PublishingEof => begin_receiver_waker_update(state),
        TerminalState::Eof => ReceivePollStep::Ready(ReceiveReady {
            result: Ok(None),
            notification: None,
        }),
        TerminalState::Aborted => receive_error(state.aborted_error(), None),
    }
}

fn begin_receiver_waker_update(state: &mut PipeState) -> ReceivePollStep {
    match state.receiver_waker_updates.checked_add(1) {
        Some(next) => {
            state.receiver_waker_updates = next;
            ReceivePollStep::RegisterWaker
        }
        None => {
            let notification = state.abort(false);
            receive_error(internal_error(), notification)
        }
    }
}

fn receive_retained(state: &mut PipeState, sequence: u64, retained: Box<[u8]>) -> ReceiveReady {
    let chunk = match FileChunk::new(retained.into_vec()) {
        Ok(chunk) => chunk,
        Err(_) => {
            let notification = state.abort(false);
            return ready_receive_error(internal_error(), notification);
        }
    };
    state.in_flight = Some(sequence);
    ReceiveReady {
        result: Ok(Some(PipeReceivedChunk { sequence, chunk })),
        notification: None,
    }
}

fn receive_error(error: ApiFilesError, notification: Option<Waker>) -> ReceivePollStep {
    ReceivePollStep::Ready(ReceiveReady {
        result: Err(error),
        notification,
    })
}

fn ready_receive_error(error: ApiFilesError, notification: Option<Waker>) -> ReceiveReady {
    ReceiveReady {
        result: Err(error),
        notification,
    }
}

fn finish_receive_ready(
    shared: &Arc<PipeShared>,
    ready: ReceiveReady,
) -> Poll<Result<Option<PipeReceivedChunk>, ApiFilesError>> {
    shared.changed.notify_all();
    let _ = wake_caught(ready.notification);
    Poll::Ready(ready.result)
}

fn register_receiver_waker(
    shared: &Arc<PipeShared>,
    waker: &Waker,
) -> Poll<Result<Option<PipeReceivedChunk>, ApiFilesError>> {
    let cloned = match clone_waker_caught(waker) {
        Ok(cloned) => cloned,
        Err(()) => return fail_receiver_waker_update(shared),
    };
    let installation = install_receiver_waker(shared, cloned);
    resolve_receiver_waker_installation(shared, installation)
}

fn install_receiver_waker(shared: &Arc<PipeShared>, waker: Waker) -> ReceiverWakerInstallation {
    let (mut state, poisoned) = lock_state(shared);
    if poisoned {
        return ReceiverWakerInstallation {
            step: receive_error(internal_error(), None),
            discarded: Some(waker),
            failed: true,
        };
    }
    install_receiver_waker_state(&mut state, waker)
}

fn install_receiver_waker_state(state: &mut PipeState, waker: Waker) -> ReceiverWakerInstallation {
    if state.in_flight.is_some() {
        return install_pending_receiver_waker(state, waker);
    }
    if let Some((sequence, retained)) = state.retained.take() {
        let ready = receive_retained(state, sequence, retained);
        return install_ready_receiver_waker(ready, waker);
    }
    install_terminal_receiver_waker(state, waker)
}

fn install_terminal_receiver_waker(
    state: &mut PipeState,
    waker: Waker,
) -> ReceiverWakerInstallation {
    match state.terminal {
        TerminalState::Open | TerminalState::PublishingEof => {
            install_pending_receiver_waker(state, waker)
        }
        TerminalState::Eof => install_ready_receiver_waker(
            ReceiveReady {
                result: Ok(None),
                notification: None,
            },
            waker,
        ),
        TerminalState::Aborted => {
            install_ready_receiver_waker(ready_receive_error(state.aborted_error(), None), waker)
        }
    }
}

fn install_pending_receiver_waker(
    state: &mut PipeState,
    waker: Waker,
) -> ReceiverWakerInstallation {
    ReceiverWakerInstallation {
        step: ReceivePollStep::RegisterWaker,
        discarded: state.async_waker.replace(waker),
        failed: false,
    }
}

fn install_ready_receiver_waker(ready: ReceiveReady, waker: Waker) -> ReceiverWakerInstallation {
    ReceiverWakerInstallation {
        step: ReceivePollStep::Ready(ready),
        discarded: Some(waker),
        failed: false,
    }
}

fn resolve_receiver_waker_installation(
    shared: &Arc<PipeShared>,
    installation: ReceiverWakerInstallation,
) -> Poll<Result<Option<PipeReceivedChunk>, ApiFilesError>> {
    let ReceiverWakerInstallation {
        mut step,
        discarded,
        failed: installation_failed,
    } = installation;
    let discarded_cleanly = drop_waker_caught(discarded);
    let update_succeeded = !installation_failed && discarded_cleanly;
    let (completion_notification, completion_failed) =
        complete_receiver_waker_update(shared, update_succeeded);
    let step_notification = take_receive_notification(&mut step);
    let failed = installation_failed || !discarded_cleanly || completion_failed;
    let _ = wake_caught(step_notification);
    let _ = wake_caught(completion_notification);
    if failed {
        Poll::Ready(Err(internal_error()))
    } else {
        resolve_receive_poll_step(step)
    }
}

fn fail_receiver_waker_update(
    shared: &Arc<PipeShared>,
) -> Poll<Result<Option<PipeReceivedChunk>, ApiFilesError>> {
    let (notification, _) = complete_receiver_waker_update(shared, false);
    let _ = wake_caught(notification);
    Poll::Ready(Err(internal_error()))
}

fn complete_receiver_waker_update(
    shared: &Arc<PipeShared>,
    succeeded: bool,
) -> (Option<Waker>, bool) {
    let (mut state, poisoned) = lock_state(shared);
    let decremented = decrement_receiver_waker_updates(&mut state);
    let failed = !succeeded || poisoned || !decremented;
    let notification = if failed { state.abort(false) } else { None };
    drop(state);
    shared.changed.notify_all();
    (notification, failed)
}

fn decrement_receiver_waker_updates(state: &mut PipeState) -> bool {
    match state.receiver_waker_updates.checked_sub(1) {
        Some(remaining) => {
            state.receiver_waker_updates = remaining;
            true
        }
        None => false,
    }
}

fn take_receive_notification(step: &mut ReceivePollStep) -> Option<Waker> {
    match step {
        ReceivePollStep::Ready(ready) => ready.notification.take(),
        ReceivePollStep::RegisterWaker => None,
    }
}

fn resolve_receive_poll_step(
    step: ReceivePollStep,
) -> Poll<Result<Option<PipeReceivedChunk>, ApiFilesError>> {
    match step {
        ReceivePollStep::Ready(ready) => Poll::Ready(ready.result),
        ReceivePollStep::RegisterWaker => Poll::Pending,
    }
}

fn retained_sequence(state: &PipeState) -> Option<u64> {
    state.retained.as_ref().map(|(sequence, _)| *sequence)
}

fn retain_blocking_chunk(
    shared: &Arc<PipeShared>,
    sequence: u64,
    input: &[u8],
) -> io::Result<Option<Waker>> {
    let (mut state, poisoned) = lock_state(shared);
    if poisoned {
        return Err(internal_io_error());
    }
    if state.terminal != TerminalState::Open
        || state.retained.is_some()
        || state.in_flight.is_some()
    {
        return Err(aborted_or_internal_io_error(&state));
    }
    state.retained = Some((sequence, input.to_vec().into_boxed_slice()));
    Ok(state.async_waker.take())
}

fn wait_until_empty(shared: &Arc<PipeShared>, context: &RequestContext) -> io::Result<()> {
    loop {
        check_blocking_context(shared, context)?;
        let (state, poisoned) = lock_state(shared);
        if poisoned {
            return Err(internal_io_error());
        }
        let wait_state = empty_wait_state(&state);
        if resolve_empty_wait(shared, context, state, wait_state)? {
            return Ok(());
        }
    }
}

fn wait_for_acknowledgement(
    shared: &Arc<PipeShared>,
    context: &RequestContext,
    sequence: u64,
) -> io::Result<()> {
    loop {
        check_blocking_context(shared, context)?;
        let (state, poisoned) = lock_state(shared);
        if poisoned {
            return Err(internal_io_error());
        }
        let acknowledgement = acknowledgement_state(&state, sequence);
        if resolve_acknowledgement(shared, context, state, acknowledgement)? {
            return Ok(());
        }
    }
}

enum EmptyWaitState {
    Ready,
    Wait,
    Aborted(io::Error),
}

fn empty_wait_state(state: &PipeState) -> EmptyWaitState {
    match state.terminal {
        TerminalState::Aborted => EmptyWaitState::Aborted(aborted_io_error(state)),
        TerminalState::PublishingEof | TerminalState::Eof => {
            EmptyWaitState::Aborted(internal_io_error())
        }
        TerminalState::Open if state.retained.is_none() && state.in_flight.is_none() => {
            EmptyWaitState::Ready
        }
        TerminalState::Open => EmptyWaitState::Wait,
    }
}

fn resolve_empty_wait(
    shared: &Arc<PipeShared>,
    context: &RequestContext,
    state: MutexGuard<'_, PipeState>,
    wait_state: EmptyWaitState,
) -> io::Result<bool> {
    match wait_state {
        EmptyWaitState::Ready => Ok(true),
        EmptyWaitState::Wait => wait_for_change(shared, state, context).map(|()| false),
        EmptyWaitState::Aborted(error) => Err(error),
    }
}

enum AcknowledgementState {
    Acknowledged,
    Wait,
    Invalid,
    Aborted(io::Error),
}

fn acknowledgement_state(state: &PipeState, sequence: u64) -> AcknowledgementState {
    match (state.terminal, retained_sequence(state), state.in_flight) {
        (TerminalState::Aborted, _, _) => AcknowledgementState::Aborted(aborted_io_error(state)),
        (_, None, None) => AcknowledgementState::Acknowledged,
        (_, Some(retained), _) if retained == sequence => AcknowledgementState::Wait,
        (_, _, Some(in_flight)) if in_flight == sequence => AcknowledgementState::Wait,
        _ => AcknowledgementState::Invalid,
    }
}

fn resolve_acknowledgement(
    shared: &Arc<PipeShared>,
    context: &RequestContext,
    state: MutexGuard<'_, PipeState>,
    acknowledgement: AcknowledgementState,
) -> io::Result<bool> {
    match acknowledgement {
        AcknowledgementState::Acknowledged => Ok(true),
        AcknowledgementState::Wait => wait_for_change(shared, state, context).map(|()| false),
        AcknowledgementState::Aborted(error) => Err(error),
        AcknowledgementState::Invalid => {
            drop(state);
            abort_shared(shared, false);
            Err(internal_io_error())
        }
    }
}

fn wait_for_change(
    shared: &Arc<PipeShared>,
    state: MutexGuard<'_, PipeState>,
    context: &RequestContext,
) -> io::Result<()> {
    let duration = match bounded_wait_duration(context) {
        Ok(duration) => duration,
        Err(error) => {
            drop(state);
            abort_shared(shared, true);
            return Err(error);
        }
    };
    match shared.changed.wait_timeout(state, duration) {
        Ok((_state, _timeout)) => Ok(()),
        Err(poisoned) => {
            let (mut state, _timeout) = poisoned.into_inner();
            let waker = state.abort(false);
            drop(state);
            shared.changed.notify_all();
            let _ = wake_caught(waker);
            Err(internal_io_error())
        }
    }
}

fn bounded_wait_duration(context: &RequestContext) -> io::Result<Duration> {
    match context.remaining().map_err(core_to_io)? {
        Some(remaining) => Ok(cmp::min(remaining, WAIT_QUANTUM)),
        None => Ok(WAIT_QUANTUM),
    }
}

fn check_blocking_context(shared: &Arc<PipeShared>, context: &RequestContext) -> io::Result<()> {
    context.check_active().map_err(|error| {
        abort_shared(shared, true);
        core_to_io(error)
    })
}

fn next_sequence(next: &mut u64, shared: &Arc<PipeShared>) -> Result<u64, ApiFilesError> {
    let sequence = *next;
    let Some(following) = sequence.checked_add(1) else {
        abort_shared(shared, false);
        return Err(internal_error());
    };
    *next = following;
    Ok(sequence)
}

fn next_blocking_sequence(next: &mut u64, shared: &Arc<PipeShared>) -> io::Result<u64> {
    next_sequence(next, shared).map_err(api_to_io)
}

fn clone_waker(waker: &Waker, shared: &Arc<PipeShared>) -> Result<Waker, ApiFilesError> {
    match clone_waker_caught(waker) {
        Ok(cloned) => Ok(cloned),
        Err(()) => {
            abort_shared(shared, false);
            Err(internal_error())
        }
    }
}

fn clone_waker_caught(waker: &Waker) -> Result<Waker, ()> {
    catch_unwind(AssertUnwindSafe(|| waker.clone())).map_err(|_| ())
}

fn drop_waker_caught(waker: Option<Waker>) -> bool {
    catch_unwind(AssertUnwindSafe(|| drop(waker))).is_ok()
}

fn wake_or_abort(shared: &Arc<PipeShared>, waker: Option<Waker>) -> Result<(), ApiFilesError> {
    if wake_caught(waker) {
        return Ok(());
    }
    abort_shared(shared, false);
    Err(internal_error())
}

fn wake_caught(waker: Option<Waker>) -> bool {
    let Some(waker) = waker else {
        return true;
    };
    catch_unwind(AssertUnwindSafe(|| waker.wake())).is_ok()
}

fn abort_shared(shared: &Arc<PipeShared>, io_fault_observed: bool) {
    let (mut state, _) = lock_state(shared);
    let waker = state.abort(io_fault_observed);
    drop(state);
    shared.changed.notify_all();
    let _ = wake_caught(waker);
}

fn abort_if_unpublished(shared: &Arc<PipeShared>) {
    let (mut state, _) = lock_state(shared);
    let unpublished = matches!(
        state.terminal,
        TerminalState::Open | TerminalState::PublishingEof
    );
    let waker = if unpublished {
        state.abort(false)
    } else {
        None
    };
    drop(state);
    if unpublished {
        shared.changed.notify_all();
        let _ = wake_caught(waker);
    }
}

fn lock_state(shared: &PipeShared) -> (MutexGuard<'_, PipeState>, bool) {
    match shared.state.lock() {
        Ok(state) => (state, false),
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            let waker = state.abort(false);
            drop(state);
            shared.state.clear_poison();
            shared.changed.notify_all();
            let _ = wake_caught(waker);
            relock_poisoned_state(shared)
        }
    }
}

fn relock_poisoned_state(shared: &PipeShared) -> (MutexGuard<'_, PipeState>, bool) {
    match shared.state.lock() {
        Ok(state) => (state, true),
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            if state.terminal != TerminalState::Eof {
                state.terminal = TerminalState::Aborted;
                state.retained = None;
                state.in_flight = None;
            }
            (state, true)
        }
    }
}

const fn internal_error() -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::Internal)
}

fn aborted_or_internal_io_error(state: &PipeState) -> io::Error {
    if state.terminal == TerminalState::Aborted {
        aborted_io_error(state)
    } else {
        internal_io_error()
    }
}

fn aborted_io_error(state: &PipeState) -> io::Error {
    if state.io_fault_observed {
        io::Error::from(io::ErrorKind::BrokenPipe)
    } else {
        internal_io_error()
    }
}

fn internal_io_error() -> io::Error {
    io::Error::from(io::ErrorKind::Other)
}

fn api_to_io(error: ApiFilesError) -> io::Error {
    match error.code() {
        ApiFilesErrorCode::Cancelled => io::Error::from(io::ErrorKind::Interrupted),
        ApiFilesErrorCode::DeadlineExceeded => io::Error::from(io::ErrorKind::TimedOut),
        ApiFilesErrorCode::Unavailable => io::Error::from(io::ErrorKind::BrokenPipe),
        _ => internal_io_error(),
    }
}

fn core_to_io(error: ariadnion_core::CoreError) -> io::Error {
    match error.code() {
        ErrorCode::Cancelled => io::Error::from(io::ErrorKind::Interrupted),
        ErrorCode::DeadlineExceeded => io::Error::from(io::ErrorKind::TimedOut),
        _ => internal_io_error(),
    }
}

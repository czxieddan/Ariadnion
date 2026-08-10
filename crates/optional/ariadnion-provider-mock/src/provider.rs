// crates/optional/ariadnion-provider-mock/src/provider.rs - Rust source for Ariadnion.
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
//! Fixed bounded chat generation without external side effects.

use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ariadnion_api_domain::{
    ChatServiceRequest, ChatServiceResponse, FinishReason, ResponseMode, ServiceContractVersion,
    ServiceRequest, ServiceResponse, TextOutput, TokenUsage,
};
use ariadnion_core::{CancellationToken, ErrorCode, EventEnvelope, ModuleVersion, RequestContext};
use ariadnion_provider_sdk::{
    BoxProviderCall, ProviderAttempt, ProviderAttemptEvidence, ProviderCapabilities,
    ProviderCapability, ProviderContractError, ProviderDescriptor, ProviderFailure,
    ProviderFailureClass, ProviderId, ProviderLimits, ProviderPort, ProviderRawOutcome,
    ProviderStreamConfig, ProviderStreamEvent, ProviderStreamPublishError, ProviderStreamPublisher,
    bounded_provider_stream,
};

use crate::chunk::for_each_chat_delta;

/// Stable provider identifier for the deterministic in-process adapter.
pub const MOCK_PROVIDER_ID: &str = "mock";
/// Stable provider model identifier accepted by the deterministic adapter.
pub const MOCK_PROVIDER_MODEL_ID: &str = "mock-chat-v1";
/// Maximum UTF-8 bytes carried by one deterministic mock stream delta.
pub const MAX_MOCK_STREAM_DELTA_BYTES: usize = 1_024;

const MAX_MOCK_REQUEST_BYTES: usize = 1_048_576;
const MAX_MOCK_STREAM_BYTES: usize = 1_048_576;
const MAX_MOCK_STREAM_EVENTS: usize = 1_024;
const MOCK_STREAM_CHANNEL_CAPACITY: usize = 8;
const MOCK_STREAM_WORKERS: usize = 2;
const MOCK_STREAM_QUEUE_CAPACITY: usize = 16;
const BACKPRESSURE_RETRY_DELAY: Duration = Duration::from_millis(1);
const MOCK_PREFIX: &str = "mock: ";
const STREAM_EVENT_VERSION: ModuleVersion = ModuleVersion::new(1, 0, 0);

/// A deterministic in-process provider used for compatibility and deployment checks.
///
/// The adapter accepts one fixed chat model. It performs no provider network,
/// filesystem, database, random, or credential access. Core-owned deadline and
/// event-envelope primitives remain authoritative, and diagnostics retain neither
/// message content nor model selectors.
pub struct DeterministicMockProvider {
    descriptor: ProviderDescriptor,
    stream_executor: StreamExecutor,
}

impl Debug for DeterministicMockProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicMockProvider")
            .field("descriptor", &self.descriptor)
            .field("stream_executor", &self.stream_executor)
            .finish()
    }
}

impl DeterministicMockProvider {
    /// Creates the fixed descriptor and bounded stream limits.
    ///
    /// # Errors
    ///
    /// Returns a redacted provider contract error if the built-in descriptor
    /// constants cease to satisfy provider SDK invariants.
    pub fn new() -> Result<Self, ProviderContractError> {
        let id = ProviderId::new(MOCK_PROVIDER_ID)?;
        let capabilities = ProviderCapabilities::new(ProviderCapability::TextGeneration)
            .with(ProviderCapability::TextStreaming);
        let limits = ProviderLimits::new(
            MAX_MOCK_REQUEST_BYTES,
            MAX_MOCK_STREAM_DELTA_BYTES,
            MAX_MOCK_STREAM_BYTES,
            MAX_MOCK_STREAM_EVENTS,
        )?;
        let descriptor = ProviderDescriptor::with_limits(id, capabilities, limits)?;
        Ok(Self {
            descriptor,
            stream_executor: StreamExecutor::new(),
        })
    }
}

impl ProviderPort for DeterministicMockProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }

    fn start_raw<'a>(&'a self, attempt: ProviderAttempt) -> BoxProviderCall<'a> {
        let limits = self.descriptor.limits();
        Box::pin(async move { execute(attempt, limits, &self.stream_executor) })
    }
}

struct StreamExecutionContext {
    request: RequestContext,
    shutdown: CancellationToken,
}

impl StreamExecutionContext {
    const fn new(request: RequestContext, shutdown: CancellationToken) -> Self {
        Self { request, shutdown }
    }

    fn cancellation(&self) -> CancellationToken {
        self.request.cancellation()
    }

    fn check_active(&self) -> Result<(), ProviderFailure> {
        self.check_shutdown()?;
        check_context(&self.request)
    }

    fn check_shutdown(&self) -> Result<(), ProviderFailure> {
        if !self.shutdown.is_cancelled() {
            return Ok(());
        }
        self.cancel();
        Err(failure(ProviderFailureClass::Cancelled))
    }

    fn cancel(&self) {
        self.request.cancellation().cancel();
    }
}

struct StreamJob {
    publisher: ProviderStreamPublisher,
    context: StreamExecutionContext,
    sequence: u64,
    plan: ChatPlan,
}

impl StreamJob {
    fn run(self) {
        run_stream(self.publisher, self.context, self.sequence, self.plan);
    }

    fn cancel(self) {
        self.context.cancel();
    }
}

// Receiver ownership is released before worker handles are taken during drop;
// the two mutexes are never nested, and workers never acquire the handle lock.
struct StreamExecutor {
    sender: Option<SyncSender<StreamJob>>,
    receiver: Arc<Mutex<Receiver<StreamJob>>>,
    shutdown: CancellationToken,
    workers: Mutex<Vec<JoinHandle<()>>>,
    started: OnceLock<Result<(), StreamExecutorStartError>>,
}

impl StreamExecutor {
    fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(MOCK_STREAM_QUEUE_CAPACITY);
        Self {
            sender: Some(sender),
            receiver: Arc::new(Mutex::new(receiver)),
            shutdown: CancellationToken::new(),
            workers: Mutex::new(Vec::with_capacity(MOCK_STREAM_WORKERS)),
            started: OnceLock::new(),
        }
    }

    fn submit(&self, job: StreamJob) -> Result<(), ProviderFailure> {
        self.ensure_started()?;
        let Some(sender) = self.sender.as_ref() else {
            return Err(failure(ProviderFailureClass::Internal));
        };
        match sender.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(response_limit()),
            Err(TrySendError::Disconnected(_)) => Err(failure(ProviderFailureClass::Internal)),
        }
    }

    fn ensure_started(&self) -> Result<(), ProviderFailure> {
        let status = self
            .started
            .get_or_init(|| start_stream_workers(&self.receiver, &self.shutdown, &self.workers));
        status
            .as_ref()
            .copied()
            .map_err(|_| failure(ProviderFailureClass::Internal))
    }

    fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

impl Debug for StreamExecutor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamExecutor(<bounded>)")
    }
}

impl Drop for StreamExecutor {
    fn drop(&mut self) {
        self.shutdown.cancel();
        let sender = self.sender.take();
        drop(sender);
        discard_queued_stream_jobs(&self.receiver);
        join_stream_workers(take_stream_workers(&self.workers));
    }
}

#[derive(Clone, Copy)]
struct StreamExecutorStartError;

struct ChatPlan {
    version: ServiceContractVersion,
    content: Box<str>,
    generated_scalars: usize,
    finish_reason: FinishReason,
    usage: TokenUsage,
}

fn execute(
    attempt: ProviderAttempt,
    limits: ProviderLimits,
    stream_executor: &StreamExecutor,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    check_active(&attempt)?;
    let (mode, plan) = {
        let request = checked_chat_request(&attempt)?;
        (request.response_mode(), plan_chat(request)?)
    };
    check_active(&attempt)?;
    outcome_for_mode(attempt, limits, stream_executor, mode, plan)
}

fn checked_chat_request(attempt: &ProviderAttempt) -> Result<&ChatServiceRequest, ProviderFailure> {
    check_model(attempt.model().as_str())?;
    let ServiceRequest::Chat(request) = attempt.request() else {
        return Err(failure(ProviderFailureClass::InvalidRequest));
    };
    check_model(request.model().as_str())?;
    Ok(request)
}

fn check_model(model: &str) -> Result<(), ProviderFailure> {
    if model != MOCK_PROVIDER_MODEL_ID {
        return Err(failure(ProviderFailureClass::NotFound));
    }
    Ok(())
}

fn outcome_for_mode(
    attempt: ProviderAttempt,
    limits: ProviderLimits,
    stream_executor: &StreamExecutor,
    mode: ResponseMode,
    plan: ChatPlan,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    match mode {
        ResponseMode::Complete => complete_outcome(attempt.evidence(), plan),
        ResponseMode::Stream => stream_outcome(attempt, limits, stream_executor, plan),
        _ => Err(failure(ProviderFailureClass::InvalidRequest)),
    }
}

fn plan_chat(request: &ChatServiceRequest) -> Result<ChatPlan, ProviderFailure> {
    let last = request
        .messages()
        .as_slice()
        .last()
        .ok_or_else(|| failure(ProviderFailureClass::InvalidRequest))?;
    let limit = request.output_token_limit().get() as usize;
    let source_scalars = source_scalar_count(last.content().as_str())?;
    let generated_scalars = source_scalars.min(limit);
    let output_tokens = u64::try_from(generated_scalars).map_err(|_| response_limit())?;
    let input_tokens = input_usage(request)?;
    let usage = TokenUsage::new(input_tokens, output_tokens).map_err(|_| response_limit())?;
    Ok(ChatPlan {
        version: request.version(),
        content: last.content().as_str().into(),
        generated_scalars,
        finish_reason: finish_reason(source_scalars, limit),
        usage,
    })
}

fn source_scalar_count(content: &str) -> Result<usize, ProviderFailure> {
    MOCK_PREFIX
        .chars()
        .count()
        .checked_add(content.chars().count())
        .ok_or_else(response_limit)
}

const fn finish_reason(source_scalars: usize, limit: usize) -> FinishReason {
    if source_scalars > limit {
        FinishReason::OutputLimitReached
    } else {
        FinishReason::Completed
    }
}

fn input_usage(request: &ChatServiceRequest) -> Result<u64, ProviderFailure> {
    request
        .messages()
        .as_slice()
        .iter()
        .try_fold(0_u64, |total, message| {
            let count = scalar_count(message.content().as_str())?;
            total.checked_add(count).ok_or_else(response_limit)
        })
}

fn scalar_count(value: &str) -> Result<u64, ProviderFailure> {
    u64::try_from(value.chars().count()).map_err(|_| response_limit())
}

fn complete_outcome(
    evidence: ProviderAttemptEvidence,
    plan: ChatPlan,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    mark_response_started(&evidence)?;
    let output: String = MOCK_PREFIX
        .chars()
        .chain(plan.content.chars())
        .take(plan.generated_scalars)
        .collect();
    let output = TextOutput::new(&output).map_err(|_| response_limit())?;
    let response = ChatServiceResponse::new(plan.version, output, plan.finish_reason, plan.usage);
    Ok(ProviderRawOutcome::Complete(ServiceResponse::Chat(
        response,
    )))
}

fn stream_outcome(
    attempt: ProviderAttempt,
    limits: ProviderLimits,
    stream_executor: &StreamExecutor,
    plan: ChatPlan,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    let config = ProviderStreamConfig::new(MOCK_STREAM_CHANNEL_CAPACITY, limits)
        .map_err(|_| response_limit())?;
    let context =
        StreamExecutionContext::new(attempt.context().clone(), stream_executor.shutdown_token());
    let (publisher, subscriber) =
        bounded_provider_stream(config, attempt.evidence(), context.cancellation())
            .map_err(|_| failure(ProviderFailureClass::Internal))?;
    let mut sequence = 1_u64;
    publish_next(
        &publisher,
        &context,
        &mut sequence,
        ProviderStreamEvent::ChatStarted {
            version: plan.version,
        },
    )?;
    stream_executor.submit(StreamJob {
        publisher,
        context,
        sequence,
        plan,
    })?;
    Ok(ProviderRawOutcome::Stream(subscriber))
}

fn run_stream(
    publisher: ProviderStreamPublisher,
    context: StreamExecutionContext,
    mut sequence: u64,
    plan: ChatPlan,
) {
    if let Err(error) = publish_chat_stream(&publisher, &context, &mut sequence, &plan)
        && publish_terminal_failure(&publisher, &context, sequence, error).is_err()
    {
        context.cancel();
    }
}

fn publish_chat_stream(
    publisher: &ProviderStreamPublisher,
    context: &StreamExecutionContext,
    sequence: &mut u64,
    plan: &ChatPlan,
) -> Result<(), ProviderFailure> {
    for_each_chat_delta(
        MOCK_PREFIX,
        &plan.content,
        plan.generated_scalars,
        |delta| {
            publish_next(
                publisher,
                context,
                sequence,
                ProviderStreamEvent::ChatDelta(delta),
            )
        },
    )?;
    publish_next(
        publisher,
        context,
        sequence,
        ProviderStreamEvent::ChatCompleted {
            finish_reason: plan.finish_reason,
            usage: plan.usage,
        },
    )
}

fn publish_next(
    publisher: &ProviderStreamPublisher,
    context: &StreamExecutionContext,
    sequence: &mut u64,
    payload: ProviderStreamEvent,
) -> Result<(), ProviderFailure> {
    let event = EventEnvelope::new(*sequence, STREAM_EVENT_VERSION, payload);
    publish_with_backpressure(publisher, context, event)?;
    *sequence = sequence.checked_add(1).ok_or_else(response_limit)?;
    Ok(())
}

fn publish_with_backpressure(
    publisher: &ProviderStreamPublisher,
    context: &StreamExecutionContext,
    mut event: EventEnvelope<ProviderStreamEvent>,
) -> Result<(), ProviderFailure> {
    loop {
        context.check_active()?;
        match publisher.try_publish(event) {
            Ok(()) => return Ok(()),
            Err(ProviderStreamPublishError::Full(returned)) => {
                event = returned;
                thread::sleep(BACKPRESSURE_RETRY_DELAY);
            }
            Err(error) => return Err(publish_failure(error)),
        }
    }
}

fn publish_terminal_failure(
    publisher: &ProviderStreamPublisher,
    context: &StreamExecutionContext,
    sequence: u64,
    failure: ProviderFailure,
) -> Result<(), ProviderFailure> {
    let mut event = EventEnvelope::new(
        sequence,
        STREAM_EVENT_VERSION,
        ProviderStreamEvent::Failed(failure),
    );
    loop {
        context.check_shutdown()?;
        match publisher.try_publish(event) {
            Ok(()) => return Ok(()),
            Err(ProviderStreamPublishError::Full(returned)) => {
                event = returned;
                thread::sleep(BACKPRESSURE_RETRY_DELAY);
            }
            Err(error) => return Err(publish_failure(error)),
        }
    }
}

fn publish_failure(error: ProviderStreamPublishError) -> ProviderFailure {
    let class = match error {
        ProviderStreamPublishError::Cancelled(_) | ProviderStreamPublishError::Closed(_) => {
            ProviderFailureClass::Cancelled
        }
        ProviderStreamPublishError::Full(_) | ProviderStreamPublishError::ResourceLimit(_) => {
            ProviderFailureClass::ResponseLimit
        }
        ProviderStreamPublishError::OutOfOrder(_)
        | ProviderStreamPublishError::InvalidTransition(_) => ProviderFailureClass::Internal,
    };
    failure(class)
}

fn start_stream_workers(
    receiver: &Arc<Mutex<Receiver<StreamJob>>>,
    shutdown: &CancellationToken,
    workers: &Mutex<Vec<JoinHandle<()>>>,
) -> Result<(), StreamExecutorStartError> {
    let mut workers = lock_stream_workers(workers);
    for index in 0..MOCK_STREAM_WORKERS {
        let receiver = receiver.clone();
        let shutdown = shutdown.clone();
        let worker = thread::Builder::new()
            .name(format!("ariadnion-mock-stream-{index}"))
            .spawn(move || stream_worker(receiver, shutdown))
            .map_err(|_| StreamExecutorStartError)?;
        workers.push(worker);
    }
    Ok(())
}

fn stream_worker(receiver: Arc<Mutex<Receiver<StreamJob>>>, shutdown: CancellationToken) {
    while let Some(job) = receive_stream_job(&receiver, &shutdown) {
        if shutdown.is_cancelled() {
            job.cancel();
            break;
        }
        job.run();
    }
}

fn receive_stream_job(
    receiver: &Mutex<Receiver<StreamJob>>,
    shutdown: &CancellationToken,
) -> Option<StreamJob> {
    if shutdown.is_cancelled() {
        return None;
    }
    lock_receiver(receiver).recv().ok()
}

fn discard_queued_stream_jobs(receiver: &Mutex<Receiver<StreamJob>>) {
    let receiver = lock_receiver(receiver);
    while let Ok(job) = receiver.try_recv() {
        job.cancel();
    }
}

fn take_stream_workers(workers: &Mutex<Vec<JoinHandle<()>>>) -> Vec<JoinHandle<()>> {
    let mut workers = lock_stream_workers(workers);
    std::mem::take(&mut *workers)
}

fn join_stream_workers(workers: Vec<JoinHandle<()>>) {
    for worker in workers {
        let _result = worker.join();
    }
}

fn lock_receiver(receiver: &Mutex<Receiver<StreamJob>>) -> MutexGuard<'_, Receiver<StreamJob>> {
    match receiver.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn lock_stream_workers(
    workers: &Mutex<Vec<JoinHandle<()>>>,
) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
    match workers.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn mark_response_started(evidence: &ProviderAttemptEvidence) -> Result<(), ProviderFailure> {
    evidence
        .mark_upstream_response_started()
        .map_err(|_| failure(ProviderFailureClass::Internal))
}

fn check_active(attempt: &ProviderAttempt) -> Result<(), ProviderFailure> {
    check_context(attempt.context())
}

fn check_context(context: &RequestContext) -> Result<(), ProviderFailure> {
    context
        .check_active()
        .map_err(|error| failure(failure_class(error.code())))
}

const fn failure_class(code: ErrorCode) -> ProviderFailureClass {
    match code {
        ErrorCode::Cancelled => ProviderFailureClass::Cancelled,
        ErrorCode::DeadlineExceeded => ProviderFailureClass::DeadlineExceeded,
        _ => ProviderFailureClass::Internal,
    }
}

const fn response_limit() -> ProviderFailure {
    failure(ProviderFailureClass::ResponseLimit)
}

const fn failure(class: ProviderFailureClass) -> ProviderFailure {
    ProviderFailure::new(class)
}

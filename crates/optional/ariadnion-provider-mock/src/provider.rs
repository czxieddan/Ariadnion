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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Fixed bounded text, chat, embedding, and image generation without external side effects.

use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ariadnion_api_domain::{
    ChatServiceRequest, ChatServiceResponse, EmbeddingInput, EmbeddingServiceRequest,
    EmbeddingServiceResponse, EmbeddingVector, EmbeddingVectors, FinishReason, ResponseMode,
    ServiceContractVersion, ServiceRequest, ServiceResponse, TextOutput, TextServiceRequest,
    TextServiceResponse, TokenUsage,
};
use ariadnion_core::{CancellationToken, ErrorCode, EventEnvelope, ModuleVersion, RequestContext};
use ariadnion_provider_sdk::{
    BoxProviderCall, ProviderAttempt, ProviderAttemptEvidence, ProviderCapabilities,
    ProviderCapability, ProviderContractError, ProviderDescriptor, ProviderFailure,
    ProviderFailureClass, ProviderId, ProviderLimits, ProviderPort, ProviderRawOutcome,
    ProviderStreamConfig, ProviderStreamEvent, ProviderStreamPublishError, ProviderStreamPublisher,
    bounded_provider_stream,
};

use crate::chunk::for_each_delta;
use crate::image::plan_image;

/// Stable provider identifier for the deterministic in-process adapter.
pub const MOCK_PROVIDER_ID: &str = "mock";
/// Stable provider model identifier accepted by the deterministic adapter.
pub const MOCK_PROVIDER_MODEL_ID: &str = "mock-chat-v1";
/// Stable text provider model identifier accepted by the deterministic adapter.
pub const MOCK_PROVIDER_TEXT_MODEL_ID: &str = "mock-text-v1";
/// Stable embedding provider model identifier accepted by the deterministic adapter.
pub const MOCK_PROVIDER_EMBEDDING_MODEL_ID: &str = "mock-embedding-v1";
/// Stable image provider model identifier accepted by the deterministic adapter.
pub const MOCK_PROVIDER_IMAGE_MODEL_ID: &str = "mock-image-v1";
/// Fixed output dimensions produced by the deterministic embedding model.
pub const MOCK_PROVIDER_EMBEDDING_DIMENSIONS: usize = 4;
/// Maximum UTF-8 bytes carried by one deterministic mock stream delta.
pub const MAX_MOCK_STREAM_DELTA_BYTES: usize = 1_024;

const MOCK_PREFIX: &str = "mock: ";
const MAX_MOCK_REQUEST_BYTES: usize = 1_048_576;
const MAX_MOCK_STREAM_BYTES: usize = MAX_MOCK_REQUEST_BYTES + MOCK_PREFIX.len();
const MAX_UTF8_SCALAR_BYTES: usize = 4;
// A non-final chunk can be short by at most three bytes when the next scalar is four bytes.
const MIN_FULL_MOCK_STREAM_DELTA_BYTES: usize =
    MAX_MOCK_STREAM_DELTA_BYTES - (MAX_UTF8_SCALAR_BYTES - 1);
const MAX_MOCK_STREAM_EVENTS: usize =
    MAX_MOCK_STREAM_BYTES.div_ceil(MIN_FULL_MOCK_STREAM_DELTA_BYTES) + 2;
const MOCK_STREAM_CHANNEL_CAPACITY: usize = 8;
const MOCK_STREAM_WORKERS: usize = 2;
const MOCK_STREAM_QUEUE_CAPACITY: usize = 16;
const BACKPRESSURE_RETRY_DELAY: Duration = Duration::from_millis(1);
const STREAM_EVENT_VERSION: ModuleVersion = ModuleVersion::new(1, 0, 0);

/// A deterministic in-process provider used for compatibility and deployment checks.
///
/// The adapter accepts one fixed model for each supported request kind. It
/// performs no provider network, filesystem, database, random, or credential
/// access. Core-owned deadline and event-envelope primitives remain authoritative,
/// and diagnostics retain neither input content nor model selectors.
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
            .with(ProviderCapability::TextStreaming)
            .with(ProviderCapability::Embeddings)
            .with(ProviderCapability::ImageGeneration);
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
    plan: GenerationPlan,
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
    output: OutputPlan,
    usage: TokenUsage,
}

struct TextPlan {
    output: OutputPlan,
}

enum GenerationPlan {
    Chat(ChatPlan),
    Text(TextPlan),
}

enum AttemptPlan {
    Generation {
        mode: ResponseMode,
        plan: GenerationPlan,
    },
    Complete(ServiceResponse),
}

enum ProviderModelKind {
    Chat,
    Text,
    Embedding,
    Image,
}

impl GenerationPlan {
    const fn output(&self) -> &OutputPlan {
        match self {
            Self::Chat(plan) => &plan.output,
            Self::Text(plan) => &plan.output,
        }
    }

    const fn started_event(&self) -> ProviderStreamEvent {
        match self {
            Self::Chat(plan) => ProviderStreamEvent::ChatStarted {
                version: plan.output.version,
            },
            Self::Text(plan) => ProviderStreamEvent::Started {
                version: plan.output.version,
            },
        }
    }

    const fn delta_event(&self, delta: ariadnion_api_domain::TextDelta) -> ProviderStreamEvent {
        match self {
            Self::Chat(_) => ProviderStreamEvent::ChatDelta(delta),
            Self::Text(_) => ProviderStreamEvent::TextDelta(delta),
        }
    }

    const fn completed_event(&self) -> ProviderStreamEvent {
        match self {
            Self::Chat(plan) => ProviderStreamEvent::ChatCompleted {
                finish_reason: plan.output.finish_reason,
                usage: plan.usage,
            },
            Self::Text(plan) => ProviderStreamEvent::Completed {
                finish_reason: plan.output.finish_reason,
            },
        }
    }
}

struct OutputPlan {
    version: ServiceContractVersion,
    content: Box<str>,
    generated_scalars: usize,
    finish_reason: FinishReason,
}

fn execute(
    attempt: ProviderAttempt,
    limits: ProviderLimits,
    stream_executor: &StreamExecutor,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    check_active(&attempt)?;
    let plan = plan_attempt(&attempt)?;
    check_active(&attempt)?;
    outcome_for_plan(attempt, limits, stream_executor, plan)
}

fn plan_attempt(attempt: &ProviderAttempt) -> Result<AttemptPlan, ProviderFailure> {
    let model = provider_model_kind(attempt.model().as_str())?;
    match (model, attempt.request()) {
        (ProviderModelKind::Chat, ServiceRequest::Chat(request)) => plan_chat(request).map(|plan| {
            AttemptPlan::Generation {
                mode: request.response_mode(),
                plan: GenerationPlan::Chat(plan),
            }
        }),
        (ProviderModelKind::Text, ServiceRequest::Text(request)) => plan_text(request).map(|plan| {
            AttemptPlan::Generation {
                mode: request.response_mode(),
                plan: GenerationPlan::Text(plan),
            }
        }),
        (ProviderModelKind::Embedding, ServiceRequest::Embedding(request)) => {
            plan_embedding(request)
                .map(ServiceResponse::Embedding)
                .map(AttemptPlan::Complete)
        }
        (ProviderModelKind::Image, ServiceRequest::Image(request)) => plan_image(request)
            .map(ServiceResponse::Image)
            .map(AttemptPlan::Complete),
        _ => Err(failure(ProviderFailureClass::InvalidRequest)),
    }
}

fn provider_model_kind(model: &str) -> Result<ProviderModelKind, ProviderFailure> {
    match model {
        MOCK_PROVIDER_MODEL_ID => Ok(ProviderModelKind::Chat),
        MOCK_PROVIDER_TEXT_MODEL_ID => Ok(ProviderModelKind::Text),
        MOCK_PROVIDER_EMBEDDING_MODEL_ID => Ok(ProviderModelKind::Embedding),
        MOCK_PROVIDER_IMAGE_MODEL_ID => Ok(ProviderModelKind::Image),
        _ => Err(failure(ProviderFailureClass::NotFound)),
    }
}

fn outcome_for_plan(
    attempt: ProviderAttempt,
    limits: ProviderLimits,
    stream_executor: &StreamExecutor,
    plan: AttemptPlan,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    match plan {
        AttemptPlan::Generation { mode, plan } => {
            outcome_for_mode(attempt, limits, stream_executor, mode, plan)
        }
        AttemptPlan::Complete(response) => {
            mark_response_started(&attempt.evidence())?;
            Ok(complete_response(response))
        }
    }
}

fn outcome_for_mode(
    attempt: ProviderAttempt,
    limits: ProviderLimits,
    stream_executor: &StreamExecutor,
    mode: ResponseMode,
    plan: GenerationPlan,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    match (mode, plan) {
        (ResponseMode::Complete, plan) => complete_outcome(attempt.evidence(), plan),
        (ResponseMode::Stream, plan) => stream_outcome(attempt, limits, stream_executor, plan),
        _ => Err(failure(ProviderFailureClass::InvalidRequest)),
    }
}

fn plan_chat(request: &ChatServiceRequest) -> Result<ChatPlan, ProviderFailure> {
    let last = request
        .messages()
        .as_slice()
        .last()
        .ok_or_else(|| failure(ProviderFailureClass::InvalidRequest))?;
    let output = plan_output(
        request.version(),
        last.content().as_str(),
        request.output_token_limit().get() as usize,
    )?;
    let output_tokens = u64::try_from(output.generated_scalars).map_err(|_| response_limit())?;
    let input_tokens = input_usage(request)?;
    let usage = TokenUsage::new(input_tokens, output_tokens).map_err(|_| response_limit())?;
    Ok(ChatPlan { output, usage })
}

fn plan_text(request: &TextServiceRequest) -> Result<TextPlan, ProviderFailure> {
    let output = plan_output(
        request.version(),
        request.input().as_str(),
        request.output_token_limit().get() as usize,
    )?;
    Ok(TextPlan { output })
}

fn plan_embedding(
    request: &EmbeddingServiceRequest,
) -> Result<EmbeddingServiceResponse, ProviderFailure> {
    let mut vectors = Vec::with_capacity(request.inputs().len());
    let mut input_tokens = 0_u64;
    for input in request.inputs().as_slice() {
        let (vector, tokens) = embedding_vector(input)?;
        input_tokens = input_tokens
            .checked_add(tokens)
            .ok_or_else(response_limit)?;
        vectors.push(vector);
    }
    let count = request.inputs().len();
    let vectors = EmbeddingVectors::new(vectors, count, MOCK_PROVIDER_EMBEDDING_DIMENSIONS)
        .map_err(|_| internal_failure())?;
    let usage = TokenUsage::new(input_tokens, 0).map_err(|_| response_limit())?;
    EmbeddingServiceResponse::new(request.version(), vectors, usage).map_err(|_| internal_failure())
}

fn embedding_vector(input: &EmbeddingInput) -> Result<(EmbeddingVector, u64), ProviderFailure> {
    let value = input.as_str();
    let first = value.chars().next().ok_or_else(invalid_request)?;
    let scalar_count = scalar_count(value)?;
    let values = vec![
        value.len() as f32,
        scalar_count as f32,
        u32::from(first) as f32,
        embedding_fingerprint(value) as f32,
    ];
    let vector = EmbeddingVector::new(values).map_err(|_| internal_failure())?;
    Ok((vector, scalar_count))
}

fn embedding_fingerprint(value: &str) -> u32 {
    let mut hash = 2_166_136_261_u32;
    for byte in value.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    // This non-cryptographic mock fingerprint stays exactly representable as f32.
    hash & 0x00ff_ffff
}

fn plan_output(
    version: ServiceContractVersion,
    content: &str,
    limit: usize,
) -> Result<OutputPlan, ProviderFailure> {
    let source_scalars = source_scalar_count(content)?;
    Ok(OutputPlan {
        version,
        content: content.into(),
        generated_scalars: source_scalars.min(limit),
        finish_reason: finish_reason(source_scalars, limit),
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
    plan: GenerationPlan,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    mark_response_started(&evidence)?;
    let output = complete_output(plan.output())?;
    let response = match plan {
        GenerationPlan::Chat(plan) => ServiceResponse::Chat(ChatServiceResponse::new(
            plan.output.version,
            output,
            plan.output.finish_reason,
            plan.usage,
        )),
        GenerationPlan::Text(plan) => ServiceResponse::Text(TextServiceResponse::new(
            plan.output.version,
            output,
            plan.output.finish_reason,
        )),
    };
    Ok(complete_response(response))
}

const fn complete_response(response: ServiceResponse) -> ProviderRawOutcome {
    ProviderRawOutcome::Complete(response)
}

fn complete_output(plan: &OutputPlan) -> Result<TextOutput, ProviderFailure> {
    let output: String = MOCK_PREFIX
        .chars()
        .chain(plan.content.chars())
        .take(plan.generated_scalars)
        .collect();
    TextOutput::new(&output).map_err(|_| response_limit())
}

fn stream_outcome(
    attempt: ProviderAttempt,
    limits: ProviderLimits,
    stream_executor: &StreamExecutor,
    plan: GenerationPlan,
) -> Result<ProviderRawOutcome, ProviderFailure> {
    let config = ProviderStreamConfig::new(MOCK_STREAM_CHANNEL_CAPACITY, limits)
        .map_err(|_| response_limit())?;
    let context =
        StreamExecutionContext::new(attempt.context().clone(), stream_executor.shutdown_token());
    let (publisher, subscriber) =
        bounded_provider_stream(config, attempt.evidence(), context.cancellation())
            .map_err(|_| failure(ProviderFailureClass::Internal))?;
    let mut sequence = 1_u64;
    publish_next(&publisher, &context, &mut sequence, plan.started_event())?;
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
    plan: GenerationPlan,
) {
    if let Err(error) = publish_generation_stream(&publisher, &context, &mut sequence, &plan)
        && publish_terminal_failure(&publisher, &context, sequence, error).is_err()
    {
        context.cancel();
    }
}

fn publish_generation_stream(
    publisher: &ProviderStreamPublisher,
    context: &StreamExecutionContext,
    sequence: &mut u64,
    plan: &GenerationPlan,
) -> Result<(), ProviderFailure> {
    for_each_delta(
        MOCK_PREFIX,
        &plan.output().content,
        plan.output().generated_scalars,
        |delta| publish_next(publisher, context, sequence, plan.delta_event(delta)),
    )?;
    publish_next(publisher, context, sequence, plan.completed_event())
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

const fn invalid_request() -> ProviderFailure {
    failure(ProviderFailureClass::InvalidRequest)
}

const fn internal_failure() -> ProviderFailure {
    failure(ProviderFailureClass::Internal)
}

const fn failure(class: ProviderFailureClass) -> ProviderFailure {
    ProviderFailure::new(class)
}

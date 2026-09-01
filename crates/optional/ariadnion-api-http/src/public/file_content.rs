// crates/optional/ariadnion-api-http/src/public/file_content.rs - Native file content HTTP ingress.
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

//! Native bounded streaming file-content retrieval.

use std::future::{Future, pending, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::SystemTime;

use ariadnion_api_domain::{ApiDomainError, ApiDomainErrorCode, FileDescriptor, FileReference};
use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, FileChunk, FileDownloadSink, FileServicePort,
};
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext, RequestId};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_core::Stream;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio::task::{AbortHandle, JoinHandle};

use super::error::{ResponseFailure, domain_failure, failure, response_with_request_id};
use super::{ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpRequestIdentity, execution};

const REFERENCE_HEX_BYTES: usize = FileReference::BYTE_LENGTH * 2;
const CONTENT_PATH_SUFFIX: &str = "/content";
const REQUEST_ID_HEADER: &str = "x-request-id";
const RELEASE_REQUESTED: u8 = 0b01;
const PRODUCER_FINISHED: u8 = 0b10;
const RELEASE_READY: u8 = RELEASE_REQUESTED | PRODUCER_FINISHED;

type ProducerFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type ProducerTask = JoinHandle<()>;

/// Handles one authenticated, backpressure-preserving file download.
pub(super) async fn handle_content(
    State(state): State<HttpApiState>,
    request: Request<Body>,
) -> Response {
    let (parts, _body) = request.into_parts();
    let reference_text = content_reference(parts.uri.path());
    let admission = match admit_request(&state, &parts.headers) {
        Ok(admission) => admission,
        Err(response) => return *response,
    };
    let prepared = match prepare_content(&state, &parts.headers, reference_text, admission).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    start_content(prepared).await
}

fn content_reference(path: &str) -> Option<&str> {
    path.strip_prefix("/v1/files/")
        .and_then(|value| value.strip_suffix(CONTENT_PATH_SUFFIX))
        .filter(|value| !value.is_empty() && !value.contains('/'))
}

struct RequestAdmission {
    identity: HttpRequestIdentity,
    deadline: SystemTime,
    permit: OwnedSemaphorePermit,
}

fn admit_request(
    state: &HttpApiState,
    headers: &HeaderMap,
) -> Result<RequestAdmission, Box<Response>> {
    let generated = state.identity.issue().map_err(|error| {
        Box::new(failure(state.identity.fallback_identity(), error).into_response())
    })?;
    let permit = state.admission.clone().try_acquire_owned().map_err(|_| {
        Box::new(
            failure(
                generated.clone(),
                ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted),
            )
            .into_response(),
        )
    })?;
    let (identity, deadline) = admit_identity(generated, headers)
        .map_err(|(identity, error)| Box::new(failure(identity, error).into_response()))?;
    Ok(RequestAdmission {
        identity,
        deadline,
        permit,
    })
}

struct PreparedContent {
    permit: OwnedSemaphorePermit,
    identity: HttpRequestIdentity,
    service: Arc<dyn FileServicePort>,
    reference: FileReference,
    descriptor: FileDescriptor,
    lifetime: RequestLifetime,
    context: RequestContext,
}

async fn prepare_content(
    state: &HttpApiState,
    headers: &HeaderMap,
    reference_text: Option<&str>,
    admission: RequestAdmission,
) -> Result<PreparedContent, Box<Response>> {
    let RequestAdmission {
        identity,
        deadline,
        permit,
    } = admission;
    let service = state.file_service.clone().ok_or_else(|| {
        Box::new(
            ResponseFailure::file(
                identity.clone(),
                ApiFilesError::new(ApiFilesErrorCode::Unavailable),
            )
            .into_response(),
        )
    })?;
    let authorization = execution::parse_authorization(headers)
        .map_err(|error| Box::new(failure(identity.clone(), error).into_response()))?;
    let reference = reference_text.and_then(decode_reference).ok_or_else(|| {
        Box::new(
            ResponseFailure::file(
                identity.clone(),
                ApiFilesError::new(ApiFilesErrorCode::NotFound),
            )
            .into_response(),
        )
    })?;
    let lifetime = RequestLifetime::new(&state.shutdown);
    let context = authenticate_context(state, &identity, deadline, authorization, &lifetime)
        .await
        .map_err(|error| Box::new(file_failure_response(identity.clone(), error)))?;
    let descriptor = load_metadata(&service, &reference, &context)
        .await
        .map_err(|error| Box::new(file_failure_response(identity.clone(), error)))?;
    if descriptor.reference() != &reference {
        return Err(Box::new(file_failure_response(
            identity,
            ApiFilesError::new(ApiFilesErrorCode::NotFound),
        )));
    }
    Ok(PreparedContent {
        permit,
        identity,
        service,
        reference,
        descriptor,
        lifetime,
        context,
    })
}

async fn authenticate_context(
    state: &HttpApiState,
    identity: &HttpRequestIdentity,
    deadline: SystemTime,
    authorization: super::PresentedBearer,
    lifetime: &RequestLifetime,
) -> Result<RequestContext, FileFailure> {
    let anonymous = RequestContext::new(
        identity.request_id().clone(),
        identity.trace_id().clone(),
        None,
        Some(deadline),
        lifetime.token(),
    );
    anonymous
        .check_active()
        .map_err(|error| FileFailure::Domain(error.into()))?;
    let evidence = execution::within_request_context(
        &anonymous,
        state
            .authentication
            .authenticate(&authorization, &anonymous),
    )
    .await
    .map_err(|error| FileFailure::Files(error.into()))?
    .map_err(FileFailure::Http)?;
    Ok(RequestContext::new(
        identity.request_id().clone(),
        identity.trace_id().clone(),
        Some(PrincipalContext::new(
            evidence.tenant_id().clone(),
            evidence.principal_id().clone(),
        )),
        Some(deadline),
        lifetime.token(),
    ))
}

async fn load_metadata(
    service: &Arc<dyn FileServicePort>,
    reference: &FileReference,
    context: &RequestContext,
) -> Result<FileDescriptor, FileFailure> {
    execution::within_request_context(context, service.metadata(reference, context))
        .await
        .map_err(|error| FileFailure::Files(error.into()))?
        .map_err(FileFailure::Files)
}

async fn start_content(prepared: PreparedContent) -> Response {
    let identity = prepared.identity.clone();
    match build_content_response(prepared).await {
        Ok(response) => response,
        Err(error) => file_failure_response(identity, error),
    }
}

async fn build_content_response(prepared: PreparedContent) -> Result<Response, FileFailure> {
    let PreparedContent {
        permit,
        identity,
        service,
        reference,
        descriptor,
        lifetime,
        context,
    } = prepared;
    let (sender, mut receiver) = mpsc::channel(1);
    let lifetime_sender = sender.clone();
    let mut producer: ProducerFuture = Box::pin(run_download(
        service,
        reference,
        descriptor.clone(),
        sender,
        context.clone(),
    ));
    let first = receive_first_chunk(&context, &mut receiver, &mut producer, &lifetime).await?;
    validate_first_chunk(&first, &descriptor, &lifetime)?;
    let execution = DownloadExecution::new(
        receiver,
        lifetime_sender,
        producer,
        permit,
        lifetime,
        context,
    );
    let body = DownloadBody::new(first, execution, descriptor);
    let response_descriptor = body.descriptor.clone();
    content_response(&identity, &response_descriptor, body).map_err(FileFailure::Http)
}

async fn receive_first_chunk(
    context: &RequestContext,
    receiver: &mut mpsc::Receiver<DownloadMessage>,
    producer: &mut ProducerFuture,
    lifetime: &RequestLifetime,
) -> Result<Bytes, FileFailure> {
    let message = receive_first(context, receiver, producer)
        .await
        .map_err(|error| {
            lifetime.cancel();
            FileFailure::Files(error)
        })?;
    match message {
        DownloadMessage::Chunk(bytes) => Ok(bytes),
        DownloadMessage::Error(error) => {
            lifetime.cancel();
            Err(error.into())
        }
        DownloadMessage::Complete(_) => {
            lifetime.cancel();
            Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure).into())
        }
    }
}

fn validate_first_chunk(
    first: &Bytes,
    descriptor: &FileDescriptor,
    lifetime: &RequestLifetime,
) -> Result<(), FileFailure> {
    match checked_chunk_length(first, 0, descriptor.byte_length().get()) {
        Ok(_) => Ok(()),
        Err(error) => {
            lifetime.cancel();
            Err(error.into())
        }
    }
}

async fn receive_first(
    context: &RequestContext,
    receiver: &mut mpsc::Receiver<DownloadMessage>,
    producer: &mut ProducerFuture,
) -> Result<DownloadMessage, ApiFilesError> {
    execution::within_request_context(
        context,
        poll_fn(|task| {
            if let Poll::Ready(message) = Pin::new(&mut *receiver).poll_recv(task) {
                return Poll::Ready(
                    message.ok_or_else(|| ApiFilesError::new(ApiFilesErrorCode::Internal)),
                );
            }
            if producer.as_mut().poll(task).is_ready() {
                return match Pin::new(&mut *receiver).poll_recv(task) {
                    Poll::Ready(message) => Poll::Ready(
                        message
                            .ok_or_else(|| ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure)),
                    ),
                    Poll::Pending => {
                        Poll::Ready(Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure)))
                    }
                };
            }
            Poll::Pending
        }),
    )
    .await
    .map_err(ApiFilesError::from)?
}

async fn run_download(
    service: Arc<dyn FileServicePort>,
    reference: FileReference,
    expected: FileDescriptor,
    sender: mpsc::Sender<DownloadMessage>,
    context: RequestContext,
) {
    let mut sink = ChannelDownloadSink::new(sender.clone());
    let result = execution::within_request_context(
        &context,
        service.content(&reference, &mut sink, &context),
    )
    .await;
    let message = match result {
        Ok(Ok(descriptor)) if sink.finished() && descriptor == expected => {
            DownloadMessage::Complete(descriptor)
        }
        Ok(Ok(_)) => {
            DownloadMessage::Error(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure))
        }
        Ok(Err(error)) => DownloadMessage::Error(error),
        Err(error) => DownloadMessage::Error(error.into()),
    };
    let _ = execution::within_request_context(&context, sender.send(message)).await;
}

struct ChannelDownloadSink {
    sender: mpsc::Sender<DownloadMessage>,
    finished: bool,
}

impl ChannelDownloadSink {
    fn new(sender: mpsc::Sender<DownloadMessage>) -> Self {
        Self {
            sender,
            finished: false,
        }
    }

    fn finished(&self) -> bool {
        self.finished
    }
}

impl FileDownloadSink for ChannelDownloadSink {
    fn write_chunk<'a>(
        &'a mut self,
        chunk: FileChunk,
        context: &'a RequestContext,
    ) -> ariadnion_api_files::BoxFileFuture<'a, Result<(), ApiFilesError>> {
        if self.finished {
            return Box::pin(async {
                Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure))
            });
        }
        let sender = self.sender.clone();
        Box::pin(async move {
            context.check_active().map_err(ApiFilesError::from)?;
            execution::within_request_context(
                context,
                sender.send(DownloadMessage::Chunk(Bytes::from(chunk.into_bytes()))),
            )
            .await
            .map_err(ApiFilesError::from)?
            .map_err(|_| ApiFilesError::new(ApiFilesErrorCode::Cancelled))
        })
    }

    fn finish<'a>(
        &'a mut self,
        context: &'a RequestContext,
    ) -> ariadnion_api_files::BoxFileFuture<'a, Result<(), ApiFilesError>> {
        Box::pin(async move {
            if self.finished {
                return Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure));
            }
            context.check_active().map_err(ApiFilesError::from)?;
            self.finished = true;
            Ok(())
        })
    }
}

fn checked_chunk_length(
    bytes: &Bytes,
    delivered: usize,
    expected: usize,
) -> Result<usize, ApiFilesError> {
    if bytes.is_empty() || bytes.len() > ariadnion_api_files::MAX_FILE_CHUNK_BYTES {
        return Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure));
    }
    let delivered = delivered
        .checked_add(bytes.len())
        .ok_or_else(|| ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure))?;
    if delivered > expected {
        return Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure));
    }
    Ok(delivered)
}

enum DownloadMessage {
    Chunk(Bytes),
    Complete(FileDescriptor),
    Error(ApiFilesError),
}

enum DownloadPollStep {
    Continue,
    Pending,
    Ready(Poll<Option<Result<Bytes, ApiFilesError>>>),
}

struct DownloadBody {
    first: Option<Bytes>,
    execution: DownloadExecution,
    descriptor: FileDescriptor,
    delivered: usize,
    done: bool,
}

impl DownloadBody {
    fn new(first: Bytes, execution: DownloadExecution, descriptor: FileDescriptor) -> Self {
        Self {
            first: Some(first),
            execution,
            descriptor,
            delivered: 0,
            done: false,
        }
    }

    fn finish(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        self.execution.stop();
    }

    fn process_chunk(&mut self, bytes: Bytes) -> Result<Bytes, ApiFilesError> {
        let delivered =
            checked_chunk_length(&bytes, self.delivered, self.descriptor.byte_length().get())?;
        self.delivered = delivered;
        Ok(bytes)
    }

    fn check_and_process_chunk(&mut self, bytes: Bytes) -> Result<Bytes, ApiFilesError> {
        if let Some(error) = self.context_error() {
            return Err(error);
        }
        self.process_chunk(bytes)
    }

    fn context_error(&self) -> Option<ApiFilesError> {
        let deadline_expired = self.execution.lease.deadline_expired();
        #[rustfmt::skip]
        let activity = self.execution
            .context
            .check_active();
        match activity {
            Ok(()) if deadline_expired => {
                Some(ApiFilesError::new(ApiFilesErrorCode::DeadlineExceeded))
            }
            Ok(()) => None,
            Err(error) => Some(error.into()),
        }
    }

    fn contextual_error(&self, fallback: ApiFilesError) -> ApiFilesError {
        self.context_error().unwrap_or(fallback)
    }

    fn process_message(
        &mut self,
        message: DownloadMessage,
    ) -> Poll<Option<Result<Bytes, ApiFilesError>>> {
        match message {
            DownloadMessage::Chunk(bytes) => self.process_chunk_result(bytes),
            DownloadMessage::Complete(descriptor) => self.process_complete(descriptor),
            DownloadMessage::Error(error) => self.process_error(error),
        }
    }

    fn process_chunk_result(&mut self, bytes: Bytes) -> Poll<Option<Result<Bytes, ApiFilesError>>> {
        match self.check_and_process_chunk(bytes) {
            Ok(bytes) => Poll::Ready(Some(Ok(bytes))),
            Err(error) => {
                self.finish();
                Poll::Ready(Some(Err(error)))
            }
        }
    }

    fn process_complete(
        &mut self,
        descriptor: FileDescriptor,
    ) -> Poll<Option<Result<Bytes, ApiFilesError>>> {
        let valid =
            descriptor == self.descriptor && self.delivered == self.descriptor.byte_length().get();
        let context_error = self.context_error();
        self.finish();
        completion_poll(valid, context_error)
    }

    fn process_error(
        &mut self,
        error: ApiFilesError,
    ) -> Poll<Option<Result<Bytes, ApiFilesError>>> {
        let error = self.contextual_error(error);
        self.finish();
        Poll::Ready(Some(Err(error)))
    }

    fn poll_remaining(
        &mut self,
        task: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, ApiFilesError>>> {
        loop {
            match self.poll_download_step(task) {
                DownloadPollStep::Continue => {}
                DownloadPollStep::Pending => return Poll::Pending,
                DownloadPollStep::Ready(result) => return result,
            }
        }
    }

    fn poll_download_step(&mut self, task: &mut Context<'_>) -> DownloadPollStep {
        match Pin::new(&mut self.execution.receiver).poll_recv(task) {
            Poll::Ready(message) => self.poll_receiver_message(message),
            Poll::Pending => self.poll_producer(task),
        }
    }

    fn poll_receiver_message(&mut self, message: Option<DownloadMessage>) -> DownloadPollStep {
        match message {
            Some(message) => DownloadPollStep::Ready(self.process_message(message)),
            None => DownloadPollStep::Ready(self.receiver_closed()),
        }
    }

    fn poll_producer(&mut self, task: &mut Context<'_>) -> DownloadPollStep {
        match self.execution.producer.as_mut() {
            Some(producer) => {
                if Pin::new(producer).poll(task).is_ready() {
                    self.execution.producer.take();
                    DownloadPollStep::Continue
                } else {
                    DownloadPollStep::Pending
                }
            }
            None => DownloadPollStep::Ready(self.producer_missing()),
        }
    }

    fn receiver_closed(&mut self) -> Poll<Option<Result<Bytes, ApiFilesError>>> {
        let error = self.contextual_error(ApiFilesError::new(ApiFilesErrorCode::Internal));
        self.finish();
        Poll::Ready(Some(Err(error)))
    }

    fn producer_missing(&mut self) -> Poll<Option<Result<Bytes, ApiFilesError>>> {
        let error = self.contextual_error(ApiFilesError::new(ApiFilesErrorCode::Internal));
        self.finish();
        Poll::Ready(Some(Err(error)))
    }
}

struct DownloadExecution {
    receiver: mpsc::Receiver<DownloadMessage>,
    producer: Option<ProducerTask>,
    deadline_watch: Option<ProducerTask>,
    lease: Arc<DownloadLease>,
    lifetime: RequestLifetime,
    context: RequestContext,
}

impl DownloadExecution {
    fn new(
        receiver: mpsc::Receiver<DownloadMessage>,
        lifetime_sender: mpsc::Sender<DownloadMessage>,
        producer: ProducerFuture,
        permit: OwnedSemaphorePermit,
        lifetime: RequestLifetime,
        context: RequestContext,
    ) -> Self {
        let lease = Arc::new(DownloadLease::new(permit));
        let producer = TrackedProducer::new(producer, Arc::clone(&lease));
        let producer = tokio::spawn(producer);
        let producer_abort = producer.abort_handle();
        let deadline_watch = Some(tokio::spawn(watch_download_lifetime(
            context.clone(),
            Arc::clone(&lease),
            producer_abort,
            lifetime_sender,
        )));
        Self {
            receiver,
            producer: Some(producer),
            deadline_watch,
            lease,
            lifetime,
            context,
        }
    }

    fn stop(&mut self) {
        self.lifetime.cancel();
        abort_task(&mut self.producer);
        abort_task(&mut self.deadline_watch);
        self.lease.request_release();
    }
}

impl Drop for DownloadExecution {
    fn drop(&mut self) {
        self.stop();
    }
}

struct DownloadLease {
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    release_state: AtomicU8,
    deadline_expired: AtomicBool,
}

impl DownloadLease {
    fn new(permit: OwnedSemaphorePermit) -> Self {
        Self {
            permit: Mutex::new(Some(permit)),
            release_state: AtomicU8::new(0),
            deadline_expired: AtomicBool::new(false),
        }
    }

    fn mark_deadline_expired(&self) {
        self.deadline_expired.store(true, Ordering::Release);
    }

    fn deadline_expired(&self) -> bool {
        self.deadline_expired.load(Ordering::Acquire)
    }

    fn request_release(&self) {
        self.record_release_transition(RELEASE_REQUESTED);
    }

    fn mark_producer_finished(&self) {
        self.record_release_transition(PRODUCER_FINISHED);
    }

    fn record_release_transition(&self, transition: u8) {
        let state = self.release_state.fetch_or(transition, Ordering::AcqRel) | transition;
        if state & RELEASE_READY == RELEASE_READY {
            self.release_permit();
        }
    }

    fn release_permit(&self) {
        let permit = {
            let mut permit = match self.permit.lock() {
                Ok(permit) => permit,
                // Taking the permit remains safe after poison because no protected
                // invariant depends on its prior value.
                Err(poisoned) => poisoned.into_inner(),
            };
            permit.take()
        };
        drop(permit);
    }
}

struct TrackedProducer {
    // Declaration order keeps provider state alive until teardown is acknowledged.
    inner: ProducerFuture,
    _completion: ProducerCompletionGuard,
}

impl TrackedProducer {
    fn new(inner: ProducerFuture, lease: Arc<DownloadLease>) -> Self {
        Self {
            inner,
            _completion: ProducerCompletionGuard { lease },
        }
    }
}

impl Future for TrackedProducer {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(task)
    }
}

struct ProducerCompletionGuard {
    lease: Arc<DownloadLease>,
}

impl Drop for ProducerCompletionGuard {
    fn drop(&mut self) {
        self.lease.mark_producer_finished();
    }
}

async fn watch_download_lifetime(
    context: RequestContext,
    lease: Arc<DownloadLease>,
    producer: AbortHandle,
    lifetime_sender: mpsc::Sender<DownloadMessage>,
) {
    let outcome = execution::within_request_context(&context, pending::<()>()).await;
    let error = download_lifetime_error(outcome, &lease);
    producer.abort();
    lease.request_release();
    // A full channel already contains a wakeable message; a closed channel has no body.
    let _ = lifetime_sender.try_send(DownloadMessage::Error(error));
}

fn download_lifetime_error(
    outcome: Result<(), ApiDomainError>,
    lease: &DownloadLease,
) -> ApiFilesError {
    match outcome {
        Ok(()) => ApiFilesError::new(ApiFilesErrorCode::Internal),
        Err(error) => {
            if error.code() == ApiDomainErrorCode::DeadlineExceeded {
                lease.mark_deadline_expired();
            }
            error.into()
        }
    }
}

fn abort_task(task: &mut Option<ProducerTask>) {
    if let Some(task) = task.take() {
        task.abort();
    }
}

fn completion_poll(
    valid: bool,
    context_error: Option<ApiFilesError>,
) -> Poll<Option<Result<Bytes, ApiFilesError>>> {
    match context_error {
        Some(error) => Poll::Ready(Some(Err(error))),
        None if valid => Poll::Ready(None),
        None => Poll::Ready(Some(Err(ApiFilesError::new(
            ApiFilesErrorCode::IntegrityFailure,
        )))),
    }
}

impl Stream for DownloadBody {
    type Item = Result<Bytes, ApiFilesError>;

    fn poll_next(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.first.take() {
            Some(first) => self.process_chunk_result(first),
            None => self.poll_remaining(task),
        }
    }
}

impl Drop for DownloadBody {
    fn drop(&mut self) {
        self.finish();
    }
}

struct RequestLifetime {
    cancellation: CancellationToken,
}

impl RequestLifetime {
    fn new(shutdown: &CancellationToken) -> Self {
        Self {
            cancellation: shutdown.child(),
        }
    }

    fn token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }
}

impl Drop for RequestLifetime {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn admit_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<(HttpRequestIdentity, SystemTime), (HttpRequestIdentity, ApiHttpError)> {
    execution::validate_header_budget(headers).map_err(|error| (generated.clone(), error))?;
    let identity = resolve_identity(generated, headers)?;
    let deadline = execution::parse_deadline(headers, SystemTime::now())
        .map_err(|error| (identity.clone(), error))?;
    Ok((identity, deadline))
}

fn resolve_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<HttpRequestIdentity, (HttpRequestIdentity, ApiHttpError)> {
    let value = execution::one_header(headers, REQUEST_ID_HEADER, false)
        .map_err(|error| (generated.clone(), error))?;
    let Some(value) = value else {
        return Ok(generated);
    };
    let text = value.to_str().map_err(|_| {
        (
            generated.clone(),
            ApiHttpError::new(ApiHttpErrorCode::InvalidRequest),
        )
    })?;
    let request_id = RequestId::parse(text).map_err(|_| {
        (
            generated.clone(),
            ApiHttpError::new(ApiHttpErrorCode::InvalidRequest),
        )
    })?;
    Ok(HttpRequestIdentity::new(
        request_id,
        generated.trace_id().clone(),
    ))
}

fn decode_reference(value: &str) -> Option<FileReference> {
    if value.len() != REFERENCE_HEX_BYTES {
        return None;
    }
    let mut output = [0_u8; FileReference::BYTE_LENGTH];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_lower_hex(pair[0])?;
        let low = decode_lower_hex(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(FileReference::new(output))
}

fn decode_lower_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn content_response(
    identity: &HttpRequestIdentity,
    descriptor: &FileDescriptor,
    body: DownloadBody,
) -> Result<Response, ApiHttpError> {
    let mut response = Body::from_stream(body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(descriptor.media_type().as_str())
            .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::Internal))?,
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&descriptor.byte_length().get().to_string())
            .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::Internal))?,
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition(descriptor.display_name().as_str()))
            .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::Internal))?,
    );
    Ok(response_with_request_id(identity, response))
}

fn content_disposition(display_name: &str) -> String {
    let mut value = String::from("attachment; filename*=UTF-8''");
    for byte in display_name.bytes() {
        if is_rfc5987_attr_char(byte) {
            value.push(byte as char);
        } else {
            value.push('%');
            value.push(hex_digit(byte >> 4));
            value.push(hex_digit(byte & 0x0f));
        }
    }
    value
}

fn is_rfc5987_attr_char(value: u8) -> bool {
    value.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&value)
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + value - 10) as char,
        _ => '0',
    }
}

enum FileFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
    Files(ApiFilesError),
}

impl From<ApiHttpError> for FileFailure {
    fn from(error: ApiHttpError) -> Self {
        Self::Http(error)
    }
}

impl From<ApiDomainError> for FileFailure {
    fn from(error: ApiDomainError) -> Self {
        Self::Domain(error)
    }
}

impl From<ApiFilesError> for FileFailure {
    fn from(error: ApiFilesError) -> Self {
        Self::Files(error)
    }
}

fn file_failure_response(identity: HttpRequestIdentity, error: impl Into<FileFailure>) -> Response {
    match error.into() {
        FileFailure::Http(error) => failure(identity, error).into_response(),
        FileFailure::Domain(error) => domain_failure(identity, error).into_response(),
        FileFailure::Files(error) => ResponseFailure::file(identity, error).into_response(),
    }
}

// crates/optional/ariadnion-protocol-openai/src/stream.rs - OpenAI chat completion SSE projection for Ariadnion.
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
//! Bounded poll-driven projection of domain chat events into OpenAI SSE frames.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, ChatStreamEvent, FinishReason, ServiceContractVersion,
    ServiceStreamEvent, TextDelta, TokenUsage,
};
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, HttpRequestIdentity, ProtocolFailure, ProtocolStreamResponse,
};
use ariadnion_core::{
    CancellationToken, EventEnvelope, EventSubscriber, ReceiveOutcome, RequestContext,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use futures_core::Stream;
use serde::Serialize;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

const CREATED_EPOCH_SECONDS: u64 = 0;
const EVENT_RECEIVE_POLL: Duration = Duration::from_millis(25);
const MAX_OPENAI_SSE_FRAME_BYTES: usize = 256 * 1024;
const DATA_PREFIX: &[u8] = b"data: ";
const FRAME_SUFFIX: &[u8] = b"\n\n";
const DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

type ReceiveTask = JoinHandle<(EventSubscriber<ServiceStreamEvent>, StreamReceiveOutcome)>;

pub(crate) fn project_stream(
    identity: &HttpRequestIdentity,
    model: &str,
    include_usage: bool,
    subscriber: EventSubscriber<ServiceStreamEvent>,
    context: &RequestContext,
) -> Result<ProtocolStreamResponse, ProtocolFailure> {
    context
        .check_active()
        .map_err(ApiDomainError::from)
        .map_err(project_domain_error)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    let stream = OpenAiSseStream::new(identity, model, include_usage, subscriber, context);
    ProtocolStreamResponse::new(StatusCode::OK, headers, Box::pin(stream))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StreamState {
    AwaitingStart,
    Open,
    AfterFinish(Option<TokenUsage>),
    AfterUsage,
    AfterDone,
    Closed,
}

enum StreamReceiveOutcome {
    Event(EventEnvelope<ServiceStreamEvent>),
    Closed,
    Cancelled,
    RequestInactive,
}

struct OpenAiSseStream {
    subscriber: Option<EventSubscriber<ServiceStreamEvent>>,
    receive: Option<ReceiveTask>,
    channel_cancellation: CancellationToken,
    request_context: RequestContext,
    id: Box<str>,
    model: Box<str>,
    include_usage: bool,
    last_sequence: Option<u64>,
    state: StreamState,
}

impl OpenAiSseStream {
    fn new(
        identity: &HttpRequestIdentity,
        model: &str,
        include_usage: bool,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Self {
        let channel_cancellation = subscriber.cancellation();
        Self {
            subscriber: Some(subscriber),
            receive: None,
            channel_cancellation,
            request_context: context.clone(),
            id: format!("chatcmpl-{}", identity.request_id().as_str()).into(),
            model: model.into(),
            include_usage,
            last_sequence: None,
            state: StreamState::AwaitingStart,
        }
    }

    fn poll_queued(&mut self) -> Option<Poll<Option<Result<Bytes, ApiHttpError>>>> {
        match self.state {
            StreamState::AfterFinish(Some(usage)) => {
                let encoded = self.encode_usage(usage);
                Some(self.emit_queued(encoded, StreamState::AfterUsage))
            }
            StreamState::AfterFinish(None) | StreamState::AfterUsage => {
                self.state = StreamState::AfterDone;
                Some(ready(Bytes::from_static(DONE_FRAME)))
            }
            StreamState::AfterDone => {
                self.close();
                Some(Poll::Ready(None))
            }
            StreamState::Closed => Some(Poll::Ready(None)),
            StreamState::AwaitingStart | StreamState::Open => None,
        }
    }

    fn emit_queued(
        &mut self,
        encoded: Result<Bytes, ApiHttpError>,
        next: StreamState,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match encoded {
            Ok(frame) => {
                self.state = next;
                ready(frame)
            }
            Err(error) => self.fail(error),
        }
    }

    fn ensure_receive(&mut self) -> Result<(), ApiHttpError> {
        if self.receive.is_some() {
            return Ok(());
        }
        let handle = Handle::try_current().map_err(|_| internal_error())?;
        let subscriber = self.subscriber.take().ok_or_else(internal_error)?;
        let request_context = self.request_context.clone();
        self.receive =
            Some(handle.spawn_blocking(move || receive_until_ready(subscriber, &request_context)));
        Ok(())
    }

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        let Some(mut receive) = self.receive.take() else {
            return self.fail(internal_error());
        };
        match Pin::new(&mut receive).poll(context) {
            Poll::Pending => {
                self.receive = Some(receive);
                Poll::Pending
            }
            Poll::Ready(Ok((subscriber, outcome))) => {
                self.subscriber = Some(subscriber);
                self.handle_receive(outcome)
            }
            Poll::Ready(Err(_)) => self.fail(internal_error()),
        }
    }

    fn handle_receive(
        &mut self,
        outcome: StreamReceiveOutcome,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match outcome {
            StreamReceiveOutcome::Event(event) => self.handle_event(event),
            StreamReceiveOutcome::Closed => self.fail(internal_error()),
            StreamReceiveOutcome::Cancelled | StreamReceiveOutcome::RequestInactive => {
                self.close();
                Poll::Ready(None)
            }
        }
    }

    fn handle_event(
        &mut self,
        event: EventEnvelope<ServiceStreamEvent>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        let sequence = event.sequence();
        if !valid_sequence(self.last_sequence, sequence) {
            return self.fail(internal_error());
        }
        self.last_sequence = Some(sequence);
        let ServiceStreamEvent::Chat(event) = event.into_payload() else {
            return self.fail(internal_error());
        };
        self.handle_chat_event(event)
    }

    fn handle_chat_event(
        &mut self,
        event: ChatStreamEvent,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match (self.state, event) {
            (StreamState::AwaitingStart, ChatStreamEvent::Started { version }) => {
                self.handle_started(version)
            }
            (StreamState::Open, ChatStreamEvent::Delta(delta)) => self.handle_delta(&delta),
            (
                StreamState::Open,
                ChatStreamEvent::Completed {
                    finish_reason,
                    usage,
                },
            ) => self.handle_completed(finish_reason, usage),
            (_, ChatStreamEvent::Failed(error)) => self.handle_failure(error),
            _ => self.fail(internal_error()),
        }
    }

    fn handle_started(
        &mut self,
        version: ServiceContractVersion,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        if version != ServiceContractVersion::V1 {
            return self.fail(internal_error());
        }
        let encoded = self.encode_choice(DeltaBody::assistant(), None);
        self.emit_queued(encoded, StreamState::Open)
    }

    fn handle_delta(&mut self, delta: &TextDelta) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        let encoded = self.encode_choice(DeltaBody::content(delta.as_str()), None);
        self.emit_queued(encoded, StreamState::Open)
    }

    fn handle_completed(
        &mut self,
        finish_reason: FinishReason,
        usage: TokenUsage,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        let reason = match finish_reason_value(finish_reason) {
            Ok(reason) => reason,
            Err(error) => return self.fail(error),
        };
        let encoded = self.encode_choice(DeltaBody::empty(), Some(reason));
        self.stop_receiving();
        let pending_usage = self.include_usage.then_some(usage);
        self.emit_queued(encoded, StreamState::AfterFinish(pending_usage))
    }

    fn handle_failure(
        &mut self,
        error: ApiDomainError,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        if error.code() == ApiDomainErrorCode::Cancelled {
            self.close();
            return Poll::Ready(None);
        }
        self.fail(project_domain_error(error))
    }

    fn encode_choice(
        &self,
        delta: DeltaBody<'_>,
        finish_reason: Option<&'static str>,
    ) -> Result<Bytes, ApiHttpError> {
        let choices = [ChunkChoice {
            index: 0,
            delta,
            finish_reason,
        }];
        let body = ChunkBody {
            id: &self.id,
            object: "chat.completion.chunk",
            created: CREATED_EPOCH_SECONDS,
            model: &self.model,
            choices: &choices,
            usage: regular_usage_field(self.include_usage),
        };
        encode_frame(&body)
    }

    fn encode_usage(&self, usage: TokenUsage) -> Result<Bytes, ApiHttpError> {
        let choices: [ChunkChoice<'_>; 0] = [];
        let body = ChunkBody {
            id: &self.id,
            object: "chat.completion.chunk",
            created: CREATED_EPOCH_SECONDS,
            model: &self.model,
            choices: &choices,
            usage: Some(Some(UsageBody::from(usage))),
        };
        encode_frame(&body)
    }

    fn fail(&mut self, error: ApiHttpError) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        self.close();
        Poll::Ready(Some(Err(error)))
    }

    fn stop_receiving(&mut self) {
        self.channel_cancellation.cancel();
        self.subscriber.take();
        self.receive.take();
    }

    fn close(&mut self) {
        self.stop_receiving();
        self.state = StreamState::Closed;
    }
}

impl Stream for OpenAiSseStream {
    type Item = Result<Bytes, ApiHttpError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.as_mut().get_mut();
        if stream.request_context.is_inactive() {
            stream.close();
            return Poll::Ready(None);
        }
        if let Some(poll) = stream.poll_queued() {
            return poll;
        }
        if let Err(error) = stream.ensure_receive() {
            return stream.fail(error);
        }
        stream.poll_receive(context)
    }
}

impl Drop for OpenAiSseStream {
    fn drop(&mut self) {
        self.channel_cancellation.cancel();
    }
}

fn receive_until_ready(
    subscriber: EventSubscriber<ServiceStreamEvent>,
    context: &RequestContext,
) -> (EventSubscriber<ServiceStreamEvent>, StreamReceiveOutcome) {
    loop {
        if context.is_inactive() {
            return (subscriber, StreamReceiveOutcome::RequestInactive);
        }
        let outcome = subscriber.receive_timeout(EVENT_RECEIVE_POLL);
        if let Some(outcome) = classify_receive_outcome(context, outcome) {
            return (subscriber, outcome);
        }
    }
}

fn classify_receive_outcome(
    context: &RequestContext,
    outcome: ReceiveOutcome<ServiceStreamEvent>,
) -> Option<StreamReceiveOutcome> {
    if context.is_inactive() {
        return Some(StreamReceiveOutcome::RequestInactive);
    }
    match outcome {
        ReceiveOutcome::Event(event) => Some(StreamReceiveOutcome::Event(event)),
        ReceiveOutcome::TimedOut => None,
        ReceiveOutcome::Closed => Some(StreamReceiveOutcome::Closed),
        ReceiveOutcome::Cancelled => Some(StreamReceiveOutcome::Cancelled),
    }
}

fn encode_frame<T>(body: &T) -> Result<Bytes, ApiHttpError>
where
    T: Serialize,
{
    let encoded = serde_json::to_vec(body).map_err(|_| internal_error())?;
    let frame_length = DATA_PREFIX
        .len()
        .checked_add(encoded.len())
        .and_then(|length| length.checked_add(FRAME_SUFFIX.len()))
        .ok_or_else(internal_error)?;
    if frame_length > MAX_OPENAI_SSE_FRAME_BYTES {
        return Err(internal_error());
    }
    let mut frame = Vec::with_capacity(frame_length);
    frame.extend_from_slice(DATA_PREFIX);
    frame.extend_from_slice(&encoded);
    frame.extend_from_slice(FRAME_SUFFIX);
    Ok(Bytes::from(frame))
}

fn valid_sequence(previous: Option<u64>, candidate: u64) -> bool {
    candidate > 0 && previous.is_none_or(|sequence| candidate > sequence)
}

fn finish_reason_value(reason: FinishReason) -> Result<&'static str, ApiHttpError> {
    match reason {
        FinishReason::Completed => Ok("stop"),
        FinishReason::OutputLimitReached => Ok("length"),
        FinishReason::ContentFiltered => Ok("content_filter"),
        _ => Err(internal_error()),
    }
}

const fn project_domain_error(error: ApiDomainError) -> ApiHttpError {
    let code = match error.code() {
        ApiDomainErrorCode::Cancelled => ApiHttpErrorCode::Cancelled,
        ApiDomainErrorCode::DeadlineExceeded => ApiHttpErrorCode::DeadlineExceeded,
        ApiDomainErrorCode::Unavailable => ApiHttpErrorCode::Unavailable,
        ApiDomainErrorCode::ResourceExhausted => ApiHttpErrorCode::ResourceExhausted,
        _ => ApiHttpErrorCode::Internal,
    };
    ApiHttpError::new(code)
}

const fn regular_usage_field(include_usage: bool) -> Option<Option<UsageBody>> {
    if include_usage { Some(None) } else { None }
}

fn ready(frame: Bytes) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
    Poll::Ready(Some(Ok(frame)))
}

const fn internal_error() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::Internal)
}

#[derive(Serialize)]
struct ChunkBody<'a> {
    id: &'a str,
    object: &'static str,
    created: u64,
    model: &'a str,
    choices: &'a [ChunkChoice<'a>],
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<Option<UsageBody>>,
}

#[derive(Serialize)]
struct ChunkChoice<'a> {
    index: u8,
    delta: DeltaBody<'a>,
    finish_reason: Option<&'static str>,
}

#[derive(Serialize)]
struct DeltaBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<&'a str>,
}

impl<'a> DeltaBody<'a> {
    const fn assistant() -> Self {
        Self {
            role: Some("assistant"),
            content: Some(""),
        }
    }

    const fn content(content: &'a str) -> Self {
        Self {
            role: None,
            content: Some(content),
        }
    }

    const fn empty() -> Self {
        Self {
            role: None,
            content: None,
        }
    }
}

#[derive(Clone, Copy, Serialize)]
struct UsageBody {
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
}

impl From<TokenUsage> for UsageBody {
    fn from(usage: TokenUsage) -> Self {
        Self {
            prompt_tokens: usage.input_tokens(),
            completion_tokens: usage.output_tokens(),
            total_tokens: usage.total_tokens(),
        }
    }
}

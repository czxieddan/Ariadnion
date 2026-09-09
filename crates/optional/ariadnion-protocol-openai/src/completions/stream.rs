// crates/optional/ariadnion-protocol-openai/src/completions/stream.rs - Legacy Completions data-only SSE projection.
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
//! Poll-driven bounded SSE state machine with cancellation and deadline checks.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, FinishReason, ServiceContractVersion, ServiceStreamEvent,
    TextStreamEvent,
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
    created: u64,
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
    let stream =
        CompletionStream::new(identity, model, include_usage, created, subscriber, context);
    ProtocolStreamResponse::new(StatusCode::OK, headers, Box::pin(stream))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StreamState {
    AwaitingStart,
    Open,
    AfterFinish,
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

struct CompletionStream {
    subscriber: Option<EventSubscriber<ServiceStreamEvent>>,
    receive: Option<ReceiveTask>,
    channel_cancellation: CancellationToken,
    request_context: RequestContext,
    id: Box<str>,
    model: Box<str>,
    include_usage: bool,
    created: u64,
    last_sequence: Option<u64>,
    state: StreamState,
}

impl CompletionStream {
    fn new(
        identity: &HttpRequestIdentity,
        model: &str,
        include_usage: bool,
        created: u64,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Self {
        let channel_cancellation = subscriber.cancellation();
        Self {
            subscriber: Some(subscriber),
            receive: None,
            channel_cancellation,
            request_context: context.clone(),
            id: super::response::completion_id(identity).into(),
            model: model.into(),
            include_usage,
            created,
            last_sequence: None,
            state: StreamState::AwaitingStart,
        }
    }

    fn poll_queued(&mut self) -> Option<Poll<Option<Result<Bytes, ApiHttpError>>>> {
        match self.state {
            StreamState::AfterFinish if self.include_usage => {
                self.state = StreamState::AfterUsage;
                Some(self.emit_frame(self.usage_body()))
            }
            StreamState::AfterFinish | StreamState::AfterUsage => {
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

    fn emit_frame(
        &mut self,
        encoded: Result<Bytes, ApiHttpError>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match encoded {
            Ok(frame) => Poll::Ready(Some(Ok(frame))),
            Err(error) => self.fail(error),
        }
    }

    fn ensure_receive(&mut self) -> Result<(), ApiHttpError> {
        if self.receive.is_some() {
            return Ok(());
        }
        let handle = Handle::try_current().map_err(|_| internal_error())?;
        let subscriber = self.subscriber.take().ok_or_else(internal_error)?;
        let context = self.request_context.clone();
        self.receive =
            Some(handle.spawn_blocking(move || receive_until_ready(subscriber, &context)));
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
        envelope: EventEnvelope<ServiceStreamEvent>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        let sequence = envelope.sequence();
        if !valid_sequence(self.last_sequence, sequence) {
            return self.fail(internal_error());
        }
        self.last_sequence = Some(sequence);
        let ServiceStreamEvent::Text(event) = envelope.into_payload() else {
            return self.fail(internal_error());
        };
        self.handle_text_event(event)
    }

    fn handle_text_event(
        &mut self,
        event: TextStreamEvent,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match (self.state, event) {
            (StreamState::AwaitingStart, TextStreamEvent::Started { version }) => {
                self.handle_started(version)
            }
            (StreamState::Open, TextStreamEvent::Delta(delta)) => {
                self.emit_frame(self.choice_body(delta.as_str(), None, None))
            }
            (StreamState::Open, TextStreamEvent::Completed { finish_reason }) => {
                self.handle_completed(finish_reason)
            }
            (_, TextStreamEvent::Failed(error)) => self.handle_failure(error),
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
        let encoded = self.choice_body("", Some("assistant"), None);
        self.state = StreamState::Open;
        self.emit_frame(encoded)
    }

    fn handle_completed(
        &mut self,
        finish_reason: FinishReason,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        let reason = match super::response::finish_reason(finish_reason) {
            Ok(reason) => reason,
            Err(_) => return self.fail(internal_error()),
        };
        let encoded = self.choice_body("", None, Some(reason));
        self.stop_receiving();
        self.state = StreamState::AfterFinish;
        self.emit_frame(encoded)
    }

    fn handle_failure(
        &mut self,
        error: ApiDomainError,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        if error.code() == ApiDomainErrorCode::Cancelled {
            self.close();
            Poll::Ready(None)
        } else {
            self.fail(project_domain_error(error))
        }
    }

    fn choice_body<'a>(
        &'a self,
        text: &'a str,
        role: Option<&'static str>,
        finish_reason: Option<&'static str>,
    ) -> Result<Bytes, ApiHttpError> {
        let choices = [ChunkChoice {
            text,
            index: 0,
            logprobs: None,
            finish_reason,
            role,
        }];
        let body = CompletionChunk {
            id: &self.id,
            object: "text_completion",
            created: self.created,
            model: &self.model,
            choices: &choices,
            usage: regular_usage_field(self.include_usage),
        };
        encode_frame(&body)
    }

    fn usage_body(&self) -> Result<Bytes, ApiHttpError> {
        let choices: [ChunkChoice<'_>; 0] = [];
        let body = CompletionChunk {
            id: &self.id,
            object: "text_completion",
            created: self.created,
            model: &self.model,
            choices: &choices,
            usage: Some(Some(super::response::UsageBody::zero())),
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

impl Stream for CompletionStream {
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

impl Drop for CompletionStream {
    fn drop(&mut self) {
        self.channel_cancellation.cancel();
    }
}

fn receive_until_ready(
    subscriber: EventSubscriber<ServiceStreamEvent>,
    context: &RequestContext,
) -> (EventSubscriber<ServiceStreamEvent>, StreamReceiveOutcome) {
    loop {
        if let Some(outcome) = receive_once(&subscriber, context) {
            return (subscriber, outcome);
        }
    }
}

fn receive_once(
    subscriber: &EventSubscriber<ServiceStreamEvent>,
    context: &RequestContext,
) -> Option<StreamReceiveOutcome> {
    if context.is_inactive() {
        return Some(StreamReceiveOutcome::RequestInactive);
    }
    match subscriber.receive_timeout(EVENT_RECEIVE_POLL) {
        ReceiveOutcome::Event(event) => Some(StreamReceiveOutcome::Event(event)),
        ReceiveOutcome::TimedOut => None,
        ReceiveOutcome::Closed => Some(StreamReceiveOutcome::Closed),
        ReceiveOutcome::Cancelled => Some(StreamReceiveOutcome::Cancelled),
    }
}

fn valid_sequence(previous: Option<u64>, candidate: u64) -> bool {
    candidate > 0 && previous.is_none_or(|sequence| candidate > sequence)
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

const fn regular_usage_field(include_usage: bool) -> Option<Option<super::response::UsageBody>> {
    if include_usage { Some(None) } else { None }
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

const fn internal_error() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::Internal)
}

fn ready(frame: Bytes) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
    Poll::Ready(Some(Ok(frame)))
}

#[derive(Serialize)]
struct CompletionChunk<'a> {
    id: &'a str,
    object: &'static str,
    created: u64,
    model: &'a str,
    choices: &'a [ChunkChoice<'a>],
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<Option<super::response::UsageBody>>,
}

#[derive(Serialize)]
struct ChunkChoice<'a> {
    text: &'a str,
    index: u8,
    logprobs: Option<()>,
    finish_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
}

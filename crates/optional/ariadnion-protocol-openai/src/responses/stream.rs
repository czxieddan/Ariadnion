// crates/optional/ariadnion-protocol-openai/src/responses/stream.rs - Typed Responses SSE projection.
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
//! Poll-driven typed SSE projection that preserves text-stream backpressure.

use std::collections::VecDeque;
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
const MAX_FRAME_BYTES: usize = 256 * 1024;

type ReceiveTask = JoinHandle<(EventSubscriber<ServiceStreamEvent>, ReceiveResult)>;

pub(crate) fn project_stream(
    identity: &HttpRequestIdentity,
    model: &str,
    created_at: u64,
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
    let stream = if created_at == 0 {
        ResponseStream::new(identity, model, subscriber, context)
    } else {
        ResponseStream::new_with_created(identity, model, created_at, subscriber, context)
    };
    ProtocolStreamResponse::new(StatusCode::OK, headers, Box::pin(stream))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StreamState {
    AwaitingStart,
    Open,
    Terminal,
    Closed,
}
#[derive(Clone, Copy)]
enum QueuedEvent {
    Response(ResponseEvent),
    Item(ItemEvent),
    Part(PartEvent),
}
#[derive(Clone, Copy)]
enum ResponseEvent {
    Created,
    InProgress,
    Completed,
    Incomplete,
}
#[derive(Clone, Copy)]
enum ItemEvent {
    Added,
    Done,
}
#[derive(Clone, Copy)]
enum PartEvent {
    Added,
    TextDone,
    Done,
}
enum ReceiveResult {
    Event(EventEnvelope<ServiceStreamEvent>),
    Closed,
    Cancelled,
    Inactive,
}

pub(crate) struct ResponseStream {
    subscriber: Option<EventSubscriber<ServiceStreamEvent>>,
    receive: Option<ReceiveTask>,
    cancellation: CancellationToken,
    context: RequestContext,
    response_id: Box<str>,
    item_id: Box<str>,
    model: Box<str>,
    created_at: u64,
    next_sequence: u64,
    input_sequence: Option<u64>,
    queued: VecDeque<QueuedEvent>,
    state: StreamState,
}

impl ResponseStream {
    pub(crate) fn new(
        identity: &HttpRequestIdentity,
        model: &str,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Self {
        Self::new_with_created(identity, model, 0, subscriber, context)
    }

    pub(crate) fn new_with_created(
        identity: &HttpRequestIdentity,
        model: &str,
        created_at: u64,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Self {
        let cancellation = subscriber.cancellation();
        let request_id = identity.request_id().as_str();
        Self {
            subscriber: Some(subscriber),
            receive: None,
            cancellation,
            context: context.clone(),
            response_id: format!("resp-{request_id}").into(),
            item_id: format!("msg-{request_id}").into(),
            model: model.into(),
            created_at,
            next_sequence: 1,
            input_sequence: None,
            queued: VecDeque::new(),
            state: StreamState::AwaitingStart,
        }
    }

    fn poll_queued(&mut self) -> Option<Poll<Option<Result<Bytes, ApiHttpError>>>> {
        let event = self.queued.pop_front()?;
        let frame = self.encode_queued(event);
        if self.queued.is_empty() && self.state == StreamState::Terminal {
            self.close();
        }
        Some(match frame {
            Ok(frame) => Poll::Ready(Some(Ok(frame))),
            Err(error) => self.fail(error),
        })
    }

    fn ensure_receive(&mut self) -> Result<(), ApiHttpError> {
        if self.receive.is_some() {
            return Ok(());
        }
        let handle = Handle::try_current().map_err(|_| internal_error())?;
        let subscriber = self.subscriber.take().ok_or_else(internal_error)?;
        let context = self.context.clone();
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
            Poll::Ready(Ok((subscriber, result))) => {
                self.subscriber = Some(subscriber);
                self.handle_receive(result)
            }
            Poll::Ready(Err(_)) => self.fail(internal_error()),
        }
    }

    fn handle_receive(
        &mut self,
        result: ReceiveResult,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match result {
            ReceiveResult::Event(event) => self.handle_event(event),
            ReceiveResult::Cancelled | ReceiveResult::Inactive => {
                self.close();
                Poll::Ready(None)
            }
            ReceiveResult::Closed => self.fail(internal_error()),
        }
    }

    fn handle_event(
        &mut self,
        envelope: EventEnvelope<ServiceStreamEvent>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        if !valid_input_sequence(self.input_sequence, envelope.sequence()) {
            return self.fail(internal_error());
        }
        self.input_sequence = Some(envelope.sequence());
        let ServiceStreamEvent::Text(event) = envelope.into_payload() else {
            return self.fail(internal_error());
        };
        self.handle_text(event)
    }

    fn handle_text(&mut self, event: TextStreamEvent) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match (self.state, event) {
            (StreamState::AwaitingStart, TextStreamEvent::Started { version }) => {
                self.handle_start(version)
            }
            (StreamState::Open, TextStreamEvent::Delta(delta)) => self.emit_delta(delta.as_str()),
            (StreamState::Open, TextStreamEvent::Completed { finish_reason }) => {
                self.handle_complete(finish_reason)
            }
            (_, TextStreamEvent::Failed(error)) => self.handle_failure(error),
            _ => self.fail(internal_error()),
        }
    }

    fn handle_start(
        &mut self,
        version: ServiceContractVersion,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        if version != ServiceContractVersion::V1 {
            return self.fail(internal_error());
        }
        self.queued.extend([
            QueuedEvent::Response(ResponseEvent::Created),
            QueuedEvent::Response(ResponseEvent::InProgress),
            QueuedEvent::Item(ItemEvent::Added),
            QueuedEvent::Part(PartEvent::Added),
        ]);
        self.state = StreamState::Open;
        self.poll_queued().unwrap_or(Poll::Pending)
    }

    fn handle_complete(
        &mut self,
        finish_reason: FinishReason,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        self.queued.extend([
            QueuedEvent::Part(PartEvent::TextDone),
            QueuedEvent::Part(PartEvent::Done),
            QueuedEvent::Item(ItemEvent::Done),
        ]);
        match finish_reason {
            FinishReason::Completed => self
                .queued
                .push_back(QueuedEvent::Response(ResponseEvent::Completed)),
            FinishReason::OutputLimitReached => self
                .queued
                .push_back(QueuedEvent::Response(ResponseEvent::Incomplete)),
            FinishReason::ContentFiltered | _ => return self.fail(internal_error()),
        }
        self.stop_receiving();
        self.state = StreamState::Terminal;
        self.poll_queued().unwrap_or(Poll::Pending)
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

    fn emit_delta(&mut self, delta: &str) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match self.encode_delta(delta) {
            Ok(frame) => Poll::Ready(Some(Ok(frame))),
            Err(error) => self.fail(error),
        }
    }

    fn encode_queued(&mut self, event: QueuedEvent) -> Result<Bytes, ApiHttpError> {
        match event {
            QueuedEvent::Response(event) => self.encode_response_event(event),
            QueuedEvent::Item(event) => self.encode_item_event(event),
            QueuedEvent::Part(event) => self.encode_part_event(event),
        }
    }

    fn encode_response_event(&mut self, event: ResponseEvent) -> Result<Bytes, ApiHttpError> {
        let (event_type, status) = match event {
            ResponseEvent::Created => ("response.created", "in_progress"),
            ResponseEvent::InProgress => ("response.in_progress", "in_progress"),
            ResponseEvent::Completed => ("response.completed", "completed"),
            ResponseEvent::Incomplete => ("response.incomplete", "incomplete"),
        };
        let body = EventBody::response(
            event_type,
            self.take_sequence()?,
            &self.response_id,
            &self.model,
            status,
            self.created_at,
        );
        encode_frame(event_type, &body)
    }

    fn encode_item_event(&mut self, event: ItemEvent) -> Result<Bytes, ApiHttpError> {
        let event_type = match event {
            ItemEvent::Added => "response.output_item.added",
            ItemEvent::Done => "response.output_item.done",
        };
        let body = EventBody::item(
            event_type,
            self.take_sequence()?,
            &self.response_id,
            &self.item_id,
        );
        encode_frame(event_type, &body)
    }

    fn encode_part_event(&mut self, event: PartEvent) -> Result<Bytes, ApiHttpError> {
        let event_type = match event {
            PartEvent::Added => "response.content_part.added",
            PartEvent::TextDone => "response.output_text.done",
            PartEvent::Done => "response.content_part.done",
        };
        let body = match event {
            PartEvent::Added => EventBody::part(
                event_type,
                self.take_sequence()?,
                &self.response_id,
                &self.item_id,
            ),
            PartEvent::TextDone | PartEvent::Done => EventBody::position(
                event_type,
                self.take_sequence()?,
                &self.response_id,
                &self.item_id,
            ),
        };
        encode_frame(event_type, &body)
    }

    fn encode_delta(&mut self, delta: &str) -> Result<Bytes, ApiHttpError> {
        let body = DeltaBody {
            event_type: "response.output_text.delta",
            sequence_number: self.take_sequence()?,
            response_id: &self.response_id,
            item_id: &self.item_id,
            output_index: 0,
            content_index: 0,
            delta,
        };
        encode_frame(body.event_type, &body)
    }

    fn take_sequence(&mut self) -> Result<u64, ApiHttpError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(internal_error)?;
        Ok(sequence)
    }

    fn fail(&mut self, error: ApiHttpError) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        self.close();
        Poll::Ready(Some(Err(error)))
    }
    fn stop_receiving(&mut self) {
        self.subscriber.take();
        self.receive.take();
    }
    fn close(&mut self) {
        self.stop_receiving();
        self.cancellation.cancel();
        self.state = StreamState::Closed;
    }

    fn poll_active(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        if self.state == StreamState::Closed {
            return Poll::Ready(None);
        }
        if let Err(error) = self.ensure_receive() {
            return self.fail(error);
        }
        self.poll_receive(context)
    }
}

impl Stream for ResponseStream {
    type Item = Result<Bytes, ApiHttpError>;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.as_mut().get_mut();
        if stream.context.is_inactive() {
            stream.close();
            return Poll::Ready(None);
        }
        if let Some(queued) = stream.poll_queued() {
            return queued;
        }
        stream.poll_active(context)
    }
}

impl Drop for ResponseStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn receive_until_ready(
    subscriber: EventSubscriber<ServiceStreamEvent>,
    context: &RequestContext,
) -> (EventSubscriber<ServiceStreamEvent>, ReceiveResult) {
    loop {
        if let Some(result) = inactive_receive_result(context) {
            return (subscriber, result);
        }
        let outcome = subscriber.receive_timeout(EVENT_RECEIVE_POLL);
        if let Some(result) = completed_receive_result(outcome) {
            return (subscriber, result);
        }
    }
}

fn inactive_receive_result(context: &RequestContext) -> Option<ReceiveResult> {
    if context.is_inactive() {
        Some(ReceiveResult::Inactive)
    } else {
        None
    }
}

fn completed_receive_result(outcome: ReceiveOutcome<ServiceStreamEvent>) -> Option<ReceiveResult> {
    match outcome {
        ReceiveOutcome::Event(event) => Some(ReceiveResult::Event(event)),
        ReceiveOutcome::TimedOut => None,
        ReceiveOutcome::Closed => Some(ReceiveResult::Closed),
        ReceiveOutcome::Cancelled => Some(ReceiveResult::Cancelled),
    }
}

fn valid_input_sequence(previous: Option<u64>, candidate: u64) -> bool {
    candidate > 0 && previous.is_none_or(|prior| candidate > prior)
}
fn encode_frame<T: Serialize>(event_type: &str, body: &T) -> Result<Bytes, ApiHttpError> {
    let encoded = serde_json::to_vec(body).map_err(|_| internal_error())?;
    let prefix = format!("event: {event_type}\ndata: ");
    let length = prefix
        .len()
        .checked_add(encoded.len())
        .and_then(|value| value.checked_add(2))
        .ok_or_else(internal_error)?;
    if length > MAX_FRAME_BYTES {
        return Err(internal_error());
    }
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(prefix.as_bytes());
    frame.extend_from_slice(&encoded);
    frame.extend_from_slice(b"\n\n");
    Ok(Bytes::from(frame))
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

#[derive(Serialize)]
struct EventBody<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    sequence_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<ResponseRef<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    item: Option<ItemRef<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    part: Option<PartRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_index: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_index: Option<u8>,
}
impl<'a> EventBody<'a> {
    fn response(
        event_type: &'static str,
        sequence_number: u64,
        id: &'a str,
        model: &'a str,
        status: &'static str,
        created_at: u64,
    ) -> Self {
        Self {
            event_type,
            sequence_number,
            response: Some(ResponseRef {
                id,
                object: "response",
                model,
                status,
                created_at,
            }),
            item: None,
            part: None,
            response_id: None,
            item_id: None,
            output_index: None,
            content_index: None,
        }
    }
    fn item(
        event_type: &'static str,
        sequence_number: u64,
        response_id: &'a str,
        item_id: &'a str,
    ) -> Self {
        Self {
            event_type,
            sequence_number,
            response: None,
            item: Some(ItemRef {
                id: item_id,
                item_type: "message",
                role: "assistant",
                status: "in_progress",
            }),
            part: None,
            response_id: Some(response_id),
            item_id: None,
            output_index: Some(0),
            content_index: None,
        }
    }
    fn part(
        event_type: &'static str,
        sequence_number: u64,
        response_id: &'a str,
        item_id: &'a str,
    ) -> Self {
        Self {
            event_type,
            sequence_number,
            response: None,
            item: None,
            part: Some(PartRef {
                part_type: "output_text",
                text: "",
                annotations: [],
            }),
            response_id: Some(response_id),
            item_id: Some(item_id),
            output_index: Some(0),
            content_index: Some(0),
        }
    }
    fn position(
        event_type: &'static str,
        sequence_number: u64,
        response_id: &'a str,
        item_id: &'a str,
    ) -> Self {
        Self {
            event_type,
            sequence_number,
            response: None,
            item: None,
            part: None,
            response_id: Some(response_id),
            item_id: Some(item_id),
            output_index: Some(0),
            content_index: Some(0),
        }
    }
}
#[derive(Serialize)]
struct ResponseRef<'a> {
    id: &'a str,
    object: &'static str,
    model: &'a str,
    status: &'static str,
    created_at: u64,
}
#[derive(Serialize)]
struct ItemRef<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    item_type: &'static str,
    role: &'static str,
    status: &'static str,
}
#[derive(Serialize)]
struct PartRef {
    #[serde(rename = "type")]
    part_type: &'static str,
    text: &'static str,
    annotations: [(); 0],
}
#[derive(Serialize)]
struct DeltaBody<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    sequence_number: u64,
    response_id: &'a str,
    item_id: &'a str,
    output_index: u8,
    content_index: u8,
    delta: &'a str,
}

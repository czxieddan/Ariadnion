// crates/optional/ariadnion-api-stream/src/bridge.rs - Poll-driven SSE bridge for Ariadnion.
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

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ariadnion_api_domain::{ServiceStreamEvent, TextStreamEvent};
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, BoxHttpBodyStream, ServiceStreamBridgePort,
};
use ariadnion_core::{
    CancellationToken, EventEnvelope, EventSubscriber, ReceiveOutcome, RequestContext,
};
use bytes::Bytes;
use futures_core::Stream;
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::encode;
use crate::error::{ApiStreamError, ApiStreamErrorCode};

mod receive;

/// Default maximum number of concurrently active SSE bridges.
pub const DEFAULT_MAX_ACTIVE_STREAMS: usize = 64;
/// Default interval between SSE heartbeat comments while no event is available.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

const MIN_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(100);
const MAX_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const MAX_ACTIVE_STREAMS: usize = 64;

type ReceiveTask = JoinHandle<(
    EventSubscriber<ServiceStreamEvent>,
    ReceiveOutcome<ServiceStreamEvent>,
    OwnedSemaphorePermit,
)>;

/// Validated resource and liveness bounds for an [`SseBridge`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SseBridgeConfig {
    max_active_streams: usize,
    heartbeat_interval: Duration,
}

impl SseBridgeConfig {
    /// Validates bounded active-stream and heartbeat settings.
    ///
    /// # Errors
    ///
    /// Returns [`ApiStreamErrorCode::InvalidConfiguration`] when active streams
    /// are outside 1 through 64 or the heartbeat is outside 100 ms through 60 s.
    pub fn new(
        max_active_streams: usize,
        heartbeat_interval: Duration,
    ) -> Result<Self, ApiStreamError> {
        validate_config(max_active_streams, heartbeat_interval)?;
        Ok(Self {
            max_active_streams,
            heartbeat_interval,
        })
    }

    /// Returns the validated concurrent stream limit.
    #[must_use]
    pub const fn max_active_streams(&self) -> usize {
        self.max_active_streams
    }

    /// Returns the validated heartbeat interval.
    #[must_use]
    pub const fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }
}

impl Default for SseBridgeConfig {
    fn default() -> Self {
        Self {
            max_active_streams: DEFAULT_MAX_ACTIVE_STREAMS,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
        }
    }
}

/// A cloneable bounded adapter from core event subscribers to SSE body streams.
#[derive(Clone)]
pub struct SseBridge {
    permits: Arc<Semaphore>,
    heartbeat_interval: Duration,
}

impl SseBridge {
    /// Creates a bridge whose clones share one active-stream budget.
    #[must_use]
    pub fn new(config: SseBridgeConfig) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(config.max_active_streams())),
            heartbeat_interval: config.heartbeat_interval(),
        }
    }
}

impl Default for SseBridge {
    fn default() -> Self {
        Self::new(SseBridgeConfig::default())
    }
}

impl ServiceStreamBridgePort for SseBridge {
    fn bridge(
        &self,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        _context: &RequestContext,
    ) -> Result<BoxHttpBodyStream, ApiHttpError> {
        let permit = acquire_permit(&self.permits)?;
        Ok(Box::pin(SseByteStream::new(
            subscriber,
            permit,
            self.heartbeat_interval,
        )))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StreamState {
    AwaitingStart,
    Open,
    Terminal,
    Done,
}

struct SseByteStream {
    subscriber: Option<EventSubscriber<ServiceStreamEvent>>,
    receive: Option<ReceiveTask>,
    permit: Option<OwnedSemaphorePermit>,
    cancellation: CancellationToken,
    heartbeat_interval: Duration,
    last_sequence: Option<u64>,
    state: StreamState,
}

impl SseByteStream {
    fn new(
        subscriber: EventSubscriber<ServiceStreamEvent>,
        permit: OwnedSemaphorePermit,
        heartbeat_interval: Duration,
    ) -> Self {
        let cancellation = subscriber.cancellation();
        Self {
            subscriber: Some(subscriber),
            receive: None,
            permit: Some(permit),
            cancellation,
            heartbeat_interval,
            last_sequence: None,
            state: StreamState::AwaitingStart,
        }
    }

    fn terminal_poll(&mut self) -> Option<Poll<Option<Result<Bytes, ApiHttpError>>>> {
        match self.state {
            StreamState::Terminal => {
                self.close();
                Some(Poll::Ready(None))
            }
            StreamState::Done => Some(Poll::Ready(None)),
            StreamState::AwaitingStart | StreamState::Open => None,
        }
    }

    fn ensure_receive(&mut self) -> Result<(), ApiStreamError> {
        if self.receive.is_some() {
            return Ok(());
        }
        let handle = Handle::try_current().map_err(|_| internal_failure())?;
        let (subscriber, permit) = self.take_receive_resources()?;
        let timeout = self.heartbeat_interval;
        self.receive = Some(handle.spawn_blocking(move || {
            let outcome = subscriber.receive_timeout(timeout);
            (subscriber, outcome, permit)
        }));
        Ok(())
    }

    fn take_receive_resources(
        &mut self,
    ) -> Result<(EventSubscriber<ServiceStreamEvent>, OwnedSemaphorePermit), ApiStreamError> {
        let subscriber = self.subscriber.take();
        let permit = self.permit.take();
        match (subscriber, permit) {
            (Some(subscriber), Some(permit)) => Ok((subscriber, permit)),
            (subscriber, permit) => {
                self.subscriber = subscriber;
                self.permit = permit;
                Err(internal_failure())
            }
        }
    }

    fn handle_outcome(
        &mut self,
        outcome: ReceiveOutcome<ServiceStreamEvent>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        match outcome {
            ReceiveOutcome::Event(event) => ready(self.handle_event(event)),
            ReceiveOutcome::TimedOut => ready(encode::heartbeat()),
            ReceiveOutcome::Closed => self.stream_error(None, ApiStreamErrorCode::Incomplete),
            ReceiveOutcome::Cancelled => {
                self.close();
                Poll::Ready(None)
            }
        }
    }

    fn handle_event(&mut self, event: EventEnvelope<ServiceStreamEvent>) -> Bytes {
        let sequence = event.sequence();
        if !valid_sequence(self.last_sequence, sequence) {
            return self.terminal_error(Some(sequence), ApiStreamErrorCode::InvalidSequence);
        }
        self.last_sequence = Some(sequence);
        match self.state {
            StreamState::AwaitingStart => self.handle_awaiting(sequence, event.into_payload()),
            StreamState::Open => self.handle_open(sequence, event.into_payload()),
            StreamState::Terminal | StreamState::Done => {
                self.terminal_error(Some(sequence), ApiStreamErrorCode::InvalidTransition)
            }
        }
    }

    fn handle_awaiting(&mut self, sequence: u64, event: ServiceStreamEvent) -> Bytes {
        match event {
            ServiceStreamEvent::Text(text) => self.handle_awaiting_text(sequence, text),
            _ => self.terminal_error(Some(sequence), ApiStreamErrorCode::Internal),
        }
    }

    fn handle_awaiting_text(&mut self, sequence: u64, event: TextStreamEvent) -> Bytes {
        match event {
            TextStreamEvent::Started { version } => {
                self.open_frame(sequence, encode::started(sequence, version))
            }
            TextStreamEvent::Delta(_)
            | TextStreamEvent::Completed { .. }
            | TextStreamEvent::Failed(_) => {
                self.terminal_error(Some(sequence), ApiStreamErrorCode::InvalidTransition)
            }
            _ => self.terminal_error(Some(sequence), ApiStreamErrorCode::Internal),
        }
    }

    fn handle_open(&mut self, sequence: u64, event: ServiceStreamEvent) -> Bytes {
        match event {
            ServiceStreamEvent::Text(text) => self.handle_open_text(sequence, text),
            _ => self.terminal_error(Some(sequence), ApiStreamErrorCode::Internal),
        }
    }

    fn handle_open_text(&mut self, sequence: u64, event: TextStreamEvent) -> Bytes {
        match event {
            TextStreamEvent::Delta(value) => {
                self.open_frame(sequence, encode::delta(sequence, &value))
            }
            TextStreamEvent::Completed { finish_reason } => {
                self.completed_frame(sequence, finish_reason)
            }
            TextStreamEvent::Failed(error) => self.domain_error(sequence, error),
            TextStreamEvent::Started { .. } => {
                self.terminal_error(Some(sequence), ApiStreamErrorCode::InvalidTransition)
            }
            _ => self.terminal_error(Some(sequence), ApiStreamErrorCode::Internal),
        }
    }

    fn open_frame(&mut self, sequence: u64, encoded: Result<Bytes, ApiStreamError>) -> Bytes {
        match encoded {
            Ok(frame) => {
                self.state = StreamState::Open;
                frame
            }
            Err(_) => self.terminal_error(Some(sequence), ApiStreamErrorCode::Internal),
        }
    }

    fn completed_frame(
        &mut self,
        sequence: u64,
        finish_reason: ariadnion_api_domain::FinishReason,
    ) -> Bytes {
        match encode::completed(sequence, finish_reason) {
            Ok(frame) => self.terminal(frame),
            Err(_) => self.terminal_error(Some(sequence), ApiStreamErrorCode::Internal),
        }
    }

    fn domain_error(
        &mut self,
        sequence: u64,
        error: ariadnion_api_domain::ApiDomainError,
    ) -> Bytes {
        let frame = encode::domain_error(sequence, error);
        self.terminal(frame)
    }

    fn stream_error(
        &mut self,
        sequence: Option<u64>,
        code: ApiStreamErrorCode,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        ready(self.terminal_error(sequence, code))
    }

    fn internal_terminal(
        &mut self,
        sequence: Option<u64>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        self.stream_error(sequence, ApiStreamErrorCode::Internal)
    }

    fn terminal_error(&mut self, sequence: Option<u64>, code: ApiStreamErrorCode) -> Bytes {
        self.terminal(encode::stream_error(sequence, code))
    }

    fn terminal(&mut self, frame: Bytes) -> Bytes {
        self.state = StreamState::Terminal;
        frame
    }

    fn close(&mut self) {
        self.state = StreamState::Done;
        self.cancellation.cancel();
        self.subscriber.take();
        self.permit.take();
    }
}

impl Stream for SseByteStream {
    type Item = Result<Bytes, ApiHttpError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.as_mut().get_mut();
        if let Some(poll) = stream.terminal_poll() {
            return poll;
        }
        if stream.ensure_receive().is_err() {
            return stream.internal_terminal(None);
        }
        stream.poll_receive(context)
    }
}

impl Drop for SseByteStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn acquire_permit(permits: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, ApiHttpError> {
    permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted))
}

fn validate_config(
    max_active_streams: usize,
    heartbeat_interval: Duration,
) -> Result<(), ApiStreamError> {
    if !valid_stream_count(max_active_streams) || !valid_heartbeat_interval(heartbeat_interval) {
        return Err(ApiStreamError::new(
            ApiStreamErrorCode::InvalidConfiguration,
        ));
    }
    Ok(())
}

const fn valid_stream_count(value: usize) -> bool {
    value > 0 && value <= MAX_ACTIVE_STREAMS
}

fn valid_heartbeat_interval(value: Duration) -> bool {
    value >= MIN_HEARTBEAT_INTERVAL && value <= MAX_HEARTBEAT_INTERVAL
}

fn valid_sequence(previous: Option<u64>, candidate: u64) -> bool {
    candidate > 0 && previous.is_none_or(|sequence| candidate > sequence)
}

fn ready(frame: Bytes) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
    Poll::Ready(Some(Ok(frame)))
}

const fn internal_failure() -> ApiStreamError {
    ApiStreamError::new(ApiStreamErrorCode::Internal)
}

// crates/optional/ariadnion-provider-sdk/src/stream.rs - Provider stream contracts for Ariadnion.
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
//! Bounded provider-native response stream lifecycles.

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ariadnion_api_domain::{FinishReason, ServiceContractVersion, TextDelta};
use ariadnion_core::{
    CancellationToken, EventEnvelope, EventPublisher, EventSubscriber, PublishError,
    ReceiveOutcome, bounded_event_channel,
};

use crate::{
    ProviderAttemptEvidence, ProviderContractError, ProviderContractErrorCode, ProviderFailure,
    ProviderLimits,
};

/// A provider-native stream event retained until orchestration projects it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderStreamEvent {
    /// Announces the service contract used by subsequent events.
    Started {
        /// Service contract version used by this stream.
        version: ServiceContractVersion,
    },
    /// Carries one bounded text increment without accumulated output.
    TextDelta(TextDelta),
    /// Reports normal terminal completion.
    Completed {
        /// Reason generation ended.
        finish_reason: FinishReason,
    },
    /// Reports one classified terminal provider failure.
    Failed(ProviderFailure),
}

/// Checked bounds used to create one provider stream channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderStreamConfig {
    capacity: usize,
    limits: ProviderLimits,
}

impl ProviderStreamConfig {
    /// Creates a stream configuration within its event-count bound.
    ///
    /// # Errors
    ///
    /// Returns a redacted provider contract error when the queue is empty or
    /// could retain more events than the complete stream permits.
    pub const fn new(
        capacity: usize,
        limits: ProviderLimits,
    ) -> Result<Self, ProviderContractError> {
        if capacity == 0 {
            return Err(ProviderContractError::new(
                ProviderContractErrorCode::InvalidArgument,
            ));
        }
        if capacity > limits.max_stream_events() {
            return Err(ProviderContractError::new(
                ProviderContractErrorCode::LimitExceeded,
            ));
        }
        Ok(Self { capacity, limits })
    }

    /// Returns the bounded channel capacity.
    #[must_use]
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// Returns the checked per-attempt resource limits.
    #[must_use]
    pub const fn limits(self) -> ProviderLimits {
        self.limits
    }
}

/// A publication failure that retains ownership of the rejected event.
pub enum ProviderStreamPublishError {
    /// The attempt was cancelled before publication.
    Cancelled(EventEnvelope<ProviderStreamEvent>),
    /// The bounded queue has no remaining capacity.
    Full(EventEnvelope<ProviderStreamEvent>),
    /// The single subscriber has been dropped.
    Closed(EventEnvelope<ProviderStreamEvent>),
    /// The producer sequence did not increase.
    OutOfOrder(EventEnvelope<ProviderStreamEvent>),
    /// The event violates the provider stream lifecycle.
    InvalidTransition(EventEnvelope<ProviderStreamEvent>),
    /// The event would exceed a checked stream resource bound.
    ResourceLimit(EventEnvelope<ProviderStreamEvent>),
}

impl ProviderStreamPublishError {
    /// Recovers the event that was not accepted by the stream.
    #[must_use]
    pub fn into_event(self) -> EventEnvelope<ProviderStreamEvent> {
        match self {
            Self::Cancelled(event)
            | Self::Full(event)
            | Self::Closed(event)
            | Self::OutOfOrder(event)
            | Self::InvalidTransition(event)
            | Self::ResourceLimit(event) => event,
        }
    }

    const fn code(&self) -> &'static str {
        match self {
            Self::Cancelled(_) => "provider_stream_cancelled",
            Self::Full(_) => "provider_stream_full",
            Self::Closed(_) => "provider_stream_closed",
            Self::OutOfOrder(_) => "provider_stream_out_of_order",
            Self::InvalidTransition(_) => "provider_stream_invalid_transition",
            Self::ResourceLimit(_) => "provider_stream_resource_limit",
        }
    }
}

impl Debug for ProviderStreamPublishError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderStreamPublishError")
            .field("code", &self.code())
            .finish()
    }
}

impl Display for ProviderStreamPublishError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProviderStreamPublishError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamPhase {
    AwaitingStart,
    Active,
    Terminal,
}

#[derive(Debug)]
struct StreamState {
    phase: StreamPhase,
    published_events: usize,
    published_bytes: usize,
}

impl StreamState {
    const fn new() -> Self {
        Self {
            phase: StreamPhase::AwaitingStart,
            published_events: 0,
            published_bytes: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct AcceptedEvent {
    next_phase: StreamPhase,
    next_events: usize,
    next_bytes: usize,
}

/// The bounded producer side of a provider response stream.
pub struct ProviderStreamPublisher {
    inner: EventPublisher<ProviderStreamEvent>,
    evidence: ProviderAttemptEvidence,
    limits: ProviderLimits,
    state: Arc<Mutex<StreamState>>,
}

impl ProviderStreamPublisher {
    /// Attempts a nonblocking publication while enforcing lifecycle and limits.
    ///
    /// Every error retains the original event. In particular, a full queue
    /// requires the adapter to retry later rather than dropping provider data.
    pub fn try_publish(
        &self,
        event: EventEnvelope<ProviderStreamEvent>,
    ) -> Result<(), ProviderStreamPublishError> {
        if self.inner.cancellation().is_cancelled() {
            return Err(ProviderStreamPublishError::Cancelled(event));
        }
        let mut state = lock_state(&self.state);
        let accepted = validate_event(&state, &event, self.limits)?;
        self.inner.try_publish(event).map_err(map_publish_error)?;
        apply_accepted(&mut state, accepted);
        mark_upstream_started(&self.evidence);
        Ok(())
    }

    /// Returns the attempt cancellation token observed by this publisher.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.inner.cancellation()
    }
}

/// The single-consumer side of a provider response stream.
pub struct ProviderStreamSubscriber {
    inner: EventSubscriber<ProviderStreamEvent>,
    evidence: ProviderAttemptEvidence,
    cancellation: CancellationToken,
}

impl ProviderStreamSubscriber {
    /// Receives at most one event within a bounded wait.
    ///
    /// Cancellation is checked by the core channel before every wait. Receiving
    /// the first event irreversibly records downstream delivery without
    /// concatenating or retaining its payload.
    #[must_use]
    pub fn receive_timeout(&self, timeout: Duration) -> ReceiveOutcome<ProviderStreamEvent> {
        let outcome = self.inner.receive_timeout(timeout);
        if matches!(outcome, ReceiveOutcome::Event(_)) {
            mark_downstream_started(&self.evidence);
        }
        outcome
    }

    /// Returns the attempt cancellation token observed by this subscriber.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

impl Drop for ProviderStreamSubscriber {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// Creates a bounded provider stream without polling or receiving eagerly.
///
/// # Errors
///
/// Returns a redacted provider contract error when the configuration cannot be
/// represented by the core bounded event channel.
pub fn bounded_provider_stream(
    config: ProviderStreamConfig,
    evidence: ProviderAttemptEvidence,
    cancellation: CancellationToken,
) -> Result<(ProviderStreamPublisher, ProviderStreamSubscriber), ProviderContractError> {
    let (publisher, subscriber) = bounded_event_channel(config.capacity(), cancellation.clone())
        .map_err(|_| ProviderContractError::new(ProviderContractErrorCode::InvalidArgument))?;
    let state = Arc::new(Mutex::new(StreamState::new()));
    Ok((
        ProviderStreamPublisher {
            inner: publisher,
            evidence: evidence.clone(),
            limits: config.limits(),
            state,
        },
        ProviderStreamSubscriber {
            inner: subscriber,
            evidence,
            cancellation,
        },
    ))
}

fn validate_event(
    state: &StreamState,
    event: &EventEnvelope<ProviderStreamEvent>,
    limits: ProviderLimits,
) -> Result<AcceptedEvent, ProviderStreamPublishError> {
    if event.sequence() == 0 || !valid_transition(state.phase, event.payload()) {
        return Err(ProviderStreamPublishError::InvalidTransition(event.clone()));
    }
    let next_events = checked_event_count(state, limits)
        .ok_or_else(|| ProviderStreamPublishError::ResourceLimit(event.clone()))?;
    let next_bytes = checked_stream_bytes(state, event.payload(), limits)
        .ok_or_else(|| ProviderStreamPublishError::ResourceLimit(event.clone()))?;
    Ok(AcceptedEvent {
        next_phase: next_phase(event.payload()),
        next_events,
        next_bytes,
    })
}

const fn valid_transition(phase: StreamPhase, event: &ProviderStreamEvent) -> bool {
    matches!(
        (phase, event),
        (
            StreamPhase::AwaitingStart,
            ProviderStreamEvent::Started { .. }
        ) | (
            StreamPhase::Active,
            ProviderStreamEvent::TextDelta(_)
                | ProviderStreamEvent::Completed { .. }
                | ProviderStreamEvent::Failed(_),
        )
    )
}

const fn next_phase(event: &ProviderStreamEvent) -> StreamPhase {
    match event {
        ProviderStreamEvent::Started { .. } | ProviderStreamEvent::TextDelta(_) => {
            StreamPhase::Active
        }
        ProviderStreamEvent::Completed { .. } | ProviderStreamEvent::Failed(_) => {
            StreamPhase::Terminal
        }
    }
}

fn checked_event_count(state: &StreamState, limits: ProviderLimits) -> Option<usize> {
    state
        .published_events
        .checked_add(1)
        .filter(|count| *count <= limits.max_stream_events())
}

fn checked_stream_bytes(
    state: &StreamState,
    event: &ProviderStreamEvent,
    limits: ProviderLimits,
) -> Option<usize> {
    let delta_bytes = event_bytes(event);
    if delta_bytes > limits.max_delta_bytes() {
        return None;
    }
    state
        .published_bytes
        .checked_add(delta_bytes)
        .filter(|bytes| *bytes <= limits.max_stream_bytes())
}

fn event_bytes(event: &ProviderStreamEvent) -> usize {
    match event {
        ProviderStreamEvent::TextDelta(delta) => delta.as_str().len(),
        _ => 0,
    }
}

const fn apply_accepted(state: &mut StreamState, accepted: AcceptedEvent) {
    state.phase = accepted.next_phase;
    state.published_events = accepted.next_events;
    state.published_bytes = accepted.next_bytes;
}

fn map_publish_error(error: PublishError<ProviderStreamEvent>) -> ProviderStreamPublishError {
    match error {
        PublishError::Cancelled(event) => ProviderStreamPublishError::Cancelled(event),
        PublishError::Full(event) => ProviderStreamPublishError::Full(event),
        PublishError::Closed(event) => ProviderStreamPublishError::Closed(event),
        PublishError::OutOfOrder(event) => ProviderStreamPublishError::OutOfOrder(event),
    }
}

fn mark_upstream_started(evidence: &ProviderAttemptEvidence) {
    if !evidence.progress().upstream_response_started() {
        let _transition = evidence.mark_upstream_response_started();
    }
}

fn mark_downstream_started(evidence: &ProviderAttemptEvidence) {
    if !evidence.progress().downstream_delivery_started() {
        let _transition = evidence.mark_downstream_delivery_started();
    }
}

fn lock_state(state: &Mutex<StreamState>) -> MutexGuard<'_, StreamState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

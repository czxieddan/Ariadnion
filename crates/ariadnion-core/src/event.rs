//! Bounded in-process event envelopes with explicit backpressure.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, SystemTime};

use crate::context::CancellationToken;
use crate::error::{CoreError, ErrorCode};
use crate::ids::ModuleVersion;

const MAX_EVENT_CAPACITY: usize = 1_048_576;

/// A versioned event value with a monotonic producer sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnvelope<E> {
    sequence: u64,
    version: ModuleVersion,
    occurred_at: SystemTime,
    payload: E,
}

impl<E> EventEnvelope<E> {
    /// Creates a versioned envelope.
    #[must_use]
    pub fn new(sequence: u64, version: ModuleVersion, payload: E) -> Self {
        Self {
            sequence,
            version,
            occurred_at: SystemTime::now(),
            payload,
        }
    }

    /// Returns the producer sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the event schema version.
    #[must_use]
    pub const fn version(&self) -> ModuleVersion {
        self.version
    }

    /// Returns the UTC event timestamp.
    #[must_use]
    pub const fn occurred_at(&self) -> SystemTime {
        self.occurred_at
    }

    /// Returns the event payload.
    #[must_use]
    pub const fn payload(&self) -> &E {
        &self.payload
    }

    /// Consumes the envelope and returns its payload.
    #[must_use]
    pub fn into_payload(self) -> E {
        self.payload
    }
}

/// A publication failure that returns ownership of the event.
pub enum PublishError<E> {
    /// The publisher cancellation token was already cancelled.
    Cancelled(EventEnvelope<E>),
    /// The bounded queue has no remaining capacity.
    Full(EventEnvelope<E>),
    /// The subscriber has been dropped.
    Closed(EventEnvelope<E>),
}

/// The receive result for a bounded wait.
pub enum ReceiveOutcome<E> {
    /// One event was received.
    Event(EventEnvelope<E>),
    /// The supplied wait duration elapsed.
    TimedOut,
    /// Every publisher has been dropped.
    Closed,
    /// The subscriber cancellation token was cancelled.
    Cancelled,
}

/// A cloneable publisher backed by a bounded synchronous channel.
pub struct EventPublisher<E> {
    sender: SyncSender<EventEnvelope<E>>,
    cancellation: CancellationToken,
}

impl<E> Clone for EventPublisher<E> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            cancellation: self.cancellation.clone(),
        }
    }
}

impl<E> EventPublisher<E> {
    /// Attempts publication without blocking the producer.
    pub fn try_publish(&self, event: EventEnvelope<E>) -> Result<(), PublishError<E>> {
        if self.cancellation.is_cancelled() {
            return Err(PublishError::Cancelled(event));
        }
        match self.sender.try_send(event) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(event)) => Err(PublishError::Full(event)),
            Err(TrySendError::Disconnected(event)) => Err(PublishError::Closed(event)),
        }
    }

    /// Returns a clone of the publisher cancellation token.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

/// The single consumer for a bounded event channel.
pub struct EventSubscriber<E> {
    receiver: Receiver<EventEnvelope<E>>,
    cancellation: CancellationToken,
}

impl<E> EventSubscriber<E> {
    /// Waits for an event while respecting cancellation and a bounded timeout.
    #[must_use]
    pub fn receive_timeout(&self, timeout: Duration) -> ReceiveOutcome<E> {
        if self.cancellation.is_cancelled() {
            return ReceiveOutcome::Cancelled;
        }
        match self.receiver.recv_timeout(timeout) {
            Ok(event) => ReceiveOutcome::Event(event),
            Err(RecvTimeoutError::Timeout) => ReceiveOutcome::TimedOut,
            Err(RecvTimeoutError::Disconnected) => ReceiveOutcome::Closed,
        }
    }

    /// Returns a clone of the subscriber cancellation token.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

/// Creates a bounded publisher/subscriber pair.
///
/// A zero or over-limit capacity returns [`ErrorCode::InvalidArgument`].
pub fn bounded_event_channel<E>(
    capacity: usize,
    cancellation: CancellationToken,
) -> Result<(EventPublisher<E>, EventSubscriber<E>), CoreError> {
    validate_capacity(capacity)?;
    let (sender, receiver) = mpsc::sync_channel(capacity);
    Ok((
        EventPublisher {
            sender,
            cancellation: cancellation.clone(),
        },
        EventSubscriber {
            receiver,
            cancellation,
        },
    ))
}

fn validate_capacity(capacity: usize) -> Result<(), CoreError> {
    if capacity == 0 || capacity > MAX_EVENT_CAPACITY {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("event channel capacity is outside its bound"));
    }
    Ok(())
}

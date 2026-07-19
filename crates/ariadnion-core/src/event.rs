//! Bounded in-process event envelopes with explicit backpressure.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use crate::context::CancellationToken;
use crate::error::{CoreError, ErrorCode};
use crate::ids::ModuleVersion;

const MAX_EVENT_CAPACITY: usize = 1_048_576;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);

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
    /// The event sequence did not increase from the previous publication.
    OutOfOrder(EventEnvelope<E>),
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
    last_sequence: Arc<Mutex<Option<u64>>>,
}

impl<E> Clone for EventPublisher<E> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            cancellation: self.cancellation.clone(),
            last_sequence: self.last_sequence.clone(),
        }
    }
}

impl<E> EventPublisher<E> {
    /// Attempts publication without blocking the producer.
    pub fn try_publish(&self, event: EventEnvelope<E>) -> Result<(), PublishError<E>> {
        if self.cancellation.is_cancelled() {
            return Err(PublishError::Cancelled(event));
        }
        let mut last_sequence = lock_sequence(&self.last_sequence);
        let sequence = event.sequence();
        if !sequence_increases(*last_sequence, sequence) {
            return Err(PublishError::OutOfOrder(event));
        }
        match self.sender.try_send(event) {
            Ok(()) => {
                *last_sequence = Some(sequence);
                Ok(())
            }
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
        let started = Instant::now();
        loop {
            if self.cancellation.is_cancelled() {
                return ReceiveOutcome::Cancelled;
            }
            let Some(wait) = next_receive_wait(started, timeout) else {
                return ReceiveOutcome::TimedOut;
            };
            match self.receiver.recv_timeout(wait) {
                Ok(event) => return ReceiveOutcome::Event(event),
                Err(RecvTimeoutError::Disconnected) => return ReceiveOutcome::Closed,
                Err(RecvTimeoutError::Timeout) => {}
            }
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
    let last_sequence = Arc::new(Mutex::new(None));
    Ok((
        EventPublisher {
            sender,
            cancellation: cancellation.clone(),
            last_sequence,
        },
        EventSubscriber {
            receiver,
            cancellation,
        },
    ))
}

fn sequence_increases(previous: Option<u64>, candidate: u64) -> bool {
    previous.is_none_or(|sequence| candidate > sequence)
}

fn next_receive_wait(started: Instant, timeout: Duration) -> Option<Duration> {
    let remaining = timeout.saturating_sub(started.elapsed());
    (!remaining.is_zero()).then(|| remaining.min(CANCELLATION_POLL_INTERVAL))
}

fn lock_sequence(sequence: &Mutex<Option<u64>>) -> MutexGuard<'_, Option<u64>> {
    match sequence.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn validate_capacity(capacity: usize) -> Result<(), CoreError> {
    if capacity == 0 || capacity > MAX_EVENT_CAPACITY {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("event channel capacity is outside its bound"));
    }
    Ok(())
}

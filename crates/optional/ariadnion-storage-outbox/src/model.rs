use std::fmt::{self, Debug, Display, Formatter};
use std::num::{NonZeroU32, NonZeroUsize};
use std::time::{Duration, SystemTime};

use ariadnion_core::TenantId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_EVENT_ID_BYTES: usize = 128;
const MAX_TOPIC_BYTES: usize = 128;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_WORKER_ID_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_LEASE_TOKEN_BYTES: usize = 256;
const MAX_LEASE_BATCH: usize = 256;
const MIN_LEASE_DURATION: Duration = Duration::from_secs(1);
const MAX_LEASE_DURATION: Duration = Duration::from_secs(15 * 60);

/// A stable tenant-local identity for one outbox event.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutboxEventId(Box<str>);

impl OutboxEventId {
    /// Parses a bounded ASCII event identity.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        validate_identifier(value, MAX_EVENT_ID_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated event identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for OutboxEventId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OutboxEventId")
            .field(&self.0)
            .finish()
    }
}

impl Display for OutboxEventId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A stable routing topic that does not encode a destination address.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutboxTopic(Box<str>);

impl OutboxTopic {
    /// Parses a bounded ASCII topic.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        validate_identifier(value, MAX_TOPIC_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated topic.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded key used to collapse repeated enqueue attempts.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutboxIdempotencyKey(Box<str>);

impl OutboxIdempotencyKey {
    /// Parses a bounded ASCII idempotency key.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        validate_identifier(value, MAX_IDEMPOTENCY_KEY_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated idempotency key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for OutboxIdempotencyKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboxIdempotencyKey")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A stable identity for one bounded dispatcher worker.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutboxWorkerId(Box<str>);

impl OutboxWorkerId {
    /// Parses a bounded ASCII worker identity.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        validate_identifier(value, MAX_WORKER_ID_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated worker identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded payload whose bytes are redacted and cleared on drop.
pub struct OutboxPayload(Box<[u8]>);

impl OutboxPayload {
    /// Copies a non-empty payload of at most 1 MiB.
    pub fn new(value: &[u8]) -> Result<Self, StorageError> {
        if value.is_empty() || value.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Returns payload bytes to a trusted dispatcher adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for OutboxPayload {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboxPayload")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Zeroize for OutboxPayload {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for OutboxPayload {}

impl Drop for OutboxPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Values written atomically with a business transaction.
#[derive(Debug)]
pub struct NewOutboxMessage {
    tenant_id: TenantId,
    event_id: OutboxEventId,
    topic: OutboxTopic,
    idempotency_key: OutboxIdempotencyKey,
    payload: OutboxPayload,
    created_at: SystemTime,
}

impl NewOutboxMessage {
    /// Creates a complete immutable outbox message.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        event_id: OutboxEventId,
        topic: OutboxTopic,
        idempotency_key: OutboxIdempotencyKey,
        payload: OutboxPayload,
        created_at: SystemTime,
    ) -> Self {
        Self {
            tenant_id,
            event_id,
            topic,
            idempotency_key,
            payload,
            created_at,
        }
    }

    /// Returns the tenant that owns the message.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the event identity.
    #[must_use]
    pub const fn event_id(&self) -> &OutboxEventId {
        &self.event_id
    }

    /// Returns the routing topic.
    #[must_use]
    pub const fn topic(&self) -> &OutboxTopic {
        &self.topic
    }

    /// Returns the enqueue idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &OutboxIdempotencyKey {
        &self.idempotency_key
    }

    /// Returns the redacted payload wrapper.
    #[must_use]
    pub const fn payload(&self) -> &OutboxPayload {
        &self.payload
    }

    /// Returns the UTC creation time.
    #[must_use]
    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }
}

/// Result of an idempotent transactional enqueue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueStatus {
    /// A new outbox row was inserted.
    Inserted,
    /// The same tenant and idempotency key already existed.
    AlreadyExists,
}

/// One persisted outbox message returned to a dispatcher.
#[derive(Debug)]
pub struct OutboxMessage {
    tenant_id: TenantId,
    event_id: OutboxEventId,
    topic: OutboxTopic,
    payload: OutboxPayload,
    created_at: SystemTime,
    attempt: NonZeroU32,
}

impl OutboxMessage {
    /// Reconstructs a validated persisted message.
    #[must_use]
    pub const fn from_persisted(
        tenant_id: TenantId,
        event_id: OutboxEventId,
        topic: OutboxTopic,
        payload: OutboxPayload,
        created_at: SystemTime,
        attempt: NonZeroU32,
    ) -> Self {
        Self {
            tenant_id,
            event_id,
            topic,
            payload,
            created_at,
            attempt,
        }
    }

    /// Returns the tenant that owns the message.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the event identity used for delivery idempotency.
    #[must_use]
    pub const fn event_id(&self) -> &OutboxEventId {
        &self.event_id
    }

    /// Returns the routing topic.
    #[must_use]
    pub const fn topic(&self) -> &OutboxTopic {
        &self.topic
    }

    /// Returns the redacted payload wrapper.
    #[must_use]
    pub const fn payload(&self) -> &OutboxPayload {
        &self.payload
    }

    /// Returns the original UTC enqueue time.
    #[must_use]
    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Returns the one-based delivery attempt number.
    #[must_use]
    pub const fn attempt(&self) -> NonZeroU32 {
        self.attempt
    }
}

/// An opaque lease capability cleared on drop.
pub struct OutboxLeaseToken(Box<[u8]>);

impl OutboxLeaseToken {
    /// Copies a non-empty adapter-generated token of at most 256 bytes.
    pub fn new(value: &[u8]) -> Result<Self, StorageError> {
        if value.is_empty() || value.len() > MAX_LEASE_TOKEN_BYTES {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Returns token bytes to the storage adapter that issued the lease.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for OutboxLeaseToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OutboxLeaseToken(<redacted>)")
    }
}

impl Zeroize for OutboxLeaseToken {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for OutboxLeaseToken {}

impl Drop for OutboxLeaseToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A claimed message and the capability required to settle it.
#[derive(Debug)]
pub struct OutboxLease {
    message: OutboxMessage,
    token: OutboxLeaseToken,
    worker_id: OutboxWorkerId,
    expires_at: SystemTime,
}

impl OutboxLease {
    /// Creates a lease returned by a storage adapter.
    #[must_use]
    pub const fn new(
        message: OutboxMessage,
        token: OutboxLeaseToken,
        worker_id: OutboxWorkerId,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            message,
            token,
            worker_id,
            expires_at,
        }
    }

    /// Returns the claimed message.
    #[must_use]
    pub const fn message(&self) -> &OutboxMessage {
        &self.message
    }

    /// Returns the opaque settlement capability.
    #[must_use]
    pub const fn token(&self) -> &OutboxLeaseToken {
        &self.token
    }

    /// Returns the worker that owns the lease.
    #[must_use]
    pub const fn worker_id(&self) -> &OutboxWorkerId {
        &self.worker_id
    }

    /// Returns the exclusive lease expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

/// A bounded request to claim currently available outbox messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxLeaseRequest {
    worker_id: OutboxWorkerId,
    limit: NonZeroUsize,
    duration: Duration,
}

impl OutboxLeaseRequest {
    /// Validates a claim batch and lease duration.
    pub fn new(
        worker_id: OutboxWorkerId,
        limit: usize,
        duration: Duration,
    ) -> Result<Self, StorageError> {
        let limit = NonZeroUsize::new(limit).ok_or_else(invalid_argument)?;
        if limit.get() > MAX_LEASE_BATCH {
            return Err(resource_exhausted());
        }
        if !(MIN_LEASE_DURATION..=MAX_LEASE_DURATION).contains(&duration) {
            return Err(invalid_argument());
        }
        Ok(Self {
            worker_id,
            limit,
            duration,
        })
    }

    /// Returns the worker that will own claimed leases.
    #[must_use]
    pub const fn worker_id(&self) -> &OutboxWorkerId {
        &self.worker_id
    }

    /// Returns the maximum number of messages to claim.
    #[must_use]
    pub const fn limit(&self) -> NonZeroUsize {
        self.limit
    }

    /// Returns the requested lease lifetime.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.duration
    }

    /// Computes the exclusive expiry and rejects clock overflow.
    pub fn expires_at(&self, now: SystemTime) -> Result<SystemTime, StorageError> {
        now.checked_add(self.duration)
            .ok_or_else(resource_exhausted)
    }
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > maximum || !value.is_ascii() {
        return Err(invalid_argument());
    }
    if value.bytes().any(invalid_identifier_byte) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn invalid_identifier_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_' | b':')
}

const fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

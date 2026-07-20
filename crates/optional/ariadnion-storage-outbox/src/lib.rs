//! Database-independent transactional outbox contracts.
//!
//! Business services enqueue bounded messages inside their existing storage
//! transaction. Dispatch workers claim short leases only after commit and use
//! event identities as idempotency keys at external effect boundaries.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod port;

pub use model::{
    EnqueueStatus, NewOutboxMessage, OutboxEventId, OutboxIdempotencyKey, OutboxLease,
    OutboxLeaseRequest, OutboxLeaseToken, OutboxMessage, OutboxPayload, OutboxTopic,
    OutboxWorkerId,
};
pub use port::OutboxPort;

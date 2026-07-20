use std::time::SystemTime;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, TransactionPort};

use crate::{EnqueueStatus, NewOutboxMessage, OutboxLease, OutboxLeaseRequest, OutboxLeaseToken};

/// Persists and leases outbox messages through explicit transactions.
pub trait OutboxPort: Send + Sync {
    /// Enqueues a message in the caller's existing business transaction.
    ///
    /// Implementations must verify that the request tenant equals the message
    /// tenant and use `(tenant_id, idempotency_key)` as the idempotent boundary.
    fn enqueue(
        &self,
        transaction: &mut dyn TransactionPort,
        message: NewOutboxMessage,
        context: &RequestContext,
    ) -> Result<EnqueueStatus, StorageError>;

    /// Claims a bounded deterministic batch in one short transaction.
    ///
    /// Only pending messages whose availability time has arrived and expired
    /// leases may be claimed. Returned lease tokens must be unguessable and
    /// scoped to the exact worker, event, attempt, and expiry.
    fn claim(
        &self,
        transaction: &mut dyn TransactionPort,
        request: &OutboxLeaseRequest,
        now: SystemTime,
        context: &RequestContext,
    ) -> Result<Vec<OutboxLease>, StorageError>;

    /// Marks one currently owned lease delivered exactly once.
    fn mark_delivered(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        delivered_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Releases a transient failure for a bounded future retry time.
    fn release_for_retry(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        available_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Moves one currently owned lease to a permanent dead-letter state.
    fn dead_letter(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        failed_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError>;
}

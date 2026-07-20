//! Transaction contracts backed by the serialized RNMDB local session.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{
    CommitReceipt, StorageError, StorageErrorCode, StorageInstanceId, TransactionId,
    TransactionIsolation, TransactionManagerPort, TransactionOptions, TransactionPort,
};

use crate::RnmdbSessionOwner;

/// Begins non-nested transactions on one serialized embedded session.
pub struct RnmdbTransactionManager {
    session: Arc<RnmdbSessionOwner>,
    next_id: AtomicU64,
}

impl RnmdbTransactionManager {
    /// Creates a manager whose first process-local transaction ID is one.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self {
            session,
            next_id: AtomicU64::new(1),
        }
    }

    /// Returns the embedded session owner.
    #[must_use]
    pub fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }

    fn allocate_id(&self) -> Result<TransactionId, StorageError> {
        let current = self
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| StorageError::new(StorageErrorCode::ResourceExhausted))?;
        TransactionId::new(current)
    }
}

impl TransactionManagerPort for RnmdbTransactionManager {
    fn begin(
        &self,
        instance: &StorageInstanceId,
        options: TransactionOptions,
        context: &RequestContext,
    ) -> Result<Box<dyn TransactionPort>, StorageError> {
        if instance != self.session.instance() {
            return Err(StorageError::new(StorageErrorCode::NotFound));
        }
        if options.isolation() != TransactionIsolation::ReadCommitted {
            return Err(StorageError::new(StorageErrorCode::Unavailable));
        }
        let id = self.allocate_id()?;
        self.session.begin_transaction(context)?;
        Ok(Box::new(RnmdbTransaction {
            session: self.session.clone(),
            id,
            options,
            completed: false,
        }))
    }
}

struct RnmdbTransaction {
    session: Arc<RnmdbSessionOwner>,
    id: TransactionId,
    options: TransactionOptions,
    completed: bool,
}

impl TransactionPort for RnmdbTransaction {
    fn id(&self) -> TransactionId {
        self.id
    }

    fn instance(&self) -> &StorageInstanceId {
        self.session.instance()
    }

    fn options(&self) -> TransactionOptions {
        self.options
    }

    fn commit(
        mut self: Box<Self>,
        context: &RequestContext,
    ) -> Result<CommitReceipt, StorageError> {
        self.session.commit_transaction(context)?;
        self.completed = true;
        Ok(CommitReceipt::new(self.id, SystemTime::now()))
    }

    fn rollback(mut self: Box<Self>, context: &RequestContext) -> Result<(), StorageError> {
        self.session.rollback_transaction(context)?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for RnmdbTransaction {
    fn drop(&mut self) {
        if !self.completed {
            self.session.rollback_active_transaction();
        }
    }
}

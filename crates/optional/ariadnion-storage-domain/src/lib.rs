//! Database-independent storage, transaction, and repository contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::SystemTime;

use ariadnion_core::RequestContext;

const MAX_INSTANCE_ID_BYTES: usize = 128;
const MAX_RECORD_KEY_BYTES: usize = 256;
const MAX_CURSOR_BYTES: usize = 512;
const MAX_PAGE_SIZE: usize = 1_000;

/// Stable machine-readable storage failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StorageErrorCode {
    /// Caller input is outside a documented bound.
    InvalidArgument,
    /// A requested record or storage instance does not exist.
    NotFound,
    /// A uniqueness or optimistic-version condition failed.
    Conflict,
    /// The operation exceeded its request deadline.
    DeadlineExceeded,
    /// Cancellation was observed before the operation committed.
    Cancelled,
    /// A configured resource or storage limit was reached.
    ResourceExhausted,
    /// Storage is temporarily unavailable without exposing internals.
    Unavailable,
    /// Authentication or integrity verification failed closed.
    IntegrityFailure,
    /// The requested schema transition is not supported.
    MigrationRequired,
    /// An internal adapter failure was safely projected.
    Internal,
}

impl StorageErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "STORAGE_INVALID_ARGUMENT",
            Self::NotFound => "STORAGE_NOT_FOUND",
            Self::Conflict => "STORAGE_CONFLICT",
            Self::DeadlineExceeded => "STORAGE_DEADLINE_EXCEEDED",
            Self::Cancelled => "STORAGE_CANCELLED",
            Self::ResourceExhausted => "STORAGE_RESOURCE_EXHAUSTED",
            Self::Unavailable => "STORAGE_UNAVAILABLE",
            Self::IntegrityFailure => "STORAGE_INTEGRITY_FAILURE",
            Self::MigrationRequired => "STORAGE_MIGRATION_REQUIRED",
            Self::Internal => "STORAGE_INTERNAL",
        }
    }
}

/// A redacted storage error safe to cross adapter boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageError {
    code: StorageErrorCode,
}

impl StorageError {
    /// Creates an error from a stable code without retaining sensitive input.
    #[must_use]
    pub const fn new(code: StorageErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> StorageErrorCode {
        self.code
    }
}

impl Display for StorageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for StorageError {}

/// A bounded storage-instance identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageInstanceId(Box<str>);

impl StorageInstanceId {
    /// Parses an ASCII identifier used to select an isolated database file.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_identifier(value, MAX_INSTANCE_ID_BYTES) {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for StorageInstanceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("StorageInstanceId")
            .field(&self.0)
            .finish()
    }
}

impl Display for StorageInstanceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded opaque repository key.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RecordKey(Box<[u8]>);

impl RecordKey {
    /// Copies a non-empty key of at most 256 bytes.
    pub fn new(value: &[u8]) -> Result<Self, StorageError> {
        if value.is_empty() || value.len() > MAX_RECORD_KEY_BYTES {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the opaque key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for RecordKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordKey")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A non-zero transaction identity scoped to one storage instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransactionId(NonZeroU64);

impl TransactionId {
    /// Creates a non-zero transaction identity.
    pub fn new(value: u64) -> Result<Self, StorageError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidArgument))
    }

    /// Returns the numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Transaction isolation exposed by Ariadnion repositories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionIsolation {
    /// Reads use one stable snapshot and writes detect conflicts at commit.
    Snapshot,
    /// Conflicting concurrent executions behave as if serialized.
    Serializable,
}

/// Whether a transaction can mutate persistent state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionAccess {
    /// Only read operations are permitted.
    ReadOnly,
    /// Reads and writes are permitted.
    ReadWrite,
}

/// Immutable options supplied before a transaction starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionOptions {
    isolation: TransactionIsolation,
    access: TransactionAccess,
}

impl TransactionOptions {
    /// Creates explicit isolation and access options.
    #[must_use]
    pub const fn new(isolation: TransactionIsolation, access: TransactionAccess) -> Self {
        Self { isolation, access }
    }

    /// Returns the requested isolation level.
    #[must_use]
    pub const fn isolation(self) -> TransactionIsolation {
        self.isolation
    }

    /// Returns the requested access mode.
    #[must_use]
    pub const fn access(self) -> TransactionAccess {
        self.access
    }
}

/// Evidence returned after a durable commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    transaction_id: TransactionId,
    committed_at: SystemTime,
}

impl CommitReceipt {
    /// Creates a commit receipt after the adapter confirms durability.
    #[must_use]
    pub const fn new(transaction_id: TransactionId, committed_at: SystemTime) -> Self {
        Self {
            transaction_id,
            committed_at,
        }
    }

    /// Returns the committed transaction identity.
    #[must_use]
    pub const fn transaction_id(self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the UTC commit time reported by the adapter.
    #[must_use]
    pub const fn committed_at(self) -> SystemTime {
        self.committed_at
    }
}

/// An active transaction owned by one caller.
pub trait TransactionPort: Send {
    /// Returns the transaction identity.
    fn id(&self) -> TransactionId;

    /// Commits all changes after checking cancellation and deadline state.
    fn commit(
        self: Box<Self>,
        context: &RequestContext,
    ) -> Result<CommitReceipt, StorageError>;

    /// Rolls back all uncommitted changes. Repeated consumption is impossible.
    fn rollback(self: Box<Self>, context: &RequestContext) -> Result<(), StorageError>;
}

/// Begins transactions for one isolated storage instance.
pub trait TransactionManagerPort: Send + Sync {
    /// Opens a transaction without exposing a database implementation type.
    fn begin(
        &self,
        instance: &StorageInstanceId,
        options: TransactionOptions,
        context: &RequestContext,
    ) -> Result<Box<dyn TransactionPort>, StorageError>;
}

/// A validated page-size limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageLimit(NonZeroUsize);

impl PageLimit {
    /// Creates a page limit from 1 through 1000 records.
    pub fn new(value: usize) -> Result<Self, StorageError> {
        let value = NonZeroUsize::new(value)
            .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidArgument))?;
        if value.get() > MAX_PAGE_SIZE {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self(value))
    }

    /// Returns the requested maximum record count.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// An opaque bounded continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCursor(Box<[u8]>);

impl PageCursor {
    /// Copies a non-empty cursor of at most 512 bytes.
    pub fn new(value: &[u8]) -> Result<Self, StorageError> {
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the opaque cursor bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A bounded repository page with an optional continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordPage<R> {
    records: Vec<R>,
    next: Option<PageCursor>,
}

impl<R> RecordPage<R> {
    /// Creates a page and enforces the caller-provided record limit.
    pub fn new(
        records: Vec<R>,
        next: Option<PageCursor>,
        limit: PageLimit,
    ) -> Result<Self, StorageError> {
        if records.len() > limit.get() {
            return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
        }
        Ok(Self { records, next })
    }

    /// Returns records in deterministic repository order.
    #[must_use]
    pub fn records(&self) -> &[R] {
        &self.records
    }

    /// Returns the continuation cursor when more records are available.
    #[must_use]
    pub const fn next(&self) -> Option<&PageCursor> {
        self.next.as_ref()
    }
}

/// Persistence operations for one stable domain record type.
pub trait RepositoryPort<R>: Send + Sync {
    /// Finds one record by its opaque typed boundary key.
    fn find(
        &self,
        transaction: &mut dyn TransactionPort,
        key: &RecordKey,
        context: &RequestContext,
    ) -> Result<Option<R>, StorageError>;

    /// Inserts a record and rejects an existing key as a conflict.
    fn insert(
        &self,
        transaction: &mut dyn TransactionPort,
        key: RecordKey,
        record: R,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Replaces an existing record under adapter-defined version checks.
    fn update(
        &self,
        transaction: &mut dyn TransactionPort,
        key: &RecordKey,
        record: R,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Deletes a record and returns whether it existed.
    fn delete(
        &self,
        transaction: &mut dyn TransactionPort,
        key: &RecordKey,
        context: &RequestContext,
    ) -> Result<bool, StorageError>;

    /// Lists a bounded deterministic page without exposing SQL or row types.
    fn list(
        &self,
        transaction: &mut dyn TransactionPort,
        cursor: Option<&PageCursor>,
        limit: PageLimit,
        context: &RequestContext,
    ) -> Result<RecordPage<R>, StorageError>;
}

fn valid_identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

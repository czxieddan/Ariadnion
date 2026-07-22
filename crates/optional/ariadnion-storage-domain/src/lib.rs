//! Database-independent storage, transaction, and repository contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_core::RequestContext;

const MAX_INSTANCE_ID_BYTES: usize = 128;
const MAX_RECORD_KEY_BYTES: usize = 256;
const MAX_CURSOR_BYTES: usize = 512;
const MAX_PAGE_SIZE: usize = 1_000;
const MAX_MIGRATION_ID_BYTES: usize = 128;
const MAX_MIGRATION_DOMAIN_BYTES: usize = 128;
const MAX_MIGRATIONS: usize = 1_024;

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
    /// Each statement observes data committed before that statement begins.
    ReadCommitted,
    /// All statements observe one transaction snapshot.
    RepeatableRead,
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

/// An opaque capability proving that a transaction belongs to one session.
#[derive(Clone)]
pub struct TransactionScope(Arc<()>);

impl TransactionScope {
    /// Creates a fresh session-local transaction capability.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(()))
    }

    /// Returns whether both capabilities identify the same live session.
    #[must_use]
    pub fn same_scope(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Debug for TransactionScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionScope(<opaque>)")
    }
}

impl Default for TransactionScope {
    fn default() -> Self {
        Self::new()
    }
}

/// An active transaction owned by one caller.
pub trait TransactionPort: Send {
    /// Returns the transaction identity.
    fn id(&self) -> TransactionId;

    /// Returns the storage instance that owns this transaction.
    fn instance(&self) -> &StorageInstanceId;

    /// Returns the opaque session capability that owns this transaction.
    fn scope(&self) -> &TransactionScope;

    /// Returns the immutable isolation and access contract.
    fn options(&self) -> TransactionOptions;

    /// Commits all changes after checking cancellation and deadline state.
    fn commit(self: Box<Self>, context: &RequestContext) -> Result<CommitReceipt, StorageError>;

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

/// A non-zero application schema version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SchemaVersion(NonZeroU64);

impl SchemaVersion {
    /// Creates a non-zero schema version.
    pub fn new(value: u64) -> Result<Self, StorageError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidArgument))
    }

    /// Returns the numeric schema version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A bounded immutable migration identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MigrationId(Box<str>);

impl MigrationId {
    /// Parses a stable ASCII migration identity.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_identifier(value, MAX_MIGRATION_ID_BYTES) {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded domain recorded with every immutable migration.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MigrationDomain(Box<str>);

impl MigrationDomain {
    /// Parses a stable ASCII migration domain.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_identifier(value, MAX_MIGRATION_DOMAIN_BYTES) {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A SHA-256 digest of immutable migration content.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct MigrationChecksum([u8; 32]);

impl MigrationChecksum {
    /// Creates a checksum from exactly 32 digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for MigrationChecksum {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Debug for MigrationChecksum {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MigrationChecksum")
            .field(&self.to_string())
            .finish()
    }
}

/// Immutable metadata for one forward-only schema transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationDescriptor {
    id: MigrationId,
    domain: MigrationDomain,
    from: SchemaVersion,
    to: SchemaVersion,
    checksum: MigrationChecksum,
    requires_backup: bool,
}

impl MigrationDescriptor {
    /// Creates a strictly increasing migration transition.
    pub fn new(
        id: MigrationId,
        domain: MigrationDomain,
        from: SchemaVersion,
        to: SchemaVersion,
        checksum: MigrationChecksum,
        requires_backup: bool,
    ) -> Result<Self, StorageError> {
        if from >= to {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self {
            id,
            domain,
            from,
            to,
            checksum,
            requires_backup,
        })
    }

    /// Returns the migration identity.
    #[must_use]
    pub const fn id(&self) -> &MigrationId {
        &self.id
    }

    /// Returns the migration domain recorded in the durable ledger.
    #[must_use]
    pub const fn domain(&self) -> &MigrationDomain {
        &self.domain
    }

    /// Returns the source schema version.
    #[must_use]
    pub const fn from(&self) -> SchemaVersion {
        self.from
    }

    /// Returns the target schema version.
    #[must_use]
    pub const fn to(&self) -> SchemaVersion {
        self.to
    }

    /// Returns the immutable content checksum.
    #[must_use]
    pub const fn checksum(&self) -> MigrationChecksum {
        self.checksum
    }

    /// Returns whether a verified backup is mandatory before execution.
    #[must_use]
    pub const fn requires_backup(&self) -> bool {
        self.requires_backup
    }
}

/// A validated, gap-free forward migration catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationCatalog {
    migrations: Vec<MigrationDescriptor>,
}

impl MigrationCatalog {
    /// Sorts and validates a bounded linear migration history.
    pub fn new(mut migrations: Vec<MigrationDescriptor>) -> Result<Self, StorageError> {
        if migrations.len() > MAX_MIGRATIONS {
            return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
        }
        migrations.sort_by_key(MigrationDescriptor::from);
        validate_unique_migrations(&migrations)?;
        validate_migration_chain(&migrations)?;
        Ok(Self { migrations })
    }

    /// Returns migrations in ascending source-version order.
    #[must_use]
    pub fn migrations(&self) -> &[MigrationDescriptor] {
        &self.migrations
    }

    /// Plans an exact forward path or fails without returning a partial plan.
    pub fn plan(
        &self,
        source: SchemaVersion,
        target: SchemaVersion,
    ) -> Result<MigrationPlan, StorageError> {
        if source >= target {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        let mut current = source;
        let mut steps = Vec::new();
        for migration in &self.migrations {
            if migration.from() == current && migration.to() <= target {
                current = migration.to();
                steps.push(migration.clone());
            }
            if current == target {
                return Ok(MigrationPlan {
                    source,
                    target,
                    steps,
                });
            }
        }
        Err(StorageError::new(StorageErrorCode::MigrationRequired))
    }
}

/// An exact immutable sequence of forward migrations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationPlan {
    source: SchemaVersion,
    target: SchemaVersion,
    steps: Vec<MigrationDescriptor>,
}

impl MigrationPlan {
    /// Returns the source schema version.
    #[must_use]
    pub const fn source(&self) -> SchemaVersion {
        self.source
    }

    /// Returns the final schema version.
    #[must_use]
    pub const fn target(&self) -> SchemaVersion {
        self.target
    }

    /// Returns the ordered migration steps.
    #[must_use]
    pub fn steps(&self) -> &[MigrationDescriptor] {
        &self.steps
    }

    /// Returns whether any step requires a verified backup.
    #[must_use]
    pub fn requires_backup(&self) -> bool {
        self.steps.iter().any(MigrationDescriptor::requires_backup)
    }
}

/// Evidence that a migration can proceed without touching the source target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationPreflight {
    source_authenticated: bool,
    target_empty: bool,
    backup_verified: bool,
}

impl MigrationPreflight {
    /// Creates explicit preflight evidence.
    #[must_use]
    pub const fn new(
        source_authenticated: bool,
        target_empty: bool,
        backup_verified: bool,
    ) -> Self {
        Self {
            source_authenticated,
            target_empty,
            backup_verified,
        }
    }

    /// Returns whether all required safety conditions passed.
    #[must_use]
    pub fn permits(&self, plan: &MigrationPlan) -> bool {
        self.source_authenticated
            && self.target_empty
            && (!plan.requires_backup() || self.backup_verified)
    }
}

/// Evidence returned after a new migration target is verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationReceipt {
    source: StorageInstanceId,
    target: StorageInstanceId,
    version: SchemaVersion,
    verified_at: SystemTime,
}

impl MigrationReceipt {
    /// Creates a receipt only after structural and authentication checks pass.
    #[must_use]
    pub const fn new(
        source: StorageInstanceId,
        target: StorageInstanceId,
        version: SchemaVersion,
        verified_at: SystemTime,
    ) -> Self {
        Self {
            source,
            target,
            version,
            verified_at,
        }
    }

    /// Returns the immutable source instance identity.
    #[must_use]
    pub const fn source(&self) -> &StorageInstanceId {
        &self.source
    }

    /// Returns the newly created target instance identity.
    #[must_use]
    pub const fn target(&self) -> &StorageInstanceId {
        &self.target
    }

    /// Returns the verified target schema version.
    #[must_use]
    pub const fn version(&self) -> SchemaVersion {
        self.version
    }

    /// Returns the UTC verification time.
    #[must_use]
    pub const fn verified_at(&self) -> SystemTime {
        self.verified_at
    }
}

/// Executes migrations into a distinct target and never overwrites the source.
pub trait MigrationExecutorPort: Send + Sync {
    /// Checks source authentication, target emptiness, and backup evidence.
    fn preflight(
        &self,
        source: &StorageInstanceId,
        target: &StorageInstanceId,
        plan: &MigrationPlan,
        context: &RequestContext,
    ) -> Result<MigrationPreflight, StorageError>;

    /// Applies the complete plan to a new target after successful preflight.
    fn apply_to_new_target(
        &self,
        source: &StorageInstanceId,
        target: &StorageInstanceId,
        plan: &MigrationPlan,
        preflight: MigrationPreflight,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Verifies structure and authentication before a caller can switch over.
    fn verify_target(
        &self,
        source: &StorageInstanceId,
        target: &StorageInstanceId,
        expected: SchemaVersion,
        context: &RequestContext,
    ) -> Result<MigrationReceipt, StorageError>;
}

fn validate_unique_migrations(migrations: &[MigrationDescriptor]) -> Result<(), StorageError> {
    let ids = migrations
        .iter()
        .map(MigrationDescriptor::id)
        .collect::<BTreeSet<_>>();
    let sources = migrations
        .iter()
        .map(MigrationDescriptor::from)
        .collect::<BTreeSet<_>>();
    if ids.len() != migrations.len() || sources.len() != migrations.len() {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn validate_migration_chain(migrations: &[MigrationDescriptor]) -> Result<(), StorageError> {
    for pair in migrations.windows(2) {
        if pair[0].to() != pair[1].from() {
            return Err(StorageError::new(StorageErrorCode::MigrationRequired));
        }
    }
    Ok(())
}

fn valid_identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

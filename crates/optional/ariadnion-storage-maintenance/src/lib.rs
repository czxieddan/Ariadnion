//! Bounded storage inspection, verification, and local maintenance contracts.
//!
//! Database adapters provide the actual inspection and recovery behavior. This
//! crate carries only redacted evidence, disabled-by-default endpoint policy,
//! operation identities, and audit-ready receipts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Display, Formatter};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::time::{Duration, SystemTime};

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, StorageErrorCode, StorageInstanceId};

const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_STORAGE_BYTES: u64 = 1 << 50;
const MAX_PAGE_RECORDS: u64 = 1_000_000_000_000;
const MAX_COMMAND_BYTES: u32 = 1024 * 1024;
const MIN_IO_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_IO_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// A non-zero RNMDB single-file format version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageFormatVersion(NonZeroU16);

impl StorageFormatVersion {
    /// Creates a non-zero file-format version.
    ///
    /// # Errors
    ///
    /// Zero returns [`StorageErrorCode::InvalidArgument`].
    pub fn new(value: u16) -> Result<Self, StorageError> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or_else(invalid_argument)
    }

    /// Returns the numeric format version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// A non-zero bounded database-file byte count.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageByteCount(NonZeroU64);

impl StorageByteCount {
    /// Creates a byte count from one byte through one pebibyte.
    ///
    /// # Errors
    ///
    /// Zero is invalid and values above the hard limit are resource exhaustion.
    pub fn new(value: u64) -> Result<Self, StorageError> {
        let value = NonZeroU64::new(value).ok_or_else(invalid_argument)?;
        if value.get() > MAX_STORAGE_BYTES {
            return Err(resource_exhausted());
        }
        Ok(Self(value))
    }

    /// Returns the exact byte count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A bounded page-record count that may be zero.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoragePageCount(u64);

impl StoragePageCount {
    /// Creates a count no greater than one trillion records.
    ///
    /// # Errors
    ///
    /// Values above the hard limit return resource exhaustion.
    pub fn new(value: u64) -> Result<Self, StorageError> {
        if value > MAX_PAGE_RECORDS {
            return Err(resource_exhausted());
        }
        Ok(Self(value))
    }

    /// Returns the record count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Redacted facts obtained without mutating one database file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectionEvidence {
    instance: StorageInstanceId,
    format_version: StorageFormatVersion,
    file_bytes: StorageByteCount,
    page_slots: StoragePageCount,
    present_pages: StoragePageCount,
    authenticated_pages: StoragePageCount,
    encryption_authenticated: bool,
    inspected_at: SystemTime,
}

impl InspectionEvidence {
    /// Creates internally consistent inspection evidence.
    ///
    /// # Errors
    ///
    /// Impossible slot, presence, or authentication counts fail closed with
    /// [`StorageErrorCode::IntegrityFailure`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance: StorageInstanceId,
        format_version: StorageFormatVersion,
        file_bytes: StorageByteCount,
        page_slots: StoragePageCount,
        present_pages: StoragePageCount,
        authenticated_pages: StoragePageCount,
        encryption_authenticated: bool,
        inspected_at: SystemTime,
    ) -> Result<Self, StorageError> {
        validate_page_counts(
            page_slots,
            present_pages,
            authenticated_pages,
            encryption_authenticated,
        )?;
        Ok(Self {
            instance,
            format_version,
            file_bytes,
            page_slots,
            present_pages,
            authenticated_pages,
            encryption_authenticated,
            inspected_at,
        })
    }

    /// Returns the inspected instance.
    #[must_use]
    pub const fn instance(&self) -> &StorageInstanceId {
        &self.instance
    }

    /// Returns the file-format version.
    #[must_use]
    pub const fn format_version(&self) -> StorageFormatVersion {
        self.format_version
    }

    /// Returns the verified file length.
    #[must_use]
    pub const fn file_bytes(&self) -> StorageByteCount {
        self.file_bytes
    }

    /// Returns all available page-record slots.
    #[must_use]
    pub const fn page_slots(&self) -> StoragePageCount {
        self.page_slots
    }

    /// Returns present page records.
    #[must_use]
    pub const fn present_pages(&self) -> StoragePageCount {
        self.present_pages
    }

    /// Returns page records authenticated with the supplied key.
    #[must_use]
    pub const fn authenticated_pages(&self) -> StoragePageCount {
        self.authenticated_pages
    }

    /// Returns whether encrypted-page authentication was required and passed.
    #[must_use]
    pub const fn encryption_authenticated(&self) -> bool {
        self.encryption_authenticated
    }

    /// Returns the UTC inspection time.
    #[must_use]
    pub const fn inspected_at(&self) -> SystemTime {
        self.inspected_at
    }
}

/// Complete structural and authentication verification evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationEvidence {
    inspection: InspectionEvidence,
    format_supported: bool,
    structure_verified: bool,
    verified_at: SystemTime,
}

impl VerificationEvidence {
    /// Creates time-ordered verification evidence from one inspection.
    ///
    /// # Errors
    ///
    /// A verification time before inspection is invalid.
    pub fn new(
        inspection: InspectionEvidence,
        format_supported: bool,
        structure_verified: bool,
        verified_at: SystemTime,
    ) -> Result<Self, StorageError> {
        if verified_at < inspection.inspected_at() {
            return Err(invalid_argument());
        }
        Ok(Self {
            inspection,
            format_supported,
            structure_verified,
            verified_at,
        })
    }

    /// Returns whether format, structure, and required authentication passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.format_supported
            && self.structure_verified
            && self.inspection.encryption_authenticated()
    }

    /// Returns the underlying inspection evidence.
    #[must_use]
    pub const fn inspection(&self) -> &InspectionEvidence {
        &self.inspection
    }

    /// Returns the UTC verification completion time.
    #[must_use]
    pub const fn verified_at(&self) -> SystemTime {
        self.verified_at
    }
}

/// Local transport allowed for a maintenance listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceEndpoint {
    /// A loopback-only TCP listener.
    Loopback,
    /// A Unix-domain socket with restricted filesystem permissions.
    UnixSocket,
    /// A Windows named pipe with a restricted access control list.
    NamedPipe,
}

/// A non-zero upper bound for one maintenance command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceCommandLimit(NonZeroU32);

impl MaintenanceCommandLimit {
    /// Creates a command limit from one byte through one mebibyte.
    ///
    /// # Errors
    ///
    /// Zero is invalid and larger limits are resource exhaustion.
    pub fn new(value: u32) -> Result<Self, StorageError> {
        let value = NonZeroU32::new(value).ok_or_else(invalid_argument)?;
        if value.get() > MAX_COMMAND_BYTES {
            return Err(resource_exhausted());
        }
        Ok(Self(value))
    }

    /// Returns the command byte limit.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// A bounded maintenance connection I/O timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceIoTimeout(Duration);

impl MaintenanceIoTimeout {
    /// Creates a timeout from one millisecond through five minutes.
    ///
    /// # Errors
    ///
    /// Values outside the closed range are invalid.
    pub fn new(value: Duration) -> Result<Self, StorageError> {
        if !(MIN_IO_TIMEOUT..=MAX_IO_TIMEOUT).contains(&value) {
            return Err(invalid_argument());
        }
        Ok(Self(value))
    }

    /// Returns the timeout duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// Disabled-by-default policy for one local maintenance endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceEndpointPolicy {
    enabled: bool,
    endpoint: MaintenanceEndpoint,
    command_limit: MaintenanceCommandLimit,
    io_timeout: MaintenanceIoTimeout,
}

impl MaintenanceEndpointPolicy {
    /// Creates a disabled policy that cannot accept maintenance commands.
    #[must_use]
    pub const fn disabled(
        endpoint: MaintenanceEndpoint,
        command_limit: MaintenanceCommandLimit,
        io_timeout: MaintenanceIoTimeout,
    ) -> Self {
        Self {
            enabled: false,
            endpoint,
            command_limit,
            io_timeout,
        }
    }

    /// Returns an explicitly enabled copy after composition authorization.
    #[must_use]
    pub const fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Returns whether a listener may accept commands.
    #[must_use]
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Returns the local endpoint kind.
    #[must_use]
    pub const fn endpoint(self) -> MaintenanceEndpoint {
        self.endpoint
    }

    /// Returns the command-size limit.
    #[must_use]
    pub const fn command_limit(self) -> MaintenanceCommandLimit {
        self.command_limit
    }

    /// Returns the connection I/O timeout.
    #[must_use]
    pub const fn io_timeout(self) -> MaintenanceIoTimeout {
        self.io_timeout
    }
}

/// A bounded, audit-correlated maintenance operation identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MaintenanceOperationId(Box<str>);

impl MaintenanceOperationId {
    /// Parses a stable ASCII operation identity.
    ///
    /// # Errors
    ///
    /// Empty, oversized, or malformed values are invalid.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_identifier(value) {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for MaintenanceOperationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable maintenance operation classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceOperationKind {
    /// Non-mutating storage inspection.
    Inspect,
    /// Keyed structural verification.
    Verify,
    /// New-target backup creation.
    Backup,
    /// New-target restore.
    Restore,
    /// New-target format, schema, or key upgrade.
    Upgrade,
    /// Explicit emergency read-only access.
    EmergencyReadOnly,
}

/// Immutable request metadata for one maintenance operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceOperation {
    id: MaintenanceOperationId,
    kind: MaintenanceOperationKind,
    instance: StorageInstanceId,
    requested_at: SystemTime,
}

impl MaintenanceOperation {
    /// Creates a bounded operation request without executing it.
    #[must_use]
    pub const fn new(
        id: MaintenanceOperationId,
        kind: MaintenanceOperationKind,
        instance: StorageInstanceId,
        requested_at: SystemTime,
    ) -> Self {
        Self {
            id,
            kind,
            instance,
            requested_at,
        }
    }

    /// Returns the operation identity.
    #[must_use]
    pub const fn id(&self) -> &MaintenanceOperationId {
        &self.id
    }

    /// Returns the operation class.
    #[must_use]
    pub const fn kind(&self) -> MaintenanceOperationKind {
        self.kind
    }

    /// Returns the target storage instance.
    #[must_use]
    pub const fn instance(&self) -> &StorageInstanceId {
        &self.instance
    }

    /// Returns the UTC request time.
    #[must_use]
    pub const fn requested_at(&self) -> SystemTime {
        self.requested_at
    }
}

/// Stable terminal status for an audited maintenance operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceStatus {
    /// The operation completed and its evidence was persisted.
    Succeeded,
    /// Policy rejected the operation before mutation.
    Rejected,
    /// The operation failed with a redacted storage error.
    Failed,
    /// Request cancellation stopped the operation.
    Cancelled,
    /// The request deadline expired.
    TimedOut,
}

/// Time-ordered receipt suitable for append-only operation audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceReceipt {
    operation: MaintenanceOperation,
    status: MaintenanceStatus,
    completed_at: SystemTime,
}

impl MaintenanceReceipt {
    /// Creates a receipt no earlier than its operation request.
    ///
    /// # Errors
    ///
    /// A completion time before the request is invalid.
    pub fn new(
        operation: MaintenanceOperation,
        status: MaintenanceStatus,
        completed_at: SystemTime,
    ) -> Result<Self, StorageError> {
        if completed_at < operation.requested_at() {
            return Err(invalid_argument());
        }
        Ok(Self {
            operation,
            status,
            completed_at,
        })
    }

    /// Returns the immutable operation request.
    #[must_use]
    pub const fn operation(&self) -> &MaintenanceOperation {
        &self.operation
    }

    /// Returns the terminal status.
    #[must_use]
    pub const fn status(&self) -> MaintenanceStatus {
        self.status
    }

    /// Returns the UTC completion time.
    #[must_use]
    pub const fn completed_at(&self) -> SystemTime {
        self.completed_at
    }
}

/// Reads redacted inspection and keyed verification evidence.
pub trait StorageInspectionPort: Send + Sync {
    /// Inspects one instance without mutation.
    ///
    /// # Errors
    ///
    /// Returns stable cancellation, deadline, integrity, or availability errors.
    fn inspect(
        &self,
        instance: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<InspectionEvidence, StorageError>;

    /// Authenticates and structurally verifies one instance without mutation.
    ///
    /// # Errors
    ///
    /// Returns a stable error when keys, format support, structure, cancellation,
    /// deadlines, or storage availability prevent complete verification.
    fn verify(
        &self,
        instance: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<VerificationEvidence, StorageError>;
}

/// Authorizes local maintenance and persists audit-ready terminal receipts.
pub trait MaintenanceGatePort: Send + Sync {
    /// Returns the immutable disabled or explicitly enabled endpoint policy.
    fn policy(&self) -> MaintenanceEndpointPolicy;

    /// Authorizes an operation before any mutating adapter call.
    ///
    /// # Errors
    ///
    /// Disabled endpoints, insufficient permission, cancellation, or deadline
    /// expiry return a stable error without starting the operation.
    fn authorize(
        &self,
        operation: &MaintenanceOperation,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Persists one terminal receipt before it is reported externally.
    ///
    /// # Errors
    ///
    /// Returns a stable error if durable audit recording cannot complete.
    fn record(
        &self,
        receipt: &MaintenanceReceipt,
        context: &RequestContext,
    ) -> Result<(), StorageError>;
}

fn validate_page_counts(
    slots: StoragePageCount,
    present: StoragePageCount,
    authenticated: StoragePageCount,
    encryption_authenticated: bool,
) -> Result<(), StorageError> {
    let ordered = present <= slots && authenticated <= present;
    let authentication_consistent = if encryption_authenticated {
        authenticated == present
    } else {
        authenticated.get() == 0
    };
    if !ordered || !authentication_consistent {
        return Err(integrity_failure());
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

const fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

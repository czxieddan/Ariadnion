use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU32;
use std::time::{Duration, SystemTime};

use ariadnion_storage_domain::{SchemaVersion, StorageError, StorageErrorCode, StorageInstanceId};

const MAX_BACKUP_ID_BYTES: usize = 128;
const MAX_TARGET_ID_BYTES: usize = 192;
const MAX_KEY_VERSION_ID_BYTES: usize = 128;
const MAX_RECEIPT_ID_BYTES: usize = 128;
const MAX_HOLD_ID_BYTES: usize = 128;
const MAX_REASON_CODE_BYTES: usize = 128;
const MAX_BACKUP_PAGES: u64 = 1_000_000_000_000;
const MAX_RETENTION_COPIES: u16 = 3_660;
const MAX_SIGNED_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_PURGE_DELAY: Duration = Duration::from_secs(366 * 24 * 60 * 60);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BoundedIdentifier(Box<str>);

impl BoundedIdentifier {
    fn parse(value: &str, maximum: usize) -> Result<Self, StorageError> {
        validate_identifier(value, maximum)?;
        Ok(Self(value.into()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// A stable identity for one immutable backup artifact.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackupId(BoundedIdentifier);

impl BackupId {
    /// Parses a non-empty ASCII identity of at most 128 bytes.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        BoundedIdentifier::parse(value, MAX_BACKUP_ID_BYTES).map(Self)
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for BackupId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A stable logical target that never contains a filesystem path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackupTargetId(BoundedIdentifier);

impl BackupTargetId {
    /// Parses a non-empty ASCII target identity of at most 192 bytes.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        BoundedIdentifier::parse(value, MAX_TARGET_ID_BYTES).map(Self)
    }

    /// Returns the validated target identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A stable identifier for the key version used to authenticate a backup.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackupKeyVersionId(BoundedIdentifier);

impl BackupKeyVersionId {
    /// Parses a non-empty ASCII key-version identity of at most 128 bytes.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        BoundedIdentifier::parse(value, MAX_KEY_VERSION_ID_BYTES).map(Self)
    }

    /// Returns the validated key-version identity without key material.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A stable identifier for the key version used to sign a manifest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManifestSigningKeyVersionId(BoundedIdentifier);

impl ManifestSigningKeyVersionId {
    /// Parses a non-empty ASCII key-version identity of at most 128 bytes.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        BoundedIdentifier::parse(value, MAX_KEY_VERSION_ID_BYTES).map(Self)
    }

    /// Returns the validated signing-key version without key material.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A stable identity for an audit-correlated backup operation receipt.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackupReceiptId(BoundedIdentifier);

impl BackupReceiptId {
    /// Parses a non-empty ASCII receipt identity of at most 128 bytes.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        BoundedIdentifier::parse(value, MAX_RECEIPT_ID_BYTES).map(Self)
    }

    /// Returns the validated receipt identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A non-zero source file-format version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackupFileVersion(NonZeroU32);

impl BackupFileVersion {
    /// Creates a file-format version from a non-zero integer.
    pub fn new(value: u32) -> Result<Self, StorageError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or_else(invalid_argument)
    }

    /// Returns the numeric file-format version.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// A bounded count of authenticated source pages, including an empty source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackupPageCount(u64);

impl BackupPageCount {
    /// Creates a page count from zero through one trillion pages.
    pub fn new(value: u64) -> Result<Self, StorageError> {
        if value > MAX_BACKUP_PAGES {
            return Err(resource_exhausted());
        }
        Ok(Self(value))
    }

    /// Returns the authenticated page count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An exact SHA-256 digest of a completed backup artifact.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BackupSha256Digest([u8; 32]);

impl BackupSha256Digest {
    /// Creates a digest from exactly 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for BackupSha256Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Debug for BackupSha256Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BackupSha256Digest")
            .field(&self.to_string())
            .finish()
    }
}

/// Version and size facts captured from the source before copying.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSourceSnapshot {
    instance: StorageInstanceId,
    file_version: BackupFileVersion,
    schema_version: SchemaVersion,
    page_count: BackupPageCount,
}

impl BackupSourceSnapshot {
    /// Creates immutable source facts used by verification and audit records.
    #[must_use]
    pub const fn new(
        instance: StorageInstanceId,
        file_version: BackupFileVersion,
        schema_version: SchemaVersion,
        page_count: BackupPageCount,
    ) -> Self {
        Self {
            instance,
            file_version,
            schema_version,
            page_count,
        }
    }

    /// Returns the source storage instance.
    #[must_use]
    pub const fn instance(&self) -> &StorageInstanceId {
        &self.instance
    }

    /// Returns the authenticated source file-format version.
    #[must_use]
    pub const fn file_version(&self) -> BackupFileVersion {
        self.file_version
    }

    /// Returns the application schema version found in the source.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the authenticated source page count.
    #[must_use]
    pub const fn page_count(&self) -> BackupPageCount {
        self.page_count
    }
}

/// Keyed integrity facts for one completed and authenticated artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupIntegrityProof {
    digest: BackupSha256Digest,
    key_version: BackupKeyVersionId,
    created_at: SystemTime,
    verified_at: SystemTime,
}

impl BackupIntegrityProof {
    /// Creates proof whose verification time is not earlier than creation.
    pub fn new(
        digest: BackupSha256Digest,
        key_version: BackupKeyVersionId,
        created_at: SystemTime,
        verified_at: SystemTime,
    ) -> Result<Self, StorageError> {
        if verified_at < created_at {
            return Err(invalid_argument());
        }
        Ok(Self {
            digest,
            key_version,
            created_at,
            verified_at,
        })
    }

    /// Returns the SHA-256 digest of the verified target bytes.
    #[must_use]
    pub const fn digest(&self) -> BackupSha256Digest {
        self.digest
    }

    /// Returns the identifier of the verification key version.
    #[must_use]
    pub const fn key_version(&self) -> &BackupKeyVersionId {
        &self.key_version
    }

    /// Returns the UTC time at which target creation completed.
    #[must_use]
    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Returns the UTC time at which keyed verification completed.
    #[must_use]
    pub const fn verified_at(&self) -> SystemTime {
        self.verified_at
    }
}

/// A request to create one authenticated backup at a new logical target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCreateRequest {
    backup_id: BackupId,
    source: StorageInstanceId,
    target: BackupTargetId,
    key_version: BackupKeyVersionId,
    requested_at: SystemTime,
}

impl BackupCreateRequest {
    /// Creates a request and rejects a target equal to the source identity.
    pub fn new(
        backup_id: BackupId,
        source: StorageInstanceId,
        target: BackupTargetId,
        key_version: BackupKeyVersionId,
        requested_at: SystemTime,
    ) -> Result<Self, StorageError> {
        ensure_distinct(&source, &target)?;
        Ok(Self {
            backup_id,
            source,
            target,
            key_version,
            requested_at,
        })
    }

    /// Returns the caller-selected backup identity.
    #[must_use]
    pub const fn backup_id(&self) -> &BackupId {
        &self.backup_id
    }

    /// Returns the immutable source instance.
    #[must_use]
    pub const fn source(&self) -> &StorageInstanceId {
        &self.source
    }

    /// Returns the unused target identity requested by the caller.
    #[must_use]
    pub const fn target(&self) -> &BackupTargetId {
        &self.target
    }

    /// Returns the verification-key version requested by the caller.
    #[must_use]
    pub const fn key_version(&self) -> &BackupKeyVersionId {
        &self.key_version
    }

    /// Returns the UTC request time.
    #[must_use]
    pub const fn requested_at(&self) -> SystemTime {
        self.requested_at
    }
}

/// Complete evidence for a distinct, keyed, and verified backup target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVerificationEvidence {
    backup_id: BackupId,
    target: BackupTargetId,
    source: BackupSourceSnapshot,
    proof: BackupIntegrityProof,
}

impl BackupVerificationEvidence {
    /// Creates evidence and rejects a target equal to the source identity.
    pub fn new(
        backup_id: BackupId,
        target: BackupTargetId,
        source: BackupSourceSnapshot,
        proof: BackupIntegrityProof,
    ) -> Result<Self, StorageError> {
        ensure_distinct(source.instance(), &target)?;
        Ok(Self {
            backup_id,
            target,
            source,
            proof,
        })
    }

    /// Returns the immutable backup identity.
    #[must_use]
    pub const fn backup_id(&self) -> &BackupId {
        &self.backup_id
    }

    /// Returns the distinct target identity.
    #[must_use]
    pub const fn target(&self) -> &BackupTargetId {
        &self.target
    }

    /// Returns the source instance, file version, schema version, and page count.
    #[must_use]
    pub const fn source(&self) -> &BackupSourceSnapshot {
        &self.source
    }

    /// Returns the digest, key version, creation time, and verification time.
    #[must_use]
    pub const fn proof(&self) -> &BackupIntegrityProof {
        &self.proof
    }

    /// Checks that this evidence exactly satisfies one creation request.
    pub fn validate_for(&self, request: &BackupCreateRequest) -> Result<(), StorageError> {
        if !self.matches_request_identity(request) || !self.matches_request_time(request) {
            return Err(integrity_failure());
        }
        Ok(())
    }

    fn matches_request_identity(&self, request: &BackupCreateRequest) -> bool {
        self.backup_id() == request.backup_id()
            && self.target() == request.target()
            && self.source().instance() == request.source()
            && self.proof().key_version() == request.key_version()
    }

    fn matches_request_time(&self, request: &BackupCreateRequest) -> bool {
        self.proof().created_at() >= request.requested_at()
    }
}

/// A bounded opaque envelope containing a signed backup manifest.
#[derive(Eq, PartialEq)]
pub struct SignedManifestExport {
    backup_id: BackupId,
    signing_key: ManifestSigningKeyVersionId,
    exported_at: SystemTime,
    bytes: Box<[u8]>,
}

impl SignedManifestExport {
    /// Copies a non-empty signed envelope of at most one mebibyte.
    pub fn new(
        backup_id: BackupId,
        signing_key: ManifestSigningKeyVersionId,
        exported_at: SystemTime,
        bytes: &[u8],
    ) -> Result<Self, StorageError> {
        validate_manifest_size(bytes)?;
        Ok(Self {
            backup_id,
            signing_key,
            exported_at,
            bytes: bytes.into(),
        })
    }

    /// Returns the backup identity covered by the signed envelope.
    #[must_use]
    pub const fn backup_id(&self) -> &BackupId {
        &self.backup_id
    }

    /// Returns the signing-key version identifier without key material.
    #[must_use]
    pub const fn signing_key(&self) -> &ManifestSigningKeyVersionId {
        &self.signing_key
    }

    /// Returns the UTC export time.
    #[must_use]
    pub const fn exported_at(&self) -> SystemTime {
        self.exported_at
    }

    /// Returns the opaque signed envelope bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Debug for SignedManifestExport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedManifestExport")
            .field("backup_id", &self.backup_id)
            .field("signing_key", &self.signing_key)
            .field("exported_at", &self.exported_at)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A bounded number of backup generations retained for one UTC cadence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionCount(u16);

impl RetentionCount {
    /// Creates a retained generation count from zero through 3660.
    pub fn new(value: u16) -> Result<Self, StorageError> {
        if value > MAX_RETENTION_COPIES {
            return Err(resource_exhausted());
        }
        Ok(Self(value))
    }

    /// Returns the retained generation count.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// UTC generation counts for daily, weekly, and monthly backup retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    daily: RetentionCount,
    weekly: RetentionCount,
    monthly: RetentionCount,
}

impl RetentionPolicy {
    /// Creates a policy with explicit counts for every supported cadence.
    #[must_use]
    pub const fn new(
        daily: RetentionCount,
        weekly: RetentionCount,
        monthly: RetentionCount,
    ) -> Self {
        Self {
            daily,
            weekly,
            monthly,
        }
    }

    /// Returns the number of daily generations to retain.
    #[must_use]
    pub const fn daily(self) -> RetentionCount {
        self.daily
    }

    /// Returns the number of weekly generations to retain.
    #[must_use]
    pub const fn weekly(self) -> RetentionCount {
        self.weekly
    }

    /// Returns the number of monthly generations to retain.
    #[must_use]
    pub const fn monthly(self) -> RetentionCount {
        self.monthly
    }
}

/// The strongest retention result for one backup at an evaluation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionDisposition {
    /// The backup occupies a retained daily generation.
    Daily,
    /// The backup occupies a retained weekly generation.
    Weekly,
    /// The backup occupies a retained monthly generation.
    Monthly,
    /// An active legal hold overrides deletion eligibility.
    LegalHold,
    /// No policy tier or legal hold currently retains the backup.
    EligibleForDeletion,
}

/// A stable identity for one legal hold.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LegalHoldId(BoundedIdentifier);

impl LegalHoldId {
    /// Parses a non-empty ASCII hold identity of at most 128 bytes.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        BoundedIdentifier::parse(value, MAX_HOLD_ID_BYTES).map(Self)
    }

    /// Returns the validated legal-hold identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A request to place an indefinite or time-bounded legal hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegalHoldRequest {
    hold_id: LegalHoldId,
    backup_id: BackupId,
    placed_at: SystemTime,
    expires_at: Option<SystemTime>,
}

impl LegalHoldRequest {
    /// Creates a hold and rejects an expiry that is not after placement.
    pub fn new(
        hold_id: LegalHoldId,
        backup_id: BackupId,
        placed_at: SystemTime,
        expires_at: Option<SystemTime>,
    ) -> Result<Self, StorageError> {
        validate_optional_expiry(placed_at, expires_at)?;
        Ok(Self {
            hold_id,
            backup_id,
            placed_at,
            expires_at,
        })
    }

    /// Returns the legal-hold identity.
    #[must_use]
    pub const fn hold_id(&self) -> &LegalHoldId {
        &self.hold_id
    }

    /// Returns the held backup identity.
    #[must_use]
    pub const fn backup_id(&self) -> &BackupId {
        &self.backup_id
    }

    /// Returns the UTC placement time.
    #[must_use]
    pub const fn placed_at(&self) -> SystemTime {
        self.placed_at
    }

    /// Returns the exclusive UTC expiry, or `None` for an indefinite hold.
    #[must_use]
    pub const fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
}

/// Durable evidence that a legal hold was placed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegalHoldReceipt {
    receipt_id: BackupReceiptId,
    request: LegalHoldRequest,
}

impl LegalHoldReceipt {
    /// Creates a durable receipt from an already validated hold request.
    #[must_use]
    pub fn from_request(receipt_id: BackupReceiptId, request: &LegalHoldRequest) -> Self {
        Self {
            receipt_id,
            request: request.clone(),
        }
    }

    /// Returns the audit-correlated placement receipt identity.
    #[must_use]
    pub const fn receipt_id(&self) -> &BackupReceiptId {
        &self.receipt_id
    }

    /// Returns the exact durable hold request.
    #[must_use]
    pub const fn request(&self) -> &LegalHoldRequest {
        &self.request
    }
}

/// Durable evidence that one exact legal hold was released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegalHoldReleaseReceipt {
    receipt_id: BackupReceiptId,
    placement_receipt_id: BackupReceiptId,
    hold_id: LegalHoldId,
    backup_id: BackupId,
    released_at: SystemTime,
}

impl LegalHoldReleaseReceipt {
    /// Creates a release receipt no earlier than the hold placement.
    pub fn from_hold(
        receipt_id: BackupReceiptId,
        hold: &LegalHoldReceipt,
        released_at: SystemTime,
    ) -> Result<Self, StorageError> {
        if released_at < hold.request().placed_at() {
            return Err(invalid_argument());
        }
        Ok(Self {
            receipt_id,
            placement_receipt_id: hold.receipt_id().clone(),
            hold_id: hold.request().hold_id().clone(),
            backup_id: hold.request().backup_id().clone(),
            released_at,
        })
    }

    /// Returns the audit-correlated release receipt identity.
    #[must_use]
    pub const fn receipt_id(&self) -> &BackupReceiptId {
        &self.receipt_id
    }

    /// Returns the placement receipt released by this operation.
    #[must_use]
    pub const fn placement_receipt_id(&self) -> &BackupReceiptId {
        &self.placement_receipt_id
    }

    /// Returns the released legal-hold identity.
    #[must_use]
    pub const fn hold_id(&self) -> &LegalHoldId {
        &self.hold_id
    }

    /// Returns the backup released from the hold.
    #[must_use]
    pub const fn backup_id(&self) -> &BackupId {
        &self.backup_id
    }

    /// Returns the UTC release time.
    #[must_use]
    pub const fn released_at(&self) -> SystemTime {
        self.released_at
    }
}

/// A stable machine-readable reason for marking a backup for deletion.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeletionReasonCode(BoundedIdentifier);

impl DeletionReasonCode {
    /// Parses a non-empty ASCII reason code of at most 128 bytes.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        BoundedIdentifier::parse(value, MAX_REASON_CODE_BYTES).map(Self)
    }

    /// Returns the validated reason code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A bounded delay between a durable deletion mark and physical purge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PurgeDelay(Duration);

impl PurgeDelay {
    /// Creates a non-zero delay of at most 366 days.
    pub fn new(value: Duration) -> Result<Self, StorageError> {
        if value.is_zero() || value > MAX_PURGE_DELAY {
            return Err(invalid_argument());
        }
        Ok(Self(value))
    }

    /// Returns the validated purge delay.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// A request to mark one retention-eligible backup for later purge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionMarkRequest {
    backup_id: BackupId,
    reason: DeletionReasonCode,
    purge_delay: PurgeDelay,
}

impl DeletionMarkRequest {
    /// Creates a mark request with an explicit reason and purge delay.
    #[must_use]
    pub const fn new(
        backup_id: BackupId,
        reason: DeletionReasonCode,
        purge_delay: PurgeDelay,
    ) -> Self {
        Self {
            backup_id,
            reason,
            purge_delay,
        }
    }

    /// Returns the backup to mark.
    #[must_use]
    pub const fn backup_id(&self) -> &BackupId {
        &self.backup_id
    }

    /// Returns the stable deletion reason.
    #[must_use]
    pub const fn reason(&self) -> &DeletionReasonCode {
        &self.reason
    }

    /// Returns the required delay before purge.
    #[must_use]
    pub const fn purge_delay(&self) -> PurgeDelay {
        self.purge_delay
    }
}

/// Durable evidence that content remains present but is marked for purge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionMarkReceipt {
    receipt_id: BackupReceiptId,
    backup_id: BackupId,
    source: StorageInstanceId,
    target: BackupTargetId,
    digest: BackupSha256Digest,
    reason: DeletionReasonCode,
    marked_at: SystemTime,
    purge_not_before: SystemTime,
}

impl DeletionMarkReceipt {
    /// Creates a receipt from exact verification evidence and a mark request.
    pub fn from_evidence(
        receipt_id: BackupReceiptId,
        request: &DeletionMarkRequest,
        evidence: &BackupVerificationEvidence,
        marked_at: SystemTime,
    ) -> Result<Self, StorageError> {
        validate_mark_identity(request, evidence)?;
        let purge_not_before = marked_at
            .checked_add(request.purge_delay().get())
            .ok_or_else(resource_exhausted)?;
        Ok(Self {
            receipt_id,
            backup_id: request.backup_id().clone(),
            source: evidence.source().instance().clone(),
            target: evidence.target().clone(),
            digest: evidence.proof().digest(),
            reason: request.reason().clone(),
            marked_at,
            purge_not_before,
        })
    }

    /// Returns the audit-correlated deletion-mark receipt identity.
    #[must_use]
    pub const fn receipt_id(&self) -> &BackupReceiptId {
        &self.receipt_id
    }

    /// Returns the marked backup identity.
    #[must_use]
    pub const fn backup_id(&self) -> &BackupId {
        &self.backup_id
    }

    /// Returns the source instance recorded by verification.
    #[must_use]
    pub const fn source(&self) -> &StorageInstanceId {
        &self.source
    }

    /// Returns the exact target that remains present after marking.
    #[must_use]
    pub const fn target(&self) -> &BackupTargetId {
        &self.target
    }

    /// Returns the digest that a later purge must compare.
    #[must_use]
    pub const fn digest(&self) -> BackupSha256Digest {
        self.digest
    }

    /// Returns the stable deletion reason.
    #[must_use]
    pub const fn reason(&self) -> &DeletionReasonCode {
        &self.reason
    }

    /// Returns the UTC time at which the durable mark was recorded.
    #[must_use]
    pub const fn marked_at(&self) -> SystemTime {
        self.marked_at
    }

    /// Returns the earliest UTC time at which purge may begin.
    #[must_use]
    pub const fn purge_not_before(&self) -> SystemTime {
        self.purge_not_before
    }
}

/// Durable evidence that a previously marked artifact was physically purged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurgeReceipt {
    receipt_id: BackupReceiptId,
    mark_receipt_id: BackupReceiptId,
    backup_id: BackupId,
    source: StorageInstanceId,
    target: BackupTargetId,
    digest: BackupSha256Digest,
    marked_at: SystemTime,
    purged_at: SystemTime,
}

impl PurgeReceipt {
    /// Creates a purge receipt no earlier than the mark's permitted purge time.
    pub fn from_mark(
        receipt_id: BackupReceiptId,
        mark: &DeletionMarkReceipt,
        purged_at: SystemTime,
    ) -> Result<Self, StorageError> {
        if purged_at < mark.purge_not_before() {
            return Err(invalid_argument());
        }
        Ok(Self {
            receipt_id,
            mark_receipt_id: mark.receipt_id().clone(),
            backup_id: mark.backup_id().clone(),
            source: mark.source().clone(),
            target: mark.target().clone(),
            digest: mark.digest(),
            marked_at: mark.marked_at(),
            purged_at,
        })
    }

    /// Returns the audit-correlated purge receipt identity.
    #[must_use]
    pub const fn receipt_id(&self) -> &BackupReceiptId {
        &self.receipt_id
    }

    /// Returns the deletion-mark receipt consumed by this purge.
    #[must_use]
    pub const fn mark_receipt_id(&self) -> &BackupReceiptId {
        &self.mark_receipt_id
    }

    /// Returns the purged backup identity.
    #[must_use]
    pub const fn backup_id(&self) -> &BackupId {
        &self.backup_id
    }

    /// Returns the original source instance.
    #[must_use]
    pub const fn source(&self) -> &StorageInstanceId {
        &self.source
    }

    /// Returns the exact purged target identity.
    #[must_use]
    pub const fn target(&self) -> &BackupTargetId {
        &self.target
    }

    /// Returns the digest recorded before deletion.
    #[must_use]
    pub const fn digest(&self) -> BackupSha256Digest {
        self.digest
    }

    /// Returns the UTC deletion-mark time.
    #[must_use]
    pub const fn marked_at(&self) -> SystemTime {
        self.marked_at
    }

    /// Returns the UTC physical purge time.
    #[must_use]
    pub const fn purged_at(&self) -> SystemTime {
        self.purged_at
    }
}

fn ensure_distinct(
    source: &StorageInstanceId,
    target: &BackupTargetId,
) -> Result<(), StorageError> {
    if source.as_str() == target.as_str() {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > maximum || !value.is_ascii() {
        return Err(invalid_argument());
    }
    if invalid_identifier_boundary(value) {
        return Err(invalid_argument());
    }
    if value.bytes().any(invalid_identifier_byte) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn invalid_identifier_boundary(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
}

fn invalid_identifier_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_' | b':')
}

fn validate_manifest_size(bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.is_empty() {
        return Err(invalid_argument());
    }
    if bytes.len() > MAX_SIGNED_MANIFEST_BYTES {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn validate_optional_expiry(
    placed_at: SystemTime,
    expires_at: Option<SystemTime>,
) -> Result<(), StorageError> {
    if expires_at.is_some_and(|expiry| expiry <= placed_at) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_mark_identity(
    request: &DeletionMarkRequest,
    evidence: &BackupVerificationEvidence,
) -> Result<(), StorageError> {
    if request.backup_id() != evidence.backup_id() {
        return Err(integrity_failure());
    }
    Ok(())
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

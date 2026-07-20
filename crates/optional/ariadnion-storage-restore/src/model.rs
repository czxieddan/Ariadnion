use std::fmt::{self, Debug, Formatter};
use std::num::{NonZeroU32, NonZeroU64};
use std::time::SystemTime;

use ariadnion_storage_domain::{SchemaVersion, StorageError, StorageErrorCode, StorageInstanceId};

const MAX_SOURCE_ID_BYTES: usize = 128;
const MAX_AUTHORIZATION_ID_BYTES: usize = 128;
const MAX_RESTORE_BYTES: u64 = 1 << 50;
const MAX_VERIFICATION_OBSERVATIONS: u32 = 10_000_000;

/// Maximum records compared by one read-only shadow sample.
pub const MAX_SHADOW_SAMPLE_RECORDS: u32 = 10_000;

/// Bounded logical identifier for a previously verified backup.
///
/// Only ASCII letters, digits, `.`, `-`, and `_` are accepted, so this value
/// cannot carry an arbitrary filesystem path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RestoreSourceId(Box<str>);

impl RestoreSourceId {
    /// Parses a stable restore-source identifier.
    ///
    /// # Errors
    ///
    /// Invalid or oversized input returns [`StorageErrorCode::InvalidArgument`].
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_identifier(value, MAX_SOURCE_ID_BYTES) {
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

/// SHA-256 digest of an authenticated immutable backup manifest.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RestoreSourceDigest([u8; 32]);

impl RestoreSourceDigest {
    /// Creates a digest from exactly 32 bytes.
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

impl Debug for RestoreSourceDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RestoreSourceDigest(<sha256>)")
    }
}

/// Non-zero bounded estimate of bytes required by a restored target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RestoreSize(NonZeroU64);

impl RestoreSize {
    /// Creates an estimate no greater than one pebibyte.
    ///
    /// # Errors
    ///
    /// Zero is invalid; values above the limit are resource exhaustion.
    pub fn new(bytes: u64) -> Result<Self, StorageError> {
        let bytes =
            NonZeroU64::new(bytes).ok_or(StorageError::new(StorageErrorCode::InvalidArgument))?;
        if bytes.get() > MAX_RESTORE_BYTES {
            return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
        }
        Ok(Self(bytes))
    }

    /// Returns the estimated byte count.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0.get()
    }
}

/// Typed reference issued after an upstream backup verification succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRestoreSource {
    id: RestoreSourceId,
    digest: RestoreSourceDigest,
    schema: SchemaVersion,
    size: RestoreSize,
}

impl VerifiedRestoreSource {
    /// Records a verified backup reference without performing I/O.
    #[must_use]
    pub const fn new(
        id: RestoreSourceId,
        digest: RestoreSourceDigest,
        schema: SchemaVersion,
        size: RestoreSize,
    ) -> Self {
        Self {
            id,
            digest,
            schema,
            size,
        }
    }

    /// Returns the logical source identifier.
    #[must_use]
    pub const fn id(&self) -> &RestoreSourceId {
        &self.id
    }

    /// Returns the authenticated manifest digest.
    #[must_use]
    pub const fn digest(&self) -> RestoreSourceDigest {
        self.digest
    }

    /// Returns the source schema version.
    #[must_use]
    pub const fn schema(&self) -> SchemaVersion {
        self.schema
    }

    /// Returns the target-space estimate.
    #[must_use]
    pub const fn size(&self) -> RestoreSize {
        self.size
    }
}

/// Inclusive source-schema window supported by the running composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaCompatibility {
    minimum: SchemaVersion,
    maximum: SchemaVersion,
}

impl SchemaCompatibility {
    /// Creates an ordered inclusive compatibility window.
    ///
    /// # Errors
    ///
    /// A reversed window returns [`StorageErrorCode::InvalidArgument`].
    pub fn new(minimum: SchemaVersion, maximum: SchemaVersion) -> Result<Self, StorageError> {
        if minimum > maximum {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self { minimum, maximum })
    }

    /// Returns whether `version` is supported.
    #[must_use]
    pub fn supports(self, version: SchemaVersion) -> bool {
        version >= self.minimum && version <= self.maximum
    }
}

/// Restore request whose active instance and empty target must be distinct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreRequest {
    source: VerifiedRestoreSource,
    active: StorageInstanceId,
    target: StorageInstanceId,
    compatibility: SchemaCompatibility,
}

impl RestoreRequest {
    /// Creates a request without permitting in-place restore.
    ///
    /// # Errors
    ///
    /// Equal active and target identities return [`StorageErrorCode::Conflict`].
    pub fn new(
        source: VerifiedRestoreSource,
        active: StorageInstanceId,
        target: StorageInstanceId,
        compatibility: SchemaCompatibility,
    ) -> Result<Self, StorageError> {
        if active == target {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        Ok(Self {
            source,
            active,
            target,
            compatibility,
        })
    }

    /// Returns the verified source reference.
    #[must_use]
    pub const fn source(&self) -> &VerifiedRestoreSource {
        &self.source
    }

    /// Returns the instance that must remain unchanged before switch.
    #[must_use]
    pub const fn active(&self) -> &StorageInstanceId {
        &self.active
    }

    /// Returns the isolated new target.
    #[must_use]
    pub const fn target(&self) -> &StorageInstanceId {
        &self.target
    }

    /// Returns the supported schema window.
    #[must_use]
    pub const fn compatibility(&self) -> SchemaCompatibility {
        self.compatibility
    }
}

/// Bounded available-space measurement from dry-run preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailableStorageBytes(u64);

impl AvailableStorageBytes {
    /// Creates a measurement no greater than one pebibyte.
    ///
    /// # Errors
    ///
    /// Values above the limit return [`StorageErrorCode::ResourceExhausted`].
    pub fn new(bytes: u64) -> Result<Self, StorageError> {
        if bytes > MAX_RESTORE_BYTES {
            return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
        }
        Ok(Self(bytes))
    }

    /// Returns the measured byte count.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// Space, permission, and key observations from non-mutating preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreResourceEvidence {
    available_storage: AvailableStorageBytes,
    permissions_available: bool,
    keys_available: bool,
}

impl RestoreResourceEvidence {
    /// Records bounded resource availability without secrets or paths.
    #[must_use]
    pub const fn new(
        available_storage: AvailableStorageBytes,
        permissions_available: bool,
        keys_available: bool,
    ) -> Self {
        Self {
            available_storage,
            permissions_available,
            keys_available,
        }
    }

    /// Returns the available-space measurement.
    #[must_use]
    pub const fn available_storage(self) -> AvailableStorageBytes {
        self.available_storage
    }

    /// Returns whether source-read, target-create/read/write, and switch permissions exist.
    #[must_use]
    pub const fn permissions_available(self) -> bool {
        self.permissions_available
    }

    /// Returns whether source-decryption and target-encryption keys are available.
    #[must_use]
    pub const fn keys_available(self) -> bool {
        self.keys_available
    }

    fn permits(self, required: RestoreSize) -> bool {
        self.available_storage.bytes() >= required.bytes()
            && self.permissions_available
            && self.keys_available
    }
}

/// Evidence produced by a non-mutating restore preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePreflightEvidence {
    source: VerifiedRestoreSource,
    active: StorageInstanceId,
    target: StorageInstanceId,
    target_empty: bool,
    resources: RestoreResourceEvidence,
}

impl RestorePreflightEvidence {
    /// Records the exact identities and all required preflight observations.
    #[must_use]
    pub const fn new(
        source: VerifiedRestoreSource,
        active: StorageInstanceId,
        target: StorageInstanceId,
        target_empty: bool,
        resources: RestoreResourceEvidence,
    ) -> Self {
        Self {
            source,
            active,
            target,
            target_empty,
            resources,
        }
    }

    /// Returns whether evidence permits materialization for `request`.
    #[must_use]
    pub fn permits(&self, request: &RestoreRequest) -> bool {
        self.matches(request)
            && self.target_empty
            && request.compatibility().supports(self.source.schema())
            && self.resources.permits(request.source().size())
    }

    /// Returns whether the target was observed empty.
    #[must_use]
    pub const fn target_empty(&self) -> bool {
        self.target_empty
    }

    /// Returns the bounded resource observations.
    #[must_use]
    pub const fn resources(&self) -> RestoreResourceEvidence {
        self.resources
    }

    fn matches(&self, request: &RestoreRequest) -> bool {
        &self.source == request.source()
            && &self.active == request.active()
            && &self.target == request.target()
    }
}

/// Bounded summary of one required verification class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationObservation {
    checked: NonZeroU32,
    failures: u32,
}

impl VerificationObservation {
    /// Creates a summary with at least one and at most ten million checks.
    ///
    /// # Errors
    ///
    /// Invalid counts return [`StorageErrorCode::InvalidArgument`]; excessive
    /// counts return [`StorageErrorCode::ResourceExhausted`].
    pub fn new(checked: u32, failures: u32) -> Result<Self, StorageError> {
        let checked =
            NonZeroU32::new(checked).ok_or(StorageError::new(StorageErrorCode::InvalidArgument))?;
        if checked.get() > MAX_VERIFICATION_OBSERVATIONS {
            return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
        }
        if failures > checked.get() {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self { checked, failures })
    }

    /// Returns the number checked.
    #[must_use]
    pub const fn checked(self) -> u32 {
        self.checked.get()
    }

    /// Returns the number that failed.
    #[must_use]
    pub const fn failures(self) -> u32 {
        self.failures
    }

    /// Returns whether every observation passed.
    #[must_use]
    pub fn passed(self) -> bool {
        self.failures == 0
    }
}

/// Verification summaries required before shadow sampling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreVerificationChecks {
    page_authentication: VerificationObservation,
    schema: VerificationObservation,
    audit_chain: VerificationObservation,
    referential_integrity: VerificationObservation,
    business_invariants: VerificationObservation,
}

impl RestoreVerificationChecks {
    /// Records page, schema, audit, referential, and business checks.
    #[must_use]
    pub const fn new(
        page_authentication: VerificationObservation,
        schema: VerificationObservation,
        audit_chain: VerificationObservation,
        referential_integrity: VerificationObservation,
        business_invariants: VerificationObservation,
    ) -> Self {
        Self {
            page_authentication,
            schema,
            audit_chain,
            referential_integrity,
            business_invariants,
        }
    }

    /// Returns the authenticated-page summary.
    #[must_use]
    pub const fn page_authentication(self) -> VerificationObservation {
        self.page_authentication
    }

    /// Returns the schema summary.
    #[must_use]
    pub const fn schema(self) -> VerificationObservation {
        self.schema
    }

    /// Returns the audit-chain summary.
    #[must_use]
    pub const fn audit_chain(self) -> VerificationObservation {
        self.audit_chain
    }

    /// Returns the referential-integrity summary.
    #[must_use]
    pub const fn referential_integrity(self) -> VerificationObservation {
        self.referential_integrity
    }

    /// Returns the business-invariant summary.
    #[must_use]
    pub const fn business_invariants(self) -> VerificationObservation {
        self.business_invariants
    }

    /// Returns whether all five required classes passed.
    #[must_use]
    pub fn all_passed(self) -> bool {
        self.page_authentication.passed()
            && self.schema.passed()
            && self.audit_chain.passed()
            && self.referential_integrity.passed()
            && self.business_invariants.passed()
    }
}

/// Complete verification evidence for an isolated restored target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreVerificationEvidence {
    target: StorageInstanceId,
    source_digest: RestoreSourceDigest,
    schema: SchemaVersion,
    checks: RestoreVerificationChecks,
}

impl RestoreVerificationEvidence {
    /// Records the target schema and every required check class.
    #[must_use]
    pub const fn new(
        target: StorageInstanceId,
        source_digest: RestoreSourceDigest,
        schema: SchemaVersion,
        checks: RestoreVerificationChecks,
    ) -> Self {
        Self {
            target,
            source_digest,
            schema,
            checks,
        }
    }

    /// Returns whether this evidence permits shadow sampling for `request`.
    #[must_use]
    pub fn permits(&self, request: &RestoreRequest) -> bool {
        &self.target == request.target()
            && self.source_digest == request.source().digest()
            && self.schema == request.source().schema()
            && self.checks.all_passed()
    }

    /// Returns the authenticated source digest bound to this verification.
    #[must_use]
    pub const fn source_digest(&self) -> RestoreSourceDigest {
        self.source_digest
    }

    /// Returns all verification summaries.
    #[must_use]
    pub const fn checks(&self) -> RestoreVerificationChecks {
        self.checks
    }
}

/// Non-zero bounded request for shadow comparisons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowSampleLimit(NonZeroU32);

impl ShadowSampleLimit {
    /// Creates a limit from one through 10,000 records.
    ///
    /// # Errors
    ///
    /// Zero is invalid; values above the limit are resource exhaustion.
    pub fn new(records: u32) -> Result<Self, StorageError> {
        let records =
            NonZeroU32::new(records).ok_or(StorageError::new(StorageErrorCode::InvalidArgument))?;
        if records.get() > MAX_SHADOW_SAMPLE_RECORDS {
            return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
        }
        Ok(Self(records))
    }

    /// Returns the record limit.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Access mode observed during shadow sampling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowAccessMode {
    /// Both instances were opened without mutation rights.
    ReadOnly,
    /// At least one sampled instance permitted writes.
    ReadWrite,
}

/// Bounded evidence comparing active and restored instances.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowSampleEvidence {
    active: StorageInstanceId,
    target: StorageInstanceId,
    source_digest: RestoreSourceDigest,
    mode: ShadowAccessMode,
    requested: ShadowSampleLimit,
    observed: u32,
    mismatches: u32,
}

impl ShadowSampleEvidence {
    /// Creates evidence whose counts cannot exceed the requested sample.
    ///
    /// # Errors
    ///
    /// Inconsistent counts return [`StorageErrorCode::InvalidArgument`].
    pub fn new(
        active: StorageInstanceId,
        target: StorageInstanceId,
        source_digest: RestoreSourceDigest,
        mode: ShadowAccessMode,
        requested: ShadowSampleLimit,
        observed: u32,
        mismatches: u32,
    ) -> Result<Self, StorageError> {
        if observed > requested.get() || mismatches > observed {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self {
            active,
            target,
            source_digest,
            mode,
            requested,
            observed,
            mismatches,
        })
    }

    /// Returns whether sampling was read-only, non-empty, and mismatch-free.
    #[must_use]
    pub fn permits(&self, request: &RestoreRequest) -> bool {
        &self.active == request.active()
            && &self.target == request.target()
            && self.source_digest == request.source().digest()
            && self.mode == ShadowAccessMode::ReadOnly
            && self.observed > 0
            && self.mismatches == 0
    }

    /// Returns the number compared.
    #[must_use]
    pub const fn observed(&self) -> u32 {
        self.observed
    }

    /// Returns the requested comparison limit.
    #[must_use]
    pub const fn requested(&self) -> ShadowSampleLimit {
        self.requested
    }

    /// Returns the authenticated source digest sampled by both instances.
    #[must_use]
    pub const fn source_digest(&self) -> RestoreSourceDigest {
        self.source_digest
    }

    /// Returns the mismatch count.
    #[must_use]
    pub const fn mismatches(&self) -> u32 {
        self.mismatches
    }
}

/// Bounded reference to an externally approved switch decision.
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct AtomicSwitchAuthorizationId(Box<str>);

impl AtomicSwitchAuthorizationId {
    /// Parses a stable approval reference.
    ///
    /// # Errors
    ///
    /// Invalid or oversized input returns [`StorageErrorCode::InvalidArgument`].
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_identifier(value, MAX_AUTHORIZATION_ID_BYTES) {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Explicit one-shot authorization bound to reviewed restore evidence.
#[derive(Debug, Eq, PartialEq)]
pub struct AtomicSwitchAuthorization {
    id: AtomicSwitchAuthorizationId,
    source_digest: RestoreSourceDigest,
    expected_active: StorageInstanceId,
    target: StorageInstanceId,
    authorized_at: SystemTime,
}

impl AtomicSwitchAuthorization {
    /// Creates approval only from passing verification and shadow evidence.
    ///
    /// # Errors
    ///
    /// Evidence not bound to `request` returns
    /// [`StorageErrorCode::IntegrityFailure`].
    pub fn new(
        id: AtomicSwitchAuthorizationId,
        request: &RestoreRequest,
        verification: &RestoreVerificationEvidence,
        shadow: &ShadowSampleEvidence,
        authorized_at: SystemTime,
    ) -> Result<Self, StorageError> {
        if !verification.permits(request) || !shadow.permits(request) {
            return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
        }
        Ok(Self {
            id,
            source_digest: request.source().digest(),
            expected_active: request.active().clone(),
            target: request.target().clone(),
            authorized_at,
        })
    }

    /// Returns the approval reference.
    #[must_use]
    pub const fn id(&self) -> &AtomicSwitchAuthorizationId {
        &self.id
    }

    /// Returns the authenticated source digest bound to approval.
    #[must_use]
    pub const fn source_digest(&self) -> RestoreSourceDigest {
        self.source_digest
    }

    /// Returns the active identity that an adapter must compare before switch.
    #[must_use]
    pub const fn expected_active(&self) -> &StorageInstanceId {
        &self.expected_active
    }

    /// Returns the verified target selected by approval.
    #[must_use]
    pub const fn target(&self) -> &StorageInstanceId {
        &self.target
    }

    /// Returns the UTC approval time supplied by the authorizer.
    #[must_use]
    pub const fn authorized_at(&self) -> SystemTime {
        self.authorized_at
    }
}

/// Receipt returned only after an atomic active-target switch succeeds.
#[derive(Debug, Eq, PartialEq)]
pub struct RestoreReceipt {
    authorization_id: AtomicSwitchAuthorizationId,
    source_digest: RestoreSourceDigest,
    previous_active: StorageInstanceId,
    active: StorageInstanceId,
    authorized_at: SystemTime,
    switched_at: SystemTime,
}

impl RestoreReceipt {
    /// Consumes the one-shot authorization after a time-ordered switch.
    ///
    /// # Errors
    ///
    /// A switch time before authorization returns
    /// [`StorageErrorCode::InvalidArgument`].
    pub fn new(
        authorization: AtomicSwitchAuthorization,
        switched_at: SystemTime,
    ) -> Result<Self, StorageError> {
        if switched_at < authorization.authorized_at {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self {
            authorization_id: authorization.id,
            source_digest: authorization.source_digest,
            previous_active: authorization.expected_active,
            active: authorization.target,
            authorized_at: authorization.authorized_at,
            switched_at,
        })
    }

    /// Returns the approval reference.
    #[must_use]
    pub const fn authorization_id(&self) -> &AtomicSwitchAuthorizationId {
        &self.authorization_id
    }

    /// Returns the authenticated source digest bound to the switch.
    #[must_use]
    pub const fn source_digest(&self) -> RestoreSourceDigest {
        self.source_digest
    }

    /// Returns the formerly active instance.
    #[must_use]
    pub const fn previous_active(&self) -> &StorageInstanceId {
        &self.previous_active
    }

    /// Returns the newly active restored instance.
    #[must_use]
    pub const fn active(&self) -> &StorageInstanceId {
        &self.active
    }

    /// Returns the UTC approval time.
    #[must_use]
    pub const fn authorized_at(&self) -> SystemTime {
        self.authorized_at
    }

    /// Returns the UTC switch time reported by the adapter.
    #[must_use]
    pub const fn switched_at(&self) -> SystemTime {
        self.switched_at
    }
}

/// Stable stage identifiers for bounded failure evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreStage {
    /// Non-mutating preflight.
    Preflight,
    /// New-target materialization.
    Materialization,
    /// Target verification.
    Verification,
    /// Read-only shadow sampling.
    ShadowSampling,
    /// Atomic active-target switch.
    AtomicSwitch,
}

/// Observable isolated-target state after a failed operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreTargetDisposition {
    /// The target was not written.
    Untouched,
    /// The target may contain a partial restore.
    PartialInactive,
    /// The restored target did not pass verification.
    UnverifiedInactive,
    /// The verified target remains inactive.
    VerifiedInactive,
    /// The authorized target remains inactive after a failed switch.
    AuthorizedInactive,
}

/// Bounded redacted evidence for a restore failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreFailureEvidence {
    source: RestoreSourceId,
    expected_active: StorageInstanceId,
    observed_active: StorageInstanceId,
    target: StorageInstanceId,
    stage: RestoreStage,
    disposition: RestoreTargetDisposition,
    error: StorageError,
}

impl RestoreFailureEvidence {
    /// Records a shared storage error without paths, secrets, or artifact data.
    #[must_use]
    pub fn new(
        request: &RestoreRequest,
        observed_active: StorageInstanceId,
        stage: RestoreStage,
        disposition: RestoreTargetDisposition,
        error: StorageError,
    ) -> Self {
        Self {
            source: request.source().id().clone(),
            expected_active: request.active().clone(),
            observed_active,
            target: request.target().clone(),
            stage,
            disposition,
            error,
        }
    }

    /// Returns the source identifier.
    #[must_use]
    pub const fn source(&self) -> &RestoreSourceId {
        &self.source
    }

    /// Returns the instance expected to remain active.
    #[must_use]
    pub const fn expected_active(&self) -> &StorageInstanceId {
        &self.expected_active
    }

    /// Returns the active instance observed after failure cleanup.
    #[must_use]
    pub const fn observed_active(&self) -> &StorageInstanceId {
        &self.observed_active
    }

    /// Returns the isolated target.
    #[must_use]
    pub const fn target(&self) -> &StorageInstanceId {
        &self.target
    }

    /// Returns the failed stage.
    #[must_use]
    pub const fn stage(&self) -> RestoreStage {
        self.stage
    }

    /// Returns the bounded target-state classification.
    #[must_use]
    pub const fn disposition(&self) -> RestoreTargetDisposition {
        self.disposition
    }

    /// Returns the stable redacted storage error.
    #[must_use]
    pub const fn error(&self) -> StorageError {
        self.error
    }

    /// Confirms the mandatory failure invariant.
    #[must_use]
    pub fn active_instance_unchanged(&self) -> bool {
        self.expected_active == self.observed_active
    }
}

fn valid_identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

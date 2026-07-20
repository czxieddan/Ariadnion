//! New-target RNMDB restore orchestration with evidence-bound switching.

use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::SystemTime;

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{SchemaVersion, StorageError, StorageErrorCode, StorageInstanceId};
use ariadnion_storage_restore::{
    AtomicSwitchAuthorization, AvailableStorageBytes, MAX_SHADOW_SAMPLE_RECORDS, RestorePort,
    RestorePreflightEvidence, RestoreReceipt, RestoreRequest, RestoreResourceEvidence,
    RestoreVerificationChecks, RestoreVerificationEvidence, ShadowAccessMode, ShadowSampleEvidence,
    ShadowSampleLimit, VerificationObservation, VerifiedRestoreSource,
};

use crate::file_integrity::digest_location;
use crate::{PageKeyMaterial, RnmdbMaintenance, StorageFileLocation, VerificationSummary};

/// Application-level verification facts for one restored RNMDB target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnmdbRestoreDomainVerification {
    schema: SchemaVersion,
    schema_check: VerificationObservation,
    audit_chain: VerificationObservation,
    referential_integrity: VerificationObservation,
    business_invariants: VerificationObservation,
}

impl RnmdbRestoreDomainVerification {
    /// Creates complete domain verification facts without database row types.
    #[must_use]
    pub const fn new(
        schema: SchemaVersion,
        schema_check: VerificationObservation,
        audit_chain: VerificationObservation,
        referential_integrity: VerificationObservation,
        business_invariants: VerificationObservation,
    ) -> Self {
        Self {
            schema,
            schema_check,
            audit_chain,
            referential_integrity,
            business_invariants,
        }
    }

    /// Returns the verified application schema version.
    #[must_use]
    pub const fn schema(self) -> SchemaVersion {
        self.schema
    }

    /// Returns the schema verification summary.
    #[must_use]
    pub const fn schema_check(self) -> VerificationObservation {
        self.schema_check
    }

    /// Returns the audit-chain verification summary.
    #[must_use]
    pub const fn audit_chain(self) -> VerificationObservation {
        self.audit_chain
    }

    /// Returns the referential-integrity verification summary.
    #[must_use]
    pub const fn referential_integrity(self) -> VerificationObservation {
        self.referential_integrity
    }

    /// Returns the business-invariant verification summary.
    #[must_use]
    pub const fn business_invariants(self) -> VerificationObservation {
        self.business_invariants
    }
}

/// Bounded result returned by a trusted read-only shadow comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnmdbShadowComparison {
    mode: ShadowAccessMode,
    observed: u32,
    mismatches: u32,
}

impl RnmdbShadowComparison {
    /// Creates a bounded comparison result.
    ///
    /// # Errors
    ///
    /// Impossible counts are invalid and counts above the platform sample cap
    /// return resource exhaustion.
    pub fn new(
        mode: ShadowAccessMode,
        observed: u32,
        mismatches: u32,
    ) -> Result<Self, StorageError> {
        if observed > MAX_SHADOW_SAMPLE_RECORDS {
            return Err(resource_exhausted());
        }
        if mismatches > observed {
            return Err(invalid_argument());
        }
        Ok(Self {
            mode,
            observed,
            mismatches,
        })
    }

    /// Returns the access mode observed by the comparison.
    #[must_use]
    pub const fn mode(self) -> ShadowAccessMode {
        self.mode
    }

    /// Returns the number of records compared.
    #[must_use]
    pub const fn observed(self) -> u32 {
        self.observed
    }

    /// Returns the mismatch count.
    #[must_use]
    pub const fn mismatches(self) -> u32 {
        self.mismatches
    }
}

/// Resolves trusted resources and application checks around physical restore.
pub trait RnmdbRestoreEnvironment: Send + Sync {
    /// Resolves a verified backup identity to its redacted RNMDB location.
    fn resolve_source(
        &self,
        source: &VerifiedRestoreSource,
        context: &RequestContext,
    ) -> Result<StorageFileLocation, StorageError>;

    /// Resolves an active or target instance to a redacted RNMDB location.
    fn resolve_instance(
        &self,
        instance: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<StorageFileLocation, StorageError>;

    /// Supplies fresh source page-key material for one authentication attempt.
    ///
    /// Restore preserves the source page key. Key rotation is a separate
    /// new-target upgrade operation.
    fn fresh_page_key(
        &self,
        source: &VerifiedRestoreSource,
        context: &RequestContext,
    ) -> Result<PageKeyMaterial, StorageError>;

    /// Reports bounded capacity available to the new target.
    fn available_storage(
        &self,
        target: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<AvailableStorageBytes, StorageError>;

    /// Returns whether source, target, and switch permissions are available.
    fn permissions_available(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<bool, StorageError>;

    /// Verifies schema, audit chain, references, and business invariants.
    fn verify_domains(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<RnmdbRestoreDomainVerification, StorageError>;

    /// Compares a bounded sample with both instances opened read-only.
    fn compare_shadow(
        &self,
        request: &RestoreRequest,
        limit: ShadowSampleLimit,
        context: &RequestContext,
    ) -> Result<RnmdbShadowComparison, StorageError>;

    /// Returns the active instance immediately before a guarded operation.
    fn current_active(&self, context: &RequestContext) -> Result<StorageInstanceId, StorageError>;

    /// Atomically switches from the expected active instance to the target.
    ///
    /// An error must leave the active selection unchanged. Success returns a
    /// trusted UTC switch time no earlier than the authorization time.
    fn atomic_switch(
        &self,
        expected: &StorageInstanceId,
        target: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<SystemTime, StorageError>;
}

/// Restores RNMDB files to isolated targets and coordinates explicit switching.
pub struct RnmdbRestoreAdapter {
    environment: Arc<dyn RnmdbRestoreEnvironment>,
    maintenance: Mutex<()>,
}

impl RnmdbRestoreAdapter {
    /// Creates a restore adapter with one trusted environment.
    #[must_use]
    pub fn new(environment: Arc<dyn RnmdbRestoreEnvironment>) -> Self {
        Self {
            environment,
            maintenance: Mutex::new(()),
        }
    }

    fn resolve_locations(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<ResolvedRestoreLocations, StorageError> {
        let source = self.environment.resolve_source(request.source(), context)?;
        let active = self
            .environment
            .resolve_instance(request.active(), context)?;
        let target = self
            .environment
            .resolve_instance(request.target(), context)?;
        require_instance_binding(request.active(), &active)?;
        require_instance_binding(request.target(), &target)?;
        require_distinct_locations(&source, &active, &target)?;
        Ok(ResolvedRestoreLocations { source, target })
    }

    fn authenticate(
        &self,
        source: &VerifiedRestoreSource,
        location: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<VerificationSummary, StorageError> {
        let key = self.environment.fresh_page_key(source, context)?;
        let summary = RnmdbMaintenance::verify(location, key, context)?;
        require_authenticated(&summary)?;
        Ok(summary)
    }

    fn verify_source(
        &self,
        request: &RestoreRequest,
        location: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<VerificationSummary, StorageError> {
        let summary = self.authenticate(request.source(), location, context)?;
        require_digest(request.source(), location, &summary, context)?;
        Ok(summary)
    }

    fn require_current_active(
        &self,
        expected: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        if self.environment.current_active(context)? != *expected {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        Ok(())
    }

    fn run_preflight(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<RestorePreflightEvidence, StorageError> {
        let locations = self.resolve_locations(request, context)?;
        self.require_current_active(request.active(), context)?;
        let source = self.verify_source(request, &locations.source, context)?;
        let dry_run =
            RnmdbMaintenance::restore_preflight(&locations.source, &locations.target, context)?;
        validate_dry_run(&source, &dry_run)?;
        let resources = self.preflight_resources(request, dry_run.bytes_to_restore(), context)?;
        Ok(RestorePreflightEvidence::new(
            request.source().clone(),
            request.active().clone(),
            request.target().clone(),
            !dry_run.target_exists(),
            resources,
        ))
    }

    fn preflight_resources(
        &self,
        request: &RestoreRequest,
        bytes_to_restore: u64,
        context: &RequestContext,
    ) -> Result<RestoreResourceEvidence, StorageError> {
        let available = self
            .environment
            .available_storage(request.target(), context)?;
        if bytes_to_restore > available.bytes() {
            return Err(resource_exhausted());
        }
        let permissions = self.environment.permissions_available(request, context)?;
        Ok(RestoreResourceEvidence::new(available, permissions, true))
    }

    fn prepare_restore(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<PreparedRestore, StorageError> {
        let locations = self.resolve_locations(request, context)?;
        self.require_current_active(request.active(), context)?;
        let source = self.verify_source(request, &locations.source, context)?;
        let dry_run =
            RnmdbMaintenance::restore_preflight(&locations.source, &locations.target, context)?;
        validate_dry_run(&source, &dry_run)?;
        Ok(PreparedRestore {
            locations,
            source,
            dry_run,
        })
    }

    fn run_restore(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let prepared = self.prepare_restore(request, context)?;
        let restored = RnmdbMaintenance::restore(
            &prepared.locations.source,
            &prepared.locations.target,
            prepared.dry_run,
            context,
        )?;
        validate_restore_result(&prepared.source, restored)
    }

    fn run_verification(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<RestoreVerificationEvidence, StorageError> {
        self.require_current_active(request.active(), context)?;
        let locations = self.resolve_locations(request, context)?;
        let target = self.authenticate(request.source(), &locations.target, context)?;
        require_digest(request.source(), &locations.target, &target, context)?;
        let domains = self.environment.verify_domains(request, context)?;
        build_verification_evidence(request, domains)
    }
}

impl Debug for RnmdbRestoreAdapter {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbRestoreAdapter")
            .field("environment", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RestorePort for RnmdbRestoreAdapter {
    fn preflight(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<RestorePreflightEvidence, StorageError> {
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.run_preflight(request, context)
    }

    fn restore_to_new_target(
        &self,
        request: &RestoreRequest,
        preflight: &RestorePreflightEvidence,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        if !preflight.permits(request) {
            return Err(integrity_failure());
        }
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.run_restore(request, context)
    }

    fn verify_new_target(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<RestoreVerificationEvidence, StorageError> {
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.run_verification(request, context)
    }

    fn sample_read_only_shadow(
        &self,
        request: &RestoreRequest,
        verification: &RestoreVerificationEvidence,
        limit: ShadowSampleLimit,
        context: &RequestContext,
    ) -> Result<ShadowSampleEvidence, StorageError> {
        if !verification.permits(request) {
            return Err(integrity_failure());
        }
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.require_current_active(request.active(), context)?;
        let comparison = self.environment.compare_shadow(request, limit, context)?;
        if comparison.observed > limit.get() {
            return Err(integrity_failure());
        }
        ShadowSampleEvidence::new(
            request.active().clone(),
            request.target().clone(),
            request.source().digest(),
            comparison.mode,
            limit,
            comparison.observed,
            comparison.mismatches,
        )
    }

    fn atomic_switch(
        &self,
        authorization: AtomicSwitchAuthorization,
        context: &RequestContext,
    ) -> Result<RestoreReceipt, StorageError> {
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.require_current_active(authorization.expected_active(), context)?;
        let switched_at = self.environment.atomic_switch(
            authorization.expected_active(),
            authorization.target(),
            context,
        )?;
        RestoreReceipt::new(authorization, switched_at)
    }
}

struct ResolvedRestoreLocations {
    source: StorageFileLocation,
    target: StorageFileLocation,
}

struct PreparedRestore {
    locations: ResolvedRestoreLocations,
    source: VerificationSummary,
    dry_run: crate::RestorePreflight,
}

fn build_verification_evidence(
    request: &RestoreRequest,
    domains: RnmdbRestoreDomainVerification,
) -> Result<RestoreVerificationEvidence, StorageError> {
    let checks = RestoreVerificationChecks::new(
        VerificationObservation::new(1, 0)?,
        domains.schema_check(),
        domains.audit_chain(),
        domains.referential_integrity(),
        domains.business_invariants(),
    );
    Ok(RestoreVerificationEvidence::new(
        request.target().clone(),
        request.source().digest(),
        domains.schema(),
        checks,
    ))
}

fn validate_dry_run(
    source: &VerificationSummary,
    dry_run: &crate::RestorePreflight,
) -> Result<(), StorageError> {
    if !dry_run.backup_valid() {
        return Err(integrity_failure());
    }
    if dry_run.bytes_to_restore() != source.file_len_bytes() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_restore_result(
    source: &VerificationSummary,
    restored: crate::NewTargetSummary,
) -> Result<(), StorageError> {
    let bytes_match = restored.bytes_written() == source.file_len_bytes();
    let pages_match = restored.page_records() == source.present_page_records();
    if !bytes_match || !pages_match {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_digest(
    source: &VerifiedRestoreSource,
    location: &StorageFileLocation,
    summary: &VerificationSummary,
    context: &RequestContext,
) -> Result<(), StorageError> {
    let digest = digest_location(location, summary.file_len_bytes(), context)?;
    if digest != *source.digest().as_bytes() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_authenticated(summary: &VerificationSummary) -> Result<(), StorageError> {
    if !summary.is_valid() || !summary.encryption_authenticated() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_instance_binding(
    expected: &StorageInstanceId,
    location: &StorageFileLocation,
) -> Result<(), StorageError> {
    if expected != location.instance() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_distinct_locations(
    source: &StorageFileLocation,
    active: &StorageFileLocation,
    target: &StorageFileLocation,
) -> Result<(), StorageError> {
    if source.path() == target.path()
        || active.path() == target.path()
        || source.path() == active.path()
    {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn lock_maintenance(gate: &Mutex<()>) -> Result<MutexGuard<'_, ()>, StorageError> {
    match gate.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => Err(unavailable()),
        Err(TryLockError::Poisoned(_)) => Err(internal()),
    }
}

fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => StorageError::new(StorageErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => StorageError::new(StorageErrorCode::DeadlineExceeded),
        _ => internal(),
    })
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

const fn unavailable() -> StorageError {
    StorageError::new(StorageErrorCode::Unavailable)
}

const fn internal() -> StorageError {
    StorageError::new(StorageErrorCode::Internal)
}

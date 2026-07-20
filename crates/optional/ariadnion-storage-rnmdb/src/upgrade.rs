//! Evidence-bound RNMDB upgrades that preserve the immutable source.

use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::io::ErrorKind as IoErrorKind;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{StorageError, StorageErrorCode, StorageInstanceId};
use ariadnion_storage_upgrade::{
    DatabaseFormatWindow, InactiveUpgradeTarget, PreflightAccessEvidence, RetainedSourceEvidence,
    Sha256Digest, StorageUpgradePort, StorageVersionState, SwitchAuthorization, SwitchPurpose,
    SwitchReceipt, UpgradePlan, UpgradePreflightEvidence, UpgradeSource, UpgradeStep,
    UpgradeVerificationChecks, UpgradeVerificationEvidence, VerifiedBackupEvidence,
};
use rnmdb_storage::SINGLE_FILE_FORMAT_VERSION;

use crate::file_integrity::digest_location;
use crate::{PageKeyMaterial, RnmdbMaintenance, StorageFileLocation, UpgradeSummary};

/// Trusted application-level observations for one inactive upgrade target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RnmdbUpgradeDomainVerification {
    observed_state: StorageVersionState,
    schema_valid: bool,
    domain_valid: bool,
}

impl RnmdbUpgradeDomainVerification {
    /// Creates read-only target observations without paths or key material.
    #[must_use]
    pub const fn new(
        observed_state: StorageVersionState,
        schema_valid: bool,
        domain_valid: bool,
    ) -> Self {
        Self {
            observed_state,
            schema_valid,
            domain_valid,
        }
    }

    /// Returns the exact format, schema, and public key-version state observed.
    #[must_use]
    pub const fn observed_state(&self) -> &StorageVersionState {
        &self.observed_state
    }

    /// Returns whether the application schema passed structural verification.
    #[must_use]
    pub const fn schema_valid(&self) -> bool {
        self.schema_valid
    }

    /// Returns whether all registered application invariants passed.
    #[must_use]
    pub const fn domain_valid(&self) -> bool {
        self.domain_valid
    }
}

/// Trusted read-only observations for a retained pre-upgrade source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RnmdbRetainedSourceInspection {
    observed: UpgradeSource,
    checks: UpgradeVerificationChecks,
    key_available: bool,
}

impl RnmdbRetainedSourceInspection {
    /// Creates retained-source observations without filesystem or key details.
    #[must_use]
    pub const fn new(
        observed: UpgradeSource,
        checks: UpgradeVerificationChecks,
        key_available: bool,
    ) -> Self {
        Self {
            observed,
            checks,
            key_available,
        }
    }

    /// Returns the authenticated source identity, digest, and version state.
    #[must_use]
    pub const fn observed(&self) -> &UpgradeSource {
        &self.observed
    }

    /// Returns the read-only authentication and structural checks.
    #[must_use]
    pub const fn checks(&self) -> UpgradeVerificationChecks {
        self.checks
    }

    /// Returns whether the retained source key is still available.
    #[must_use]
    pub const fn key_available(&self) -> bool {
        self.key_available
    }
}

/// Supplies trusted locations, secrets, evidence, and atomic selection changes.
pub trait RnmdbUpgradeEnvironment: Send + Sync {
    /// Resolves an instance to a redacted location owned by that identity.
    fn resolve_instance(
        &self,
        instance: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<StorageFileLocation, StorageError>;

    /// Supplies fresh source key material bound to the plan's source key version.
    fn fresh_source_page_key(
        &self,
        plan: &UpgradePlan,
        context: &RequestContext,
    ) -> Result<PageKeyMaterial, StorageError>;

    /// Supplies fresh target key material bound to the plan's target key version.
    fn fresh_target_page_key(
        &self,
        plan: &UpgradePlan,
        context: &RequestContext,
    ) -> Result<PageKeyMaterial, StorageError>;

    /// Reports bounded capacity available for the exact plan and target.
    fn available_storage_bytes(
        &self,
        plan: &UpgradePlan,
        required_bytes: u64,
        context: &RequestContext,
    ) -> Result<u64, StorageError>;

    /// Reports source, target, switch, backup-key, and page-key access checks.
    fn access_evidence(
        &self,
        plan: &UpgradePlan,
        backup: &VerifiedBackupEvidence,
        context: &RequestContext,
    ) -> Result<PreflightAccessEvidence, StorageError>;

    /// Returns the active instance immediately before a guarded operation.
    fn current_active(&self, context: &RequestContext) -> Result<StorageInstanceId, StorageError>;

    /// Verifies schema and domain state with the inactive target opened read-only.
    fn verify_target_domains(
        &self,
        plan: &UpgradePlan,
        context: &RequestContext,
    ) -> Result<RnmdbUpgradeDomainVerification, StorageError>;

    /// Revalidates a retained source and its durable forward-switch ledger entry.
    ///
    /// The implementation must reject missing or inconsistent ledger entries,
    /// perform no migration or reverse SQL, and leave both instances unchanged.
    fn inspect_retained_source(
        &self,
        receipt: &SwitchReceipt,
        context: &RequestContext,
    ) -> Result<RnmdbRetainedSourceInspection, StorageError>;

    /// Atomically compares active identity, consumes authorization, and switches.
    ///
    /// The implementation must authenticate the selected instance bytes against
    /// `authorization.selected_digest()`. The one-shot authorization identity,
    /// purpose, plan digest, and selected digest must be written durably in the
    /// same atomic operation as active-pointer selection. A digest mismatch,
    /// replay, or active mismatch returns an error without changing selection.
    fn atomic_compare_consume_and_switch(
        &self,
        authorization: &SwitchAuthorization,
        context: &RequestContext,
    ) -> Result<(), StorageError>;
}

/// Executes supported RNMDB upgrades into isolated inactive targets.
///
/// This adapter accepts only RNMDB's physical legacy-v1 to current-v2 file
/// transform, optionally with page-key rotation. Registered application-schema
/// transitions remain the responsibility of [`crate::RnmdbMigrationExecutor`];
/// plans containing schema steps are rejected before any target write.
pub struct RnmdbUpgradeAdapter {
    environment: Arc<dyn RnmdbUpgradeEnvironment>,
    maintenance: Mutex<()>,
}

impl RnmdbUpgradeAdapter {
    /// Creates an upgrade adapter over one trusted environment.
    #[must_use]
    pub fn new(environment: Arc<dyn RnmdbUpgradeEnvironment>) -> Self {
        Self {
            environment,
            maintenance: Mutex::new(()),
        }
    }

    fn resolve_locations(
        &self,
        plan: &UpgradePlan,
        context: &RequestContext,
    ) -> Result<UpgradeLocations, StorageError> {
        let source = self
            .environment
            .resolve_instance(&plan.source().instance, context)?;
        let target = self.environment.resolve_instance(plan.target(), context)?;
        require_instance_binding(&plan.source().instance, &source)?;
        require_instance_binding(plan.target(), &target)?;
        require_distinct_locations(&source, &target)?;
        Ok(UpgradeLocations { source, target })
    }

    fn require_current_active(
        &self,
        expected: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        if self.environment.current_active(context)? != *expected {
            return Err(conflict());
        }
        Ok(())
    }

    fn bind_source(
        &self,
        plan: &UpgradePlan,
        location: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<u64, StorageError> {
        let file_len = source_file_len(location)?;
        let digest = digest_location(location, file_len, context)?;
        if digest != plan.source().digest.0 {
            return Err(integrity_failure());
        }
        Ok(file_len)
    }

    fn run_preflight(
        &self,
        plan: &UpgradePlan,
        backup: &VerifiedBackupEvidence,
        context: &RequestContext,
    ) -> Result<UpgradePreflightEvidence, StorageError> {
        validate_supported_plan(plan)?;
        self.require_current_active(&plan.source().instance, context)?;
        let locations = self.resolve_locations(plan, context)?;
        let required_bytes = self.bind_source(plan, &locations.source, context)?;
        let target_empty = target_absent(&locations.target)?;
        let available_bytes =
            self.environment
                .available_storage_bytes(plan, required_bytes, context)?;
        let access = self.environment.access_evidence(plan, backup, context)?;
        UpgradePreflightEvidence::new(
            plan,
            backup,
            target_empty,
            required_bytes,
            available_bytes,
            access,
        )
    }

    fn run_upgrade(
        &self,
        plan: &UpgradePlan,
        preflight: &UpgradePreflightEvidence,
        context: &RequestContext,
    ) -> Result<InactiveUpgradeTarget, StorageError> {
        let (physical_plan, locations) = self.prepare_upgrade(plan, context)?;
        let (source_key, target_key) = self.upgrade_keys(plan, context)?;
        let summary = RnmdbMaintenance::upgrade(
            &locations.source,
            &locations.target,
            source_key,
            target_key,
            context,
        )?;
        finish_upgrade(plan, preflight, physical_plan, summary)
    }

    fn prepare_upgrade(
        &self,
        plan: &UpgradePlan,
        context: &RequestContext,
    ) -> Result<(PhysicalUpgradePlan, UpgradeLocations), StorageError> {
        let physical_plan = validate_supported_plan(plan)?;
        self.require_current_active(&plan.source().instance, context)?;
        let locations = self.resolve_locations(plan, context)?;
        self.bind_source(plan, &locations.source, context)?;
        require_target_absent(&locations.target)?;
        Ok((physical_plan, locations))
    }

    fn upgrade_keys(
        &self,
        plan: &UpgradePlan,
        context: &RequestContext,
    ) -> Result<(PageKeyMaterial, PageKeyMaterial), StorageError> {
        let source = self.environment.fresh_source_page_key(plan, context)?;
        let target = self.environment.fresh_target_page_key(plan, context)?;
        Ok((source, target))
    }

    fn prepare_target_verification(
        &self,
        plan: &UpgradePlan,
        target: &InactiveUpgradeTarget,
        context: &RequestContext,
    ) -> Result<UpgradeLocations, StorageError> {
        require_target_binding(plan, target)?;
        self.require_current_active(&plan.source().instance, context)?;
        let locations = self.resolve_locations(plan, context)?;
        require_target_present(&locations.target)?;
        Ok(locations)
    }

    fn verify_physical_target(
        &self,
        plan: &UpgradePlan,
        location: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<Sha256Digest, StorageError> {
        let key = self.environment.fresh_target_page_key(plan, context)?;
        let physical = RnmdbMaintenance::verify(location, key, context)?;
        validate_target_physical(plan, location, &physical, context)
    }

    fn verify_target_domains(
        &self,
        plan: &UpgradePlan,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let domains = self.environment.verify_target_domains(plan, context)?;
        validate_target_domains(plan, &domains)
    }

    fn run_target_verification(
        &self,
        plan: &UpgradePlan,
        target: &InactiveUpgradeTarget,
        context: &RequestContext,
    ) -> Result<UpgradeVerificationEvidence, StorageError> {
        let locations = self.prepare_target_verification(plan, target, context)?;
        let target_digest = self.verify_physical_target(plan, &locations.target, context)?;
        self.verify_target_domains(plan, context)?;
        build_target_verification(plan, target, target_digest)
    }

    fn run_retained_inspection(
        &self,
        receipt: &SwitchReceipt,
        context: &RequestContext,
    ) -> Result<RetainedSourceEvidence, StorageError> {
        require_forward_receipt(receipt)?;
        self.require_current_active(receipt.active(), context)?;
        let location = self
            .environment
            .resolve_instance(receipt.previous_active(), context)?;
        require_instance_binding(receipt.previous_active(), &location)?;
        let inspection = self.environment.inspect_retained_source(receipt, context)?;
        validate_retained_observation(receipt, &location, &inspection, context)?;
        Ok(RetainedSourceEvidence::new(
            inspection.observed,
            inspection.checks,
            inspection.key_available,
        ))
    }
}

impl Debug for RnmdbUpgradeAdapter {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbUpgradeAdapter")
            .field("environment", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl StorageUpgradePort for RnmdbUpgradeAdapter {
    fn preflight(
        &self,
        plan: &UpgradePlan,
        backup: &VerifiedBackupEvidence,
        context: &RequestContext,
    ) -> Result<UpgradePreflightEvidence, StorageError> {
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.run_preflight(plan, backup, context)
    }

    fn execute_to_new_target(
        &self,
        plan: &UpgradePlan,
        preflight: &UpgradePreflightEvidence,
        context: &RequestContext,
    ) -> Result<InactiveUpgradeTarget, StorageError> {
        if !preflight.permits(plan) {
            return Err(integrity_failure());
        }
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.run_upgrade(plan, preflight, context)
    }

    fn verify_new_target(
        &self,
        plan: &UpgradePlan,
        target: &InactiveUpgradeTarget,
        context: &RequestContext,
    ) -> Result<UpgradeVerificationEvidence, StorageError> {
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.run_target_verification(plan, target, context)
    }

    fn inspect_retained_source(
        &self,
        upgrade_switch: &SwitchReceipt,
        context: &RequestContext,
    ) -> Result<RetainedSourceEvidence, StorageError> {
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.run_retained_inspection(upgrade_switch, context)
    }

    fn atomic_switch(
        &self,
        authorization: SwitchAuthorization,
        context: &RequestContext,
    ) -> Result<SwitchReceipt, StorageError> {
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        self.require_current_active(authorization.expected_active(), context)?;
        self.environment
            .atomic_compare_consume_and_switch(&authorization, context)?;
        Ok(SwitchReceipt::from_authorization(authorization))
    }
}

#[derive(Clone, Copy)]
struct PhysicalUpgradePlan {
    format: DatabaseFormatWindow,
    rotates_key: bool,
}

struct UpgradeLocations {
    source: StorageFileLocation,
    target: StorageFileLocation,
}

fn finish_upgrade(
    plan: &UpgradePlan,
    preflight: &UpgradePreflightEvidence,
    physical: PhysicalUpgradePlan,
    summary: UpgradeSummary,
) -> Result<InactiveUpgradeTarget, StorageError> {
    validate_upgrade_summary(plan, physical, summary)?;
    let applied_steps = applied_step_count(plan)?;
    InactiveUpgradeTarget::new(plan, preflight, applied_steps)
}

fn build_target_verification(
    plan: &UpgradePlan,
    target: &InactiveUpgradeTarget,
    target_digest: Sha256Digest,
) -> Result<UpgradeVerificationEvidence, StorageError> {
    let checks = UpgradeVerificationChecks {
        authentication_passed: true,
        structure_valid: true,
    };
    UpgradeVerificationEvidence::new(plan, target, target_digest, checks)
}

fn validate_supported_plan(plan: &UpgradePlan) -> Result<PhysicalUpgradePlan, StorageError> {
    let physical = extract_physical_plan(plan)?;
    validate_format_window(plan, physical.format)?;
    validate_key_transition(plan, physical.rotates_key)?;
    Ok(physical)
}

fn extract_physical_plan(plan: &UpgradePlan) -> Result<PhysicalUpgradePlan, StorageError> {
    let mut format = None;
    let mut rotates_key = false;
    for step in plan.steps() {
        match step {
            UpgradeStep::DatabaseFormat(window) => {
                if format.replace(*window).is_some() {
                    return Err(migration_required());
                }
            }
            UpgradeStep::ApplicationSchema(_) => return Err(migration_required()),
            UpgradeStep::KeyRotation(_) => {
                if rotates_key {
                    return Err(migration_required());
                }
                rotates_key = true;
            }
        }
    }
    let format = format.ok_or_else(migration_required)?;
    Ok(PhysicalUpgradePlan {
        format,
        rotates_key,
    })
}

fn validate_format_window(
    plan: &UpgradePlan,
    format: DatabaseFormatWindow,
) -> Result<(), StorageError> {
    let target_format = u32::from(SINGLE_FILE_FORMAT_VERSION);
    let Some(source_format) = target_format.checked_sub(1) else {
        return Err(migration_required());
    };
    if format.from().get() != source_format || format.to().get() != target_format {
        return Err(migration_required());
    }
    if plan.source().state.format != format.from() {
        return Err(integrity_failure());
    }
    if plan.target_state().format != format.to() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_key_transition(plan: &UpgradePlan, rotates_key: bool) -> Result<(), StorageError> {
    let keys_differ = plan.source().state.key_version != plan.target_state().key_version;
    if keys_differ != rotates_key {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_upgrade_summary(
    plan: &UpgradePlan,
    physical: PhysicalUpgradePlan,
    summary: UpgradeSummary,
) -> Result<(), StorageError> {
    if u32::from(summary.source_format_version()) != physical.format.from().get() {
        return Err(integrity_failure());
    }
    if u32::from(summary.target_format_version()) != physical.format.to().get() {
        return Err(integrity_failure());
    }
    if physical.rotates_key && summary.pages_upgraded() == 0 {
        return Err(migration_required());
    }
    if summary.key_rotated() != physical.rotates_key {
        return Err(integrity_failure());
    }
    if summary.bytes_written() == 0 {
        return Err(integrity_failure());
    }
    validate_reported_state(plan, summary)
}

fn validate_reported_state(
    plan: &UpgradePlan,
    summary: UpgradeSummary,
) -> Result<(), StorageError> {
    if u32::from(summary.source_format_version()) != plan.source().state.format.get() {
        return Err(integrity_failure());
    }
    if u32::from(summary.target_format_version()) != plan.target_state().format.get() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_target_physical(
    plan: &UpgradePlan,
    location: &StorageFileLocation,
    summary: &crate::VerificationSummary,
    context: &RequestContext,
) -> Result<Sha256Digest, StorageError> {
    if !summary.is_valid() {
        return Err(integrity_failure());
    }
    if u32::from(summary.format_version()) != plan.target_state().format.get() {
        return Err(integrity_failure());
    }
    if summary.present_page_records() > 0 && !summary.encryption_authenticated() {
        return Err(integrity_failure());
    }
    digest_location(location, summary.file_len_bytes(), context).map(Sha256Digest)
}

fn validate_target_domains(
    plan: &UpgradePlan,
    domains: &RnmdbUpgradeDomainVerification,
) -> Result<(), StorageError> {
    if domains.observed_state != *plan.target_state() {
        return Err(integrity_failure());
    }
    if !domains.schema_valid || !domains.domain_valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_retained_observation(
    receipt: &SwitchReceipt,
    location: &StorageFileLocation,
    inspection: &RnmdbRetainedSourceInspection,
    context: &RequestContext,
) -> Result<(), StorageError> {
    if inspection.observed.instance != *receipt.previous_active() {
        return Err(integrity_failure());
    }
    if !inspection.checks.authentication_passed || !inspection.checks.structure_valid {
        return Err(integrity_failure());
    }
    if !inspection.key_available {
        return Err(integrity_failure());
    }
    let file_len = source_file_len(location)?;
    let digest = digest_location(location, file_len, context)?;
    if digest != inspection.observed.digest.0 {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_forward_receipt(receipt: &SwitchReceipt) -> Result<(), StorageError> {
    if receipt.purpose() != SwitchPurpose::ActivateUpgrade {
        return Err(conflict());
    }
    Ok(())
}

fn require_target_binding(
    plan: &UpgradePlan,
    target: &InactiveUpgradeTarget,
) -> Result<(), StorageError> {
    if target.target() != plan.target() || target.state() != plan.target_state() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_instance_binding(
    expected: &StorageInstanceId,
    location: &StorageFileLocation,
) -> Result<(), StorageError> {
    if location.instance() != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_distinct_locations(
    source: &StorageFileLocation,
    target: &StorageFileLocation,
) -> Result<(), StorageError> {
    if source.path() == target.path() {
        return Err(conflict());
    }
    Ok(())
}

fn source_file_len(location: &StorageFileLocation) -> Result<u64, StorageError> {
    let metadata = fs::metadata(location.path()).map_err(map_io_error)?;
    if !metadata.is_file() {
        return Err(StorageError::new(StorageErrorCode::NotFound));
    }
    Ok(metadata.len())
}

fn target_absent(location: &StorageFileLocation) -> Result<bool, StorageError> {
    location
        .path()
        .try_exists()
        .map(|exists| !exists)
        .map_err(map_io_error)
}

fn require_target_absent(location: &StorageFileLocation) -> Result<(), StorageError> {
    if !target_absent(location)? {
        return Err(conflict());
    }
    Ok(())
}

fn require_target_present(location: &StorageFileLocation) -> Result<(), StorageError> {
    if target_absent(location)? {
        return Err(StorageError::new(StorageErrorCode::NotFound));
    }
    Ok(())
}

fn applied_step_count(plan: &UpgradePlan) -> Result<u16, StorageError> {
    u16::try_from(plan.steps().len()).map_err(|_| resource_exhausted())
}

fn map_io_error(error: std::io::Error) -> StorageError {
    match error.kind() {
        IoErrorKind::NotFound => StorageError::new(StorageErrorCode::NotFound),
        IoErrorKind::PermissionDenied => StorageError::new(StorageErrorCode::Unavailable),
        _ => StorageError::new(StorageErrorCode::Unavailable),
    }
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

const fn migration_required() -> StorageError {
    StorageError::new(StorageErrorCode::MigrationRequired)
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

const fn unavailable() -> StorageError {
    StorageError::new(StorageErrorCode::Unavailable)
}

const fn internal() -> StorageError {
    StorageError::new(StorageErrorCode::Internal)
}

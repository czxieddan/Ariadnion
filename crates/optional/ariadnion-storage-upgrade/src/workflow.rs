use ariadnion_storage_domain::{SchemaVersion, StorageError, StorageInstanceId};

use crate::model::{conflict, integrity_failure, invalid_argument, resource_exhausted};
use crate::{
    DatabaseFormatVersion, Sha256Digest, StorageVersionState, SwitchAuthorizationId, UpgradePlan,
};

const MAX_UPGRADE_BYTES: u64 = 1 << 50;

/// Authenticated reference to backup evidence for the exact source bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBackupEvidence {
    /// Backed-up source identity.
    pub source: StorageInstanceId,
    /// Exact backed-up source digest.
    pub source_digest: Sha256Digest,
    /// Digest of the upstream-authenticated evidence.
    pub evidence_digest: Sha256Digest,
}

/// Permission and key-availability facts required by preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreflightAccessEvidence {
    /// Source-read permission passed.
    pub source_readable: bool,
    /// New-target creation permission passed.
    pub target_creatable: bool,
    /// Active-selection switch permission passed.
    pub selection_switchable: bool,
    /// Backup verification key is available.
    pub backup_key_available: bool,
    /// Source decryption key is available.
    pub source_key_available: bool,
    /// Target encryption key is available.
    pub target_key_available: bool,
}

impl PreflightAccessEvidence {
    fn permits(self) -> bool {
        self.source_readable
            && self.target_creatable
            && self.selection_switchable
            && self.backup_key_available
            && self.source_key_available
            && self.target_key_available
    }
}

/// Plan-bound result of a non-mutating upgrade preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradePreflightEvidence {
    plan: UpgradePlan,
    backup_digest: Sha256Digest,
    target_empty: bool,
    required_bytes: u64,
    available_bytes: u64,
    access: PreflightAccessEvidence,
}

impl UpgradePreflightEvidence {
    /// Binds backup, target emptiness, bounded capacity, permissions, and keys.
    /// # Errors
    /// Returns `IntegrityFailure` for backup mismatch and `ResourceExhausted`
    /// when either capacity count exceeds one pebibyte.
    pub fn new(
        plan: &UpgradePlan,
        backup: &VerifiedBackupEvidence,
        target_empty: bool,
        required_bytes: u64,
        available_bytes: u64,
        access: PreflightAccessEvidence,
    ) -> Result<Self, StorageError> {
        validate_backup(plan, backup)?;
        validate_capacity(required_bytes, available_bytes)?;
        Ok(Self {
            plan: plan.clone(),
            backup_digest: backup.evidence_digest,
            target_empty,
            required_bytes,
            available_bytes,
            access,
        })
    }

    /// Returns whether the exact plan and every safety check permit execution.
    #[must_use]
    pub fn permits(&self, plan: &UpgradePlan) -> bool {
        self.matches_plan(plan) && self.safety_checks_pass()
    }

    /// Returns the digest of the verified backup evidence bound by preflight.
    #[must_use]
    pub const fn backup_digest(&self) -> Sha256Digest {
        self.backup_digest
    }

    fn matches_plan(&self, plan: &UpgradePlan) -> bool {
        &self.plan == plan
    }

    fn safety_checks_pass(&self) -> bool {
        self.target_empty && self.available_bytes >= self.required_bytes && self.access.permits()
    }
}

/// Exact result of complete execution in a still-inactive new target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InactiveUpgradeTarget {
    plan: UpgradePlan,
    applied_steps: u16,
}

impl InactiveUpgradeTarget {
    /// Records execution only when preflight passed and every step was applied.
    /// # Errors
    /// Returns `IntegrityFailure` for binding or step-count mismatch and
    /// `Conflict` when any preflight check failed.
    pub fn new(
        plan: &UpgradePlan,
        preflight: &UpgradePreflightEvidence,
        applied_steps: u16,
    ) -> Result<Self, StorageError> {
        if !preflight.matches_plan(plan) {
            return Err(integrity_failure());
        }
        if !preflight.safety_checks_pass() {
            return Err(conflict());
        }
        if usize::from(applied_steps) != plan.steps().len() {
            return Err(integrity_failure());
        }
        Ok(Self {
            plan: plan.clone(),
            applied_steps,
        })
    }

    /// Returns the new inactive target identity.
    #[must_use]
    pub const fn target(&self) -> &StorageInstanceId {
        self.plan.target()
    }

    /// Returns the exact final target state, including its key version.
    #[must_use]
    pub const fn state(&self) -> &StorageVersionState {
        self.plan.target_state()
    }

    fn matches_plan(&self, plan: &UpgradePlan) -> bool {
        &self.plan == plan && usize::from(self.applied_steps) == plan.steps().len()
    }
}

/// Authentication and structural checks required before a switch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeVerificationChecks {
    /// All target authentication checks passed.
    pub authentication_passed: bool,
    /// All structural checks passed.
    pub structure_valid: bool,
}

impl UpgradeVerificationChecks {
    const fn passes(self) -> bool {
        self.authentication_passed && self.structure_valid
    }
}

/// Evidence binding verification to source, exact plan, target, and key state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeVerificationEvidence {
    plan: UpgradePlan,
    target_digest: Sha256Digest,
    checks: UpgradeVerificationChecks,
}

impl UpgradeVerificationEvidence {
    /// Binds authentication and structure results to inactive execution.
    /// # Errors
    /// Returns `IntegrityFailure` unless execution matches the complete plan.
    pub fn new(
        plan: &UpgradePlan,
        target: &InactiveUpgradeTarget,
        target_digest: Sha256Digest,
        checks: UpgradeVerificationChecks,
    ) -> Result<Self, StorageError> {
        if !target.matches_plan(plan) {
            return Err(integrity_failure());
        }
        Ok(Self {
            plan: plan.clone(),
            target_digest,
            checks,
        })
    }

    fn permits(&self, plan: &UpgradePlan) -> bool {
        &self.plan == plan && self.checks.passes()
    }

    /// Returns the digest of the authenticated inactive target bytes.
    #[must_use]
    pub const fn target_digest(&self) -> Sha256Digest {
        self.target_digest
    }
}

/// Inclusive runtime read windows used only to approve rollback selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCompatibility {
    minimum_format: DatabaseFormatVersion,
    maximum_format: DatabaseFormatVersion,
    minimum_schema: SchemaVersion,
    maximum_schema: SchemaVersion,
}

impl RuntimeCompatibility {
    /// Creates ordered database-format and application-schema read windows.
    /// # Errors
    /// Returns `InvalidArgument` when either inclusive window is reversed.
    pub fn new(
        minimum_format: DatabaseFormatVersion,
        maximum_format: DatabaseFormatVersion,
        minimum_schema: SchemaVersion,
        maximum_schema: SchemaVersion,
    ) -> Result<Self, StorageError> {
        if minimum_format > maximum_format || minimum_schema > maximum_schema {
            return Err(invalid_argument());
        }
        Ok(Self {
            minimum_format,
            maximum_format,
            minimum_schema,
            maximum_schema,
        })
    }

    fn supports(self, state: &StorageVersionState) -> bool {
        state.format >= self.minimum_format
            && state.format <= self.maximum_format
            && state.schema >= self.minimum_schema
            && state.schema <= self.maximum_schema
    }
}

/// Stable reason for an atomic active-instance selection change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchPurpose {
    /// Select a completely verified new upgrade target.
    ActivateUpgrade,
    /// Select the verified retained source without transforming either instance.
    Rollback,
}

/// Evidence that the original source remains authentic, structured, and keyed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedSourceEvidence {
    observed: crate::UpgradeSource,
    checks: UpgradeVerificationChecks,
    key_available: bool,
}

impl RetainedSourceEvidence {
    /// Records an explicitly observed retained source without paths or key material.
    #[must_use]
    pub const fn new(
        observed: crate::UpgradeSource,
        checks: UpgradeVerificationChecks,
        key_available: bool,
    ) -> Self {
        Self {
            observed,
            checks,
            key_available,
        }
    }

    fn permits(&self, receipt: &SwitchReceipt, compatibility: RuntimeCompatibility) -> bool {
        self.observed == *receipt.plan.source()
            && self.checks.passes()
            && self.key_available
            && compatibility.supports(&self.observed.state)
    }
}

/// One-shot authorization bound to the active identity expected at switch time.
#[derive(Debug, Eq, PartialEq)]
pub struct SwitchAuthorization {
    id: SwitchAuthorizationId,
    purpose: SwitchPurpose,
    plan: UpgradePlan,
    selected_digest: Sha256Digest,
}

impl SwitchAuthorization {
    /// Creates forward authorization only from exact passing verification.
    /// # Errors
    /// Returns `IntegrityFailure` for failed checks or any plan mismatch.
    pub fn activate(
        id: SwitchAuthorizationId,
        plan: &UpgradePlan,
        verification: &UpgradeVerificationEvidence,
    ) -> Result<Self, StorageError> {
        if !verification.permits(plan) {
            return Err(integrity_failure());
        }
        Ok(Self {
            id,
            purpose: SwitchPurpose::ActivateUpgrade,
            plan: plan.clone(),
            selected_digest: verification.target_digest,
        })
    }

    /// Returns the authorization identity that must be consumed durably once.
    #[must_use]
    pub const fn id(&self) -> &SwitchAuthorizationId {
        &self.id
    }

    /// Returns whether this authorization activates or rolls back selection.
    #[must_use]
    pub const fn purpose(&self) -> SwitchPurpose {
        self.purpose
    }

    /// Returns the plan digest persisted with durable authorization consumption.
    #[must_use]
    pub const fn plan_digest(&self) -> Sha256Digest {
        self.plan.digest()
    }

    /// Creates rollback authorization only for a verified compatible retained source.
    /// # Errors
    /// Returns `Conflict` for a non-upgrade receipt and `IntegrityFailure` for
    /// retained-source, key, check, or compatibility mismatch.
    pub fn rollback(
        id: SwitchAuthorizationId,
        upgrade_switch: &SwitchReceipt,
        retained: &RetainedSourceEvidence,
        compatibility: RuntimeCompatibility,
    ) -> Result<Self, StorageError> {
        if upgrade_switch.purpose != SwitchPurpose::ActivateUpgrade {
            return Err(conflict());
        }
        if !retained.permits(upgrade_switch, compatibility) {
            return Err(integrity_failure());
        }
        Ok(Self {
            id,
            purpose: SwitchPurpose::Rollback,
            plan: upgrade_switch.plan.clone(),
            selected_digest: retained.observed.digest,
        })
    }

    /// Returns the identity that must still be active immediately before switching.
    #[must_use]
    pub const fn expected_active(&self) -> &StorageInstanceId {
        match self.purpose {
            SwitchPurpose::ActivateUpgrade => &self.plan.source().instance,
            SwitchPurpose::Rollback => self.plan.target(),
        }
    }

    /// Returns the distinct instance to select.
    #[must_use]
    pub const fn target(&self) -> &StorageInstanceId {
        match self.purpose {
            SwitchPurpose::ActivateUpgrade => self.plan.target(),
            SwitchPurpose::Rollback => &self.plan.source().instance,
        }
    }

    /// Returns the authenticated digest the atomic switch must select.
    #[must_use]
    pub const fn selected_digest(&self) -> Sha256Digest {
        self.selected_digest
    }

    /// Returns the exact state the atomic switch must revalidate and select.
    #[must_use]
    pub const fn selected_state(&self) -> &StorageVersionState {
        match self.purpose {
            SwitchPurpose::ActivateUpgrade => self.plan.target_state(),
            SwitchPurpose::Rollback => &self.plan.source().state,
        }
    }
}

/// Receipt returned only after an atomic selection switch consumes authorization.
#[derive(Debug, Eq, PartialEq)]
pub struct SwitchReceipt {
    authorization_id: SwitchAuthorizationId,
    purpose: SwitchPurpose,
    plan: UpgradePlan,
    selected_digest: Sha256Digest,
}

impl SwitchReceipt {
    /// Records a trusted adapter's completed durable comparison-and-switch.
    #[must_use]
    pub fn from_authorization(authorization: SwitchAuthorization) -> Self {
        Self {
            authorization_id: authorization.id,
            purpose: authorization.purpose,
            plan: authorization.plan,
            selected_digest: authorization.selected_digest,
        }
    }

    /// Returns the consumed authorization reference.
    #[must_use]
    pub const fn authorization_id(&self) -> &SwitchAuthorizationId {
        &self.authorization_id
    }

    /// Returns why active selection changed.
    #[must_use]
    pub const fn purpose(&self) -> SwitchPurpose {
        self.purpose
    }

    /// Returns the identity that was active before the switch.
    #[must_use]
    pub const fn previous_active(&self) -> &StorageInstanceId {
        match self.purpose {
            SwitchPurpose::ActivateUpgrade => &self.plan.source().instance,
            SwitchPurpose::Rollback => self.plan.target(),
        }
    }

    /// Returns the selected active identity.
    #[must_use]
    pub const fn active(&self) -> &StorageInstanceId {
        match self.purpose {
            SwitchPurpose::ActivateUpgrade => self.plan.target(),
            SwitchPurpose::Rollback => &self.plan.source().instance,
        }
    }

    /// Returns the exact forward plan digest retained across both directions.
    #[must_use]
    pub const fn plan_digest(&self) -> Sha256Digest {
        self.plan.digest()
    }

    /// Returns the authenticated digest selected by the atomic switch.
    #[must_use]
    pub const fn selected_digest(&self) -> Sha256Digest {
        self.selected_digest
    }
}

fn validate_backup(
    plan: &UpgradePlan,
    backup: &VerifiedBackupEvidence,
) -> Result<(), StorageError> {
    if backup.source != plan.source().instance {
        return Err(integrity_failure());
    }
    if backup.source_digest != plan.source().digest {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_capacity(required: u64, available: u64) -> Result<(), StorageError> {
    if required > MAX_UPGRADE_BYTES || available > MAX_UPGRADE_BYTES {
        return Err(resource_exhausted());
    }
    Ok(())
}

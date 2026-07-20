//! Database-independent contracts for safe new-target storage upgrades.
//!
//! Adapters may mutate only a distinct empty target, verify it while inactive,
//! and atomically select it after one-shot authorization. Rollback selects a
//! retained compatible source and never runs reverse SQL.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod workflow;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::StorageError;

pub use model::{
    ApplicationSchemaWindow, DatabaseFormatVersion, DatabaseFormatWindow, KeyRotationStep,
    KeyVersionId, MAX_UPGRADE_STEPS, Sha256Digest, StorageVersionState, SupportedVersionWindow,
    SwitchAuthorizationId, UpgradePlan, UpgradeSource, UpgradeStep,
};
pub use workflow::{
    InactiveUpgradeTarget, PreflightAccessEvidence, RetainedSourceEvidence, RuntimeCompatibility,
    SwitchAuthorization, SwitchPurpose, SwitchReceipt, UpgradePreflightEvidence,
    UpgradeVerificationChecks, UpgradeVerificationEvidence, VerifiedBackupEvidence,
};

/// Storage operations needed to execute and activate an immutable upgrade plan.
///
/// Implementations must observe cancellation and deadlines from `context`.
/// They expose no database handles, paths, SQL, raw configuration, or key
/// material. Every failure before an atomic switch leaves the source active and
/// unchanged; partial target output remains inactive.
pub trait StorageUpgradePort: Send + Sync {
    /// Performs a non-mutating check of backup, target, capacity, permissions, and keys.
    /// Returns stable storage errors for cancellation, deadlines, or failed evidence.
    fn preflight(
        &self,
        plan: &UpgradePlan,
        backup: &VerifiedBackupEvidence,
        context: &RequestContext,
    ) -> Result<UpgradePreflightEvidence, StorageError>;

    /// Applies every step to an empty inactive target without writing the source.
    /// Returns a stable error before publication on cancellation or changed preconditions.
    fn execute_to_new_target(
        &self,
        plan: &UpgradePlan,
        preflight: &UpgradePreflightEvidence,
        context: &RequestContext,
    ) -> Result<InactiveUpgradeTarget, StorageError>;

    /// Authenticates the target and validates its structure and exact final state.
    /// Returns a stable error for cancellation or any failed or mismatched check.
    fn verify_new_target(
        &self,
        plan: &UpgradePlan,
        target: &InactiveUpgradeTarget,
        context: &RequestContext,
    ) -> Result<UpgradeVerificationEvidence, StorageError>;

    /// Revalidates the unchanged retained source before rollback authorization.
    /// Returns a stable error for cancellation, changed bytes, structure, or keys.
    /// It rejects receipts absent from or inconsistent with the durable switch ledger.
    fn inspect_retained_source(
        &self,
        upgrade_switch: &SwitchReceipt,
        context: &RequestContext,
    ) -> Result<RetainedSourceEvidence, StorageError>;

    /// Atomically changes only active-instance selection and consumes authorization.
    ///
    /// The implementation must compare the current active identity with
    /// [`SwitchAuthorization::expected_active`] immediately before switching.
    /// While excluding concurrent process and environment writers, it must
    /// reauthenticate and structurally validate the exact selected bytes,
    /// validate their domain state against [`SwitchAuthorization::selected_state`],
    /// and compare their digest with [`SwitchAuthorization::selected_digest`].
    /// These checks, authorization consumption, and active selection form one
    /// failure-atomic boundary. It must durably reject an already consumed
    /// authorization identity.
    /// For [`SwitchPurpose::Rollback`], it must not execute schema changes,
    /// format transforms, key rotation, reverse SQL, or writes to either target.
    /// Returns `Conflict` for active/replay mismatch and stable interruption errors.
    fn atomic_switch(
        &self,
        authorization: SwitchAuthorization,
        context: &RequestContext,
    ) -> Result<SwitchReceipt, StorageError>;
}

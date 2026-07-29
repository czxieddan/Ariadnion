// crates/optional/ariadnion-storage-restore/src/lib.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Database-independent contracts for safe new-target storage restores.
//!
//! Restore adapters preflight without mutation, materialize only into a
//! distinct empty target, verify all integrity classes, sample both instances
//! read-only, and require explicit evidence-bound authorization before an
//! atomic switch. No database implementation type crosses this crate boundary.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::StorageError;

pub use model::{
    AtomicSwitchAuthorization, AtomicSwitchAuthorizationId, AvailableStorageBytes,
    MAX_SHADOW_SAMPLE_RECORDS, RestoreFailureEvidence, RestorePreflightEvidence, RestoreReceipt,
    RestoreRequest, RestoreResourceEvidence, RestoreSize, RestoreSourceDigest, RestoreSourceId,
    RestoreStage, RestoreTargetDisposition, RestoreVerificationChecks, RestoreVerificationEvidence,
    SchemaCompatibility, ShadowAccessMode, ShadowSampleEvidence, ShadowSampleLimit,
    VerificationObservation, VerifiedRestoreSource,
};

/// Database-independent operations required by a restore workflow.
///
/// Implementations may use an embedded database internally, but must expose
/// only these typed values and the shared redacted [`StorageError`]. Every
/// failure leaves the active instance unchanged; partial work remains isolated
/// under the target identity and can be described by [`RestoreFailureEvidence`].
pub trait RestorePort: Send + Sync {
    /// Performs a dry run without creating or mutating either instance.
    ///
    /// Evidence covers exact identities, target emptiness, source-schema
    /// compatibility, free space, permissions, and key availability.
    fn preflight(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<RestorePreflightEvidence, StorageError>;

    /// Materializes the verified source into the isolated new target.
    ///
    /// The adapter must reject evidence when
    /// [`RestorePreflightEvidence::permits`] is false. It must never write the
    /// active instance or overwrite a target that ceased to be empty.
    fn restore_to_new_target(
        &self,
        request: &RestoreRequest,
        preflight: &RestorePreflightEvidence,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Verifies the restored target without mutation.
    ///
    /// Evidence covers page authentication, schema validity, the audit chain,
    /// referential integrity, and business invariants.
    fn verify_new_target(
        &self,
        request: &RestoreRequest,
        context: &RequestContext,
    ) -> Result<RestoreVerificationEvidence, StorageError>;

    /// Compares a bounded sample while active and target are strictly read-only.
    ///
    /// The adapter must reject verification evidence when
    /// [`RestoreVerificationEvidence::permits`] is false.
    fn sample_read_only_shadow(
        &self,
        request: &RestoreRequest,
        verification: &RestoreVerificationEvidence,
        limit: ShadowSampleLimit,
        context: &RequestContext,
    ) -> Result<ShadowSampleEvidence, StorageError>;

    /// Atomically selects the explicitly authorized target as active.
    ///
    /// Immediately before switching, the adapter compares the current active
    /// identity with [`AtomicSwitchAuthorization::expected_active`]. A mismatch
    /// returns [`ariadnion_storage_domain::StorageErrorCode::Conflict`]. Any error leaves selection
    /// unchanged; success consumes the authorization and returns a receipt.
    fn atomic_switch(
        &self,
        authorization: AtomicSwitchAuthorization,
        context: &RequestContext,
    ) -> Result<RestoreReceipt, StorageError>;
}

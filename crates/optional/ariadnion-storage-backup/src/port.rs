// crates/optional/ariadnion-storage-backup/src/port.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
use std::time::SystemTime;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::StorageError;

use crate::{
    BackupCreateRequest, BackupId, BackupReceiptId, BackupVerificationEvidence,
    DeletionMarkReceipt, DeletionMarkRequest, LegalHoldReceipt, LegalHoldReleaseReceipt,
    LegalHoldRequest, ManifestSigningKeyVersionId, PurgeReceipt, RetentionDisposition,
    RetentionPolicy, SignedManifestExport,
};

/// Creates authenticated backups without exposing an engine or filesystem API.
pub trait BackupPort: Send + Sync {
    /// Creates and verifies a backup at the request's unused target.
    ///
    /// The implementation rejects existing targets and source aliases, never
    /// mutates the source, and quarantines incomplete output. An exact replay
    /// returns its durable evidence; conflicting identity reuse fails closed.
    /// Cancellation and deadlines come from `context`.
    ///
    /// # Errors
    ///
    /// Returns a stable error for cancellation, deadline expiry, conflicts,
    /// failed verification, or incomplete cleanup.
    fn create_verified_backup(
        &self,
        request: &BackupCreateRequest,
        context: &RequestContext,
    ) -> Result<BackupVerificationEvidence, StorageError>;
}

/// Signs, exports, and authenticates portable backup manifests.
pub trait BackupManifestPort: Send + Sync {
    /// Signs a bounded envelope covering every verification-evidence field.
    ///
    /// The envelope identifies the signing-key version but contains no key
    /// material. Cancellation and deadline expiry stop work before publication.
    ///
    /// # Errors
    ///
    /// Returns a stable error when signing is unavailable, bounds are exceeded,
    /// or cancellation or deadline expiry is observed.
    fn export_signed_manifest(
        &self,
        evidence: &BackupVerificationEvidence,
        signing_key: &ManifestSigningKeyVersionId,
        exported_at: SystemTime,
        context: &RequestContext,
    ) -> Result<SignedManifestExport, StorageError>;

    /// Authenticates a signed envelope before returning typed evidence.
    ///
    /// Unknown keys, malformed envelopes, invalid signatures, and mismatched
    /// fields fail closed without returning partially trusted values.
    ///
    /// # Errors
    ///
    /// Returns a stable error for authentication, compatibility, cancellation,
    /// deadline, or adapter failures.
    fn verify_signed_manifest(
        &self,
        manifest: &SignedManifestExport,
        context: &RequestContext,
    ) -> Result<BackupVerificationEvidence, StorageError>;
}

/// Classifies retention and records legal-hold transitions.
pub trait BackupRetentionPort: Send + Sync {
    /// Classifies one backup into UTC daily, weekly, or monthly retention.
    ///
    /// An active legal hold wins over every cadence. Monthly wins over weekly,
    /// and weekly wins over daily when buckets overlap.
    ///
    /// # Errors
    ///
    /// Returns a stable error when catalog state or authentication is invalid,
    /// or cancellation or deadline expiry is observed.
    fn classify(
        &self,
        backup_id: &BackupId,
        policy: RetentionPolicy,
        evaluated_at: SystemTime,
        context: &RequestContext,
    ) -> Result<RetentionDisposition, StorageError>;

    /// Durably places an indefinite or expiring legal hold.
    ///
    /// Reusing one hold identity for a different backup fails with a conflict.
    ///
    /// # Errors
    ///
    /// Returns a stable error for unknown backups, conflicting identities,
    /// cancellation, deadline expiry, or failed durability.
    fn place_legal_hold(
        &self,
        request: &LegalHoldRequest,
        context: &RequestContext,
    ) -> Result<LegalHoldReceipt, StorageError>;

    /// Durably releases the exact hold represented by its placement receipt.
    ///
    /// Release never deletes or marks the backup.
    ///
    /// # Errors
    ///
    /// Returns a stable error for mismatched or unknown holds, cancellation,
    /// deadline expiry, or failed durability.
    fn release_legal_hold(
        &self,
        hold: &LegalHoldReceipt,
        release_receipt_id: BackupReceiptId,
        released_at: SystemTime,
        context: &RequestContext,
    ) -> Result<LegalHoldReleaseReceipt, StorageError>;
}

/// Enforces two-stage deletion with durable, audit-ready receipts.
pub trait BackupDeletionPort: Send + Sync {
    /// Marks a retention-eligible backup without removing content.
    ///
    /// The implementation re-evaluates retention and legal holds, obtains time
    /// from a trusted clock, and returns the exact digest and earliest purge.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the backup is held, retained, unknown, or
    /// cannot be durably marked.
    fn mark_for_deletion(
        &self,
        request: &DeletionMarkRequest,
        context: &RequestContext,
    ) -> Result<DeletionMarkReceipt, StorageError>;

    /// Purges only the artifact authorized by a durable deletion mark.
    ///
    /// The implementation rejects early calls, rechecks legal holds and the
    /// stored digest, and persists a receipt before reporting success.
    ///
    /// # Errors
    ///
    /// Returns a stable error for early purge, new holds, evidence mismatch,
    /// cancellation, deadline expiry, or physical deletion failure.
    fn purge_marked_backup(
        &self,
        mark: &DeletionMarkReceipt,
        purge_receipt_id: BackupReceiptId,
        context: &RequestContext,
    ) -> Result<PurgeReceipt, StorageError>;
}

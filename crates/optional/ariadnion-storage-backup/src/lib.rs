// crates/optional/ariadnion-storage-backup/src/lib.rs - Rust source for Ariadnion.
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
//! Database-independent backup, retention, manifest, and deletion contracts.
//!
//! Backup adapters create a new target, authenticate it with caller-selected
//! key material, and return portable verification evidence. Manifest signing,
//! retention classification, legal holds, and physical deletion remain
//! explicit ports so no database, filesystem, serialization, or key-provider
//! type crosses this crate boundary.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod port;

pub use model::{
    BackupCreateRequest, BackupFileVersion, BackupId, BackupIntegrityProof, BackupKeyVersionId,
    BackupPageCount, BackupReceiptId, BackupSha256Digest, BackupSourceSnapshot, BackupTargetId,
    BackupVerificationEvidence, DeletionMarkReceipt, DeletionMarkRequest, DeletionReasonCode,
    LegalHoldId, LegalHoldReceipt, LegalHoldReleaseReceipt, LegalHoldRequest,
    ManifestSigningKeyVersionId, PurgeDelay, PurgeReceipt, RetentionCount, RetentionDisposition,
    RetentionPolicy, SignedManifestExport,
};
pub use port::{BackupDeletionPort, BackupManifestPort, BackupPort, BackupRetentionPort};

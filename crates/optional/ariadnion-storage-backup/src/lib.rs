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

pub use model::{
    BackupCreateRequest, BackupFileVersion, BackupId, BackupIntegrityProof, BackupKeyVersionId,
    BackupPageCount, BackupReceiptId, BackupSha256Digest, BackupSourceSnapshot, BackupTargetId,
    BackupVerificationEvidence, DeletionMarkReceipt, DeletionMarkRequest, DeletionReasonCode,
    LegalHoldId, LegalHoldReceipt, LegalHoldReleaseReceipt, LegalHoldRequest,
    ManifestSigningKeyVersionId, PurgeDelay, PurgeReceipt, RetentionCount, RetentionDisposition,
    RetentionPolicy, SignedManifestExport,
};

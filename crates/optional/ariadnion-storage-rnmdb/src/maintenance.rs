//! New-target backup, verification, restore, and upgrade operations.

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{
    backup_storage, restore_storage, restore_storage_dry_run, upgrade_storage_with_key,
    verify_storage_with_key,
};

use crate::location::StorageFileLocation;
use crate::session::{PageKeyMaterial, map_rnmdb_error};

/// Safe verification facts without filesystem paths or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationSummary {
    format_version: u16,
    file_len_bytes: u64,
    present_page_records: u64,
    encryption_authenticated: bool,
    valid: bool,
}

impl VerificationSummary {
    /// Returns the database file format version.
    #[must_use]
    pub const fn format_version(self) -> u16 {
        self.format_version
    }

    /// Returns the verified file length.
    #[must_use]
    pub const fn file_len_bytes(self) -> u64 {
        self.file_len_bytes
    }

    /// Returns the count of present page records.
    #[must_use]
    pub const fn present_page_records(self) -> u64 {
        self.present_page_records
    }

    /// Returns whether encrypted page authentication passed.
    #[must_use]
    pub const fn encryption_authenticated(self) -> bool {
        self.encryption_authenticated
    }

    /// Returns whether every structural and authentication check passed.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.valid
    }
}

/// Safe evidence produced after copying a backup to a new file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupSummary {
    bytes_copied: u64,
    page_record_slots: u64,
    present_page_records: u64,
}

impl BackupSummary {
    /// Returns the copied byte count.
    #[must_use]
    pub const fn bytes_copied(self) -> u64 {
        self.bytes_copied
    }

    /// Returns the total page-record slots.
    #[must_use]
    pub const fn page_record_slots(self) -> u64 {
        self.page_record_slots
    }

    /// Returns the present page-record count.
    #[must_use]
    pub const fn present_page_records(self) -> u64 {
        self.present_page_records
    }
}

/// Dry-run facts checked before a restore creates its target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestorePreflight {
    target_exists: bool,
    backup_valid: bool,
    bytes_to_restore: u64,
}

impl RestorePreflight {
    /// Returns whether the target already exists and must block restore.
    #[must_use]
    pub const fn target_exists(self) -> bool {
        self.target_exists
    }

    /// Returns whether the backup structure passed dry-run validation.
    #[must_use]
    pub const fn backup_valid(self) -> bool {
        self.backup_valid
    }

    /// Returns the expected restore byte count.
    #[must_use]
    pub const fn bytes_to_restore(self) -> u64 {
        self.bytes_to_restore
    }

    /// Returns whether creating the target is safe.
    #[must_use]
    pub const fn permits_restore(self) -> bool {
        !self.target_exists && self.backup_valid
    }
}

/// Safe facts returned after a restore or format upgrade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewTargetSummary {
    bytes_written: u64,
    page_records: u64,
}

impl NewTargetSummary {
    /// Returns the written byte count.
    #[must_use]
    pub const fn bytes_written(self) -> u64 {
        self.bytes_written
    }

    /// Returns the restored or upgraded page-record count.
    #[must_use]
    pub const fn page_records(self) -> u64 {
        self.page_records
    }
}

/// Stateless maintenance operations that never overwrite the source file.
pub struct RnmdbMaintenance;

impl RnmdbMaintenance {
    /// Authenticates and verifies one encrypted database file.
    pub fn verify(
        location: &StorageFileLocation,
        key: PageKeyMaterial,
        context: &RequestContext,
    ) -> Result<VerificationSummary, StorageError> {
        check_context(context)?;
        let report = verify_storage_with_key(location.path(), key.into_upstream_key())
            .map_err(map_rnmdb_error)?;
        Ok(VerificationSummary {
            format_version: report.format_version(),
            file_len_bytes: report.file_len_bytes(),
            present_page_records: report.present_page_records(),
            encryption_authenticated: report.encryption_authenticated(),
            valid: report.is_valid(),
        })
    }

    /// Copies a source file to a distinct new backup target.
    pub fn backup(
        source: &StorageFileLocation,
        target: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<BackupSummary, StorageError> {
        check_context(context)?;
        ensure_distinct(source, target)?;
        let report = backup_storage(source.path(), target.path()).map_err(map_rnmdb_error)?;
        Ok(BackupSummary {
            bytes_copied: report.bytes_copied(),
            page_record_slots: report.page_record_slots(),
            present_page_records: report.present_page_records(),
        })
    }

    /// Checks a backup and target without writing either file.
    pub fn restore_preflight(
        backup: &StorageFileLocation,
        target: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<RestorePreflight, StorageError> {
        check_context(context)?;
        ensure_distinct(backup, target)?;
        let report =
            restore_storage_dry_run(backup.path(), target.path()).map_err(map_rnmdb_error)?;
        Ok(RestorePreflight {
            target_exists: report.target_exists(),
            backup_valid: report.backup_valid(),
            bytes_to_restore: report.bytes_to_restore(),
        })
    }

    /// Restores a verified backup to a distinct target that does not exist.
    pub fn restore(
        backup: &StorageFileLocation,
        target: &StorageFileLocation,
        preflight: RestorePreflight,
        context: &RequestContext,
    ) -> Result<NewTargetSummary, StorageError> {
        check_context(context)?;
        ensure_distinct(backup, target)?;
        if !preflight.permits_restore() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        let report = restore_storage(backup.path(), target.path()).map_err(map_rnmdb_error)?;
        Ok(NewTargetSummary {
            bytes_written: report.bytes_restored(),
            page_records: report.present_page_records(),
        })
    }

    /// Upgrades a source file into a distinct new authenticated target.
    pub fn upgrade(
        source: &StorageFileLocation,
        target: &StorageFileLocation,
        key: PageKeyMaterial,
        context: &RequestContext,
    ) -> Result<NewTargetSummary, StorageError> {
        check_context(context)?;
        ensure_distinct(source, target)?;
        let report = upgrade_storage_with_key(
            source.path(),
            target.path(),
            key.into_upstream_key(),
        )
        .map_err(map_rnmdb_error)?;
        Ok(NewTargetSummary {
            bytes_written: report.bytes_written(),
            page_records: report.pages_upgraded(),
        })
    }
}

fn ensure_distinct(
    source: &StorageFileLocation,
    target: &StorageFileLocation,
) -> Result<(), StorageError> {
    if source == target {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => StorageError::new(StorageErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => StorageError::new(StorageErrorCode::DeadlineExceeded),
        _ => StorageError::new(StorageErrorCode::Internal),
    })
}

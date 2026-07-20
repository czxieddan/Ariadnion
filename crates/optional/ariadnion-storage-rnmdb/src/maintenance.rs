//! New-target backup, verification, restore, and upgrade operations.

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{
    backup_storage, restore_storage, restore_storage_dry_run, verify_storage_with_key,
};
use rnmdb_storage::{SingleFileUpgradeOptions, upgrade_single_file_with_options};

use crate::location::StorageFileLocation;
use crate::session::{PageKeyMaterial, map_rnmdb_error};

/// Safe verification facts without filesystem paths or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationSummary {
    format_version: u16,
    file_len_bytes: u64,
    page_record_slots: u64,
    present_page_records: u64,
    authenticated_page_records: u64,
    format_supported: bool,
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

    /// Returns the total page-record slot count.
    #[must_use]
    pub const fn page_record_slots(self) -> u64 {
        self.page_record_slots
    }

    /// Returns the count of present page records.
    #[must_use]
    pub const fn present_page_records(self) -> u64 {
        self.present_page_records
    }

    /// Returns the number of encrypted page records authenticated by the key.
    #[must_use]
    pub const fn authenticated_page_records(self) -> u64 {
        self.authenticated_page_records
    }

    /// Returns whether the file format is supported by this RNMDB revision.
    #[must_use]
    pub const fn format_supported(self) -> bool {
        self.format_supported
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

/// Safe evidence returned by a physical new-target format upgrade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeSummary {
    source_format_version: u16,
    target_format_version: u16,
    bytes_written: u64,
    pages_upgraded: u64,
    key_rotated: bool,
}

impl UpgradeSummary {
    /// Returns the format version read from the immutable source.
    #[must_use]
    pub const fn source_format_version(self) -> u16 {
        self.source_format_version
    }

    /// Returns the format version written to the new target.
    #[must_use]
    pub const fn target_format_version(self) -> u16 {
        self.target_format_version
    }

    /// Returns the authenticated target byte count.
    #[must_use]
    pub const fn bytes_written(self) -> u64 {
        self.bytes_written
    }

    /// Returns the count of page records transformed into the target.
    #[must_use]
    pub const fn pages_upgraded(self) -> u64 {
        self.pages_upgraded
    }

    /// Returns whether RNMDB used distinct source and target page keys.
    #[must_use]
    pub const fn key_rotated(self) -> bool {
        self.key_rotated
    }
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
            page_record_slots: report.page_record_slots(),
            present_page_records: report.present_page_records(),
            authenticated_page_records: report.authenticated_page_records(),
            format_supported: report.format_supported(),
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
        source_key: PageKeyMaterial,
        target_key: PageKeyMaterial,
        context: &RequestContext,
    ) -> Result<UpgradeSummary, StorageError> {
        check_context(context)?;
        ensure_distinct(source, target)?;
        let options = SingleFileUpgradeOptions::new()
            .with_source_page_key(source_key.into_upstream_key())
            .with_target_page_key(target_key.into_upstream_key());
        let report = upgrade_single_file_with_options(source.path(), target.path(), options)
            .map_err(map_rnmdb_error)?;
        check_context(context)?;
        Ok(UpgradeSummary {
            source_format_version: report.source_format_version(),
            target_format_version: report.target_format_version(),
            bytes_written: report.bytes_written(),
            pages_upgraded: report.pages_upgraded(),
            key_rotated: report.key_rotated(),
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

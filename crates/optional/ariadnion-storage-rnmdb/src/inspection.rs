//! Keyed RNMDB inspection projected into database-independent evidence.

use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, StorageErrorCode, StorageInstanceId};
use ariadnion_storage_maintenance::{
    InspectionEvidence, StorageByteCount, StorageFormatVersion, StorageInspectionPort,
    StoragePageCount, VerificationEvidence,
};

use crate::{PageKeyMaterial, RnmdbMaintenance, StorageFileLocation};

/// Resolves trusted locations and fresh page keys for maintenance inspection.
pub trait RnmdbInspectionResolver: Send + Sync {
    /// Resolves one instance to a validated, redacted RNMDB file location.
    fn location(&self, instance: &StorageInstanceId) -> Result<StorageFileLocation, StorageError>;

    /// Returns fresh page-key material for one inspection operation.
    fn page_key(&self, instance: &StorageInstanceId) -> Result<PageKeyMaterial, StorageError>;
}

/// Authenticates RNMDB files and exposes only bounded maintenance evidence.
pub struct RnmdbInspectionAdapter {
    resolver: Arc<dyn RnmdbInspectionResolver>,
}

impl RnmdbInspectionAdapter {
    /// Creates an adapter using one trusted location and key resolver.
    #[must_use]
    pub const fn new(resolver: Arc<dyn RnmdbInspectionResolver>) -> Self {
        Self { resolver }
    }

    /// Returns the trusted resolver used by this adapter.
    #[must_use]
    pub const fn resolver(&self) -> &Arc<dyn RnmdbInspectionResolver> {
        &self.resolver
    }

    fn collect(
        &self,
        instance: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<CollectedInspection, StorageError> {
        let location = self.resolve_location(instance)?;
        let key = self.resolver.page_key(instance)?;
        let summary = RnmdbMaintenance::verify(&location, key, context)?;
        project_inspection(instance, summary, SystemTime::now())
    }

    fn resolve_location(
        &self,
        instance: &StorageInstanceId,
    ) -> Result<StorageFileLocation, StorageError> {
        let location = self.resolver.location(instance)?;
        if location.instance() != instance {
            return Err(integrity_failure());
        }
        Ok(location)
    }
}

impl StorageInspectionPort for RnmdbInspectionAdapter {
    fn inspect(
        &self,
        instance: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<InspectionEvidence, StorageError> {
        self.collect(instance, context)
            .map(|collected| collected.inspection)
    }

    fn verify(
        &self,
        instance: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<VerificationEvidence, StorageError> {
        let collected = self.collect(instance, context)?;
        VerificationEvidence::new(
            collected.inspection,
            collected.format_supported,
            collected.structurally_valid,
            SystemTime::now(),
        )
    }
}

struct CollectedInspection {
    inspection: InspectionEvidence,
    format_supported: bool,
    structurally_valid: bool,
}

fn project_inspection(
    instance: &StorageInstanceId,
    summary: crate::VerificationSummary,
    inspected_at: SystemTime,
) -> Result<CollectedInspection, StorageError> {
    let inspection = InspectionEvidence::new(
        instance.clone(),
        StorageFormatVersion::new(summary.format_version())?,
        StorageByteCount::new(summary.file_len_bytes())?,
        StoragePageCount::new(summary.page_record_slots())?,
        StoragePageCount::new(summary.present_page_records())?,
        StoragePageCount::new(summary.authenticated_page_records())?,
        summary.encryption_authenticated(),
        inspected_at,
    )?;
    Ok(CollectedInspection {
        inspection,
        format_supported: summary.format_supported(),
        structurally_valid: summary.is_valid(),
    })
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

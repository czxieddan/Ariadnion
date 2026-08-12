// crates/optional/ariadnion-storage-rnmdb/src/inspection.rs - Rust source for Ariadnion.
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

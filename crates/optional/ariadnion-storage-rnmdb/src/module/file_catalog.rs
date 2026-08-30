// crates/optional/ariadnion-storage-rnmdb/src/module/file_catalog.rs - Rust source for Ariadnion.
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
//! Typed file-catalog capability owned by the RNMDB module lifecycle.

use std::sync::Arc;
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicBool, Ordering};

use ariadnion_api_files::{ApiFilesError, ApiFilesErrorCode, FileCatalogServicePort};
use ariadnion_core::{
    CancellationToken, CapabilityId, CapabilityProvider, CoreError, ErrorCode, ModuleId,
    ModuleVersion, PortHandle, PortKey, PortSlot,
};

use crate::{
    FileCatalogCommitmentKeys, FileCatalogLookupKeyMaterial, RnmdbFileCatalogRepository,
    RnmdbSessionOwner,
};

pub(super) const FILE_CATALOG_CAPABILITY_ID: &str = "org.ariadnion.file.catalog";
const FILE_CATALOG_PORT_NAME: &str = "org.ariadnion.file.catalog.port";
const PRIMARY_PROVIDER_PRIORITY: u16 = 0;

/// One lifecycle-owned typed slot for the durable file catalog.
#[derive(Clone)]
pub(super) struct FileCatalogCapability {
    slot: Arc<PortSlot<dyn FileCatalogServicePort>>,
    #[cfg(feature = "test-hooks")]
    fail_next_publication: Arc<AtomicBool>,
}

impl FileCatalogCapability {
    /// Creates an empty typed slot without publishing a provider.
    pub(super) fn new() -> Result<Self, CoreError> {
        let key = PortKey::new(FILE_CATALOG_PORT_NAME)?;
        Ok(Self {
            slot: Arc::new(PortSlot::new(key)),
            #[cfg(feature = "test-hooks")]
            fail_next_publication: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Resolves the current generation only after successful publication.
    pub(super) fn resolve(&self) -> Result<PortHandle<dyn FileCatalogServicePort>, CoreError> {
        self.slot.resolve()
    }

    /// Builds the catalog over the module's existing sole session owner.
    pub(super) fn build(
        session: Arc<RnmdbSessionOwner>,
        lookup: FileCatalogLookupKeyMaterial,
        commitments: FileCatalogCommitmentKeys,
    ) -> Result<Arc<dyn FileCatalogServicePort>, CoreError> {
        let repository = RnmdbFileCatalogRepository::new(session, lookup, commitments)
            .map_err(map_catalog_error)?;
        Ok(Arc::new(repository))
    }

    /// Publishes one preconstructed catalog after storage is fully ready.
    pub(super) fn publish(
        &self,
        catalog: Arc<dyn FileCatalogServicePort>,
        cancellation: CancellationToken,
    ) -> Result<(), CoreError> {
        #[cfg(feature = "test-hooks")]
        self.fail_if_armed()?;
        let _published = self
            .slot
            .register(PRIMARY_PROVIDER_PRIORITY, catalog, cancellation)?;
        Ok(())
    }

    /// Arms one deterministic pre-registration failure for lifecycle contracts.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub(super) fn fail_next_publication_for_test(&self) -> Result<(), CoreError> {
        self.fail_next_publication
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| {
                CoreError::from_code(ErrorCode::Conflict)
                    .with_internal_context("file catalog publication failure is already armed")
            })
    }

    /// Invalidates every resolved generation before storage shutdown begins.
    pub(super) fn invalidate(&self) -> Result<(), CoreError> {
        self.slot.invalidate().map(|_generation| ())
    }

    #[cfg(feature = "test-hooks")]
    fn fail_if_armed(&self) -> Result<(), CoreError> {
        if self.fail_next_publication.swap(false, Ordering::AcqRel) {
            return Err(CoreError::from_code(ErrorCode::Unavailable)
                .with_internal_context("file catalog publication failure was injected"));
        }
        Ok(())
    }
}

pub(super) fn file_catalog_provider(
    module_id: &ModuleId,
    version: ModuleVersion,
) -> Result<CapabilityProvider, CoreError> {
    Ok(CapabilityProvider::new(
        CapabilityId::parse(FILE_CATALOG_CAPABILITY_ID)?,
        version,
        module_id.clone(),
    ))
}

fn map_catalog_error(error: ApiFilesError) -> CoreError {
    let code = match error.code() {
        ApiFilesErrorCode::InvalidArgument | ApiFilesErrorCode::LimitExceeded => {
            ErrorCode::InvalidArgument
        }
        ApiFilesErrorCode::Conflict => ErrorCode::Conflict,
        ApiFilesErrorCode::Cancelled => ErrorCode::Cancelled,
        ApiFilesErrorCode::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        ApiFilesErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        ApiFilesErrorCode::Unavailable | ApiFilesErrorCode::CommitIndeterminate => {
            ErrorCode::Unavailable
        }
        _ => ErrorCode::Internal,
    };
    CoreError::from_code(code).with_internal_context("RNMDB file catalog construction failed")
}

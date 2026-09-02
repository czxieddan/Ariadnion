// crates/optional/ariadnion-file-service/src/service.rs - Durable file service for Ariadnion.
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

use std::sync::Arc;

use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, BoxFileFuture, FileCatalogServicePort,
    FileDeleteReconciliation, FileDeleteRequest, FileDescriptor, FileListPage, FileListRequest,
    FileReference, FileReferenceIssuerPort,
};
use ariadnion_core::{PrincipalContext, RequestContext};
use ariadnion_storage_asset::LocalVolumeAssetStoragePort;

use crate::worker::TransferWorker;

mod upload;

/// Coordinates authenticated metadata and durable content operations.
pub struct DurableFileService {
    pub(super) catalog: Arc<dyn FileCatalogServicePort>,
    pub(super) issuer: Arc<dyn FileReferenceIssuerPort>,
    pub(super) worker: TransferWorker,
}

impl DurableFileService {
    /// Creates a cold service with one worker owning the asset storage adapter.
    #[must_use]
    pub fn new(
        catalog: Arc<dyn FileCatalogServicePort>,
        issuer: Arc<dyn FileReferenceIssuerPort>,
        assets: Arc<dyn LocalVolumeAssetStoragePort>,
    ) -> Self {
        Self {
            catalog,
            issuer,
            worker: TransferWorker::new(assets),
        }
    }

    /// Stops worker admission, cancels active work, and joins the worker thread.
    ///
    /// # Errors
    ///
    /// Returns a redacted service error when the worker cannot stop cleanly.
    pub fn shutdown(&self) -> Result<(), ApiFilesError> {
        self.worker.shutdown()
    }

    /// Loads one authenticated catalog descriptor.
    ///
    /// The returned future is lazy and performs authentication and context
    /// checks before delegating exactly once to the catalog.
    pub fn metadata<'a>(
        &'a self,
        reference: &'a FileReference,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDescriptor, ApiFilesError>> {
        Box::pin(async move {
            require_authenticated_active(context)?;
            self.catalog.metadata(reference, context).await
        })
    }

    /// Lists one authenticated catalog page.
    ///
    /// The returned future is lazy and performs authentication and context
    /// checks before delegating exactly once to the catalog.
    pub fn list<'a>(
        &'a self,
        request: FileListRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileListPage, ApiFilesError>> {
        Box::pin(async move {
            require_authenticated_active(context)?;
            self.catalog.list(request, context).await
        })
    }

    /// Deletes one visible catalog record using compare-and-delete semantics.
    ///
    /// A missing record is resolved through request-only reconciliation; no
    /// asset bytes are deleted by this operation.
    pub fn delete<'a>(
        &'a self,
        request: FileDeleteRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>> {
        Box::pin(async move {
            require_authenticated_active(context)?;
            delete_catalog(self.catalog.as_ref(), request, context).await
        })
    }

    /// Reconciles one indeterminate catalog deletion without touching assets.
    ///
    /// The returned future is lazy and delegates the exact request once after
    /// authentication and context checks.
    pub fn reconcile_delete<'a>(
        &'a self,
        request: &'a FileDeleteRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDeleteReconciliation, ApiFilesError>> {
        Box::pin(async move {
            require_authenticated_active(context)?;
            self.catalog.reconcile_delete(request, context).await
        })
    }
}

async fn delete_catalog(
    catalog: &dyn FileCatalogServicePort,
    request: FileDeleteRequest,
    context: &RequestContext,
) -> Result<(), ApiFilesError> {
    match catalog.metadata(request.reference(), context).await {
        Ok(descriptor) => catalog.delete(&request, &descriptor, context).await,
        Err(error) if error.code() == ApiFilesErrorCode::NotFound => {
            reconcile_missing_delete(catalog, &request, context).await
        }
        Err(error) => Err(error),
    }
}

async fn reconcile_missing_delete(
    catalog: &dyn FileCatalogServicePort,
    request: &FileDeleteRequest,
    context: &RequestContext,
) -> Result<(), ApiFilesError> {
    match catalog.reconcile_delete(request, context).await? {
        FileDeleteReconciliation::Deleted => Ok(()),
        FileDeleteReconciliation::NotDeleted => {
            Err(ApiFilesError::new(ApiFilesErrorCode::NotFound))
        }
    }
}

fn require_authenticated_active(
    context: &RequestContext,
) -> Result<&PrincipalContext, ApiFilesError> {
    let Some(principal) = context.principal() else {
        return Err(ApiFilesError::new(ApiFilesErrorCode::Unauthenticated));
    };
    context.check_active()?;
    Ok(principal)
}

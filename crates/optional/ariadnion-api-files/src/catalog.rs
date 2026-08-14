// crates/optional/ariadnion-api-files/src/catalog.rs - Rust source for Ariadnion.
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
//! Authenticated file catalog record values.

use std::fmt::{self, Debug, Formatter};

use ariadnion_api_domain::FileDescriptor;
use ariadnion_core::{PrincipalContext, PrincipalId, RequestContext, TenantId};

use crate::{ApiFilesError, ApiFilesErrorCode, FileUploadRequest};

/// One exact authenticated owner, upload request, and verified descriptor binding.
///
/// Trusted catalog adapters may persist these values only after independently
/// confirming that [`Self::owner`] equals the authenticated request context.
#[derive(Clone, Eq, PartialEq)]
pub struct FileCatalogRecord {
    owner: PrincipalContext,
    request: FileUploadRequest,
    descriptor: FileDescriptor,
}

impl FileCatalogRecord {
    /// Validates and binds one exact owner, request, and verified descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::IntegrityFailure`] when the display name,
    /// media type, byte length, or supplied expected digest differs from the
    /// verified descriptor.
    pub fn new(
        owner: PrincipalContext,
        request: FileUploadRequest,
        descriptor: FileDescriptor,
    ) -> Result<Self, ApiFilesError> {
        validate_descriptor(&request, &descriptor)?;
        Ok(Self {
            owner,
            request,
            descriptor,
        })
    }

    /// Clones the exact authenticated owner and binds the supplied file values.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::Unauthenticated`] for an anonymous context.
    /// Returns [`ApiFilesErrorCode::IntegrityFailure`] for request and descriptor
    /// divergence documented by [`Self::new`].
    pub fn from_authenticated_context(
        context: &RequestContext,
        request: FileUploadRequest,
        descriptor: FileDescriptor,
    ) -> Result<Self, ApiFilesError> {
        let Some(owner) = context.principal().cloned() else {
            return Err(error(ApiFilesErrorCode::Unauthenticated));
        };
        Self::new(owner, request, descriptor)
    }

    /// Returns the exact authenticated owner to a trusted catalog adapter.
    #[must_use]
    pub const fn owner(&self) -> &PrincipalContext {
        &self.owner
    }

    /// Returns the exact tenant identity to a trusted catalog adapter.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.owner.tenant_id()
    }

    /// Returns the exact principal identity to a trusted catalog adapter.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        self.owner.principal_id()
    }

    /// Returns the original validated upload request to a trusted catalog adapter.
    #[must_use]
    pub const fn request(&self) -> &FileUploadRequest {
        &self.request
    }

    /// Returns the verified descriptor to a trusted catalog adapter.
    #[must_use]
    pub const fn descriptor(&self) -> &FileDescriptor {
        &self.descriptor
    }
}

impl Debug for FileCatalogRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileCatalogRecord")
            .finish_non_exhaustive()
    }
}

fn validate_descriptor(
    request: &FileUploadRequest,
    descriptor: &FileDescriptor,
) -> Result<(), ApiFilesError> {
    let specification = request.specification();
    if specification.display_name() != descriptor.display_name()
        || specification.media_type() != descriptor.media_type()
        || specification.byte_length() != descriptor.byte_length()
    {
        return Err(error(ApiFilesErrorCode::IntegrityFailure));
    }
    validate_expected_digest(specification.expected_digest(), descriptor.digest())
}

fn validate_expected_digest(
    expected: Option<&ariadnion_api_domain::FileDigest>,
    verified: &ariadnion_api_domain::FileDigest,
) -> Result<(), ApiFilesError> {
    if let Some(expected) = expected
        && expected != verified
    {
        return Err(error(ApiFilesErrorCode::IntegrityFailure));
    }
    Ok(())
}

const fn error(code: ApiFilesErrorCode) -> ApiFilesError {
    ApiFilesError::new(code)
}

// crates/optional/ariadnion-provider-dispatch/src/error.rs - Redacted provider failure projection for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Fixed provider-to-service failure projection.

use ariadnion_api_domain::{ApiDomainError, ApiDomainErrorCode};
use ariadnion_provider_sdk::{ProviderFailure, ProviderFailureClass};

pub(crate) const fn internal_error() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::Internal)
}

pub(crate) const fn unavailable_error() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::Unavailable)
}

pub(crate) const fn resource_exhausted_error() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::ResourceExhausted)
}

pub(crate) const fn project_provider_failure(failure: ProviderFailure) -> ApiDomainError {
    let code = match failure.class() {
        ProviderFailureClass::Cancelled => ApiDomainErrorCode::Cancelled,
        ProviderFailureClass::DeadlineExceeded | ProviderFailureClass::AttemptTimeout => {
            ApiDomainErrorCode::DeadlineExceeded
        }
        ProviderFailureClass::InvalidRequest | ProviderFailureClass::ContentRejected => {
            ApiDomainErrorCode::InvalidArgument
        }
        ProviderFailureClass::RateLimited
        | ProviderFailureClass::QuotaExhausted
        | ProviderFailureClass::ResponseLimit => ApiDomainErrorCode::ResourceExhausted,
        ProviderFailureClass::UpstreamUnavailable => ApiDomainErrorCode::Unavailable,
        ProviderFailureClass::Authentication
        | ProviderFailureClass::PermissionDenied
        | ProviderFailureClass::NotFound
        | ProviderFailureClass::ProtocolViolation
        | ProviderFailureClass::Internal => ApiDomainErrorCode::Internal,
        _ => ApiDomainErrorCode::Internal,
    };
    ApiDomainError::new(code)
}

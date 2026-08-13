// crates/optional/ariadnion-api-http/src/public/authentication.rs - Fail-closed public authentication adapter for Ariadnion.
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
//! Static fail-closed authentication when no authoritative service is composed.

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;

use super::{
    ApiHttpError, ApiHttpErrorCode, BoxHttpFuture, PresentedBearer, ServiceAuthenticationPort,
};

/// Rejects every active request because no authentication service is available.
///
/// This zero-state adapter never observes or retains presented Bearer bytes.
/// Cancellation and deadline failures retain precedence over the stable
/// unavailable result so the shared HTTP lifecycle projects request boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableServiceAuthentication;

impl ServiceAuthenticationPort for UnavailableServiceAuthentication {
    fn authenticate<'a>(
        &'a self,
        _authorization: &'a PresentedBearer,
        context: &'a RequestContext,
    ) -> BoxHttpFuture<'a, Result<AuthenticatedPrincipalEvidence, ApiHttpError>> {
        let code = context
            .check_active()
            .err()
            .map_or(ApiHttpErrorCode::Unavailable, project_context_error);
        Box::pin(async move { Err(ApiHttpError::new(code)) })
    }
}

fn project_context_error(code: ariadnion_core::CoreError) -> ApiHttpErrorCode {
    match code.code() {
        ErrorCode::Cancelled => ApiHttpErrorCode::Cancelled,
        ErrorCode::DeadlineExceeded => ApiHttpErrorCode::DeadlineExceeded,
        _ => ApiHttpErrorCode::Unavailable,
    }
}

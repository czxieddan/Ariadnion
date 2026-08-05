// crates/optional/ariadnion-api-http/src/lib.rs - Rust source for Ariadnion.
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
//! Bounded administration and public HTTP adapters.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admin;
mod public;

pub use admin::{
    HttpAdminAdapter, HttpAdminResponse, HttpAuthenticationPort, HttpAuthorization,
    HttpRequestMetadata, HttpSuspendUserBody, HttpSuspendUserRequest, MAX_AUTHORIZATION_BYTES,
    MAX_ENCODED_BODY_BYTES, MAX_ENCODED_HEADER_BYTES,
};
pub use public::{
    ApiHttpError, ApiHttpErrorCode, BoxHttpBodyStream, BoxHttpFuture, HttpApiState,
    HttpRequestIdentity, MAX_PRESENTED_BEARER_BYTES, MAX_PUBLIC_BODY_BYTES,
    MAX_PUBLIC_HEADER_BYTES, MAX_PUBLIC_HEADERS, MAX_PUBLIC_IN_FLIGHT_REQUESTS, PresentedBearer,
    RequestIdentityPort, ServiceAuthenticationPort, ServiceDispatchOutcome, ServiceDispatchPort,
    ServiceStreamBridgePort, public_router,
};

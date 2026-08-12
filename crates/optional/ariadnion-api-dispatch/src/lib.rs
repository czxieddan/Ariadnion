// crates/optional/ariadnion-api-dispatch/src/lib.rs - Rust source for Ariadnion.
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
//! Transport-neutral authenticated service dispatch contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::future::Future;
use std::pin::Pin;

use ariadnion_api_domain::{ApiDomainError, ServiceRequest, ServiceResponse, ServiceStreamEvent};
use ariadnion_core::{EventSubscriber, RequestContext};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;

/// Boxed asynchronous result used by authenticated service dispatch ports.
///
/// The future borrows the dispatch port, authenticated evidence, and request
/// context for at most `'a`. It is safe to move between executor workers and
/// does not prescribe an asynchronous runtime or transport implementation.
pub type BoxServiceDispatchFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A transport-neutral service dispatch result.
///
/// The variant must match the request's declared response mode. Transport
/// adapters must reject a mismatch without exposing internal service details.
/// Future compatible variants may be added, so external consumers must retain
/// a fallback arm.
#[non_exhaustive]
pub enum ServiceDispatchOutcome {
    /// A complete response ready for transport-specific projection.
    Complete(ServiceResponse),
    /// A bounded event subscriber requiring a transport-specific stream bridge.
    Stream(EventSubscriber<ServiceStreamEvent>),
}

/// Dispatches a validated service request with authenticated principal evidence.
pub trait ServiceDispatchPort: Send + Sync {
    /// Executes one request with independent authentication evidence and context.
    ///
    /// The implementation owns idempotent replay, canonical request digests,
    /// and durable outcome semantics. It must observe context cancellation and
    /// the UTC deadline before every externally visible side effect. The
    /// returned outcome variant must match the request's declared response mode.
    ///
    /// # Errors
    ///
    /// Returns a stable [`ApiDomainError`] when dispatch is rejected, cancelled,
    /// exceeds its deadline or resource bounds, or cannot produce a durable
    /// outcome. Errors must not disclose credentials or sensitive request data.
    fn dispatch<'a>(
        &'a self,
        request: ServiceRequest,
        evidence: &'a AuthenticatedPrincipalEvidence,
        context: &'a RequestContext,
    ) -> BoxServiceDispatchFuture<'a, Result<ServiceDispatchOutcome, ApiDomainError>>;
}

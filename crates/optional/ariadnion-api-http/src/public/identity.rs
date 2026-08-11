// crates/optional/ariadnion-api-http/src/public/identity.rs - Bounded HTTP request identity issuance for Ariadnion.
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
//! Bounded process-local request and trace identity issuance.

use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

use ariadnion_core::{RequestId, TraceId};

use super::{ApiHttpError, ApiHttpErrorCode, HttpRequestIdentity, RequestIdentityPort};

/// Issues monotonic, bounded request and trace identity pairs without clock or
/// random-source dependencies.
pub struct MonotonicRequestIdentityIssuer {
    next: AtomicU64,
    fallback: HttpRequestIdentity,
}

impl MonotonicRequestIdentityIssuer {
    /// Creates an issuer whose first pair uses sequence `1`.
    ///
    /// # Errors
    ///
    /// Returns a stable internal error only if the fixed fallback identifiers
    /// cease to satisfy core identifier validation.
    pub fn new() -> Result<Self, ApiHttpError> {
        Self::from_next_sequence(1)
    }

    /// Creates an issuer with an explicitly selected next sequence.
    ///
    /// Passing `u64::MAX` creates an already exhausted issuer. The reserved
    /// marker makes overflow fail closed instead of wrapping to a duplicate.
    pub fn from_next_sequence(next: u64) -> Result<Self, ApiHttpError> {
        let fallback =
            identity_from_parts("ariadnion-request-fallback", "ariadnion-trace-fallback")?;
        Ok(Self {
            next: AtomicU64::new(next),
            fallback,
        })
    }

    fn issue_next(&self) -> Result<HttpRequestIdentity, ApiHttpError> {
        let sequence = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted))?;
        identity_for_sequence(sequence)
    }
}

impl RequestIdentityPort for MonotonicRequestIdentityIssuer {
    fn issue(&self) -> Result<HttpRequestIdentity, ApiHttpError> {
        self.issue_next()
    }

    fn fallback_identity(&self) -> HttpRequestIdentity {
        self.fallback.clone()
    }
}

impl Debug for MonotonicRequestIdentityIssuer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("MonotonicRequestIdentityIssuer(<redacted>)")
    }
}

fn identity_for_sequence(sequence: u64) -> Result<HttpRequestIdentity, ApiHttpError> {
    let request = format!("ariadnion-request-{sequence}");
    let trace = format!("ariadnion-trace-{sequence}");
    identity_from_parts(&request, &trace)
}

fn identity_from_parts(request: &str, trace: &str) -> Result<HttpRequestIdentity, ApiHttpError> {
    let request = RequestId::parse(request).map_err(|_| internal_error())?;
    let trace = TraceId::parse(trace).map_err(|_| internal_error())?;
    Ok(HttpRequestIdentity::new(request, trace))
}

const fn internal_error() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::Internal)
}

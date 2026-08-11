// crates/optional/ariadnion-provider-dispatch/src/identity.rs - Bounded provider attempt identity issuance for Ariadnion.
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
//! Process-local, checked provider-attempt identity issuance.

use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

use ariadnion_api_domain::{ApiDomainError, ApiDomainErrorCode};
use ariadnion_core::AttemptId;

use crate::AttemptIdIssuerPort;

const FIRST_SEQUENCE: u64 = 1;

/// Issues bounded process-local provider attempt identifiers.
///
/// The issuer uses a monotonic atomic sequence and reserves `u64::MAX` as an
/// exhaustion marker. It does not read a clock, random source, network, or
/// database, and it retains no request, credential, or provider material.
pub struct MonotonicAttemptIdIssuer {
    next_sequence: AtomicU64,
}

impl MonotonicAttemptIdIssuer {
    /// Creates an issuer whose first identifier uses sequence one.
    #[must_use]
    pub const fn new() -> Self {
        Self::from_next_sequence(FIRST_SEQUENCE)
    }

    /// Creates an issuer with an explicitly checked next sequence.
    ///
    /// Passing `u64::MAX` creates an already exhausted issuer. The reserved
    /// marker makes overflow fail closed instead of wrapping to a duplicate.
    #[must_use]
    pub const fn from_next_sequence(next_sequence: u64) -> Self {
        Self {
            next_sequence: AtomicU64::new(next_sequence),
        }
    }

    fn next_sequence(&self) -> Result<u64, ApiDomainError> {
        self.next_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ApiDomainError::new(ApiDomainErrorCode::ResourceExhausted))
    }
}

impl Default for MonotonicAttemptIdIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for MonotonicAttemptIdIssuer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("MonotonicAttemptIdIssuer(<redacted>)")
    }
}

impl AttemptIdIssuerPort for MonotonicAttemptIdIssuer {
    fn issue_attempt_id(&self) -> Result<AttemptId, ApiDomainError> {
        let sequence = self.next_sequence()?;
        let value = format!("attempt-{sequence:020}");
        AttemptId::parse(&value).map_err(|_| ApiDomainError::new(ApiDomainErrorCode::Internal))
    }
}

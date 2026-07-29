// crates/optional/ariadnion-principal-binding/src/error.rs - Rust source for Ariadnion.
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
//! Stable principal-binding failures with input-free formatting.

use std::fmt::{self, Display, Formatter};

/// Stable machine-readable failures returned by principal-binding operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum PrincipalBindingErrorCode {
    /// A supplied scalar is outside its documented range.
    InvalidArgument = 0,
    /// An authenticated principal belongs to another tenant.
    TenantMismatch = 1,
    /// An authenticated principal does not match the durable principal key.
    PrincipalMismatch = 2,
    /// Direct identity fields do not reproduce the retained commitment.
    CommitmentMismatch = 3,
    /// A persisted snapshot has an impossible lifecycle shape.
    InvalidSnapshot = 4,
    /// The supplied optimistic version is stale or otherwise incorrect.
    VersionConflict = 5,
    /// The monotonic version cannot be incremented.
    VersionExhausted = 6,
    /// The requested lifecycle transition is not permitted.
    InvalidTransition = 7,
    /// A trusted transition timestamp precedes durable lifecycle history.
    TimestampRegression = 8,
    /// A persisted event has an impossible lifecycle version or shape.
    InvalidEvent = 9,
}

const ERROR_CODES: [&str; 10] = [
    "PRINCIPAL_BINDING_INVALID_ARGUMENT",
    "PRINCIPAL_BINDING_TENANT_MISMATCH",
    "PRINCIPAL_BINDING_PRINCIPAL_MISMATCH",
    "PRINCIPAL_BINDING_COMMITMENT_MISMATCH",
    "PRINCIPAL_BINDING_INVALID_SNAPSHOT",
    "PRINCIPAL_BINDING_VERSION_CONFLICT",
    "PRINCIPAL_BINDING_VERSION_EXHAUSTED",
    "PRINCIPAL_BINDING_INVALID_TRANSITION",
    "PRINCIPAL_BINDING_TIMESTAMP_REGRESSION",
    "PRINCIPAL_BINDING_INVALID_EVENT",
];

impl PrincipalBindingErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        ERROR_CODES[self as usize]
    }
}

/// A redacted principal-binding error that never retains rejected values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalBindingError {
    code: PrincipalBindingErrorCode,
}

impl PrincipalBindingError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: PrincipalBindingErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> PrincipalBindingErrorCode {
        self.code
    }
}

impl Display for PrincipalBindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for PrincipalBindingError {}

pub(crate) const fn error(code: PrincipalBindingErrorCode) -> PrincipalBindingError {
    PrincipalBindingError::new(code)
}

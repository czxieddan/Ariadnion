// crates/optional/ariadnion-principal-binding/src/authenticator_error.rs - Rust source for Ariadnion.
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
//! Stable redacted failures for principal-authenticator links.

use std::fmt::{self, Display, Formatter};

const ERROR_CODES: [&str; 12] = [
    "PRINCIPAL_AUTHENTICATOR_INVALID_KIND",
    "PRINCIPAL_AUTHENTICATOR_INVALID_SOURCE_ID",
    "PRINCIPAL_AUTHENTICATOR_INVALID_ID",
    "PRINCIPAL_AUTHENTICATOR_INVALID_VERSION",
    "PRINCIPAL_AUTHENTICATOR_VERSION_EXHAUSTED",
    "PRINCIPAL_AUTHENTICATOR_PRINCIPAL_BINDING_INACTIVE",
    "PRINCIPAL_AUTHENTICATOR_INVALID_SNAPSHOT",
    "PRINCIPAL_AUTHENTICATOR_INVALID_EVENT",
    "PRINCIPAL_AUTHENTICATOR_INVALID_TRANSITION",
    "PRINCIPAL_AUTHENTICATOR_VERSION_CONFLICT",
    "PRINCIPAL_AUTHENTICATOR_TIMESTAMP_REGRESSION",
    "PRINCIPAL_AUTHENTICATOR_EVIDENCE_MISMATCH",
];

/// Stable machine-readable failures for principal-authenticator links.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PrincipalAuthenticatorErrorCode {
    /// A durable authenticator kind string is not recognized.
    InvalidKind = 0,
    /// A source identifier violates its length or alphabet boundary.
    InvalidSourceId = 1,
    /// A durable derived authenticator identifier is malformed or inconsistent.
    InvalidAuthenticatorId = 2,
    /// An optimistic version is zero.
    InvalidVersion = 3,
    /// An optimistic version cannot advance beyond `u64::MAX`.
    VersionExhausted = 4,
    /// The referenced principal binding is not active and exact.
    PrincipalBindingInactive = 5,
    /// A durable snapshot violates aggregate invariants.
    InvalidSnapshot = 6,
    /// An immutable event violates event invariants.
    InvalidEvent = 7,
    /// The requested lifecycle transition is not permitted.
    InvalidTransition = 8,
    /// The supplied expected version is stale or inconsistent.
    VersionConflict = 9,
    /// A transition timestamp precedes the latest aggregate timestamp.
    TimestampRegression = 10,
    /// Authentication evidence does not match both active aggregates exactly.
    EvidenceMismatch = 11,
}

impl PrincipalAuthenticatorErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        ERROR_CODES[self as usize]
    }
}

/// A redacted principal-authenticator failure that retains no identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalAuthenticatorError {
    code: PrincipalAuthenticatorErrorCode,
}

impl PrincipalAuthenticatorError {
    /// Creates one redacted failure from a stable code.
    #[must_use]
    pub const fn new(code: PrincipalAuthenticatorErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> PrincipalAuthenticatorErrorCode {
        self.code
    }
}

impl Display for PrincipalAuthenticatorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for PrincipalAuthenticatorError {}

pub(crate) const fn authenticator_error(
    code: PrincipalAuthenticatorErrorCode,
) -> PrincipalAuthenticatorError {
    PrincipalAuthenticatorError::new(code)
}

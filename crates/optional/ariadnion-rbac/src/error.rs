// crates/optional/ariadnion-rbac/src/error.rs - Rust source for Ariadnion.
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
//! Stable authorization construction errors.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Stable machine-readable failures returned while constructing policy data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorizationErrorCode {
    /// A value failed structural validation.
    InvalidArgument,
    /// A bounded collection exceeded its public limit.
    ResourceLimitExceeded,
    /// A policy contains duplicate stable identities.
    DuplicateIdentity,
    /// Policy data crosses a tenant boundary.
    TenantMismatch,
    /// An assignment refers to a role absent from the policy.
    UnknownRole,
    /// The expected authorization policy version does not match current state.
    VersionConflict,
    /// The authorization policy version cannot advance without wrapping.
    VersionExhausted,
}

impl AuthorizationErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "RBAC_INVALID_ARGUMENT",
            Self::ResourceLimitExceeded => "RBAC_RESOURCE_LIMIT_EXCEEDED",
            Self::DuplicateIdentity => "RBAC_DUPLICATE_IDENTITY",
            Self::TenantMismatch => "RBAC_TENANT_MISMATCH",
            Self::UnknownRole => "RBAC_UNKNOWN_ROLE",
            Self::VersionConflict => "RBAC_VERSION_CONFLICT",
            Self::VersionExhausted => "RBAC_VERSION_EXHAUSTED",
        }
    }
}

/// A redacted authorization construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationError {
    code: AuthorizationErrorCode,
}

impl AuthorizationError {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> AuthorizationErrorCode {
        self.code
    }
}

impl Display for AuthorizationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for AuthorizationError {}

pub(crate) const fn error(code: AuthorizationErrorCode) -> AuthorizationError {
    AuthorizationError { code }
}

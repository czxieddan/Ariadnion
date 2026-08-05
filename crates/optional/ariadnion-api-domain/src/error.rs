// crates/optional/ariadnion-api-domain/src/error.rs - Stable API-domain failures for Ariadnion.
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
//! Stable, redacted failures for transport-neutral service requests.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned while constructing service requests.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ApiDomainErrorCode {
    /// A supplied value is empty or violates its documented syntax.
    InvalidArgument,
    /// The caller requested a service-request version this crate does not support.
    UnsupportedVersion,
    /// A supplied value exceeds its documented hard limit.
    LimitExceeded,
}

impl ApiDomainErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "API_DOMAIN_INVALID_ARGUMENT",
            Self::UnsupportedVersion => "API_DOMAIN_UNSUPPORTED_VERSION",
            Self::LimitExceeded => "API_DOMAIN_LIMIT_EXCEEDED",
        }
    }
}

/// A redacted request-contract error that never retains rejected input.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApiDomainError {
    code: ApiDomainErrorCode,
}

impl ApiDomainError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: ApiDomainErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ApiDomainErrorCode {
        self.code
    }
}

impl Debug for ApiDomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApiDomainError({})", self.code.as_str())
    }
}

impl Display for ApiDomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ApiDomainError {}

/// Builds a redacted invalid-argument failure.
#[must_use]
pub(crate) const fn invalid_argument() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::InvalidArgument)
}

/// Builds a redacted hard-limit failure.
#[must_use]
pub(crate) const fn limit_exceeded() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::LimitExceeded)
}

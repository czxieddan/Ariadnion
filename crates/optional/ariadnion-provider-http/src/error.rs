// crates/optional/ariadnion-provider-http/src/error.rs - Redacted profile validation failures for Ariadnion.
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

//! Stable errors that never echo profile material.

use std::fmt::{self, Debug, Display, Formatter};

const PROFILE_ERROR_CODES: [&str; 8] = [
    "provider_http_invalid_origin",
    "provider_http_invalid_path_and_query",
    "provider_http_invalid_header",
    "provider_http_sensitive_header",
    "provider_http_limit_exceeded",
    "provider_http_invalid_timeout",
    "provider_http_invalid_pool",
    "provider_http_invalid_proxy",
];

/// Stable classifications for rejected provider HTTP profile material.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ProviderHttpProfileErrorCode {
    /// The fixed HTTPS origin is invalid.
    InvalidOrigin = 0,
    /// The fixed request path or query is invalid.
    InvalidPathAndQuery = 1,
    /// A header name or value is invalid.
    InvalidHeader = 2,
    /// Profile configuration attempted to retain a secret-bearing header.
    SensitiveHeader = 3,
    /// A configured bound is zero, inconsistent, or exceeds a hard boundary.
    LimitExceeded = 4,
    /// A configured time budget is zero.
    InvalidTimeout = 5,
    /// A connection-pool bound is zero or inconsistent.
    InvalidPool = 6,
    /// A proxy configuration is invalid for this transport profile.
    InvalidProxy = 7,
}

impl ProviderHttpProfileErrorCode {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        PROFILE_ERROR_CODES
            .get(self as usize)
            .copied()
            .unwrap_or("provider_http_invalid_profile")
    }
}

impl Debug for ProviderHttpProfileErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Display for ProviderHttpProfileErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted provider HTTP profile validation failure.
///
/// Formatting this error emits only its stable code. It never exposes a host,
/// request target, header name, header value, or proxy target.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProviderHttpProfileError {
    code: ProviderHttpProfileErrorCode,
}

impl ProviderHttpProfileError {
    pub(crate) const fn new(code: ProviderHttpProfileErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable classification.
    #[must_use]
    pub const fn code(self) -> ProviderHttpProfileErrorCode {
        self.code
    }
}

impl Debug for ProviderHttpProfileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Display for ProviderHttpProfileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ProviderHttpProfileError {}

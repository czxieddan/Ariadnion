// crates/optional/ariadnion-provider-http/src/endpoint.rs - Fixed HTTPS endpoint contracts for Ariadnion.
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

//! Immutable fixed-origin HTTPS endpoints.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::OutboundHost;

use crate::error::{ProviderHttpProfileError, ProviderHttpProfileErrorCode};

/// A checked HTTPS origin and fixed path/query request target.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProviderHttpEndpoint {
    host: OutboundHost,
    port: u16,
    path_and_query: Box<str>,
}

impl ProviderHttpEndpoint {
    /// Creates a fixed HTTPS endpoint.
    ///
    /// `host` must already be a canonical DNS host. `path_and_query` starts
    /// with `/`, may include a query string, and cannot contain a fragment or
    /// ASCII control character.
    ///
    /// # Errors
    ///
    /// Returns a redacted stable error code when the port or request target is
    /// invalid. Invalid input is never retained or formatted by the error.
    pub fn https(
        host: OutboundHost,
        port: u16,
        path_and_query: &str,
    ) -> Result<Self, ProviderHttpProfileError> {
        if port == 0 {
            return Err(ProviderHttpProfileError::new(
                ProviderHttpProfileErrorCode::InvalidOrigin,
            ));
        }
        validate_path_and_query(path_and_query)?;
        Ok(Self {
            host,
            port,
            path_and_query: path_and_query.into(),
        })
    }

    /// Returns the canonical DNS host used for both DNS and TLS identity.
    #[must_use]
    pub const fn host(&self) -> &OutboundHost {
        &self.host
    }

    /// Returns the nonzero TCP origin port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the fixed origin-form request target.
    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }
}

impl Debug for ProviderHttpEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpEndpoint { redacted }")
    }
}

fn validate_path_and_query(value: &str) -> Result<(), ProviderHttpProfileError> {
    if value.starts_with('/') && value.is_ascii() && !contains_disallowed_target_byte(value) {
        return Ok(());
    }
    Err(ProviderHttpProfileError::new(
        ProviderHttpProfileErrorCode::InvalidPathAndQuery,
    ))
}

fn contains_disallowed_target_byte(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b'#' || byte == b' ')
}

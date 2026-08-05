// crates/optional/ariadnion-api-stream/src/error.rs - Stable stream bridge failures for Ariadnion.
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

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures produced by the SSE bridge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ApiStreamErrorCode {
    /// The configured stream or heartbeat bound is invalid.
    InvalidConfiguration,
    /// Every configured active-stream permit is in use.
    ResourceExhausted,
    /// An event envelope sequence is not strictly increasing.
    InvalidSequence,
    /// A payload event violates the stream state machine.
    InvalidTransition,
    /// The publisher closed before sending a terminal event.
    Incomplete,
    /// The stream failed without a safe external explanation.
    Internal,
}

impl ApiStreamErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "API_STREAM_INVALID_CONFIGURATION",
            Self::ResourceExhausted => "API_STREAM_RESOURCE_EXHAUSTED",
            Self::InvalidSequence => "API_STREAM_INVALID_SEQUENCE",
            Self::InvalidTransition => "API_STREAM_INVALID_TRANSITION",
            Self::Incomplete => "API_STREAM_INCOMPLETE",
            Self::Internal => "API_STREAM_INTERNAL",
        }
    }
}

/// A redacted stream bridge error that retains no rejected value or payload.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApiStreamError {
    code: ApiStreamErrorCode,
}

impl ApiStreamError {
    /// Creates a redacted error from its stable machine-readable code.
    #[must_use]
    pub const fn new(code: ApiStreamErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ApiStreamErrorCode {
        self.code
    }
}

impl Debug for ApiStreamError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApiStreamError({})", self.code.as_str())
    }
}

impl Display for ApiStreamError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ApiStreamError {}

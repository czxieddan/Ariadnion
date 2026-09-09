// crates/optional/ariadnion-protocol-openai/src/realtime/error.rs - Redacted Realtime protocol failure classifications.
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
//! Redacted classifications retained by the Realtime protocol leaf.

use std::fmt::{self, Display, Formatter};

use ariadnion_api_domain::{ApiDomainError, ApiDomainErrorCode};

/// Stable redacted classifications for Realtime setup and post-upgrade frames.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum OpenAiRealtimeErrorCode {
    /// The query or frame envelope is malformed or structurally invalid.
    InvalidRequest,
    /// A recognized field has an invalid bounded value.
    InvalidParameter,
    /// A recognized field or event belongs to an unsupported surface variant.
    UnsupportedParameter,
    /// A tenant-scoped public resource is absent or inaccessible.
    NotFound,
    /// The event conflicts with the current bounded session state.
    Conflict,
    /// The caller cancelled before an externally visible effect.
    Cancelled,
    /// The active session or request deadline elapsed.
    DeadlineExceeded,
    /// A bounded queue or resource budget cannot accept more work.
    ResourceExhausted,
    /// A required optional runtime capability is unavailable.
    Unavailable,
    /// An internal event/projection mismatch was redacted.
    Internal,
}

/// A redacted Realtime protocol failure without wire input or secret material.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OpenAiRealtimeError {
    code: OpenAiRealtimeErrorCode,
}

impl OpenAiRealtimeError {
    /// Creates one stable redacted failure classification.
    #[must_use]
    pub const fn new(code: OpenAiRealtimeErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable classification used by the later WebSocket adapter.
    #[must_use]
    pub const fn code(self) -> OpenAiRealtimeErrorCode {
        self.code
    }

    pub(super) const fn invalid_request() -> Self {
        Self::new(OpenAiRealtimeErrorCode::InvalidRequest)
    }

    pub(super) const fn invalid_parameter() -> Self {
        Self::new(OpenAiRealtimeErrorCode::InvalidParameter)
    }

    pub(super) const fn unsupported_parameter() -> Self {
        Self::new(OpenAiRealtimeErrorCode::UnsupportedParameter)
    }

    pub(super) const fn internal() -> Self {
        Self::new(OpenAiRealtimeErrorCode::Internal)
    }
}

impl Display for OpenAiRealtimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for OpenAiRealtimeError {}

impl From<ApiDomainError> for OpenAiRealtimeError {
    fn from(error: ApiDomainError) -> Self {
        Self::new(domain_code(error.code()))
    }
}

impl OpenAiRealtimeErrorCode {
    /// Returns the stable wire code selected by the frozen P4 matrix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        ERROR_CODE_STRINGS[self as usize]
    }
}

const fn domain_code(code: ApiDomainErrorCode) -> OpenAiRealtimeErrorCode {
    match code {
        ApiDomainErrorCode::InvalidArgument | ApiDomainErrorCode::LimitExceeded => {
            OpenAiRealtimeErrorCode::InvalidParameter
        }
        ApiDomainErrorCode::UnsupportedVersion => OpenAiRealtimeErrorCode::UnsupportedParameter,
        ApiDomainErrorCode::Conflict => OpenAiRealtimeErrorCode::Conflict,
        _ => runtime_domain_code(code),
    }
}

const fn runtime_domain_code(code: ApiDomainErrorCode) -> OpenAiRealtimeErrorCode {
    match code {
        ApiDomainErrorCode::Cancelled => OpenAiRealtimeErrorCode::Cancelled,
        ApiDomainErrorCode::DeadlineExceeded => OpenAiRealtimeErrorCode::DeadlineExceeded,
        ApiDomainErrorCode::ResourceExhausted => OpenAiRealtimeErrorCode::ResourceExhausted,
        ApiDomainErrorCode::Unavailable => OpenAiRealtimeErrorCode::Unavailable,
        ApiDomainErrorCode::Internal => OpenAiRealtimeErrorCode::Internal,
        _ => OpenAiRealtimeErrorCode::Internal,
    }
}

const ERROR_CODE_STRINGS: [&str; 10] = [
    "invalid_request",
    "invalid_parameter",
    "unsupported_parameter",
    "not_found",
    "conflict",
    "cancelled",
    "deadline_exceeded",
    "rate_limit_exceeded",
    "service_unavailable",
    "internal_error",
];

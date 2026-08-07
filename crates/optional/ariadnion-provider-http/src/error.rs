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

use ariadnion_provider_sdk::{ProviderFailure, ProviderFailureClass};

const HTTP_ERROR_CODES: [&str; 26] = [
    "provider_http_invalid_origin",
    "provider_http_invalid_path_and_query",
    "provider_http_invalid_header",
    "provider_http_sensitive_header",
    "provider_http_limit_exceeded",
    "provider_http_invalid_timeout",
    "provider_http_invalid_pool",
    "provider_http_invalid_proxy",
    "provider_http_invalid_trust",
    "provider_http_resolution_failed",
    "provider_http_outbound_denied",
    "provider_http_connect_failed",
    "provider_http_tls_handshake_failed",
    "provider_http_http1_handshake_failed",
    "provider_http_cancelled",
    "provider_http_deadline_exceeded",
    "provider_http_runtime_unavailable",
    "provider_http_proxy_connect_failed",
    "provider_http_request_failed",
    "provider_http_redirect_rejected",
    "provider_http_protocol_violation",
    "provider_http_response_limit",
    "provider_http_response_body_failed",
    "provider_http_attempt_timeout",
    "provider_http_pool_exhausted",
    "provider_http_pool_shutdown",
];

/// Stable classifications for provider HTTP failures.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum ProviderHttpErrorCode {
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
    /// The explicit TLS trust-root configuration is invalid.
    InvalidTrust = 8,
    /// DNS resolution or answer validation failed.
    ResolutionFailed = 9,
    /// Outbound policy, freshness, or address authorization denied the connection.
    OutboundDenied = 10,
    /// Numeric TCP connection establishment failed.
    ConnectFailed = 11,
    /// TLS negotiation or peer verification failed.
    TlsHandshakeFailed = 12,
    /// The low-level HTTP/1 client handshake failed.
    Http1HandshakeFailed = 13,
    /// Request cancellation stopped the current phase.
    Cancelled = 14,
    /// A request deadline or phase timeout stopped the current phase.
    DeadlineExceeded = 15,
    /// The required Tokio runtime capability was unavailable.
    RuntimeUnavailable = 16,
    /// HTTP CONNECT tunnel establishment or validation failed.
    ProxyConnectFailed = 17,
    /// Request readiness, serialization, or dispatch failed.
    RequestFailed = 18,
    /// A redirect response was rejected without being followed.
    RedirectRejected = 19,
    /// The upstream response violated the bounded HTTP contract.
    ProtocolViolation = 20,
    /// The upstream response exceeded a configured hard limit.
    ResponseLimit = 21,
    /// Pulling the upstream response body failed.
    ResponseBodyFailed = 22,
    /// A per-attempt phase budget elapsed before the request deadline.
    AttemptTimeout = 23,
    /// The bounded pool cannot admit another connection or waiter.
    PoolExhausted = 24,
    /// The pool has stopped accepting new exchanges.
    PoolShutdown = 25,
}

impl ProviderHttpErrorCode {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        HTTP_ERROR_CODES
            .get(self as usize)
            .copied()
            .unwrap_or("provider_http_invalid_profile")
    }
}

impl Debug for ProviderHttpErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Display for ProviderHttpErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The transport phase associated with an HTTP failure when one is known.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderHttpPhase {
    /// DNS resolution or validation.
    Resolution,
    /// TCP connection establishment.
    Connect,
    /// HTTP CONNECT tunneling through the configured proxy.
    ProxyConnect,
    /// TLS peer verification and handshake.
    TlsHandshake,
    /// Low-level HTTP/1 client connection setup.
    Http1Handshake,
    /// Request-header serialization and transmission.
    RequestHeaders,
    /// Response-header receipt and validation.
    ResponseHeaders,
    /// Pull-driven response-body receipt and validation.
    ResponseBody,
}

impl ProviderHttpPhase {
    /// Returns the stable phase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        connection_phase_name(self)
    }
}

const fn connection_phase_name(phase: ProviderHttpPhase) -> &'static str {
    match phase {
        ProviderHttpPhase::Resolution => "resolution",
        ProviderHttpPhase::Connect => "connect",
        ProviderHttpPhase::ProxyConnect => "proxy_connect",
        ProviderHttpPhase::TlsHandshake => "tls_handshake",
        ProviderHttpPhase::Http1Handshake
        | ProviderHttpPhase::RequestHeaders
        | ProviderHttpPhase::ResponseHeaders
        | ProviderHttpPhase::ResponseBody => exchange_phase_name(phase),
    }
}

const fn exchange_phase_name(phase: ProviderHttpPhase) -> &'static str {
    match phase {
        ProviderHttpPhase::Http1Handshake => "http1_handshake",
        ProviderHttpPhase::RequestHeaders => "request_headers",
        ProviderHttpPhase::ResponseHeaders => "response_headers",
        ProviderHttpPhase::ResponseBody => "response_body",
        ProviderHttpPhase::Resolution
        | ProviderHttpPhase::Connect
        | ProviderHttpPhase::ProxyConnect
        | ProviderHttpPhase::TlsHandshake => connection_phase_name(phase),
    }
}

impl Display for ProviderHttpPhase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted provider HTTP failure.
///
/// Formatting this error emits only its stable code and, when present, its
/// stable phase. It never exposes a host, request target, header name, header
/// value, or proxy target.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProviderHttpError {
    code: ProviderHttpErrorCode,
    phase: Option<ProviderHttpPhase>,
}

impl ProviderHttpError {
    /// Creates an unphased provider HTTP failure.
    #[must_use]
    pub const fn new(code: ProviderHttpErrorCode) -> Self {
        Self { code, phase: None }
    }

    /// Creates a provider HTTP failure associated with one transport phase.
    #[must_use]
    pub const fn with_phase(code: ProviderHttpErrorCode, phase: ProviderHttpPhase) -> Self {
        Self {
            code,
            phase: Some(phase),
        }
    }

    /// Returns the stable classification.
    #[must_use]
    pub const fn code(self) -> ProviderHttpErrorCode {
        self.code
    }

    /// Returns the associated transport phase when the failure is phase-specific.
    #[must_use]
    pub const fn phase(self) -> Option<ProviderHttpPhase> {
        self.phase
    }

    /// Projects this transport error to an unbound provider failure.
    ///
    /// The provider SDK remains the only layer allowed to bind authoritative
    /// attempt progress to the returned classification.
    #[must_use]
    pub const fn provider_failure(self) -> ProviderFailure {
        ProviderFailure::new(provider_failure_class(self.code))
    }
}

const fn provider_failure_class(code: ProviderHttpErrorCode) -> ProviderFailureClass {
    primary_failure_class(code)
}

const fn primary_failure_class(code: ProviderHttpErrorCode) -> ProviderFailureClass {
    match code {
        ProviderHttpErrorCode::Cancelled => ProviderFailureClass::Cancelled,
        ProviderHttpErrorCode::DeadlineExceeded => ProviderFailureClass::DeadlineExceeded,
        ProviderHttpErrorCode::AttemptTimeout => ProviderFailureClass::AttemptTimeout,
        ProviderHttpErrorCode::InvalidPathAndQuery
        | ProviderHttpErrorCode::InvalidHeader
        | ProviderHttpErrorCode::SensitiveHeader
        | ProviderHttpErrorCode::LimitExceeded => ProviderFailureClass::InvalidRequest,
        ProviderHttpErrorCode::RedirectRejected | ProviderHttpErrorCode::ProtocolViolation => {
            ProviderFailureClass::ProtocolViolation
        }
        ProviderHttpErrorCode::ResponseLimit
        | ProviderHttpErrorCode::ResolutionFailed
        | ProviderHttpErrorCode::OutboundDenied
        | ProviderHttpErrorCode::ConnectFailed
        | ProviderHttpErrorCode::TlsHandshakeFailed
        | ProviderHttpErrorCode::Http1HandshakeFailed
        | ProviderHttpErrorCode::ProxyConnectFailed
        | ProviderHttpErrorCode::RequestFailed
        | ProviderHttpErrorCode::ResponseBodyFailed
        | ProviderHttpErrorCode::InvalidOrigin
        | ProviderHttpErrorCode::InvalidTimeout
        | ProviderHttpErrorCode::InvalidPool
        | ProviderHttpErrorCode::InvalidProxy
        | ProviderHttpErrorCode::InvalidTrust
        | ProviderHttpErrorCode::RuntimeUnavailable
        | ProviderHttpErrorCode::PoolExhausted
        | ProviderHttpErrorCode::PoolShutdown => secondary_failure_class(code),
    }
}

const fn secondary_failure_class(code: ProviderHttpErrorCode) -> ProviderFailureClass {
    match code {
        ProviderHttpErrorCode::ResponseLimit => ProviderFailureClass::ResponseLimit,
        ProviderHttpErrorCode::ResolutionFailed
        | ProviderHttpErrorCode::OutboundDenied
        | ProviderHttpErrorCode::ConnectFailed
        | ProviderHttpErrorCode::TlsHandshakeFailed
        | ProviderHttpErrorCode::Http1HandshakeFailed
        | ProviderHttpErrorCode::ProxyConnectFailed
        | ProviderHttpErrorCode::RequestFailed
        | ProviderHttpErrorCode::ResponseBodyFailed
        | ProviderHttpErrorCode::PoolExhausted => ProviderFailureClass::UpstreamUnavailable,
        ProviderHttpErrorCode::InvalidOrigin
        | ProviderHttpErrorCode::InvalidTimeout
        | ProviderHttpErrorCode::InvalidPool
        | ProviderHttpErrorCode::InvalidProxy
        | ProviderHttpErrorCode::InvalidTrust
        | ProviderHttpErrorCode::RuntimeUnavailable
        | ProviderHttpErrorCode::PoolShutdown => ProviderFailureClass::Internal,
        ProviderHttpErrorCode::Cancelled
        | ProviderHttpErrorCode::DeadlineExceeded
        | ProviderHttpErrorCode::AttemptTimeout
        | ProviderHttpErrorCode::InvalidPathAndQuery
        | ProviderHttpErrorCode::InvalidHeader
        | ProviderHttpErrorCode::SensitiveHeader
        | ProviderHttpErrorCode::LimitExceeded
        | ProviderHttpErrorCode::RedirectRejected
        | ProviderHttpErrorCode::ProtocolViolation => primary_failure_class(code),
    }
}

impl Debug for ProviderHttpError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        format_error(formatter, *self)
    }
}

impl Display for ProviderHttpError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        format_error(formatter, *self)
    }
}

impl std::error::Error for ProviderHttpError {}

/// Compatibility alias for profile validation failures.
pub type ProviderHttpProfileError = ProviderHttpError;

/// Compatibility alias for profile validation failure codes.
pub type ProviderHttpProfileErrorCode = ProviderHttpErrorCode;

fn format_error(formatter: &mut Formatter<'_>, error: ProviderHttpError) -> fmt::Result {
    formatter.write_str(error.code.as_str())?;
    match error.phase {
        Some(phase) => write!(formatter, ":{phase}"),
        None => Ok(()),
    }
}

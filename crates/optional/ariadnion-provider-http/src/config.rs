// crates/optional/ariadnion-provider-http/src/config.rs - Bounded provider HTTP profile configuration for Ariadnion.
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

//! Immutable checked configuration for the provider HTTP transport.

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use ariadnion_core::{MAX_OUTBOUND_RESOLVED_ADDRESSES, OutboundTarget};

use crate::endpoint::ProviderHttpEndpoint;
use crate::error::{ProviderHttpProfileError, ProviderHttpProfileErrorCode};

/// Maximum retained fixed path/query bytes before allocation.
pub const MAX_PROVIDER_HTTP_PATH_AND_QUERY_BYTES: usize = 8 * 1024;
/// Maximum static header-name bytes before allocation.
pub const MAX_PROVIDER_HTTP_HEADER_NAME_BYTES: usize = 256;
/// Maximum static header-value bytes before allocation.
pub const MAX_PROVIDER_HTTP_HEADER_VALUE_BYTES: usize = 8 * 1024;

const MAX_DNS_ANSWERS: usize = MAX_OUTBOUND_RESOLVED_ADDRESSES;
const MAX_HEADERS: usize = 64;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 64;
const MAX_IDLE: usize = 64;
const MAX_WAITERS: usize = 128;
const MAX_RESOLUTION_AGE_MILLIS: u64 = 60_000;
const MAX_CANCELLATION_POLL_MILLIS: u64 = 25;
const MAX_CONNECT_MILLIS: u64 = 5_000;
const MAX_TLS_MILLIS: u64 = 10_000;
const MAX_RESPONSE_HEADERS_MILLIS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct BoundedCount<const MAX: usize>(usize);

impl<const MAX: usize> BoundedCount<MAX> {
    fn new(
        value: usize,
        code: ProviderHttpProfileErrorCode,
    ) -> Result<Self, ProviderHttpProfileError> {
        if value == 0 || value > MAX {
            return Err(ProviderHttpProfileError::new(code));
        }
        Ok(Self(value))
    }

    const fn get(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct BoundedDuration<const MAX_MILLIS: u64>(Duration);

impl<const MAX_MILLIS: u64> BoundedDuration<MAX_MILLIS> {
    fn new(
        value: Duration,
        code: ProviderHttpProfileErrorCode,
    ) -> Result<Self, ProviderHttpProfileError> {
        if value == Duration::ZERO || value > Duration::from_millis(MAX_MILLIS) {
            return Err(ProviderHttpProfileError::new(code));
        }
        Ok(Self(value))
    }

    const fn get(self) -> Duration {
        self.0
    }
}

/// One HTTP method supported by a fixed provider HTTP profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderHttpMethod {
    /// Retrieve a resource without a request body.
    Get,
    /// Submit a request body to create or process a resource.
    Post,
    /// Replace a resource representation.
    Put,
    /// Apply a partial resource update.
    Patch,
    /// Delete a resource.
    Delete,
    /// Retrieve response metadata without a response body.
    Head,
}

impl ProviderHttpMethod {
    /// Returns the HTTP/1 method token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
        }
    }
}

/// One checked static request header.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProviderHttpHeader {
    name: Box<str>,
    value: Box<str>,
}

impl ProviderHttpHeader {
    /// Creates a checked non-sensitive static request header.
    ///
    /// Static profile headers cannot carry credentials, cookies, or proxy
    /// authorization. Those values belong to later request-scoped boundaries.
    ///
    /// # Errors
    ///
    /// Returns a redacted stable error code when either component is malformed
    /// or the name is secret-bearing.
    pub fn new(name: &str, value: &str) -> Result<Self, ProviderHttpProfileError> {
        validate_component_length(name, MAX_PROVIDER_HTTP_HEADER_NAME_BYTES)?;
        validate_header_name(name)?;
        validate_component_length(value, MAX_PROVIDER_HTTP_HEADER_VALUE_BYTES)?;
        validate_header_value(value)?;
        Ok(Self {
            name: name.into(),
            value: value.into(),
        })
    }

    /// Returns the checked header name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the checked static header value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    fn wire_len(&self) -> usize {
        self.name.len() + self.value.len() + 4
    }
}

impl Debug for ProviderHttpHeader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpHeader { redacted }")
    }
}

/// Checked hard limits for one provider HTTP profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProviderHttpLimits {
    max_dns_answers: BoundedCount<MAX_DNS_ANSWERS>,
    max_headers: BoundedCount<MAX_HEADERS>,
    max_header_bytes: BoundedCount<MAX_HEADER_BYTES>,
    max_request_body_bytes: BoundedCount<MAX_BODY_BYTES>,
    max_response_body_bytes: BoundedCount<MAX_BODY_BYTES>,
    max_frame_bytes: BoundedCount<MAX_FRAME_BYTES>,
}

impl ProviderHttpLimits {
    /// Creates checked finite transport limits.
    ///
    /// DNS answers cannot exceed the core outbound authorization boundary.
    ///
    /// # Errors
    ///
    /// Returns a stable error code when a bound is zero or exceeds its hard
    /// transport ceiling, including the core DNS-answer maximum.
    pub fn new(
        max_dns_answers: usize,
        max_headers: usize,
        max_header_bytes: usize,
        max_request_body_bytes: usize,
        max_response_body_bytes: usize,
        max_frame_bytes: usize,
    ) -> Result<Self, ProviderHttpProfileError> {
        Ok(Self {
            max_dns_answers: BoundedCount::new(
                max_dns_answers,
                ProviderHttpProfileErrorCode::LimitExceeded,
            )?,
            max_headers: BoundedCount::new(
                max_headers,
                ProviderHttpProfileErrorCode::LimitExceeded,
            )?,
            max_header_bytes: BoundedCount::new(
                max_header_bytes,
                ProviderHttpProfileErrorCode::LimitExceeded,
            )?,
            max_request_body_bytes: BoundedCount::new(
                max_request_body_bytes,
                ProviderHttpProfileErrorCode::LimitExceeded,
            )?,
            max_response_body_bytes: BoundedCount::new(
                max_response_body_bytes,
                ProviderHttpProfileErrorCode::LimitExceeded,
            )?,
            max_frame_bytes: BoundedCount::new(
                max_frame_bytes,
                ProviderHttpProfileErrorCode::LimitExceeded,
            )?,
        })
    }

    /// Returns the maximum accepted DNS answers before policy authorization.
    #[must_use]
    pub const fn max_dns_answers(self) -> usize {
        self.max_dns_answers.get()
    }

    /// Returns the maximum number of request headers.
    #[must_use]
    pub const fn max_headers(self) -> usize {
        self.max_headers.get()
    }

    /// Returns the aggregate encoded request-header limit.
    #[must_use]
    pub const fn max_header_bytes(self) -> usize {
        self.max_header_bytes.get()
    }

    /// Returns the maximum request-body byte count.
    #[must_use]
    pub const fn max_request_body_bytes(self) -> usize {
        self.max_request_body_bytes.get()
    }

    /// Returns the maximum response-body byte count.
    #[must_use]
    pub const fn max_response_body_bytes(self) -> usize {
        self.max_response_body_bytes.get()
    }

    /// Returns the maximum decoded HTTP frame byte count.
    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes.get()
    }
}

impl Default for ProviderHttpLimits {
    fn default() -> Self {
        Self {
            max_dns_answers: BoundedCount(MAX_DNS_ANSWERS),
            max_headers: BoundedCount(MAX_HEADERS),
            max_header_bytes: BoundedCount(MAX_HEADER_BYTES),
            max_request_body_bytes: BoundedCount(MAX_BODY_BYTES),
            max_response_body_bytes: BoundedCount(MAX_BODY_BYTES),
            max_frame_bytes: BoundedCount(MAX_FRAME_BYTES),
        }
    }
}

/// Checked phase and cancellation budgets for one provider HTTP profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProviderHttpTimeouts {
    max_resolution_age: BoundedDuration<MAX_RESOLUTION_AGE_MILLIS>,
    cancellation_poll: BoundedDuration<MAX_CANCELLATION_POLL_MILLIS>,
    connect: BoundedDuration<MAX_CONNECT_MILLIS>,
    tls_handshake: BoundedDuration<MAX_TLS_MILLIS>,
    response_headers: BoundedDuration<MAX_RESPONSE_HEADERS_MILLIS>,
}

impl ProviderHttpTimeouts {
    /// Creates nonzero resolution, cancellation, and phase budgets.
    ///
    /// # Errors
    ///
    /// Returns a stable error code when any duration is zero or exceeds its
    /// hard phase ceiling.
    pub fn new(
        max_resolution_age: Duration,
        cancellation_poll: Duration,
        connect: Duration,
        tls_handshake: Duration,
        response_headers: Duration,
    ) -> Result<Self, ProviderHttpProfileError> {
        Ok(Self {
            max_resolution_age: BoundedDuration::new(
                max_resolution_age,
                ProviderHttpProfileErrorCode::InvalidTimeout,
            )?,
            cancellation_poll: BoundedDuration::new(
                cancellation_poll,
                ProviderHttpProfileErrorCode::InvalidTimeout,
            )?,
            connect: BoundedDuration::new(connect, ProviderHttpProfileErrorCode::InvalidTimeout)?,
            tls_handshake: BoundedDuration::new(
                tls_handshake,
                ProviderHttpProfileErrorCode::InvalidTimeout,
            )?,
            response_headers: BoundedDuration::new(
                response_headers,
                ProviderHttpProfileErrorCode::InvalidTimeout,
            )?,
        })
    }

    /// Returns the maximum age of a completed DNS resolution.
    #[must_use]
    pub const fn max_resolution_age(self) -> Duration {
        self.max_resolution_age.get()
    }

    /// Returns the maximum delay before a cancellable operation observes cancellation.
    #[must_use]
    pub const fn cancellation_poll(self) -> Duration {
        self.cancellation_poll.get()
    }

    /// Returns the TCP connection phase budget.
    #[must_use]
    pub const fn connect(self) -> Duration {
        self.connect.get()
    }

    /// Returns the TLS handshake phase budget.
    #[must_use]
    pub const fn tls_handshake(self) -> Duration {
        self.tls_handshake.get()
    }

    /// Returns the response-header phase budget.
    #[must_use]
    pub const fn response_headers(self) -> Duration {
        self.response_headers.get()
    }
}

impl Default for ProviderHttpTimeouts {
    fn default() -> Self {
        Self {
            max_resolution_age: BoundedDuration(Duration::from_secs(60)),
            cancellation_poll: BoundedDuration(Duration::from_millis(25)),
            connect: BoundedDuration(Duration::from_secs(5)),
            tls_handshake: BoundedDuration(Duration::from_secs(10)),
            response_headers: BoundedDuration(Duration::from_secs(30)),
        }
    }
}

/// Checked connection-pool limits for one isolated provider HTTP profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProviderHttpPool {
    max_connections: BoundedCount<MAX_CONNECTIONS>,
    max_idle: BoundedCount<MAX_IDLE>,
    max_waiters: BoundedCount<MAX_WAITERS>,
}

impl ProviderHttpPool {
    /// Creates checked connection-pool limits.
    ///
    /// # Errors
    ///
    /// Returns a stable error code when a count is zero or idle connections
    /// would exceed all connections.
    pub fn new(
        max_connections: usize,
        max_idle: usize,
        max_waiters: usize,
    ) -> Result<Self, ProviderHttpProfileError> {
        let connections =
            BoundedCount::new(max_connections, ProviderHttpProfileErrorCode::InvalidPool)?;
        let idle = BoundedCount::new(max_idle, ProviderHttpProfileErrorCode::InvalidPool)?;
        let waiters = BoundedCount::new(max_waiters, ProviderHttpProfileErrorCode::InvalidPool)?;
        if max_idle > max_connections {
            return Err(ProviderHttpProfileError::new(
                ProviderHttpProfileErrorCode::InvalidPool,
            ));
        }
        Ok(Self {
            max_connections: connections,
            max_idle: idle,
            max_waiters: waiters,
        })
    }

    /// Returns the maximum live TCP connections for the profile.
    #[must_use]
    pub const fn max_connections(self) -> usize {
        self.max_connections.get()
    }

    /// Returns the maximum idle reusable connections for the profile.
    #[must_use]
    pub const fn max_idle(self) -> usize {
        self.max_idle.get()
    }

    /// Returns the maximum callers waiting for a pooled connection.
    #[must_use]
    pub const fn max_waiters(self) -> usize {
        self.max_waiters.get()
    }
}

impl Default for ProviderHttpPool {
    fn default() -> Self {
        Self {
            max_connections: BoundedCount(MAX_CONNECTIONS),
            max_idle: BoundedCount(MAX_IDLE),
            max_waiters: BoundedCount(MAX_WAITERS),
        }
    }
}

/// The root-store choice for provider TLS peer validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderHttpTrust {
    /// Validate against the versioned WebPKI root set bundled by this crate.
    WebPkiRoots,
}

impl ProviderHttpTrust {
    /// Selects the bundled WebPKI root set.
    #[must_use]
    pub const fn webpki_roots() -> Self {
        Self::WebPkiRoots
    }
}

/// A proxy boundary that never carries proxy credentials.
#[derive(Clone, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderHttpProxy {
    /// Connect directly to the fixed HTTPS origin.
    Disabled,
    /// Establish an unauthenticated HTTP CONNECT tunnel through this target.
    UnauthenticatedConnect {
        /// The canonical proxy DNS target authorized before the tunnel opens.
        target: OutboundTarget,
    },
}

impl Debug for ProviderHttpProxy {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("ProviderHttpProxy::Disabled"),
            Self::UnauthenticatedConnect { .. } => {
                formatter.write_str("ProviderHttpProxy::UnauthenticatedConnect { redacted }")
            }
        }
    }
}

impl ProviderHttpProxy {
    /// Disables proxy use for the profile.
    #[must_use]
    pub const fn disabled() -> Self {
        Self::Disabled
    }

    /// Selects an unauthenticated HTTP CONNECT proxy target.
    #[must_use]
    pub const fn unauthenticated_connect(target: OutboundTarget) -> Self {
        Self::UnauthenticatedConnect { target }
    }

    /// Returns the configured proxy target when proxy use is enabled.
    #[must_use]
    pub const fn target(&self) -> Option<&OutboundTarget> {
        match self {
            Self::Disabled => None,
            Self::UnauthenticatedConnect { target } => Some(target),
        }
    }
}

/// An immutable checked HTTP transport profile with no network side effects.
pub struct ProviderHttpProfile {
    endpoint: ProviderHttpEndpoint,
    method: ProviderHttpMethod,
    headers: Box<[ProviderHttpHeader]>,
    limits: ProviderHttpLimits,
    timeouts: ProviderHttpTimeouts,
    pool: ProviderHttpPool,
    trust: ProviderHttpTrust,
    proxy: ProviderHttpProxy,
}

impl ProviderHttpProfile {
    /// Starts construction of one fixed-origin profile.
    #[must_use]
    pub fn builder(
        endpoint: ProviderHttpEndpoint,
        method: ProviderHttpMethod,
    ) -> ProviderHttpProfileBuilder {
        ProviderHttpProfileBuilder {
            endpoint,
            method,
            headers: Vec::new(),
            limits: ProviderHttpLimits::default(),
            timeouts: ProviderHttpTimeouts::default(),
            pool: ProviderHttpPool::default(),
            trust: ProviderHttpTrust::webpki_roots(),
            proxy: ProviderHttpProxy::disabled(),
            header_overflow: false,
        }
    }

    /// Returns the checked fixed HTTPS endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &ProviderHttpEndpoint {
        &self.endpoint
    }

    /// Returns the fixed request method.
    #[must_use]
    pub const fn method(&self) -> ProviderHttpMethod {
        self.method
    }

    /// Returns the checked static request headers.
    #[must_use]
    pub fn headers(&self) -> &[ProviderHttpHeader] {
        &self.headers
    }

    /// Returns the configured transport limits.
    #[must_use]
    pub const fn limits(&self) -> ProviderHttpLimits {
        self.limits
    }

    /// Returns the configured phase and cancellation budgets.
    #[must_use]
    pub const fn timeouts(&self) -> ProviderHttpTimeouts {
        self.timeouts
    }

    /// Returns the configured isolated-pool limits.
    #[must_use]
    pub const fn pool(&self) -> ProviderHttpPool {
        self.pool
    }

    /// Returns the TLS root-store choice.
    #[must_use]
    pub const fn trust(&self) -> ProviderHttpTrust {
        self.trust
    }

    /// Returns the proxy boundary choice.
    #[must_use]
    pub const fn proxy(&self) -> &ProviderHttpProxy {
        &self.proxy
    }
}

impl Debug for ProviderHttpProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpProfile { redacted }")
    }
}

/// A single-use builder for an immutable checked HTTP transport profile.
pub struct ProviderHttpProfileBuilder {
    endpoint: ProviderHttpEndpoint,
    method: ProviderHttpMethod,
    headers: Vec<ProviderHttpHeader>,
    limits: ProviderHttpLimits,
    timeouts: ProviderHttpTimeouts,
    pool: ProviderHttpPool,
    trust: ProviderHttpTrust,
    proxy: ProviderHttpProxy,
    header_overflow: bool,
}

impl ProviderHttpProfileBuilder {
    /// Replaces the static request headers.
    #[must_use]
    pub fn headers<I>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = ProviderHttpHeader>,
    {
        self.header_overflow = false;
        let mut bounded = Vec::with_capacity(MAX_HEADERS);
        let mut iterator = headers.into_iter();
        for _ in 0..=MAX_HEADERS {
            let Some(header) = iterator.next() else {
                break;
            };
            if bounded.len() == MAX_HEADERS {
                self.header_overflow = true;
                break;
            }
            bounded.push(header);
        }
        self.headers = bounded;
        self
    }

    /// Replaces the transport limits.
    #[must_use]
    pub const fn limits(mut self, limits: ProviderHttpLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the resolution, cancellation, and phase budgets.
    #[must_use]
    pub const fn timeouts(mut self, timeouts: ProviderHttpTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Replaces the isolated-pool limits.
    #[must_use]
    pub const fn pool(mut self, pool: ProviderHttpPool) -> Self {
        self.pool = pool;
        self
    }

    /// Replaces the TLS root-store choice.
    #[must_use]
    pub const fn trust(mut self, trust: ProviderHttpTrust) -> Self {
        self.trust = trust;
        self
    }

    /// Replaces the proxy boundary choice.
    #[must_use]
    pub fn proxy(mut self, proxy: ProviderHttpProxy) -> Self {
        self.proxy = proxy;
        self
    }

    /// Validates and freezes the profile without opening a network connection.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when static headers violate the checked
    /// header count, size, or duplicate-name constraints.
    pub fn build(self) -> Result<ProviderHttpProfile, ProviderHttpProfileError> {
        if self.header_overflow {
            return Err(ProviderHttpProfileError::new(
                ProviderHttpProfileErrorCode::LimitExceeded,
            ));
        }
        validate_headers(&self.headers, self.limits)?;
        Ok(ProviderHttpProfile {
            endpoint: self.endpoint,
            method: self.method,
            headers: self.headers.into_boxed_slice(),
            limits: self.limits,
            timeouts: self.timeouts,
            pool: self.pool,
            trust: self.trust,
            proxy: self.proxy,
        })
    }
}

fn validate_header_name(name: &str) -> Result<(), ProviderHttpProfileError> {
    if is_sensitive_header(name) {
        return Err(ProviderHttpProfileError::new(
            ProviderHttpProfileErrorCode::SensitiveHeader,
        ));
    }
    if name.is_empty() || !name.is_ascii() || name.bytes().any(is_not_header_token) {
        return Err(ProviderHttpProfileError::new(
            ProviderHttpProfileErrorCode::InvalidHeader,
        ));
    }
    if is_reserved_header(name) {
        return Err(ProviderHttpProfileError::new(
            ProviderHttpProfileErrorCode::InvalidHeader,
        ));
    }
    Ok(())
}

fn validate_component_length(value: &str, maximum: usize) -> Result<(), ProviderHttpProfileError> {
    if value.len() > maximum {
        return Err(ProviderHttpProfileError::new(
            ProviderHttpProfileErrorCode::LimitExceeded,
        ));
    }
    Ok(())
}

fn is_reserved_header(name: &str) -> bool {
    const RESERVED: [&str; 8] = [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
    ];
    name.to_ascii_lowercase().starts_with("proxy-")
        || RESERVED
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

fn is_sensitive_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("set-cookie")
}

fn is_not_header_token(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric()
        && !matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_header_value(value: &str) -> Result<(), ProviderHttpProfileError> {
    if value.is_empty() || !value.is_ascii() || value.bytes().any(is_invalid_header_value_byte) {
        return Err(ProviderHttpProfileError::new(
            ProviderHttpProfileErrorCode::InvalidHeader,
        ));
    }
    Ok(())
}

fn is_invalid_header_value_byte(byte: u8) -> bool {
    byte.is_ascii_control() && byte != b'\t'
}

fn validate_headers(
    headers: &[ProviderHttpHeader],
    limits: ProviderHttpLimits,
) -> Result<(), ProviderHttpProfileError> {
    validate_header_count(headers.len(), limits.max_headers.get())?;
    validate_header_bytes(headers, limits.max_header_bytes.get())?;
    validate_unique_header_names(headers)
}

fn validate_header_count(count: usize, limit: usize) -> Result<(), ProviderHttpProfileError> {
    if count > limit {
        return Err(ProviderHttpProfileError::new(
            ProviderHttpProfileErrorCode::LimitExceeded,
        ));
    }
    Ok(())
}

fn validate_header_bytes(
    headers: &[ProviderHttpHeader],
    limit: usize,
) -> Result<(), ProviderHttpProfileError> {
    let encoded = headers.iter().try_fold(0_usize, |total, header| {
        total.checked_add(header.wire_len()).ok_or_else(|| {
            ProviderHttpProfileError::new(ProviderHttpProfileErrorCode::LimitExceeded)
        })
    })?;
    if encoded > limit {
        return Err(ProviderHttpProfileError::new(
            ProviderHttpProfileErrorCode::LimitExceeded,
        ));
    }
    Ok(())
}

fn validate_unique_header_names(
    headers: &[ProviderHttpHeader],
) -> Result<(), ProviderHttpProfileError> {
    let names = headers
        .iter()
        .map(|header| header.name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if names.len() != headers.len() {
        return Err(ProviderHttpProfileError::new(
            ProviderHttpProfileErrorCode::InvalidHeader,
        ));
    }
    Ok(())
}

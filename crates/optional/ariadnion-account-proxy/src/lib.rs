// crates/optional/ariadnion-account-proxy/src/lib.rs - Account proxy contracts for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Typed account proxy profiles, secret references, and bounded egress policy.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::num::{NonZeroU16, NonZeroU32};

use ariadnion_account_domain::SecretRef;

/// Maximum bytes in a profile identity.
pub const MAX_PROFILE_ID_BYTES: usize = 128;
/// Maximum bytes in a proxy host name.
pub const MAX_HOST_BYTES: usize = 253;
/// Maximum bytes in a region identifier.
pub const MAX_REGION_BYTES: usize = 32;
/// Maximum regions in an allow or deny constraint.
pub const MAX_REGIONS: usize = 64;
/// Maximum simultaneous connections allowed by a profile.
pub const MAX_CONNECTIONS: u32 = 4096;
/// Maximum connect timeout in milliseconds.
pub const MAX_CONNECT_TIMEOUT_MS: u32 = 120_000;
/// Maximum request timeout in milliseconds.
pub const MAX_REQUEST_TIMEOUT_MS: u32 = 900_000;
/// Maximum redirects followed by a proxy client.
pub const MAX_REDIRECTS: u8 = 16;

/// Stable machine-readable proxy validation failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AccountProxyErrorCode {
    /// A value is empty, malformed, or outside its bound.
    InvalidArgument,
    /// A proxy host is malformed or outside its bound.
    InvalidHost,
    /// A proxy port is outside the permitted range.
    InvalidPort,
    /// A region identifier is malformed or duplicated.
    InvalidRegion,
    /// A secret reference is not valid for the selected endpoint mode.
    InvalidSecretReference,
    /// A connectivity policy exceeds a configured bound.
    ConnectivityOutOfBounds,
    /// A profile requires a proxy endpoint but was configured for direct egress.
    InvalidEgressConstraint,
}

impl AccountProxyErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ACCOUNT_PROXY_INVALID_ARGUMENT",
            Self::InvalidHost => "ACCOUNT_PROXY_INVALID_HOST",
            Self::InvalidPort => "ACCOUNT_PROXY_INVALID_PORT",
            Self::InvalidRegion => "ACCOUNT_PROXY_INVALID_REGION",
            Self::InvalidSecretReference => "ACCOUNT_PROXY_INVALID_SECRET_REFERENCE",
            Self::ConnectivityOutOfBounds => "ACCOUNT_PROXY_CONNECTIVITY_OUT_OF_BOUNDS",
            Self::InvalidEgressConstraint => "ACCOUNT_PROXY_INVALID_EGRESS_CONSTRAINT",
        }
    }
}

impl Display for AccountProxyErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted proxy validation error that never stores rejected input or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountProxyError {
    code: AccountProxyErrorCode,
}

impl AccountProxyError {
    fn new(code: AccountProxyErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AccountProxyErrorCode {
        self.code
    }
}

impl Display for AccountProxyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AccountProxyError {}

/// A bounded proxy profile identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProxyProfileId(Box<str>);

impl ProxyProfileId {
    /// Parses a visible ASCII profile identity.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::InvalidArgument`] when the value is
    /// empty, oversized, non-ASCII, or contains control bytes.
    pub fn parse(value: &str) -> Result<Self, AccountProxyError> {
        if !valid_ascii(value, MAX_PROFILE_ID_BYTES) {
            return Err(AccountProxyError::new(
                AccountProxyErrorCode::InvalidArgument,
            ));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ProxyProfileId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProxyProfileId")
            .field(&self.0)
            .finish()
    }
}

impl Display for ProxyProfileId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Supported proxy transport schemes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProxyScheme {
    /// HTTP CONNECT proxy.
    Http,
    /// HTTPS CONNECT proxy.
    Https,
    /// SOCKS5 proxy.
    Socks5,
}

/// A validated proxy endpoint or explicit direct egress.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum EgressEndpoint {
    /// Connect directly without a proxy.
    Direct,
    /// Connect through a bounded proxy host and port.
    Proxy {
        /// Transport scheme used by the proxy.
        scheme: ProxyScheme,
        /// Proxy host name or address.
        host: Box<str>,
        /// Proxy TCP port.
        port: NonZeroU16,
    },
}

impl EgressEndpoint {
    /// Creates an explicit direct endpoint.
    #[must_use]
    pub const fn direct() -> Self {
        Self::Direct
    }

    /// Creates a validated proxy endpoint.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::InvalidHost`] or
    /// [`AccountProxyErrorCode::InvalidPort`] when the endpoint is malformed.
    pub fn proxy(scheme: ProxyScheme, host: &str, port: u16) -> Result<Self, AccountProxyError> {
        if !valid_host(host) {
            return Err(AccountProxyError::new(AccountProxyErrorCode::InvalidHost));
        }
        let Some(port) = NonZeroU16::new(port) else {
            return Err(AccountProxyError::new(AccountProxyErrorCode::InvalidPort));
        };
        Ok(Self::Proxy {
            scheme,
            host: host.into(),
            port,
        })
    }

    /// Returns whether this endpoint is direct egress.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    /// Returns the transport scheme for a proxied endpoint.
    #[must_use]
    pub const fn scheme(&self) -> Option<ProxyScheme> {
        match self {
            Self::Direct => None,
            Self::Proxy { scheme, .. } => Some(*scheme),
        }
    }

    /// Returns the validated proxy host, or `None` for direct egress.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        match self {
            Self::Direct => None,
            Self::Proxy { host, .. } => Some(host),
        }
    }

    /// Returns the proxy port, or `None` for direct egress.
    #[must_use]
    pub const fn port(&self) -> Option<NonZeroU16> {
        match self {
            Self::Direct => None,
            Self::Proxy { port, .. } => Some(*port),
        }
    }
}

impl Debug for EgressEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => formatter.write_str("EgressEndpoint::Direct"),
            Self::Proxy { scheme, host, port } => formatter
                .debug_struct("EgressEndpoint::Proxy")
                .field("scheme", scheme)
                .field("host", host)
                .field("port", port)
                .finish(),
        }
    }
}

/// Allowed destination-region constraint for a profile.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RegionConstraint {
    /// Permit any validated destination region.
    Any,
    /// Permit only the listed regions.
    Allowlist(Box<[Box<str>]>),
    /// Permit every region except those listed.
    Denylist(Box<[Box<str>]>),
}

impl RegionConstraint {
    /// Creates an unconstrained region policy.
    #[must_use]
    pub const fn any() -> Self {
        Self::Any
    }

    /// Creates an allowlist with deterministic ordering and duplicate rejection.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::InvalidRegion`] for malformed, duplicate,
    /// or overlong region lists.
    pub fn allowlist<I, S>(regions: I) -> Result<Self, AccountProxyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        build_region_constraint(regions, false)
    }

    /// Creates a denylist with deterministic ordering and duplicate rejection.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::InvalidRegion`] for malformed, duplicate,
    /// or overlong region lists.
    pub fn denylist<I, S>(regions: I) -> Result<Self, AccountProxyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        build_region_constraint(regions, true)
    }

    /// Returns whether a destination region is permitted.
    #[must_use]
    pub fn permits(&self, region: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Allowlist(regions) => regions.iter().any(|entry| entry.as_ref() == region),
            Self::Denylist(regions) => !regions.iter().any(|entry| entry.as_ref() == region),
        }
    }
}

/// Bounded connection and request limits for a proxy profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectivityPolicy {
    connect_timeout_ms: NonZeroU32,
    request_timeout_ms: NonZeroU32,
    max_connections: NonZeroU32,
    max_redirects: u8,
}

impl ConnectivityPolicy {
    /// Creates a validated connectivity policy.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::ConnectivityOutOfBounds`] when any
    /// timeout, connection count, or redirect count is outside its bound.
    pub fn new(
        connect_timeout_ms: u32,
        request_timeout_ms: u32,
        max_connections: u32,
        max_redirects: u8,
    ) -> Result<Self, AccountProxyError> {
        let Some(connect_timeout_ms) = NonZeroU32::new(connect_timeout_ms) else {
            return Err(connectivity_error());
        };
        let Some(request_timeout_ms) = NonZeroU32::new(request_timeout_ms) else {
            return Err(connectivity_error());
        };
        let Some(max_connections) = NonZeroU32::new(max_connections) else {
            return Err(connectivity_error());
        };
        if connect_timeout_ms.get() > MAX_CONNECT_TIMEOUT_MS
            || request_timeout_ms.get() > MAX_REQUEST_TIMEOUT_MS
            || max_connections.get() > MAX_CONNECTIONS
            || max_redirects > MAX_REDIRECTS
        {
            return Err(connectivity_error());
        }
        Ok(Self {
            connect_timeout_ms,
            request_timeout_ms,
            max_connections,
            max_redirects,
        })
    }

    /// Returns the proxy connection timeout in milliseconds.
    #[must_use]
    pub const fn connect_timeout_ms(self) -> u32 {
        self.connect_timeout_ms.get()
    }

    /// Returns the request timeout in milliseconds.
    #[must_use]
    pub const fn request_timeout_ms(self) -> u32 {
        self.request_timeout_ms.get()
    }

    /// Returns the maximum concurrent connections.
    #[must_use]
    pub const fn max_connections(self) -> u32 {
        self.max_connections.get()
    }

    /// Returns the maximum redirects followed by a client.
    #[must_use]
    pub const fn max_redirects(self) -> u8 {
        self.max_redirects
    }
}

/// A typed account proxy profile containing metadata-only authentication.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AccountProxyProfile {
    id: ProxyProfileId,
    endpoint: EgressEndpoint,
    authentication: Option<SecretRef>,
    regions: RegionConstraint,
    connectivity: ConnectivityPolicy,
}

impl AccountProxyProfile {
    /// Creates a validated profile.
    ///
    /// Authentication is represented only by [`SecretRef`] metadata. Secret
    /// bytes, tokens, and passwords are never accepted or stored by this crate.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::InvalidSecretReference`] when a direct
    /// endpoint is paired with authentication metadata.
    pub fn new(
        id: ProxyProfileId,
        endpoint: EgressEndpoint,
        authentication: Option<SecretRef>,
        regions: RegionConstraint,
        connectivity: ConnectivityPolicy,
    ) -> Result<Self, AccountProxyError> {
        if endpoint.is_direct() && authentication.is_some() {
            return Err(AccountProxyError::new(
                AccountProxyErrorCode::InvalidSecretReference,
            ));
        }
        Ok(Self {
            id,
            endpoint,
            authentication,
            regions,
            connectivity,
        })
    }

    /// Returns the profile identity.
    #[must_use]
    pub const fn id(&self) -> &ProxyProfileId {
        &self.id
    }

    /// Returns the configured egress endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &EgressEndpoint {
        &self.endpoint
    }

    /// Returns metadata-only authentication, if configured.
    #[must_use]
    pub const fn authentication(&self) -> Option<&SecretRef> {
        self.authentication.as_ref()
    }

    /// Returns the destination-region constraint.
    #[must_use]
    pub const fn regions(&self) -> &RegionConstraint {
        &self.regions
    }

    /// Returns the bounded connectivity policy.
    #[must_use]
    pub const fn connectivity(&self) -> ConnectivityPolicy {
        self.connectivity
    }

    /// Returns whether a destination region may use this profile.
    #[must_use]
    pub fn permits_region(&self, region: &str) -> bool {
        self.regions.permits(region)
    }
}

fn valid_ascii(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.is_ascii()
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn valid_host(value: &str) -> bool {
    valid_ascii(value, MAX_HOST_BYTES)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-:_[]".contains(&byte))
}

fn build_region_constraint<I, S>(
    regions: I,
    denylist: bool,
) -> Result<RegionConstraint, AccountProxyError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut values = regions
        .into_iter()
        .map(|region| region.as_ref().to_owned())
        .collect::<Vec<_>>();
    if values.is_empty() || values.len() > MAX_REGIONS {
        return Err(region_error());
    }
    if values.iter().any(|region| !valid_region(region.as_str())) {
        return Err(region_error());
    }
    values.sort_unstable();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(region_error());
    }
    let values = values
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    Ok(if denylist {
        RegionConstraint::Denylist(values)
    } else {
        RegionConstraint::Allowlist(values)
    })
}

fn valid_region(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REGION_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn region_error() -> AccountProxyError {
    AccountProxyError::new(AccountProxyErrorCode::InvalidRegion)
}

fn connectivity_error() -> AccountProxyError {
    AccountProxyError::new(AccountProxyErrorCode::ConnectivityOutOfBounds)
}

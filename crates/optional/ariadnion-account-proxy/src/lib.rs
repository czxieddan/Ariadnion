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

pub mod migrations;

use std::fmt::{self, Debug, Display, Formatter};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::{Arc, RwLock};

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
/// Maximum profiles in one published proxy snapshot.
pub const MAX_PROFILES: usize = 1 << 12;

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
    /// A proxy scheme is not supported by the execution boundary.
    UnsupportedScheme,
    /// A snapshot contains duplicate profile identities.
    DuplicateProfile,
    /// A snapshot or profile collection exceeds its fixed bound.
    LimitExceeded,
    /// A publication does not extend the caller-observed snapshot.
    VersionConflict,
    /// A snapshot generation cannot advance without wrapping.
    VersionExhausted,
    /// The process-local publication owner cannot be read or updated safely.
    StateUnavailable,
    /// The requested profile is absent from the immutable snapshot.
    ProfileNotFound,
}

impl AccountProxyErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        if let Some(code) = self.validation_code() {
            return code;
        }
        if let Some(code) = self.publication_code() {
            return code;
        }
        self.egress_code()
    }

    const fn egress_code(self) -> &'static str {
        match self {
            Self::InvalidEgressConstraint => "ACCOUNT_PROXY_INVALID_EGRESS_CONSTRAINT",
            Self::UnsupportedScheme => "ACCOUNT_PROXY_UNSUPPORTED_SCHEME",
            Self::ProfileNotFound => "ACCOUNT_PROXY_PROFILE_NOT_FOUND",
            _ => "ACCOUNT_PROXY_INVALID_ARGUMENT",
        }
    }

    const fn validation_code(self) -> Option<&'static str> {
        match self {
            Self::InvalidArgument => Some("ACCOUNT_PROXY_INVALID_ARGUMENT"),
            Self::InvalidHost => Some("ACCOUNT_PROXY_INVALID_HOST"),
            Self::InvalidPort => Some("ACCOUNT_PROXY_INVALID_PORT"),
            Self::InvalidRegion => Some("ACCOUNT_PROXY_INVALID_REGION"),
            Self::InvalidSecretReference => Some("ACCOUNT_PROXY_INVALID_SECRET_REFERENCE"),
            Self::ConnectivityOutOfBounds => Some("ACCOUNT_PROXY_CONNECTIVITY_OUT_OF_BOUNDS"),
            _ => None,
        }
    }

    const fn publication_code(self) -> Option<&'static str> {
        match self {
            Self::DuplicateProfile => Some("ACCOUNT_PROXY_DUPLICATE_PROFILE"),
            Self::LimitExceeded => Some("ACCOUNT_PROXY_LIMIT_EXCEEDED"),
            Self::VersionConflict => Some("ACCOUNT_PROXY_VERSION_CONFLICT"),
            Self::VersionExhausted => Some("ACCOUNT_PROXY_VERSION_EXHAUSTED"),
            Self::StateUnavailable => Some("ACCOUNT_PROXY_STATE_UNAVAILABLE"),
            _ => None,
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

/// Stable failures returned by a durable proxy snapshot port.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProxyPersistenceErrorCode {
    /// The backing store could not complete the requested operation.
    Unavailable,
    /// The backing store rejected a stale or non-successor generation.
    Conflict,
    /// The backing store returned a malformed or mismatched result.
    Corrupt,
}

impl ProxyPersistenceErrorCode {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "ACCOUNT_PROXY_PERSISTENCE_UNAVAILABLE",
            Self::Conflict => "ACCOUNT_PROXY_PERSISTENCE_CONFLICT",
            Self::Corrupt => "ACCOUNT_PROXY_PERSISTENCE_CORRUPT",
        }
    }
}

impl Display for ProxyPersistenceErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted failure returned by a durable proxy snapshot port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyPersistenceError {
    code: ProxyPersistenceErrorCode,
}

impl ProxyPersistenceError {
    /// Creates a redacted persistence failure.
    #[must_use]
    pub const fn new(code: ProxyPersistenceErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ProxyPersistenceErrorCode {
        self.code
    }
}

impl Display for ProxyPersistenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ProxyPersistenceError {}

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

impl ProxyScheme {
    /// Parses one supported wire-level proxy scheme.
    ///
    /// Scheme matching is ASCII case-insensitive. No other scheme is accepted
    /// by this execution boundary.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::UnsupportedScheme`] for every value
    /// outside the supported set.
    pub fn parse(value: &str) -> Result<Self, AccountProxyError> {
        if value.eq_ignore_ascii_case("http") {
            return Ok(Self::Http);
        }
        if value.eq_ignore_ascii_case("https") {
            return Ok(Self::Https);
        }
        if value.eq_ignore_ascii_case("socks5") {
            return Ok(Self::Socks5);
        }
        Err(AccountProxyError::new(
            AccountProxyErrorCode::UnsupportedScheme,
        ))
    }
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
        let connect_timeout_ms = bounded_connectivity(connect_timeout_ms, MAX_CONNECT_TIMEOUT_MS)?;
        let request_timeout_ms = bounded_connectivity(request_timeout_ms, MAX_REQUEST_TIMEOUT_MS)?;
        let max_connections = bounded_connectivity(max_connections, MAX_CONNECTIONS)?;
        if max_redirects > MAX_REDIRECTS {
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

/// A non-zero generation identifying one immutable proxy snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProxyGeneration(NonZeroU64);

impl ProxyGeneration {
    /// Returns the first publishable generation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero generation.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, AccountProxyError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| AccountProxyError::new(AccountProxyErrorCode::InvalidArgument))
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Advances the generation without wrapping.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, AccountProxyError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| AccountProxyError::new(AccountProxyErrorCode::VersionExhausted))
    }
}

/// The exact proxy profile selected from one immutable generation.
///
/// The descriptor owns the validated profile and its source generation. An
/// execution adapter can retain this value across asynchronous work without
/// resolving the mutable profile identity again.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProxyExecutionDescriptor {
    generation: ProxyGeneration,
    profile: Arc<AccountProxyProfile>,
}

impl ProxyExecutionDescriptor {
    fn new(generation: ProxyGeneration, profile: AccountProxyProfile) -> Self {
        Self {
            generation,
            profile: Arc::new(profile),
        }
    }

    /// Returns the immutable source generation.
    #[must_use]
    pub const fn generation(&self) -> ProxyGeneration {
        self.generation
    }

    /// Returns the exact metadata-only profile selected for execution.
    #[must_use]
    pub fn profile(&self) -> &AccountProxyProfile {
        self.profile.as_ref()
    }
}

/// A complete immutable collection of proxy profiles published as one unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyExecutionSnapshot {
    generation: ProxyGeneration,
    profiles: Arc<[AccountProxyProfile]>,
}

impl ProxyExecutionSnapshot {
    /// Validates and freezes a complete proxy profile snapshot.
    ///
    /// Profiles are sorted by identity, and duplicate identities are rejected
    /// before any snapshot becomes visible to readers.
    ///
    /// # Errors
    /// Returns a bounded, duplicate, or validation error without publishing a
    /// partial collection.
    pub fn new(
        generation: ProxyGeneration,
        mut profiles: Vec<AccountProxyProfile>,
    ) -> Result<Self, AccountProxyError> {
        if profiles.len() > MAX_PROFILES {
            return Err(AccountProxyError::new(AccountProxyErrorCode::LimitExceeded));
        }
        profiles.sort_unstable_by(|left, right| left.id().cmp(right.id()));
        if profiles.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(AccountProxyError::new(
                AccountProxyErrorCode::DuplicateProfile,
            ));
        }
        Ok(Self {
            generation,
            profiles: Arc::from(profiles.into_boxed_slice()),
        })
    }

    /// Returns the immutable snapshot generation.
    #[must_use]
    pub const fn generation(&self) -> ProxyGeneration {
        self.generation
    }

    /// Returns profiles in canonical identity order.
    #[must_use]
    pub fn profiles(&self) -> &[AccountProxyProfile] {
        &self.profiles
    }

    /// Resolves a profile into an execution-owned descriptor.
    ///
    /// The returned descriptor retains the exact profile selected from this
    /// snapshot and therefore remains valid if a later generation is
    /// published.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::ProfileNotFound`] when the identity is
    /// absent from this complete snapshot.
    pub fn resolve(
        &self,
        profile_id: &ProxyProfileId,
    ) -> Result<ProxyExecutionDescriptor, AccountProxyError> {
        let profile = self
            .profiles
            .binary_search_by(|candidate| candidate.id().cmp(profile_id))
            .ok()
            .map(|index| self.profiles[index].clone())
            .ok_or_else(|| AccountProxyError::new(AccountProxyErrorCode::ProfileNotFound))?;
        Ok(ProxyExecutionDescriptor::new(self.generation, profile))
    }
}

/// One generation-checked durable proxy publication request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyPublishRequest {
    expected_generation: ProxyGeneration,
    snapshot: ProxyExecutionSnapshot,
}

impl ProxyPublishRequest {
    /// Creates a request to publish one exact successor snapshot.
    #[must_use]
    pub const fn new(
        expected_generation: ProxyGeneration,
        snapshot: ProxyExecutionSnapshot,
    ) -> Self {
        Self {
            expected_generation,
            snapshot,
        }
    }

    /// Returns the generation observed by the caller before publication.
    #[must_use]
    pub const fn expected_generation(&self) -> ProxyGeneration {
        self.expected_generation
    }

    /// Returns the complete immutable snapshot requested for publication.
    #[must_use]
    pub const fn snapshot(&self) -> &ProxyExecutionSnapshot {
        &self.snapshot
    }
}

/// Receipt proving that a durable proxy publication committed one generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyPublishReceipt {
    generation: ProxyGeneration,
}

impl ProxyPublishReceipt {
    /// Creates a receipt for one committed generation.
    #[must_use]
    pub const fn committed(generation: ProxyGeneration) -> Self {
        Self { generation }
    }

    /// Returns the generation durably committed by the store.
    #[must_use]
    pub const fn generation(self) -> ProxyGeneration {
        self.generation
    }
}

/// Durable port for complete immutable proxy snapshots.
///
/// Implementations own serialization, authorization, transactionality, and
/// recovery. They must reject a stale expected generation, persist the entire
/// requested snapshot as one bounded unit, and return a receipt containing the
/// exact committed generation. Authentication metadata remains a [`SecretRef`]
/// inside the typed profile and must never be replaced with secret bytes. A
/// store must not reenter the owning [`AtomicProxyExecutionBook`] while a
/// publication call is active; the owner holds its write lock through the
/// durable commit and local pointer replacement.
pub trait ProxySnapshotStore: Send + Sync {
    /// Loads the latest complete snapshot from durable storage.
    ///
    /// # Errors
    /// Returns a redacted [`ProxyPersistenceError`] when storage is unavailable
    /// or the persisted snapshot is corrupt.
    fn load(&self) -> Result<ProxyExecutionSnapshot, ProxyPersistenceError>;

    /// Persists one exact generation-checked snapshot.
    ///
    /// # Errors
    /// Returns [`ProxyPersistenceErrorCode::Conflict`] for a stale expected
    /// generation and never reports success without a matching receipt.
    fn publish(
        &self,
        request: &ProxyPublishRequest,
    ) -> Result<ProxyPublishReceipt, ProxyPersistenceError>;
}

/// Process-local atomic owner for complete immutable proxy snapshots.
pub struct AtomicProxyExecutionBook {
    current: RwLock<Arc<ProxyExecutionSnapshot>>,
}

impl AtomicProxyExecutionBook {
    /// Creates an owner from one complete initial snapshot.
    #[must_use]
    pub fn new(initial: ProxyExecutionSnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
        }
    }

    /// Loads one complete snapshot into a process-local owner.
    ///
    /// The store is read before the owner is created, so a failed load cannot
    /// expose a partially initialized or synthetic in-memory state.
    ///
    /// # Errors
    /// Returns the store's redacted persistence failure unchanged.
    pub fn load_from_store(store: &dyn ProxySnapshotStore) -> Result<Self, ProxyPersistenceError> {
        Ok(Self::new(store.load()?))
    }

    /// Reads the latest complete snapshot.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::StateUnavailable`] when the read lock
    /// is poisoned.
    pub fn current_snapshot(&self) -> Result<Arc<ProxyExecutionSnapshot>, AccountProxyError> {
        self.current
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| AccountProxyError::new(AccountProxyErrorCode::StateUnavailable))
    }

    /// Publishes the exact successor of the caller-observed generation.
    ///
    /// The write lock covers generation validation and pointer replacement, so
    /// readers observe either the complete old snapshot or the complete new
    /// snapshot. Existing descriptors remain valid because they own their
    /// selected profile and source generation.
    ///
    /// # Errors
    /// Returns [`AccountProxyErrorCode::VersionConflict`] for a stale expected
    /// generation or non-successor snapshot, and preserves the current value
    /// on every failure.
    pub fn publish(
        &self,
        expected: ProxyGeneration,
        next: ProxyExecutionSnapshot,
    ) -> Result<Arc<ProxyExecutionSnapshot>, AccountProxyError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| AccountProxyError::new(AccountProxyErrorCode::StateUnavailable))?;
        if current.generation() != expected {
            return Err(AccountProxyError::new(
                AccountProxyErrorCode::VersionConflict,
            ));
        }
        let required = current.generation().next()?;
        if next.generation() != required {
            return Err(AccountProxyError::new(
                AccountProxyErrorCode::VersionConflict,
            ));
        }
        let published = Arc::new(next);
        *current = Arc::clone(&published);
        Ok(published)
    }

    /// Persists and then publishes one exact successor snapshot.
    ///
    /// The write lock spans local generation validation, durable publication,
    /// receipt validation, and pointer replacement. A store error or mismatched
    /// receipt leaves the current in-memory snapshot unchanged.
    ///
    /// # Errors
    /// Returns a redacted persistence failure when the store rejects the
    /// request. A stale local generation is projected as a persistence conflict
    /// without invoking the store.
    pub fn publish_durable(
        &self,
        store: &dyn ProxySnapshotStore,
        expected: ProxyGeneration,
        next: ProxyExecutionSnapshot,
    ) -> Result<Arc<ProxyExecutionSnapshot>, ProxyPersistenceError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| ProxyPersistenceError::new(ProxyPersistenceErrorCode::Unavailable))?;
        validate_durable_successor(current.generation(), expected, next.generation())?;
        let request = ProxyPublishRequest::new(expected, next.clone());
        let receipt = store.publish(&request)?;
        if receipt.generation() != next.generation() {
            return Err(ProxyPersistenceError::new(
                ProxyPersistenceErrorCode::Corrupt,
            ));
        }
        let published = Arc::new(next);
        *current = Arc::clone(&published);
        Ok(published)
    }
}

/// Compatibility alias naming the immutable collection as a profile snapshot.
pub type ProxyProfileSnapshot = ProxyExecutionSnapshot;

/// Compatibility alias for the process-local profile snapshot owner.
pub type AtomicProxyProfileBook = AtomicProxyExecutionBook;

fn validate_durable_successor(
    current: ProxyGeneration,
    expected: ProxyGeneration,
    next: ProxyGeneration,
) -> Result<(), ProxyPersistenceError> {
    if current != expected {
        return Err(ProxyPersistenceError::new(
            ProxyPersistenceErrorCode::Conflict,
        ));
    }
    let required = current
        .next()
        .map_err(|_| ProxyPersistenceError::new(ProxyPersistenceErrorCode::Conflict))?;
    if next != required {
        return Err(ProxyPersistenceError::new(
            ProxyPersistenceErrorCode::Conflict,
        ));
    }
    Ok(())
}

fn bounded_connectivity(value: u32, maximum: u32) -> Result<NonZeroU32, AccountProxyError> {
    let value = NonZeroU32::new(value).ok_or_else(connectivity_error)?;
    if value.get() > maximum {
        return Err(connectivity_error());
    }
    Ok(value)
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
    validate_regions(&values)?;
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

fn validate_regions(values: &[String]) -> Result<(), AccountProxyError> {
    if values.is_empty() || values.len() > MAX_REGIONS {
        return Err(region_error());
    }
    if values.iter().any(|region| !valid_region(region.as_str())) {
        return Err(region_error());
    }
    Ok(())
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

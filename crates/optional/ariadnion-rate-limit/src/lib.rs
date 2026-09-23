// crates/optional/ariadnion-rate-limit/src/lib.rs - Rate and concurrency admission for Ariadnion.
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
//! Atomic, bounded admission across rate and concurrency dimensions.
//!
//! The controller uses caller-supplied monotonic nanosecond ticks. UTC time is
//! deliberately excluded from admission arithmetic, so wall-clock correction,
//! leap seconds, and clock rollback cannot lengthen or reopen a window. Adapters
//! may attach UTC timestamps to audit events after admission has completed.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod controller;
mod policy_publication;

pub use controller::{AcceptedFinalization, AdmissionController, AdmissionLease};
pub use policy_publication::{
    AdmissionPolicyBook, AdmissionPolicyPort, AdmissionPolicyReceipt, AdmissionPolicySnapshot,
    AdmissionPolicyVersion,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU32;
use std::time::Duration;
/// Maximum byte length of a tenant, user, API-key, or model limit identity.
pub const MAX_LIMIT_ID_BYTES: usize = 160;
/// Maximum number of dimensions admitted atomically for one request.
pub const MAX_DIMENSIONS_PER_ADMISSION: usize = 4;
/// Maximum number of configured dimension policies.
pub const MAX_POLICIES: usize = 1 << 17;
/// Shortest supported rate window.
pub const MIN_RATE_WINDOW: Duration = Duration::from_millis(10);
/// Longest supported short-window rate interval.
pub const MAX_RATE_WINDOW: Duration = Duration::from_secs(60 * 60);
/// Longest supported concurrency lease.
pub const MAX_LEASE_DURATION: Duration = Duration::from_secs(15 * 60);
/// Stable machine-readable admission failure codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AdmissionErrorCode {
    /// An input is empty, malformed, duplicated, or outside its bound.
    InvalidArgument,
    /// An admission request contains too many dimensions.
    TooManyDimensions,
    /// The policy set contains too many entries.
    TooManyPolicies,
    /// A dimension appears more than once.
    DuplicateDimension,
    /// No policy exists for a requested dimension.
    PolicyNotFound,
    /// A static policy publication used a stale expected version.
    PolicyVersionConflict,
    /// A configured short-window rate capacity is exhausted.
    RateLimited,
    /// A configured concurrency capacity is exhausted.
    ConcurrencyLimited,
    /// A supplied monotonic observation moved backward.
    ClockRegressed,
    /// Monotonic time or an internal identity cannot advance safely.
    CounterExhausted,
    /// An admission lease has already expired.
    LeaseExpired,
    /// An admission lease has already been released or cancelled.
    LeaseClosed,
    /// Internal admission state is unavailable.
    StateUnavailable,
}

/// Redacted capacity scope associated with a refusal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AdmissionRefusalScope {
    /// The selected account's rate or concurrency dimension refused admission.
    Account,
    /// A tenant, user, API-key, or model dimension refused admission.
    Request,
}

impl AdmissionErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument
            | Self::TooManyDimensions
            | Self::TooManyPolicies
            | Self::DuplicateDimension
            | Self::PolicyNotFound => request_error_code(self),
            Self::RateLimited | Self::ConcurrencyLimited | Self::ClockRegressed => {
                capacity_error_code(self)
            }
            _ => lifecycle_error_code(self),
        }
    }
}

const fn request_error_code(code: AdmissionErrorCode) -> &'static str {
    match code {
        AdmissionErrorCode::InvalidArgument => "ADMISSION_INVALID_ARGUMENT",
        AdmissionErrorCode::TooManyDimensions => "ADMISSION_TOO_MANY_DIMENSIONS",
        AdmissionErrorCode::TooManyPolicies => "ADMISSION_TOO_MANY_POLICIES",
        AdmissionErrorCode::DuplicateDimension => "ADMISSION_DUPLICATE_DIMENSION",
        AdmissionErrorCode::PolicyNotFound => "ADMISSION_POLICY_NOT_FOUND",
        _ => "ADMISSION_INVALID_ARGUMENT",
    }
}

const fn capacity_error_code(code: AdmissionErrorCode) -> &'static str {
    match code {
        AdmissionErrorCode::RateLimited => "ADMISSION_RATE_LIMITED",
        AdmissionErrorCode::ConcurrencyLimited => "ADMISSION_CONCURRENCY_LIMITED",
        AdmissionErrorCode::ClockRegressed => "ADMISSION_CLOCK_REGRESSED",
        _ => "ADMISSION_STATE_UNAVAILABLE",
    }
}

const fn lifecycle_error_code(code: AdmissionErrorCode) -> &'static str {
    match code {
        AdmissionErrorCode::CounterExhausted => "ADMISSION_COUNTER_EXHAUSTED",
        AdmissionErrorCode::LeaseExpired => "ADMISSION_LEASE_EXPIRED",
        AdmissionErrorCode::LeaseClosed => "ADMISSION_LEASE_CLOSED",
        AdmissionErrorCode::PolicyVersionConflict => "ADMISSION_POLICY_VERSION_CONFLICT",
        AdmissionErrorCode::StateUnavailable => "ADMISSION_STATE_UNAVAILABLE",
        _ => "ADMISSION_STATE_UNAVAILABLE",
    }
}
/// Redacted admission failure with optional bounded retry guidance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionError {
    code: AdmissionErrorCode,
    retry_after: Option<Duration>,
    scope: Option<AdmissionRefusalScope>,
}

impl AdmissionError {
    const fn new(code: AdmissionErrorCode, retry_after: Option<Duration>) -> Self {
        Self {
            code,
            retry_after,
            scope: None,
        }
    }

    const fn with_scope(
        code: AdmissionErrorCode,
        retry_after: Option<Duration>,
        scope: AdmissionRefusalScope,
    ) -> Self {
        Self {
            code,
            retry_after,
            scope: Some(scope),
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AdmissionErrorCode {
        self.code
    }

    /// Returns the minimum known wait before a retry can succeed.
    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        self.retry_after
    }

    /// Returns the redacted scope that refused capacity, when applicable.
    #[must_use]
    pub const fn refusal_scope(self) -> Option<AdmissionRefusalScope> {
        self.scope
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AdmissionError {}

/// Monotonic nanoseconds from an adapter-owned clock origin.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    /// Creates a monotonic observation from nanoseconds since a stable origin.
    #[must_use]
    pub const fn from_nanos(value: u64) -> Self {
        Self(value)
    }

    /// Returns nanoseconds since the adapter's stable origin.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    fn checked_add(self, duration: Duration) -> Result<Self, AdmissionError> {
        let nanos = u64::try_from(duration.as_nanos()).map_err(|_| exhausted())?;
        self.0.checked_add(nanos).map(Self).ok_or_else(exhausted)
    }

    fn duration_until(self, later: Self) -> Duration {
        Duration::from_nanos(later.0.saturating_sub(self.0))
    }
}

macro_rules! define_limit_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses a non-empty visible ASCII identity of at most 160 bytes.
            ///
            /// # Errors
            /// Returns [`AdmissionErrorCode::InvalidArgument`] for malformed input.
            pub fn parse(value: &str) -> Result<Self, AdmissionError> {
                validate_identity(value)?;
                Ok(Self(value.into()))
            }

            /// Returns the validated identity.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }
    };
}

define_limit_id!(
    /// Tenant identity used only for tenant-scoped admission.
    TenantLimitId
);
define_limit_id!(
    /// Account identity used only inside a tenant-bound account admission key.
    AccountLimitId
);
define_limit_id!(
    /// User identity used only for user-scoped admission.
    UserLimitId
);
define_limit_id!(
    /// Non-secret API-key identity or fingerprint used for key-scoped admission.
    ApiKeyLimitId
);
define_limit_id!(
    /// Canonical model identity used only for model-scoped admission.
    ModelLimitId
);

/// Tenant-bound identity for one provider account's admission capacity.
///
/// Account identifiers are not assumed to be globally unique. Keeping the
/// tenant identity in the key prevents equal account names in different
/// tenants from sharing rate or concurrency counters.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountLimitKey {
    tenant: TenantLimitId,
    account: AccountLimitId,
}

impl AccountLimitKey {
    /// Creates one account-scoped key from validated opaque identities.
    #[must_use]
    pub const fn new(tenant: TenantLimitId, account: AccountLimitId) -> Self {
        Self { tenant, account }
    }

    /// Returns the tenant that owns the account capacity.
    #[must_use]
    pub const fn tenant(&self) -> &TenantLimitId {
        &self.tenant
    }

    /// Returns the account identity within the owning tenant.
    #[must_use]
    pub const fn account(&self) -> &AccountLimitId {
        &self.account
    }
}

impl Debug for AccountLimitKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountLimitKey(<opaque>)")
    }
}

/// The stable category of a rate or concurrency dimension.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LimitDimension {
    /// Tenant-wide capacity.
    Tenant,
    /// Capacity for one account within an explicit tenant boundary.
    Account,
    /// Capacity for one user within an adapter-defined tenant boundary.
    User,
    /// Capacity for one non-secret API-key identity or fingerprint.
    ApiKey,
    /// Capacity for one canonical model.
    Model,
}

/// A strongly typed admission dimension key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LimitKey {
    /// Tenant-scoped key.
    Tenant(TenantLimitId),
    /// Account-scoped key with an explicit tenant binding.
    Account(AccountLimitKey),
    /// User-scoped key.
    User(UserLimitId),
    /// API-key-scoped key.
    ApiKey(ApiKeyLimitId),
    /// Model-scoped key.
    Model(ModelLimitId),
}

impl LimitKey {
    /// Returns the key's dimension without exposing its identity.
    #[must_use]
    pub const fn dimension(&self) -> LimitDimension {
        match self {
            Self::Tenant(_) => LimitDimension::Tenant,
            Self::Account(_) => LimitDimension::Account,
            Self::User(_) => LimitDimension::User,
            Self::ApiKey(_) => LimitDimension::ApiKey,
            Self::Model(_) => LimitDimension::Model,
        }
    }
}

impl Debug for LimitKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LimitKey")
            .field(&self.dimension())
            .finish()
    }
}

/// A bounded short-window rate policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateRule {
    capacity: NonZeroU32,
    window: Duration,
}

impl RateRule {
    /// Creates a rate policy for a half-open monotonic window `[start, end)`.
    ///
    /// # Errors
    /// Returns [`AdmissionErrorCode::InvalidArgument`] when the window is
    /// shorter than 10 milliseconds or longer than one hour.
    pub fn new(capacity: NonZeroU32, window: Duration) -> Result<Self, AdmissionError> {
        if !(MIN_RATE_WINDOW..=MAX_RATE_WINDOW).contains(&window) {
            return Err(invalid());
        }
        Ok(Self { capacity, window })
    }

    /// Returns the maximum units accepted in one window.
    #[must_use]
    pub const fn capacity(self) -> NonZeroU32 {
        self.capacity
    }

    /// Returns the fixed monotonic window length.
    #[must_use]
    pub const fn window(self) -> Duration {
        self.window
    }
}

/// A bounded concurrency policy with an expiry safety net.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConcurrencyRule {
    limit: NonZeroU32,
    lease_duration: Duration,
}

impl ConcurrencyRule {
    /// Creates a concurrency policy with a non-zero lease duration.
    ///
    /// # Errors
    /// Returns [`AdmissionErrorCode::InvalidArgument`] when the duration is
    /// zero or exceeds 15 minutes.
    pub fn new(limit: NonZeroU32, lease_duration: Duration) -> Result<Self, AdmissionError> {
        if lease_duration.is_zero() || lease_duration > MAX_LEASE_DURATION {
            return Err(invalid());
        }
        Ok(Self {
            limit,
            lease_duration,
        })
    }

    /// Returns the simultaneous admission limit.
    #[must_use]
    pub const fn limit(self) -> NonZeroU32 {
        self.limit
    }

    /// Returns the maximum lifetime of an unreleased permit.
    #[must_use]
    pub const fn lease_duration(self) -> Duration {
        self.lease_duration
    }
}

/// Rate and concurrency policy for one exact dimension key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimitPolicy {
    key: LimitKey,
    rate: Option<RateRule>,
    concurrency: Option<ConcurrencyRule>,
}

impl LimitPolicy {
    /// Creates a policy with at least one enforced resource boundary.
    ///
    /// # Errors
    /// Returns [`AdmissionErrorCode::InvalidArgument`] when both rules are absent.
    pub fn new(
        key: LimitKey,
        rate: Option<RateRule>,
        concurrency: Option<ConcurrencyRule>,
    ) -> Result<Self, AdmissionError> {
        if rate.is_none() && concurrency.is_none() {
            return Err(invalid());
        }
        Ok(Self {
            key,
            rate,
            concurrency,
        })
    }

    /// Returns the exact policy key.
    #[must_use]
    pub const fn key(&self) -> &LimitKey {
        &self.key
    }

    /// Returns the optional rate rule.
    #[must_use]
    pub const fn rate(&self) -> Option<RateRule> {
        self.rate
    }

    /// Returns the optional concurrency rule.
    #[must_use]
    pub const fn concurrency(&self) -> Option<ConcurrencyRule> {
        self.concurrency
    }
}

/// Immutable, duplicate-free admission policy set.
#[derive(Clone, Debug)]
pub struct AdmissionPolicySet {
    policies: BTreeMap<LimitKey, LimitPolicy>,
}

impl AdmissionPolicySet {
    /// Validates and indexes admission policies.
    ///
    /// # Errors
    /// Returns a stable error for an oversized or duplicate policy set.
    pub fn new(policies: Vec<LimitPolicy>) -> Result<Self, AdmissionError> {
        if policies.len() > MAX_POLICIES {
            return Err(error(AdmissionErrorCode::TooManyPolicies));
        }
        let mut indexed = BTreeMap::new();
        for policy in policies {
            if indexed.insert(policy.key.clone(), policy).is_some() {
                return Err(error(AdmissionErrorCode::DuplicateDimension));
            }
        }
        Ok(Self { policies: indexed })
    }

    /// Returns the policy for one exact dimension key.
    #[must_use]
    pub fn policy(&self, key: &LimitKey) -> Option<&LimitPolicy> {
        self.policies.get(key)
    }

    /// Returns the number of configured policies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Returns whether no policies are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

/// One atomic request for rate units and concurrency permits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRequest {
    keys: Vec<LimitKey>,
    units: NonZeroU32,
}

impl AdmissionRequest {
    /// Creates a bounded, duplicate-free multi-dimensional request.
    ///
    /// # Errors
    /// Returns a stable error for an empty, oversized, or duplicate key set.
    pub fn new(keys: Vec<LimitKey>, units: NonZeroU32) -> Result<Self, AdmissionError> {
        validate_request_keys(&keys)?;
        Ok(Self { keys, units })
    }

    /// Returns requested dimensions in deterministic caller order.
    #[must_use]
    pub fn keys(&self) -> &[LimitKey] {
        &self.keys
    }

    /// Returns the rate units reserved for every configured rate dimension.
    #[must_use]
    pub const fn units(&self) -> NonZeroU32 {
        self.units
    }
}

/// Opaque identity of one pending or committed rate reservation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RateReservationId(u64);

impl RateReservationId {
    /// Returns the process-local reservation identity for durable correlation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Opaque identity of one concurrency admission lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdmissionLeaseId(u64);

impl AdmissionLeaseId {
    /// Returns the process-local lease identity for durable correlation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A pending rate reservation held until commit, cancellation, or expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateReservation {
    id: RateReservationId,
    keys: Vec<LimitKey>,
    units: NonZeroU32,
    expires_at: MonotonicTime,
}

impl RateReservation {
    /// Returns the reservation identity.
    #[must_use]
    pub const fn id(&self) -> RateReservationId {
        self.id
    }

    /// Returns rate-limited keys covered atomically.
    #[must_use]
    pub fn keys(&self) -> &[LimitKey] {
        &self.keys
    }

    /// Returns reserved units per rate-limited key.
    #[must_use]
    pub const fn units(&self) -> NonZeroU32 {
        self.units
    }

    /// Returns the exclusive monotonic expiry before commit.
    #[must_use]
    pub const fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }
}

/// Typed concurrency permit for one exact dimension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrencyPermit {
    lease_id: AdmissionLeaseId,
    key: LimitKey,
    expires_at: MonotonicTime,
}

impl ConcurrencyPermit {
    /// Returns the owning lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> AdmissionLeaseId {
        self.lease_id
    }

    /// Returns the exact protected dimension.
    #[must_use]
    pub const fn key(&self) -> &LimitKey {
        &self.key
    }

    /// Returns the exclusive monotonic permit expiry.
    #[must_use]
    pub const fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }
}

/// Remaining capacity snapshot for one exact dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitSnapshot {
    rate_remaining: Option<u32>,
    rate_resets_at: Option<MonotonicTime>,
    concurrency_remaining: Option<u32>,
}

impl LimitSnapshot {
    /// Returns remaining short-window units, when rate limiting is configured.
    #[must_use]
    pub const fn rate_remaining(self) -> Option<u32> {
        self.rate_remaining
    }

    /// Returns the exclusive monotonic window end, when configured.
    #[must_use]
    pub const fn rate_resets_at(self) -> Option<MonotonicTime> {
        self.rate_resets_at
    }

    /// Returns remaining simultaneous permits, when configured.
    #[must_use]
    pub const fn concurrency_remaining(self) -> Option<u32> {
        self.concurrency_remaining
    }
}

fn validate_identity(value: &str) -> Result<(), AdmissionError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_LIMIT_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
    if valid { Ok(()) } else { Err(invalid()) }
}

fn validate_request_keys(keys: &[LimitKey]) -> Result<(), AdmissionError> {
    if keys.is_empty() {
        return Err(invalid());
    }
    if keys.len() > MAX_DIMENSIONS_PER_ADMISSION {
        return Err(error(AdmissionErrorCode::TooManyDimensions));
    }
    let mut dimensions = BTreeSet::new();
    for key in keys {
        if !dimensions.insert(key.dimension()) {
            return Err(error(AdmissionErrorCode::DuplicateDimension));
        }
    }
    Ok(())
}

const fn invalid() -> AdmissionError {
    error(AdmissionErrorCode::InvalidArgument)
}

const fn exhausted() -> AdmissionError {
    error(AdmissionErrorCode::CounterExhausted)
}

const fn error(code: AdmissionErrorCode) -> AdmissionError {
    AdmissionError::new(code, None)
}

const fn refusal_scope(dimension: LimitDimension) -> AdmissionRefusalScope {
    match dimension {
        LimitDimension::Account => AdmissionRefusalScope::Account,
        _ => AdmissionRefusalScope::Request,
    }
}

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

mod policy_publication;

pub use policy_publication::{
    AdmissionPolicyBook, AdmissionPolicyPort, AdmissionPolicyReceipt, AdmissionPolicySnapshot,
    AdmissionPolicyVersion,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard};
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
}

impl AdmissionError {
    const fn new(code: AdmissionErrorCode, retry_after: Option<Duration>) -> Self {
        Self { code, retry_after }
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

/// Thread-safe atomic admission controller over an immutable policy set.
#[derive(Clone)]
pub struct AdmissionController {
    inner: Arc<ControllerInner>,
}

impl AdmissionController {
    /// Creates an empty controller at a caller-observed monotonic time.
    #[must_use]
    pub fn new(policies: AdmissionPolicySet, initial_now: MonotonicTime) -> Self {
        Self {
            inner: Arc::new(ControllerInner {
                policies,
                state: Mutex::new(ControllerState::new(initial_now)),
            }),
        }
    }

    /// Atomically reserves all requested rate and concurrency dimensions.
    ///
    /// Rate use remains pending until [`AdmissionLease::commit_rate`] succeeds.
    /// Dropping or cancelling an uncommitted lease refunds its pending rate use;
    /// committed use remains charged until its fixed window ends.
    ///
    /// # Errors
    /// Returns a stable redacted error without partially consuming capacity.
    pub fn try_admit(
        &self,
        request: &AdmissionRequest,
        now: MonotonicTime,
    ) -> Result<AdmissionLease, AdmissionError> {
        let prepared = self.inner.prepare_admission(request, now)?;
        Ok(AdmissionLease {
            inner: Arc::clone(&self.inner),
            id: prepared.lease_id,
            expires_at: prepared.expires_at,
            reservation: prepared.reservation,
            permits: prepared.permits,
            closed: false,
        })
    }

    /// Reads remaining capacity after applying expiry and window rollover.
    ///
    /// # Errors
    /// Returns a stable error for missing policy, clock regression, or state loss.
    pub fn snapshot(
        &self,
        key: &LimitKey,
        now: MonotonicTime,
    ) -> Result<LimitSnapshot, AdmissionError> {
        let policy = self
            .inner
            .policies
            .policy(key)
            .ok_or_else(|| error(AdmissionErrorCode::PolicyNotFound))?;
        let mut state = self.inner.lock_state()?;
        state.observe_and_expire(now)?;
        state.prepare_window(policy, now)?;
        Ok(state.snapshot(policy, now))
    }
}

impl Debug for AdmissionController {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionController(<shared-state>)")
    }
}

/// Owning admission lease for pending rate use and concurrency permits.
pub struct AdmissionLease {
    inner: Arc<ControllerInner>,
    id: AdmissionLeaseId,
    expires_at: MonotonicTime,
    reservation: Option<RateReservation>,
    permits: Vec<ConcurrencyPermit>,
    closed: bool,
}

impl AdmissionLease {
    /// Returns the process-local lease identity.
    #[must_use]
    pub const fn id(&self) -> AdmissionLeaseId {
        self.id
    }

    /// Returns the pending reservation, when any requested policy has a rate rule.
    #[must_use]
    pub const fn reservation(&self) -> Option<&RateReservation> {
        self.reservation.as_ref()
    }

    /// Returns typed concurrency permits in request order.
    #[must_use]
    pub fn permits(&self) -> &[ConcurrencyPermit] {
        &self.permits
    }

    /// Returns the exclusive monotonic lease expiry.
    #[must_use]
    pub const fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }

    /// Permanently charges pending rate units while retaining concurrency permits.
    ///
    /// Repeating a successful commit is idempotent. Cancellation or release after
    /// commit does not refund charged rate units.
    ///
    /// # Errors
    /// Returns a stable error for expiry, closure, clock regression, or state loss.
    pub fn commit_rate(&mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        self.ensure_open()?;
        let mut state = self.inner.lock_state()?;
        state.observe_and_expire(now)?;
        state.commit_rate(self.id)?;
        Ok(())
    }

    /// Releases concurrency and refunds rate units only when not yet committed.
    ///
    /// # Errors
    /// Returns a stable error for expiry, closure, clock regression, or state loss.
    pub fn release(mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        self.close(now)
    }

    /// Cancels the lease with the same capacity behavior as release.
    ///
    /// Cancellation is explicit for request-lifetime propagation. Pending rate
    /// units are refunded; committed units remain charged.
    ///
    /// # Errors
    /// Returns a stable error for expiry, closure, clock regression, or state loss.
    pub fn cancel(mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        self.close(now)
    }

    fn close(&mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        self.ensure_open()?;
        let result = self.inner.close_lease(self.id, now);
        if result.is_ok()
            || matches!(result, Err(value) if value.code() == AdmissionErrorCode::LeaseExpired)
        {
            self.closed = true;
        }
        result
    }

    fn ensure_open(&self) -> Result<(), AdmissionError> {
        if self.closed {
            Err(error(AdmissionErrorCode::LeaseClosed))
        } else {
            Ok(())
        }
    }
}

impl Debug for AdmissionLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmissionLease")
            .field("id", &self.id)
            .field("expires_at", &self.expires_at)
            .field("reservation", &self.reservation)
            .field("permit_count", &self.permits.len())
            .field("closed", &self.closed)
            .finish()
    }
}

impl Drop for AdmissionLease {
    fn drop(&mut self) {
        if !self.closed {
            self.inner.close_lease_without_time(self.id);
            self.closed = true;
        }
    }
}

struct ControllerInner {
    policies: AdmissionPolicySet,
    state: Mutex<ControllerState>,
}

impl ControllerInner {
    fn lock_state(&self) -> Result<MutexGuard<'_, ControllerState>, AdmissionError> {
        self.state
            .lock()
            .map_err(|_| error(AdmissionErrorCode::StateUnavailable))
    }

    fn resolve_policies<'a>(
        &'a self,
        request: &AdmissionRequest,
    ) -> Result<Vec<&'a LimitPolicy>, AdmissionError> {
        request
            .keys()
            .iter()
            .map(|key| {
                self.policies
                    .policy(key)
                    .ok_or_else(|| error(AdmissionErrorCode::PolicyNotFound))
            })
            .collect()
    }

    fn prepare_admission(
        &self,
        request: &AdmissionRequest,
        now: MonotonicTime,
    ) -> Result<PreparedAdmission, AdmissionError> {
        let policies = self.resolve_policies(request)?;
        let mut state = self.lock_state()?;
        state.prepare_admission(&policies, request, now)
    }

    fn close_lease(&self, id: AdmissionLeaseId, now: MonotonicTime) -> Result<(), AdmissionError> {
        let mut state = self.lock_state()?;
        state.observe_and_expire(now)?;
        if state.remove_lease(id) {
            Ok(())
        } else {
            Err(error(AdmissionErrorCode::LeaseExpired))
        }
    }

    fn close_lease_without_time(&self, id: AdmissionLeaseId) {
        if let Ok(mut state) = self.state.lock() {
            state.remove_lease(id);
        }
    }
}

struct ControllerState {
    last_now: MonotonicTime,
    next_identity: u64,
    windows: BTreeMap<LimitKey, RateWindowState>,
    concurrency: BTreeMap<LimitKey, u32>,
    leases: BTreeMap<AdmissionLeaseId, ActiveLease>,
}

impl ControllerState {
    fn new(initial_now: MonotonicTime) -> Self {
        Self {
            last_now: initial_now,
            next_identity: 0,
            windows: BTreeMap::new(),
            concurrency: BTreeMap::new(),
            leases: BTreeMap::new(),
        }
    }

    fn prepare_admission(
        &mut self,
        policies: &[&LimitPolicy],
        request: &AdmissionRequest,
        now: MonotonicTime,
    ) -> Result<PreparedAdmission, AdmissionError> {
        self.observe_and_expire(now)?;
        self.prepare_windows(policies, now)?;
        self.check_capacity(policies, request, now)?;
        let (reservation_id, lease_id) = self.allocate_identities()?;
        let expires_at = lease_expiry(policies, now)?;
        let parts = self.reserve(policies, request, reservation_id, lease_id, expires_at)?;
        Ok(PreparedAdmission {
            lease_id,
            expires_at,
            reservation: parts.reservation,
            permits: parts.permits,
        })
    }

    fn observe_and_expire(&mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        if now < self.last_now {
            return Err(error(AdmissionErrorCode::ClockRegressed));
        }
        self.last_now = now;
        let expired: Vec<_> = self
            .leases
            .iter()
            .filter_map(|(id, lease)| (lease.expires_at <= now).then_some(*id))
            .collect();
        for id in expired {
            self.remove_lease(id);
        }
        Ok(())
    }

    fn prepare_windows(
        &mut self,
        policies: &[&LimitPolicy],
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        for policy in policies {
            if let Some(rule) = policy.rate {
                now.checked_add(rule.window)?;
            }
        }
        for policy in policies {
            self.prepare_window(policy, now)?;
        }
        Ok(())
    }

    fn prepare_window(
        &mut self,
        policy: &LimitPolicy,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        let Some(rule) = policy.rate else {
            return Ok(());
        };
        let window = self
            .windows
            .entry(policy.key.clone())
            .or_insert(RateWindowState::new(now, rule)?);
        if window.ends_at <= now {
            *window = RateWindowState::new(now, rule)?;
        }
        Ok(())
    }

    fn check_capacity(
        &self,
        policies: &[&LimitPolicy],
        request: &AdmissionRequest,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        for policy in policies {
            self.check_rate(policy, request.units(), now)?;
            self.check_concurrency(policy, now)?;
        }
        Ok(())
    }

    fn check_rate(
        &self,
        policy: &LimitPolicy,
        units: NonZeroU32,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        let Some(rule) = policy.rate else {
            return Ok(());
        };
        let Some(window) = self.windows.get(&policy.key) else {
            return Err(error(AdmissionErrorCode::StateUnavailable));
        };
        let used = window.committed.saturating_add(window.pending);
        let remaining = rule.capacity.get().saturating_sub(used);
        if units.get() > remaining {
            return Err(AdmissionError::new(
                AdmissionErrorCode::RateLimited,
                Some(now.duration_until(window.ends_at)),
            ));
        }
        Ok(())
    }

    fn check_concurrency(
        &self,
        policy: &LimitPolicy,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        let Some(rule) = policy.concurrency else {
            return Ok(());
        };
        let active = self.concurrency.get(&policy.key).copied().unwrap_or(0);
        if active < rule.limit.get() {
            return Ok(());
        }
        let retry_after = self
            .earliest_expiry(&policy.key)
            .map(|at| now.duration_until(at));
        Err(AdmissionError::new(
            AdmissionErrorCode::ConcurrencyLimited,
            retry_after,
        ))
    }

    fn earliest_expiry(&self, key: &LimitKey) -> Option<MonotonicTime> {
        self.leases
            .values()
            .filter(|lease| lease.concurrency_keys.contains(key))
            .map(|lease| lease.expires_at)
            .min()
    }

    fn allocate_identities(
        &mut self,
    ) -> Result<(RateReservationId, AdmissionLeaseId), AdmissionError> {
        let reservation = self.next_identity.checked_add(1).ok_or_else(exhausted)?;
        let lease = reservation.checked_add(1).ok_or_else(exhausted)?;
        self.next_identity = lease;
        Ok((RateReservationId(reservation), AdmissionLeaseId(lease)))
    }

    fn reserve(
        &mut self,
        policies: &[&LimitPolicy],
        request: &AdmissionRequest,
        reservation_id: RateReservationId,
        lease_id: AdmissionLeaseId,
        expires_at: MonotonicTime,
    ) -> Result<ReservedParts, AdmissionError> {
        let rate_keys = rate_keys(policies);
        let concurrency_keys = concurrency_keys(policies);
        self.add_pending(&rate_keys, request.units())?;
        self.add_concurrency(&concurrency_keys)?;
        self.leases.insert(
            lease_id,
            ActiveLease {
                rate_keys: rate_keys.clone(),
                concurrency_keys: concurrency_keys.clone(),
                units: request.units(),
                expires_at,
                rate_committed: false,
            },
        );
        Ok(ReservedParts {
            reservation: (!rate_keys.is_empty()).then_some(RateReservation {
                id: reservation_id,
                keys: rate_keys,
                units: request.units(),
                expires_at,
            }),
            permits: concurrency_keys
                .into_iter()
                .map(|key| ConcurrencyPermit {
                    lease_id,
                    key,
                    expires_at,
                })
                .collect(),
        })
    }

    fn add_pending(&mut self, keys: &[LimitKey], units: NonZeroU32) -> Result<(), AdmissionError> {
        self.validate_pending_addition(keys, units)?;
        self.apply_pending_addition(keys, units)
    }

    fn validate_pending_addition(
        &self,
        keys: &[LimitKey],
        units: NonZeroU32,
    ) -> Result<(), AdmissionError> {
        for key in keys {
            let Some(window) = self.windows.get(key) else {
                return Err(error(AdmissionErrorCode::StateUnavailable));
            };
            window
                .pending
                .checked_add(units.get())
                .ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn apply_pending_addition(
        &mut self,
        keys: &[LimitKey],
        units: NonZeroU32,
    ) -> Result<(), AdmissionError> {
        for key in keys {
            let Some(window) = self.windows.get_mut(key) else {
                return Err(error(AdmissionErrorCode::StateUnavailable));
            };
            window.pending = window
                .pending
                .checked_add(units.get())
                .ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn add_concurrency(&mut self, keys: &[LimitKey]) -> Result<(), AdmissionError> {
        for key in keys {
            let active = self.concurrency.get(key).copied().unwrap_or(0);
            active.checked_add(1).ok_or_else(exhausted)?;
        }
        for key in keys {
            let active = self.concurrency.entry(key.clone()).or_default();
            *active = active.checked_add(1).ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn commit_rate(&mut self, id: AdmissionLeaseId) -> Result<(), AdmissionError> {
        let Some((keys, units)) = self.pending_rate_commitment(id)? else {
            return Ok(());
        };
        self.validate_rate_commitment(&keys, units)?;
        self.apply_rate_commitment(&keys, units)?;
        self.mark_rate_committed(id)
    }

    fn pending_rate_commitment(
        &self,
        id: AdmissionLeaseId,
    ) -> Result<Option<(Vec<LimitKey>, NonZeroU32)>, AdmissionError> {
        let Some(lease) = self.leases.get(&id) else {
            return Err(error(AdmissionErrorCode::LeaseExpired));
        };
        Ok((!lease.rate_committed).then(|| (lease.rate_keys.clone(), lease.units)))
    }

    fn validate_rate_commitment(
        &self,
        keys: &[LimitKey],
        units: NonZeroU32,
    ) -> Result<(), AdmissionError> {
        for key in keys {
            let Some(window) = self.windows.get(key) else {
                return Err(error(AdmissionErrorCode::StateUnavailable));
            };
            window
                .committed
                .checked_add(units.get())
                .ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn apply_rate_commitment(
        &mut self,
        keys: &[LimitKey],
        units: NonZeroU32,
    ) -> Result<(), AdmissionError> {
        for key in keys {
            let Some(window) = self.windows.get_mut(key) else {
                return Err(error(AdmissionErrorCode::StateUnavailable));
            };
            window.pending = window.pending.saturating_sub(units.get());
            window.committed = window
                .committed
                .checked_add(units.get())
                .ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn mark_rate_committed(&mut self, id: AdmissionLeaseId) -> Result<(), AdmissionError> {
        let Some(lease) = self.leases.get_mut(&id) else {
            return Err(error(AdmissionErrorCode::LeaseExpired));
        };
        lease.rate_committed = true;
        Ok(())
    }

    fn remove_lease(&mut self, id: AdmissionLeaseId) -> bool {
        let Some(lease) = self.leases.remove(&id) else {
            return false;
        };
        self.release_concurrency(&lease.concurrency_keys);
        if !lease.rate_committed {
            self.release_pending(&lease.rate_keys, lease.units);
        }
        true
    }

    fn release_concurrency(&mut self, keys: &[LimitKey]) {
        for key in keys {
            if let Some(active) = self.concurrency.get_mut(key) {
                *active = active.saturating_sub(1);
            }
        }
    }

    fn release_pending(&mut self, keys: &[LimitKey], units: NonZeroU32) {
        for key in keys {
            if let Some(window) = self.windows.get_mut(key) {
                window.pending = window.pending.saturating_sub(units.get());
            }
        }
    }

    fn snapshot(&self, policy: &LimitPolicy, now: MonotonicTime) -> LimitSnapshot {
        let (rate_remaining, rate_resets_at) = self.rate_snapshot(policy, now);
        let concurrency_remaining = policy.concurrency.map(|rule| {
            let active = self.concurrency.get(&policy.key).copied().unwrap_or(0);
            rule.limit.get().saturating_sub(active)
        });
        LimitSnapshot {
            rate_remaining,
            rate_resets_at,
            concurrency_remaining,
        }
    }

    fn rate_snapshot(
        &self,
        policy: &LimitPolicy,
        now: MonotonicTime,
    ) -> (Option<u32>, Option<MonotonicTime>) {
        let Some(rule) = policy.rate else {
            return (None, None);
        };
        let Some(window) = self.windows.get(&policy.key) else {
            return (Some(rule.capacity.get()), None);
        };
        let used = window.committed.saturating_add(window.pending);
        let remaining = rule.capacity.get().saturating_sub(used);
        let reset = (window.ends_at > now).then_some(window.ends_at);
        (Some(remaining), reset)
    }
}

struct RateWindowState {
    ends_at: MonotonicTime,
    committed: u32,
    pending: u32,
}

impl RateWindowState {
    fn new(now: MonotonicTime, rule: RateRule) -> Result<Self, AdmissionError> {
        Ok(Self {
            ends_at: now.checked_add(rule.window)?,
            committed: 0,
            pending: 0,
        })
    }
}

struct ActiveLease {
    rate_keys: Vec<LimitKey>,
    concurrency_keys: Vec<LimitKey>,
    units: NonZeroU32,
    expires_at: MonotonicTime,
    rate_committed: bool,
}

struct ReservedParts {
    reservation: Option<RateReservation>,
    permits: Vec<ConcurrencyPermit>,
}

struct PreparedAdmission {
    lease_id: AdmissionLeaseId,
    expires_at: MonotonicTime,
    reservation: Option<RateReservation>,
    permits: Vec<ConcurrencyPermit>,
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

fn lease_expiry(
    policies: &[&LimitPolicy],
    now: MonotonicTime,
) -> Result<MonotonicTime, AdmissionError> {
    let duration = policies
        .iter()
        .flat_map(|policy| {
            [
                policy.rate.map(|rule| rule.window),
                policy.concurrency.map(|rule| rule.lease_duration),
            ]
        })
        .flatten()
        .min()
        .ok_or_else(invalid)?;
    now.checked_add(duration)
}

fn rate_keys(policies: &[&LimitPolicy]) -> Vec<LimitKey> {
    policies
        .iter()
        .filter(|policy| policy.rate.is_some())
        .map(|policy| policy.key.clone())
        .collect()
}

fn concurrency_keys(policies: &[&LimitPolicy]) -> Vec<LimitKey> {
    policies
        .iter()
        .filter(|policy| policy.concurrency.is_some())
        .map(|policy| policy.key.clone())
        .collect()
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

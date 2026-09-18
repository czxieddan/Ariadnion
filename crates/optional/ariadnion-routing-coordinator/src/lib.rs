// crates/optional/ariadnion-routing-coordinator/src/lib.rs - Complete routing coordination for Ariadnion.
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
//! Deterministic account routing and coupled admission coordination.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod engine;

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::num::{NonZeroU32, NonZeroU64};
#[cfg(feature = "wasm-policy")]
use std::sync::Arc;
use std::time::Duration;

use ariadnion_account_affinity::{AffinityKey, AffinitySnapshot, UtcSeconds as AffinityTime};
use ariadnion_account_budget::{ReservationId, UnixTimeSeconds as BudgetTime};
use ariadnion_account_circuit::CircuitSnapshot;
use ariadnion_account_domain::AccountId;
use ariadnion_account_health::HealthSnapshot;
use ariadnion_account_pool::{CandidateMetadata, CandidateSnapshot};
use ariadnion_account_proxy::{AccountProxyProfile, ProxyProfileId, RegionConstraint};
use ariadnion_account_quota::QuotaSnapshotSet;
use ariadnion_account_schedule::ScheduleSnapshot;
use ariadnion_core::{AttemptId, RequestId, TenantId};
use ariadnion_model_catalog::ModelCatalogSnapshot;
use ariadnion_model_domain::ProviderModelId;
use ariadnion_model_pricing::{PriceDimension, PricingCatalog};
use ariadnion_rate_limit::{
    AccountLimitId, AccountLimitKey, ConcurrencyRule, LimitKey, LimitPolicy, MonotonicTime,
    TenantLimitId,
};
use ariadnion_routing_admission::{
    RoutingAdmissionCoordinator, RoutingAdmissionLease, RoutingAdmissionLeaseState,
};
use ariadnion_routing_cost::CostConstraints;
use ariadnion_routing_failover::{
    AttemptContext, CandidateKey, DeterministicFailoverPlanner, FailoverDecision, FailureClass,
    MAX_ATTEMPTS, OperationSafety, StreamCommitment,
};
use ariadnion_routing_usage::UsageConfirmationId;
#[cfg(feature = "wasm-policy")]
use ariadnion_routing_wasm::RoutingWasmEvaluator;

/// Maximum candidates accepted by one complete coordination request.
pub const MAX_CANDIDATES: usize = 1 << 17;
/// Maximum bytes in a normalized destination-region identity.
pub const MAX_DESTINATION_REGION_BYTES: usize = 1 << 7;
/// Maximum candidate exclusions retained in one error or explanation.
pub const MAX_RETAINED_EXCLUSIONS: usize = 1 << 12;

/// Stable failures returned by complete routing coordination.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CoordinatorErrorCode {
    /// A typed request is malformed or outside a documented bound.
    InvalidArgument,
    /// A candidate snapshot contains a different tenant or lacks tenant binding.
    TenantMismatch,
    /// The requested internal model is absent or hidden from the tenant.
    ModelNotFound,
    /// The requested model does not expose every required capability.
    CapabilityMismatch,
    /// A fail-closed signal snapshot is missing.
    MissingSignal,
    /// Every candidate was deterministically excluded.
    NoEligibleCandidate,
    /// Pricing required for cost and budget admission is unavailable.
    PricingUnavailable,
    /// The rate window rejected the selected candidate.
    RateLimited,
    /// The concurrency dimension rejected the selected candidate.
    ConcurrencyLimited,
    /// The account, group, or tenant budget rejected the selected candidate.
    BudgetRejected,
    /// Admission state could not complete without risking duplicate effects.
    AdmissionUnavailable,
    /// An installed routing policy component could not produce a safe decision.
    PolicyUnavailable,
    /// A component snapshot or state engine returned invalid state.
    StateUnavailable,
}

impl CoordinatorErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument
            | Self::TenantMismatch
            | Self::ModelNotFound
            | Self::CapabilityMismatch => request_code(self),
            Self::MissingSignal | Self::NoEligibleCandidate | Self::PricingUnavailable => {
                signal_code(self)
            }
            Self::RateLimited
            | Self::ConcurrencyLimited
            | Self::BudgetRejected
            | Self::AdmissionUnavailable
            | Self::PolicyUnavailable
            | Self::StateUnavailable => runtime_code(self),
        }
    }
}

const fn request_code(code: CoordinatorErrorCode) -> &'static str {
    match code {
        CoordinatorErrorCode::InvalidArgument => "ROUTING_COORDINATOR_INVALID_ARGUMENT",
        CoordinatorErrorCode::TenantMismatch => "ROUTING_COORDINATOR_TENANT_MISMATCH",
        CoordinatorErrorCode::ModelNotFound => "ROUTING_COORDINATOR_MODEL_NOT_FOUND",
        CoordinatorErrorCode::CapabilityMismatch => "ROUTING_COORDINATOR_CAPABILITY_MISMATCH",
        _ => "ROUTING_COORDINATOR_INVALID_ARGUMENT",
    }
}

const fn signal_code(code: CoordinatorErrorCode) -> &'static str {
    match code {
        CoordinatorErrorCode::MissingSignal => "ROUTING_COORDINATOR_MISSING_SIGNAL",
        CoordinatorErrorCode::NoEligibleCandidate => "ROUTING_COORDINATOR_NO_ELIGIBLE_CANDIDATE",
        CoordinatorErrorCode::PricingUnavailable => "ROUTING_COORDINATOR_PRICING_UNAVAILABLE",
        _ => "ROUTING_COORDINATOR_INVALID_ARGUMENT",
    }
}

const fn runtime_code(code: CoordinatorErrorCode) -> &'static str {
    match code {
        CoordinatorErrorCode::RateLimited => "ROUTING_COORDINATOR_RATE_LIMITED",
        CoordinatorErrorCode::ConcurrencyLimited => "ROUTING_COORDINATOR_CONCURRENCY_LIMITED",
        CoordinatorErrorCode::BudgetRejected => "ROUTING_COORDINATOR_BUDGET_REJECTED",
        CoordinatorErrorCode::AdmissionUnavailable => "ROUTING_COORDINATOR_ADMISSION_UNAVAILABLE",
        CoordinatorErrorCode::PolicyUnavailable => "ROUTING_COORDINATOR_POLICY_UNAVAILABLE",
        CoordinatorErrorCode::StateUnavailable => "ROUTING_COORDINATOR_STATE_UNAVAILABLE",
        _ => "ROUTING_COORDINATOR_INVALID_ARGUMENT",
    }
}

impl Display for CoordinatorErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted coordination failure with deterministic exclusion evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorError {
    code: CoordinatorErrorCode,
    exclusions: Vec<CandidateExclusion>,
    exclusions_truncated: bool,
    retry_after: Option<Duration>,
}

impl CoordinatorError {
    pub(crate) const fn new(code: CoordinatorErrorCode) -> Self {
        Self {
            code,
            exclusions: Vec::new(),
            exclusions_truncated: false,
            retry_after: None,
        }
    }

    pub(crate) fn with_exclusions(
        code: CoordinatorErrorCode,
        exclusions: Vec<CandidateExclusion>,
    ) -> Self {
        let (exclusions, exclusions_truncated) = bound_exclusions(exclusions);
        Self {
            code,
            exclusions,
            exclusions_truncated,
            retry_after: None,
        }
    }

    pub(crate) const fn with_retry_after(
        code: CoordinatorErrorCode,
        retry_after: Option<Duration>,
    ) -> Self {
        Self {
            code,
            exclusions: Vec::new(),
            exclusions_truncated: false,
            retry_after,
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> CoordinatorErrorCode {
        self.code
    }

    /// Returns deterministic candidate exclusions collected before failure.
    #[must_use]
    pub fn exclusions(&self) -> &[CandidateExclusion] {
        &self.exclusions
    }

    /// Returns whether exclusion evidence was truncated at the hard bound.
    #[must_use]
    pub const fn exclusions_truncated(&self) -> bool {
        self.exclusions_truncated
    }

    /// Returns the minimum known retry delay for admission refusal.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

impl Display for CoordinatorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for CoordinatorError {}

pub(crate) fn bound_exclusions(
    mut exclusions: Vec<CandidateExclusion>,
) -> (Vec<CandidateExclusion>, bool) {
    exclusions.sort_by(|left, right| left.candidate().cmp(right.candidate()));
    exclusions.dedup_by(|left, right| left.candidate() == right.candidate());
    let truncated = exclusions.len() > MAX_RETAINED_EXCLUSIONS;
    exclusions.truncate(MAX_RETAINED_EXCLUSIONS);
    (exclusions, truncated)
}

/// Policy applied when a complete optional signal snapshot is unavailable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MissingSignalPolicy {
    /// Exclude affected candidates rather than guessing safety state.
    FailClosed,
    /// Continue through the explicitly configured safe default and record degradation.
    AllowWithDegradation,
}

/// A borrowed optional snapshot paired with its explicit absence policy.
#[derive(Debug)]
pub struct OptionalSnapshot<'a, T: ?Sized> {
    value: Option<&'a T>,
    missing_policy: MissingSignalPolicy,
}

impl<T: ?Sized> Copy for OptionalSnapshot<'_, T> {}

impl<T: ?Sized> Clone for OptionalSnapshot<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, T: ?Sized> OptionalSnapshot<'a, T> {
    /// Wraps an available immutable snapshot.
    #[must_use]
    pub const fn available(value: &'a T, missing_policy: MissingSignalPolicy) -> Self {
        Self {
            value: Some(value),
            missing_policy,
        }
    }

    /// Represents an unavailable snapshot with an explicit safety policy.
    #[must_use]
    pub const fn missing(missing_policy: MissingSignalPolicy) -> Self {
        Self {
            value: None,
            missing_policy,
        }
    }

    pub(crate) const fn value(self) -> Option<&'a T> {
        self.value
    }

    pub(crate) const fn missing_policy(self) -> MissingSignalPolicy {
        self.missing_policy
    }
}

/// Stable signal categories retained in routing degradation evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignalKind {
    /// Active or passive account health.
    Health,
    /// Circuit-breaker state and half-open recovery.
    Circuit,
    /// Provider or account quota state.
    Quota,
    /// Account availability and maintenance schedule.
    Schedule,
    /// Proxy availability and destination-region policy.
    Proxy,
    /// Session, user, or session-family affinity.
    Affinity,
    /// Versioned model pricing required for admission.
    Pricing,
    /// Isolated routing policy evaluation was unavailable or degraded.
    RoutingPolicy,
}

/// Why one candidate was excluded from the complete routing pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CandidateExclusionReason {
    /// The published pool marked the account unavailable.
    PoolUnavailable,
    /// The account has no matching mapping for the requested internal model.
    ModelMappingMissing,
    /// An available signal set lacked state for this candidate.
    MissingSignal(SignalKind),
    /// Health state forbids selection.
    Unhealthy,
    /// The circuit is open or terminal.
    CircuitOpen,
    /// The circuit is half-open but no recovery-probe lease was supplied.
    CircuitHalfOpen,
    /// Conservative provider or account quota is exhausted.
    QuotaExhausted,
    /// The account is outside its availability window or inside maintenance.
    ScheduleClosed,
    /// The configured proxy is unavailable.
    ProxyUnavailable,
    /// The configured proxy does not permit the requested destination region.
    ProxyRegionDenied,
    /// No bounded price quote exists for this candidate.
    MissingPrice,
    /// The candidate exceeds the hard request cost limit.
    HardCostLimit,
    /// A preferred candidate exists below the soft request cost limit.
    AboveSoftCostLimit,
    /// Another candidate belongs to a lower numeric priority tier.
    LowerPriority,
    /// Another candidate has a lower weighted load ratio.
    HigherEffectiveLoad,
    /// Equal policy values were resolved by stable candidate identity.
    StableTieBreak,
    /// A live affinity binding selected a different candidate.
    AffinityPreferred,
    /// An installed isolated policy component selected a different candidate.
    WasmPolicyPreferred,
}

/// One deterministic candidate exclusion retained for audit projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateExclusion {
    candidate: CandidateKey,
    reason: CandidateExclusionReason,
}

impl CandidateExclusion {
    pub(crate) const fn new(candidate: CandidateKey, reason: CandidateExclusionReason) -> Self {
        Self { candidate, reason }
    }

    /// Returns the stable candidate identity.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateKey {
        &self.candidate
    }

    /// Returns the stable exclusion reason.
    #[must_use]
    pub const fn reason(&self) -> &CandidateExclusionReason {
        &self.reason
    }
}

/// Primary decision basis recorded by the complete coordinator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SelectionBasis {
    /// Lowest priority followed by weighted least load and stable identity.
    WeightedLeastLoad,
    /// A live tenant-bound affinity binding selected an otherwise eligible account.
    Affinity,
    /// An isolated routing component selected from the fully eligible candidate set.
    WasmPolicy,
}

/// Complete explainable evidence for one routing decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionExplanation {
    basis: SelectionBasis,
    degradations: Vec<SignalKind>,
    exclusions: Vec<CandidateExclusion>,
    exclusions_truncated: bool,
}

impl DecisionExplanation {
    pub(crate) fn new(
        basis: SelectionBasis,
        degradations: Vec<SignalKind>,
        exclusions: Vec<CandidateExclusion>,
        exclusions_truncated: bool,
    ) -> Self {
        Self {
            basis,
            degradations,
            exclusions,
            exclusions_truncated,
        }
    }

    /// Returns the selection strategy that chose the primary candidate.
    #[must_use]
    pub const fn basis(&self) -> SelectionBasis {
        self.basis
    }

    /// Returns sorted, duplicate-free degraded signal categories.
    #[must_use]
    pub fn degradations(&self) -> &[SignalKind] {
        &self.degradations
    }

    /// Returns deterministic per-candidate exclusion evidence.
    #[must_use]
    pub fn exclusions(&self) -> &[CandidateExclusion] {
        &self.exclusions
    }

    /// Returns whether exclusion evidence was truncated at the hard bound.
    #[must_use]
    pub const fn exclusions_truncated(&self) -> bool {
        self.exclusions_truncated
    }
}

/// A bounded destination region used by schedule and proxy policy.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DestinationRegion(Box<str>);

impl DestinationRegion {
    /// Parses a lower-case ASCII region identity.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorErrorCode::InvalidArgument`] for an empty,
    /// overlong, or malformed value.
    pub fn parse(value: &str) -> Result<Self, CoordinatorError> {
        if !valid_destination_region(value) {
            return Err(CoordinatorError::new(CoordinatorErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated region identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Availability state for one account's proxy route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProxyAvailability {
    /// The route may be used subject to its region constraint.
    Available,
    /// The route is known unavailable.
    Unavailable,
}

/// Immutable routing view of one account proxy execution snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyRoutingProfile {
    account_id: AccountId,
    profile: AccountProxyProfile,
    availability: ProxyAvailability,
}

impl ProxyRoutingProfile {
    /// Creates a routing view that owns the exact metadata-only execution snapshot.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        profile: AccountProxyProfile,
        availability: ProxyAvailability,
    ) -> Self {
        Self {
            account_id,
            profile,
            availability,
        }
    }

    /// Returns the account bound to this route.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the non-secret proxy profile identity.
    #[must_use]
    pub const fn profile_id(&self) -> &ProxyProfileId {
        self.profile.id()
    }

    /// Returns the exact immutable proxy execution snapshot.
    #[must_use]
    pub const fn profile(&self) -> &AccountProxyProfile {
        &self.profile
    }

    /// Returns the destination-region constraint.
    #[must_use]
    pub const fn regions(&self) -> &RegionConstraint {
        self.profile.regions()
    }

    /// Returns the observed proxy availability.
    #[must_use]
    pub const fn availability(&self) -> ProxyAvailability {
        self.availability
    }
}

/// Builds tenant-bound account concurrency policies from authoritative candidates.
///
/// The returned policies contain concurrency limits only. Callers combine them
/// with tenant, model, user, or rate policies before constructing the admission
/// controller. Every candidate must carry the tenant and persisted account bound
/// produced by account import publication; incomplete metadata fails closed.
///
/// # Errors
/// Returns a stable error for oversized input, missing authoritative metadata,
/// duplicate tenant/account identities, malformed admission identities, or an
/// invalid lease duration.
pub fn build_account_concurrency_policies(
    candidates: &[CandidateMetadata],
    lease_duration: Duration,
) -> Result<Vec<LimitPolicy>, CoordinatorError> {
    if candidates.len() > MAX_CANDIDATES {
        return Err(CoordinatorError::new(CoordinatorErrorCode::InvalidArgument));
    }
    let mut policies = BTreeMap::new();
    for candidate in candidates {
        let (key, policy) = account_concurrency_policy(candidate, lease_duration)?;
        if policies.insert(key, policy).is_some() {
            return Err(CoordinatorError::new(
                CoordinatorErrorCode::StateUnavailable,
            ));
        }
    }
    Ok(policies.into_values().collect())
}

fn account_concurrency_policy(
    candidate: &CandidateMetadata,
    lease_duration: Duration,
) -> Result<(LimitKey, LimitPolicy), CoordinatorError> {
    let tenant = candidate
        .tenant_id()
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::TenantMismatch))?;
    let limit = candidate
        .max_concurrency()
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let tenant = TenantLimitId::parse(tenant.as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let account = AccountLimitId::parse(candidate.account_id().as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let key = LimitKey::Account(AccountLimitKey::new(tenant, account));
    let rule = ConcurrencyRule::new(limit, lease_duration)
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let policy = LimitPolicy::new(key.clone(), None, Some(rule))
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    Ok((key, policy))
}

/// Explicit clocks used by rate and budget admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionTimes {
    monotonic_now: MonotonicTime,
    budget_now: BudgetTime,
    budget_expires_at: BudgetTime,
}

impl AdmissionTimes {
    /// Creates clocks with an exclusive budget-reservation expiry.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorErrorCode::InvalidArgument`] unless expiry is after
    /// the supplied UTC observation.
    pub fn new(
        monotonic_now: MonotonicTime,
        budget_now: BudgetTime,
        budget_expires_at: BudgetTime,
    ) -> Result<Self, CoordinatorError> {
        if budget_expires_at <= budget_now {
            return Err(CoordinatorError::new(CoordinatorErrorCode::InvalidArgument));
        }
        Ok(Self {
            monotonic_now,
            budget_now,
            budget_expires_at,
        })
    }

    pub(crate) const fn monotonic_now(self) -> MonotonicTime {
        self.monotonic_now
    }

    pub(crate) const fn budget_now(self) -> BudgetTime {
        self.budget_now
    }

    pub(crate) const fn budget_expires_at(self) -> BudgetTime {
        self.budget_expires_at
    }
}

/// Admission identity, units, and clocks applied after deterministic selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionTemplate {
    reservation_id: ReservationId,
    units: NonZeroU32,
    times: AdmissionTimes,
}

impl AdmissionTemplate {
    /// Creates one replay-safe coupled admission template.
    #[must_use]
    pub const fn new(
        reservation_id: ReservationId,
        units: NonZeroU32,
        times: AdmissionTimes,
    ) -> Self {
        Self {
            reservation_id,
            units,
            times,
        }
    }

    pub(crate) const fn reservation_id(&self) -> &ReservationId {
        &self.reservation_id
    }

    pub(crate) const fn units(&self) -> NonZeroU32 {
        self.units
    }

    pub(crate) const fn times(&self) -> AdmissionTimes {
        self.times
    }
}

/// Versioned pricing dimension, quantity, and request cost constraints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PricingRequest {
    dimension: PriceDimension,
    quantity: NonZeroU64,
    constraints: CostConstraints,
}

impl PricingRequest {
    /// Creates a positive quantity request with already validated constraints.
    #[must_use]
    pub const fn new(
        dimension: PriceDimension,
        quantity: NonZeroU64,
        constraints: CostConstraints,
    ) -> Self {
        Self {
            dimension,
            quantity,
            constraints,
        }
    }

    pub(crate) const fn dimension(self) -> PriceDimension {
        self.dimension
    }

    pub(crate) const fn quantity(self) -> NonZeroU64 {
        self.quantity
    }

    pub(crate) const fn constraints(self) -> CostConstraints {
        self.constraints
    }
}

/// Request-scoped retry safety and maximum provider attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    operation: OperationSafety,
    max_attempts: u8,
}

impl RetryPolicy {
    /// Creates a bounded retry policy.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorErrorCode::InvalidArgument`] for zero or more than
    /// the failover engine's supported maximum attempts.
    pub fn new(operation: OperationSafety, max_attempts: u8) -> Result<Self, CoordinatorError> {
        if !(1..=MAX_ATTEMPTS).contains(&max_attempts) {
            return Err(CoordinatorError::new(CoordinatorErrorCode::InvalidArgument));
        }
        Ok(Self {
            operation,
            max_attempts,
        })
    }

    pub(crate) const fn operation(self) -> OperationSafety {
        self.operation
    }

    pub(crate) const fn max_attempts(self) -> u8 {
        self.max_attempts
    }
}

/// Complete immutable input for one routing and admission decision.
#[derive(Clone, Debug)]
pub struct CoordinationRequest {
    context: ariadnion_routing_domain::RoutingContext,
    destination_region: Option<DestinationRegion>,
    pricing_timestamp: NonZeroU64,
    pricing: PricingRequest,
    admission: AdmissionTemplate,
    retry: RetryPolicy,
    affinity: Option<(AffinityKey, AffinityTime)>,
}

impl CoordinationRequest {
    /// Creates a request with explicit pricing, admission, and retry inputs.
    #[must_use]
    pub const fn new(
        context: ariadnion_routing_domain::RoutingContext,
        destination_region: Option<DestinationRegion>,
        pricing_timestamp: NonZeroU64,
        pricing: PricingRequest,
        admission: AdmissionTemplate,
        retry: RetryPolicy,
    ) -> Self {
        Self {
            context,
            destination_region,
            pricing_timestamp,
            pricing,
            admission,
            retry,
            affinity: None,
        }
    }

    /// Adds one tenant-bound affinity lookup and its explicit UTC observation.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorErrorCode::TenantMismatch`] when the key belongs to
    /// another tenant.
    pub fn with_affinity(
        mut self,
        key: AffinityKey,
        now: AffinityTime,
    ) -> Result<Self, CoordinatorError> {
        if key.tenant_id() != self.context.tenant_id() {
            return Err(CoordinatorError::new(CoordinatorErrorCode::TenantMismatch));
        }
        self.affinity = Some((key, now));
        Ok(self)
    }

    pub(crate) const fn context(&self) -> &ariadnion_routing_domain::RoutingContext {
        &self.context
    }

    pub(crate) const fn destination_region(&self) -> Option<&DestinationRegion> {
        self.destination_region.as_ref()
    }

    pub(crate) const fn pricing_timestamp(&self) -> u64 {
        self.pricing_timestamp.get()
    }

    pub(crate) const fn pricing(&self) -> PricingRequest {
        self.pricing
    }

    pub(crate) const fn admission(&self) -> &AdmissionTemplate {
        &self.admission
    }

    pub(crate) const fn retry(&self) -> RetryPolicy {
        self.retry
    }

    pub(crate) const fn affinity(&self) -> Option<&(AffinityKey, AffinityTime)> {
        self.affinity.as_ref()
    }
}

/// Optional eligibility snapshots consumed by the routing pipeline.
#[derive(Clone, Copy, Debug)]
pub struct EligibilitySnapshots<'a> {
    health: OptionalSnapshot<'a, [HealthSnapshot]>,
    circuit: OptionalSnapshot<'a, [CircuitSnapshot]>,
    quota: OptionalSnapshot<'a, QuotaSnapshotSet>,
    schedule: OptionalSnapshot<'a, ScheduleSnapshot>,
    proxy: OptionalSnapshot<'a, [ProxyRoutingProfile]>,
}

impl<'a> EligibilitySnapshots<'a> {
    /// Groups immutable account eligibility views in pipeline order.
    #[must_use]
    pub const fn new(
        health: OptionalSnapshot<'a, [HealthSnapshot]>,
        circuit: OptionalSnapshot<'a, [CircuitSnapshot]>,
        quota: OptionalSnapshot<'a, QuotaSnapshotSet>,
        schedule: OptionalSnapshot<'a, ScheduleSnapshot>,
        proxy: OptionalSnapshot<'a, [ProxyRoutingProfile]>,
    ) -> Self {
        Self {
            health,
            circuit,
            quota,
            schedule,
            proxy,
        }
    }

    pub(crate) const fn health(self) -> OptionalSnapshot<'a, [HealthSnapshot]> {
        self.health
    }

    pub(crate) const fn circuit(self) -> OptionalSnapshot<'a, [CircuitSnapshot]> {
        self.circuit
    }

    pub(crate) const fn quota(self) -> OptionalSnapshot<'a, QuotaSnapshotSet> {
        self.quota
    }

    pub(crate) const fn schedule(self) -> OptionalSnapshot<'a, ScheduleSnapshot> {
        self.schedule
    }

    pub(crate) const fn proxy(self) -> OptionalSnapshot<'a, [ProxyRoutingProfile]> {
        self.proxy
    }
}

/// Complete borrowed snapshot set for one deterministic coordination attempt.
#[derive(Clone, Copy, Debug)]
pub struct CoordinationSnapshots<'a> {
    pool: &'a CandidateSnapshot,
    models: &'a ModelCatalogSnapshot,
    pricing: OptionalSnapshot<'a, PricingCatalog>,
    eligibility: EligibilitySnapshots<'a>,
    affinity: OptionalSnapshot<'a, AffinitySnapshot>,
}

impl<'a> CoordinationSnapshots<'a> {
    /// Creates an immutable cross-domain snapshot view.
    #[must_use]
    pub const fn new(
        pool: &'a CandidateSnapshot,
        models: &'a ModelCatalogSnapshot,
        pricing: OptionalSnapshot<'a, PricingCatalog>,
        eligibility: EligibilitySnapshots<'a>,
        affinity: OptionalSnapshot<'a, AffinitySnapshot>,
    ) -> Self {
        Self {
            pool,
            models,
            pricing,
            eligibility,
            affinity,
        }
    }

    pub(crate) const fn pool(self) -> &'a CandidateSnapshot {
        self.pool
    }

    pub(crate) const fn models(self) -> &'a ModelCatalogSnapshot {
        self.models
    }

    pub(crate) const fn pricing(self) -> OptionalSnapshot<'a, PricingCatalog> {
        self.pricing
    }

    pub(crate) const fn eligibility(self) -> EligibilitySnapshots<'a> {
        self.eligibility
    }

    pub(crate) const fn affinity(self) -> OptionalSnapshot<'a, AffinitySnapshot> {
        self.affinity
    }
}

/// Request-bound wrapper around the pure failover state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingRetryPlan {
    planner: DeterministicFailoverPlanner,
    operation: OperationSafety,
}

impl RoutingRetryPlan {
    pub(crate) const fn new(
        planner: DeterministicFailoverPlanner,
        operation: OperationSafety,
    ) -> Self {
        Self { planner, operation }
    }

    /// Classifies one failed provider attempt without permitting post-first-byte switching.
    ///
    /// # Errors
    ///
    /// Returns a stable failover error when the candidate or attempt is outside
    /// the immutable plan.
    pub fn decide(
        &self,
        candidate: &CandidateKey,
        attempt: u8,
        stream: StreamCommitment,
        failure: FailureClass,
    ) -> Result<FailoverDecision, ariadnion_routing_failover::FailoverError> {
        let context = AttemptContext::new(candidate.clone(), attempt, self.operation, stream)?;
        self.planner.decide(&context, failure)
    }

    /// Returns candidates in deterministic provider-attempt order.
    #[must_use]
    pub fn candidates(&self) -> &[CandidateKey] {
        self.planner.plan().candidates()
    }
}

/// Successful explainable route with its owned admission lifecycle lease.
pub struct CoordinatedRoute {
    selected_candidate: CandidateKey,
    selected_account: AccountId,
    provider_model: ProviderModelId,
    selected_proxy_profile: Option<AccountProxyProfile>,
    explanation: DecisionExplanation,
    retry_plan: RoutingRetryPlan,
    tenant_id: TenantId,
    request_id: RequestId,
    admission_lease: RoutingAdmissionLease,
}

pub(crate) struct CoordinatedRouteParts {
    selected_candidate: CandidateKey,
    selected_account: AccountId,
    provider_model: ProviderModelId,
    selected_proxy_profile: Option<AccountProxyProfile>,
    explanation: DecisionExplanation,
    retry_plan: RoutingRetryPlan,
    tenant_id: TenantId,
    request_id: RequestId,
    admission_lease: RoutingAdmissionLease,
}

impl CoordinatedRoute {
    pub(crate) fn new(parts: CoordinatedRouteParts) -> Self {
        Self {
            selected_candidate: parts.selected_candidate,
            selected_account: parts.selected_account,
            provider_model: parts.provider_model,
            selected_proxy_profile: parts.selected_proxy_profile,
            explanation: parts.explanation,
            retry_plan: parts.retry_plan,
            tenant_id: parts.tenant_id,
            request_id: parts.request_id,
            admission_lease: parts.admission_lease,
        }
    }

    /// Returns the selected candidate identity.
    #[must_use]
    pub const fn selected_candidate(&self) -> &CandidateKey {
        &self.selected_candidate
    }

    /// Returns the selected account identity.
    #[must_use]
    pub const fn selected_account(&self) -> &AccountId {
        &self.selected_account
    }

    /// Returns the provider-side model chosen through the model catalog.
    #[must_use]
    pub const fn provider_model(&self) -> &ProviderModelId {
        &self.provider_model
    }

    /// Returns the exact proxy profile approved by eligibility evaluation.
    ///
    /// `None` means the proxy signal was explicitly allowed to degrade or no
    /// approved profile was supplied. Callers must not silently re-resolve a
    /// different profile after this immutable routing decision.
    #[must_use]
    pub const fn selected_proxy_profile(&self) -> Option<&AccountProxyProfile> {
        self.selected_proxy_profile.as_ref()
    }

    /// Returns the complete deterministic decision explanation.
    #[must_use]
    pub const fn explanation(&self) -> &DecisionExplanation {
        &self.explanation
    }

    /// Returns the immutable retry and failover plan.
    #[must_use]
    pub const fn retry_plan(&self) -> &RoutingRetryPlan {
        &self.retry_plan
    }

    /// Returns the owned coupled admission lease.
    #[must_use]
    pub const fn admission_lease(&self) -> &RoutingAdmissionLease {
        &self.admission_lease
    }

    /// Returns mutable access for the runtime to commit admitted usage.
    #[must_use]
    pub fn admission_lease_mut(&mut self) -> &mut RoutingAdmissionLease {
        &mut self.admission_lease
    }

    /// Consumes the route and returns its admission lifecycle lease.
    #[must_use]
    pub fn into_admission_lease(self) -> RoutingAdmissionLease {
        self.admission_lease
    }

    /// Creates the exact idempotency identity for one provider attempt's usage.
    #[must_use]
    pub fn usage_confirmation_id(&self, attempt_id: AttemptId) -> UsageConfirmationId {
        UsageConfirmationId::new(
            self.tenant_id.clone(),
            self.selected_account.clone(),
            self.request_id.clone(),
            attempt_id,
        )
    }

    /// Returns the current coupled admission lifecycle state.
    #[must_use]
    pub const fn admission_state(&self) -> RoutingAdmissionLeaseState {
        self.admission_lease.state()
    }
}

/// Stateless routing pipeline paired with the authoritative admission engines.
#[derive(Clone)]
pub struct RoutingCoordinator {
    admission: RoutingAdmissionCoordinator,
    #[cfg(feature = "wasm-policy")]
    wasm_policy: Option<Arc<dyn RoutingWasmEvaluator>>,
}

impl fmt::Debug for RoutingCoordinator {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RoutingCoordinator");
        debug.field("admission", &self.admission);
        #[cfg(feature = "wasm-policy")]
        debug.field("wasm_policy_installed", &self.wasm_policy.is_some());
        debug.finish()
    }
}

impl RoutingCoordinator {
    /// Creates a coordinator from the coupled rate, concurrency, and budget engine.
    #[must_use]
    pub const fn new(admission: RoutingAdmissionCoordinator) -> Self {
        Self {
            admission,
            #[cfg(feature = "wasm-policy")]
            wasm_policy: None,
        }
    }

    /// Installs one isolated optional routing policy evaluator.
    ///
    /// The evaluator receives only sorted candidate identifiers plus the
    /// non-secret priority, weight, and load values of candidates that passed
    /// native eligibility and cost checks. A validated selection overrides the
    /// native weighted policy after affinity lookup, while an explicit decline
    /// preserves native routing. Evaluation errors, degradation, invalid output,
    /// traps, timeouts, and resource exhaustion fail closed before admission.
    #[cfg(feature = "wasm-policy")]
    #[must_use]
    pub fn with_wasm_policy(mut self, evaluator: Arc<dyn RoutingWasmEvaluator>) -> Self {
        self.wasm_policy = Some(evaluator);
        self
    }

    /// Filters, prices, selects, explains, and admits one request.
    ///
    /// The function consumes immutable cross-domain snapshots and never reads a
    /// credential. Admission occurs only after deterministic selection. Failure
    /// before admission has no external effect; admission failures preserve the
    /// coupled engine's rollback or reconciliation semantics.
    ///
    /// # Errors
    ///
    /// Returns a redacted stable code and any deterministic candidate exclusions.
    pub fn coordinate(
        &self,
        request: CoordinationRequest,
        snapshots: CoordinationSnapshots<'_>,
    ) -> Result<CoordinatedRoute, CoordinatorError> {
        engine::coordinate(
            &self.admission,
            #[cfg(feature = "wasm-policy")]
            self.wasm_policy.as_deref(),
            request,
            snapshots,
        )
    }
}

fn valid_destination_region(value: &str) -> bool {
    let Some(first) = value.as_bytes().first() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= MAX_DESTINATION_REGION_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

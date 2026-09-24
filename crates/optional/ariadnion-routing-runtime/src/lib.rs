// crates/optional/ariadnion-routing-runtime/src/lib.rs - Routing runtime orchestration for Ariadnion.
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
//! Durable account projection, routing, credential leasing, and final execution.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod circuit_probe;
mod error_code;
mod execution;
mod runtime_support;

use circuit_probe::CircuitProbeGuard;
pub use circuit_probe::{
    CircuitProbeAcquisition, CircuitProbeClock, CircuitProbeClockError, CircuitProbeClockReading,
    CircuitProbeError, CircuitProbeErrorCode, CircuitProbeKey, CircuitProbeLease, CircuitProbePort,
    CircuitProbeRegistration, CircuitProbeRegistry, CircuitProbeRegistryError,
    CircuitProbeRegistryErrorCode, CircuitProbeValidation, MAX_CIRCUIT_PROBE_ACCOUNTS,
    ProcessCircuitProbeClock,
};
pub use execution::{
    PhysicalAttemptIdentity, PhysicalExecutionAcceptance, ProviderExecutionInterruption,
    ProviderExecutionOutcome, ProviderExecutionPort, ProviderExecutionRequest, RuntimeFailure,
    RuntimeFailureReason, RuntimeOutcome, RuntimePorts, RuntimeSuccess,
};

use runtime_support::*;

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;
use std::time::Instant;

use ariadnion_account_affinity::AffinitySnapshot;
use ariadnion_account_circuit::CircuitOutcome;
use ariadnion_account_domain::SecretPurpose;
use ariadnion_account_import::{
    AccountCredentialReference, AccountCredentialReferenceRequest, AccountProjectionRequest,
};
use ariadnion_account_pool::{CandidateSnapshot, SnapshotId, SnapshotVersion};
use ariadnion_account_vault::{SecretLease, SecretLeaseLifetime, SecretReadRequest};
use ariadnion_core::{AttemptId, ModuleId, RequestContext, TenantId};
use ariadnion_model_catalog::ModelCatalogSnapshot;
use ariadnion_model_pricing::PricingCatalog;
use ariadnion_provider_http::{PROVIDER_HTTP_CREDENTIAL_MODULE, PROVIDER_HTTP_CREDENTIAL_PURPOSE};
use ariadnion_rate_limit::MonotonicTime;
use ariadnion_routing_coordinator::{
    CoordinatedRoute, CoordinationRequest, CoordinationSnapshots, EligibilitySnapshots,
    OptionalSnapshot, RoutingCoordinator,
};
use ariadnion_routing_failover::{CandidateKey, FailureClass, MAX_ATTEMPTS, StreamCommitment};
use ariadnion_routing_usage::UsageConfirmationId;

/// Maximum physical attempts accepted by one runtime request.
pub const MAX_RUNTIME_ATTEMPTS: usize = MAX_ATTEMPTS as usize;

/// Stable, redacted routing-runtime failure codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RoutingRuntimeErrorCode {
    /// A request or adapter result is malformed.
    InvalidArgument,
    /// A physical attempt identity occurs more than once.
    DuplicateAttempt,
    /// The request has no authenticated principal.
    Unauthenticated,
    /// An authenticated tenant does not match durable or routing state.
    TenantMismatch,
    /// Cancellation stopped work; accepted attempts retain reconciliation evidence.
    Cancelled,
    /// The request deadline expired; accepted attempts retain reconciliation evidence.
    DeadlineExceeded,
    /// Durable account state could not be loaded or reconstructed.
    ProjectionUnavailable,
    /// The authoritative immutable account-pool snapshot is unavailable or stale.
    PoolUnavailable,
    /// The immutable model catalog could not be loaded or resolved.
    ModelUnavailable,
    /// The injected monotonic clock could not produce a finalization time.
    MonotonicClockUnavailable,
    /// Deterministic routing or admission rejected the request.
    CoordinationFailed,
    /// The approved proxy snapshot cannot be executed by provider HTTP.
    UnsupportedProxyProfile,
    /// The selected account's credential reference could not be authorized.
    CredentialUnavailable,
    /// A credential resolution result crossed its exact account binding.
    CredentialMismatch,
    /// The short credential lease could not be issued.
    VaultUnavailable,
    /// A returned lease crossed its module, purpose, reference, or lifetime binding.
    InvalidLease,
    /// A final executor reported a contradictory physical result.
    InvalidExecutionOutcome,
    /// Authoritative circuit state rejected or could not issue a selected probe.
    CircuitProbeUnavailable,
    /// An acquired probe lease could not be finalized after its disposition was known.
    CircuitProbeFinalizeFailed,
    /// Admission could not be finalized after the physical disposition was known.
    AdmissionFinalizeFailed,
    /// Caller-supplied attempt capacity ended before the failover plan stopped.
    AttemptsExhausted,
    /// An internal cross-snapshot invariant failed closed.
    InvariantViolation,
}

/// A routing-runtime failure that never formats identifiers or secret material.
#[derive(Clone)]
pub struct RoutingRuntimeError {
    code: RoutingRuntimeErrorCode,
    accepted_attempts: Arc<[PhysicalAttemptIdentity]>,
}

impl RoutingRuntimeError {
    /// Creates a redacted failure for a runtime port implementation.
    #[must_use]
    pub fn from_code(code: RoutingRuntimeErrorCode) -> Self {
        Self {
            code,
            accepted_attempts: Arc::from([]),
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> RoutingRuntimeErrorCode {
        self.code
    }

    /// Returns the last accepted physical-attempt identity carried for
    /// reconciliation, when any accepted attempt preceded this error.
    #[must_use]
    pub fn usage_confirmation_id(&self) -> Option<&UsageConfirmationId> {
        self.accepted_attempts
            .last()
            .map(PhysicalAttemptIdentity::usage_confirmation_id)
    }

    /// Returns every physically accepted attempt requiring reconciliation.
    #[must_use]
    pub fn accepted_attempts(&self) -> &[PhysicalAttemptIdentity] {
        &self.accepted_attempts
    }

    fn with_accepted(mut self, identity: PhysicalAttemptIdentity) -> Self {
        let mut accepted = self.accepted_attempts.to_vec();
        accepted.push(identity);
        self.accepted_attempts = Arc::from(accepted.into_boxed_slice());
        self
    }

    fn prepend_accepted(mut self, prior: &[PhysicalAttemptIdentity]) -> Self {
        if prior.is_empty() {
            return self;
        }
        let mut accepted = Vec::with_capacity(prior.len() + self.accepted_attempts.len());
        accepted.extend_from_slice(prior);
        accepted.extend_from_slice(&self.accepted_attempts);
        self.accepted_attempts = Arc::from(accepted.into_boxed_slice());
        self
    }
}

impl Debug for RoutingRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingRuntimeError")
            .field("code", &self.code)
            .field("accepted_attempt_count", &self.accepted_attempts.len())
            .finish()
    }
}

impl Display for RoutingRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for RoutingRuntimeError {}

/// One caller-stable physical attempt identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAttempt {
    attempt_id: AttemptId,
}

impl RuntimeAttempt {
    /// Creates one attempt descriptor.
    #[must_use]
    pub const fn new(attempt_id: AttemptId) -> Self {
        Self { attempt_id }
    }

    /// Returns the stable physical attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
}

/// Redacted failure returned by a monotonic clock implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeMonotonicClockError;

impl Display for RuntimeMonotonicClockError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ROUTING_RUNTIME_MONOTONIC_CLOCK_UNAVAILABLE")
    }
}

impl std::error::Error for RuntimeMonotonicClockError {}

/// Adapter-owned monotonic clock sharing the origin used by admission requests.
pub trait RuntimeMonotonicClock: Send + Sync {
    /// Samples nanoseconds from the clock's stable origin.
    ///
    /// # Errors
    /// Returns a redacted error when a monotonic observation is unavailable.
    fn now(&self) -> Result<MonotonicTime, RuntimeMonotonicClockError>;
}

/// Process-local monotonic clock backed by one stable [`Instant`] origin.
///
/// Callers must use observations from this same instance when constructing
/// admission requests passed to a runtime that owns it.
#[derive(Clone, Debug)]
pub struct ProcessMonotonicClock {
    origin: Instant,
}

impl ProcessMonotonicClock {
    /// Creates a clock whose zero point is the current process-local instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for ProcessMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeMonotonicClock for ProcessMonotonicClock {
    fn now(&self) -> Result<MonotonicTime, RuntimeMonotonicClockError> {
        u64::try_from(self.origin.elapsed().as_nanos())
            .map(MonotonicTime::from_nanos)
            .map_err(|_| RuntimeMonotonicClockError)
    }
}

/// A bounded, duplicate-free physical attempt schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptSchedule(Arc<[RuntimeAttempt]>);

impl AttemptSchedule {
    /// Validates one non-empty schedule containing at most eight attempts.
    ///
    /// # Errors
    /// Returns a stable error for an empty, oversized, or duplicate schedule.
    pub fn new(attempts: Vec<RuntimeAttempt>) -> Result<Self, RoutingRuntimeError> {
        if attempts.is_empty() || attempts.len() > MAX_RUNTIME_ATTEMPTS {
            return Err(runtime_error(RoutingRuntimeErrorCode::InvalidArgument));
        }
        let mut identities = BTreeSet::new();
        for attempt in &attempts {
            if !identities.insert(attempt.attempt_id()) {
                return Err(runtime_error(RoutingRuntimeErrorCode::DuplicateAttempt));
            }
        }
        Ok(Self(Arc::from(attempts.into_boxed_slice())))
    }

    /// Returns attempt descriptors in caller-provided order.
    #[must_use]
    pub fn attempts(&self) -> &[RuntimeAttempt] {
        &self.0
    }
}

/// Complete bounded runtime input with one fresh admission request per attempt.
#[derive(Clone)]
pub struct RuntimeRequest {
    schedule: AttemptSchedule,
    coordination: Vec<CoordinationRequest>,
    executor: Arc<dyn ProviderExecutionPort>,
}

impl RuntimeRequest {
    /// Couples each physical attempt with one independently identifiable
    /// coordination and admission request.
    ///
    /// Every attempt must retain the same routing and admission policy scope.
    /// Reservation identities and observation times may change between attempts;
    /// tenant, request, model, placement, cost, budget, and retry constraints may
    /// not. Validation performs no admission, credential access, or provider I/O.
    ///
    /// # Errors
    /// Returns [`RoutingRuntimeErrorCode::InvalidArgument`] unless both arrays
    /// have equal, non-zero bounded lengths and all requests have the same scope.
    pub fn new(
        schedule: AttemptSchedule,
        coordination: Vec<CoordinationRequest>,
        executor: Arc<dyn ProviderExecutionPort>,
    ) -> Result<Self, RoutingRuntimeError> {
        if coordination.len() != schedule.attempts().len() {
            return Err(runtime_error(RoutingRuntimeErrorCode::InvalidArgument));
        }
        if coordination
            .windows(2)
            .any(|requests| !requests[0].has_same_routing_scope(&requests[1]))
        {
            return Err(runtime_error(RoutingRuntimeErrorCode::InvalidArgument));
        }
        Ok(Self {
            schedule,
            coordination,
            executor,
        })
    }

    fn into_parts(
        self,
    ) -> (
        Arc<[RuntimeAttempt]>,
        Vec<CoordinationRequest>,
        Arc<dyn ProviderExecutionPort>,
    ) {
        (self.schedule.0, self.coordination, self.executor)
    }
}

impl Debug for RuntimeRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeRequest")
            .field("attempt_count", &self.schedule.attempts().len())
            .field("coordination_count", &self.coordination.len())
            .field("executor", &"<request-scoped>")
            .finish()
    }
}

/// Optional immutable signals supplied alongside durable pool and model state.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeSignals<'a> {
    pricing: OptionalSnapshot<'a, PricingCatalog>,
    eligibility: EligibilitySnapshots<'a>,
    affinity: OptionalSnapshot<'a, AffinitySnapshot>,
}

impl<'a> RuntimeSignals<'a> {
    /// Creates one request-scoped immutable signal view.
    #[must_use]
    pub const fn new(
        pricing: OptionalSnapshot<'a, PricingCatalog>,
        eligibility: EligibilitySnapshots<'a>,
        affinity: OptionalSnapshot<'a, AffinitySnapshot>,
    ) -> Self {
        Self {
            pricing,
            eligibility,
            affinity,
        }
    }

    fn snapshots<'b>(
        self,
        pool: &'b CandidateSnapshot,
        models: &'b ModelCatalogSnapshot,
    ) -> CoordinationSnapshots<'b>
    where
        'a: 'b,
    {
        CoordinationSnapshots::new(pool, models, self.pricing, self.eligibility, self.affinity)
    }
}

/// Routing runtime connecting durable state to final provider execution.
#[derive(Clone, Debug)]
pub struct RoutingRuntime {
    coordinator: RoutingCoordinator,
    ports: RuntimePorts,
    module: ModuleId,
    purpose: SecretPurpose,
    lease_lifetime: SecretLeaseLifetime,
}

impl RoutingRuntime {
    /// Creates the provider HTTP runtime with the exact module and credential purpose.
    ///
    /// # Errors
    /// Returns an invariant failure only if the compiled provider HTTP constants
    /// cease to satisfy their public identifier contracts.
    pub fn new(
        coordinator: RoutingCoordinator,
        ports: RuntimePorts,
        lease_lifetime: SecretLeaseLifetime,
    ) -> Result<Self, RoutingRuntimeError> {
        let module = ModuleId::parse(PROVIDER_HTTP_CREDENTIAL_MODULE)
            .map_err(|_| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
        let purpose = SecretPurpose::parse(PROVIDER_HTTP_CREDENTIAL_PURPOSE)
            .map_err(|_| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
        Ok(Self {
            coordinator,
            ports,
            module,
            purpose,
            lease_lifetime,
        })
    }

    /// Loads one durable account generation and one model snapshot, then
    /// coordinates, acquires authoritative circuit probes, authorizes, leases,
    /// and executes bounded physical attempts.
    ///
    /// Each attempt receives a fresh coordination request so candidate switches
    /// never reuse an account-bound budget reservation. A selected half-open
    /// account must acquire its bounded probe before credential access; closed
    /// accounts carry a generation-bound observation lease. Physical acceptance commits admission even
    /// when the provider later fails. Pre-execution failure releases admission.
    /// Retry safety and the first-byte boundary are enforced by the first route's
    /// immutable failover plan. Accepted usage identities are returned but never
    /// persisted by this P5 runtime.
    ///
    /// # Errors
    /// Returns a redacted stable failure for authentication, durable snapshots,
    /// model resolution, routing, credential authorization, leasing, or admission
    /// finalization. An admission-finalization error after physical acceptance
    /// carries the stable usage identity through [`RoutingRuntimeError::usage_confirmation_id`].
    /// Provider-originated cancellation or deadline expiry returns the matching
    /// runtime code without failover; physically accepted attempts retain every
    /// reconciliation identity through [`RoutingRuntimeError::accepted_attempts`].
    pub async fn execute(
        &self,
        request: RuntimeRequest,
        signals: RuntimeSignals<'_>,
        context: &RequestContext,
    ) -> Result<RuntimeOutcome, RoutingRuntimeError> {
        let tenant = authenticated_tenant(context)?;
        let loaded = self.load_state(&tenant, context).await?;
        let (attempts, coordination, executor) = request.into_parts();
        self.execute_loaded(
            loaded,
            attempts,
            coordination,
            executor.as_ref(),
            signals,
            context,
        )
        .await
    }

    async fn load_state(
        &self,
        tenant: &TenantId,
        context: &RequestContext,
    ) -> Result<LoadedState, RoutingRuntimeError> {
        ensure_active(context)?;
        let pool = self
            .ports
            .pool
            .candidate_snapshot()
            .map_err(|_| runtime_error(RoutingRuntimeErrorCode::PoolUnavailable))?;
        let generation = pool_generation(&pool)?;
        let projection = self
            .ports
            .account_projection
            .account_projection(AccountProjectionRequest::new(generation), context)
            .await
            .map_err(map_projection_error)?;
        validate_projection(&projection, tenant, generation)?;
        let models = self
            .ports
            .models
            .current_snapshot()
            .map_err(|_| runtime_error(RoutingRuntimeErrorCode::ModelUnavailable))?;
        ensure_active(context)?;
        Ok(LoadedState {
            tenant: tenant.clone(),
            projection,
            pool,
            models,
        })
    }

    async fn execute_loaded(
        &self,
        loaded: LoadedState,
        attempts: Arc<[RuntimeAttempt]>,
        coordination: Vec<CoordinationRequest>,
        executor: &dyn ProviderExecutionPort,
        signals: RuntimeSignals<'_>,
        context: &RequestContext,
    ) -> Result<RuntimeOutcome, RoutingRuntimeError> {
        let mut control = self.start_state(&loaded, attempts, coordination, signals)?;
        loop {
            match control {
                LoopControl::Continue(state) => {
                    control = self
                        .run_state(*state, &loaded, executor, signals, context)
                        .await?;
                }
                LoopControl::Finished(outcome) => return Ok(outcome),
            }
        }
    }

    fn start_state(
        &self,
        loaded: &LoadedState,
        attempts: Arc<[RuntimeAttempt]>,
        coordination: Vec<CoordinationRequest>,
        signals: RuntimeSignals<'_>,
    ) -> Result<LoopControl, RoutingRuntimeError> {
        let mut remaining_attempts = attempts
            .iter()
            .cloned()
            .collect::<std::collections::VecDeque<_>>();
        let mut remaining_coordination = coordination
            .into_iter()
            .collect::<std::collections::VecDeque<_>>();
        let attempt = remaining_attempts
            .pop_front()
            .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvalidArgument))?;
        let request = remaining_coordination
            .pop_front()
            .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvalidArgument))?;
        let accepted = Vec::with_capacity(MAX_RUNTIME_ATTEMPTS);
        match self.coordinate(request, &loaded.pool, &loaded.models, signals) {
            Ok(route) => Ok(LoopControl::Continue(Box::new(ExecutionState {
                retry_plan: route.retry_plan().clone(),
                current: route.selected_candidate().clone(),
                route,
                attempt,
                ordinal: 1,
                accepted,
                remaining_attempts,
                remaining_coordination,
            }))),
            Err(TargetCoordinationFailure::Admission {
                refusal,
                initial_retry_context: Some(context),
            }) => self.retry_after_admission(
                RetryDirective {
                    candidate: context.candidate().clone(),
                    failure: FailureClass::RateLimited,
                    commitment: StreamCommitment::Uncommitted,
                },
                ExecutionRemainder {
                    retry_plan: context.retry_plan().clone(),
                    current: context.candidate().clone(),
                    ordinal: 1,
                    accepted,
                    remaining_attempts,
                    remaining_coordination,
                },
                refusal,
                loaded,
                signals,
            ),
            Err(TargetCoordinationFailure::Admission { .. }) => {
                Err(runtime_error(RoutingRuntimeErrorCode::CoordinationFailed))
            }
            Err(TargetCoordinationFailure::Runtime(error)) => Err(error),
        }
    }

    async fn run_state(
        &self,
        state: ExecutionState,
        loaded: &LoadedState,
        executor: &dyn ProviderExecutionPort,
        signals: RuntimeSignals<'_>,
        context: &RequestContext,
    ) -> Result<LoopControl, RoutingRuntimeError> {
        let ExecutionState {
            route,
            attempt,
            retry_plan,
            current,
            ordinal,
            accepted,
            remaining_attempts,
            remaining_coordination,
        } = state;
        let progress = self
            .execute_route(route, &attempt, loaded, executor, context)
            .await
            .map_err(|error| error.prepend_accepted(&accepted))?;
        let remainder = ExecutionRemainder {
            retry_plan,
            current,
            ordinal,
            accepted,
            remaining_attempts,
            remaining_coordination,
        };
        match progress {
            AttemptProgress::Succeeded(identity, commitment) => Ok(LoopControl::Finished(
                success_outcome(identity, commitment, remainder.accepted),
            )),
            AttemptProgress::Failed(failed) => {
                self.advance_failed(failed, remainder, loaded, signals)
            }
        }
    }

    fn advance_failed(
        &self,
        failed: FailedAttempt,
        mut remainder: ExecutionRemainder,
        loaded: &LoadedState,
        signals: RuntimeSignals<'_>,
    ) -> Result<LoopControl, RoutingRuntimeError> {
        retain_accepted(&mut remainder.accepted, failed.accepted.clone());
        let accepted = remainder.accepted.clone();
        self.advance_failed_inner(failed, remainder, loaded, signals)
            .map_err(|error| error.prepend_accepted(&accepted))
    }

    fn advance_failed_inner(
        &self,
        failed: FailedAttempt,
        remainder: ExecutionRemainder,
        loaded: &LoadedState,
        signals: RuntimeSignals<'_>,
    ) -> Result<LoopControl, RoutingRuntimeError> {
        let decision = remainder
            .retry_plan
            .decide(
                &remainder.current,
                remainder.ordinal,
                failed.commitment,
                failed.failure,
            )
            .map_err(|_| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
        match next_candidate(decision.action(), &remainder.current) {
            Some(candidate) => self.prepare_retry(
                RetryDirective {
                    candidate,
                    failure: failed.failure,
                    commitment: failed.commitment,
                },
                remainder,
                loaded,
                signals,
            ),
            None => Ok(LoopControl::Finished(failed_runtime_outcome(
                RuntimeFailureReason::FailoverStopped,
                failed.failure,
                failed.commitment,
                remainder.accepted,
            ))),
        }
    }

    fn prepare_retry(
        &self,
        directive: RetryDirective,
        mut remainder: ExecutionRemainder,
        loaded: &LoadedState,
        signals: RuntimeSignals<'_>,
    ) -> Result<LoopControl, RoutingRuntimeError> {
        let Some(slot) = take_retry_slot(&mut remainder)? else {
            return Ok(LoopControl::Finished(failed_runtime_outcome(
                RuntimeFailureReason::AttemptsExhausted,
                directive.failure,
                directive.commitment,
                remainder.accepted,
            )));
        };
        match self.coordinate_target(slot.request, &directive.candidate, loaded, signals) {
            Ok(route) => Ok(LoopControl::Continue(Box::new(ExecutionState {
                route,
                attempt: slot.attempt,
                retry_plan: remainder.retry_plan,
                current: directive.candidate,
                ordinal: remainder.ordinal,
                accepted: remainder.accepted,
                remaining_attempts: remainder.remaining_attempts,
                remaining_coordination: remainder.remaining_coordination,
            }))),
            Err(TargetCoordinationFailure::Admission { refusal, .. }) => {
                self.retry_after_admission(directive, remainder, refusal, loaded, signals)
            }
            Err(TargetCoordinationFailure::Runtime(error)) => Err(error),
        }
    }

    fn retry_after_admission(
        &self,
        directive: RetryDirective,
        remainder: ExecutionRemainder,
        refusal: ariadnion_routing_failover::AdmissionRefusal,
        loaded: &LoadedState,
        signals: RuntimeSignals<'_>,
    ) -> Result<LoopControl, RoutingRuntimeError> {
        let next = next_candidate_after_admission(
            &remainder.retry_plan,
            &directive.candidate,
            remainder.ordinal,
            directive.commitment,
            refusal,
        )?;
        match next {
            Some(candidate) => self.prepare_retry(
                RetryDirective {
                    candidate,
                    ..directive
                },
                remainder,
                loaded,
                signals,
            ),
            None => Err(runtime_error(RoutingRuntimeErrorCode::CoordinationFailed)),
        }
    }

    fn coordinate(
        &self,
        request: CoordinationRequest,
        pool: &CandidateSnapshot,
        models: &ModelCatalogSnapshot,
        signals: RuntimeSignals<'_>,
    ) -> Result<CoordinatedRoute, TargetCoordinationFailure> {
        self.coordinator
            .coordinate(request, signals.snapshots(pool, models))
            .map_err(map_target_coordination_error)
    }

    fn coordinate_target(
        &self,
        request: CoordinationRequest,
        target: &CandidateKey,
        loaded: &LoadedState,
        signals: RuntimeSignals<'_>,
    ) -> Result<CoordinatedRoute, TargetCoordinationFailure> {
        let candidate =
            find_candidate(&loaded.pool, target).map_err(TargetCoordinationFailure::Runtime)?;
        let pool = CandidateSnapshot::new(
            SnapshotId::new(loaded.pool.id().get()),
            SnapshotVersion::new(loaded.pool.version().get()),
            vec![candidate.clone()],
        )
        .map_err(|_| {
            TargetCoordinationFailure::Runtime(runtime_error(
                RoutingRuntimeErrorCode::InvariantViolation,
            ))
        })?;
        let route = self
            .coordinator
            .coordinate(request, signals.snapshots(&pool, &loaded.models))
            .map_err(map_target_coordination_error)?;
        if route.selected_candidate() != target {
            return Err(TargetCoordinationFailure::Runtime(runtime_error(
                RoutingRuntimeErrorCode::InvariantViolation,
            )));
        }
        Ok(route)
    }

    async fn execute_route(
        &self,
        route: CoordinatedRoute,
        attempt: &RuntimeAttempt,
        loaded: &LoadedState,
        executor: &dyn ProviderExecutionPort,
        context: &RequestContext,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        let mut prepared = self.prepare_route(route, attempt, loaded, context).await?;
        let dispatch_time = match self.ports.clock.now() {
            Ok(now) => now,
            Err(_) => {
                return self.release_pre_dispatch(
                    prepared.route,
                    prepared.probe,
                    runtime_error(RoutingRuntimeErrorCode::MonotonicClockUnavailable),
                );
            }
        };
        if let Err(error) = self.validate_prepared_probe(&mut prepared) {
            let route = prepared.route;
            let probe = prepared.probe.take();
            return self.release_pre_dispatch(route, probe, error);
        }
        let pending = PendingExecutionGuard::new(
            prepared.route,
            prepared.identity,
            prepared.probe,
            Arc::clone(&self.ports.clock),
            dispatch_time,
        );
        let outcome = executor.execute(prepared.execution, context).await;
        let (route, identity, probe) = pending.disarm()?;
        self.finalize_execution(route, identity, probe, dispatch_time, outcome)
    }

    fn validate_prepared_probe(
        &self,
        prepared: &mut PreparedRoute,
    ) -> Result<(), RoutingRuntimeError> {
        let Some(probe) = prepared.probe.as_mut() else {
            return Ok(());
        };
        match probe.validate() {
            Ok(circuit_probe::CircuitProbeValidation::Valid) => Ok(()),
            Ok(circuit_probe::CircuitProbeValidation::Invalidated) => {
                probe.disarm();
                Err(runtime_error(
                    RoutingRuntimeErrorCode::CircuitProbeUnavailable,
                ))
            }
            Err(_) => Err(runtime_error(
                RoutingRuntimeErrorCode::CircuitProbeUnavailable,
            )),
        }
    }

    async fn prepare_route(
        &self,
        route: CoordinatedRoute,
        attempt: &RuntimeAttempt,
        loaded: &LoadedState,
        context: &RequestContext,
    ) -> Result<PreparedRoute, RoutingRuntimeError> {
        let (target, probe) = match self.prepare_target_and_probe(&route, loaded, context) {
            Ok(prepared) => prepared,
            Err(error) => return self.release_pre_dispatch(route, None, error),
        };
        match self
            .prepare_execution(&route, attempt, loaded, target, context)
            .await
        {
            Ok((execution, identity)) => Ok(PreparedRoute {
                route,
                execution,
                identity,
                probe,
            }),
            Err(error) => self.release_pre_dispatch(route, probe, error),
        }
    }

    fn prepare_target_and_probe(
        &self,
        route: &CoordinatedRoute,
        loaded: &LoadedState,
        context: &RequestContext,
    ) -> Result<(OwnedTarget, Option<CircuitProbeGuard>), RoutingRuntimeError> {
        let target = self.prepare_target(route, loaded)?;
        let key = circuit_probe_key(&target, loaded);
        let probe = self.acquire_circuit_probe(&key, context)?;
        Ok((target, probe))
    }

    fn prepare_target(
        &self,
        route: &CoordinatedRoute,
        loaded: &LoadedState,
    ) -> Result<OwnedTarget, RoutingRuntimeError> {
        execution::validate_execution_proxy(route.selected_proxy_profile())?;
        validate_route_target(route, loaded)
    }

    fn acquire_circuit_probe(
        &self,
        key: &CircuitProbeKey,
        context: &RequestContext,
    ) -> Result<Option<CircuitProbeGuard>, RoutingRuntimeError> {
        ensure_active(context)?;
        let authority = Arc::clone(
            self.ports
                .circuit_probes
                .as_ref()
                .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::CircuitProbeUnavailable))?,
        );
        let acquisition = authority
            .acquire_probe(key, context)
            .map_err(map_circuit_probe_acquire_error)?;
        self.accept_probe_acquisition(key, acquisition, authority, context)
    }

    fn accept_probe_acquisition(
        &self,
        key: &CircuitProbeKey,
        acquisition: CircuitProbeAcquisition,
        authority: Arc<dyn CircuitProbePort>,
        context: &RequestContext,
    ) -> Result<Option<CircuitProbeGuard>, RoutingRuntimeError> {
        let lease = match acquisition {
            CircuitProbeAcquisition::Closed(lease) | CircuitProbeAcquisition::HalfOpen(lease) => {
                lease
            }
        };
        let error = if lease.key() != key {
            Some(runtime_error(RoutingRuntimeErrorCode::InvariantViolation))
        } else {
            ensure_active(context).err()
        };
        let guard = CircuitProbeGuard::new(authority, lease);
        match error {
            Some(error) => self.finish_probe_rejection(guard, error),
            None => Ok(Some(guard)),
        }
    }

    fn finish_probe_rejection<T>(
        &self,
        probe: CircuitProbeGuard,
        original: RoutingRuntimeError,
    ) -> Result<T, RoutingRuntimeError> {
        Self::complete_circuit_probe(Some(probe), CircuitOutcome::Neutral)?;
        Err(original)
    }

    fn release_pre_dispatch<T>(
        &self,
        route: CoordinatedRoute,
        probe: Option<CircuitProbeGuard>,
        original: RoutingRuntimeError,
    ) -> Result<T, RoutingRuntimeError> {
        let admission = self
            .finalization_time(None)
            .and_then(|now| release_route(route, now));
        let probe = Self::complete_circuit_probe(probe, CircuitOutcome::Neutral);
        combine_finalizations(admission, probe, None)?;
        Err(original)
    }

    fn complete_circuit_probe(
        probe: Option<CircuitProbeGuard>,
        outcome: CircuitOutcome,
    ) -> Result<(), RoutingRuntimeError> {
        let Some(probe) = probe else {
            return Ok(());
        };
        probe
            .complete(outcome)
            .map_err(|_| runtime_error(RoutingRuntimeErrorCode::CircuitProbeFinalizeFailed))
    }

    fn finalize_execution(
        &self,
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        probe: Option<CircuitProbeGuard>,
        dispatch_time: MonotonicTime,
        outcome: ProviderExecutionOutcome,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        let finalization = FinalizationState {
            probe,
            dispatch_time,
        };
        match outcome {
            ProviderExecutionOutcome::Accepted { commitment } => {
                self.finalize_success(route, identity, finalization, commitment)
            }
            ProviderExecutionOutcome::Failed {
                acceptance,
                commitment,
                failure,
            } => self.finalize_failure(
                route,
                identity,
                finalization,
                acceptance,
                commitment,
                failure,
            ),
            ProviderExecutionOutcome::Interrupted {
                acceptance,
                commitment,
                interruption,
            } => self.finalize_interruption(
                route,
                identity,
                finalization,
                acceptance,
                commitment,
                interruption,
            ),
        }
    }

    fn finalize_success(
        &self,
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        finalization: FinalizationState,
        commitment: StreamCommitment,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        let admission =
            self.finalize_accepted_admission(route, &identity, finalization.dispatch_time);
        let probe = Self::complete_circuit_probe(finalization.probe, CircuitOutcome::Success);
        combine_finalizations(admission, probe, Some(&identity))?;
        Ok(AttemptProgress::Succeeded(identity, commitment))
    }

    fn finalize_failure(
        &self,
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        finalization: FinalizationState,
        acceptance: PhysicalExecutionAcceptance,
        commitment: StreamCommitment,
        failure: FailureClass,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        if contradictory_acceptance(acceptance, commitment) {
            return self.finalize_contradiction(route, identity, finalization);
        }
        let (admission, accepted_evidence) =
            self.finalize_disposition(route, identity, finalization.dispatch_time, acceptance);
        let probe =
            Self::complete_circuit_probe(finalization.probe, circuit_failure_outcome(failure));
        let accepted = combine_finalizations(admission, probe, accepted_evidence.as_ref())?;
        Ok(AttemptProgress::Failed(FailedAttempt {
            failure,
            commitment,
            accepted,
        }))
    }

    fn finalize_interruption(
        &self,
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        finalization: FinalizationState,
        acceptance: PhysicalExecutionAcceptance,
        commitment: StreamCommitment,
        interruption: ProviderExecutionInterruption,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        if contradictory_acceptance(acceptance, commitment) {
            return self.finalize_contradiction(route, identity, finalization);
        }
        let (admission, accepted_evidence) =
            self.finalize_disposition(route, identity, finalization.dispatch_time, acceptance);
        let probe = Self::complete_circuit_probe(
            finalization.probe,
            circuit_interruption_outcome(acceptance),
        );
        let accepted = combine_finalizations(admission, probe, accepted_evidence.as_ref())?;
        let error = runtime_error(interruption.runtime_error_code());
        Err(execution::with_optional_accepted(error, accepted))
    }

    fn finalize_contradiction(
        &self,
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        finalization: FinalizationState,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        let admission =
            self.finalize_accepted_admission(route, &identity, finalization.dispatch_time);
        let probe =
            Self::complete_circuit_probe(finalization.probe, CircuitOutcome::RetryableFailure);
        combine_finalizations(admission, probe, Some(&identity))?;
        Err(runtime_error(RoutingRuntimeErrorCode::InvalidExecutionOutcome).with_accepted(identity))
    }

    fn finalize_disposition(
        &self,
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        dispatch_time: MonotonicTime,
        acceptance: PhysicalExecutionAcceptance,
    ) -> (
        Result<Option<PhysicalAttemptIdentity>, RoutingRuntimeError>,
        Option<PhysicalAttemptIdentity>,
    ) {
        match acceptance {
            PhysicalExecutionAcceptance::NotAccepted => {
                let accepted = None;
                let now = self.ports.clock.now().unwrap_or(dispatch_time);
                let admission = release_route(route, now).map(|_| accepted.clone());
                (admission, accepted)
            }
            PhysicalExecutionAcceptance::Accepted => {
                let accepted = Some(identity.clone());
                let admission = self
                    .finalize_accepted_admission(route, &identity, dispatch_time)
                    .map(|_| accepted.clone());
                (admission, accepted)
            }
        }
    }

    fn finalize_accepted_admission(
        &self,
        route: CoordinatedRoute,
        identity: &PhysicalAttemptIdentity,
        _dispatch_time: MonotonicTime,
    ) -> Result<(), RoutingRuntimeError> {
        let now = self.ports.clock.now().ok();
        let result = finalize_accepted_route(route, now, identity);
        match (now, result) {
            (None, Ok(())) | (None, Err(_)) => Err(runtime_error(
                RoutingRuntimeErrorCode::MonotonicClockUnavailable,
            )
            .with_accepted(identity.clone())),
            (Some(_), result) => result,
        }
    }

    fn finalization_time(
        &self,
        accepted: Option<&PhysicalAttemptIdentity>,
    ) -> Result<MonotonicTime, RoutingRuntimeError> {
        self.ports.clock.now().map_err(|_| {
            let error = runtime_error(RoutingRuntimeErrorCode::MonotonicClockUnavailable);
            match accepted {
                Some(identity) => error.with_accepted(identity.clone()),
                None => error,
            }
        })
    }

    async fn prepare_execution(
        &self,
        route: &CoordinatedRoute,
        attempt: &RuntimeAttempt,
        loaded: &LoadedState,
        target: OwnedTarget,
        context: &RequestContext,
    ) -> Result<(ProviderExecutionRequest, PhysicalAttemptIdentity), RoutingRuntimeError> {
        let resolved = self.resolve_credential(&target, loaded, context).await?;
        let lease = self.issue_lease(&resolved, context).await?;
        self.revalidate_credential(&resolved, context).await?;
        self.build_execution(route, attempt, loaded, target, lease, context)
    }

    async fn resolve_credential(
        &self,
        target: &OwnedTarget,
        loaded: &LoadedState,
        context: &RequestContext,
    ) -> Result<AccountCredentialReference, RoutingRuntimeError> {
        ensure_active(context)?;
        let resolve_request = AccountCredentialReferenceRequest::new(
            target.account_id.clone(),
            target.provider_id.clone(),
            target.config_version.get(),
            self.purpose.clone(),
            loaded.projection.generation(),
        )
        .map_err(map_credential_error)?;
        let resolved = self
            .ports
            .credentials
            .account_credential_reference(resolve_request.clone(), context)
            .await
            .map_err(map_credential_error)?;
        validate_credential(&resolve_request, &resolved, &loaded.tenant)?;
        Ok(resolved)
    }

    async fn revalidate_credential(
        &self,
        resolved: &AccountCredentialReference,
        context: &RequestContext,
    ) -> Result<(), RoutingRuntimeError> {
        ensure_active(context)?;
        let request = resolved.revalidation_request();
        let current = self
            .ports
            .credentials
            .account_credential_reference(request.clone(), context)
            .await
            .map_err(map_credential_error)?;
        ensure_active(context)?;
        validate_credential(&request, &current, resolved.tenant_id())?;
        validate_revalidated_credential(resolved, &current)
    }

    async fn issue_lease(
        &self,
        resolved: &AccountCredentialReference,
        context: &RequestContext,
    ) -> Result<SecretLease, RoutingRuntimeError> {
        let lease = self
            .ports
            .vault
            .read(
                SecretReadRequest::new(
                    resolved.secret_ref().clone(),
                    self.module.clone(),
                    self.lease_lifetime,
                ),
                context,
            )
            .await
            .map_err(map_vault_error)?;
        ensure_active(context)?;
        validate_lease(&lease, resolved, &self.module, &self.purpose)?;
        Ok(lease)
    }

    fn build_execution(
        &self,
        route: &CoordinatedRoute,
        attempt: &RuntimeAttempt,
        loaded: &LoadedState,
        target: OwnedTarget,
        lease: SecretLease,
        context: &RequestContext,
    ) -> Result<(ProviderExecutionRequest, PhysicalAttemptIdentity), RoutingRuntimeError> {
        let usage_confirmation = route.usage_confirmation_id(attempt.attempt_id().clone());
        validate_usage_binding(&usage_confirmation, &loaded.tenant, context)?;
        let proxy_profile = route.selected_proxy_profile().cloned().map(Arc::new);
        let identity = PhysicalAttemptIdentity {
            usage_confirmation: usage_confirmation.clone(),
            candidate: route.selected_candidate().clone(),
            provider_id: target.provider_id.clone(),
            provider_model: route.provider_model().clone(),
            proxy_profile: proxy_profile.clone(),
        };
        let execution = ProviderExecutionRequest {
            candidate: route.selected_candidate().clone(),
            account_id: target.account_id,
            provider_id: target.provider_id,
            provider_model: route.provider_model().clone(),
            proxy_profile,
            usage_confirmation,
            credential: lease,
        };
        Ok((execution, identity))
    }
}

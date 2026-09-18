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

mod error_code;
mod runtime_support;

use runtime_support::*;

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use ariadnion_account_affinity::AffinitySnapshot;
use ariadnion_account_domain::{AccountId, ProviderId, SecretPurpose};
use ariadnion_account_import::{
    AccountCredentialReference, AccountCredentialReferencePort, AccountCredentialReferenceRequest,
    AccountProjectionPort, AccountProjectionRequest,
};
use ariadnion_account_pool::{
    CandidateSelectionPort, CandidateSnapshot, SnapshotId, SnapshotVersion,
};
use ariadnion_account_vault::{SecretLease, SecretLeaseLifetime, SecretReadRequest, VaultPort};
use ariadnion_core::{AttemptId, ModuleId, RequestContext, TenantId};
use ariadnion_model_catalog::{ModelCatalogPort, ModelCatalogSnapshot};
use ariadnion_model_domain::ProviderModelId;
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
    /// Cancellation stopped work before physical execution was accepted.
    Cancelled,
    /// The request deadline expired before physical execution was accepted.
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
    /// # Errors
    /// Returns [`RoutingRuntimeErrorCode::InvalidArgument`] unless both arrays
    /// have equal, non-zero bounded lengths.
    pub fn new(
        schedule: AttemptSchedule,
        coordination: Vec<CoordinationRequest>,
        executor: Arc<dyn ProviderExecutionPort>,
    ) -> Result<Self, RoutingRuntimeError> {
        if coordination.len() != schedule.attempts().len() {
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

/// Whether the provider physically accepted a request attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalExecutionAcceptance {
    /// No provider-side execution was accepted, so admission must be released.
    NotAccepted,
    /// The provider accepted execution, so admission must be committed.
    Accepted,
}

/// Final provider execution disposition without response or credential data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderExecutionOutcome {
    /// The provider accepted and completed the physical attempt.
    Accepted {
        /// Whether a client-visible response byte has been emitted.
        commitment: StreamCommitment,
    },
    /// The attempt failed with an explicit physical-acceptance boundary.
    Failed {
        /// Whether the provider physically accepted the attempt.
        acceptance: PhysicalExecutionAcceptance,
        /// Whether a client-visible response byte has been emitted.
        commitment: StreamCommitment,
        /// Stable failure class used by the immutable failover plan.
        failure: FailureClass,
    },
}

impl ProviderExecutionOutcome {
    /// Reports one successfully accepted physical execution.
    #[must_use]
    pub const fn accepted(commitment: StreamCommitment) -> Self {
        Self::Accepted { commitment }
    }

    /// Reports one classified failure with an explicit physical disposition.
    ///
    /// # Errors
    /// A first client-visible byte proves that physical execution was accepted;
    /// reporting otherwise returns a stable invariant error.
    pub fn failed(
        acceptance: PhysicalExecutionAcceptance,
        commitment: StreamCommitment,
        failure: FailureClass,
    ) -> Result<Self, RoutingRuntimeError> {
        if acceptance == PhysicalExecutionAcceptance::NotAccepted
            && commitment == StreamCommitment::FirstByteSent
        {
            return Err(runtime_error(
                RoutingRuntimeErrorCode::InvalidExecutionOutcome,
            ));
        }
        Ok(Self::Failed {
            acceptance,
            commitment,
            failure,
        })
    }
}

/// One final-provider request carrying a purpose-bound short lease.
pub struct ProviderExecutionRequest {
    candidate: CandidateKey,
    account_id: AccountId,
    provider_id: ProviderId,
    provider_model: ProviderModelId,
    usage_confirmation: UsageConfirmationId,
    credential: SecretLease,
}

impl ProviderExecutionRequest {
    /// Returns the selected candidate identity.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateKey {
        &self.candidate
    }

    /// Returns the selected provider account.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the selected provider.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the provider-side model selected by the catalog.
    #[must_use]
    pub const fn provider_model(&self) -> &ProviderModelId {
        &self.provider_model
    }

    /// Returns the immutable identity reserved for later usage confirmation.
    #[must_use]
    pub const fn usage_confirmation_id(&self) -> &UsageConfirmationId {
        &self.usage_confirmation
    }

    /// Borrows the provider HTTP purpose-bound plaintext lease.
    #[must_use]
    pub const fn credential(&self) -> &SecretLease {
        &self.credential
    }

    /// Consumes the request and returns the lease for final HTTP credential injection.
    #[must_use]
    pub fn into_credential(self) -> SecretLease {
        self.credential
    }
}

impl Debug for ProviderExecutionRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderExecutionRequest")
            .field("candidate", &self.candidate)
            .field("account_id", &"<redacted>")
            .field("provider_id", &"<redacted>")
            .field("provider_model", &"<redacted>")
            .field("usage_confirmation", &self.usage_confirmation)
            .field("credential", &self.credential)
            .finish()
    }
}

/// Final provider boundary responsible for consuming one lease exactly once.
pub trait ProviderExecutionPort: Send + Sync {
    /// Executes one physical provider request. Every failure must explicitly
    /// state whether physical execution was accepted; ambiguous transport state
    /// must be classified as accepted so admission is never incorrectly released.
    fn execute<'a>(
        &'a self,
        request: ProviderExecutionRequest,
        context: &'a RequestContext,
    ) -> Pin<Box<dyn Future<Output = ProviderExecutionOutcome> + Send + 'a>>;
}

/// Injected durable and final-execution ports used by the runtime.
#[derive(Clone)]
pub struct RuntimePorts {
    account_projection: Arc<dyn AccountProjectionPort>,
    pool: Arc<dyn CandidateSelectionPort>,
    models: Arc<dyn ModelCatalogPort>,
    credentials: Arc<dyn AccountCredentialReferencePort>,
    vault: Arc<dyn VaultPort>,
    clock: Arc<dyn RuntimeMonotonicClock>,
}

impl RuntimePorts {
    /// Groups the required typed ports without a global service container.
    #[must_use]
    pub const fn new(
        account_projection: Arc<dyn AccountProjectionPort>,
        pool: Arc<dyn CandidateSelectionPort>,
        models: Arc<dyn ModelCatalogPort>,
        credentials: Arc<dyn AccountCredentialReferencePort>,
        vault: Arc<dyn VaultPort>,
        clock: Arc<dyn RuntimeMonotonicClock>,
    ) -> Self {
        Self {
            account_projection,
            pool,
            models,
            credentials,
            vault,
            clock,
        }
    }
}

impl Debug for RuntimePorts {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimePorts(<injected>)")
    }
}

/// Stable identity of one physically accepted provider attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct PhysicalAttemptIdentity {
    usage_confirmation: UsageConfirmationId,
    candidate: CandidateKey,
    provider_id: ProviderId,
    provider_model: ProviderModelId,
}

impl PhysicalAttemptIdentity {
    /// Returns the identity later passed to P8 usage ingestion.
    #[must_use]
    pub const fn usage_confirmation_id(&self) -> &UsageConfirmationId {
        &self.usage_confirmation
    }

    /// Returns the accepted candidate.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateKey {
        &self.candidate
    }

    /// Returns the accepted provider.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the accepted provider-side model.
    #[must_use]
    pub const fn provider_model(&self) -> &ProviderModelId {
        &self.provider_model
    }
}

impl Debug for PhysicalAttemptIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhysicalAttemptIdentity")
            .field("usage_confirmation", &self.usage_confirmation)
            .field("candidate", &self.candidate)
            .field("provider", &"<redacted>")
            .field("provider_model", &"<redacted>")
            .finish()
    }
}

/// Successful provider execution and all accepted attempt identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSuccess {
    final_attempt: PhysicalAttemptIdentity,
    accepted_attempts: Arc<[PhysicalAttemptIdentity]>,
    commitment: StreamCommitment,
}

impl RuntimeSuccess {
    /// Returns the final successful physical attempt.
    #[must_use]
    pub const fn final_attempt(&self) -> &PhysicalAttemptIdentity {
        &self.final_attempt
    }

    /// Returns every physically accepted attempt in execution order.
    #[must_use]
    pub fn accepted_attempts(&self) -> &[PhysicalAttemptIdentity] {
        &self.accepted_attempts
    }

    /// Returns the final client-visible stream commitment.
    #[must_use]
    pub const fn commitment(&self) -> StreamCommitment {
        self.commitment
    }
}

/// Why provider execution ended without a successful attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFailureReason {
    /// The immutable retry policy required execution to stop.
    FailoverStopped,
    /// Caller-supplied attempt requests ended before another safe attempt.
    AttemptsExhausted,
}

/// Final failed provider result retaining accepted usage identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFailure {
    reason: RuntimeFailureReason,
    failure: FailureClass,
    commitment: StreamCommitment,
    accepted_attempts: Arc<[PhysicalAttemptIdentity]>,
}

impl RuntimeFailure {
    /// Returns why no further attempt was performed.
    #[must_use]
    pub const fn reason(&self) -> RuntimeFailureReason {
        self.reason
    }

    /// Returns the final classified provider failure.
    #[must_use]
    pub const fn failure(&self) -> FailureClass {
        self.failure
    }

    /// Returns the final client-visible stream commitment.
    #[must_use]
    pub const fn commitment(&self) -> StreamCommitment {
        self.commitment
    }

    /// Returns every physically accepted attempt in execution order.
    #[must_use]
    pub fn accepted_attempts(&self) -> &[PhysicalAttemptIdentity] {
        &self.accepted_attempts
    }
}

/// Final expected provider disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeOutcome {
    /// One provider attempt completed successfully.
    Succeeded(RuntimeSuccess),
    /// Provider attempts ended according to retry or capacity rules.
    Failed(RuntimeFailure),
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
    /// coordinates, authorizes, leases, and executes bounded physical attempts.
    ///
    /// Each attempt receives a fresh coordination request so candidate switches
    /// never reuse an account-bound budget reservation. Physical acceptance
    /// commits admission even when the provider later fails. Pre-execution
    /// failure releases admission. Retry safety and the first-byte boundary are
    /// enforced by the first route's immutable failover plan. Accepted usage
    /// identities are returned but never persisted by this P5 runtime.
    ///
    /// # Errors
    /// Returns a redacted stable failure for authentication, durable snapshots,
    /// model resolution, routing, credential authorization, leasing, or admission
    /// finalization. An admission-finalization error after physical acceptance
    /// carries the stable usage identity through [`RoutingRuntimeError::usage_confirmation_id`].
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
        let mut state = self.start_state(&loaded, attempts, coordination, signals)?;
        loop {
            match self
                .run_state(state, &loaded, executor, signals, context)
                .await?
            {
                LoopControl::Continue(next) => state = *next,
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
    ) -> Result<ExecutionState, RoutingRuntimeError> {
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
        let route = self.coordinate(request, &loaded.pool, &loaded.models, signals)?;
        Ok(ExecutionState {
            retry_plan: route.retry_plan().clone(),
            current: route.selected_candidate().clone(),
            route,
            attempt,
            ordinal: 1,
            accepted: Vec::with_capacity(MAX_RUNTIME_ATTEMPTS),
            remaining_attempts,
            remaining_coordination,
        })
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
        let Some(attempt) = remainder.remaining_attempts.pop_front() else {
            return Ok(LoopControl::Finished(failed_runtime_outcome(
                RuntimeFailureReason::AttemptsExhausted,
                directive.failure,
                directive.commitment,
                remainder.accepted,
            )));
        };
        let request = remainder
            .remaining_coordination
            .pop_front()
            .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
        let ordinal = remainder
            .ordinal
            .checked_add(1)
            .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
        let route = self.coordinate_target(request, &directive.candidate, loaded, signals)?;
        Ok(LoopControl::Continue(Box::new(ExecutionState {
            route,
            attempt,
            retry_plan: remainder.retry_plan,
            current: directive.candidate,
            ordinal,
            accepted: remainder.accepted,
            remaining_attempts: remainder.remaining_attempts,
            remaining_coordination: remainder.remaining_coordination,
        })))
    }

    fn coordinate(
        &self,
        request: CoordinationRequest,
        pool: &CandidateSnapshot,
        models: &ModelCatalogSnapshot,
        signals: RuntimeSignals<'_>,
    ) -> Result<CoordinatedRoute, RoutingRuntimeError> {
        self.coordinator
            .coordinate(request, signals.snapshots(pool, models))
            .map_err(|_| runtime_error(RoutingRuntimeErrorCode::CoordinationFailed))
    }

    fn coordinate_target(
        &self,
        request: CoordinationRequest,
        target: &CandidateKey,
        loaded: &LoadedState,
        signals: RuntimeSignals<'_>,
    ) -> Result<CoordinatedRoute, RoutingRuntimeError> {
        let candidate = find_candidate(&loaded.pool, target)?;
        let pool = CandidateSnapshot::new(
            SnapshotId::new(loaded.pool.id().get()),
            SnapshotVersion::new(loaded.pool.version().get()),
            vec![candidate.clone()],
        )
        .map_err(|_| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
        let route = self.coordinate(request, &pool, &loaded.models, signals)?;
        if route.selected_candidate() != target {
            return Err(runtime_error(RoutingRuntimeErrorCode::InvariantViolation));
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
        let prepared = self.prepare_route(route, attempt, loaded, context).await?;
        let outcome = executor.execute(prepared.execution, context).await;
        self.finalize_execution(prepared.route, prepared.identity, outcome)
    }

    async fn prepare_route(
        &self,
        route: CoordinatedRoute,
        attempt: &RuntimeAttempt,
        loaded: &LoadedState,
        context: &RequestContext,
    ) -> Result<PreparedRoute, RoutingRuntimeError> {
        match self
            .prepare_execution(&route, attempt, loaded, context)
            .await
        {
            Ok((execution, identity)) => Ok(PreparedRoute {
                route,
                execution,
                identity,
            }),
            Err(error) => release_with_error(route, self.finalization_time(None)?, error),
        }
    }

    fn finalize_execution(
        &self,
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        outcome: ProviderExecutionOutcome,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        match outcome {
            ProviderExecutionOutcome::Accepted { commitment } => {
                self.finalize_success(route, identity, commitment)
            }
            ProviderExecutionOutcome::Failed {
                acceptance,
                commitment,
                failure,
            } => self.finalize_failure(route, identity, acceptance, commitment, failure),
        }
    }

    fn finalize_success(
        &self,
        mut route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        commitment: StreamCommitment,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        let now = self.finalization_time(Some(&identity))?;
        commit_route(&mut route, now, &identity)?;
        Ok(AttemptProgress::Succeeded(identity, commitment))
    }

    fn finalize_failure(
        &self,
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        acceptance: PhysicalExecutionAcceptance,
        commitment: StreamCommitment,
        failure: FailureClass,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        if contradictory_acceptance(acceptance, commitment) {
            return self.finalize_contradiction(route, identity);
        }
        let accepted_identity = match acceptance {
            PhysicalExecutionAcceptance::NotAccepted => None,
            PhysicalExecutionAcceptance::Accepted => Some(&identity),
        };
        let now = self.finalization_time(accepted_identity)?;
        let accepted = finalize_failed_route(route, now, acceptance, identity)?;
        Ok(AttemptProgress::Failed(FailedAttempt {
            failure,
            commitment,
            accepted,
        }))
    }

    fn finalize_contradiction(
        &self,
        mut route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
    ) -> Result<AttemptProgress, RoutingRuntimeError> {
        let now = self.finalization_time(Some(&identity))?;
        commit_route(&mut route, now, &identity)?;
        Err(runtime_error(RoutingRuntimeErrorCode::InvalidExecutionOutcome).with_accepted(identity))
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
        context: &RequestContext,
    ) -> Result<(ProviderExecutionRequest, PhysicalAttemptIdentity), RoutingRuntimeError> {
        let (target, resolved) = self.resolve_credential(route, loaded, context).await?;
        let lease = self.issue_lease(&resolved, context).await?;
        self.revalidate_credential(&resolved, context).await?;
        self.build_execution(route, attempt, loaded, target, lease, context)
    }

    async fn resolve_credential(
        &self,
        route: &CoordinatedRoute,
        loaded: &LoadedState,
        context: &RequestContext,
    ) -> Result<(OwnedTarget, AccountCredentialReference), RoutingRuntimeError> {
        ensure_active(context)?;
        let target = validate_route_target(route, loaded)?;
        let resolve_request = AccountCredentialReferenceRequest::new(
            target.account_id.clone(),
            target.provider_id.clone(),
            target.config_version,
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
        Ok((target, resolved))
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
        let identity = PhysicalAttemptIdentity {
            usage_confirmation: usage_confirmation.clone(),
            candidate: route.selected_candidate().clone(),
            provider_id: target.provider_id.clone(),
            provider_model: route.provider_model().clone(),
        };
        let execution = ProviderExecutionRequest {
            candidate: route.selected_candidate().clone(),
            account_id: target.account_id,
            provider_id: target.provider_id,
            provider_model: route.provider_model().clone(),
            usage_confirmation,
            credential: lease,
        };
        Ok((execution, identity))
    }
}

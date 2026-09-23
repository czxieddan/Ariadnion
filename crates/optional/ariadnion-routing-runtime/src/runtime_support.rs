// crates/optional/ariadnion-routing-runtime/src/runtime_support.rs - Runtime invariant helpers.
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

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_account_circuit::CircuitOutcome;
use ariadnion_account_domain::{AccountConfigVersion, AccountId, ProviderId, SecretPurpose};
use ariadnion_account_import::{
    AccountCredentialReference, AccountCredentialReferenceRequest, AccountProjectionSnapshot,
    ImportGeneration, ImportPortError, ImportPortErrorCode,
};
use ariadnion_account_pool::{CandidateMetadata, CandidateSnapshot};
use ariadnion_account_vault::{SecretLease, VaultError, VaultErrorCode};
use ariadnion_core::{ErrorCode, ModuleId, RequestContext, TenantId};
use ariadnion_model_catalog::ModelCatalogSnapshot;
use ariadnion_rate_limit::MonotonicTime;
use ariadnion_routing_coordinator::{
    AdmissionRefusalScope, CoordinatedRoute, CoordinationRequest, CoordinatorError,
    CoordinatorErrorCode, InitialAdmissionRetryContext, RoutingRetryPlan,
};
use ariadnion_routing_failover::{
    AdmissionRefusal, AttemptOutcome, CandidateKey, FailoverAction, FailureClass, StreamCommitment,
};
use ariadnion_routing_usage::UsageConfirmationId;

use crate::circuit_probe::{CircuitProbeGuard, CircuitProbeKey};
use crate::{
    CircuitProbeError, CircuitProbeErrorCode, PhysicalAttemptIdentity, PhysicalExecutionAcceptance,
    ProviderExecutionRequest, RoutingRuntimeError, RoutingRuntimeErrorCode, RuntimeAttempt,
    RuntimeFailure, RuntimeFailureReason, RuntimeMonotonicClock, RuntimeOutcome, RuntimeSuccess,
};

pub(super) struct LoadedState {
    pub(super) tenant: TenantId,
    pub(super) projection: AccountProjectionSnapshot,
    pub(super) pool: Arc<CandidateSnapshot>,
    pub(super) models: Arc<ModelCatalogSnapshot>,
}

pub(super) struct ExecutionState {
    pub(super) route: CoordinatedRoute,
    pub(super) attempt: RuntimeAttempt,
    pub(super) retry_plan: RoutingRetryPlan,
    pub(super) current: CandidateKey,
    pub(super) ordinal: u8,
    pub(super) accepted: Vec<PhysicalAttemptIdentity>,
    pub(super) remaining_attempts: VecDeque<RuntimeAttempt>,
    pub(super) remaining_coordination: VecDeque<CoordinationRequest>,
}

pub(super) struct ExecutionRemainder {
    pub(super) retry_plan: RoutingRetryPlan,
    pub(super) current: CandidateKey,
    pub(super) ordinal: u8,
    pub(super) accepted: Vec<PhysicalAttemptIdentity>,
    pub(super) remaining_attempts: VecDeque<RuntimeAttempt>,
    pub(super) remaining_coordination: VecDeque<CoordinationRequest>,
}

pub(super) enum LoopControl {
    Continue(Box<ExecutionState>),
    Finished(RuntimeOutcome),
}

pub(super) struct RetryDirective {
    pub(super) candidate: CandidateKey,
    pub(super) failure: FailureClass,
    pub(super) commitment: StreamCommitment,
}

pub(super) enum TargetCoordinationFailure {
    Admission {
        refusal: AdmissionRefusal,
        initial_retry_context: Option<InitialAdmissionRetryContext>,
    },
    Runtime(RoutingRuntimeError),
}

pub(super) struct OwnedTarget {
    pub(super) account_id: AccountId,
    pub(super) provider_id: ProviderId,
    pub(super) config_version: AccountConfigVersion,
    pub(super) import_generation: ImportGeneration,
}

pub(super) enum AttemptProgress {
    Succeeded(PhysicalAttemptIdentity, StreamCommitment),
    Failed(FailedAttempt),
}

pub(super) struct FailedAttempt {
    pub(super) failure: FailureClass,
    pub(super) commitment: StreamCommitment,
    pub(super) accepted: Option<PhysicalAttemptIdentity>,
}

pub(super) struct PreparedRoute {
    pub(super) route: CoordinatedRoute,
    pub(super) execution: ProviderExecutionRequest,
    pub(super) identity: PhysicalAttemptIdentity,
    pub(super) probe: Option<CircuitProbeGuard>,
}

pub(super) struct FinalizationState {
    pub(super) probe: Option<CircuitProbeGuard>,
    pub(super) dispatch_time: MonotonicTime,
}

pub(super) struct RetrySlot {
    pub(super) attempt: RuntimeAttempt,
    pub(super) request: CoordinationRequest,
}

pub(super) fn take_retry_slot(
    remainder: &mut ExecutionRemainder,
) -> Result<Option<RetrySlot>, RoutingRuntimeError> {
    let Some(attempt) = remainder.remaining_attempts.pop_front() else {
        return Ok(None);
    };
    let request = remainder
        .remaining_coordination
        .pop_front()
        .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
    remainder.ordinal = remainder
        .ordinal
        .checked_add(1)
        .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
    Ok(Some(RetrySlot { attempt, request }))
}

pub(super) struct PendingExecutionGuard {
    route: Option<CoordinatedRoute>,
    identity: Option<PhysicalAttemptIdentity>,
    probe: Option<CircuitProbeGuard>,
    clock: Arc<dyn RuntimeMonotonicClock>,
    dispatch_time: MonotonicTime,
}

impl PendingExecutionGuard {
    pub(super) fn new(
        route: CoordinatedRoute,
        identity: PhysicalAttemptIdentity,
        mut probe: Option<CircuitProbeGuard>,
        clock: Arc<dyn RuntimeMonotonicClock>,
        dispatch_time: MonotonicTime,
    ) -> Self {
        if let Some(probe) = &mut probe {
            probe.arm_retryable_drop();
        }
        Self {
            route: Some(route),
            identity: Some(identity),
            probe,
            clock,
            dispatch_time,
        }
    }

    pub(super) fn disarm(
        mut self,
    ) -> Result<
        (
            CoordinatedRoute,
            PhysicalAttemptIdentity,
            Option<CircuitProbeGuard>,
        ),
        RoutingRuntimeError,
    > {
        let route = self
            .route
            .take()
            .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
        let identity = self
            .identity
            .take()
            .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
        Ok((route, identity, self.probe.take()))
    }
}

impl Drop for PendingExecutionGuard {
    fn drop(&mut self) {
        let Some(route) = self.route.take() else {
            return;
        };
        let now = match self.clock.now() {
            Ok(now) => now,
            Err(_) => self.dispatch_time,
        };
        let _ = route.into_admission_lease().commit_dispatch_unknown(now);
    }
}

pub(super) fn authenticated_tenant(
    context: &RequestContext,
) -> Result<TenantId, RoutingRuntimeError> {
    ensure_active(context)?;
    context
        .principal()
        .map(|principal| principal.tenant_id().clone())
        .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::Unauthenticated))
}

pub(super) fn ensure_active(context: &RequestContext) -> Result<(), RoutingRuntimeError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => runtime_error(RoutingRuntimeErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => runtime_error(RoutingRuntimeErrorCode::DeadlineExceeded),
        _ => runtime_error(RoutingRuntimeErrorCode::InvariantViolation),
    })
}

pub(super) fn validate_projection(
    projection: &AccountProjectionSnapshot,
    tenant: &TenantId,
    generation: ImportGeneration,
) -> Result<(), RoutingRuntimeError> {
    if projection.generation() != generation {
        return Err(runtime_error(
            RoutingRuntimeErrorCode::ProjectionUnavailable,
        ));
    }
    if projection
        .accounts()
        .iter()
        .any(|account| account.tenant_id() != tenant)
    {
        return Err(runtime_error(RoutingRuntimeErrorCode::TenantMismatch));
    }
    Ok(())
}

pub(super) fn pool_generation(
    pool: &CandidateSnapshot,
) -> Result<ImportGeneration, RoutingRuntimeError> {
    if pool.id().get() != pool.version().get() {
        return Err(runtime_error(RoutingRuntimeErrorCode::PoolUnavailable));
    }
    Ok(ImportGeneration::new(pool.version().get()))
}

pub(super) fn find_candidate<'a>(
    pool: &'a CandidateSnapshot,
    key: &CandidateKey,
) -> Result<&'a CandidateMetadata, RoutingRuntimeError> {
    pool.candidates()
        .iter()
        .find(|candidate| candidate.id().as_str() == key.as_str())
        .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))
}

pub(super) fn validate_route_target(
    route: &CoordinatedRoute,
    loaded: &LoadedState,
) -> Result<OwnedTarget, RoutingRuntimeError> {
    let candidate = find_candidate(&loaded.pool, route.selected_candidate())?;
    validate_candidate_binding(candidate, route, &loaded.tenant)?;
    let (config_version, import_generation) =
        validate_projection_binding(candidate, &loaded.projection, &loaded.tenant)?;
    validate_provider_model(candidate, route)?;
    Ok(OwnedTarget {
        account_id: candidate.account_id().clone(),
        provider_id: candidate.provider_id().clone(),
        config_version,
        import_generation,
    })
}

fn validate_candidate_binding(
    candidate: &CandidateMetadata,
    route: &CoordinatedRoute,
    tenant: &TenantId,
) -> Result<(), RoutingRuntimeError> {
    if candidate.account_id() != route.selected_account() || candidate.tenant_id() != Some(tenant) {
        return Err(runtime_error(RoutingRuntimeErrorCode::TenantMismatch));
    }
    Ok(())
}

fn validate_projection_binding(
    candidate: &CandidateMetadata,
    projection: &AccountProjectionSnapshot,
    tenant: &TenantId,
) -> Result<(AccountConfigVersion, ImportGeneration), RoutingRuntimeError> {
    let row = projection
        .accounts()
        .iter()
        .find(|row| row.account_id() == candidate.account_id())
        .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
    if row.provider_id() != candidate.provider_id() || row.tenant_id() != tenant {
        return Err(runtime_error(RoutingRuntimeErrorCode::InvariantViolation));
    }
    let config_version = AccountConfigVersion::new(row.config_version())
        .map_err(|_| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
    Ok((config_version, row.import_generation()))
}

pub(super) fn circuit_probe_key(target: &OwnedTarget, loaded: &LoadedState) -> CircuitProbeKey {
    CircuitProbeKey::new(
        loaded.tenant.clone(),
        target.account_id.clone(),
        target.config_version,
        target.import_generation,
    )
}

fn validate_provider_model(
    candidate: &CandidateMetadata,
    route: &CoordinatedRoute,
) -> Result<(), RoutingRuntimeError> {
    let model = candidate
        .model()
        .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
    if model.as_str() != route.provider_model().as_str() {
        return Err(runtime_error(RoutingRuntimeErrorCode::InvariantViolation));
    }
    Ok(())
}

pub(super) fn map_projection_error(error: ImportPortError) -> RoutingRuntimeError {
    match error.code() {
        ImportPortErrorCode::Unauthenticated => {
            runtime_error(RoutingRuntimeErrorCode::Unauthenticated)
        }
        ImportPortErrorCode::Cancelled => runtime_error(RoutingRuntimeErrorCode::Cancelled),
        ImportPortErrorCode::DeadlineExceeded => {
            runtime_error(RoutingRuntimeErrorCode::DeadlineExceeded)
        }
        _ => runtime_error(RoutingRuntimeErrorCode::ProjectionUnavailable),
    }
}

pub(super) fn runtime_error(code: RoutingRuntimeErrorCode) -> RoutingRuntimeError {
    RoutingRuntimeError::from_code(code)
}

pub(super) const fn contradictory_acceptance(
    acceptance: PhysicalExecutionAcceptance,
    commitment: StreamCommitment,
) -> bool {
    matches!(acceptance, PhysicalExecutionAcceptance::NotAccepted)
        && matches!(commitment, StreamCommitment::FirstByteSent)
}

pub(super) fn map_credential_error(error: ImportPortError) -> RoutingRuntimeError {
    match error.code() {
        ImportPortErrorCode::Unauthenticated => {
            runtime_error(RoutingRuntimeErrorCode::Unauthenticated)
        }
        ImportPortErrorCode::Cancelled => runtime_error(RoutingRuntimeErrorCode::Cancelled),
        ImportPortErrorCode::DeadlineExceeded => {
            runtime_error(RoutingRuntimeErrorCode::DeadlineExceeded)
        }
        _ => runtime_error(RoutingRuntimeErrorCode::CredentialUnavailable),
    }
}

pub(super) fn map_vault_error(error: VaultError) -> RoutingRuntimeError {
    match error.code() {
        VaultErrorCode::Cancelled => runtime_error(RoutingRuntimeErrorCode::Cancelled),
        VaultErrorCode::DeadlineExceeded => {
            runtime_error(RoutingRuntimeErrorCode::DeadlineExceeded)
        }
        _ => runtime_error(RoutingRuntimeErrorCode::VaultUnavailable),
    }
}

pub(super) fn map_circuit_probe_acquire_error(error: CircuitProbeError) -> RoutingRuntimeError {
    match error.code() {
        CircuitProbeErrorCode::Cancelled => runtime_error(RoutingRuntimeErrorCode::Cancelled),
        CircuitProbeErrorCode::DeadlineExceeded => {
            runtime_error(RoutingRuntimeErrorCode::DeadlineExceeded)
        }
        CircuitProbeErrorCode::Unavailable | CircuitProbeErrorCode::Rejected => {
            runtime_error(RoutingRuntimeErrorCode::CircuitProbeUnavailable)
        }
    }
}

pub(super) fn validate_credential(
    request: &AccountCredentialReferenceRequest,
    resolved: &AccountCredentialReference,
    tenant: &TenantId,
) -> Result<(), RoutingRuntimeError> {
    validate_credential_identity(request, resolved, tenant)?;
    validate_credential_scope(request, resolved)
}

fn validate_credential_identity(
    request: &AccountCredentialReferenceRequest,
    resolved: &AccountCredentialReference,
    tenant: &TenantId,
) -> Result<(), RoutingRuntimeError> {
    let mismatch = resolved.tenant_id() != tenant
        || resolved.account_id() != request.account_id()
        || resolved.provider_id() != request.provider_id()
        || resolved.config_version() != request.config_version();
    if mismatch {
        return Err(runtime_error(RoutingRuntimeErrorCode::CredentialMismatch));
    }
    Ok(())
}

fn validate_credential_scope(
    request: &AccountCredentialReferenceRequest,
    resolved: &AccountCredentialReference,
) -> Result<(), RoutingRuntimeError> {
    let mismatch = resolved.purpose() != request.purpose()
        || resolved.import_generation() != request.expected_generation()
        || resolved.secret_ref().purpose() != request.purpose();
    if mismatch {
        return Err(runtime_error(RoutingRuntimeErrorCode::CredentialMismatch));
    }
    Ok(())
}

pub(super) fn validate_revalidated_credential(
    expected: &AccountCredentialReference,
    current: &AccountCredentialReference,
) -> Result<(), RoutingRuntimeError> {
    if current != expected {
        return Err(runtime_error(RoutingRuntimeErrorCode::CredentialMismatch));
    }
    Ok(())
}

pub(super) fn validate_lease(
    lease: &SecretLease,
    resolved: &AccountCredentialReference,
    module: &ModuleId,
    purpose: &SecretPurpose,
) -> Result<(), RoutingRuntimeError> {
    if lease.reference() != resolved.secret_ref()
        || lease.module() != module
        || lease.reference().purpose() != purpose
        || !lease.is_valid_at(SystemTime::now())
    {
        return Err(runtime_error(RoutingRuntimeErrorCode::InvalidLease));
    }
    Ok(())
}

pub(super) fn validate_usage_binding(
    identity: &UsageConfirmationId,
    tenant: &TenantId,
    context: &RequestContext,
) -> Result<(), RoutingRuntimeError> {
    if identity.tenant() != tenant || identity.request() != context.request_id() {
        return Err(runtime_error(RoutingRuntimeErrorCode::InvariantViolation));
    }
    Ok(())
}

pub(super) fn release_route(
    route: CoordinatedRoute,
    now: MonotonicTime,
) -> Result<(), RoutingRuntimeError> {
    route
        .into_admission_lease()
        .release(now)
        .map_err(|_| runtime_error(RoutingRuntimeErrorCode::AdmissionFinalizeFailed))
}

pub(super) fn finalize_accepted_route(
    route: CoordinatedRoute,
    now: Option<MonotonicTime>,
    identity: &PhysicalAttemptIdentity,
) -> Result<(), RoutingRuntimeError> {
    route
        .into_admission_lease()
        .finalize_accepted(now)
        .map_err(|_| {
            runtime_error(RoutingRuntimeErrorCode::AdmissionFinalizeFailed)
                .with_accepted(identity.clone())
        })
}

pub(super) fn combine_finalizations<T>(
    admission: Result<T, RoutingRuntimeError>,
    probe: Result<(), RoutingRuntimeError>,
    accepted: Option<&PhysicalAttemptIdentity>,
) -> Result<T, RoutingRuntimeError> {
    let value = admission?;
    match probe {
        Ok(()) => Ok(value),
        Err(error) => Err(match accepted {
            Some(identity) => error.with_accepted(identity.clone()),
            None => error,
        }),
    }
}

pub(super) const fn circuit_failure_outcome(failure: FailureClass) -> CircuitOutcome {
    match failure {
        FailureClass::Authentication => CircuitOutcome::TerminalFailure,
        FailureClass::Transport | FailureClass::TransientServer | FailureClass::RateLimited => {
            CircuitOutcome::RetryableFailure
        }
        FailureClass::InvalidRequest | FailureClass::Policy => CircuitOutcome::Neutral,
    }
}

pub(super) const fn circuit_interruption_outcome(
    acceptance: PhysicalExecutionAcceptance,
) -> CircuitOutcome {
    match acceptance {
        PhysicalExecutionAcceptance::NotAccepted => CircuitOutcome::Neutral,
        PhysicalExecutionAcceptance::Accepted => CircuitOutcome::RetryableFailure,
    }
}

pub(super) fn next_candidate(
    action: &FailoverAction,
    current: &CandidateKey,
) -> Option<CandidateKey> {
    match action {
        FailoverAction::RetrySame => Some(current.clone()),
        FailoverAction::SwitchCandidate(candidate) => Some(candidate.clone()),
        FailoverAction::Stop => None,
    }
}

pub(super) fn map_target_coordination_error(error: CoordinatorError) -> TargetCoordinationFailure {
    let refusal = match error.code() {
        CoordinatorErrorCode::ConcurrencyLimited | CoordinatorErrorCode::RateLimited => {
            Some(refusal_from_scope(error.admission_scope()))
        }
        CoordinatorErrorCode::BudgetRejected => Some(refusal_from_scope(error.admission_scope())),
        CoordinatorErrorCode::AdmissionUnavailable | CoordinatorErrorCode::PolicyUnavailable => {
            Some(AdmissionRefusal::RequestRejected)
        }
        _ => None,
    };
    match refusal {
        Some(refusal) => TargetCoordinationFailure::Admission {
            refusal,
            initial_retry_context: error.initial_admission_retry_context().cloned(),
        },
        None => TargetCoordinationFailure::Runtime(runtime_error(
            RoutingRuntimeErrorCode::CoordinationFailed,
        )),
    }
}

fn refusal_from_scope(scope: Option<AdmissionRefusalScope>) -> AdmissionRefusal {
    match scope {
        Some(AdmissionRefusalScope::Account) => AdmissionRefusal::CandidateUnavailable,
        _ => AdmissionRefusal::RequestRejected,
    }
}

pub(super) fn next_candidate_after_admission(
    retry_plan: &RoutingRetryPlan,
    candidate: &CandidateKey,
    ordinal: u8,
    commitment: StreamCommitment,
    refusal: AdmissionRefusal,
) -> Result<Option<CandidateKey>, RoutingRuntimeError> {
    let decision = retry_plan
        .decide_outcome(
            candidate,
            ordinal,
            commitment,
            AttemptOutcome::AdmissionRejected(refusal),
        )
        .map_err(|_| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
    Ok(match decision.action() {
        FailoverAction::SwitchCandidate(next) => Some(next.clone()),
        FailoverAction::RetrySame | FailoverAction::Stop => None,
    })
}

pub(super) fn failed_runtime_outcome(
    reason: RuntimeFailureReason,
    failure: FailureClass,
    commitment: StreamCommitment,
    accepted: Vec<PhysicalAttemptIdentity>,
) -> RuntimeOutcome {
    RuntimeOutcome::Failed(RuntimeFailure {
        reason,
        failure,
        commitment,
        accepted_attempts: Arc::from(accepted.into_boxed_slice()),
    })
}

pub(super) fn success_outcome(
    identity: PhysicalAttemptIdentity,
    commitment: StreamCommitment,
    mut accepted: Vec<PhysicalAttemptIdentity>,
) -> RuntimeOutcome {
    accepted.push(identity.clone());
    RuntimeOutcome::Succeeded(RuntimeSuccess {
        final_attempt: identity,
        accepted_attempts: Arc::from(accepted.into_boxed_slice()),
        commitment,
    })
}

pub(super) fn retain_accepted(
    accepted: &mut Vec<PhysicalAttemptIdentity>,
    identity: Option<PhysicalAttemptIdentity>,
) {
    if let Some(identity) = identity {
        accepted.push(identity);
    }
}

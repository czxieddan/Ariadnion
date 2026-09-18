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

use ariadnion_account_domain::{AccountId, ProviderId, SecretPurpose};
use ariadnion_account_import::{
    AccountCredentialReference, AccountCredentialReferenceRequest, AccountProjectionSnapshot,
    ImportGeneration, ImportPortError, ImportPortErrorCode,
};
use ariadnion_account_pool::{CandidateMetadata, CandidateSnapshot};
use ariadnion_account_vault::{SecretLease, VaultError, VaultErrorCode};
use ariadnion_core::{ErrorCode, ModuleId, RequestContext, TenantId};
use ariadnion_model_catalog::ModelCatalogSnapshot;
use ariadnion_rate_limit::MonotonicTime;
use ariadnion_routing_coordinator::{CoordinatedRoute, CoordinationRequest, RoutingRetryPlan};
use ariadnion_routing_failover::{CandidateKey, FailoverAction, FailureClass, StreamCommitment};
use ariadnion_routing_usage::UsageConfirmationId;

use crate::{
    PhysicalAttemptIdentity, PhysicalExecutionAcceptance, ProviderExecutionRequest,
    RoutingRuntimeError, RoutingRuntimeErrorCode, RuntimeAttempt, RuntimeFailure,
    RuntimeFailureReason, RuntimeOutcome, RuntimeSuccess,
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

pub(super) struct OwnedTarget {
    pub(super) account_id: AccountId,
    pub(super) provider_id: ProviderId,
    pub(super) config_version: u64,
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
    let config_version =
        validate_projection_binding(candidate, &loaded.projection, &loaded.tenant)?;
    validate_provider_model(candidate, route)?;
    Ok(OwnedTarget {
        account_id: candidate.account_id().clone(),
        provider_id: candidate.provider_id().clone(),
        config_version,
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
) -> Result<u64, RoutingRuntimeError> {
    let row = projection
        .accounts()
        .iter()
        .find(|row| row.account_id() == candidate.account_id())
        .ok_or_else(|| runtime_error(RoutingRuntimeErrorCode::InvariantViolation))?;
    if row.provider_id() != candidate.provider_id() || row.tenant_id() != tenant {
        return Err(runtime_error(RoutingRuntimeErrorCode::InvariantViolation));
    }
    Ok(row.config_version())
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

pub(super) fn release_with_error<T>(
    route: CoordinatedRoute,
    now: MonotonicTime,
    original: RoutingRuntimeError,
) -> Result<T, RoutingRuntimeError> {
    route
        .into_admission_lease()
        .release(now)
        .map_err(|_| runtime_error(RoutingRuntimeErrorCode::AdmissionFinalizeFailed))?;
    Err(original)
}

pub(super) fn commit_route(
    route: &mut CoordinatedRoute,
    now: MonotonicTime,
    identity: &PhysicalAttemptIdentity,
) -> Result<(), RoutingRuntimeError> {
    route.admission_lease_mut().commit(now).map_err(|_| {
        runtime_error(RoutingRuntimeErrorCode::AdmissionFinalizeFailed)
            .with_accepted(identity.clone())
    })
}

pub(super) fn finalize_failed_route(
    mut route: CoordinatedRoute,
    now: MonotonicTime,
    acceptance: PhysicalExecutionAcceptance,
    identity: PhysicalAttemptIdentity,
) -> Result<Option<PhysicalAttemptIdentity>, RoutingRuntimeError> {
    match acceptance {
        PhysicalExecutionAcceptance::NotAccepted => {
            route
                .into_admission_lease()
                .release(now)
                .map_err(|_| runtime_error(RoutingRuntimeErrorCode::AdmissionFinalizeFailed))?;
            Ok(None)
        }
        PhysicalExecutionAcceptance::Accepted => {
            commit_route(&mut route, now, &identity)?;
            Ok(Some(identity))
        }
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

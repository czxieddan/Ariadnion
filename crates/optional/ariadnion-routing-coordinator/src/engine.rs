// crates/optional/ariadnion-routing-coordinator/src/engine.rs - Routing pipeline for Ariadnion.
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
//! Deterministic cross-domain filtering, selection, and coupled admission.

use std::collections::{BTreeMap, BTreeSet};

use ariadnion_account_affinity::AffinitySnapshot;
use ariadnion_account_budget::{
    BudgetContext, CurrencyCode as BudgetCurrency, Money, ReservationRequest,
};
use ariadnion_account_circuit::{CircuitSnapshot, CircuitState};
use ariadnion_account_domain::{AccountId, ProviderId};
use ariadnion_account_health::{HealthSnapshot, HealthState};
use ariadnion_account_pool::{Availability as PoolAvailability, CandidateMetadata};
use ariadnion_account_quota::{QuotaSnapshotSet, QuotaSubject, UnixTimeSeconds as QuotaTime};
use ariadnion_account_schedule::UtcSeconds as ScheduleTime;
use ariadnion_core::CapabilityId;
use ariadnion_model_catalog::{CatalogEntry, ModelCatalogSnapshot};
use ariadnion_model_domain::{ModelCapability, ProviderId as ModelProviderId, ProviderModelId};
use ariadnion_model_pricing::{PriceQuote, PricingCatalog};
use ariadnion_rate_limit::{AdmissionRequest, LimitKey, ModelLimitId, TenantLimitId};
use ariadnion_routing_admission::{
    RoutingAdmissionCoordinator, RoutingAdmissionErrorCode, RoutingAdmissionRequest,
};
use ariadnion_routing_cost::{
    CandidateCostInput, CostCandidateId, CostEstimate, CostExclusionReason, CostUnits,
};
use ariadnion_routing_failover::{CandidateKey, DeterministicFailoverPlanner, FailoverPlan};
use ariadnion_routing_policy::{
    Availability, Candidate, CandidateId, ExclusionReason as PolicyExclusionReason, Load,
    PreparedCandidateSet, Priority, Weight, WeightedLeastLoadPolicy,
};

use crate::{
    CandidateExclusion, CandidateExclusionReason, CoordinatedRoute, CoordinatedRouteParts,
    CoordinationRequest, CoordinationSnapshots, CoordinatorError, CoordinatorErrorCode,
    DecisionExplanation, MAX_CANDIDATES, MissingSignalPolicy, OptionalSnapshot, ProxyAvailability,
    ProxyRoutingProfile, RoutingRetryPlan, SelectionBasis, SignalKind, bound_exclusions,
};

struct CandidateState<'a> {
    source: &'a CandidateMetadata,
    key: CandidateKey,
    provider_model: Option<ProviderModelId>,
    quote: Option<PriceQuote>,
    exclusion: Option<CandidateExclusionReason>,
}

struct RouteSelection<'a> {
    states: Vec<CandidateState<'a>>,
    degradations: BTreeSet<SignalKind>,
    selected_index: usize,
    basis: SelectionBasis,
    exclusions: Vec<CandidateExclusion>,
    exclusions_truncated: bool,
}

impl CandidateState<'_> {
    const fn eligible(&self) -> bool {
        self.exclusion.is_none()
    }

    fn exclude(&mut self, reason: CandidateExclusionReason) {
        if self.exclusion.is_none() {
            self.exclusion = Some(reason);
        }
    }
}

pub(crate) fn coordinate(
    admission: &RoutingAdmissionCoordinator,
    request: CoordinationRequest,
    snapshots: CoordinationSnapshots<'_>,
) -> Result<CoordinatedRoute, CoordinatorError> {
    let selection = prepare_selection(&request, snapshots)?;
    let RouteSelection {
        states,
        degradations,
        selected_index,
        basis,
        exclusions,
        exclusions_truncated,
    } = selection;
    let selected = states
        .get(selected_index)
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let retry_plan = build_retry_plan(&request, &states, selected_index)?;
    let admission_lease = admit(admission, &request, selected, &exclusions)?;
    let provider_model = selected
        .provider_model
        .clone()
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let explanation = DecisionExplanation::new(
        basis,
        degradations.into_iter().collect(),
        exclusions,
        exclusions_truncated,
    );
    Ok(CoordinatedRoute::new(CoordinatedRouteParts {
        selected_candidate: selected.key.clone(),
        selected_account: selected.source.account_id().clone(),
        provider_model,
        explanation,
        retry_plan,
        tenant_id: request.context().tenant_id().clone(),
        request_id: request.context().request_id().clone(),
        admission_lease,
    }))
}

fn prepare_selection<'a>(
    request: &CoordinationRequest,
    snapshots: CoordinationSnapshots<'a>,
) -> Result<RouteSelection<'a>, CoordinatorError> {
    validate_model(request, snapshots.models())?;
    let (mut states, mut degradations) = prepare_state(request, snapshots)?;
    apply_pricing(request, snapshots.pricing(), &mut states, &mut degradations)?;
    let (selected_index, basis, policy_exclusions) =
        select_candidate(request, snapshots.affinity(), &states, &mut degradations)?;
    let (exclusions, exclusions_truncated) = collect_exclusions(&states, policy_exclusions)?;
    Ok(RouteSelection {
        states,
        degradations,
        selected_index,
        basis,
        exclusions,
        exclusions_truncated,
    })
}

fn prepare_state<'a>(
    request: &CoordinationRequest,
    snapshots: CoordinationSnapshots<'a>,
) -> Result<(Vec<CandidateState<'a>>, BTreeSet<SignalKind>), CoordinatorError> {
    let mut states =
        prepare_candidates(request, snapshots.pool().candidates(), snapshots.models())?;
    let mut degradations = BTreeSet::new();
    apply_eligibility(request, snapshots, &mut states, &mut degradations)?;
    Ok((states, degradations))
}

fn validate_model<'a>(
    request: &CoordinationRequest,
    models: &'a ModelCatalogSnapshot,
) -> Result<&'a CatalogEntry, CoordinatorError> {
    let model = models
        .resolve_internal(request.context().model().as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::ModelNotFound))?;
    if !model
        .visibility()
        .is_visible_to(request.context().tenant_id())
    {
        return Err(CoordinatorError::new(CoordinatorErrorCode::ModelNotFound));
    }
    for capability in request.context().required_capabilities() {
        let mapped = map_capability(capability)?;
        if !model.descriptor().capabilities().contains(mapped) {
            return Err(CoordinatorError::new(
                CoordinatorErrorCode::CapabilityMismatch,
            ));
        }
    }
    Ok(model)
}

fn map_capability(capability: &CapabilityId) -> Result<ModelCapability, CoordinatorError> {
    let value = capability.as_str();
    if let Some(mapped) = map_text_capability(value) {
        return Ok(mapped);
    }
    if let Some(mapped) = map_media_capability(value) {
        return Ok(mapped);
    }
    map_capability_extended(value)
}

fn map_text_capability(value: &str) -> Option<ModelCapability> {
    match value {
        "model.text-generation" => Some(ModelCapability::TextGeneration),
        "model.text-streaming" => Some(ModelCapability::TextStreaming),
        "model.tool-calls" => Some(ModelCapability::ToolCalls),
        "model.structured-output" => Some(ModelCapability::StructuredOutput),
        _ => None,
    }
}

fn map_media_capability(value: &str) -> Option<ModelCapability> {
    match value {
        "model.vision-input" => Some(ModelCapability::VisionInput),
        "model.audio-input" => Some(ModelCapability::AudioInput),
        "model.audio-output" => Some(ModelCapability::AudioOutput),
        "model.audio-streaming" => Some(ModelCapability::AudioStreaming),
        "model.embeddings" => Some(ModelCapability::Embeddings),
        "model.image-generation" => Some(ModelCapability::ImageGeneration),
        _ => None,
    }
}

fn map_capability_extended(value: &str) -> Result<ModelCapability, CoordinatorError> {
    let mapped = match value {
        "model.files" => ModelCapability::Files,
        "model.realtime" => ModelCapability::Realtime,
        "model.batch" => ModelCapability::Batch,
        "model.rerank" => ModelCapability::Rerank,
        "model.moderation" => ModelCapability::Moderation,
        _ => {
            return Err(CoordinatorError::new(
                CoordinatorErrorCode::CapabilityMismatch,
            ));
        }
    };
    Ok(mapped)
}

fn prepare_candidates<'a>(
    request: &CoordinationRequest,
    candidates: &'a [CandidateMetadata],
    models: &ModelCatalogSnapshot,
) -> Result<Vec<CandidateState<'a>>, CoordinatorError> {
    if candidates.is_empty() || candidates.len() > MAX_CANDIDATES {
        return Err(CoordinatorError::new(CoordinatorErrorCode::InvalidArgument));
    }
    let mut states = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        ensure_tenant(request, candidate)?;
        let key = CandidateKey::parse(candidate.id().as_str())
            .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
        let provider_model = resolve_provider_model(request, candidate, models);
        let exclusion = initial_exclusion(candidate, provider_model.as_ref());
        states.push(CandidateState {
            source: candidate,
            key,
            provider_model,
            quote: None,
            exclusion,
        });
    }
    Ok(states)
}

fn ensure_tenant(
    request: &CoordinationRequest,
    candidate: &CandidateMetadata,
) -> Result<(), CoordinatorError> {
    if candidate.tenant_id() != Some(request.context().tenant_id()) {
        return Err(CoordinatorError::new(CoordinatorErrorCode::TenantMismatch));
    }
    Ok(())
}

fn resolve_provider_model(
    request: &CoordinationRequest,
    candidate: &CandidateMetadata,
    models: &ModelCatalogSnapshot,
) -> Option<ProviderModelId> {
    let provider = ModelProviderId::parse(candidate.provider_id().as_str()).ok()?;
    let target = models
        .resolve_provider_target(request.context().model().as_str(), &provider)
        .ok()?;
    let configured = candidate.model()?;
    (target.provider_model().as_str() == configured.as_str())
        .then(|| target.provider_model().clone())
}

fn initial_exclusion(
    candidate: &CandidateMetadata,
    provider_model: Option<&ProviderModelId>,
) -> Option<CandidateExclusionReason> {
    if candidate.availability() != PoolAvailability::Available {
        return Some(CandidateExclusionReason::PoolUnavailable);
    }
    provider_model
        .is_none()
        .then_some(CandidateExclusionReason::ModelMappingMissing)
}

fn apply_eligibility(
    request: &CoordinationRequest,
    snapshots: CoordinationSnapshots<'_>,
    states: &mut [CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) -> Result<(), CoordinatorError> {
    let eligibility = snapshots.eligibility();
    apply_health(eligibility.health(), states, degradations)?;
    apply_circuit(eligibility.circuit(), states, degradations)?;
    apply_quota(
        eligibility.quota(),
        request.admission().times().budget_now().get(),
        request.pricing().quantity().get(),
        states,
        degradations,
    );
    apply_schedule(
        eligibility.schedule(),
        request.admission().times().budget_now().get(),
        states,
        degradations,
    )?;
    apply_proxy(
        eligibility.proxy(),
        request
            .destination_region()
            .map(crate::DestinationRegion::as_str),
        states,
        degradations,
    )?;
    Ok(())
}

fn apply_health(
    snapshot: OptionalSnapshot<'_, [HealthSnapshot]>,
    states: &mut [CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) -> Result<(), CoordinatorError> {
    let Some(values) = snapshot.value() else {
        apply_missing_snapshot(
            snapshot.missing_policy(),
            SignalKind::Health,
            states,
            degradations,
        );
        return Ok(());
    };
    let index = unique_account_index(values, HealthSnapshot::account_id)?;
    for state in states.iter_mut().filter(|state| state.eligible()) {
        match index.get(state.source.account_id()).copied() {
            Some(value) => apply_health_state(
                state,
                value.state(),
                snapshot.missing_policy(),
                degradations,
            ),
            None => apply_missing_candidate(
                snapshot.missing_policy(),
                SignalKind::Health,
                state,
                degradations,
            ),
        }
    }
    Ok(())
}

fn apply_health_state(
    state: &mut CandidateState<'_>,
    health: HealthState,
    policy: MissingSignalPolicy,
    degradations: &mut BTreeSet<SignalKind>,
) {
    match health {
        HealthState::Healthy => {}
        HealthState::Degraded => {
            degradations.insert(SignalKind::Health);
        }
        HealthState::Unknown => {
            apply_missing_candidate(policy, SignalKind::Health, state, degradations);
        }
        HealthState::Unhealthy => state.exclude(CandidateExclusionReason::Unhealthy),
    }
}

fn apply_circuit(
    snapshot: OptionalSnapshot<'_, [CircuitSnapshot]>,
    states: &mut [CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) -> Result<(), CoordinatorError> {
    let Some(values) = snapshot.value() else {
        apply_missing_snapshot(
            snapshot.missing_policy(),
            SignalKind::Circuit,
            states,
            degradations,
        );
        return Ok(());
    };
    let index = unique_account_index(values, CircuitSnapshot::account_id)?;
    for state in states.iter_mut().filter(|state| state.eligible()) {
        match index.get(state.source.account_id()).copied() {
            Some(value) => apply_circuit_state(state, value.state()),
            None => apply_missing_candidate(
                snapshot.missing_policy(),
                SignalKind::Circuit,
                state,
                degradations,
            ),
        }
    }
    Ok(())
}

fn apply_circuit_state(state: &mut CandidateState<'_>, circuit: CircuitState) {
    match circuit {
        CircuitState::Closed => {}
        CircuitState::Open | CircuitState::Terminal => {
            state.exclude(CandidateExclusionReason::CircuitOpen);
        }
        CircuitState::HalfOpen => state.exclude(CandidateExclusionReason::CircuitHalfOpen),
    }
}

fn unique_account_index<T>(
    values: &[T],
    account: impl Fn(&T) -> &AccountId,
) -> Result<BTreeMap<&AccountId, &T>, CoordinatorError> {
    let mut index = BTreeMap::new();
    for value in values {
        if index.insert(account(value), value).is_some() {
            return Err(CoordinatorError::new(
                CoordinatorErrorCode::StateUnavailable,
            ));
        }
    }
    Ok(index)
}

fn apply_quota(
    snapshot: OptionalSnapshot<'_, QuotaSnapshotSet>,
    now: u64,
    required: u64,
    states: &mut [CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) {
    let Some(values) = snapshot.value() else {
        apply_missing_snapshot(
            snapshot.missing_policy(),
            SignalKind::Quota,
            states,
            degradations,
        );
        return;
    };
    let now = QuotaTime::new(now);
    for state in states.iter_mut().filter(|state| state.eligible()) {
        let mut observed = false;
        let exhausted = values.snapshots().iter().any(|quota| {
            let matches = quota_matches(
                quota.subject(),
                state.source.account_id(),
                state.source.provider_id(),
            );
            observed |= matches;
            matches && quota.conservative_remaining_at(now) < required
        });
        if exhausted {
            state.exclude(CandidateExclusionReason::QuotaExhausted);
        } else if !observed {
            apply_missing_candidate(
                snapshot.missing_policy(),
                SignalKind::Quota,
                state,
                degradations,
            );
        }
    }
}

fn quota_matches(subject: &QuotaSubject, account: &AccountId, provider: &ProviderId) -> bool {
    match subject {
        QuotaSubject::Account(value) => value == account,
        QuotaSubject::Provider(value) => value == provider,
    }
}

fn apply_schedule(
    snapshot: OptionalSnapshot<'_, ariadnion_account_schedule::ScheduleSnapshot>,
    now: u64,
    states: &mut [CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) -> Result<(), CoordinatorError> {
    let Some(values) = snapshot.value() else {
        apply_missing_snapshot(
            snapshot.missing_policy(),
            SignalKind::Schedule,
            states,
            degradations,
        );
        return Ok(());
    };
    for state in states.iter_mut().filter(|state| state.eligible()) {
        let Some(schedule) = values.schedule_for(state.source.account_id()) else {
            apply_missing_candidate(
                snapshot.missing_policy(),
                SignalKind::Schedule,
                state,
                degradations,
            );
            continue;
        };
        let available = schedule
            .is_available_at(ScheduleTime::new(now))
            .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
        if !available {
            state.exclude(CandidateExclusionReason::ScheduleClosed);
        }
    }
    Ok(())
}

fn apply_proxy(
    snapshot: OptionalSnapshot<'_, [ProxyRoutingProfile]>,
    destination: Option<&str>,
    states: &mut [CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) -> Result<(), CoordinatorError> {
    let Some(values) = snapshot.value() else {
        apply_missing_snapshot(
            snapshot.missing_policy(),
            SignalKind::Proxy,
            states,
            degradations,
        );
        return Ok(());
    };
    let index = unique_account_index(values, ProxyRoutingProfile::account_id)?;
    for state in states.iter_mut().filter(|state| state.eligible()) {
        let Some(profile) = index.get(state.source.account_id()).copied() else {
            apply_missing_candidate(
                snapshot.missing_policy(),
                SignalKind::Proxy,
                state,
                degradations,
            );
            continue;
        };
        if profile.availability() == ProxyAvailability::Unavailable {
            state.exclude(CandidateExclusionReason::ProxyUnavailable);
        } else if destination.is_some_and(|region| !profile.regions().permits(region)) {
            state.exclude(CandidateExclusionReason::ProxyRegionDenied);
        }
    }
    Ok(())
}

fn apply_missing_snapshot(
    policy: MissingSignalPolicy,
    signal: SignalKind,
    states: &mut [CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) {
    if policy == MissingSignalPolicy::AllowWithDegradation {
        degradations.insert(signal);
        return;
    }
    for state in states.iter_mut().filter(|state| state.eligible()) {
        state.exclude(CandidateExclusionReason::MissingSignal(signal));
    }
}

fn apply_missing_candidate(
    policy: MissingSignalPolicy,
    signal: SignalKind,
    state: &mut CandidateState<'_>,
    degradations: &mut BTreeSet<SignalKind>,
) {
    if policy == MissingSignalPolicy::AllowWithDegradation {
        degradations.insert(signal);
    } else {
        state.exclude(CandidateExclusionReason::MissingSignal(signal));
    }
}

fn apply_pricing(
    request: &CoordinationRequest,
    snapshot: OptionalSnapshot<'_, PricingCatalog>,
    states: &mut [CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) -> Result<(), CoordinatorError> {
    let Some(pricing) = snapshot.value() else {
        let _ = degradations;
        return Err(CoordinatorError::new(
            CoordinatorErrorCode::PricingUnavailable,
        ));
    };
    quote_candidates(request, pricing, states);
    let inputs = cost_inputs(states)?;
    if inputs.is_empty() {
        return Ok(());
    }
    let evaluation = evaluate_cost(&inputs, request)?;
    apply_cost_exclusions(states, &evaluation);
    Ok(())
}

fn evaluate_cost(
    inputs: &[CandidateCostInput],
    request: &CoordinationRequest,
) -> Result<ariadnion_routing_cost::CostEvaluation, CoordinatorError> {
    ariadnion_routing_cost::evaluate(inputs, request.pricing().constraints())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))
}

fn apply_cost_exclusions(
    states: &mut [CandidateState<'_>],
    evaluation: &ariadnion_routing_cost::CostEvaluation,
) {
    for exclusion in evaluation.exclusions() {
        let reason = match exclusion.reason() {
            CostExclusionReason::MissingEstimate => CandidateExclusionReason::MissingPrice,
            CostExclusionReason::HardLimitExceeded { .. } => {
                CandidateExclusionReason::HardCostLimit
            }
        };
        exclude_by_id(states, exclusion.candidate().as_str(), reason);
    }
    if !evaluation.preferred().is_empty() {
        for candidate in evaluation.fallback() {
            exclude_by_id(
                states,
                candidate.candidate().as_str(),
                CandidateExclusionReason::AboveSoftCostLimit,
            );
        }
    }
}

fn quote_candidates(
    request: &CoordinationRequest,
    pricing: &PricingCatalog,
    states: &mut [CandidateState<'_>],
) {
    for state in states.iter_mut().filter(|state| state.eligible()) {
        let Some(model) = state.provider_model.as_ref() else {
            state.exclude(CandidateExclusionReason::ModelMappingMissing);
            continue;
        };
        state.quote = pricing
            .quote_at(
                model.as_str(),
                request.pricing().dimension(),
                request.pricing_timestamp(),
                request.pricing().quantity().get(),
            )
            .ok();
        if state.quote.is_none() {
            state.exclude(CandidateExclusionReason::MissingPrice);
        }
    }
}

fn cost_inputs(states: &[CandidateState<'_>]) -> Result<Vec<CandidateCostInput>, CoordinatorError> {
    states
        .iter()
        .filter(|state| state.eligible())
        .map(|state| {
            let id = CostCandidateId::parse(state.key.as_str())
                .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
            let quote = state
                .quote
                .as_ref()
                .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
            let units = CostUnits::new(quote.total().minor_units())
                .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
            Ok(CandidateCostInput::estimated(
                id,
                CostEstimate::from_units(units),
            ))
        })
        .collect()
}

fn exclude_by_id(
    states: &mut [CandidateState<'_>],
    candidate: &str,
    reason: CandidateExclusionReason,
) {
    if let Some(state) = states
        .iter_mut()
        .find(|state| state.key.as_str() == candidate)
    {
        state.exclude(reason);
    }
}

fn select_candidate(
    request: &CoordinationRequest,
    affinity: OptionalSnapshot<'_, AffinitySnapshot>,
    states: &[CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) -> Result<(usize, SelectionBasis, Vec<CandidateExclusion>), CoordinatorError> {
    if let Some((key, now)) = request.affinity()
        && let Some(selected) = select_affinity(key, *now, affinity, states, degradations)?
    {
        let exclusions = affinity_exclusions(states, selected)?;
        return Ok((selected, SelectionBasis::Affinity, exclusions));
    }
    select_weighted(states)
}

fn select_affinity(
    key: &ariadnion_account_affinity::AffinityKey,
    now: ariadnion_account_affinity::UtcSeconds,
    snapshot: OptionalSnapshot<'_, AffinitySnapshot>,
    states: &[CandidateState<'_>],
    degradations: &mut BTreeSet<SignalKind>,
) -> Result<Option<usize>, CoordinatorError> {
    let Some(value) = snapshot.value() else {
        if snapshot.missing_policy() == MissingSignalPolicy::FailClosed {
            return Err(CoordinatorError::new(CoordinatorErrorCode::MissingSignal));
        }
        degradations.insert(SignalKind::Affinity);
        return Ok(None);
    };
    if value.tenant_id() != key.tenant_id() {
        return Err(CoordinatorError::new(CoordinatorErrorCode::TenantMismatch));
    }
    let candidate = affinity_candidate(value, key, now);
    Ok(candidate.and_then(|candidate| {
        states
            .iter()
            .position(|state| state.eligible() && state.key.as_str() == candidate)
    }))
}

fn affinity_candidate<'a>(
    value: &'a AffinitySnapshot,
    key: &ariadnion_account_affinity::AffinityKey,
    now: ariadnion_account_affinity::UtcSeconds,
) -> Option<&'a str> {
    value
        .bindings()
        .iter()
        .find(|binding| binding.key() == key && binding.expires_at() > now)
        .map(|binding| binding.candidate().as_str())
}

fn affinity_exclusions(
    states: &[CandidateState<'_>],
    selected: usize,
) -> Result<Vec<CandidateExclusion>, CoordinatorError> {
    states
        .iter()
        .enumerate()
        .filter(|(index, state)| *index != selected && state.eligible())
        .map(|(_, state)| {
            Ok(CandidateExclusion::new(
                state.key.clone(),
                CandidateExclusionReason::AffinityPreferred,
            ))
        })
        .collect()
}

fn select_weighted(
    states: &[CandidateState<'_>],
) -> Result<(usize, SelectionBasis, Vec<CandidateExclusion>), CoordinatorError> {
    let candidates = policy_candidates(states)?;
    if candidates.is_empty() {
        return Err(CoordinatorError::with_exclusions(
            CoordinatorErrorCode::NoEligibleCandidate,
            collect_exclusions(states, Vec::new())?.0,
        ));
    }
    let (selected_key, exclusions) = choose_weighted(candidates)?;
    let selected = states
        .iter()
        .position(|state| state.key == selected_key)
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    Ok((selected, SelectionBasis::WeightedLeastLoad, exclusions))
}

fn choose_weighted(
    candidates: Vec<Candidate>,
) -> Result<(CandidateKey, Vec<CandidateExclusion>), CoordinatorError> {
    let prepared = PreparedCandidateSet::new(candidates)
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let selection = WeightedLeastLoadPolicy::new()
        .select_prepared(&prepared)
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::NoEligibleCandidate))?;
    let selected_key = CandidateKey::parse(selection.selected().as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let exclusions = selection
        .explain()
        .exclusions()
        .iter()
        .map(map_policy_exclusion)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((selected_key, exclusions))
}

fn policy_candidates(states: &[CandidateState<'_>]) -> Result<Vec<Candidate>, CoordinatorError> {
    states
        .iter()
        .filter(|state| state.eligible())
        .map(policy_candidate)
        .collect()
}

fn policy_candidate(state: &CandidateState<'_>) -> Result<Candidate, CoordinatorError> {
    let id = CandidateId::new(state.key.as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let weight = Weight::new(state.source.weight().get())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let load = Load::new(state.source.load().get())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    Ok(Candidate::new(
        id,
        Priority::new(state.source.priority().get()),
        weight,
        load,
        Availability::Available,
    ))
}

fn map_policy_exclusion(
    exclusion: &ariadnion_routing_policy::CandidateExclusion,
) -> Result<CandidateExclusion, CoordinatorError> {
    let reason = match exclusion.reason() {
        PolicyExclusionReason::Unavailable => CandidateExclusionReason::PoolUnavailable,
        PolicyExclusionReason::ZeroWeight => CandidateExclusionReason::HigherEffectiveLoad,
        PolicyExclusionReason::LowerPriority { .. } => CandidateExclusionReason::LowerPriority,
        PolicyExclusionReason::HigherEffectiveLoad { .. } => {
            CandidateExclusionReason::HigherEffectiveLoad
        }
        PolicyExclusionReason::StableTieBreak { .. } => CandidateExclusionReason::StableTieBreak,
    };
    let key = CandidateKey::parse(exclusion.candidate_id().as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    Ok(CandidateExclusion::new(key, reason))
}

fn collect_exclusions(
    states: &[CandidateState<'_>],
    mut policy: Vec<CandidateExclusion>,
) -> Result<(Vec<CandidateExclusion>, bool), CoordinatorError> {
    let mut exclusions = states
        .iter()
        .filter_map(|state| {
            state
                .exclusion
                .clone()
                .map(|reason| CandidateExclusion::new(state.key.clone(), reason))
        })
        .collect::<Vec<_>>();
    exclusions.append(&mut policy);
    Ok(bound_exclusions(exclusions))
}

fn build_retry_plan(
    request: &CoordinationRequest,
    states: &[CandidateState<'_>],
    selected: usize,
) -> Result<RoutingRetryPlan, CoordinatorError> {
    let primary = states
        .get(selected)
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let mut candidates = Vec::with_capacity(usize::from(request.retry().max_attempts()));
    candidates.push(primary.key.clone());
    for state in states.iter().filter(|state| state.eligible()) {
        if state.key != primary.key
            && candidates.len() < usize::from(request.retry().max_attempts())
        {
            candidates.push(state.key.clone());
        }
    }
    let plan = FailoverPlan::new(candidates, request.retry().max_attempts())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    Ok(RoutingRetryPlan::new(
        DeterministicFailoverPlanner::new(plan),
        request.retry().operation(),
    ))
}

fn admit(
    coordinator: &RoutingAdmissionCoordinator,
    request: &CoordinationRequest,
    selected: &CandidateState<'_>,
    exclusions: &[CandidateExclusion],
) -> Result<ariadnion_routing_admission::RoutingAdmissionLease, CoordinatorError> {
    let quote = selected
        .quote
        .as_ref()
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::PricingUnavailable))?;
    let tenant = request.context().tenant_id();
    let rate = AdmissionRequest::new(
        vec![
            LimitKey::Tenant(
                TenantLimitId::parse(tenant.as_str())
                    .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?,
            ),
            LimitKey::Model(
                ModelLimitId::parse(request.context().model().as_str())
                    .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?,
            ),
        ],
        request.admission().units(),
    )
    .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let currency = BudgetCurrency::parse(quote.currency().as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let budget = ReservationRequest::new(
        request.admission().reservation_id().clone(),
        BudgetContext::new(tenant.clone(), None, selected.source.account_id().clone()),
        Money::new(currency, quote.total().minor_units()),
        request.admission().times().budget_expires_at(),
    )
    .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let times = request.admission().times();
    coordinator
        .admit(RoutingAdmissionRequest::new(
            rate,
            budget,
            times.monotonic_now(),
            times.budget_now(),
        ))
        .map_err(|error| map_admission_error(error.code(), error.retry_after(), exclusions))
}

fn map_admission_error(
    code: RoutingAdmissionErrorCode,
    retry_after: Option<std::time::Duration>,
    exclusions: &[CandidateExclusion],
) -> CoordinatorError {
    let mapped = match code {
        RoutingAdmissionErrorCode::RateLimited => CoordinatorErrorCode::RateLimited,
        RoutingAdmissionErrorCode::ConcurrencyLimited => CoordinatorErrorCode::ConcurrencyLimited,
        RoutingAdmissionErrorCode::BudgetRejected => CoordinatorErrorCode::BudgetRejected,
        RoutingAdmissionErrorCode::TenantMismatch => CoordinatorErrorCode::TenantMismatch,
        RoutingAdmissionErrorCode::InvalidArgument => CoordinatorErrorCode::InvalidArgument,
        RoutingAdmissionErrorCode::StateUnavailable
        | RoutingAdmissionErrorCode::ClockRegressed
        | RoutingAdmissionErrorCode::LeaseExpired
        | RoutingAdmissionErrorCode::LeaseClosed
        | RoutingAdmissionErrorCode::CommitIncomplete
        | RoutingAdmissionErrorCode::RollbackFailed => CoordinatorErrorCode::AdmissionUnavailable,
        _ => CoordinatorErrorCode::AdmissionUnavailable,
    };
    let mut error = CoordinatorError::with_retry_after(mapped, retry_after);
    let (bounded, truncated) = bound_exclusions(exclusions.to_vec());
    error.exclusions = bounded;
    error.exclusions_truncated = truncated;
    error
}

// crates/optional/ariadnion-routing-simulator/src/lib.rs - Read-only routing simulation contracts.
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
//! Read-only, deterministic routing configuration simulation.
//!
//! The simulator composes the routing-domain snapshot and context with the
//! routing-policy typed candidates. It never mutates input, accesses clocks or
//! credentials, or performs floating-point arithmetic. Capacity projections are
//! bounded integer calculations and expose only stable, non-sensitive errors.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_routing_domain::{
    CandidateExclusion as DomainExclusion, ExclusionReason as DomainExclusionReason, RouteDecision,
    RouteSnapshot, RoutingContext, RoutingEvaluation,
};
use ariadnion_routing_policy::{
    Candidate, RoutingPolicyErrorCode, SelectionDecision, SelectionPolicy, WeightedLeastLoadPolicy,
};
use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::fmt;

/// Maximum candidates accepted by one simulation input.
pub const MAX_CANDIDATES: usize = 4_096;
/// Maximum projected requests or capacity units in one forecast.
pub const MAX_FORECAST_UNITS: u64 = 1_000_000_000_000;

/// Stable machine-readable simulator failures.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SimulationErrorCode {
    /// An argument is malformed or outside its bound.
    InvalidArgument,
    /// No policy candidates were supplied.
    EmptyCandidates,
    /// A candidate collection exceeds its fixed bound.
    TooManyCandidates,
    /// A policy candidate identifier occurs more than once.
    DuplicateCandidate,
    /// A policy candidate has no matching routing-domain snapshot entry.
    CandidateNotFound,
    /// A selected candidate cannot serve the requested model.
    ModelMismatch,
    /// A policy evaluation has no eligible candidate.
    NoEligibleCandidates,
    /// A projected request or capacity value exceeds its fixed bound.
    CapacityOverflow,
    /// The routing context and snapshot belong to different tenants.
    TenantMismatch,
}

impl SimulationErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ROUTING_SIMULATOR_INVALID_ARGUMENT",
            Self::EmptyCandidates => "ROUTING_SIMULATOR_EMPTY_CANDIDATES",
            Self::TooManyCandidates => "ROUTING_SIMULATOR_TOO_MANY_CANDIDATES",
            Self::DuplicateCandidate => "ROUTING_SIMULATOR_DUPLICATE_CANDIDATE",
            Self::CandidateNotFound => "ROUTING_SIMULATOR_CANDIDATE_NOT_FOUND",
            other => other.as_tail_str(),
        }
    }

    const fn as_tail_str(self) -> &'static str {
        match self {
            Self::ModelMismatch => "ROUTING_SIMULATOR_MODEL_MISMATCH",
            Self::NoEligibleCandidates => "ROUTING_SIMULATOR_NO_ELIGIBLE_CANDIDATES",
            Self::CapacityOverflow => "ROUTING_SIMULATOR_CAPACITY_OVERFLOW",
            Self::TenantMismatch => "ROUTING_SIMULATOR_TENANT_MISMATCH",
            _ => "ROUTING_SIMULATOR_INVALID_ARGUMENT",
        }
    }
}

impl fmt::Display for SimulationErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted simulator error containing only its stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulationError {
    code: SimulationErrorCode,
}

impl SimulationError {
    const fn new(code: SimulationErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> SimulationErrorCode {
        self.code
    }
}

impl fmt::Display for SimulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for SimulationError {}

/// A bounded integer forecast for projected requests and available capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityForecast {
    projected: u64,
    capacity: u64,
    accepted: u64,
    remaining: u64,
    deficit: u64,
}

impl CapacityForecast {
    /// Creates a forecast without floating-point rounding or unbounded values.
    ///
    /// # Errors
    /// Returns [`SimulationErrorCode::CapacityOverflow`] when either input is
    /// greater than [`MAX_FORECAST_UNITS`].
    pub const fn new(projected: u64, capacity: u64) -> Result<Self, SimulationError> {
        if projected > MAX_FORECAST_UNITS || capacity > MAX_FORECAST_UNITS {
            return Err(SimulationError::new(SimulationErrorCode::CapacityOverflow));
        }
        let accepted = if projected < capacity {
            projected
        } else {
            capacity
        };
        Ok(Self {
            projected,
            capacity,
            accepted,
            remaining: capacity - accepted,
            deficit: projected - accepted,
        })
    }

    /// Returns projected request units.
    #[must_use]
    pub const fn projected(self) -> u64 {
        self.projected
    }

    /// Returns available capacity units.
    #[must_use]
    pub const fn capacity(self) -> u64 {
        self.capacity
    }

    /// Returns request units that fit within capacity.
    #[must_use]
    pub const fn accepted(self) -> u64 {
        self.accepted
    }

    /// Returns unused capacity units.
    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.remaining
    }

    /// Returns projected request units beyond capacity.
    #[must_use]
    pub const fn deficit(self) -> u64 {
        self.deficit
    }
}

/// Immutable input to one routing simulation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationInput {
    context: RoutingContext,
    snapshot: RouteSnapshot,
    policy: Vec<Candidate>,
    projected: u64,
    capacity: u64,
}

impl SimulationInput {
    /// Validates a read-only simulation input.
    ///
    /// Policy identifiers must be unique and correspond to candidates in the
    /// routing snapshot. Inputs are copied into an immutable value; no state is
    /// retained outside this value.
    ///
    /// # Errors
    /// Returns a stable error when bounds, identifiers, or capacity units are
    /// invalid.
    pub fn new(
        context: RoutingContext,
        snapshot: RouteSnapshot,
        policy: Vec<Candidate>,
        projected: u64,
        capacity: u64,
    ) -> Result<Self, SimulationError> {
        validate_input_bounds(&context, &snapshot, &policy, projected, capacity)?;
        validate_policy_candidates(&snapshot, &policy)?;
        Ok(Self {
            context,
            snapshot,
            policy,
            projected,
            capacity,
        })
    }

    /// Returns the routing context copied into this input.
    #[must_use]
    pub const fn context(&self) -> &RoutingContext {
        &self.context
    }

    /// Returns the immutable routing snapshot copied into this input.
    #[must_use]
    pub const fn snapshot(&self) -> &RouteSnapshot {
        &self.snapshot
    }

    /// Returns policy candidates in caller-provided deterministic order.
    #[must_use]
    pub fn policy(&self) -> &[Candidate] {
        &self.policy
    }

    /// Returns projected request units.
    #[must_use]
    pub const fn projected(&self) -> u64 {
        self.projected
    }

    /// Returns available capacity units.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }
}

/// Complete deterministic output of one simulation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationResult {
    policy: SelectionDecision,
    evaluation: RoutingEvaluation,
    forecast: CapacityForecast,
}

impl SimulationResult {
    /// Returns the policy decision and its exclusions.
    #[must_use]
    pub const fn policy(&self) -> &SelectionDecision {
        &self.policy
    }

    /// Returns the domain-level decision explanation.
    #[must_use]
    pub const fn evaluation(&self) -> &RoutingEvaluation {
        &self.evaluation
    }

    /// Returns the bounded integer capacity forecast.
    #[must_use]
    pub const fn forecast(&self) -> CapacityForecast {
        self.forecast
    }
}

/// Runs a read-only deterministic simulation.
///
/// The generic borrow accepts either an owned [`SimulationInput`] or a shared
/// reference. Equal typed inputs always produce equal output and no input is
/// mutated.
///
/// # Errors
/// Returns a stable simulator code for policy, snapshot, model, or capacity
/// failures. No sensitive candidate metadata is included in errors.
pub fn simulate(input: impl Borrow<SimulationInput>) -> Result<SimulationResult, SimulationError> {
    let input = input.borrow();
    let policy_decision = select_policy(input)?;
    let evaluation = evaluate_policy(input, &policy_decision)?;
    let forecast = CapacityForecast::new(input.projected(), input.capacity())?;
    Ok(SimulationResult {
        policy: policy_decision,
        evaluation,
        forecast,
    })
}

fn validate_input_bounds(
    context: &RoutingContext,
    snapshot: &RouteSnapshot,
    policy: &[Candidate],
    projected: u64,
    capacity: u64,
) -> Result<(), SimulationError> {
    if policy.is_empty() {
        return Err(SimulationError::new(SimulationErrorCode::EmptyCandidates));
    }
    if context.tenant_id() != snapshot.tenant_id() {
        return Err(SimulationError::new(SimulationErrorCode::TenantMismatch));
    }
    if policy.len() > MAX_CANDIDATES {
        return Err(SimulationError::new(SimulationErrorCode::TooManyCandidates));
    }
    CapacityForecast::new(projected, capacity).map(|_| ())
}

fn validate_policy_candidates(
    snapshot: &RouteSnapshot,
    policy: &[Candidate],
) -> Result<(), SimulationError> {
    let mut ids = BTreeSet::new();
    for candidate in policy {
        if !ids.insert(candidate.id().clone()) {
            return Err(SimulationError::new(
                SimulationErrorCode::DuplicateCandidate,
            ));
        }
        if !snapshot
            .candidates()
            .iter()
            .any(|route| route.key().as_str() == candidate.id().as_str())
        {
            return Err(SimulationError::new(SimulationErrorCode::CandidateNotFound));
        }
    }
    Ok(())
}

fn select_policy(input: &SimulationInput) -> Result<SelectionDecision, SimulationError> {
    WeightedLeastLoadPolicy::new()
        .select(input.policy())
        .map_err(map_policy_error)
}

fn evaluate_policy(
    input: &SimulationInput,
    policy: &SelectionDecision,
) -> Result<RoutingEvaluation, SimulationError> {
    let selected = input
        .snapshot()
        .candidates()
        .iter()
        .find(|candidate| candidate.key().as_str() == policy.selected().as_str())
        .ok_or_else(|| SimulationError::new(SimulationErrorCode::CandidateNotFound))?;
    let decision = RouteDecision::new(input.snapshot().version(), selected.key().clone())
        .map_err(|_| SimulationError::new(SimulationErrorCode::InvalidArgument))?;
    let exclusions = policy_exclusions(input.snapshot(), policy);
    RoutingEvaluation::new(
        input.context().clone(),
        input.snapshot(),
        decision,
        exclusions,
    )
    .map_err(map_domain_error)
}

fn policy_exclusions(snapshot: &RouteSnapshot, policy: &SelectionDecision) -> Vec<DomainExclusion> {
    policy
        .exclusions()
        .iter()
        .filter_map(|exclusion| {
            snapshot
                .candidates()
                .iter()
                .find(|candidate| candidate.key().as_str() == exclusion.candidate_id().as_str())
                .map(|candidate| {
                    DomainExclusion::new(
                        candidate.key().clone(),
                        DomainExclusionReason::PolicyExcluded,
                    )
                })
        })
        .collect()
}

fn map_domain_error(error: ariadnion_routing_domain::RoutingDomainError) -> SimulationError {
    let code = match error.code() {
        ariadnion_routing_domain::RoutingDomainErrorCode::ModelMismatch => {
            SimulationErrorCode::ModelMismatch
        }
        ariadnion_routing_domain::RoutingDomainErrorCode::CandidateNotFound => {
            SimulationErrorCode::CandidateNotFound
        }
        ariadnion_routing_domain::RoutingDomainErrorCode::TenantMismatch => {
            SimulationErrorCode::TenantMismatch
        }
        _ => SimulationErrorCode::InvalidArgument,
    };
    SimulationError::new(code)
}

fn map_policy_error(error: ariadnion_routing_policy::RoutingPolicyError) -> SimulationError {
    let code = match error.code() {
        RoutingPolicyErrorCode::EmptyCandidates => SimulationErrorCode::EmptyCandidates,
        RoutingPolicyErrorCode::TooManyCandidates => SimulationErrorCode::TooManyCandidates,
        RoutingPolicyErrorCode::DuplicateCandidateId => SimulationErrorCode::DuplicateCandidate,
        RoutingPolicyErrorCode::NoEligibleCandidates => SimulationErrorCode::NoEligibleCandidates,
        _ => SimulationErrorCode::InvalidArgument,
    };
    SimulationError::new(code)
}

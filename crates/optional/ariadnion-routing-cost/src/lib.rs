// crates/optional/ariadnion-routing-cost/src/lib.rs - Bounded routing cost contracts for Ariadnion.
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
//! Bounded integer cost estimates and deterministic request constraints.
//!
//! Costs are represented as abstract integer units rather than floating-point
//! money. An evaluator retains candidates within the hard limit, splitting them
//! into a preferred soft-limit tier and a deterministic fallback tier while
//! recording redacted exclusion reasons.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;
use std::collections::BTreeSet;

/// Maximum candidates accepted by one cost evaluation.
pub const MAX_CANDIDATES: usize = 1 << 17;
/// Maximum UTF-8 byte length of one candidate identifier.
pub const MAX_CANDIDATE_ID_BYTES: usize = 128;
/// Maximum representable abstract cost in one estimate or constraint.
pub const MAX_COST_UNITS: u64 = 1_000_000_000_000;

/// Stable machine-readable routing-cost failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RoutingCostErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// An evaluation contains no candidates.
    EmptyCandidates,
    /// An evaluation exceeds its bounded candidate capacity.
    TooManyCandidates,
    /// A candidate identifier occurs more than once.
    DuplicateCandidate,
    /// A soft limit is greater than a configured hard limit.
    ConstraintConflict,
    /// An arithmetic operation exceeded the supported cost bound.
    CostOverflow,
}

impl RoutingCostErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ROUTING_COST_INVALID_ARGUMENT",
            Self::EmptyCandidates => "ROUTING_COST_EMPTY_CANDIDATES",
            Self::TooManyCandidates => "ROUTING_COST_TOO_MANY_CANDIDATES",
            Self::DuplicateCandidate => "ROUTING_COST_DUPLICATE_CANDIDATE",
            Self::ConstraintConflict => "ROUTING_COST_CONSTRAINT_CONFLICT",
            Self::CostOverflow => "ROUTING_COST_OVERFLOW",
        }
    }
}

impl fmt::Display for RoutingCostErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted routing-cost failure containing only its stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingCostError {
    code: RoutingCostErrorCode,
}

impl RoutingCostError {
    const fn new(code: RoutingCostErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> RoutingCostErrorCode {
        self.code
    }
}

impl fmt::Display for RoutingCostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for RoutingCostError {}

/// A bounded identifier for a candidate evaluated by the cost policy.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CostCandidateId(Box<str>);

impl CostCandidateId {
    /// Parses a non-empty visible ASCII identifier.
    ///
    /// # Errors
    /// Returns [`RoutingCostErrorCode::InvalidArgument`] for an empty,
    /// overlong, non-ASCII, or control-containing identifier.
    pub fn parse(value: &str) -> Result<Self, RoutingCostError> {
        if value.is_empty()
            || value.len() > MAX_CANDIDATE_ID_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(RoutingCostError::new(RoutingCostErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CostCandidateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An abstract integer cost unit suitable for deterministic comparisons.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CostUnits(u64);

impl CostUnits {
    /// Creates a bounded cost value.
    ///
    /// # Errors
    /// Returns [`RoutingCostErrorCode::CostOverflow`] when `value` exceeds
    /// [`MAX_COST_UNITS`].
    pub const fn new(value: u64) -> Result<Self, RoutingCostError> {
        if value > MAX_COST_UNITS {
            Err(RoutingCostError::new(RoutingCostErrorCode::CostOverflow))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the integer cost value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds two bounded costs without wrapping.
    ///
    /// # Errors
    /// Returns [`RoutingCostErrorCode::CostOverflow`] when the sum exceeds
    /// [`MAX_COST_UNITS`].
    pub const fn checked_add(self, other: Self) -> Result<Self, RoutingCostError> {
        match self.0.checked_add(other.0) {
            Some(value) if value <= MAX_COST_UNITS => Ok(Self(value)),
            _ => Err(RoutingCostError::new(RoutingCostErrorCode::CostOverflow)),
        }
    }
}

/// A validated estimate for one candidate request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CostEstimate {
    units: CostUnits,
}

impl CostEstimate {
    /// Creates an estimate from abstract integer units.
    #[must_use]
    pub const fn from_units(units: CostUnits) -> Self {
        Self { units }
    }

    /// Builds an estimate by adding bounded input, output, and overhead units.
    ///
    /// # Errors
    /// Returns [`RoutingCostErrorCode::CostOverflow`] when the sum exceeds the
    /// supported bound.
    pub const fn from_components(
        input: CostUnits,
        output: CostUnits,
        overhead: CostUnits,
    ) -> Result<Self, RoutingCostError> {
        let total = match input.checked_add(output) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let total = match total.checked_add(overhead) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Ok(Self::from_units(total))
    }

    /// Returns the total abstract cost.
    #[must_use]
    pub const fn units(self) -> CostUnits {
        self.units
    }
}

/// A request-scoped soft and hard cost policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CostConstraints {
    soft_limit: Option<CostUnits>,
    hard_limit: Option<CostUnits>,
}

impl CostConstraints {
    /// Creates a policy where the soft tier is preferred and the hard tier is
    /// always enforced.
    ///
    /// A missing limit means that tier is unbounded. The soft limit must not
    /// exceed the hard limit when both are present.
    ///
    /// # Errors
    /// Returns [`RoutingCostErrorCode::ConstraintConflict`] for an invalid
    /// soft and hard limit pair.
    pub const fn new(
        soft_limit: Option<CostUnits>,
        hard_limit: Option<CostUnits>,
    ) -> Result<Self, RoutingCostError> {
        if let (Some(soft), Some(hard)) = (soft_limit, hard_limit)
            && soft.get() > hard.get()
        {
            return Err(RoutingCostError::new(
                RoutingCostErrorCode::ConstraintConflict,
            ));
        }
        Ok(Self {
            soft_limit,
            hard_limit,
        })
    }

    /// Returns the preferred-tier limit, if configured.
    #[must_use]
    pub const fn soft_limit(self) -> Option<CostUnits> {
        self.soft_limit
    }

    /// Returns the enforced hard limit, if configured.
    #[must_use]
    pub const fn hard_limit(self) -> Option<CostUnits> {
        self.hard_limit
    }
}

/// A candidate with a validated cost estimate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostedCandidate {
    candidate: CostCandidateId,
    estimate: CostEstimate,
}

impl CostedCandidate {
    /// Creates a costed candidate.
    #[must_use]
    pub const fn new(candidate: CostCandidateId, estimate: CostEstimate) -> Self {
        Self {
            candidate,
            estimate,
        }
    }

    /// Returns the candidate identifier.
    #[must_use]
    pub const fn candidate(&self) -> &CostCandidateId {
        &self.candidate
    }

    /// Returns the candidate estimate.
    #[must_use]
    pub const fn estimate(&self) -> CostEstimate {
        self.estimate
    }
}

/// An input candidate whose estimate may be unavailable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateCostInput {
    candidate: CostCandidateId,
    estimate: Option<CostEstimate>,
}

impl CandidateCostInput {
    /// Creates an input with an available estimate.
    #[must_use]
    pub const fn estimated(candidate: CostCandidateId, estimate: CostEstimate) -> Self {
        Self {
            candidate,
            estimate: Some(estimate),
        }
    }

    /// Creates an input for which no estimate is available.
    #[must_use]
    pub const fn unavailable(candidate: CostCandidateId) -> Self {
        Self {
            candidate,
            estimate: None,
        }
    }

    /// Returns the candidate identifier.
    #[must_use]
    pub const fn candidate(&self) -> &CostCandidateId {
        &self.candidate
    }

    /// Returns the estimate, if one was available.
    #[must_use]
    pub const fn estimate(&self) -> Option<CostEstimate> {
        self.estimate
    }
}

/// Stable reasons a candidate was excluded from a cost result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CostExclusionReason {
    /// No bounded estimate was supplied for the candidate.
    MissingEstimate,
    /// The estimate exceeded the request's hard limit.
    HardLimitExceeded {
        /// Hard limit that the candidate exceeded.
        limit: CostUnits,
    },
}

/// One candidate exclusion retained for deterministic explanation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostExclusion {
    candidate: CostCandidateId,
    reason: CostExclusionReason,
}

impl CostExclusion {
    const fn new(candidate: CostCandidateId, reason: CostExclusionReason) -> Self {
        Self { candidate, reason }
    }

    /// Returns the excluded candidate identifier.
    #[must_use]
    pub const fn candidate(&self) -> &CostCandidateId {
        &self.candidate
    }

    /// Returns the stable exclusion reason.
    #[must_use]
    pub const fn reason(&self) -> CostExclusionReason {
        self.reason
    }
}

/// Deterministic result of one bounded cost evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostEvaluation {
    preferred: Vec<CostedCandidate>,
    fallback: Vec<CostedCandidate>,
    exclusions: Vec<CostExclusion>,
}

impl CostEvaluation {
    /// Returns candidates at or below the soft limit in input order.
    #[must_use]
    pub fn preferred(&self) -> &[CostedCandidate] {
        &self.preferred
    }

    /// Returns candidates above the soft limit but within the hard limit.
    #[must_use]
    pub fn fallback(&self) -> &[CostedCandidate] {
        &self.fallback
    }

    /// Returns hard-limit and missing-estimate exclusions in input order.
    #[must_use]
    pub fn exclusions(&self) -> &[CostExclusion] {
        &self.exclusions
    }

    /// Returns the first preferred candidate, or the first fallback candidate.
    #[must_use]
    pub fn first_acceptable(&self) -> Option<&CostedCandidate> {
        self.preferred.first().or_else(|| self.fallback.first())
    }
}

/// Evaluates bounded candidate cost inputs against request constraints.
///
/// Input order is preserved in every result tier and in exclusions. Duplicate
/// candidate identifiers fail the complete evaluation, preventing ambiguous
/// explanations. Missing estimates and hard-limit violations are excluded;
/// candidates above the soft limit remain available as deterministic fallbacks.
///
/// # Errors
/// Returns a stable error for an empty, oversized, or duplicate candidate set.
pub fn evaluate(
    inputs: &[CandidateCostInput],
    constraints: CostConstraints,
) -> Result<CostEvaluation, RoutingCostError> {
    if inputs.is_empty() {
        return Err(RoutingCostError::new(RoutingCostErrorCode::EmptyCandidates));
    }
    if inputs.len() > MAX_CANDIDATES {
        return Err(RoutingCostError::new(
            RoutingCostErrorCode::TooManyCandidates,
        ));
    }

    let mut seen = BTreeSet::new();
    let mut preferred = Vec::new();
    let mut fallback = Vec::new();
    let mut exclusions = Vec::new();
    for input in inputs {
        if !seen.insert(input.candidate()) {
            return Err(RoutingCostError::new(
                RoutingCostErrorCode::DuplicateCandidate,
            ));
        }
        classify_input(
            input,
            constraints,
            &mut preferred,
            &mut fallback,
            &mut exclusions,
        );
    }

    Ok(CostEvaluation {
        preferred,
        fallback,
        exclusions,
    })
}

fn classify_input(
    input: &CandidateCostInput,
    constraints: CostConstraints,
    preferred: &mut Vec<CostedCandidate>,
    fallback: &mut Vec<CostedCandidate>,
    exclusions: &mut Vec<CostExclusion>,
) {
    let Some(estimate) = input.estimate() else {
        exclusions.push(CostExclusion::new(
            input.candidate().clone(),
            CostExclusionReason::MissingEstimate,
        ));
        return;
    };

    if let Some(limit) = constraints.hard_limit()
        && estimate.units() > limit
    {
        exclusions.push(CostExclusion::new(
            input.candidate().clone(),
            CostExclusionReason::HardLimitExceeded { limit },
        ));
        return;
    }

    let costed = CostedCandidate::new(input.candidate().clone(), estimate);
    if constraints
        .soft_limit()
        .is_some_and(|limit| estimate.units() > limit)
    {
        fallback.push(costed);
    } else {
        preferred.push(costed);
    }
}

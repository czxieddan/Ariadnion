// crates/optional/ariadnion-routing-policy/src/policy.rs - Deterministic selection for Ariadnion.
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

use crate::error::{RoutingPolicyError, RoutingPolicyErrorCode};
use crate::model::{
    Availability, Candidate, CandidateExclusion, CandidateId, ExclusionReason,
    PreparedCandidateSet, Priority, SelectionDecision, validate_candidates,
};
use std::cmp::Ordering;

/// Pure policy contract over an immutable candidate slice.
pub trait SelectionPolicy {
    /// Selects one candidate and returns a complete deterministic explanation.
    fn select(&self, candidates: &[Candidate]) -> Result<SelectionDecision, RoutingPolicyError>;
}

/// Lowest-priority weighted least-load policy with an ID tie-break.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WeightedLeastLoadPolicy;

impl WeightedLeastLoadPolicy {
    /// Creates the stateless policy.
    pub const fn new() -> Self {
        Self
    }

    /// Selects from a snapshot that already passed bounded identity validation.
    ///
    /// This is the request hot path for large immutable account pools. The
    /// returned value borrows the prepared snapshot and can materialize the
    /// complete per-candidate explanation later through
    /// [`PreparedSelection::explain`].
    ///
    /// # Errors
    /// Returns [`RoutingPolicyErrorCode::NoEligibleCandidates`] when every
    /// candidate is unavailable or has zero weight.
    pub fn select_prepared<'a>(
        &self,
        candidates: &'a PreparedCandidateSet,
    ) -> Result<PreparedSelection<'a>, RoutingPolicyError> {
        select_candidates(candidates.candidates())
    }
}

impl SelectionPolicy for WeightedLeastLoadPolicy {
    fn select(&self, candidates: &[Candidate]) -> Result<SelectionDecision, RoutingPolicyError> {
        validate_candidates(candidates)?;
        Ok(select_candidates(candidates)?.explain())
    }
}

/// Fast routing result bound to the prepared snapshot that produced it.
///
/// The result contains no copied candidate set or exclusion list. Call
/// [`Self::explain`] when a full audit explanation is required.
#[derive(Clone, Copy, Debug)]
pub struct PreparedSelection<'a> {
    candidates: &'a [Candidate],
    winner: &'a Candidate,
    winning_priority: Priority,
}

impl PreparedSelection<'_> {
    /// Returns the selected candidate identifier.
    #[must_use]
    pub fn selected(&self) -> &CandidateId {
        self.winner.id()
    }

    /// Returns the lowest eligible priority tier used by the decision.
    #[must_use]
    pub const fn winning_priority(&self) -> Priority {
        self.winning_priority
    }

    /// Materializes the complete deterministic per-candidate explanation.
    ///
    /// Explanation allocation is deliberately separate from the selection hot
    /// path so large pools do not pay that cost before dispatch.
    #[must_use]
    pub fn explain(&self) -> SelectionDecision {
        let exclusions = explain_exclusions(self.candidates, self.winner, self.winning_priority);
        SelectionDecision::new(self.winner.id().clone(), self.winning_priority, exclusions)
    }
}

fn select_candidates(
    candidates: &[Candidate],
) -> Result<PreparedSelection<'_>, RoutingPolicyError> {
    let winning_priority = find_winning_priority(candidates)?;
    let winner = find_winner(candidates, winning_priority)?;
    Ok(PreparedSelection {
        candidates,
        winner,
        winning_priority,
    })
}

fn find_winning_priority(candidates: &[Candidate]) -> Result<Priority, RoutingPolicyError> {
    candidates
        .iter()
        .filter(|candidate| is_eligible(candidate))
        .map(Candidate::priority)
        .min()
        .ok_or_else(|| {
            RoutingPolicyError::new(
                RoutingPolicyErrorCode::NoEligibleCandidates,
                "all candidates are unavailable or have zero weight",
            )
        })
}

fn find_winner(
    candidates: &[Candidate],
    winning_priority: Priority,
) -> Result<&Candidate, RoutingPolicyError> {
    candidates
        .iter()
        .filter(|candidate| candidate.priority() == winning_priority && is_eligible(candidate))
        .min_by(|left, right| compare_effective_load(left, right))
        .ok_or_else(|| {
            RoutingPolicyError::new(
                RoutingPolicyErrorCode::NoEligibleCandidates,
                "winning priority tier has no eligible candidate",
            )
        })
}

fn explain_exclusions(
    candidates: &[Candidate],
    winner: &Candidate,
    winning_priority: Priority,
) -> Vec<CandidateExclusion> {
    candidates
        .iter()
        .filter_map(|candidate| {
            exclusion_for(candidate, winner, winning_priority)
                .map(|reason| CandidateExclusion::new(candidate.id().clone(), reason))
        })
        .collect()
}

fn exclusion_for(
    candidate: &Candidate,
    winner: &Candidate,
    winning_priority: Priority,
) -> Option<ExclusionReason> {
    if candidate.id() == winner.id() {
        return None;
    }
    if candidate.availability() == Availability::Unavailable {
        return Some(ExclusionReason::Unavailable);
    }
    if candidate.weight().get() == 0 {
        return Some(ExclusionReason::ZeroWeight);
    }
    if candidate.priority() > winning_priority {
        return Some(ExclusionReason::LowerPriority { winning_priority });
    }
    if compare_load_ratio(candidate, winner) == Ordering::Greater {
        return Some(ExclusionReason::HigherEffectiveLoad {
            winning_candidate: winner.id().clone(),
        });
    }
    Some(ExclusionReason::StableTieBreak {
        winning_candidate: winner.id().clone(),
    })
}

fn is_eligible(candidate: &Candidate) -> bool {
    candidate.availability() == Availability::Available && candidate.weight().get() > 0
}

fn compare_effective_load(left: &Candidate, right: &Candidate) -> Ordering {
    compare_load_ratio(left, right).then_with(|| left.id().cmp(right.id()))
}

fn compare_load_ratio(left: &Candidate, right: &Candidate) -> Ordering {
    let left_ratio = u128::from(left.load().get()) * u128::from(right.weight().get());
    let right_ratio = u128::from(right.load().get()) * u128::from(left.weight().get());
    left_ratio.cmp(&right_ratio)
}

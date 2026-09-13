// crates/optional/ariadnion-routing-policy/src/policy.rs - Deterministic selection for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
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
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0

use crate::error::{RoutingPolicyError, RoutingPolicyErrorCode};
use crate::model::{
    Availability, Candidate, CandidateExclusion, ExclusionReason, MAX_CANDIDATES, Priority,
    SelectionDecision,
};
use std::cmp::Ordering;
use std::collections::BTreeSet;

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
}

impl SelectionPolicy for WeightedLeastLoadPolicy {
    fn select(&self, candidates: &[Candidate]) -> Result<SelectionDecision, RoutingPolicyError> {
        validate_input(candidates)?;
        let winning_priority = find_winning_priority(candidates)?;
        let winner = find_winner(candidates, winning_priority)?;
        let exclusions = explain_exclusions(candidates, winner, winning_priority);
        Ok(SelectionDecision::new(
            winner.id().clone(),
            winning_priority,
            exclusions,
        ))
    }
}

fn validate_input(candidates: &[Candidate]) -> Result<(), RoutingPolicyError> {
    if candidates.is_empty() {
        return Err(RoutingPolicyError::new(
            RoutingPolicyErrorCode::EmptyCandidates,
            "at least one candidate is required",
        ));
    }
    if candidates.len() > MAX_CANDIDATES {
        return Err(RoutingPolicyError::new(
            RoutingPolicyErrorCode::TooManyCandidates,
            "candidate set exceeds the bounded policy limit",
        ));
    }
    let mut identifiers = BTreeSet::new();
    for candidate in candidates {
        if !identifiers.insert(candidate.id().clone()) {
            return Err(RoutingPolicyError::new(
                RoutingPolicyErrorCode::DuplicateCandidateId,
                "candidate identifiers must be unique within one snapshot",
            ));
        }
    }
    Ok(())
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

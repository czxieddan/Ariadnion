// crates/optional/ariadnion-routing-policy/src/model.rs - Routing policy models for Ariadnion.
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
use core::fmt;

/// Maximum number of candidates accepted by one policy evaluation.
pub const MAX_CANDIDATES: usize = 4_096;
/// Maximum UTF-8 byte length of a candidate identifier.
pub const MAX_CANDIDATE_ID_BYTES: usize = 128;
/// Maximum supported instantaneous load value.
pub const MAX_LOAD: u32 = 1_000_000_000;
/// Maximum supported candidate weight.
pub const MAX_WEIGHT: u32 = 1_000_000;

/// Stable identifier for a routable candidate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct CandidateId(String);

impl CandidateId {
    /// Creates an identifier after enforcing the non-empty bounded form.
    pub fn new(value: impl Into<String>) -> Result<Self, RoutingPolicyError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CANDIDATE_ID_BYTES {
            return Err(RoutingPolicyError::new(
                RoutingPolicyErrorCode::InvalidCandidateId,
                "candidate identifier must be non-empty and within the byte limit",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the identifier as a borrowed string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CandidateId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CandidateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Priority tier where lower numeric values win first.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Priority(u16);

impl Priority {
    /// Creates a priority tier.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric priority.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Positive or zero relative weight used by weighted least-load comparison.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Weight(u32);

impl Weight {
    /// Creates a bounded weight. Zero is accepted and causes an explicit exclusion.
    pub const fn new(value: u32) -> Result<Self, RoutingPolicyError> {
        if value > MAX_WEIGHT {
            Err(RoutingPolicyError::new(
                RoutingPolicyErrorCode::WeightOutOfRange,
                "candidate weight exceeds the supported bound",
            ))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric weight.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Bounded instantaneous candidate load used by a pure policy snapshot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Load(u32);

impl Load {
    /// Creates a bounded load value.
    pub const fn new(value: u32) -> Result<Self, RoutingPolicyError> {
        if value > MAX_LOAD {
            Err(RoutingPolicyError::new(
                RoutingPolicyErrorCode::LoadOutOfRange,
                "candidate load exceeds the supported bound",
            ))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric load.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Availability fact supplied by the caller's immutable snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Availability {
    /// The candidate may be considered by the policy.
    Available,
    /// The candidate is excluded before priority and load comparison.
    Unavailable,
}

/// Strongly typed candidate input to a routing policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    id: CandidateId,
    priority: Priority,
    weight: Weight,
    load: Load,
    availability: Availability,
}

impl Candidate {
    /// Creates a candidate from validated, bounded values.
    pub const fn new(
        id: CandidateId,
        priority: Priority,
        weight: Weight,
        load: Load,
        availability: Availability,
    ) -> Self {
        Self {
            id,
            priority,
            weight,
            load,
            availability,
        }
    }

    /// Returns the candidate identifier.
    pub fn id(&self) -> &CandidateId {
        &self.id
    }

    /// Returns the priority tier.
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Returns the configured weight.
    pub const fn weight(&self) -> Weight {
        self.weight
    }

    /// Returns the instantaneous load.
    pub const fn load(&self) -> Load {
        self.load
    }

    /// Returns the availability fact.
    pub const fn availability(&self) -> Availability {
        self.availability
    }
}

/// Policy strategy recorded in a selection explanation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionStrategy {
    /// Lowest priority, weighted least load, then ascending ID.
    PriorityWeightedLeastLoad,
}

/// Why one candidate was excluded from the final decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExclusionReason {
    /// The immutable snapshot marked the candidate unavailable.
    Unavailable,
    /// The candidate supplied a zero weight.
    ZeroWeight,
    /// A lower numeric priority tier won.
    LowerPriority {
        /// Priority tier that won the evaluation.
        winning_priority: Priority,
    },
    /// Another candidate had a lower weighted load ratio.
    HigherEffectiveLoad {
        /// Candidate with the lower weighted load ratio.
        winning_candidate: CandidateId,
    },
    /// The weighted load ratio tied and the other ID sorted first.
    StableTieBreak {
        /// Candidate selected by the ascending identifier tie-break.
        winning_candidate: CandidateId,
    },
}

/// An excluded candidate and its explainable reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateExclusion {
    candidate_id: CandidateId,
    reason: ExclusionReason,
}

impl CandidateExclusion {
    pub(crate) const fn new(candidate_id: CandidateId, reason: ExclusionReason) -> Self {
        Self {
            candidate_id,
            reason,
        }
    }

    /// Returns the excluded candidate identifier.
    pub fn candidate_id(&self) -> &CandidateId {
        &self.candidate_id
    }

    /// Returns the stable exclusion reason.
    pub const fn reason(&self) -> &ExclusionReason {
        &self.reason
    }
}

/// Deterministic result and explanation of one policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionDecision {
    selected: CandidateId,
    strategy: SelectionStrategy,
    winning_priority: Priority,
    exclusions: Vec<CandidateExclusion>,
}

impl SelectionDecision {
    pub(crate) fn new(
        selected: CandidateId,
        winning_priority: Priority,
        exclusions: Vec<CandidateExclusion>,
    ) -> Self {
        Self {
            selected,
            strategy: SelectionStrategy::PriorityWeightedLeastLoad,
            winning_priority,
            exclusions,
        }
    }

    /// Returns the selected candidate identifier.
    pub fn selected(&self) -> &CandidateId {
        &self.selected
    }

    /// Returns the strategy used to produce this decision.
    pub const fn strategy(&self) -> SelectionStrategy {
        self.strategy
    }

    /// Returns the winning priority tier.
    pub const fn winning_priority(&self) -> Priority {
        self.winning_priority
    }

    /// Returns exclusions in the original candidate input order.
    pub fn exclusions(&self) -> &[CandidateExclusion] {
        &self.exclusions
    }
}

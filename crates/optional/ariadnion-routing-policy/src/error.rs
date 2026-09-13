// crates/optional/ariadnion-routing-policy/src/error.rs - Routing policy errors for Ariadnion.
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

use core::fmt;

/// Stable machine-readable codes for routing policy failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingPolicyErrorCode {
    /// No candidates were supplied.
    EmptyCandidates,
    /// The candidate set exceeded the bounded policy input size.
    TooManyCandidates,
    /// A candidate identifier was empty or exceeded its byte limit.
    InvalidCandidateId,
    /// A candidate identifier appeared more than once in one snapshot.
    DuplicateCandidateId,
    /// A weight exceeded the supported bound.
    WeightOutOfRange,
    /// A load exceeded the supported bound.
    LoadOutOfRange,
    /// Every candidate was filtered out.
    NoEligibleCandidates,
}

impl RoutingPolicyErrorCode {
    /// Returns the stable external error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyCandidates => "ROUTING_POLICY_EMPTY_CANDIDATES",
            Self::TooManyCandidates => "ROUTING_POLICY_TOO_MANY_CANDIDATES",
            Self::InvalidCandidateId => "ROUTING_POLICY_INVALID_CANDIDATE_ID",
            Self::DuplicateCandidateId => "ROUTING_POLICY_DUPLICATE_CANDIDATE_ID",
            Self::WeightOutOfRange => "ROUTING_POLICY_WEIGHT_OUT_OF_RANGE",
            Self::LoadOutOfRange => "ROUTING_POLICY_LOAD_OUT_OF_RANGE",
            Self::NoEligibleCandidates => "ROUTING_POLICY_NO_ELIGIBLE_CANDIDATES",
        }
    }
}

impl fmt::Display for RoutingPolicyErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Structured failure returned by candidate construction or selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingPolicyError {
    code: RoutingPolicyErrorCode,
    detail: &'static str,
}

impl RoutingPolicyError {
    pub(crate) const fn new(code: RoutingPolicyErrorCode, detail: &'static str) -> Self {
        Self { code, detail }
    }

    /// Returns the stable machine-readable code.
    pub const fn code(&self) -> RoutingPolicyErrorCode {
        self.code
    }

    /// Returns a bounded, non-sensitive diagnostic detail.
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for RoutingPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RoutingPolicyError {}

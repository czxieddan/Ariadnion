// crates/optional/ariadnion-routing-coordinator/src/retry.rs - Complete routing coordination for Ariadnion.
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

use ariadnion_routing_failover::{
    AttemptContext, AttemptDecision, AttemptOutcome, CandidateKey, DeterministicFailoverPlanner,
    FailoverDecision, FailoverError, FailureClass, OperationSafety, StreamCommitment,
};

/// Request-bound wrapper around the pure failover state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingRetryPlan {
    planner: DeterministicFailoverPlanner,
    operation: OperationSafety,
}

impl RoutingRetryPlan {
    pub(crate) const fn new(
        planner: DeterministicFailoverPlanner,
        operation: OperationSafety,
    ) -> Self {
        Self { planner, operation }
    }

    /// Classifies one failed provider attempt without permitting post-first-byte switching.
    ///
    /// # Errors
    ///
    /// Returns a stable failover error when the candidate or attempt is outside
    /// the immutable plan.
    pub fn decide(
        &self,
        candidate: &CandidateKey,
        attempt: u8,
        stream: StreamCommitment,
        failure: FailureClass,
    ) -> Result<FailoverDecision, ariadnion_routing_failover::FailoverError> {
        let context = AttemptContext::new(candidate.clone(), attempt, self.operation, stream)?;
        self.planner.decide(&context, failure)
    }

    /// Classifies a typed pre-dispatch refusal or accepted provider failure.
    ///
    /// The immutable plan supplies operation safety and candidate ordering.
    /// `attempt` is one-based; first-byte commitment always prevents switching.
    /// This synchronous delegation performs no admission, dispatch, or I/O.
    ///
    /// # Errors
    /// Returns a stable failover error for an unknown candidate, a zero attempt,
    /// or an attempt beyond the immutable plan's bound.
    pub fn decide_outcome(
        &self,
        candidate: &CandidateKey,
        attempt: u8,
        stream: StreamCommitment,
        outcome: AttemptOutcome,
    ) -> Result<AttemptDecision, FailoverError> {
        let context = AttemptContext::new(candidate.clone(), attempt, self.operation, stream)?;
        self.planner.decide_outcome(&context, outcome)
    }

    /// Returns candidates in deterministic provider-attempt order.
    #[must_use]
    pub fn candidates(&self) -> &[CandidateKey] {
        self.planner.plan().candidates()
    }
}

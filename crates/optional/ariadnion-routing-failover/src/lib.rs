// crates/optional/ariadnion-routing-failover/src/lib.rs - Retry-safe routing failover contracts for Ariadnion.
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
//! Deterministic retry-safe routing failover decisions.
//!
//! The planner classifies provider failures, enforces explicit idempotency
//! boundaries, limits alternate candidates and attempts, and refuses all
//! failover after a stream emits its first byte. It stores no credentials,
//! response bodies, clocks, or mutable global state.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

/// Maximum candidates retained in one ordered failover plan.
pub const MAX_PLAN_CANDIDATES: usize = 32;
/// Maximum attempts permitted by one failover plan.
pub const MAX_ATTEMPTS: u8 = 8;
/// Maximum bytes accepted for a candidate key.
pub const MAX_CANDIDATE_KEY_BYTES: usize = 128;

/// Stable machine-readable failover errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FailoverErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// A plan contains no candidate or exceeds its candidate bound.
    PlanTooLarge,
    /// A candidate key occurs more than once in one plan.
    DuplicateCandidate,
    /// The attempt ordinal is outside the plan's bound.
    AttemptOutOfRange,
    /// The current candidate is absent from the plan.
    CandidateNotInPlan,
    /// A decision was requested for a stream that already committed bytes.
    StreamCommitted,
}

impl FailoverErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ROUTING_FAILOVER_INVALID_ARGUMENT",
            Self::PlanTooLarge => "ROUTING_FAILOVER_PLAN_TOO_LARGE",
            Self::DuplicateCandidate => "ROUTING_FAILOVER_DUPLICATE_CANDIDATE",
            Self::AttemptOutOfRange => "ROUTING_FAILOVER_ATTEMPT_OUT_OF_RANGE",
            Self::CandidateNotInPlan => "ROUTING_FAILOVER_CANDIDATE_NOT_IN_PLAN",
            Self::StreamCommitted => "ROUTING_FAILOVER_STREAM_COMMITTED",
        }
    }
}

impl fmt::Display for FailoverErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted failover error containing only a stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailoverError {
    code: FailoverErrorCode,
}

impl FailoverError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> FailoverErrorCode {
        self.code
    }
}

impl fmt::Display for FailoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for FailoverError {}

/// A bounded, opaque candidate identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateKey(Box<str>);

impl CandidateKey {
    /// Parses a visible ASCII candidate key.
    ///
    /// # Errors
    /// Returns [`FailoverErrorCode::InvalidArgument`] for empty, non-ASCII,
    /// control-containing, or oversized values.
    pub fn parse(value: &str) -> Result<Self, FailoverError> {
        if value.is_empty()
            || value.len() > MAX_CANDIDATE_KEY_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(error(FailoverErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CandidateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CandidateKey")
            .field(&"<opaque>")
            .finish()
    }
}

impl fmt::Display for CandidateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<opaque>")
    }
}

/// Safety boundary for retrying an operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationSafety {
    /// The operation has no externally visible side effect.
    ReadOnly,
    /// Repeating the operation is explicitly idempotent at the provider boundary.
    Idempotent,
    /// Repeating the operation could create a duplicate or irreversible effect.
    NonIdempotent,
}

impl OperationSafety {
    fn permits_retry(self) -> bool {
        matches!(self, Self::ReadOnly | Self::Idempotent)
    }
}

/// Whether the provider stream has emitted its first byte.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StreamCommitment {
    /// No response byte has been emitted.
    Uncommitted,
    /// At least one response byte has been emitted; switching is forbidden.
    FirstByteSent,
}

/// Provider failure class used for deterministic retry decisions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FailureClass {
    /// A connection, timeout, or transport failure before response commitment.
    Transport,
    /// A transient provider/server failure.
    TransientServer,
    /// A rate or concurrency refusal that may be retried on another candidate.
    RateLimited,
    /// Authentication or credential rejection requiring operator action.
    Authentication,
    /// The request is invalid and must not be retried.
    InvalidRequest,
    /// A provider policy or safety rejection that must not be retried.
    Policy,
}

impl FailureClass {
    /// Returns whether this failure can be considered for failover.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Transport | Self::TransientServer | Self::RateLimited
        )
    }
}

/// One ordered, bounded failover plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailoverPlan {
    candidates: Vec<CandidateKey>,
    max_attempts: u8,
}

impl FailoverPlan {
    /// Creates a plan whose first candidate is the primary route.
    ///
    /// Candidates are evaluated in caller-provided order. The planner never
    /// invents candidates and never retries beyond `max_attempts`.
    ///
    /// # Errors
    /// Returns a stable error for empty, oversized, duplicate, or invalid input.
    pub fn new(candidates: Vec<CandidateKey>, max_attempts: u8) -> Result<Self, FailoverError> {
        validate_plan_bounds(candidates.len(), max_attempts)?;
        ensure_unique_candidates(&candidates)?;
        Ok(Self {
            candidates,
            max_attempts,
        })
    }

    /// Returns candidates in deterministic attempt order.
    #[must_use]
    pub fn candidates(&self) -> &[CandidateKey] {
        &self.candidates
    }

    /// Returns the maximum number of attempts.
    #[must_use]
    pub const fn max_attempts(&self) -> u8 {
        self.max_attempts
    }

    fn index_of(&self, candidate: &CandidateKey) -> Option<usize> {
        self.candidates.iter().position(|item| item == candidate)
    }
}

/// Request-scoped context used to evaluate one failed attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptContext {
    candidate: CandidateKey,
    attempt: u8,
    operation: OperationSafety,
    stream: StreamCommitment,
}

impl AttemptContext {
    /// Creates an attempt context. Attempts are one-based.
    ///
    /// # Errors
    /// Returns [`FailoverErrorCode::InvalidArgument`] for attempt zero.
    pub fn new(
        candidate: CandidateKey,
        attempt: u8,
        operation: OperationSafety,
        stream: StreamCommitment,
    ) -> Result<Self, FailoverError> {
        if attempt == 0 {
            return Err(error(FailoverErrorCode::InvalidArgument));
        }
        Ok(Self {
            candidate,
            attempt,
            operation,
            stream,
        })
    }

    /// Returns the candidate used by this attempt.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateKey {
        &self.candidate
    }

    /// Returns the one-based attempt ordinal.
    #[must_use]
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    /// Returns the operation safety boundary.
    #[must_use]
    pub const fn operation(&self) -> OperationSafety {
        self.operation
    }

    /// Returns the stream commitment state.
    #[must_use]
    pub const fn stream(&self) -> StreamCommitment {
        self.stream
    }
}

/// Deterministic action after classifying one provider failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailoverAction {
    /// Repeat the same candidate before exhausting the attempt budget.
    RetrySame,
    /// Switch to the next candidate in the immutable plan.
    SwitchCandidate(CandidateKey),
    /// Stop without another provider attempt.
    Stop,
}

/// A redacted, deterministic failover decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailoverDecision {
    action: FailoverAction,
    failure: FailureClass,
}

impl FailoverDecision {
    fn new(action: FailoverAction, failure: FailureClass) -> Self {
        Self { action, failure }
    }

    /// Returns the action to execute.
    #[must_use]
    pub const fn action(&self) -> &FailoverAction {
        &self.action
    }

    /// Returns the classified failure.
    #[must_use]
    pub const fn failure(&self) -> FailureClass {
        self.failure
    }
}

/// Pure planner implementing retry and first-byte commitment rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicFailoverPlanner {
    plan: FailoverPlan,
}

impl DeterministicFailoverPlanner {
    /// Creates a planner from an immutable ordered plan.
    #[must_use]
    pub const fn new(plan: FailoverPlan) -> Self {
        Self { plan }
    }

    /// Returns the immutable plan.
    #[must_use]
    pub const fn plan(&self) -> &FailoverPlan {
        &self.plan
    }

    /// Evaluates one failure without exposing response data or secrets.
    ///
    /// Retryable failures may retry only for read-only or explicitly idempotent
    /// operations. Once the first stream byte is sent, the result is always
    /// [`FailoverAction::Stop`]. Candidate order and attempt limits are fixed by
    /// the plan, so equal inputs produce equal decisions.
    ///
    /// # Errors
    /// Returns a stable error when the candidate is absent or the attempt is
    /// outside the configured bound.
    pub fn decide(
        &self,
        context: &AttemptContext,
        failure: FailureClass,
    ) -> Result<FailoverDecision, FailoverError> {
        let index = self
            .plan
            .index_of(context.candidate())
            .ok_or_else(|| error(FailoverErrorCode::CandidateNotInPlan))?;
        validate_attempt(context, self.plan.max_attempts)?;
        if should_stop(context, failure, self.plan.max_attempts) {
            return Ok(FailoverDecision::new(FailoverAction::Stop, failure));
        }
        let action = next_action(&self.plan, index);
        Ok(FailoverDecision::new(action, failure))
    }
}

fn validate_plan_bounds(candidate_count: usize, max_attempts: u8) -> Result<(), FailoverError> {
    if candidate_count == 0 || candidate_count > MAX_PLAN_CANDIDATES {
        return Err(error(FailoverErrorCode::PlanTooLarge));
    }
    if !(1..=MAX_ATTEMPTS).contains(&max_attempts) {
        return Err(error(FailoverErrorCode::InvalidArgument));
    }
    Ok(())
}

fn ensure_unique_candidates(candidates: &[CandidateKey]) -> Result<(), FailoverError> {
    let mut seen = std::collections::BTreeSet::new();
    for candidate in candidates {
        if !seen.insert(candidate) {
            return Err(error(FailoverErrorCode::DuplicateCandidate));
        }
    }
    Ok(())
}

fn validate_attempt(context: &AttemptContext, max_attempts: u8) -> Result<(), FailoverError> {
    if context.attempt() > max_attempts {
        return Err(error(FailoverErrorCode::AttemptOutOfRange));
    }
    Ok(())
}

fn should_stop(context: &AttemptContext, failure: FailureClass, max_attempts: u8) -> bool {
    context.stream() == StreamCommitment::FirstByteSent
        || !failure.is_retryable()
        || !context.operation().permits_retry()
        || context.attempt() >= max_attempts
}

fn next_action(plan: &FailoverPlan, index: usize) -> FailoverAction {
    plan.candidates
        .get(index + 1)
        .cloned()
        .map_or(FailoverAction::RetrySame, FailoverAction::SwitchCandidate)
}

/// Read-only port for failover decision consumers.
pub trait FailoverDecisionPort: Send + Sync {
    /// Evaluates one failed attempt against the configured immutable plan.
    fn decide(
        &self,
        context: &AttemptContext,
        failure: FailureClass,
    ) -> Result<FailoverDecision, FailoverError>;
}

impl FailoverDecisionPort for DeterministicFailoverPlanner {
    fn decide(
        &self,
        context: &AttemptContext,
        failure: FailureClass,
    ) -> Result<FailoverDecision, FailoverError> {
        Self::decide(self, context, failure)
    }
}

const fn error(code: FailoverErrorCode) -> FailoverError {
    FailoverError { code }
}

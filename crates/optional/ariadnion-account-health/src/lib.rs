// crates/optional/ariadnion-account-health/src/lib.rs - Account health aggregation for Ariadnion.
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
//! Deterministic active and passive account health aggregation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_account_domain::AccountId;
use std::fmt;
use std::sync::{Arc, RwLock};

const MAX_THRESHOLD: u32 = 1 << 20;

/// Maximum number of account snapshots in one published health state.
pub const MAX_SNAPSHOTS: usize = 1 << 12;

/// Stable machine-readable account-health failure codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AccountHealthErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// A degraded threshold is greater than the unhealthy threshold.
    InvalidThresholdOrder,
    /// An observation sequence is not strictly newer than the last accepted one.
    ObservationOutOfOrder,
    /// An observation timestamp is older than the last accepted timestamp.
    TimestampOutOfOrder,
    /// An observation belongs to another account.
    AccountMismatch,
    /// A revision or counter cannot advance without wrapping.
    VersionExhausted,
    /// The authoritative snapshot lock is unavailable.
    StateUnavailable,
    /// A batch exceeds the maximum number of account snapshots.
    LimitExceeded,
    /// A publication was based on an obsolete generation.
    GenerationConflict,
    /// A batch contains more than one snapshot for an account identity.
    DuplicateSnapshot,
    /// The publication generation cannot advance without wrapping.
    GenerationExhausted,
}

impl AccountHealthErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ACCOUNT_HEALTH_INVALID_ARGUMENT",
            Self::InvalidThresholdOrder => "ACCOUNT_HEALTH_INVALID_THRESHOLD_ORDER",
            Self::ObservationOutOfOrder => "ACCOUNT_HEALTH_OBSERVATION_OUT_OF_ORDER",
            Self::TimestampOutOfOrder => "ACCOUNT_HEALTH_TIMESTAMP_OUT_OF_ORDER",
            Self::AccountMismatch => "ACCOUNT_HEALTH_ACCOUNT_MISMATCH",
            Self::VersionExhausted => "ACCOUNT_HEALTH_VERSION_EXHAUSTED",
            Self::StateUnavailable => "ACCOUNT_HEALTH_STATE_UNAVAILABLE",
            Self::LimitExceeded => "ACCOUNT_HEALTH_LIMIT_EXCEEDED",
            Self::GenerationConflict => "ACCOUNT_HEALTH_GENERATION_CONFLICT",
            Self::DuplicateSnapshot => "ACCOUNT_HEALTH_DUPLICATE_SNAPSHOT",
            Self::GenerationExhausted => "ACCOUNT_HEALTH_GENERATION_EXHAUSTED",
        }
    }
}

impl fmt::Display for AccountHealthErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted account-health failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountHealthError {
    code: AccountHealthErrorCode,
}

impl AccountHealthError {
    const fn new(code: AccountHealthErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AccountHealthErrorCode {
        self.code
    }
}

impl fmt::Display for AccountHealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AccountHealthError {}

/// A strictly positive sequence assigned by the observation source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObservationSequence(u64);

impl ObservationSequence {
    /// Creates a non-zero observation sequence.
    ///
    /// # Errors
    /// Returns [`AccountHealthErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, AccountHealthError> {
        if value == 0 {
            Err(error(AccountHealthErrorCode::InvalidArgument))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A UTC Unix timestamp in milliseconds supplied by an observation source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcMillis(u64);

impl UtcMillis {
    /// Creates a UTC millisecond timestamp.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the Unix millisecond value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Source category for a health observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HealthSource {
    /// A probe initiated by the health subsystem.
    ActiveProbe,
    /// A result observed while serving a normal request.
    PassiveRequest,
}

/// Result classified at the provider boundary without exposing response data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HealthSignal {
    /// The account completed the observed operation successfully.
    Success,
    /// The account failed in a way that may recover on a later attempt.
    RetryableFailure,
    /// The account is known to be unusable until an explicit recovery sequence.
    TerminalFailure,
}

/// Health state exposed to candidate selectors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HealthState {
    /// No observation has been accepted yet.
    Unknown,
    /// The account is eligible for normal selection.
    Healthy,
    /// The account is eligible only when a policy permits degraded candidates.
    Degraded,
    /// The account must be excluded until recovery succeeds.
    Unhealthy,
}

/// Thresholds controlling deterministic health transitions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HealthPolicy {
    degraded_after_failures: u32,
    unhealthy_after_failures: u32,
    recovery_successes: u32,
}

impl HealthPolicy {
    /// Creates bounded failure and recovery thresholds.
    ///
    /// # Errors
    /// Returns [`AccountHealthErrorCode::InvalidArgument`] for zero or overly
    /// large thresholds, and [`AccountHealthErrorCode::InvalidThresholdOrder`]
    /// when the degraded threshold exceeds the unhealthy threshold.
    pub fn new(
        degraded_after_failures: u32,
        unhealthy_after_failures: u32,
        recovery_successes: u32,
    ) -> Result<Self, AccountHealthError> {
        let bounded = [
            degraded_after_failures,
            unhealthy_after_failures,
            recovery_successes,
        ]
        .into_iter()
        .all(|value| (1..=MAX_THRESHOLD).contains(&value));
        if !bounded {
            return Err(error(AccountHealthErrorCode::InvalidArgument));
        }
        if degraded_after_failures > unhealthy_after_failures {
            return Err(error(AccountHealthErrorCode::InvalidThresholdOrder));
        }
        Ok(Self {
            degraded_after_failures,
            unhealthy_after_failures,
            recovery_successes,
        })
    }

    /// Returns the failure count that enters the degraded state.
    #[must_use]
    pub const fn degraded_after_failures(self) -> u32 {
        self.degraded_after_failures
    }

    /// Returns the failure count that enters the unhealthy state.
    #[must_use]
    pub const fn unhealthy_after_failures(self) -> u32 {
        self.unhealthy_after_failures
    }

    /// Returns the consecutive success count required to recover.
    #[must_use]
    pub const fn recovery_successes(self) -> u32 {
        self.recovery_successes
    }
}

/// One ordered active or passive observation for an account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthObservation {
    account_id: AccountId,
    sequence: ObservationSequence,
    observed_at: UtcMillis,
    source: HealthSource,
    signal: HealthSignal,
}

impl HealthObservation {
    /// Creates an observation with caller-supplied ordering metadata.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        sequence: ObservationSequence,
        observed_at: UtcMillis,
        source: HealthSource,
        signal: HealthSignal,
    ) -> Self {
        Self {
            account_id,
            sequence,
            observed_at,
            source,
            signal,
        }
    }

    /// Returns the observed account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the source-assigned sequence.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns the UTC observation timestamp.
    #[must_use]
    pub const fn observed_at(&self) -> UtcMillis {
        self.observed_at
    }

    /// Returns whether the observation came from an active or passive source.
    #[must_use]
    pub const fn source(&self) -> HealthSource {
        self.source
    }

    /// Returns the classified result.
    #[must_use]
    pub const fn signal(&self) -> HealthSignal {
        self.signal
    }
}

/// Immutable health snapshot published after an accepted observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    account_id: AccountId,
    revision: u64,
    state: HealthState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_sequence: Option<ObservationSequence>,
    last_observed_at: Option<UtcMillis>,
    last_source: Option<HealthSource>,
}

impl HealthSnapshot {
    fn initial(account_id: AccountId) -> Self {
        Self {
            account_id,
            revision: 0,
            state: HealthState::Unknown,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_sequence: None,
            last_observed_at: None,
            last_source: None,
        }
    }

    /// Returns the account identity represented by this snapshot.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the number of accepted observations.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the current health state.
    #[must_use]
    pub const fn state(&self) -> HealthState {
        self.state
    }

    /// Returns the consecutive retryable-failure count.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Returns the consecutive recovery-success count.
    #[must_use]
    pub const fn consecutive_successes(&self) -> u32 {
        self.consecutive_successes
    }

    /// Returns the latest accepted observation sequence, if any.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<ObservationSequence> {
        self.last_sequence
    }

    /// Returns the latest accepted UTC timestamp, if any.
    #[must_use]
    pub const fn last_observed_at(&self) -> Option<UtcMillis> {
        self.last_observed_at
    }

    /// Returns the source category of the latest observation, if any.
    #[must_use]
    pub const fn last_source(&self) -> Option<HealthSource> {
        self.last_source
    }
}

/// A strictly monotonic publication generation for a health snapshot set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HealthGeneration(u64);

impl HealthGeneration {
    /// Returns the initial empty-state generation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Creates a generation from a persisted value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, AccountHealthError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AccountHealthErrorCode::GenerationExhausted))
    }
}

/// An immutable, sorted set of account health snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshotSet {
    generation: HealthGeneration,
    snapshots: Arc<[HealthSnapshot]>,
}

impl HealthSnapshotSet {
    /// Returns the publication generation.
    #[must_use]
    pub const fn generation(&self) -> HealthGeneration {
        self.generation
    }

    /// Returns snapshots sorted by account identity.
    #[must_use]
    pub fn snapshots(&self) -> &[HealthSnapshot] {
        &self.snapshots
    }
}

#[derive(Debug)]
struct HealthBookState {
    generation: HealthGeneration,
    snapshots: Arc<[HealthSnapshot]>,
}

/// Evidence returned after a successful health publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshReceipt {
    previous_generation: HealthGeneration,
    generation: HealthGeneration,
    snapshot_count: usize,
}

impl RefreshReceipt {
    /// Returns the generation replaced by the publication.
    #[must_use]
    pub const fn previous_generation(&self) -> HealthGeneration {
        self.previous_generation
    }

    /// Returns the newly committed generation.
    #[must_use]
    pub const fn generation(&self) -> HealthGeneration {
        self.generation
    }

    /// Returns the number of snapshots committed.
    #[must_use]
    pub const fn snapshot_count(&self) -> usize {
        self.snapshot_count
    }
}

/// Read-only port for consumers that need the complete health snapshot set.
pub trait HealthSnapshotSetPort: Send + Sync {
    /// Returns the latest immutable health snapshot set.
    ///
    /// # Errors
    /// Returns [`AccountHealthErrorCode::StateUnavailable`] when authoritative
    /// state cannot be read.
    fn snapshot_set(&self) -> Result<Arc<HealthSnapshotSet>, AccountHealthError>;

    /// Returns the latest immutable health snapshot set.
    fn snapshot(&self) -> Result<Arc<HealthSnapshotSet>, AccountHealthError> {
        self.snapshot_set()
    }
}

/// Concurrent owner for bounded, generation-checked health snapshot sets.
#[derive(Debug)]
pub struct HealthSnapshotBook {
    state: RwLock<HealthBookState>,
}

impl Default for HealthSnapshotBook {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthSnapshotBook {
    /// Creates an empty health snapshot book at generation zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(HealthBookState {
                generation: HealthGeneration::initial(),
                snapshots: Arc::from([]),
            }),
        }
    }

    /// Returns the current publication generation.
    ///
    /// # Errors
    /// Returns [`AccountHealthErrorCode::StateUnavailable`] when the lock is
    /// poisoned.
    pub fn generation(&self) -> Result<HealthGeneration, AccountHealthError> {
        self.state
            .read()
            .map(|state| state.generation)
            .map_err(|_| error(AccountHealthErrorCode::StateUnavailable))
    }

    /// Atomically replaces all health snapshots after validating the batch.
    ///
    /// Validation and sorting occur before state mutation. A caller must supply
    /// the generation it observed, so stale writers are rejected without
    /// disturbing a previously published set.
    ///
    /// # Errors
    /// Returns a stable bound, duplicate, generation, or state error.
    pub fn refresh(
        &self,
        mut snapshots: Vec<HealthSnapshot>,
        expected_generation: HealthGeneration,
    ) -> Result<RefreshReceipt, AccountHealthError> {
        validate_snapshot_batch(&mut snapshots)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountHealthErrorCode::StateUnavailable))?;
        if state.generation != expected_generation {
            return Err(error(AccountHealthErrorCode::GenerationConflict));
        }
        let generation = state.generation.next()?;
        let previous_generation = state.generation;
        state.generation = generation;
        state.snapshots = snapshots.into();
        Ok(RefreshReceipt {
            previous_generation,
            generation,
            snapshot_count: state.snapshots.len(),
        })
    }

    /// Returns a shared immutable health snapshot set.
    ///
    /// # Errors
    /// Returns [`AccountHealthErrorCode::StateUnavailable`] when the lock is
    /// poisoned.
    pub fn snapshot_set(&self) -> Result<Arc<HealthSnapshotSet>, AccountHealthError> {
        self.state
            .read()
            .map(|state| {
                Arc::new(HealthSnapshotSet {
                    generation: state.generation,
                    snapshots: Arc::clone(&state.snapshots),
                })
            })
            .map_err(|_| error(AccountHealthErrorCode::StateUnavailable))
    }

    /// Returns the latest immutable health snapshot set.
    pub fn snapshot(&self) -> Result<Arc<HealthSnapshotSet>, AccountHealthError> {
        self.snapshot_set()
    }
}

impl HealthSnapshotSetPort for HealthSnapshotBook {
    fn snapshot_set(&self) -> Result<Arc<HealthSnapshotSet>, AccountHealthError> {
        self.snapshot_set()
    }
}

/// Read-only port for consumers that only need the latest health snapshot.
pub trait HealthSnapshotPort: Send + Sync {
    /// Returns the current immutable health snapshot.
    ///
    /// # Errors
    /// Returns [`AccountHealthErrorCode::StateUnavailable`] when the
    /// implementation cannot read its authoritative state.
    fn snapshot(&self) -> Result<Arc<HealthSnapshot>, AccountHealthError>;
}

/// Concurrent account health reducer with atomic snapshot publication.
#[derive(Debug)]
pub struct AccountHealth {
    account_id: AccountId,
    snapshot: RwLock<HealthSnapshot>,
}

impl AccountHealth {
    /// Creates an account health reducer with an unknown initial state.
    #[must_use]
    pub fn new(account_id: AccountId) -> Self {
        Self {
            snapshot: RwLock::new(HealthSnapshot::initial(account_id.clone())),
            account_id,
        }
    }

    /// Returns the account identity owned by this reducer.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Applies one ordered observation and publishes the resulting snapshot.
    ///
    /// The write lock covers validation and replacement, so concurrent sources
    /// cannot publish a partially updated state. Rejected observations leave the
    /// previous snapshot untouched.
    ///
    /// # Errors
    /// Returns a stable account, ordering, counter, or state error.
    pub fn observe(
        &self,
        observation: HealthObservation,
        policy: HealthPolicy,
    ) -> Result<HealthSnapshot, AccountHealthError> {
        let mut current = self
            .snapshot
            .write()
            .map_err(|_| error(AccountHealthErrorCode::StateUnavailable))?;
        validate_observation(&self.account_id, &current, &observation)?;
        let next = reduce_snapshot(&current, &observation, policy)?;
        *current = next.clone();
        Ok(next)
    }

    /// Returns the latest immutable snapshot.
    ///
    /// # Errors
    /// Returns [`AccountHealthErrorCode::StateUnavailable`] if a prior panic
    /// poisoned the internal lock.
    pub fn snapshot(&self) -> Result<HealthSnapshot, AccountHealthError> {
        self.snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| error(AccountHealthErrorCode::StateUnavailable))
    }
}

impl HealthSnapshotPort for AccountHealth {
    fn snapshot(&self) -> Result<Arc<HealthSnapshot>, AccountHealthError> {
        self.snapshot
            .read()
            .map(|snapshot| Arc::new(snapshot.clone()))
            .map_err(|_| error(AccountHealthErrorCode::StateUnavailable))
    }
}

fn validate_observation(
    account_id: &AccountId,
    current: &HealthSnapshot,
    observation: &HealthObservation,
) -> Result<(), AccountHealthError> {
    if observation.account_id() != account_id {
        return Err(error(AccountHealthErrorCode::AccountMismatch));
    }
    if current
        .last_sequence
        .is_some_and(|sequence| observation.sequence <= sequence)
    {
        return Err(error(AccountHealthErrorCode::ObservationOutOfOrder));
    }
    if current
        .last_observed_at
        .is_some_and(|timestamp| observation.observed_at < timestamp)
    {
        return Err(error(AccountHealthErrorCode::TimestampOutOfOrder));
    }
    Ok(())
}

fn reduce_snapshot(
    current: &HealthSnapshot,
    observation: &HealthObservation,
    policy: HealthPolicy,
) -> Result<HealthSnapshot, AccountHealthError> {
    let revision = current
        .revision
        .checked_add(1)
        .ok_or_else(|| error(AccountHealthErrorCode::VersionExhausted))?;
    let mut next = current.clone();
    next.revision = revision;
    next.last_sequence = Some(observation.sequence);
    next.last_observed_at = Some(observation.observed_at);
    next.last_source = Some(observation.source);
    match observation.signal {
        HealthSignal::Success => apply_success(&mut next, current.state, policy)?,
        HealthSignal::RetryableFailure => {
            apply_retryable_failure(&mut next, current.state, policy)?
        }
        HealthSignal::TerminalFailure => apply_terminal_failure(&mut next, policy),
    }
    Ok(next)
}

fn apply_success(
    snapshot: &mut HealthSnapshot,
    previous_state: HealthState,
    policy: HealthPolicy,
) -> Result<(), AccountHealthError> {
    snapshot.consecutive_failures = 0;
    snapshot.consecutive_successes = snapshot
        .consecutive_successes
        .checked_add(1)
        .ok_or_else(|| error(AccountHealthErrorCode::VersionExhausted))?;
    if previous_state != HealthState::Unhealthy
        || snapshot.consecutive_successes >= policy.recovery_successes
    {
        snapshot.state = HealthState::Healthy;
    }
    Ok(())
}

fn apply_retryable_failure(
    snapshot: &mut HealthSnapshot,
    previous_state: HealthState,
    policy: HealthPolicy,
) -> Result<(), AccountHealthError> {
    snapshot.consecutive_successes = 0;
    snapshot.consecutive_failures = snapshot
        .consecutive_failures
        .checked_add(1)
        .ok_or_else(|| error(AccountHealthErrorCode::VersionExhausted))?;
    snapshot.state = failure_state(previous_state, snapshot.consecutive_failures, policy);
    Ok(())
}

fn apply_terminal_failure(snapshot: &mut HealthSnapshot, policy: HealthPolicy) {
    snapshot.consecutive_successes = 0;
    snapshot.consecutive_failures = policy.unhealthy_after_failures;
    snapshot.state = HealthState::Unhealthy;
}

fn failure_state(previous_state: HealthState, failures: u32, policy: HealthPolicy) -> HealthState {
    if failures >= policy.unhealthy_after_failures {
        HealthState::Unhealthy
    } else if failures >= policy.degraded_after_failures {
        HealthState::Degraded
    } else if previous_state == HealthState::Unknown {
        HealthState::Unknown
    } else {
        HealthState::Healthy
    }
}

fn validate_snapshot_batch(snapshots: &mut [HealthSnapshot]) -> Result<(), AccountHealthError> {
    if snapshots.len() > MAX_SNAPSHOTS {
        return Err(error(AccountHealthErrorCode::LimitExceeded));
    }
    snapshots.sort_by(|left, right| left.account_id.cmp(&right.account_id));
    if snapshots
        .windows(2)
        .any(|pair| pair[0].account_id == pair[1].account_id)
    {
        return Err(error(AccountHealthErrorCode::DuplicateSnapshot));
    }
    Ok(())
}

const fn error(code: AccountHealthErrorCode) -> AccountHealthError {
    AccountHealthError::new(code)
}

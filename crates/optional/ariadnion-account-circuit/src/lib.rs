// crates/optional/ariadnion-account-circuit/src/lib.rs - Account circuit breaker contracts for Ariadnion.
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
//! Deterministic fail-closed account circuit breaking with half-open leases.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_account_domain::AccountId;
use std::fmt;
use std::sync::{Arc, RwLock};

const MAX_THRESHOLD: u32 = 1_000_000;
const MAX_WINDOW_MILLIS: u64 = 86_400_000;
const MAX_LEASE_MILLIS: u64 = 300_000;
const MAX_PROBES: u16 = 128;

/// Stable machine-readable circuit errors.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AccountCircuitErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// The supplied account does not own this circuit.
    AccountMismatch,
    /// The caller used a stale circuit generation.
    GenerationConflict,
    /// The supplied monotonic or UTC value precedes the accepted value.
    TimestampOutOfOrder,
    /// The requested operation is not valid in the current state.
    InvalidTransition,
    /// The recovery window has not elapsed.
    RecoveryWindowClosed,
    /// No half-open probe slot is available.
    ProbeLimitReached,
    /// The account requires an explicit administrative reset before probing.
    AdministrativeResetRequired,
    /// A probe lease is unknown, already completed, or belongs to another generation.
    LeaseConflict,
    /// A probe lease exceeded its bounded lifetime.
    LeaseExpired,
    /// A revision or lease identifier cannot advance without wrapping.
    VersionExhausted,
    /// The authoritative snapshot lock is unavailable.
    StateUnavailable,
}

impl AccountCircuitErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        const CODES: [&str; 12] = [
            "ACCOUNT_CIRCUIT_INVALID_ARGUMENT",
            "ACCOUNT_CIRCUIT_ACCOUNT_MISMATCH",
            "ACCOUNT_CIRCUIT_GENERATION_CONFLICT",
            "ACCOUNT_CIRCUIT_TIMESTAMP_OUT_OF_ORDER",
            "ACCOUNT_CIRCUIT_INVALID_TRANSITION",
            "ACCOUNT_CIRCUIT_RECOVERY_WINDOW_CLOSED",
            "ACCOUNT_CIRCUIT_PROBE_LIMIT_REACHED",
            "ACCOUNT_CIRCUIT_ADMINISTRATIVE_RESET_REQUIRED",
            "ACCOUNT_CIRCUIT_LEASE_CONFLICT",
            "ACCOUNT_CIRCUIT_LEASE_EXPIRED",
            "ACCOUNT_CIRCUIT_VERSION_EXHAUSTED",
            "ACCOUNT_CIRCUIT_STATE_UNAVAILABLE",
        ];
        CODES[self as usize]
    }
}

impl fmt::Display for AccountCircuitErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted circuit failure that never retains account secrets or payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountCircuitError {
    code: AccountCircuitErrorCode,
}

impl AccountCircuitError {
    const fn new(code: AccountCircuitErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AccountCircuitErrorCode {
        self.code
    }
}

impl fmt::Display for AccountCircuitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AccountCircuitError {}

/// Monotonic millisecond reading used for lease expiry and ordering.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(u64);

impl MonotonicMillis {
    /// Creates a bounded monotonic reading.
    ///
    /// # Errors
    /// Returns [`AccountCircuitErrorCode::InvalidArgument`] above the supported
    /// `u64` range reserved for future clock calibration.
    pub const fn new(value: u64) -> Result<Self, AccountCircuitError> {
        if value > 9_000_000_000_000_000 {
            Err(error(AccountCircuitErrorCode::InvalidArgument))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the monotonic millisecond value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// UTC Unix timestamp in milliseconds.
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

/// Monotonic generation used for optimistic circuit updates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CircuitGeneration(u64);

impl CircuitGeneration {
    /// Returns the initial generation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Creates a generation value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, AccountCircuitError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AccountCircuitErrorCode::VersionExhausted))
    }
}

/// Circuit breaker state visible to selectors and health reporting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CircuitState {
    /// Requests may proceed normally.
    Closed,
    /// Requests fail closed until the recovery window elapses.
    Open,
    /// A bounded number of recovery probes may run.
    HalfOpen,
    /// The account is permanently unavailable until an administrative reset.
    Terminal,
}

/// Result classified at the provider boundary without retaining response data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CircuitOutcome {
    /// The operation completed successfully.
    Success,
    /// The operation failed in a potentially recoverable way.
    RetryableFailure,
    /// The account is unusable until an explicit administrative change.
    TerminalFailure,
}

/// Bounded thresholds and windows governing deterministic transitions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CircuitPolicy {
    failure_threshold: u32,
    recovery_successes: u32,
    recovery_window_millis: u64,
    probe_lease_millis: u64,
    max_half_open_probes: u16,
}

impl CircuitPolicy {
    /// Creates a bounded circuit policy.
    ///
    /// # Errors
    /// Returns [`AccountCircuitErrorCode::InvalidArgument`] for zero or
    /// excessive thresholds, windows, or probe counts.
    pub fn new(
        failure_threshold: u32,
        recovery_successes: u32,
        recovery_window_millis: u64,
        probe_lease_millis: u64,
        max_half_open_probes: u16,
    ) -> Result<Self, AccountCircuitError> {
        let valid = (1..=MAX_THRESHOLD).contains(&failure_threshold)
            && (1..=MAX_THRESHOLD).contains(&recovery_successes)
            && (1..=MAX_WINDOW_MILLIS).contains(&recovery_window_millis)
            && (1..=MAX_LEASE_MILLIS).contains(&probe_lease_millis)
            && (1..=MAX_PROBES).contains(&max_half_open_probes);
        if !valid {
            return Err(error(AccountCircuitErrorCode::InvalidArgument));
        }
        Ok(Self {
            failure_threshold,
            recovery_successes,
            recovery_window_millis,
            probe_lease_millis,
            max_half_open_probes,
        })
    }

    /// Returns the failures required to open the circuit.
    #[must_use]
    pub const fn failure_threshold(self) -> u32 {
        self.failure_threshold
    }

    /// Returns the successes required to close a half-open circuit.
    #[must_use]
    pub const fn recovery_successes(self) -> u32 {
        self.recovery_successes
    }

    /// Returns the open-state recovery window in milliseconds.
    #[must_use]
    pub const fn recovery_window_millis(self) -> u64 {
        self.recovery_window_millis
    }

    /// Returns the maximum probe lease lifetime in milliseconds.
    #[must_use]
    pub const fn probe_lease_millis(self) -> u64 {
        self.probe_lease_millis
    }

    /// Returns the maximum concurrent half-open probes.
    #[must_use]
    pub const fn max_half_open_probes(self) -> u16 {
        self.max_half_open_probes
    }
}

/// An observation accepted by a closed circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitObservation {
    account_id: AccountId,
    generation: CircuitGeneration,
    observed_at: UtcMillis,
    monotonic: MonotonicMillis,
    outcome: CircuitOutcome,
}

impl CircuitObservation {
    /// Creates a generation-checked observation.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        generation: CircuitGeneration,
        observed_at: UtcMillis,
        monotonic: MonotonicMillis,
        outcome: CircuitOutcome,
    ) -> Self {
        Self {
            account_id,
            generation,
            observed_at,
            monotonic,
            outcome,
        }
    }

    /// Returns the account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the expected circuit generation.
    #[must_use]
    pub const fn generation(&self) -> CircuitGeneration {
        self.generation
    }

    /// Returns the UTC observation timestamp.
    #[must_use]
    pub const fn observed_at(&self) -> UtcMillis {
        self.observed_at
    }

    /// Returns the monotonic observation reading.
    #[must_use]
    pub const fn monotonic(&self) -> MonotonicMillis {
        self.monotonic
    }

    /// Returns the classified outcome.
    #[must_use]
    pub const fn outcome(&self) -> CircuitOutcome {
        self.outcome
    }
}

/// Opaque identifier for one half-open probe lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProbeLeaseId(u64);

impl ProbeLeaseId {
    /// Returns the numeric lease identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Capability proving admission to one half-open probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeLease {
    account_id: AccountId,
    generation: CircuitGeneration,
    id: ProbeLeaseId,
    issued_at: MonotonicMillis,
    expires_at: MonotonicMillis,
}

impl ProbeLease {
    /// Returns the account identity bound to this lease.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the circuit generation bound to this lease.
    #[must_use]
    pub const fn generation(&self) -> CircuitGeneration {
        self.generation
    }

    /// Returns the opaque lease id.
    #[must_use]
    pub const fn id(&self) -> ProbeLeaseId {
        self.id
    }

    /// Returns the monotonic issuance reading.
    #[must_use]
    pub const fn issued_at(&self) -> MonotonicMillis {
        self.issued_at
    }

    /// Returns the monotonic expiry reading.
    #[must_use]
    pub const fn expires_at(&self) -> MonotonicMillis {
        self.expires_at
    }
}

/// Immutable snapshot published after each accepted transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitSnapshot {
    account_id: AccountId,
    generation: CircuitGeneration,
    state: CircuitState,
    consecutive_failures: u32,
    recovery_successes: u32,
    half_open_in_flight: u16,
    opened_at: Option<UtcMillis>,
    last_observed_at: Option<UtcMillis>,
    last_monotonic: Option<MonotonicMillis>,
}

impl CircuitSnapshot {
    fn initial(account_id: AccountId) -> Self {
        Self {
            account_id,
            generation: CircuitGeneration::initial(),
            state: CircuitState::Closed,
            consecutive_failures: 0,
            recovery_successes: 0,
            half_open_in_flight: 0,
            opened_at: None,
            last_observed_at: None,
            last_monotonic: None,
        }
    }

    /// Returns the account identity represented by this snapshot.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the optimistic circuit generation.
    #[must_use]
    pub const fn generation(&self) -> CircuitGeneration {
        self.generation
    }

    /// Returns the current breaker state.
    #[must_use]
    pub const fn state(&self) -> CircuitState {
        self.state
    }

    /// Returns consecutive failures observed while closed.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Returns successful recovery probes accepted in half-open state.
    #[must_use]
    pub const fn recovery_successes(&self) -> u32 {
        self.recovery_successes
    }

    /// Returns the number of outstanding half-open leases.
    #[must_use]
    pub const fn half_open_in_flight(&self) -> u16 {
        self.half_open_in_flight
    }

    /// Returns when the circuit entered open state.
    #[must_use]
    pub const fn opened_at(&self) -> Option<UtcMillis> {
        self.opened_at
    }

    /// Returns the latest accepted UTC timestamp.
    #[must_use]
    pub const fn last_observed_at(&self) -> Option<UtcMillis> {
        self.last_observed_at
    }

    /// Returns the latest accepted monotonic reading.
    #[must_use]
    pub const fn last_monotonic(&self) -> Option<MonotonicMillis> {
        self.last_monotonic
    }
}

/// Read-only port for consumers that need the latest circuit snapshot.
pub trait CircuitSnapshotPort: Send + Sync {
    /// Returns the current immutable snapshot.
    ///
    /// # Errors
    /// Returns [`AccountCircuitErrorCode::StateUnavailable`] when the
    /// authoritative state cannot be read.
    fn snapshot(&self) -> Result<Arc<CircuitSnapshot>, AccountCircuitError>;
}

#[derive(Clone, Debug)]
struct LeaseRecord {
    id: ProbeLeaseId,
}

#[derive(Debug)]
struct CircuitStateData {
    snapshot: CircuitSnapshot,
    leases: Vec<LeaseRecord>,
    next_lease_id: u64,
}

/// Concurrent deterministic account circuit breaker.
#[derive(Debug)]
pub struct AccountCircuit {
    account_id: AccountId,
    policy: CircuitPolicy,
    state: RwLock<CircuitStateData>,
}

impl AccountCircuit {
    /// Creates a closed circuit for one account.
    #[must_use]
    pub fn new(account_id: AccountId, policy: CircuitPolicy) -> Self {
        Self {
            state: RwLock::new(CircuitStateData {
                snapshot: CircuitSnapshot::initial(account_id.clone()),
                leases: Vec::new(),
                next_lease_id: 1,
            }),
            account_id,
            policy,
        }
    }

    /// Returns the account identity owned by this circuit.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the configured deterministic policy.
    #[must_use]
    pub const fn policy(&self) -> CircuitPolicy {
        self.policy
    }

    /// Applies one ordered closed-state observation.
    ///
    /// A retryable threshold opens the circuit; a terminal failure enters the
    /// administrative-only terminal state. Rejected observations leave the
    /// prior snapshot and leases untouched.
    ///
    /// # Errors
    /// Returns stable account, generation, ordering, transition, or state errors.
    pub fn observe(
        &self,
        observation: CircuitObservation,
    ) -> Result<CircuitSnapshot, AccountCircuitError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountCircuitErrorCode::StateUnavailable))?;
        validate_observation(&self.account_id, &state.snapshot, &observation)?;
        if state.snapshot.state != CircuitState::Closed {
            return Err(error(AccountCircuitErrorCode::InvalidTransition));
        }
        let mut next = state.snapshot.clone();
        advance_clock(
            &mut next,
            observation.observed_at(),
            observation.monotonic(),
        );
        apply_closed_outcome(&mut next, observation.outcome(), self.policy)?;
        if next.state != state.snapshot.state {
            next.generation = next.generation.next()?;
        }
        state.snapshot = next.clone();
        Ok(next)
    }

    /// Admits one bounded recovery probe after the open window elapsed.
    ///
    /// The lease binds account, generation, and a monotonic expiry. Callers must
    /// complete it exactly once with [`Self::complete_probe`].
    ///
    /// # Errors
    /// Returns a stable generation, ordering, transition, window, capacity, or
    /// state error. No lease is issued on failure.
    pub fn acquire_probe(
        &self,
        expected_generation: CircuitGeneration,
        observed_at: UtcMillis,
        monotonic: MonotonicMillis,
    ) -> Result<ProbeLease, AccountCircuitError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountCircuitErrorCode::StateUnavailable))?;
        validate_clock(&state.snapshot, observed_at, monotonic)?;
        if state.snapshot.generation != expected_generation {
            return Err(error(AccountCircuitErrorCode::GenerationConflict));
        }
        admit_probe(
            &mut state,
            &self.account_id,
            self.policy,
            observed_at,
            monotonic,
        )
    }

    /// Completes one half-open probe and publishes its deterministic result.
    ///
    /// Expired or replayed leases fail closed: the circuit returns to `Open`,
    /// outstanding leases are discarded, and the generation advances.
    ///
    /// # Errors
    /// Returns stable account, generation, lease, ordering, or state errors.
    pub fn complete_probe(
        &self,
        lease: ProbeLease,
        outcome: CircuitOutcome,
        observed_at: UtcMillis,
        monotonic: MonotonicMillis,
    ) -> Result<CircuitSnapshot, AccountCircuitError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountCircuitErrorCode::StateUnavailable))?;
        let index = validate_lease_request(
            &state,
            &self.account_id,
            &lease,
            observed_at,
            monotonic,
        )?;
        if monotonic >= lease.expires_at {
            return expire_probe(&mut state, index, observed_at, monotonic);
        }
        let next = complete_valid_probe(&mut state, index, outcome, observed_at, monotonic, self.policy)?;
        state.snapshot = next.clone();
        Ok(next)
    }

    /// Resets a terminal circuit after an authorized administrative change.
    ///
    /// The caller must enforce the administrative authorization boundary before
    /// invoking this method. The reset is generation-bound and advances the
    /// circuit generation so stale decisions cannot resume the account.
    ///
    /// # Errors
    /// Returns a stable generation, ordering, transition, overflow, or state
    /// error. Rejected resets leave the prior snapshot untouched.
    pub fn reset(
        &self,
        expected_generation: CircuitGeneration,
        observed_at: UtcMillis,
        monotonic: MonotonicMillis,
    ) -> Result<CircuitSnapshot, AccountCircuitError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountCircuitErrorCode::StateUnavailable))?;
        if state.snapshot.generation != expected_generation {
            return Err(error(AccountCircuitErrorCode::GenerationConflict));
        }
        validate_clock(&state.snapshot, observed_at, monotonic)?;
        if state.snapshot.state != CircuitState::Terminal {
            return Err(error(AccountCircuitErrorCode::InvalidTransition));
        }
        let mut next = state.snapshot.clone();
        advance_clock(&mut next, observed_at, monotonic);
        clear_recovery_state(&mut next);
        next.generation = next.generation.next()?;
        state.leases.clear();
        state.snapshot = next.clone();
        Ok(next)
    }

    /// Returns the latest immutable circuit snapshot.
    ///
    /// # Errors
    /// Returns [`AccountCircuitErrorCode::StateUnavailable`] when a prior panic
    /// poisoned the internal lock.
    pub fn snapshot_value(&self) -> Result<CircuitSnapshot, AccountCircuitError> {
        self.state
            .read()
            .map(|state| state.snapshot.clone())
            .map_err(|_| error(AccountCircuitErrorCode::StateUnavailable))
    }
}

impl CircuitSnapshotPort for AccountCircuit {
    fn snapshot(&self) -> Result<Arc<CircuitSnapshot>, AccountCircuitError> {
        self.state
            .read()
            .map(|state| Arc::new(state.snapshot.clone()))
            .map_err(|_| error(AccountCircuitErrorCode::StateUnavailable))
    }
}

fn validate_observation(
    account_id: &AccountId,
    snapshot: &CircuitSnapshot,
    observation: &CircuitObservation,
) -> Result<(), AccountCircuitError> {
    if observation.account_id() != account_id {
        return Err(error(AccountCircuitErrorCode::AccountMismatch));
    }
    if observation.generation() != snapshot.generation {
        return Err(error(AccountCircuitErrorCode::GenerationConflict));
    }
    validate_clock(snapshot, observation.observed_at(), observation.monotonic())
}

fn validate_clock(
    snapshot: &CircuitSnapshot,
    observed_at: UtcMillis,
    monotonic: MonotonicMillis,
) -> Result<(), AccountCircuitError> {
    if snapshot
        .last_observed_at
        .is_some_and(|last| observed_at < last)
        || snapshot.last_monotonic.is_some_and(|last| monotonic < last)
    {
        Err(error(AccountCircuitErrorCode::TimestampOutOfOrder))
    } else {
        Ok(())
    }
}

fn advance_clock(
    snapshot: &mut CircuitSnapshot,
    observed_at: UtcMillis,
    monotonic: MonotonicMillis,
) {
    snapshot.last_observed_at = Some(observed_at);
    snapshot.last_monotonic = Some(monotonic);
}

fn apply_closed_outcome(
    snapshot: &mut CircuitSnapshot,
    outcome: CircuitOutcome,
    policy: CircuitPolicy,
) -> Result<(), AccountCircuitError> {
    match outcome {
        CircuitOutcome::Success => {
            snapshot.consecutive_failures = 0;
        }
        CircuitOutcome::RetryableFailure => {
            snapshot.consecutive_failures = snapshot
                .consecutive_failures
                .checked_add(1)
                .ok_or_else(|| error(AccountCircuitErrorCode::VersionExhausted))?;
            if snapshot.consecutive_failures >= policy.failure_threshold {
                snapshot.state = CircuitState::Open;
                snapshot.opened_at = snapshot.last_observed_at;
            }
        }
        CircuitOutcome::TerminalFailure => {
            snapshot.consecutive_failures = policy.failure_threshold;
            snapshot.state = CircuitState::Terminal;
            snapshot.opened_at = snapshot.last_observed_at;
        }
    }
    Ok(())
}

fn admit_probe(
    state: &mut CircuitStateData,
    account_id: &AccountId,
    policy: CircuitPolicy,
    observed_at: UtcMillis,
    monotonic: MonotonicMillis,
) -> Result<ProbeLease, AccountCircuitError> {
    validate_probe_admission(state, policy, observed_at)?;
    let (id, next_lease_id, expires_at) = prepare_probe_lease(state.next_lease_id, monotonic, policy)?;
    transition_to_half_open(&mut state.snapshot);
    state.next_lease_id = next_lease_id;
    state.leases.push(LeaseRecord { id });
    state.snapshot.half_open_in_flight = state.leases.len() as u16;
    advance_clock(&mut state.snapshot, observed_at, monotonic);
    Ok(ProbeLease {
        account_id: account_id.clone(),
        generation: state.snapshot.generation,
        id,
        issued_at: monotonic,
        expires_at,
    })
}

fn apply_probe_outcome(
    snapshot: &mut CircuitSnapshot,
    outcome: CircuitOutcome,
    policy: CircuitPolicy,
) -> Result<(), AccountCircuitError> {
    match outcome {
        CircuitOutcome::Success => {
            snapshot.recovery_successes = snapshot
                .recovery_successes
                .checked_add(1)
                .ok_or_else(|| error(AccountCircuitErrorCode::VersionExhausted))?;
            if snapshot.recovery_successes >= policy.recovery_successes
                && snapshot.half_open_in_flight == 0
            {
                snapshot.state = CircuitState::Closed;
                snapshot.consecutive_failures = 0;
                snapshot.opened_at = None;
            }
        }
        CircuitOutcome::RetryableFailure => mark_open(snapshot),
        CircuitOutcome::TerminalFailure => mark_terminal(snapshot),
    }
    Ok(())
}

fn validate_lease_request(
    state: &CircuitStateData,
    account_id: &AccountId,
    lease: &ProbeLease,
    observed_at: UtcMillis,
    monotonic: MonotonicMillis,
) -> Result<usize, AccountCircuitError> {
    if &lease.account_id != account_id {
        return Err(error(AccountCircuitErrorCode::AccountMismatch));
    }
    if lease.generation != state.snapshot.generation {
        return Err(error(AccountCircuitErrorCode::GenerationConflict));
    }
    validate_clock(&state.snapshot, observed_at, monotonic)?;
    state
        .leases
        .iter()
        .position(|entry| entry.id == lease.id)
        .ok_or_else(|| error(AccountCircuitErrorCode::LeaseConflict))
}

fn expire_probe(
    state: &mut CircuitStateData,
    index: usize,
    observed_at: UtcMillis,
    monotonic: MonotonicMillis,
) -> Result<CircuitSnapshot, AccountCircuitError> {
    let mut next = state.snapshot.clone();
    advance_clock(&mut next, observed_at, monotonic);
    fail_closed(&mut next)?;
    state.leases.remove(index);
    state.leases.clear();
    state.snapshot = next;
    Err(error(AccountCircuitErrorCode::LeaseExpired))
}

fn complete_valid_probe(
    state: &mut CircuitStateData,
    index: usize,
    outcome: CircuitOutcome,
    observed_at: UtcMillis,
    monotonic: MonotonicMillis,
    policy: CircuitPolicy,
) -> Result<CircuitSnapshot, AccountCircuitError> {
    let mut next = state.snapshot.clone();
    next.half_open_in_flight = (state.leases.len() - 1) as u16;
    advance_clock(&mut next, observed_at, monotonic);
    apply_probe_outcome(&mut next, outcome, policy)?;
    if next.state != state.snapshot.state {
        next.generation = next.generation.next()?;
    }
    state.leases.remove(index);
    if next.state != CircuitState::HalfOpen {
        state.leases.clear();
    }
    Ok(next)
}

fn validate_probe_admission(
    state: &CircuitStateData,
    policy: CircuitPolicy,
    observed_at: UtcMillis,
) -> Result<(), AccountCircuitError> {
    validate_probe_state(state)?;
    validate_recovery_window(state, policy, observed_at)?;
    validate_probe_capacity(state, policy)
}

fn validate_probe_state(state: &CircuitStateData) -> Result<(), AccountCircuitError> {
    if state.snapshot.state == CircuitState::Closed {
        return Err(error(AccountCircuitErrorCode::InvalidTransition));
    }
    if state.snapshot.state == CircuitState::Terminal {
        return Err(error(AccountCircuitErrorCode::AdministrativeResetRequired));
    }
    Ok(())
}

fn validate_recovery_window(
    state: &CircuitStateData,
    policy: CircuitPolicy,
    observed_at: UtcMillis,
) -> Result<(), AccountCircuitError> {
    if let Some(opened_at) = state.snapshot.opened_at
        && observed_at.get().saturating_sub(opened_at.get()) < policy.recovery_window_millis
    {
        return Err(error(AccountCircuitErrorCode::RecoveryWindowClosed));
    }
    Ok(())
}

fn validate_probe_capacity(
    state: &CircuitStateData,
    policy: CircuitPolicy,
) -> Result<(), AccountCircuitError> {
    if state.leases.len() >= usize::from(policy.max_half_open_probes) {
        return Err(error(AccountCircuitErrorCode::ProbeLimitReached));
    }
    Ok(())
}

fn prepare_probe_lease(
    next_lease_id: u64,
    monotonic: MonotonicMillis,
    policy: CircuitPolicy,
) -> Result<(ProbeLeaseId, u64, MonotonicMillis), AccountCircuitError> {
    let next_id = next_lease_id
        .checked_add(1)
        .ok_or_else(|| error(AccountCircuitErrorCode::VersionExhausted))?;
    let expires = monotonic
        .get()
        .checked_add(policy.probe_lease_millis)
        .ok_or_else(|| error(AccountCircuitErrorCode::VersionExhausted))?;
    let expires_at = MonotonicMillis::new(expires)?;
    Ok((ProbeLeaseId(next_lease_id), next_id, expires_at))
}

fn transition_to_half_open(snapshot: &mut CircuitSnapshot) {
    if snapshot.state == CircuitState::Open {
        snapshot.state = CircuitState::HalfOpen;
        snapshot.recovery_successes = 0;
        snapshot.half_open_in_flight = 0;
    }
}

fn clear_recovery_state(snapshot: &mut CircuitSnapshot) {
    snapshot.state = CircuitState::Closed;
    snapshot.consecutive_failures = 0;
    snapshot.recovery_successes = 0;
    snapshot.half_open_in_flight = 0;
    snapshot.opened_at = None;
}

fn mark_terminal(snapshot: &mut CircuitSnapshot) {
    snapshot.state = CircuitState::Terminal;
    snapshot.opened_at = snapshot.last_observed_at;
    snapshot.recovery_successes = 0;
    snapshot.half_open_in_flight = 0;
}

fn fail_closed(snapshot: &mut CircuitSnapshot) -> Result<(), AccountCircuitError> {
    mark_open(snapshot);
    snapshot.generation = snapshot.generation.next()?;
    Ok(())
}

fn mark_open(snapshot: &mut CircuitSnapshot) {
    snapshot.state = CircuitState::Open;
    snapshot.opened_at = snapshot.last_observed_at;
    snapshot.recovery_successes = 0;
    snapshot.half_open_in_flight = 0;
}

const fn error(code: AccountCircuitErrorCode) -> AccountCircuitError {
    AccountCircuitError::new(code)
}

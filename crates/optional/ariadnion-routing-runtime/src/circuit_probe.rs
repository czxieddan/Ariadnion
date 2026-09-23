// crates/optional/ariadnion-routing-runtime/src/circuit_probe.rs - Authoritative circuit probe contracts.
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

//! Typed acquisition and completion boundary for half-open circuit probes.

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ariadnion_account_circuit::{
    AccountCircuit, AccountCircuitError, AccountCircuitErrorCode, CircuitGeneration,
    CircuitObservation, CircuitOutcome, CircuitState, MonotonicMillis, ProbeLease, UtcMillis,
};
use ariadnion_account_domain::{AccountConfigVersion, AccountId};
use ariadnion_account_import::ImportGeneration;
use ariadnion_core::{ErrorCode, RequestContext, TenantId};

/// Maximum account circuits accepted by one production probe registry.
pub const MAX_CIRCUIT_PROBE_ACCOUNTS: usize = 1 << 17;

/// Complete immutable identity of one account-circuit authority.
///
/// Tenant, configuration version, and durable import generation prevent an
/// account identifier from inheriting circuit state across ownership or
/// configuration replacement boundaries.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CircuitProbeKey {
    tenant_id: TenantId,
    account_id: AccountId,
    config_version: AccountConfigVersion,
    import_generation: ImportGeneration,
}

impl CircuitProbeKey {
    /// Creates a circuit identity from already validated durable values.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        account_id: AccountId,
        config_version: AccountConfigVersion,
        import_generation: ImportGeneration,
    ) -> Self {
        Self {
            tenant_id,
            account_id,
            config_version,
            import_generation,
        }
    }

    /// Returns the owning tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the provider-account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the immutable account-configuration version.
    #[must_use]
    pub const fn config_version(&self) -> AccountConfigVersion {
        self.config_version
    }

    /// Returns the durable account snapshot generation.
    #[must_use]
    pub const fn import_generation(&self) -> ImportGeneration {
        self.import_generation
    }
}

impl Debug for CircuitProbeKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CircuitProbeKey(<redacted>)")
    }
}

/// Stable redacted failure classifications returned by a probe authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CircuitProbeErrorCode {
    /// Authoritative circuit state could not be read or updated.
    Unavailable,
    /// The account is not eligible for another bounded half-open probe.
    Rejected,
    /// Request cancellation stopped probe acquisition.
    Cancelled,
    /// The request deadline expired during probe acquisition.
    DeadlineExceeded,
}

/// Redacted error returned by an injected circuit probe authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitProbeError {
    code: CircuitProbeErrorCode,
}

impl CircuitProbeError {
    /// Creates a redacted probe authority error.
    #[must_use]
    pub const fn new(code: CircuitProbeErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn code(self) -> CircuitProbeErrorCode {
        self.code
    }
}

impl Display for CircuitProbeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            CircuitProbeErrorCode::Unavailable => "CIRCUIT_PROBE_UNAVAILABLE",
            CircuitProbeErrorCode::Rejected => "CIRCUIT_PROBE_REJECTED",
            CircuitProbeErrorCode::Cancelled => "CIRCUIT_PROBE_CANCELLED",
            CircuitProbeErrorCode::DeadlineExceeded => "CIRCUIT_PROBE_DEADLINE_EXCEEDED",
        })
    }
}

impl std::error::Error for CircuitProbeError {}

/// Result of checking whether an acquired probe is still authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitProbeValidation {
    /// The lease remains valid for physical dispatch.
    Valid,
    /// The authority invalidated or reclaimed the lease and no completion is required.
    Invalidated,
}

/// Stable redacted failures returned while constructing a probe registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CircuitProbeRegistryErrorCode {
    /// More than one circuit claimed the same complete authority identity.
    DuplicateKey,
    /// A registered circuit belongs to a different account.
    AccountMismatch,
    /// The registry input exceeded the binary account bound.
    CapacityExceeded,
}

/// Redacted construction error for a bounded circuit probe registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitProbeRegistryError {
    code: CircuitProbeRegistryErrorCode,
}

impl CircuitProbeRegistryError {
    /// Returns the stable construction failure classification.
    #[must_use]
    pub const fn code(self) -> CircuitProbeRegistryErrorCode {
        self.code
    }
}

impl Display for CircuitProbeRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            CircuitProbeRegistryErrorCode::DuplicateKey => "CIRCUIT_PROBE_REGISTRY_DUPLICATE_KEY",
            CircuitProbeRegistryErrorCode::AccountMismatch => {
                "CIRCUIT_PROBE_REGISTRY_ACCOUNT_MISMATCH"
            }
            CircuitProbeRegistryErrorCode::CapacityExceeded => {
                "CIRCUIT_PROBE_REGISTRY_CAPACITY_EXCEEDED"
            }
        })
    }
}

impl std::error::Error for CircuitProbeRegistryError {}

/// One validated circuit owner bound to a complete immutable probe key.
#[derive(Clone)]
pub struct CircuitProbeRegistration {
    key: CircuitProbeKey,
    circuit: Arc<AccountCircuit>,
    issuer: Arc<()>,
}

impl CircuitProbeRegistration {
    /// Consumes and binds one account circuit to its tenant and version identity.
    ///
    /// Consuming the circuit prevents the same mutable authority from being
    /// re-keyed across tenant, configuration, import-generation, or registry
    /// boundaries. Cloning the resulting registration preserves its original
    /// key and private shared circuit ownership.
    ///
    /// # Errors
    /// Returns a redacted mismatch when the circuit owns another account.
    pub fn new(
        key: CircuitProbeKey,
        circuit: AccountCircuit,
    ) -> Result<Self, CircuitProbeRegistryError> {
        if circuit.account_id() != key.account_id() {
            return Err(registry_error(
                CircuitProbeRegistryErrorCode::AccountMismatch,
            ));
        }
        Ok(Self {
            key,
            circuit: Arc::new(circuit),
            issuer: Arc::new(()),
        })
    }

    /// Returns the complete immutable authority identity.
    #[must_use]
    pub const fn key(&self) -> &CircuitProbeKey {
        &self.key
    }

    fn circuit(&self) -> &AccountCircuit {
        &self.circuit
    }
}

impl Debug for CircuitProbeRegistration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CircuitProbeRegistration(<redacted>)")
    }
}

/// One paired UTC and monotonic observation used for a circuit transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitProbeClockReading {
    observed_at: UtcMillis,
    monotonic: MonotonicMillis,
}

impl CircuitProbeClockReading {
    /// Creates one paired clock reading.
    #[must_use]
    pub const fn new(observed_at: UtcMillis, monotonic: MonotonicMillis) -> Self {
        Self {
            observed_at,
            monotonic,
        }
    }

    /// Returns the UTC Unix timestamp in milliseconds.
    #[must_use]
    pub const fn observed_at(self) -> UtcMillis {
        self.observed_at
    }

    /// Returns milliseconds elapsed from the clock's stable monotonic origin.
    #[must_use]
    pub const fn monotonic(self) -> MonotonicMillis {
        self.monotonic
    }
}

/// Redacted failure returned when a paired circuit clock cannot be observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitProbeClockError;

impl Display for CircuitProbeClockError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CIRCUIT_PROBE_CLOCK_UNAVAILABLE")
    }
}

impl std::error::Error for CircuitProbeClockError {}

/// Clock boundary that samples UTC and stable monotonic milliseconds together.
pub trait CircuitProbeClock: Send + Sync {
    /// Returns one paired observation for exactly one circuit transition.
    ///
    /// # Errors
    /// Returns a redacted error when either time domain cannot be represented by
    /// the bounded account-circuit types.
    fn observe(&self) -> Result<CircuitProbeClockReading, CircuitProbeClockError>;
}

/// Process-local circuit clock backed by [`SystemTime`] and one [`Instant`] origin.
///
/// UTC identifies recovery windows, while lease ordering and expiry
/// use the stable process-local monotonic origin. Conversion failure is reported
/// without exposing platform clock details.
#[derive(Clone, Debug)]
pub struct ProcessCircuitProbeClock {
    origin: Instant,
}

impl ProcessCircuitProbeClock {
    /// Creates a process clock whose monotonic zero is the current instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for ProcessCircuitProbeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitProbeClock for ProcessCircuitProbeClock {
    fn observe(&self) -> Result<CircuitProbeClockReading, CircuitProbeClockError> {
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CircuitProbeClockError)
            .and_then(duration_millis)?;
        let monotonic = duration_millis(self.origin.elapsed())?;
        let monotonic = MonotonicMillis::new(monotonic).map_err(|_| CircuitProbeClockError)?;
        Ok(CircuitProbeClockReading::new(
            UtcMillis::new(observed_at),
            monotonic,
        ))
    }
}

/// Immutable production authority for a bounded set of account circuits.
///
/// Construction validates the complete input before publication, sorts it into
/// deterministic full-key order, and rejects duplicate authority identities.
/// Runtime lookup uses that immutable ordering and never uses global mutable
/// state.
#[derive(Clone)]
pub struct CircuitProbeRegistry {
    registrations: Arc<[CircuitProbeRegistration]>,
    clock: Arc<dyn CircuitProbeClock>,
}

impl CircuitProbeRegistry {
    /// Validates and freezes one complete circuit registry.
    ///
    /// Empty registries are valid and reject every acquisition as missing.
    /// Registration clones retain their original private circuit owner; the
    /// registry does not copy or replace circuit state.
    ///
    /// # Errors
    /// Returns a redacted duplicate or capacity error before any registry value
    /// can be published.
    pub fn new(
        mut registrations: Vec<CircuitProbeRegistration>,
        clock: Arc<dyn CircuitProbeClock>,
    ) -> Result<Self, CircuitProbeRegistryError> {
        validate_registry_capacity(registrations.len())?;
        registrations.sort_unstable_by(|left, right| left.key().cmp(right.key()));
        validate_unique_keys(&registrations)?;
        Ok(Self {
            registrations: Arc::from(registrations.into_boxed_slice()),
            clock,
        })
    }

    /// Returns the number of registered account circuits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    /// Returns whether the registry contains no account circuits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    fn registration(
        &self,
        key: &CircuitProbeKey,
    ) -> Result<&CircuitProbeRegistration, CircuitProbeError> {
        self.registrations
            .binary_search_by(|registration| registration.key().cmp(key))
            .map(|index| &self.registrations[index])
            .map_err(|_| probe_error(CircuitProbeErrorCode::Rejected))
    }

    fn acquire_recovery_probe(
        &self,
        key: &CircuitProbeKey,
        registration: &CircuitProbeRegistration,
        generation: CircuitGeneration,
        context: &RequestContext,
    ) -> Result<CircuitProbeAcquisition, CircuitProbeError> {
        ensure_context_active(context)?;
        let reading = self
            .clock
            .observe()
            .map_err(|_| probe_error(CircuitProbeErrorCode::Unavailable))?;
        ensure_context_active(context)?;
        let lease = registration
            .circuit()
            .acquire_probe(generation, reading.observed_at(), reading.monotonic())
            .map_err(map_acquisition_error)?;
        let lease = CircuitProbeLease::new(key.clone(), lease)?
            .with_issuer(Arc::clone(&registration.issuer));
        Ok(CircuitProbeAcquisition::HalfOpen(lease))
    }

    fn validate_registered_probe(
        &self,
        lease: &CircuitProbeLease,
        registration: &CircuitProbeRegistration,
    ) -> Result<CircuitProbeValidation, CircuitProbeError> {
        match &lease.kind {
            CircuitProbeLeaseKind::Closed(generation) => {
                self.validate_closed_probe(registration, *generation)
            }
            CircuitProbeLeaseKind::HalfOpen(inner) => {
                self.validate_half_open_probe(registration, inner)
            }
        }
    }

    fn validate_closed_probe(
        &self,
        registration: &CircuitProbeRegistration,
        generation: CircuitGeneration,
    ) -> Result<CircuitProbeValidation, CircuitProbeError> {
        let snapshot = registration
            .circuit()
            .snapshot_value()
            .map_err(map_snapshot_error)?;
        if snapshot.state() == CircuitState::Closed && snapshot.generation() == generation {
            Ok(CircuitProbeValidation::Valid)
        } else {
            Ok(CircuitProbeValidation::Invalidated)
        }
    }

    fn validate_half_open_probe(
        &self,
        registration: &CircuitProbeRegistration,
        inner: &ProbeLease,
    ) -> Result<CircuitProbeValidation, CircuitProbeError> {
        let reading = self
            .clock
            .observe()
            .map_err(|_| probe_error(CircuitProbeErrorCode::Unavailable))?;
        match registration.circuit().validate_probe(
            inner,
            reading.observed_at(),
            reading.monotonic(),
        ) {
            Ok(()) => Ok(CircuitProbeValidation::Valid),
            Err(error) if is_stale_probe_error(error.code()) => {
                Ok(CircuitProbeValidation::Invalidated)
            }
            Err(_) => Err(probe_error(CircuitProbeErrorCode::Unavailable)),
        }
    }
}

impl Debug for CircuitProbeRegistry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CircuitProbeRegistry")
            .field("circuit_count", &self.registrations.len())
            .field("clock", &"<redacted>")
            .finish()
    }
}

impl CircuitProbePort for CircuitProbeRegistry {
    fn acquire_probe(
        &self,
        key: &CircuitProbeKey,
        context: &RequestContext,
    ) -> Result<CircuitProbeAcquisition, CircuitProbeError> {
        ensure_context_active(context)?;
        let registration = self.registration(key)?;
        let circuit = registration.circuit();
        let snapshot = circuit.snapshot_value().map_err(map_snapshot_error)?;
        match snapshot.state() {
            CircuitState::Closed => Ok(CircuitProbeAcquisition::Closed(
                CircuitProbeLease::closed(key.clone(), snapshot.generation())
                    .with_issuer(Arc::clone(&registration.issuer)),
            )),
            CircuitState::Open | CircuitState::HalfOpen => {
                self.acquire_recovery_probe(key, registration, snapshot.generation(), context)
            }
            CircuitState::Terminal => Err(probe_error(CircuitProbeErrorCode::Rejected)),
        }
    }

    fn complete_probe(
        &self,
        key: &CircuitProbeKey,
        lease: CircuitProbeLease,
        outcome: CircuitOutcome,
    ) -> Result<(), CircuitProbeError> {
        if lease.key() != key {
            return Err(probe_error(CircuitProbeErrorCode::Rejected));
        }
        let registration = self.registration(key)?;
        if !lease.is_issued_by(&registration.issuer) {
            return Err(probe_error(CircuitProbeErrorCode::Rejected));
        }
        let reading = self
            .clock
            .observe()
            .map_err(|_| probe_error(CircuitProbeErrorCode::Unavailable))?;
        complete_circuit_execution(registration.circuit(), key, lease, outcome, reading)
    }

    fn validate_probe(
        &self,
        key: &CircuitProbeKey,
        lease: &CircuitProbeLease,
    ) -> Result<CircuitProbeValidation, CircuitProbeError> {
        if lease.key() != key {
            return Err(probe_error(CircuitProbeErrorCode::Rejected));
        }
        let registration = self.registration(key)?;
        if !lease.is_issued_by(&registration.issuer) {
            return Err(probe_error(CircuitProbeErrorCode::Rejected));
        }
        self.validate_registered_probe(lease, registration)
    }
}

fn complete_circuit_execution(
    circuit: &AccountCircuit,
    key: &CircuitProbeKey,
    lease: CircuitProbeLease,
    outcome: CircuitOutcome,
    reading: CircuitProbeClockReading,
) -> Result<(), CircuitProbeError> {
    let result = match lease.into_kind() {
        CircuitProbeLeaseKind::Closed(generation) => circuit.observe(CircuitObservation::new(
            key.account_id().clone(),
            generation,
            reading.observed_at(),
            reading.monotonic(),
            outcome,
        )),
        CircuitProbeLeaseKind::HalfOpen(lease) => {
            circuit.complete_probe(lease, outcome, reading.observed_at(), reading.monotonic())
        }
    };
    result.map(|_| ()).map_err(map_completion_error)
}

fn duration_millis(duration: Duration) -> Result<u64, CircuitProbeClockError> {
    u64::try_from(duration.as_millis()).map_err(|_| CircuitProbeClockError)
}

fn validate_registry_capacity(count: usize) -> Result<(), CircuitProbeRegistryError> {
    if count > MAX_CIRCUIT_PROBE_ACCOUNTS {
        Err(registry_error(
            CircuitProbeRegistryErrorCode::CapacityExceeded,
        ))
    } else {
        Ok(())
    }
}

fn validate_unique_keys(
    registrations: &[CircuitProbeRegistration],
) -> Result<(), CircuitProbeRegistryError> {
    let duplicate = registrations
        .windows(2)
        .any(|pair| pair[0].key() == pair[1].key());
    if duplicate {
        Err(registry_error(CircuitProbeRegistryErrorCode::DuplicateKey))
    } else {
        Ok(())
    }
}

fn ensure_context_active(context: &RequestContext) -> Result<(), CircuitProbeError> {
    context.check_active().map_err(|error| {
        let code = match error.code() {
            ErrorCode::Cancelled => CircuitProbeErrorCode::Cancelled,
            ErrorCode::DeadlineExceeded => CircuitProbeErrorCode::DeadlineExceeded,
            _ => CircuitProbeErrorCode::Unavailable,
        };
        probe_error(code)
    })
}

fn map_snapshot_error(_error: AccountCircuitError) -> CircuitProbeError {
    probe_error(CircuitProbeErrorCode::Unavailable)
}

fn map_acquisition_error(error: AccountCircuitError) -> CircuitProbeError {
    let code = match error.code() {
        AccountCircuitErrorCode::AccountMismatch
        | AccountCircuitErrorCode::GenerationConflict
        | AccountCircuitErrorCode::TimestampOutOfOrder
        | AccountCircuitErrorCode::InvalidTransition
        | AccountCircuitErrorCode::RecoveryWindowClosed
        | AccountCircuitErrorCode::ProbeLimitReached
        | AccountCircuitErrorCode::LeaseExpired
        | AccountCircuitErrorCode::AdministrativeResetRequired => CircuitProbeErrorCode::Rejected,
        _ => CircuitProbeErrorCode::Unavailable,
    };
    probe_error(code)
}

fn map_completion_error(_error: AccountCircuitError) -> CircuitProbeError {
    probe_error(CircuitProbeErrorCode::Unavailable)
}

fn is_stale_probe_error(code: AccountCircuitErrorCode) -> bool {
    matches!(
        code,
        AccountCircuitErrorCode::AccountMismatch
            | AccountCircuitErrorCode::GenerationConflict
            | AccountCircuitErrorCode::InvalidTransition
            | AccountCircuitErrorCode::RecoveryWindowClosed
            | AccountCircuitErrorCode::ProbeLimitReached
            | AccountCircuitErrorCode::LeaseConflict
            | AccountCircuitErrorCode::LeaseExpired
            | AccountCircuitErrorCode::AdministrativeResetRequired
    )
}

const fn probe_error(code: CircuitProbeErrorCode) -> CircuitProbeError {
    CircuitProbeError::new(code)
}

const fn registry_error(code: CircuitProbeRegistryErrorCode) -> CircuitProbeRegistryError {
    CircuitProbeRegistryError { code }
}

enum CircuitProbeLeaseKind {
    Closed(CircuitGeneration),
    HalfOpen(ProbeLease),
}

/// Full-identity-bound capability requiring one circuit outcome completion.
pub struct CircuitProbeLease {
    key: CircuitProbeKey,
    kind: CircuitProbeLeaseKind,
    issuer: Option<Arc<()>>,
}

impl CircuitProbeLease {
    /// Binds one custom authority's closed execution to its observed generation.
    ///
    /// Registry-issued leases additionally retain a private issuer capability;
    /// this constructor cannot manufacture a lease accepted by a registry.
    #[must_use]
    pub fn closed(key: CircuitProbeKey, generation: CircuitGeneration) -> Self {
        Self {
            key,
            kind: CircuitProbeLeaseKind::Closed(generation),
            issuer: None,
        }
    }

    /// Wraps an authoritative lease with its complete immutable authority key.
    ///
    /// This constructor is for custom probe authorities. Rewrapping a registry
    /// lease does not preserve its private issuer capability.
    ///
    /// # Errors
    /// Returns a redacted mismatch when the underlying lease belongs to another
    /// account identity.
    pub fn new(key: CircuitProbeKey, inner: ProbeLease) -> Result<Self, CircuitProbeError> {
        if inner.account_id() != key.account_id() {
            return Err(probe_error(CircuitProbeErrorCode::Rejected));
        }
        Ok(Self {
            key,
            kind: CircuitProbeLeaseKind::HalfOpen(inner),
            issuer: None,
        })
    }

    /// Returns the complete immutable authority identity bound to this lease.
    #[must_use]
    pub const fn key(&self) -> &CircuitProbeKey {
        &self.key
    }

    /// Returns the account identity bound by the authoritative lease.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        self.key.account_id()
    }

    /// Consumes this capability and returns a recovery lease when it represents
    /// a half-open execution.
    #[must_use]
    pub fn into_probe(self) -> Option<ProbeLease> {
        match self.kind {
            CircuitProbeLeaseKind::Closed(_) => None,
            CircuitProbeLeaseKind::HalfOpen(lease) => Some(lease),
        }
    }

    fn with_issuer(mut self, issuer: Arc<()>) -> Self {
        self.issuer = Some(issuer);
        self
    }

    fn is_issued_by(&self, issuer: &Arc<()>) -> bool {
        self.issuer
            .as_ref()
            .is_some_and(|bound| Arc::ptr_eq(bound, issuer))
    }

    fn into_kind(self) -> CircuitProbeLeaseKind {
        self.kind
    }
}

impl Debug for CircuitProbeLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CircuitProbeLease(<redacted>)")
    }
}

/// Authoritative result of checking whether a selected account needs a probe.
pub enum CircuitProbeAcquisition {
    /// The selected account is closed and must publish its execution outcome.
    Closed(CircuitProbeLease),
    /// The selected account is half-open and owns this bounded probe lease.
    HalfOpen(CircuitProbeLease),
}

impl Debug for CircuitProbeAcquisition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(_) => formatter.write_str("CircuitProbeAcquisition::Closed(<redacted>)"),
            Self::HalfOpen(_) => {
                formatter.write_str("CircuitProbeAcquisition::HalfOpen(<redacted>)")
            }
        }
    }
}

/// Authoritative circuit observation and half-open probe port.
pub trait CircuitProbePort: Send + Sync {
    /// Checks current circuit state and returns one outcome-completion lease.
    ///
    /// Closed executions and half-open probes must both bind the exact tenant,
    /// account, configuration version, and import generation in `key`. Open
    /// circuits before their recovery window, terminal, stale, unavailable, and
    /// capacity-exhausted states must fail before credential or provider work.
    ///
    /// # Errors
    /// Returns a redacted state, capacity, cancellation, or deadline error without
    /// issuing a lease to the runtime.
    fn acquire_probe(
        &self,
        key: &CircuitProbeKey,
        context: &RequestContext,
    ) -> Result<CircuitProbeAcquisition, CircuitProbeError>;

    /// Revalidates an acquired lease immediately before physical dispatch.
    ///
    /// Authorities must invalidate or reclaim an expired or superseded lease
    /// before returning [`CircuitProbeValidation::Invalidated`]. The default
    /// implementation preserves compatibility for custom authorities that
    /// already make their lease authoritative at acquisition time.
    ///
    /// # Errors
    /// Returns a redacted failure when the lease key is not authoritative.
    fn validate_probe(
        &self,
        key: &CircuitProbeKey,
        lease: &CircuitProbeLease,
    ) -> Result<CircuitProbeValidation, CircuitProbeError> {
        if lease.key() != key {
            return Err(probe_error(CircuitProbeErrorCode::Rejected));
        }
        Ok(CircuitProbeValidation::Valid)
    }

    /// Consumes one acquired execution lease and publishes its circuit outcome.
    ///
    /// Completion is deliberately independent of request cancellation so every
    /// acquired lease can be finalized after preparation or provider execution.
    /// The implementation must reject a lease whose bound key differs from `key`
    /// and must remain bounded and non-blocking.
    ///
    /// # Errors
    /// Returns a redacted error when the authoritative lease cannot be completed.
    fn complete_probe(
        &self,
        key: &CircuitProbeKey,
        lease: CircuitProbeLease,
        outcome: CircuitOutcome,
    ) -> Result<(), CircuitProbeError>;
}

/// Owns an acquired circuit execution until one explicit or drop completion.
pub(crate) struct CircuitProbeGuard {
    authority: Arc<dyn CircuitProbePort>,
    lease: Option<CircuitProbeLease>,
    drop_outcome: CircuitOutcome,
}

impl CircuitProbeGuard {
    /// Binds a lease to the exact authority that issued it.
    pub(crate) fn new(authority: Arc<dyn CircuitProbePort>, lease: CircuitProbeLease) -> Self {
        Self {
            authority,
            lease: Some(lease),
            drop_outcome: CircuitOutcome::Neutral,
        }
    }

    /// Treats a later abandoned guard as an unknown provider dispatch.
    pub(crate) fn arm_retryable_drop(&mut self) {
        self.drop_outcome = CircuitOutcome::RetryableFailure;
    }

    pub(crate) fn validate(&self) -> Result<CircuitProbeValidation, CircuitProbeError> {
        let Some(lease) = self.lease.as_ref() else {
            return Ok(CircuitProbeValidation::Invalidated);
        };
        self.authority.validate_probe(lease.key(), lease)
    }

    pub(crate) fn disarm(&mut self) {
        self.lease.take();
    }

    /// Disarms drop cleanup before publishing an observable final outcome.
    pub(crate) fn complete(mut self, outcome: CircuitOutcome) -> Result<(), CircuitProbeError> {
        let Some(lease) = self.lease.take() else {
            return Ok(());
        };
        let key = lease.key().clone();
        self.authority.complete_probe(&key, lease, outcome)
    }
}

impl Drop for CircuitProbeGuard {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        // Drop attempts completion; authoritative lease expiry contains failed cleanup.
        let key = lease.key().clone();
        let _ = self
            .authority
            .complete_probe(&key, lease, self.drop_outcome);
    }
}

// crates/optional/ariadnion-account-affinity/src/lib.rs - Account affinity contracts for Ariadnion.
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
//! Bounded privacy-preserving stickiness keys and deterministic account selection.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_core::TenantId;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::{Arc, RwLock};

/// Maximum bytes accepted for one raw affinity subject before hashing.
pub const MAX_SUBJECT_BYTES: usize = 256;
/// Maximum bytes accepted for one candidate identity.
pub const MAX_CANDIDATE_BYTES: usize = 128;
/// Maximum number of retained bindings in one registry.
pub const MAX_BINDINGS: usize = 100_000;
/// Maximum number of candidates considered by one selection.
pub const MAX_CANDIDATES: usize = 100_000;
/// Maximum lifetime of a binding in seconds.
pub const MAX_TTL_SECONDS: u64 = 30 * 86_400;

/// Stable machine-readable account-affinity failures.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AccountAffinityErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// The candidate collection is empty.
    EmptyCandidateSet,
    /// A candidate collection exceeds its fixed bound.
    TooManyCandidates,
    /// The registry has reached its fixed binding bound.
    CapacityExceeded,
    /// The requested TTL is zero or exceeds the fixed lifetime bound.
    InvalidTtl,
    /// A generation supplied by a caller is stale.
    GenerationConflict,
    /// A key belongs to an inactive affinity epoch.
    EpochConflict,
    /// A key belongs to a different tenant than the registry.
    TenantMismatch,
    /// An epoch or generation cannot advance without wrapping.
    VersionExhausted,
    /// The authoritative affinity state could not be accessed.
    StateUnavailable,
}

impl AccountAffinityErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        const CODES: [&str; 10] = [
            "ACCOUNT_AFFINITY_INVALID_ARGUMENT",
            "ACCOUNT_AFFINITY_EMPTY_CANDIDATE_SET",
            "ACCOUNT_AFFINITY_TOO_MANY_CANDIDATES",
            "ACCOUNT_AFFINITY_CAPACITY_EXCEEDED",
            "ACCOUNT_AFFINITY_INVALID_TTL",
            "ACCOUNT_AFFINITY_GENERATION_CONFLICT",
            "ACCOUNT_AFFINITY_EPOCH_CONFLICT",
            "ACCOUNT_AFFINITY_TENANT_MISMATCH",
            "ACCOUNT_AFFINITY_VERSION_EXHAUSTED",
            "ACCOUNT_AFFINITY_STATE_UNAVAILABLE",
        ];
        CODES[self as usize]
    }
}

impl Display for AccountAffinityErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted affinity failure containing only a stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountAffinityError {
    code: AccountAffinityErrorCode,
}

impl AccountAffinityError {
    const fn new(code: AccountAffinityErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AccountAffinityErrorCode {
        self.code
    }
}

impl Display for AccountAffinityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AccountAffinityError {}

fn error(code: AccountAffinityErrorCode) -> AccountAffinityError {
    AccountAffinityError::new(code)
}

/// UTC Unix time in whole seconds.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcSeconds(u64);

impl UtcSeconds {
    /// Creates a UTC timestamp from seconds since the Unix epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn checked_add(self, seconds: u64) -> Result<Self, AccountAffinityError> {
        self.0
            .checked_add(seconds)
            .map(Self)
            .ok_or_else(|| error(AccountAffinityErrorCode::VersionExhausted))
    }
}

/// Monotonic registry generation used for optimistic publication.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AffinityGeneration(u64);

impl AffinityGeneration {
    /// Returns the initial generation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Reconstructs a generation from durable state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, AccountAffinityError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AccountAffinityErrorCode::VersionExhausted))
    }
}

/// Epoch separating affinity hashes after rotation.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AffinityEpoch(u64);

impl AffinityEpoch {
    /// Returns the initial epoch.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Reconstructs an epoch from durable state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, AccountAffinityError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AccountAffinityErrorCode::VersionExhausted))
    }
}

/// Scope of a stickiness key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AffinityScope {
    /// Stickiness derived from a user identity.
    User,
    /// Stickiness derived from a leaf session identity.
    Session,
    /// Stickiness derived from a session-family identity.
    SessionFamily,
}

/// A fixed-size opaque SHA-256 identifier.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueAffinityId([u8; 32]);

impl OpaqueAffinityId {
    /// Hashes a bounded subject with tenant, scope, and epoch separators.
    ///
    /// The input is not retained after this call. Callers should pass a stable
    /// identifier, never a credential or request body.
    ///
    /// # Errors
    /// Returns [`AccountAffinityErrorCode::InvalidArgument`] for empty, oversized,
    /// or control-containing input.
    pub fn derive(
        tenant_id: TenantId,
        scope: AffinityScope,
        subject: &str,
        epoch: AffinityEpoch,
    ) -> Result<Self, AccountAffinityError> {
        if subject.is_empty()
            || subject.len() > MAX_SUBJECT_BYTES
            || !subject.is_ascii()
            || subject.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(error(AccountAffinityErrorCode::InvalidArgument));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"ariadnion-affinity-v1\0");
        hasher.update((tenant_id.as_str().len() as u16).to_be_bytes());
        hasher.update(tenant_id.as_str().as_bytes());
        hasher.update([scope as u8]);
        hasher.update(epoch.get().to_be_bytes());
        hasher.update((subject.len() as u16).to_be_bytes());
        hasher.update(subject.as_bytes());
        Ok(Self(hasher.finalize().into()))
    }

    /// Returns the opaque digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Debug for OpaqueAffinityId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueAffinityId(<sha256>)")
    }
}

impl Display for OpaqueAffinityId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A scoped, epoch-bound key used for affinity lookups.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AffinityKey {
    tenant_id: TenantId,
    scope: AffinityScope,
    id: OpaqueAffinityId,
    epoch: AffinityEpoch,
}

impl AffinityKey {
    /// Derives a key from a user, session, or session-family subject.
    pub fn derive(
        tenant_id: TenantId,
        scope: AffinityScope,
        subject: &str,
        epoch: AffinityEpoch,
    ) -> Result<Self, AccountAffinityError> {
        Ok(Self {
            tenant_id: tenant_id.clone(),
            scope,
            id: OpaqueAffinityId::derive(tenant_id, scope, subject, epoch)?,
            epoch,
        })
    }

    /// Derives a user-scoped key.
    pub fn user(
        tenant_id: TenantId,
        subject: &str,
        epoch: AffinityEpoch,
    ) -> Result<Self, AccountAffinityError> {
        Self::derive(tenant_id, AffinityScope::User, subject, epoch)
    }

    /// Derives a leaf-session-scoped key.
    pub fn session(
        tenant_id: TenantId,
        subject: &str,
        epoch: AffinityEpoch,
    ) -> Result<Self, AccountAffinityError> {
        Self::derive(tenant_id, AffinityScope::Session, subject, epoch)
    }

    /// Derives a session-family-scoped key.
    pub fn session_family(
        tenant_id: TenantId,
        subject: &str,
        epoch: AffinityEpoch,
    ) -> Result<Self, AccountAffinityError> {
        Self::derive(tenant_id, AffinityScope::SessionFamily, subject, epoch)
    }

    /// Returns the scope without exposing the source subject.
    #[must_use]
    pub const fn scope(&self) -> AffinityScope {
        self.scope
    }

    /// Returns the tenant bound to this key.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the opaque digest.
    #[must_use]
    pub const fn id(&self) -> OpaqueAffinityId {
        self.id
    }

    /// Returns the epoch used during derivation.
    #[must_use]
    pub const fn epoch(&self) -> AffinityEpoch {
        self.epoch
    }
}

/// A bounded candidate identity suitable for deterministic selection.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateId(Box<str>);

impl CandidateId {
    /// Parses a non-empty path-free ASCII candidate identity.
    ///
    /// # Errors
    /// Returns [`AccountAffinityErrorCode::InvalidArgument`] when the value is
    /// empty, oversized, non-ASCII, or contains control bytes.
    pub fn parse(value: &str) -> Result<Self, AccountAffinityError> {
        if value.is_empty()
            || value.len() > MAX_CANDIDATE_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(error(AccountAffinityErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated candidate identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for CandidateId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CandidateId(<opaque>)")
    }
}

impl Display for CandidateId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A retained key-to-candidate binding with an absolute UTC expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinityBinding {
    key: AffinityKey,
    candidate: CandidateId,
    expires_at: UtcSeconds,
}

impl AffinityBinding {
    /// Returns the bound affinity key.
    #[must_use]
    pub const fn key(&self) -> &AffinityKey {
        &self.key
    }

    /// Returns the selected candidate identity.
    #[must_use]
    pub fn candidate(&self) -> &CandidateId {
        &self.candidate
    }

    /// Returns the absolute expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> UtcSeconds {
        self.expires_at
    }

    fn is_live(&self, key: &AffinityKey, now: UtcSeconds) -> bool {
        &self.key == key && self.expires_at > now
    }
}

/// Immutable view of the affinity registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinitySnapshot {
    tenant_id: TenantId,
    generation: AffinityGeneration,
    epoch: AffinityEpoch,
    bindings: Arc<[AffinityBinding]>,
}

impl AffinitySnapshot {
    /// Returns the publication generation.
    #[must_use]
    pub const fn generation(&self) -> AffinityGeneration {
        self.generation
    }

    /// Returns the tenant bound to this snapshot.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the active epoch.
    #[must_use]
    pub const fn epoch(&self) -> AffinityEpoch {
        self.epoch
    }

    /// Returns retained bindings in deterministic key order.
    #[must_use]
    pub fn bindings(&self) -> &[AffinityBinding] {
        &self.bindings
    }
}

struct RegistryState {
    tenant_id: TenantId,
    generation: AffinityGeneration,
    epoch: AffinityEpoch,
    bindings: HashMap<AffinityKey, AffinityBinding>,
}

/// Thread-safe bounded affinity registry.
#[derive(Clone)]
pub struct AffinityRegistry {
    state: Arc<RwLock<RegistryState>>,
}

impl Debug for AffinityRegistry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AffinityRegistry(<state>)")
    }
}

impl AffinityRegistry {
    /// Creates an empty registry at the initial epoch for one tenant.
    #[must_use]
    pub fn new(tenant_id: TenantId) -> Self {
        Self {
            state: Arc::new(RwLock::new(RegistryState {
                tenant_id,
                generation: AffinityGeneration::initial(),
                epoch: AffinityEpoch::initial(),
                bindings: HashMap::new(),
            })),
        }
    }

    /// Creates an empty registry at a reconstructed epoch for one tenant.
    #[must_use]
    pub fn with_epoch(tenant_id: TenantId, epoch: AffinityEpoch) -> Self {
        Self {
            state: Arc::new(RwLock::new(RegistryState {
                tenant_id,
                generation: AffinityGeneration::initial(),
                epoch,
                bindings: HashMap::new(),
            })),
        }
    }

    /// Creates an empty registry reconstructed at explicit durable versions for
    /// one tenant.
    #[must_use]
    pub fn with_versions(
        tenant_id: TenantId,
        epoch: AffinityEpoch,
        generation: AffinityGeneration,
    ) -> Self {
        Self {
            state: Arc::new(RwLock::new(RegistryState {
                tenant_id,
                generation,
                epoch,
                bindings: HashMap::new(),
            })),
        }
    }

    /// Returns an immutable snapshot of the current bindings.
    ///
    /// # Errors
    /// Returns [`AccountAffinityErrorCode::StateUnavailable`] if the lock is poisoned.
    pub fn snapshot(&self) -> Result<AffinitySnapshot, AccountAffinityError> {
        let state = self
            .state
            .read()
            .map_err(|_| error(AccountAffinityErrorCode::StateUnavailable))?;
        let mut bindings: Vec<_> = state.bindings.values().cloned().collect();
        bindings.sort_by_key(|binding| (binding.key.scope, binding.key.id, binding.key.epoch));
        Ok(AffinitySnapshot {
            tenant_id: state.tenant_id.clone(),
            generation: state.generation,
            epoch: state.epoch,
            bindings: bindings.into(),
        })
    }

    /// Returns the active epoch.
    ///
    /// # Errors
    /// Returns [`AccountAffinityErrorCode::StateUnavailable`] if the lock is poisoned.
    pub fn epoch(&self) -> Result<AffinityEpoch, AccountAffinityError> {
        self.state
            .read()
            .map(|state| state.epoch)
            .map_err(|_| error(AccountAffinityErrorCode::StateUnavailable))
    }

    /// Selects an existing live binding or deterministically ranks candidates.
    ///
    /// This read-only operation never stores the raw key or candidate body.
    ///
    /// # Errors
    /// Returns a bounded argument or state error when the candidate set is invalid
    /// or the registry lock is unavailable.
    pub fn select<'a>(
        &self,
        key: AffinityKey,
        candidates: &'a [CandidateId],
        now: UtcSeconds,
    ) -> Result<&'a CandidateId, AccountAffinityError> {
        validate_candidates(candidates)?;
        let state = self
            .state
            .read()
            .map_err(|_| error(AccountAffinityErrorCode::StateUnavailable))?;
        validate_key(&state, &key)?;
        if let Some(index) = live_candidate_index(&state, &key, candidates, now) {
            return Ok(&candidates[index]);
        }
        deterministic_candidate(&key, candidates)
    }

    /// Assigns a candidate and atomically retains the resulting binding.
    ///
    /// Existing live bindings remain sticky when their candidate is still eligible;
    /// otherwise the deterministic ranking chooses a replacement. `ttl_seconds` is
    /// measured from `now` using UTC wall-clock semantics.
    ///
    /// # Errors
    /// Returns a bounded argument, capacity, overflow, or state error.
    pub fn assign(
        &self,
        key: AffinityKey,
        candidates: &[CandidateId],
        now: UtcSeconds,
        ttl_seconds: u64,
    ) -> Result<AffinityBinding, AccountAffinityError> {
        validate_assignment_inputs(candidates, ttl_seconds)?;
        let expires_at = now.checked_add(ttl_seconds)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountAffinityErrorCode::StateUnavailable))?;
        let next_generation = prepare_assignment(&state, &key)?;
        prune_expired(&mut state.bindings, now);
        let candidate = assignment_candidate(&state, &key, candidates, now)?;
        ensure_capacity(&state, &key)?;
        let binding = AffinityBinding {
            key: key.clone(),
            candidate,
            expires_at,
        };
        state.bindings.insert(key, binding.clone());
        state.generation = next_generation;
        Ok(binding)
    }

    /// Removes expired bindings and returns the number removed.
    ///
    /// # Errors
    /// Returns [`AccountAffinityErrorCode::StateUnavailable`] if the lock is poisoned.
    pub fn expire(&self, now: UtcSeconds) -> Result<usize, AccountAffinityError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountAffinityErrorCode::StateUnavailable))?;
        let before = state.bindings.len();
        let has_expired = state
            .bindings
            .values()
            .any(|binding| binding.expires_at <= now);
        let next_generation = has_expired.then(|| state.generation.next()).transpose()?;
        prune_expired(&mut state.bindings, now);
        let removed = before.saturating_sub(state.bindings.len());
        if removed > 0
            && let Some(generation) = next_generation
        {
            state.generation = generation;
        }
        Ok(removed)
    }

    /// Rotates the epoch and invalidates every prior binding.
    ///
    /// # Errors
    /// Returns [`AccountAffinityErrorCode::GenerationConflict`] for a stale
    /// expected generation or [`AccountAffinityErrorCode::VersionExhausted`] on
    /// counter wrap.
    pub fn rotate_epoch(
        &self,
        expected_generation: AffinityGeneration,
    ) -> Result<(AffinityEpoch, AffinityGeneration), AccountAffinityError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountAffinityErrorCode::StateUnavailable))?;
        if state.generation != expected_generation {
            return Err(error(AccountAffinityErrorCode::GenerationConflict));
        }
        let next_epoch = state.epoch.next()?;
        let next_generation = state.generation.next()?;
        state.epoch = next_epoch;
        state.bindings.clear();
        state.generation = next_generation;
        Ok((state.epoch, state.generation))
    }
}

fn validate_candidates(candidates: &[CandidateId]) -> Result<(), AccountAffinityError> {
    if candidates.is_empty() {
        return Err(error(AccountAffinityErrorCode::EmptyCandidateSet));
    }
    if candidates.len() > MAX_CANDIDATES {
        return Err(error(AccountAffinityErrorCode::TooManyCandidates));
    }
    Ok(())
}

fn validate_ttl(ttl_seconds: u64) -> Result<(), AccountAffinityError> {
    if ttl_seconds == 0 || ttl_seconds > MAX_TTL_SECONDS {
        return Err(error(AccountAffinityErrorCode::InvalidTtl));
    }
    Ok(())
}

fn validate_assignment_inputs(
    candidates: &[CandidateId],
    ttl_seconds: u64,
) -> Result<(), AccountAffinityError> {
    validate_candidates(candidates)?;
    validate_ttl(ttl_seconds)
}

fn validate_key(state: &RegistryState, key: &AffinityKey) -> Result<(), AccountAffinityError> {
    if key.tenant_id() != &state.tenant_id {
        return Err(error(AccountAffinityErrorCode::TenantMismatch));
    }
    if key.epoch != state.epoch {
        return Err(error(AccountAffinityErrorCode::EpochConflict));
    }
    Ok(())
}

fn prepare_assignment(
    state: &RegistryState,
    key: &AffinityKey,
) -> Result<AffinityGeneration, AccountAffinityError> {
    validate_key(state, key)?;
    state.generation.next()
}

fn live_candidate_index(
    state: &RegistryState,
    key: &AffinityKey,
    candidates: &[CandidateId],
    now: UtcSeconds,
) -> Option<usize> {
    let binding = state.bindings.get(key)?;
    if !binding.is_live(key, now) {
        return None;
    }
    candidates
        .iter()
        .position(|candidate| candidate == &binding.candidate)
}

fn assignment_candidate(
    state: &RegistryState,
    key: &AffinityKey,
    candidates: &[CandidateId],
    now: UtcSeconds,
) -> Result<CandidateId, AccountAffinityError> {
    if let Some(binding) = state.bindings.get(key)
        && binding.is_live(key, now)
        && candidates
            .iter()
            .any(|candidate| candidate == &binding.candidate)
    {
        return Ok(binding.candidate.clone());
    }
    deterministic_candidate(key, candidates).cloned()
}

fn ensure_capacity(state: &RegistryState, key: &AffinityKey) -> Result<(), AccountAffinityError> {
    if !state.bindings.contains_key(key) && state.bindings.len() >= MAX_BINDINGS {
        return Err(error(AccountAffinityErrorCode::CapacityExceeded));
    }
    Ok(())
}

fn deterministic_candidate<'a>(
    key: &AffinityKey,
    candidates: &'a [CandidateId],
) -> Result<&'a CandidateId, AccountAffinityError> {
    let mut best: Option<([u8; 32], &'a CandidateId)> = None;
    for candidate in candidates {
        let mut hasher = Sha256::new();
        hasher.update(b"ariadnion-affinity-select-v1\0");
        hasher.update([key.scope() as u8]);
        hasher.update(key.epoch().get().to_be_bytes());
        hasher.update(key.id().as_bytes());
        hasher.update((candidate.as_str().len() as u16).to_be_bytes());
        hasher.update(candidate.as_str().as_bytes());
        let score: [u8; 32] = hasher.finalize().into();
        if best.as_ref().is_none_or(|(current, _)| score < *current) {
            best = Some((score, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
        .ok_or_else(|| error(AccountAffinityErrorCode::EmptyCandidateSet))
}

fn prune_expired(bindings: &mut HashMap<AffinityKey, AffinityBinding>, now: UtcSeconds) {
    bindings.retain(|_, binding| binding.expires_at > now);
}

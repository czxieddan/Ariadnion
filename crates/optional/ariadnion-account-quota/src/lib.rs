// crates/optional/ariadnion-account-quota/src/lib.rs - Account quota contracts for Ariadnion.
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
//! Bounded provider and account quota snapshots with expiry-aware reads.
//!
//! The domain stores only numeric quota facts and typed identities. It never
//! accepts credentials or response bodies. Refresh publication is atomic and
//! generation-checked so readers observe either the old or the new snapshot.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::{Arc, RwLock};

use ariadnion_account_domain::{AccountId, ProviderId};

/// Maximum number of quota snapshots in one published state.
pub const MAX_SNAPSHOTS: usize = 4_096;
/// Maximum number of bytes accepted for a quota window label.
pub const MAX_WINDOW_BYTES: usize = 128;
/// Maximum refresh lifetime accepted for one observation (31 UTC days).
pub const MAX_TTL_SECONDS: u64 = 2_678_400;

/// Stable machine-readable quota failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum QuotaErrorCode {
    /// An argument is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// A batch or label exceeds a fixed bound.
    LimitExceeded,
    /// An optimistic generation does not match the current state.
    GenerationConflict,
    /// A quota record is duplicated in one refresh.
    DuplicateSnapshot,
    /// Used capacity exceeds the configured limit.
    UsageExceedsLimit,
    /// The generation counter cannot advance.
    GenerationExhausted,
    /// Integer arithmetic overflowed while deriving capacity.
    ArithmeticOverflow,
    /// The authoritative snapshot lock is unavailable.
    StateUnavailable,
}

impl QuotaErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ACCOUNT_QUOTA_INVALID_ARGUMENT",
            Self::LimitExceeded => "ACCOUNT_QUOTA_LIMIT_EXCEEDED",
            Self::GenerationConflict => "ACCOUNT_QUOTA_GENERATION_CONFLICT",
            Self::DuplicateSnapshot => "ACCOUNT_QUOTA_DUPLICATE_SNAPSHOT",
            Self::UsageExceedsLimit => "ACCOUNT_QUOTA_USAGE_EXCEEDS_LIMIT",
            Self::GenerationExhausted => "ACCOUNT_QUOTA_GENERATION_EXHAUSTED",
            Self::ArithmeticOverflow => "ACCOUNT_QUOTA_ARITHMETIC_OVERFLOW",
            Self::StateUnavailable => "ACCOUNT_QUOTA_STATE_UNAVAILABLE",
        }
    }
}

impl Display for QuotaErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted quota failure that retains no rejected identity or amount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaError {
    code: QuotaErrorCode,
}

impl QuotaError {
    const fn new(code: QuotaErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> QuotaErrorCode {
        self.code
    }
}

impl Display for QuotaError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for QuotaError {}

/// A UTC Unix timestamp measured in whole seconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixTimeSeconds(u64);

impl UnixTimeSeconds {
    /// Creates a timestamp from seconds since the Unix epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A strictly monotonic publication generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuotaGeneration(u64);

impl QuotaGeneration {
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

    fn next(self) -> Result<Self, QuotaError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(QuotaErrorCode::GenerationExhausted))
    }
}

/// The quota subject represented by one snapshot.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuotaSubject {
    /// A provider-wide quota.
    Provider(ProviderId),
    /// An account-specific quota.
    Account(AccountId),
}

impl QuotaSubject {
    /// Creates a provider quota subject.
    #[must_use]
    pub const fn provider(id: ProviderId) -> Self {
        Self::Provider(id)
    }

    /// Creates an account quota subject.
    #[must_use]
    pub const fn account(id: AccountId) -> Self {
        Self::Account(id)
    }
}

/// A bounded quota window identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuotaWindow(Box<str>);

impl QuotaWindow {
    /// Parses a non-empty ASCII window label.
    ///
    /// # Errors
    /// Returns [`QuotaErrorCode::InvalidArgument`] for control, non-ASCII, or
    /// empty labels, and [`QuotaErrorCode::LimitExceeded`] when oversized.
    pub fn parse(value: &str) -> Result<Self, QuotaError> {
        if value.is_empty()
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(error(QuotaErrorCode::InvalidArgument));
        }
        if value.len() > MAX_WINDOW_BYTES {
            return Err(error(QuotaErrorCode::LimitExceeded));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated window label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for QuotaWindow {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuotaWindow")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Display for QuotaWindow {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One provider or account quota observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaSnapshot {
    subject: QuotaSubject,
    window: QuotaWindow,
    limit: u64,
    used: u64,
    reported_remaining: Option<u64>,
    refreshed_at: UnixTimeSeconds,
    expires_at: UnixTimeSeconds,
}

impl QuotaSnapshot {
    /// Creates a validated quota observation.
    ///
    /// `reported_remaining`, when present, is treated as an upper bound from
    /// the provider and never allowed to increase the local estimate.
    ///
    /// # Errors
    /// Returns a stable error when usage exceeds the limit or expiry is not
    /// after the refresh timestamp.
    pub fn new(
        subject: QuotaSubject,
        window: QuotaWindow,
        limit: u64,
        used: u64,
        reported_remaining: Option<u64>,
        refreshed_at: UnixTimeSeconds,
        expires_at: UnixTimeSeconds,
    ) -> Result<Self, QuotaError> {
        if limit == 0 || expires_at <= refreshed_at {
            return Err(error(QuotaErrorCode::InvalidArgument));
        }
        if expires_at
            .get()
            .checked_sub(refreshed_at.get())
            .is_none_or(|ttl| ttl > MAX_TTL_SECONDS)
        {
            return Err(error(QuotaErrorCode::LimitExceeded));
        }
        if used > limit {
            return Err(error(QuotaErrorCode::UsageExceedsLimit));
        }
        if reported_remaining.is_some_and(|remaining| remaining > limit) {
            return Err(error(QuotaErrorCode::InvalidArgument));
        }
        Ok(Self {
            subject,
            window,
            limit,
            used,
            reported_remaining,
            refreshed_at,
            expires_at,
        })
    }

    /// Returns the quota subject.
    #[must_use]
    pub const fn subject(&self) -> &QuotaSubject {
        &self.subject
    }

    /// Returns the quota window.
    #[must_use]
    pub const fn window(&self) -> &QuotaWindow {
        &self.window
    }

    /// Returns the configured quota limit in integer units.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Returns consumed integer units.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Returns the source refresh timestamp.
    #[must_use]
    pub const fn refreshed_at(&self) -> UnixTimeSeconds {
        self.refreshed_at
    }

    /// Returns the exclusive expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimeSeconds {
        self.expires_at
    }

    /// Returns whether this observation is expired at `now`.
    #[must_use]
    pub fn is_expired_at(&self, now: UnixTimeSeconds) -> bool {
        now >= self.expires_at
    }

    /// Returns a conservative remaining-capacity estimate at `now`.
    ///
    /// Expired observations report zero. Otherwise the estimate is the lower
    /// of `limit - used` and the provider-reported remaining bound.
    #[must_use]
    pub fn conservative_remaining_at(&self, now: UnixTimeSeconds) -> u64 {
        if self.is_expired_at(now) {
            return 0;
        }
        let arithmetic_remaining = self.limit - self.used;
        self.reported_remaining
            .map_or(arithmetic_remaining, |reported| {
                reported.min(arithmetic_remaining)
            })
    }

    /// Returns the conservative remaining capacity at `now`.
    #[must_use]
    pub fn remaining_capacity(&self, now: UnixTimeSeconds) -> u64 {
        self.conservative_remaining_at(now)
    }
}

/// An immutable, sorted quota snapshot collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaSnapshotSet {
    generation: QuotaGeneration,
    snapshots: Arc<[QuotaSnapshot]>,
}

impl QuotaSnapshotSet {
    /// Returns the publication generation.
    #[must_use]
    pub const fn generation(&self) -> QuotaGeneration {
        self.generation
    }

    /// Returns snapshots sorted by subject and window.
    #[must_use]
    pub fn snapshots(&self) -> &[QuotaSnapshot] {
        &self.snapshots
    }
}

#[derive(Debug)]
struct QuotaState {
    generation: QuotaGeneration,
    snapshots: Arc<[QuotaSnapshot]>,
}

/// Evidence returned after a successful refresh publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshReceipt {
    previous_generation: QuotaGeneration,
    generation: QuotaGeneration,
    snapshot_count: usize,
}

impl RefreshReceipt {
    /// Returns the generation replaced by the refresh.
    #[must_use]
    pub const fn previous_generation(&self) -> QuotaGeneration {
        self.previous_generation
    }

    /// Returns the newly committed generation.
    #[must_use]
    pub const fn generation(&self) -> QuotaGeneration {
        self.generation
    }

    /// Returns the number of snapshots committed.
    #[must_use]
    pub const fn snapshot_count(&self) -> usize {
        self.snapshot_count
    }
}

/// Evidence returned after removing expired snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiryReceipt {
    generation: QuotaGeneration,
    removed: usize,
}

impl ExpiryReceipt {
    /// Returns the resulting generation.
    #[must_use]
    pub const fn generation(self) -> QuotaGeneration {
        self.generation
    }

    /// Returns the number of removed observations.
    #[must_use]
    pub const fn removed(self) -> usize {
        self.removed
    }
}

/// Read-only port for consumers that need the latest quota snapshot set.
pub trait QuotaSnapshotPort: Send + Sync {
    /// Returns the latest immutable snapshot set.
    ///
    /// # Errors
    /// Returns [`QuotaErrorCode::StateUnavailable`] when authoritative state
    /// cannot be read.
    fn snapshot_set(&self) -> Result<Arc<QuotaSnapshotSet>, QuotaError>;

    /// Returns the latest immutable snapshot set.
    fn snapshot(&self) -> Result<Arc<QuotaSnapshotSet>, QuotaError> {
        self.snapshot_set()
    }
}

/// Concurrent quota publisher with bounded refresh and expiry operations.
#[derive(Debug)]
pub struct QuotaBook {
    state: RwLock<QuotaState>,
}

impl Default for QuotaBook {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaBook {
    /// Creates an empty quota book at generation zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(QuotaState {
                generation: QuotaGeneration::initial(),
                snapshots: Arc::from([]),
            }),
        }
    }

    /// Returns the current generation.
    ///
    /// # Errors
    /// Returns [`QuotaErrorCode::StateUnavailable`] when the lock is poisoned.
    pub fn generation(&self) -> Result<QuotaGeneration, QuotaError> {
        self.state
            .read()
            .map(|state| state.generation)
            .map_err(|_| error(QuotaErrorCode::StateUnavailable))
    }

    /// Atomically replaces all quota observations after validating the batch.
    ///
    /// The caller must provide the last generation it observed. Validation and
    /// sorting occur before state mutation, so rejected refreshes leave state
    /// unchanged.
    pub fn refresh(
        &self,
        mut snapshots: Vec<QuotaSnapshot>,
        expected_generation: QuotaGeneration,
    ) -> Result<RefreshReceipt, QuotaError> {
        validate_snapshots(&mut snapshots)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| error(QuotaErrorCode::StateUnavailable))?;
        if state.generation != expected_generation {
            return Err(error(QuotaErrorCode::GenerationConflict));
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

    /// Removes snapshots expired at `now`, advancing generation only on change.
    ///
    /// # Errors
    /// Returns a state or generation error; an empty expiry pass is successful
    /// and preserves the current generation.
    pub fn expire(&self, now: UnixTimeSeconds) -> Result<ExpiryReceipt, QuotaError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| error(QuotaErrorCode::StateUnavailable))?;
        let retained: Vec<_> = state
            .snapshots
            .iter()
            .filter(|snapshot| !snapshot.is_expired_at(now))
            .cloned()
            .collect();
        let removed = state.snapshots.len().saturating_sub(retained.len());
        if removed == 0 {
            return Ok(ExpiryReceipt {
                generation: state.generation,
                removed,
            });
        }
        let generation = state.generation.next()?;
        state.generation = generation;
        state.snapshots = retained.into();
        Ok(ExpiryReceipt {
            generation,
            removed,
        })
    }

    /// Returns a shared immutable snapshot set.
    ///
    /// # Errors
    /// Returns [`QuotaErrorCode::StateUnavailable`] when the lock is poisoned.
    pub fn snapshot_set(&self) -> Result<Arc<QuotaSnapshotSet>, QuotaError> {
        self.state
            .read()
            .map(|state| {
                Arc::new(QuotaSnapshotSet {
                    generation: state.generation,
                    snapshots: Arc::clone(&state.snapshots),
                })
            })
            .map_err(|_| error(QuotaErrorCode::StateUnavailable))
    }

    /// Returns the latest immutable snapshot set.
    pub fn snapshot(&self) -> Result<Arc<QuotaSnapshotSet>, QuotaError> {
        self.snapshot_set()
    }
}

impl QuotaSnapshotPort for QuotaBook {
    fn snapshot_set(&self) -> Result<Arc<QuotaSnapshotSet>, QuotaError> {
        self.snapshot_set()
    }
}

fn validate_snapshots(snapshots: &mut [QuotaSnapshot]) -> Result<(), QuotaError> {
    if snapshots.len() > MAX_SNAPSHOTS {
        return Err(error(QuotaErrorCode::LimitExceeded));
    }
    snapshots.sort_by(|left, right| {
        left.subject
            .cmp(&right.subject)
            .then_with(|| left.window.cmp(&right.window))
    });
    if snapshots
        .windows(2)
        .any(|pair| pair[0].subject == pair[1].subject && pair[0].window == pair[1].window)
    {
        return Err(error(QuotaErrorCode::DuplicateSnapshot));
    }
    Ok(())
}

const fn error(code: QuotaErrorCode) -> QuotaError {
    QuotaError::new(code)
}

// crates/optional/ariadnion-account-circuit/src/snapshot_book.rs - Immutable circuit snapshot publication.
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

use std::fmt;
use std::sync::{Arc, RwLock};

use ariadnion_account_domain::AccountId;

use crate::CircuitSnapshot;

/// Maximum number of account snapshots in one process-local publication.
pub const MAX_CIRCUIT_SNAPSHOTS: usize = 1 << 17;

/// Stable failures returned while constructing or publishing circuit snapshots.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CircuitSnapshotBookErrorCode {
    /// More than one snapshot claims the same account identity.
    DuplicateAccount,
    /// A publication exceeds the bounded account-snapshot capacity.
    CapacityExceeded,
    /// The expected publication generation is stale or the candidate skips one.
    GenerationConflict,
    /// A publication generation cannot advance without wrapping.
    VersionExhausted,
    /// The authoritative publication lock is unavailable.
    StateUnavailable,
}

impl CircuitSnapshotBookErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateAccount => "ACCOUNT_CIRCUIT_SNAPSHOT_DUPLICATE_ACCOUNT",
            Self::CapacityExceeded => "ACCOUNT_CIRCUIT_SNAPSHOT_CAPACITY_EXCEEDED",
            Self::GenerationConflict => "ACCOUNT_CIRCUIT_SNAPSHOT_GENERATION_CONFLICT",
            Self::VersionExhausted => "ACCOUNT_CIRCUIT_SNAPSHOT_VERSION_EXHAUSTED",
            Self::StateUnavailable => "ACCOUNT_CIRCUIT_SNAPSHOT_STATE_UNAVAILABLE",
        }
    }
}

impl fmt::Display for CircuitSnapshotBookErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted error returned by the immutable circuit-snapshot publication owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitSnapshotBookError {
    code: CircuitSnapshotBookErrorCode,
}

impl CircuitSnapshotBookError {
    const fn new(code: CircuitSnapshotBookErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> CircuitSnapshotBookErrorCode {
        self.code
    }
}

impl fmt::Display for CircuitSnapshotBookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for CircuitSnapshotBookError {}

/// Monotonic generation of one complete account-circuit snapshot publication.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CircuitSnapshotBookGeneration(u64);

impl CircuitSnapshotBookGeneration {
    /// Returns the initial unpublished generation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Reconstructs a generation from validated publication state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, CircuitSnapshotBookError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| snapshot_book_error(CircuitSnapshotBookErrorCode::VersionExhausted))
    }
}

/// One complete immutable, duplicate-free account-circuit snapshot set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitSnapshotBookSnapshot {
    generation: CircuitSnapshotBookGeneration,
    snapshots: Arc<[CircuitSnapshot]>,
}

impl CircuitSnapshotBookSnapshot {
    /// Validates and freezes account snapshots in canonical account order.
    ///
    /// # Errors
    /// Returns a stable duplicate or capacity error without retaining rejected
    /// input as an observable publication.
    pub fn new(
        generation: CircuitSnapshotBookGeneration,
        mut snapshots: Vec<CircuitSnapshot>,
    ) -> Result<Self, CircuitSnapshotBookError> {
        if snapshots.len() > MAX_CIRCUIT_SNAPSHOTS {
            return Err(snapshot_book_error(
                CircuitSnapshotBookErrorCode::CapacityExceeded,
            ));
        }
        snapshots.sort_unstable_by(|left, right| left.account_id().cmp(right.account_id()));
        let duplicate = snapshots
            .windows(2)
            .any(|pair| pair[0].account_id() == pair[1].account_id());
        if duplicate {
            return Err(snapshot_book_error(
                CircuitSnapshotBookErrorCode::DuplicateAccount,
            ));
        }
        Ok(Self {
            generation,
            snapshots: Arc::from(snapshots.into_boxed_slice()),
        })
    }

    /// Returns the exact publication generation.
    #[must_use]
    pub const fn generation(&self) -> CircuitSnapshotBookGeneration {
        self.generation
    }

    /// Returns account snapshots in deterministic account-identity order.
    #[must_use]
    pub fn snapshots(&self) -> &[CircuitSnapshot] {
        &self.snapshots
    }

    /// Returns the number of account snapshots in this publication.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Returns whether this publication contains no account snapshots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Resolves one account snapshot by canonical identity.
    #[must_use]
    pub fn account(&self, account_id: &AccountId) -> Option<&CircuitSnapshot> {
        self.snapshots
            .binary_search_by(|snapshot| snapshot.account_id().cmp(account_id))
            .ok()
            .map(|index| &self.snapshots[index])
    }
}

/// Read-only port exposing complete immutable account-circuit publications.
pub trait CircuitSnapshotBookPort: Send + Sync {
    /// Returns the latest complete immutable snapshot set.
    ///
    /// # Errors
    /// Returns [`CircuitSnapshotBookErrorCode::StateUnavailable`] when the
    /// authoritative publication state cannot be read.
    fn current_snapshot(
        &self,
    ) -> Result<Arc<CircuitSnapshotBookSnapshot>, CircuitSnapshotBookError>;
}

/// Process-local owner for generation-checked account-circuit publications.
///
/// The single lock protects only the authoritative immutable pointer. Validation
/// and sorting finish before publication; no account-circuit lock or external
/// callback is acquired while this book's lock is held. Poisoning fails closed.
pub struct CircuitSnapshotBook {
    current: RwLock<Arc<CircuitSnapshotBookSnapshot>>,
}

impl CircuitSnapshotBook {
    /// Creates a book at generation zero after validating its initial entries.
    ///
    /// # Errors
    /// Returns a stable duplicate or capacity error when the initial entries
    /// cannot form one complete publication.
    pub fn new(snapshots: Vec<CircuitSnapshot>) -> Result<Self, CircuitSnapshotBookError> {
        CircuitSnapshotBookSnapshot::new(CircuitSnapshotBookGeneration::initial(), snapshots)
            .map(Self::from_snapshot)
    }

    /// Restores a book from an already validated complete publication.
    #[must_use]
    pub fn from_snapshot(snapshot: CircuitSnapshotBookSnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(snapshot)),
        }
    }

    /// Publishes the exact successor of the caller-observed generation.
    ///
    /// Existing readers retain their previous immutable publication, while
    /// later readers observe the complete replacement. A candidate with a
    /// skipped generation is rejected before replacing the authoritative
    /// pointer.
    ///
    /// # Errors
    /// Returns a stable generation, overflow, or state error.
    pub fn publish(
        &self,
        expected_generation: CircuitSnapshotBookGeneration,
        next: CircuitSnapshotBookSnapshot,
    ) -> Result<Arc<CircuitSnapshotBookSnapshot>, CircuitSnapshotBookError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| snapshot_book_error(CircuitSnapshotBookErrorCode::StateUnavailable))?;
        if current.generation() != expected_generation {
            return Err(snapshot_book_error(
                CircuitSnapshotBookErrorCode::GenerationConflict,
            ));
        }
        if next.generation() != expected_generation.next()? {
            return Err(snapshot_book_error(
                CircuitSnapshotBookErrorCode::GenerationConflict,
            ));
        }
        let published = Arc::new(next);
        *current = Arc::clone(&published);
        Ok(published)
    }

    /// Returns the latest complete immutable publication.
    ///
    /// # Errors
    /// Returns [`CircuitSnapshotBookErrorCode::StateUnavailable`] when the
    /// publication lock is poisoned.
    pub fn current_snapshot(
        &self,
    ) -> Result<Arc<CircuitSnapshotBookSnapshot>, CircuitSnapshotBookError> {
        self.current
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| snapshot_book_error(CircuitSnapshotBookErrorCode::StateUnavailable))
    }
}

impl CircuitSnapshotBookPort for CircuitSnapshotBook {
    fn current_snapshot(
        &self,
    ) -> Result<Arc<CircuitSnapshotBookSnapshot>, CircuitSnapshotBookError> {
        CircuitSnapshotBook::current_snapshot(self)
    }
}

impl fmt::Debug for CircuitSnapshotBook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CircuitSnapshotBook(<shared-snapshot>)")
    }
}

const fn snapshot_book_error(code: CircuitSnapshotBookErrorCode) -> CircuitSnapshotBookError {
    CircuitSnapshotBookError::new(code)
}

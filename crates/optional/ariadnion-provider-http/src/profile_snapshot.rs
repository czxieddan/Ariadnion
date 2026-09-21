// crates/optional/ariadnion-provider-http/src/profile_snapshot.rs - Generation-safe provider HTTP profile publication for Ariadnion.
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

//! Atomic publication of complete provider HTTP execution profiles.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;
use std::sync::{Arc, RwLock};

use crate::config::ProviderHttpProfile;
use crate::error::{ProviderHttpError, ProviderHttpErrorCode};

/// A non-zero generation identifying one immutable provider HTTP profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderHttpProfileGeneration(NonZeroU64);

impl ProviderHttpProfileGeneration {
    /// Returns the first generation accepted by a profile book.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a generation reconstructed from an external durable value.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderHttpErrorCode::GenerationConflict`] for zero, which
    /// cannot identify an executable profile.
    pub fn new(value: u64) -> Result<Self, ProviderHttpError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| ProviderHttpError::new(ProviderHttpErrorCode::GenerationConflict))
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Advances the generation without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderHttpErrorCode::GenerationExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, ProviderHttpError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| ProviderHttpError::new(ProviderHttpErrorCode::GenerationExhausted))
    }
}

/// A complete immutable provider HTTP execution profile selected from one
/// publication generation.
///
/// The snapshot owns the already-validated endpoint, method, path/query,
/// headers, limits, TLS trust choice, and proxy boundary. Consumers can retain
/// this value across asynchronous work without resolving a mutable profile
/// identity again. No secret material is stored by this type.
#[derive(Clone)]
pub struct ProviderHttpProfileSnapshot {
    generation: ProviderHttpProfileGeneration,
    profile: Arc<ProviderHttpProfile>,
}

impl ProviderHttpProfileSnapshot {
    /// Creates an immutable snapshot from one already-validated profile.
    #[must_use]
    pub fn new(generation: ProviderHttpProfileGeneration, profile: ProviderHttpProfile) -> Self {
        Self {
            generation,
            profile: Arc::new(profile),
        }
    }

    /// Returns the source publication generation.
    #[must_use]
    pub const fn generation(&self) -> ProviderHttpProfileGeneration {
        self.generation
    }

    /// Returns the exact profile retained for execution.
    #[must_use]
    pub fn profile(&self) -> &ProviderHttpProfile {
        self.profile.as_ref()
    }
}

impl Debug for ProviderHttpProfileSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpProfileSnapshot")
            .field("generation", &self.generation)
            .field("profile", &"<redacted>")
            .finish()
    }
}

/// Process-local owner for complete immutable provider HTTP profile snapshots.
///
/// Publication validates the caller's observed generation and swaps the whole
/// `Arc` under one write lock. Readers therefore observe either the previous
/// snapshot or the complete successor; they never observe a partially updated
/// endpoint, header, trust, or proxy configuration.
pub struct ProviderHttpProfileBook {
    current: RwLock<Arc<ProviderHttpProfileSnapshot>>,
}

impl ProviderHttpProfileBook {
    /// Creates a book from one complete initial snapshot.
    #[must_use]
    pub fn new(initial: ProviderHttpProfileSnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
        }
    }

    /// Reads the current immutable execution snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderHttpErrorCode::StateUnavailable`] when the owner lock
    /// is poisoned.
    pub fn current_snapshot(&self) -> Result<Arc<ProviderHttpProfileSnapshot>, ProviderHttpError> {
        self.current
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| ProviderHttpError::new(ProviderHttpErrorCode::StateUnavailable))
    }

    /// Returns the current publication generation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderHttpErrorCode::StateUnavailable`] when the owner lock
    /// is poisoned.
    pub fn generation(&self) -> Result<ProviderHttpProfileGeneration, ProviderHttpError> {
        self.current_snapshot()
            .map(|snapshot| snapshot.generation())
    }

    /// Publishes the exact successor of the caller-observed generation.
    ///
    /// The expected generation and successor check are performed while holding
    /// the write lock. A stale or skipped publication leaves the current value
    /// unchanged, so an execution that already retained an older snapshot
    /// remains internally consistent and cannot silently switch configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderHttpErrorCode::GenerationConflict`] for stale or
    /// non-successor generations, [`ProviderHttpErrorCode::GenerationExhausted`]
    /// when the counter cannot advance, or
    /// [`ProviderHttpErrorCode::StateUnavailable`] for a poisoned lock.
    pub fn publish(
        &self,
        expected: ProviderHttpProfileGeneration,
        next: ProviderHttpProfileSnapshot,
    ) -> Result<Arc<ProviderHttpProfileSnapshot>, ProviderHttpError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| ProviderHttpError::new(ProviderHttpErrorCode::StateUnavailable))?;
        if current.generation() != expected {
            return Err(ProviderHttpError::new(
                ProviderHttpErrorCode::GenerationConflict,
            ));
        }
        let required = current.generation().next()?;
        if next.generation() != required {
            return Err(ProviderHttpError::new(
                ProviderHttpErrorCode::GenerationConflict,
            ));
        }
        let published = Arc::new(next);
        *current = Arc::clone(&published);
        Ok(published)
    }
}

/// Compatibility alias for callers that name the owner as an atomic book.
pub type AtomicProviderHttpProfileBook = ProviderHttpProfileBook;

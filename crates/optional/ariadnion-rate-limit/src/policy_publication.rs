// crates/optional/ariadnion-rate-limit/src/policy_publication.rs - Static admission policy publication for Ariadnion.
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

use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, RwLock};

use crate::{AdmissionError, AdmissionErrorCode, AdmissionPolicySet, error};

/// Monotonic version of one complete static admission-policy snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdmissionPolicyVersion(u64);

impl AdmissionPolicyVersion {
    /// Returns the initial unpublished version.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Reconstructs a version from durable configuration state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, AdmissionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AdmissionErrorCode::CounterExhausted))
    }
}

/// Immutable admission policies observed at one exact publication version.
#[derive(Clone, Debug)]
pub struct AdmissionPolicySnapshot {
    version: AdmissionPolicyVersion,
    policies: Arc<AdmissionPolicySet>,
}

impl AdmissionPolicySnapshot {
    /// Reconstructs a complete immutable snapshot from validated policies.
    #[must_use]
    pub fn new(version: AdmissionPolicyVersion, policies: AdmissionPolicySet) -> Self {
        Self {
            version,
            policies: Arc::new(policies),
        }
    }

    /// Returns the exact snapshot version.
    #[must_use]
    pub const fn version(&self) -> AdmissionPolicyVersion {
        self.version
    }

    /// Returns the immutable policy set.
    #[must_use]
    pub fn policies(&self) -> &AdmissionPolicySet {
        self.policies.as_ref()
    }
}

/// Receipt proving that one complete policy snapshot was atomically published.
#[derive(Clone, Debug)]
pub struct AdmissionPolicyReceipt {
    snapshot: Arc<AdmissionPolicySnapshot>,
}

impl AdmissionPolicyReceipt {
    /// Returns the newly published version.
    #[must_use]
    pub fn version(&self) -> AdmissionPolicyVersion {
        self.snapshot.version()
    }

    /// Returns the newly published immutable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<AdmissionPolicySnapshot> {
        Arc::clone(&self.snapshot)
    }
}

/// Read-only port for consumers that construct process-local admission engines.
pub trait AdmissionPolicyPort: Send + Sync {
    /// Returns the latest complete immutable policy snapshot.
    ///
    /// # Errors
    /// Returns [`AdmissionErrorCode::StateUnavailable`] when authoritative
    /// publication state cannot be read.
    fn current_snapshot(&self) -> Result<Arc<AdmissionPolicySnapshot>, AdmissionError>;
}

/// Concurrent publisher for complete version-checked policy snapshots.
pub struct AdmissionPolicyBook {
    snapshot: RwLock<Arc<AdmissionPolicySnapshot>>,
}

impl AdmissionPolicyBook {
    /// Creates a policy book at the initial version.
    #[must_use]
    pub fn new(policies: AdmissionPolicySet) -> Self {
        Self::from_snapshot(AdmissionPolicySnapshot::new(
            AdmissionPolicyVersion::initial(),
            policies,
        ))
    }

    /// Restores a policy book from an already validated complete snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: AdmissionPolicySnapshot) -> Self {
        Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
        }
    }

    /// Publishes one complete policy set after an exact-version check.
    ///
    /// Validation occurs before this call when [`AdmissionPolicySet`] is built.
    /// Existing readers retain their prior immutable snapshot, while later readers
    /// observe the complete replacement. Active permits remain owned by their
    /// existing [`crate::AdmissionController`] and are never migrated implicitly.
    ///
    /// # Errors
    /// Returns a stable version-conflict, version-exhaustion, or state error.
    pub fn publish(
        &self,
        expected_version: AdmissionPolicyVersion,
        policies: AdmissionPolicySet,
    ) -> Result<AdmissionPolicyReceipt, AdmissionError> {
        let mut current = self
            .snapshot
            .write()
            .map_err(|_| error(AdmissionErrorCode::StateUnavailable))?;
        if current.version() != expected_version {
            return Err(error(AdmissionErrorCode::PolicyVersionConflict));
        }
        let version = expected_version.next()?;
        let next = Arc::new(AdmissionPolicySnapshot::new(version, policies));
        *current = Arc::clone(&next);
        Ok(AdmissionPolicyReceipt { snapshot: next })
    }

    /// Returns the latest complete immutable policy snapshot.
    ///
    /// # Errors
    /// Returns [`AdmissionErrorCode::StateUnavailable`] when publication state
    /// cannot be read.
    pub fn current_snapshot(&self) -> Result<Arc<AdmissionPolicySnapshot>, AdmissionError> {
        self.snapshot
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| error(AdmissionErrorCode::StateUnavailable))
    }
}

impl AdmissionPolicyPort for AdmissionPolicyBook {
    fn current_snapshot(&self) -> Result<Arc<AdmissionPolicySnapshot>, AdmissionError> {
        AdmissionPolicyBook::current_snapshot(self)
    }
}

impl Debug for AdmissionPolicyBook {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionPolicyBook(<shared-snapshot>)")
    }
}

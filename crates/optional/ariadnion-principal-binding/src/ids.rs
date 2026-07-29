// crates/optional/ariadnion-principal-binding/src/ids.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
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
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Checked optimistic versions for one durable principal binding.

use std::num::NonZeroU64;

use crate::error::{PrincipalBindingError, PrincipalBindingErrorCode, error};

/// A non-zero optimistic version for one principal-binding aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrincipalBindingVersion(NonZeroU64);

impl PrincipalBindingVersion {
    /// Returns the only version assigned during initial provisioning.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic version.
    ///
    /// # Errors
    /// Returns [`PrincipalBindingErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, PrincipalBindingError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(PrincipalBindingErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic version.
    ///
    /// # Errors
    /// Returns [`PrincipalBindingErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, PrincipalBindingError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(PrincipalBindingErrorCode::VersionExhausted))
    }
}

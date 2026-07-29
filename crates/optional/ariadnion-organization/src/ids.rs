// crates/optional/ariadnion-organization/src/ids.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Bounded organization identities and optimistic aggregate versions.

use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU64;

use crate::error::{OrganizationError, OrganizationErrorCode, error};

const MAX_ID_BYTES: usize = 128;

macro_rules! bounded_id {
    ($name:ident, $documentation:literal, $debug_name:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses a non-empty ASCII identity of at most 128 bytes.
            ///
            /// # Errors
            /// Returns [`OrganizationErrorCode::InvalidArgument`] without
            /// retaining the rejected value when validation fails.
            pub fn parse(value: &str) -> Result<Self, OrganizationError> {
                if !valid_id(value) {
                    return Err(error(OrganizationErrorCode::InvalidArgument));
                }
                Ok(Self(value.into()))
            }

            /// Returns the validated identity.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($debug_name, "(<opaque>)"))
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

bounded_id!(
    OrganizationId,
    "A bounded organization aggregate identity.",
    "OrganizationId"
);
bounded_id!(
    MembershipId,
    "A bounded identity for one organization membership.",
    "MembershipId"
);
bounded_id!(TeamId, "A bounded organization team identity.", "TeamId");
bounded_id!(
    OwnershipTransferId,
    "A bounded identity for one ownership-transfer authorization.",
    "OwnershipTransferId"
);

/// A non-zero optimistic version for one organization aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OrganizationVersion(NonZeroU64);

impl OrganizationVersion {
    /// Returns the version assigned at organization creation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic version.
    ///
    /// # Errors
    /// Returns [`OrganizationErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, OrganizationError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(OrganizationErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic version.
    ///
    /// # Errors
    /// Returns [`OrganizationErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, OrganizationError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(OrganizationErrorCode::VersionExhausted))
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(is_id_byte)
}

fn is_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

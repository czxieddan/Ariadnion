// crates/optional/ariadnion-routing-coordinator/src/proxy.rs - Complete routing coordination for Ariadnion.
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
//! Validated destination regions and immutable proxy routing profiles.

use ariadnion_account_domain::AccountId;
use ariadnion_account_proxy::{AccountProxyProfile, ProxyProfileId, RegionConstraint};

use crate::{CoordinatorError, CoordinatorErrorCode, MAX_DESTINATION_REGION_BYTES};

/// A bounded destination region used by schedule and proxy policy.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DestinationRegion(Box<str>);

impl DestinationRegion {
    /// Parses a lower-case ASCII region identity.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorErrorCode::InvalidArgument`] for an empty,
    /// overlong, or malformed value.
    pub fn parse(value: &str) -> Result<Self, CoordinatorError> {
        if !valid_destination_region(value) {
            return Err(CoordinatorError::new(CoordinatorErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated region identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Availability state for one account's proxy route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProxyAvailability {
    /// The route may be used subject to its region constraint.
    Available,
    /// The route is known unavailable.
    Unavailable,
}

/// Immutable routing view of one account proxy execution snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyRoutingProfile {
    account_id: AccountId,
    profile: AccountProxyProfile,
    availability: ProxyAvailability,
}

impl ProxyRoutingProfile {
    /// Creates a routing view that owns the exact metadata-only execution snapshot.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        profile: AccountProxyProfile,
        availability: ProxyAvailability,
    ) -> Self {
        Self {
            account_id,
            profile,
            availability,
        }
    }

    /// Returns the account bound to this route.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the non-secret proxy profile identity.
    #[must_use]
    pub const fn profile_id(&self) -> &ProxyProfileId {
        self.profile.id()
    }

    /// Returns the exact immutable proxy execution snapshot.
    #[must_use]
    pub const fn profile(&self) -> &AccountProxyProfile {
        &self.profile
    }

    /// Returns the destination-region constraint.
    #[must_use]
    pub const fn regions(&self) -> &RegionConstraint {
        self.profile.regions()
    }

    /// Returns the observed proxy availability.
    #[must_use]
    pub const fn availability(&self) -> ProxyAvailability {
        self.availability
    }
}

fn valid_destination_region(value: &str) -> bool {
    let Some(first) = value.as_bytes().first() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= MAX_DESTINATION_REGION_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

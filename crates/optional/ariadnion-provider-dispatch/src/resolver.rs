// crates/optional/ariadnion-provider-dispatch/src/resolver.rs - Static provider model resolution for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Bounded, immutable selector-to-provider-model resolution.

use std::collections::btree_map::{BTreeMap, Entry};
use std::fmt::{self, Debug, Formatter};

use ariadnion_api_domain::{ApiDomainError, ApiDomainErrorCode, ModelSelector};
use ariadnion_provider_sdk::ProviderModelId;

use crate::ProviderModelResolverPort;

/// Resolves a fixed, bounded selector-to-provider-model mapping.
pub struct StaticProviderModelResolver {
    mappings: BTreeMap<ModelSelector, ProviderModelId>,
}

impl StaticProviderModelResolver {
    /// Maximum number of selector mappings retained by one resolver.
    pub const MAX_MAPPINGS: usize = 256;

    /// Builds an immutable resolver from checked selector and provider-model pairs.
    ///
    /// Mappings are retained in deterministic selector order. Duplicate selectors
    /// and collections above [`Self::MAX_MAPPINGS`] are rejected before the
    /// resolver becomes usable.
    ///
    /// # Errors
    ///
    /// Returns [`ApiDomainErrorCode::Conflict`] for a duplicate selector and
    /// [`ApiDomainErrorCode::LimitExceeded`] when the collection is oversized.
    pub fn new<I>(mappings: I) -> Result<Self, ApiDomainError>
    where
        I: IntoIterator<Item = (ModelSelector, ProviderModelId)>,
    {
        let mut checked = BTreeMap::new();
        for (selector, model) in mappings {
            let at_capacity = checked.len() >= Self::MAX_MAPPINGS;
            match checked.entry(selector) {
                Entry::Occupied(_) => return Err(conflict_error()),
                Entry::Vacant(entry) if at_capacity => {
                    drop(entry);
                    return Err(limit_exceeded_error());
                }
                Entry::Vacant(entry) => {
                    entry.insert(model);
                }
            }
        }
        Ok(Self { mappings: checked })
    }
}

impl ProviderModelResolverPort for StaticProviderModelResolver {
    fn resolve_model(&self, selector: &ModelSelector) -> Result<ProviderModelId, ApiDomainError> {
        self.mappings
            .get(selector)
            .cloned()
            .ok_or_else(unavailable_error)
    }
}

impl Debug for StaticProviderModelResolver {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticProviderModelResolver(<redacted>)")
    }
}

const fn conflict_error() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::Conflict)
}

const fn limit_exceeded_error() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::LimitExceeded)
}

const fn unavailable_error() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::Unavailable)
}

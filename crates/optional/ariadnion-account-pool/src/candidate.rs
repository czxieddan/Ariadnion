// crates/optional/ariadnion-account-pool/src/candidate.rs - Secret-free routing candidates for Ariadnion.
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

//! Secret-free candidate projections consumed by routing.

use std::num::NonZeroU32;

use ariadnion_account_domain::{
    AccountEffectiveWindow, AccountId, AccountStatus, ModelName, ProviderId,
};
use ariadnion_account_import::DurableAccountProjection;
use ariadnion_core::TenantId;

use super::{
    AccountImportRecord, AccountPoolError, AccountPoolErrorCode, Availability, CandidateId,
    CandidateRoutingMetadata, Load, Priority, Weight, model_error,
};

/// Secret-free routing metadata projected from an account import record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateMetadata {
    id: CandidateId,
    tenant_id: Option<TenantId>,
    account_id: AccountId,
    provider_id: ProviderId,
    model: Option<ModelName>,
    max_concurrency: Option<NonZeroU32>,
    effective_window: AccountEffectiveWindow,
    priority: Priority,
    weight: Weight,
    load: Load,
    availability: Availability,
}

impl CandidateMetadata {
    /// Creates secret-free metadata for one routing candidate.
    #[must_use]
    pub const fn new(
        id: CandidateId,
        account_id: AccountId,
        provider_id: ProviderId,
        model: Option<ModelName>,
        routing: CandidateRoutingMetadata,
    ) -> Self {
        Self {
            id,
            tenant_id: None,
            account_id,
            provider_id,
            model,
            max_concurrency: None,
            effective_window: AccountEffectiveWindow::OPEN,
            priority: routing.priority,
            weight: routing.weight,
            load: routing.load,
            availability: routing.availability,
        }
    }

    pub(crate) fn from_record(record: &AccountImportRecord) -> Self {
        let account = record.account();
        let mut candidate = Self::new(
            CandidateId::from_account(account.id()),
            account.id().clone(),
            account.provider().id().clone(),
            account.config().default_model().cloned(),
            CandidateRoutingMetadata::new(
                record.priority(),
                record.weight(),
                record.load(),
                record.availability(),
            ),
        );
        candidate.tenant_id = Some(account.tenant_id().clone());
        candidate.max_concurrency = Some(account.config().max_concurrency());
        candidate.effective_window = account.config().effective_window();
        candidate
    }

    pub(super) fn from_durable_account(
        account: DurableAccountProjection,
    ) -> Result<Self, AccountPoolError> {
        let availability =
            if account.status() == AccountStatus::Active && account.default_model().is_some() {
                Availability::Available
            } else {
                Availability::Unavailable
            };
        let routing = CandidateRoutingMetadata::new(
            account.routing_priority().into(),
            account.routing_weight().into(),
            Load::new(0)?,
            availability,
        );
        let id = CandidateId::from_account(account.account_id());
        let max_concurrency = NonZeroU32::new(account.max_concurrency())
            .ok_or_else(|| model_error(AccountPoolErrorCode::InvalidCandidate))?;
        Ok(Self {
            id,
            tenant_id: Some(account.tenant_id().clone()),
            account_id: account.account_id().clone(),
            provider_id: account.provider_id().clone(),
            model: account.default_model().cloned(),
            max_concurrency: Some(max_concurrency),
            effective_window: account.effective_window(),
            priority: routing.priority,
            weight: routing.weight,
            load: routing.load,
            availability: routing.availability,
        })
    }

    /// Returns the stable candidate identity.
    #[must_use]
    pub const fn id(&self) -> &CandidateId {
        &self.id
    }

    /// Returns the account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the source tenant when this candidate came from an account record.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// Returns the provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the configured provider model, when present.
    #[must_use]
    pub const fn model(&self) -> Option<&ModelName> {
        self.model.as_ref()
    }

    /// Returns the persisted simultaneous-attempt bound for this account.
    ///
    /// Manually constructed, tenant-unbound metadata has no authoritative
    /// account configuration and therefore returns `None`.
    #[must_use]
    pub const fn max_concurrency(&self) -> Option<NonZeroU32> {
        self.max_concurrency
    }

    /// Returns the optional half-open UTC interval owned by this configuration.
    ///
    /// The interval is retained without evaluation so callers can compare it
    /// against a fresh observation when routing occurs.
    #[must_use]
    pub const fn effective_window(&self) -> AccountEffectiveWindow {
        self.effective_window
    }

    /// Returns the priority tier.
    #[must_use]
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Returns the relative routing weight.
    #[must_use]
    pub const fn weight(&self) -> Weight {
        self.weight
    }

    /// Returns the captured instantaneous load.
    #[must_use]
    pub const fn load(&self) -> Load {
        self.load
    }

    /// Returns the captured availability fact.
    #[must_use]
    pub const fn availability(&self) -> Availability {
        self.availability
    }
}

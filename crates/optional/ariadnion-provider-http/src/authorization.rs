// crates/optional/ariadnion-provider-http/src/authorization.rs - Reuse authorization stamps for Ariadnion.
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

//! Fail-closed DNS and policy provenance retained by reusable connections.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ariadnion_core::{OutboundPolicyPort, OutboundPolicyRevision};

use crate::config::ProviderHttpProfile;
use crate::dns::{BoundedResolver, ResolutionEpoch, ResolutionRecord};
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};

#[derive(Clone, Copy)]
pub(crate) struct ProviderHttpAuthorizedTarget {
    pub(crate) address: SocketAddr,
    pub(crate) authorization: ProviderHttpAuthorizationStamp,
}

#[derive(Clone, Copy)]
pub(crate) struct ProviderHttpAuthorizationStamp {
    revision: OutboundPolicyRevision,
    epoch: ResolutionEpoch,
    resolved_at: Instant,
}

impl ProviderHttpAuthorizationStamp {
    pub(crate) const fn from_record(record: &ResolutionRecord) -> Self {
        Self {
            revision: record.revision(),
            epoch: record.epoch(),
            resolved_at: record.resolved_at(),
        }
    }

    fn is_current(
        self,
        now: Instant,
        max_age: Duration,
        epoch: ResolutionEpoch,
        revision: OutboundPolicyRevision,
    ) -> bool {
        now >= self.resolved_at
            && now.saturating_duration_since(self.resolved_at) <= max_age
            && self.epoch == epoch
            && self.revision == revision
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProviderHttpConnectionAuthorization {
    origin: ProviderHttpAuthorizationStamp,
    proxy: Option<ProviderHttpAuthorizationStamp>,
}

impl ProviderHttpConnectionAuthorization {
    pub(crate) const fn direct(origin: ProviderHttpAuthorizationStamp) -> Self {
        Self {
            origin,
            proxy: None,
        }
    }

    pub(crate) const fn proxied(
        origin: ProviderHttpAuthorizationStamp,
        proxy: ProviderHttpAuthorizationStamp,
    ) -> Self {
        Self {
            origin,
            proxy: Some(proxy),
        }
    }

    pub(crate) fn is_current(
        self,
        now: Instant,
        max_age: Duration,
        resolver: &dyn BoundedResolver,
        policy: &dyn OutboundPolicyPort,
    ) -> bool {
        let Ok(epoch) = resolver.current_epoch() else {
            return false;
        };
        let revision = policy.revision();
        self.origin.is_current(now, max_age, epoch, revision)
            && self
                .proxy
                .is_none_or(|stamp| stamp.is_current(now, max_age, epoch, revision))
    }
}

pub(crate) struct ProviderHttpAuthorizationBoundary<'a> {
    resolver: &'a dyn BoundedResolver,
    policy: &'a dyn OutboundPolicyPort,
}

impl<'a> ProviderHttpAuthorizationBoundary<'a> {
    pub(crate) const fn new(
        resolver: &'a dyn BoundedResolver,
        policy: &'a dyn OutboundPolicyPort,
    ) -> Self {
        Self { resolver, policy }
    }

    pub(crate) fn is_current(
        &self,
        authorization: ProviderHttpConnectionAuthorization,
        profile: &ProviderHttpProfile,
    ) -> bool {
        authorization.is_current(
            Instant::now(),
            profile.timeouts().max_resolution_age(),
            self.resolver,
            self.policy,
        )
    }

    pub(crate) fn ensure_current(
        &self,
        authorization: ProviderHttpConnectionAuthorization,
        profile: &ProviderHttpProfile,
    ) -> Result<(), ProviderHttpError> {
        if self.is_current(authorization, profile) {
            Ok(())
        } else {
            Err(ProviderHttpError::with_phase(
                ProviderHttpErrorCode::OutboundDenied,
                ProviderHttpPhase::Resolution,
            ))
        }
    }
}

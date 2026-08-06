// crates/optional/ariadnion-provider-http/src/egress.rs - Provider outbound authorization gate for Ariadnion.
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

use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ariadnion_core::{
    OutboundAuthorizationRequest, OutboundPolicyDecision, OutboundPolicyPort, RequestContext,
};

use crate::dns::{ResolutionRecord, classify_address};

/// Stable fail-closed egress errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EgressError {
    /// Resolver returned no usable addresses.
    ResolutionEmpty,
    /// A configured answer bound was exceeded.
    TooManyAddresses,
    /// At least one answer belongs to a forbidden range.
    ForbiddenAddress,
    /// Policy denied the complete resolution.
    PolicyDenied,
    /// The policy revision changed during authorization.
    PolicyChanged,
    /// A cached resolution exceeded its age budget.
    StaleResolution,
    /// Request cancellation was observed.
    Cancelled,
    /// Request deadline expired before work completed.
    DeadlineExceeded,
}

impl Display for EgressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ResolutionEmpty => "resolution_empty",
            Self::TooManyAddresses => "too_many_addresses",
            Self::ForbiddenAddress => "forbidden_address",
            Self::PolicyDenied => "policy_denied",
            Self::PolicyChanged => "policy_changed",
            Self::StaleResolution => "stale_resolution",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
        })
    }
}

impl std::error::Error for EgressError {}

/// Selects the first allowed numeric address in resolver order.
#[must_use]
pub fn select_numeric_address(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses
        .iter()
        .copied()
        .find(|address| !classify_address(*address).is_forbidden())
}

impl ResolutionRecord {
    /// Authorizes the exact complete resolution before numeric address selection.
    pub fn authorize(&self, policy: &dyn OutboundPolicyPort) -> Result<IpAddr, EgressError> {
        if policy.revision() != self.revision() {
            return Err(EgressError::PolicyChanged);
        }
        let request =
            OutboundAuthorizationRequest::new(self.target(), self.addresses(), self.revision())
                .map_err(|_| EgressError::PolicyDenied)?;
        match policy.authorize(&request) {
            OutboundPolicyDecision::Allow => {
                select_numeric_address(self.addresses()).ok_or(EgressError::ForbiddenAddress)
            }
            OutboundPolicyDecision::Deny(_) => Err(EgressError::PolicyDenied),
            _ => Err(EgressError::PolicyDenied),
        }
    }
    /// Rejects records older than the configured maximum age.
    pub fn ensure_fresh(&self, now: Instant, max_age: Duration) -> Result<(), EgressError> {
        if now.saturating_duration_since(self.resolved_at()) > max_age {
            Err(EgressError::StaleResolution)
        } else {
            Ok(())
        }
    }
}

/// Checks cancellation first, then deadline, before waiting for a bounded interval.
pub fn wait_for(context: &RequestContext, duration: Duration) -> Result<(), EgressError> {
    context.check_active().map_err(|error| {
        if error.code() == ariadnion_core::ErrorCode::Cancelled {
            EgressError::Cancelled
        } else {
            EgressError::DeadlineExceeded
        }
    })?;
    let start = Instant::now();
    let poll = Duration::from_millis(25);
    while start.elapsed() < duration {
        context.check_active().map_err(|error| {
            if error.code() == ariadnion_core::ErrorCode::Cancelled {
                EgressError::Cancelled
            } else {
                EgressError::DeadlineExceeded
            }
        })?;
        let remaining = poll.min(duration.saturating_sub(start.elapsed()));
        let sleep_for = context
            .deadline()
            .and_then(|deadline| deadline.duration_since(std::time::SystemTime::now()).ok())
            .map_or(remaining, |deadline| remaining.min(deadline));
        if sleep_for.is_zero() {
            return Err(EgressError::DeadlineExceeded);
        }
        std::thread::sleep(sleep_for);
    }
    context.check_active().map_err(|error| {
        if error.code() == ariadnion_core::ErrorCode::Cancelled {
            EgressError::Cancelled
        } else {
            EgressError::DeadlineExceeded
        }
    })
}

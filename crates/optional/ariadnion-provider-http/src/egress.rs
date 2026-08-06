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

use crate::config::ProviderHttpTimeouts;
use crate::dns::{BoundedResolver, ResolutionRecord, classify_address};
use crate::timeout::{check_context, ensure_time_runtime};

/// Stable fail-closed egress errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EgressError {
    /// Resolver returned no usable addresses.
    ResolutionEmpty,
    /// System resolution failed without exposing host or platform details.
    ResolutionFailed,
    /// A checked resolution was rebound to a different canonical host.
    ResolutionTargetMismatch,
    /// Resolver input host is not canonical and bounded.
    InvalidHost,
    /// A configured answer bound was exceeded.
    TooManyAddresses,
    /// At least one answer belongs to a forbidden range.
    ForbiddenAddress,
    /// Resolver returned a duplicate answer.
    DuplicateAddress,
    /// Resolver epoch is invalid.
    ResolutionEpochInvalid,
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
    /// The operation requires a Tokio runtime that is not active.
    RuntimeUnavailable,
}

const EGRESS_ERROR_CODES: [&str; 14] = [
    "resolution_empty",
    "resolution_failed",
    "resolution_target_mismatch",
    "invalid_host",
    "too_many_addresses",
    "forbidden_address",
    "duplicate_address",
    "resolution_epoch_invalid",
    "policy_denied",
    "policy_changed",
    "stale_resolution",
    "cancelled",
    "deadline_exceeded",
    "runtime_unavailable",
];

impl EgressError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        EGRESS_ERROR_CODES[self as usize]
    }
}

impl Display for EgressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for EgressError {}

fn select_numeric_address(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses
        .iter()
        .copied()
        .find(|address| !classify_address(*address).is_forbidden())
}

impl ResolutionRecord {
    /// Authorizes only when the caller still observes the captured resolver epoch.
    ///
    /// The complete checked address set is authorized before one numeric address
    /// is selected, and no stale record or changed policy revision is accepted.
    ///
    /// # Errors
    ///
    /// Returns a stable [`EgressError`] when the record is stale, the policy changed
    /// or denied the complete set, the resolver epoch is unavailable, or no allowed
    /// numeric address can be selected.
    pub fn authorize(
        &self,
        now: Instant,
        max_age: Duration,
        resolver: &dyn BoundedResolver,
        policy: &dyn OutboundPolicyPort,
    ) -> Result<IpAddr, EgressError> {
        validate_authorization_freshness(self, now, max_age, resolver)?;
        authorize_policy(policy, self)?;
        select_numeric_address(self.addresses()).ok_or(EgressError::ForbiddenAddress)
    }
}

fn validate_authorization_freshness(
    record: &ResolutionRecord,
    now: Instant,
    max_age: Duration,
    resolver: &dyn BoundedResolver,
) -> Result<(), EgressError> {
    let epoch = resolver.current_epoch()?;
    if now < record.resolved_at()
        || epoch != record.epoch()
        || now.saturating_duration_since(record.resolved_at()) > max_age
    {
        Err(EgressError::StaleResolution)
    } else {
        Ok(())
    }
}

fn authorize_policy(
    policy: &dyn OutboundPolicyPort,
    record: &ResolutionRecord,
) -> Result<(), EgressError> {
    if policy.revision() != record.revision() {
        return Err(EgressError::PolicyChanged);
    }
    let request =
        OutboundAuthorizationRequest::new(record.target(), record.addresses(), record.revision())
            .map_err(|_| EgressError::PolicyDenied)?;
    if decision_allows(policy.authorize(&request)) {
        Ok(())
    } else {
        Err(EgressError::PolicyDenied)
    }
}

fn decision_allows(decision: OutboundPolicyDecision) -> bool {
    match decision {
        OutboundPolicyDecision::Allow => true,
        OutboundPolicyDecision::Deny(_) | _ => false,
    }
}

/// Asynchronously waits in bounded cancellation and deadline-aware increments.
///
/// The future must be polled by a Tokio runtime with its time driver enabled.
///
/// # Errors
///
/// Returns [`EgressError::Cancelled`] or [`EgressError::DeadlineExceeded`] when
/// the request stops being active. Returns [`EgressError::RuntimeUnavailable`]
/// when polled without an active Tokio runtime.
pub async fn wait_for(
    context: &RequestContext,
    timeouts: ProviderHttpTimeouts,
    duration: Duration,
) -> Result<(), EgressError> {
    check_context(context)?;
    ensure_time_runtime()?;
    let start = Instant::now();
    let poll = timeouts.cancellation_poll();
    while start.elapsed() < duration {
        check_context(context)?;
        let remaining = poll.min(duration.saturating_sub(start.elapsed()));
        let sleep_for = context
            .deadline()
            .and_then(|deadline| deadline.duration_since(std::time::SystemTime::now()).ok())
            .map_or(remaining, |deadline| remaining.min(deadline));
        if sleep_for.is_zero() {
            return check_context(context);
        }
        tokio::time::sleep(sleep_for).await;
    }
    check_context(context)
}

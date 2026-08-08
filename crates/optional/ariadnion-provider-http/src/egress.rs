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

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ariadnion_core::{
    MAX_OUTBOUND_RESOLVED_ADDRESSES, OutboundAuthorizationRequest, OutboundDenyReason,
    OutboundPolicyDecision, OutboundPolicyPort, OutboundPolicyRevision, OutboundTarget,
    RequestContext,
};

use crate::config::ProviderHttpTimeouts;
use crate::dns::{BoundedResolver, ResolutionRecord, classify_address};
use crate::timeout::{check_context, ensure_time_runtime};

/// Maximum exact target rules in one immutable static outbound snapshot.
pub const MAX_STATIC_OUTBOUND_POLICY_RULES: usize = 64;

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
    /// A static policy snapshot has no rules or repeats an exact target.
    InvalidPolicyRules,
    /// A static policy snapshot exceeds its exact rule bound.
    TooManyPolicyRules,
}

const EGRESS_ERROR_CODES: [&str; 16] = [
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
    "invalid_policy_rules",
    "too_many_policy_rules",
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

/// One exact static outbound target and its approved numeric addresses.
///
/// Rules contain no wildcard, suffix, prefix, or CIDR matching. Construction
/// rejects empty, duplicate, forbidden, and oversized address collections.
#[derive(Clone, Eq, PartialEq)]
pub struct StaticOutboundRule {
    target: OutboundTarget,
    addresses: Box<[IpAddr]>,
}

impl StaticOutboundRule {
    /// Creates one immutable exact allow rule.
    ///
    /// # Errors
    ///
    /// Returns a stable [`EgressError`] when the address collection is empty,
    /// duplicated, forbidden, or exceeds the core authorization boundary.
    pub fn new<I>(target: OutboundTarget, addresses: I) -> Result<Self, EgressError>
    where
        I: IntoIterator<Item = IpAddr>,
    {
        Ok(Self {
            target,
            addresses: collect_static_addresses(addresses)?.into_boxed_slice(),
        })
    }

    fn allows(&self, request: &OutboundAuthorizationRequest<'_>) -> bool {
        self.target == *request.target()
            && request.addresses().iter().all(|address| {
                !classify_address(*address).is_forbidden()
                    && self.addresses.binary_search(address).is_ok()
            })
    }
}

impl Debug for StaticOutboundRule {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticOutboundRule { redacted }")
    }
}

/// Immutable bounded exact-match implementation of [`OutboundPolicyPort`].
///
/// The snapshot denies by default. It allows a request only when its revision,
/// canonical target, port, and every member of the complete address set match
/// one configured rule. It performs no network or persistent-storage I/O.
#[derive(Clone, Eq, PartialEq)]
pub struct StaticOutboundPolicy {
    revision: OutboundPolicyRevision,
    rules: Box<[StaticOutboundRule]>,
}

impl StaticOutboundPolicy {
    /// Creates one immutable bounded policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError::InvalidPolicyRules`] for an empty collection or
    /// duplicate exact target and [`EgressError::TooManyPolicyRules`] above
    /// [`MAX_STATIC_OUTBOUND_POLICY_RULES`].
    pub fn new<I>(revision: OutboundPolicyRevision, rules: I) -> Result<Self, EgressError>
    where
        I: IntoIterator<Item = StaticOutboundRule>,
    {
        let rules = collect_static_rules(rules)?;
        Ok(Self {
            revision,
            rules: rules.into_boxed_slice(),
        })
    }

    /// Returns the number of exact allow rules in this snapshot.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl OutboundPolicyPort for StaticOutboundPolicy {
    fn revision(&self) -> OutboundPolicyRevision {
        self.revision
    }

    fn authorize(&self, request: &OutboundAuthorizationRequest<'_>) -> OutboundPolicyDecision {
        if request.revision() != self.revision {
            return OutboundPolicyDecision::Deny(OutboundDenyReason::PolicyChanged);
        }
        match self
            .rules
            .binary_search_by(|rule| rule.target.cmp(request.target()))
        {
            Ok(index) if self.rules[index].allows(request) => OutboundPolicyDecision::Allow,
            Ok(_) => OutboundPolicyDecision::Deny(OutboundDenyReason::AddressDenied),
            Err(_) => OutboundPolicyDecision::Deny(OutboundDenyReason::TargetDenied),
        }
    }
}

impl Debug for StaticOutboundPolicy {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticOutboundPolicy { redacted }")
    }
}

fn collect_static_addresses<I>(addresses: I) -> Result<Vec<IpAddr>, EgressError>
where
    I: IntoIterator<Item = IpAddr>,
{
    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    for address in addresses {
        validate_static_address(address, output.len(), &mut seen)?;
        output.push(address);
    }
    if output.is_empty() {
        return Err(EgressError::ResolutionEmpty);
    }
    output.sort_unstable();
    Ok(output)
}

fn validate_static_address(
    address: IpAddr,
    count: usize,
    seen: &mut BTreeSet<IpAddr>,
) -> Result<(), EgressError> {
    if count == MAX_OUTBOUND_RESOLVED_ADDRESSES {
        return Err(EgressError::TooManyAddresses);
    }
    if classify_address(address).is_forbidden() {
        return Err(EgressError::ForbiddenAddress);
    }
    if !seen.insert(address) {
        return Err(EgressError::DuplicateAddress);
    }
    Ok(())
}

fn collect_static_rules<I>(rules: I) -> Result<Vec<StaticOutboundRule>, EgressError>
where
    I: IntoIterator<Item = StaticOutboundRule>,
{
    let mut output = Vec::new();
    let mut targets = BTreeSet::new();
    for rule in rules {
        validate_static_rule(&rule, output.len(), &mut targets)?;
        output.push(rule);
    }
    if output.is_empty() {
        return Err(EgressError::InvalidPolicyRules);
    }
    output.sort_by(|left, right| left.target.cmp(&right.target));
    Ok(output)
}

fn validate_static_rule(
    rule: &StaticOutboundRule,
    count: usize,
    targets: &mut BTreeSet<OutboundTarget>,
) -> Result<(), EgressError> {
    if count == MAX_STATIC_OUTBOUND_POLICY_RULES {
        return Err(EgressError::TooManyPolicyRules);
    }
    if !targets.insert(rule.target.clone()) {
        return Err(EgressError::InvalidPolicyRules);
    }
    Ok(())
}

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

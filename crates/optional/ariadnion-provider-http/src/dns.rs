// crates/optional/ariadnion-provider-http/src/dns.rs - Bounded provider DNS contracts for Ariadnion.
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
// SPDX-License-Identifier: LicenseRef-AHCL-1.0

use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::time::Instant;

use ariadnion_core::{
    MAX_OUTBOUND_RESOLVED_ADDRESSES, OutboundHost, OutboundPolicyRevision, OutboundTarget,
    RequestContext,
};

use crate::config::ProviderHttpTimeouts;
use crate::egress::EgressError;
use crate::timeout::run_with_timeout;

const MAX_RESOLUTION_HOST_ITERATIONS: usize = MAX_OUTBOUND_RESOLVED_ADDRESSES * 4;

/// Nonzero resolver-configuration generation used to reject rebinding races.
///
/// A generation remains stable across lookups and changes only when the resolver
/// configuration is replaced or reloaded.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolutionEpoch(u64);

impl ResolutionEpoch {
    /// Creates a nonzero epoch.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError::ResolutionEpochInvalid`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, EgressError> {
        if value == 0 {
            Err(EgressError::ResolutionEpochInvalid)
        } else {
            Ok(Self(value))
        }
    }
    /// Returns the epoch value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A checked, deduplicated resolver answer set bound to one resolver epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAddresses {
    host: OutboundHost,
    addresses: Box<[IpAddr]>,
    epoch: ResolutionEpoch,
    resolved_at: Instant,
}

impl ResolvedAddresses {
    fn from_checked_answers(
        host: OutboundHost,
        addresses: Vec<IpAddr>,
        epoch: ResolutionEpoch,
        resolved_at: Instant,
    ) -> Result<Self, EgressError> {
        validate_record_addresses(&addresses)?;
        Ok(Self {
            host,
            addresses: addresses.into_boxed_slice(),
            epoch,
            resolved_at,
        })
    }
    /// Returns the canonical host used for this resolution.
    #[must_use]
    pub const fn host(&self) -> &OutboundHost {
        &self.host
    }
    /// Returns the complete validated address set.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
    /// Returns the resolver epoch.
    #[must_use]
    pub const fn epoch(&self) -> ResolutionEpoch {
        self.epoch
    }
    /// Returns the monotonic completion instant.
    #[must_use]
    pub const fn resolved_at(&self) -> Instant {
        self.resolved_at
    }
}

/// An asynchronous bounded resolver implementation supplied by the runtime adapter.
pub trait BoundedResolver: Send + Sync {
    /// Streams numeric answers and returns the configuration epoch that produced them.
    ///
    /// Implementations must stop returning answers after cancellation, a request
    /// deadline, or the configured resolution phase budget. Each answer is passed
    /// directly to `visitor`; implementations must not retain an unbounded copy.
    /// Because the visitor receives only [`IpAddr`], implementations that start
    /// from socket addresses must reject every IPv6 answer with a nonzero scope
    /// identifier before discarding that metadata. [`normalize_socket_answer`]
    /// provides the production checked conversion.
    ///
    /// # Errors
    ///
    /// Returns a stable [`EgressError`] for resolution failures, visitor rejection,
    /// cancellation, deadlines, phase exhaustion, or an unavailable runtime.
    fn resolve<'a>(
        &'a self,
        host: &'a OutboundHost,
        context: &'a RequestContext,
        timeouts: ProviderHttpTimeouts,
        visitor: &'a mut (dyn FnMut(IpAddr) -> Result<(), EgressError> + Send),
    ) -> Pin<Box<dyn Future<Output = Result<ResolutionEpoch, EgressError>> + Send + 'a>>;

    /// Returns the active resolver-configuration epoch.
    ///
    /// Lookup activity must not change this value. A different value indicates
    /// that records produced under the prior resolver configuration are stale.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError::ResolutionEpochInvalid`] when an implementation
    /// cannot provide a nonzero configuration generation.
    fn current_epoch(&self) -> Result<ResolutionEpoch, EgressError>;

    /// Resolves one host into a checked, deduplicated, bounded answer set.
    ///
    /// At most [`MAX_OUTBOUND_RESOLVED_ADDRESSES`] unique numeric addresses are
    /// retained. The operation observes request cancellation, the request deadline,
    /// and the independent resolution phase budget.
    ///
    /// # Errors
    ///
    /// Returns a stable [`EgressError`] when resolution fails, any answer is
    /// forbidden, the answer stream exceeds its CPU or allocation bounds, the
    /// resolver configuration changes, the request stops, or Tokio is unavailable.
    fn resolve_checked<'a>(
        &'a self,
        host: &'a OutboundHost,
        context: &'a RequestContext,
        timeouts: ProviderHttpTimeouts,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedAddresses, EgressError>> + Send + 'a>> {
        self.resolve_checked_with_limit(host, context, timeouts, MAX_OUTBOUND_RESOLVED_ADDRESSES)
    }

    /// Resolves one host within an explicit checked profile answer limit.
    ///
    /// `max_answers` must be nonzero and cannot exceed the core outbound
    /// authorization boundary. Duplicate answers do not consume this limit.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError::TooManyAddresses`] when the supplied limit is
    /// invalid or the resolver yields too many unique answers. Other failures
    /// are identical to [`Self::resolve_checked`].
    fn resolve_checked_with_limit<'a>(
        &'a self,
        host: &'a OutboundHost,
        context: &'a RequestContext,
        timeouts: ProviderHttpTimeouts,
        max_answers: usize,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedAddresses, EgressError>> + Send + 'a>> {
        Box::pin(async move {
            validate_resolution_limit(max_answers)?;
            let mut addresses = Vec::with_capacity(max_answers);
            let mut seen = BTreeSet::new();
            let mut iterations = 0_usize;
            let mut visitor = |address| {
                retain_resolved_address(
                    address,
                    &mut iterations,
                    &mut seen,
                    &mut addresses,
                    max_answers,
                )
            };
            let resolution = self.resolve(host, context, timeouts, &mut visitor);
            let epoch = run_with_timeout(
                context,
                timeouts.resolution(),
                timeouts.cancellation_poll(),
                resolution,
            )
            .await?;
            if self.current_epoch()? != epoch {
                return Err(EgressError::StaleResolution);
            }
            ResolvedAddresses::from_checked_answers(host.clone(), addresses, epoch, Instant::now())
        })
    }
}

/// Tokio DNS resolver without an internal cache or textual-address output.
#[derive(Debug)]
pub struct TokioSystemResolver {
    epoch: ResolutionEpoch,
}

impl TokioSystemResolver {
    /// Creates an uncached system resolver in the initial configuration epoch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            epoch: ResolutionEpoch(1),
        }
    }

    /// Creates an uncached resolver for an explicit configuration generation.
    ///
    /// The supplied generation remains unchanged for the lifetime of this resolver.
    #[must_use]
    pub const fn with_epoch(epoch: ResolutionEpoch) -> Self {
        Self { epoch }
    }
}

impl Default for TokioSystemResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedResolver for TokioSystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a OutboundHost,
        context: &'a RequestContext,
        timeouts: ProviderHttpTimeouts,
        visitor: &'a mut (dyn FnMut(IpAddr) -> Result<(), EgressError> + Send),
    ) -> Pin<Box<dyn Future<Output = Result<ResolutionEpoch, EgressError>> + Send + 'a>> {
        let lookup = async move {
            let entries = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|_| EgressError::ResolutionFailed)?;
            for entry in entries {
                visitor(normalize_socket_answer(entry)?)?;
            }
            Ok(self.epoch)
        };
        Box::pin(run_with_timeout(
            context,
            timeouts.resolution(),
            timeouts.cancellation_poll(),
            lookup,
        ))
    }

    fn current_epoch(&self) -> Result<ResolutionEpoch, EgressError> {
        Ok(self.epoch)
    }
}

fn retain_resolved_address(
    address: IpAddr,
    iterations: &mut usize,
    seen: &mut BTreeSet<IpAddr>,
    addresses: &mut Vec<IpAddr>,
    limit: usize,
) -> Result<(), EgressError> {
    validate_resolution_iterations(*iterations)?;
    *iterations += 1;
    if classify_address(address).is_forbidden() {
        return Err(EgressError::ForbiddenAddress);
    }
    if !seen.insert(address) {
        return Ok(());
    }
    if addresses.len() == limit {
        return Err(EgressError::TooManyAddresses);
    }
    addresses.push(address);
    Ok(())
}

/// Returns a stable, duplicate-free host sequence, rejecting empty or oversized input.
///
/// Processing stops after a bounded number of input items even when every item is
/// a duplicate, and at most `limit` canonical hosts are retained.
///
/// # Errors
///
/// Returns [`EgressError::TooManyAddresses`] for invalid bounds or excessive input,
/// [`EgressError::InvalidHost`] for a noncanonical host, and
/// [`EgressError::ResolutionEmpty`] when no usable host remains.
pub fn resolve_bounded<I, S>(hosts: I, limit: usize) -> Result<Vec<String>, EgressError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    validate_resolution_limit(limit)?;
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for (iterations, item) in hosts.into_iter().enumerate() {
        validate_resolution_iterations(iterations)?;
        retain_host(item.as_ref(), &mut seen, &mut output, limit)?;
    }
    if output.is_empty() {
        return Err(EgressError::ResolutionEmpty);
    }
    Ok(output)
}

fn validate_resolution_limit(limit: usize) -> Result<(), EgressError> {
    if limit == 0 || limit > MAX_OUTBOUND_RESOLVED_ADDRESSES {
        return Err(EgressError::TooManyAddresses);
    }
    Ok(())
}

fn validate_resolution_iterations(iterations: usize) -> Result<(), EgressError> {
    if iterations == MAX_RESOLUTION_HOST_ITERATIONS {
        return Err(EgressError::TooManyAddresses);
    }
    Ok(())
}

fn retain_host(
    value: &str,
    seen: &mut BTreeSet<String>,
    output: &mut Vec<String>,
    limit: usize,
) -> Result<(), EgressError> {
    if value.is_empty() || seen.contains(value) {
        return Ok(());
    }
    if output.len() == limit {
        return Err(EgressError::TooManyAddresses);
    }
    OutboundHost::parse(value).map_err(|_| EgressError::InvalidHost)?;
    seen.insert(value.to_owned());
    output.push(value.to_owned());
    Ok(())
}

/// Address classification used by the fail-closed egress gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressClass {
    /// Address is eligible for policy evaluation.
    Allowed,
    /// Address belongs to a prohibited range.
    Forbidden,
}

impl AddressClass {
    /// Returns whether the address must be rejected.
    #[must_use]
    pub const fn is_forbidden(self) -> bool {
        matches!(self, Self::Forbidden)
    }
}

/// Converts one resolver socket answer without discarding IPv6 scope metadata.
///
/// IPv4 and unscoped IPv6 answers retain only their numeric address because the
/// transport dials a separately validated port. Scoped IPv6 answers fail closed
/// before conversion so no zone identifier can be silently lost.
///
/// # Errors
///
/// Returns [`EgressError::ForbiddenAddress`] for an IPv6 answer with a nonzero
/// scope identifier.
pub fn normalize_socket_answer(address: SocketAddr) -> Result<IpAddr, EgressError> {
    match address {
        SocketAddr::V4(value) => Ok(IpAddr::V4(*value.ip())),
        SocketAddr::V6(value) if value.scope_id() == 0 => Ok(IpAddr::V6(*value.ip())),
        SocketAddr::V6(_) => Err(EgressError::ForbiddenAddress),
    }
}

/// Classifies loopback, private, local, special-use, and metadata ranges.
#[must_use]
pub fn classify_address(address: IpAddr) -> AddressClass {
    if address_is_forbidden(address) {
        AddressClass::Forbidden
    } else {
        AddressClass::Allowed
    }
}

fn address_is_forbidden(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => forbidden_v4(value),
        IpAddr::V6(value) => forbidden_v6(value),
    }
}

fn forbidden_v6(value: std::net::Ipv6Addr) -> bool {
    value.is_loopback()
        || value.is_unspecified()
        || (value.segments()[0] & 0xfe00) == 0xfc00
        || (value.segments()[0] & 0xffc0) == 0xfe80
        || (value.segments()[0] & 0xffc0) == 0xfec0
        || (value.segments()[0] & 0xff00) == 0xff00
        || is_ipv6_special_use(value)
        || value.to_ipv4_mapped().is_some()
}

fn is_ipv6_documentation(value: std::net::Ipv6Addr) -> bool {
    let segments = value.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_ipv6_special_use(value: std::net::Ipv6Addr) -> bool {
    let s = value.segments();
    is_protocol_assignment_block(s)
        || is_ipv6_documentation(value)
        || is_ipv6_transition(s)
        || is_ipv6_special_prefix(s)
}

fn is_protocol_assignment_block(s: [u16; 8]) -> bool {
    s[0] == 0x2001 && (s[1] & 0xfe00) == 0
}

fn is_ipv6_transition(s: [u16; 8]) -> bool {
    is_teredo(s) || s[0] == 0x2002 || is_ipv4_compatible(s) || is_nat64_well_known(s)
}

fn is_ipv6_special_prefix(s: [u16; 8]) -> bool {
    is_ipv6_benchmark(s)
        || is_orchid(s)
        || is_orchid_v2(s)
        || is_discard_only(s)
        || is_ipv6_documentation_3fff(s)
        || is_additional_ipv6_special_use(s)
}

fn is_additional_ipv6_special_use(s: [u16; 8]) -> bool {
    s[0..4] == [0x0100, 0, 0, 1]
        || (s[0] == 0x2620 && s[1] == 0x004f && s[2] == 0x8000)
        || s[0] == 0x5f00
}

fn is_teredo(s: [u16; 8]) -> bool {
    s[0] == 0x2001 && s[1] == 0
}
fn is_ipv6_benchmark(s: [u16; 8]) -> bool {
    s[0] == 0x2001 && s[1] == 2 && s[2] == 0
}
fn is_orchid(s: [u16; 8]) -> bool {
    s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010
}
fn is_orchid_v2(s: [u16; 8]) -> bool {
    s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020
}
fn is_discard_only(s: [u16; 8]) -> bool {
    s[0..4] == [0x0100, 0, 0, 0]
}
fn is_ipv6_documentation_3fff(s: [u16; 8]) -> bool {
    s[0] == 0x3fff && (s[1] & 0xf000) == 0
}
fn is_ipv4_compatible(s: [u16; 8]) -> bool {
    s[0..6] == [0, 0, 0, 0, 0, 0]
}
fn is_nat64_well_known(s: [u16; 8]) -> bool {
    s[0..6] == [0x0064, 0xff9b, 0, 0, 0, 0] || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1)
}

fn forbidden_v4(value: Ipv4Addr) -> bool {
    let octets = value.octets();
    value.is_loopback()
        || value.is_unspecified()
        || value.is_private()
        || value.is_link_local()
        || value.is_multicast()
        || broadcast_or_cgnat(octets)
        || documentation_range(octets)
        || metadata_or_reserved(octets)
}

fn broadcast_or_cgnat(o: [u8; 4]) -> bool {
    o == [255, 255, 255, 255] || (o[0] == 100 && (64..=127).contains(&o[1]))
}

fn documentation_range(o: [u8; 4]) -> bool {
    matches!(o, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
}

fn metadata_or_reserved(o: [u8; 4]) -> bool {
    matches!(
        o,
        [0, _, _, _]
            | [240..=255, _, _, _]
            | [169, 254, _, _]
            | [192, 88, 99, _]
            | [192, 31, 196, _]
            | [192, 52, 193, _]
            | [192, 175, 48, _]
            | [192, 0, 0, _]
            | [198, 18..=19, _, _]
    )
}

/// A validated complete resolution with policy revision and monotonic timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionRecord {
    target: OutboundTarget,
    addresses: Box<[IpAddr]>,
    revision: OutboundPolicyRevision,
    epoch: ResolutionEpoch,
    resolved_at: Instant,
}

impl ResolutionRecord {
    /// Binds one checked resolver result to its target and policy revision.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError::ResolutionTargetMismatch`] when the checked answer
    /// set was produced for a different canonical host.
    pub fn from_resolution(
        target: OutboundTarget,
        answers: ResolvedAddresses,
        revision: OutboundPolicyRevision,
    ) -> Result<Self, EgressError> {
        if target.host() != answers.host() {
            return Err(EgressError::ResolutionTargetMismatch);
        }
        Ok(Self {
            target,
            addresses: answers.addresses,
            revision,
            epoch: answers.epoch,
            resolved_at: answers.resolved_at,
        })
    }
    /// Returns the target.
    #[must_use]
    pub const fn target(&self) -> &OutboundTarget {
        &self.target
    }
    /// Returns the complete answer set.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
    /// Returns the policy revision captured during resolution.
    #[must_use]
    pub const fn revision(&self) -> OutboundPolicyRevision {
        self.revision
    }
    /// Returns the resolver epoch captured by this record.
    #[must_use]
    pub const fn epoch(&self) -> ResolutionEpoch {
        self.epoch
    }
    /// Returns the monotonic completion instant.
    #[must_use]
    pub const fn resolved_at(&self) -> Instant {
        self.resolved_at
    }
}

fn validate_record_addresses(addresses: &[IpAddr]) -> Result<(), EgressError> {
    validate_answer_count(addresses)?;
    validate_answer_duplicates(addresses)?;
    validate_answer_ranges(addresses)
}

fn validate_answer_count(addresses: &[IpAddr]) -> Result<(), EgressError> {
    if addresses.is_empty() {
        return Err(EgressError::ResolutionEmpty);
    }
    if addresses.len() > MAX_OUTBOUND_RESOLVED_ADDRESSES {
        return Err(EgressError::TooManyAddresses);
    }
    Ok(())
}

fn validate_answer_duplicates(addresses: &[IpAddr]) -> Result<(), EgressError> {
    let unique = addresses.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != addresses.len() {
        return Err(EgressError::DuplicateAddress);
    }
    Ok(())
}

fn validate_answer_ranges(addresses: &[IpAddr]) -> Result<(), EgressError> {
    if addresses
        .iter()
        .any(|address| classify_address(*address).is_forbidden())
    {
        return Err(EgressError::ForbiddenAddress);
    }
    Ok(())
}

// crates/optional/ariadnion-provider-http/src/dns.rs - Bounded provider DNS contracts for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
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
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use ariadnion_core::{
    MAX_OUTBOUND_RESOLVED_ADDRESSES, OutboundHost, OutboundPolicyRevision, OutboundTarget,
};

use crate::egress::EgressError;

/// A bounded resolver implementation supplied by the runtime adapter.
pub trait BoundedResolver: Send + Sync {
    /// Resolves a canonical host into a complete, bounded answer set.
    fn resolve(&self, host: &OutboundHost) -> Result<Vec<IpAddr>, EgressError>;
}

/// Returns a stable, duplicate-free host sequence, rejecting empty or oversized input.
pub fn resolve_bounded<I, S>(hosts: I, limit: usize) -> Result<Vec<String>, EgressError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    if limit == 0 || limit > MAX_OUTBOUND_RESOLVED_ADDRESSES {
        return Err(EgressError::TooManyAddresses);
    }
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for item in hosts {
        let value = item.as_ref();
        if value.is_empty() || !seen.insert(value.to_owned()) {
            continue;
        }
        if output.len() == limit {
            return Err(EgressError::TooManyAddresses);
        }
        output.push(value.to_owned());
    }
    if output.is_empty() {
        return Err(EgressError::ResolutionEmpty);
    }
    Ok(output)
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

/// Classifies loopback, private, local, special-use, and metadata ranges.
#[must_use]
pub fn classify_address(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(value) => {
            if forbidden_v4(value) {
                AddressClass::Forbidden
            } else {
                AddressClass::Allowed
            }
        }
        IpAddr::V6(value) => {
            if value.is_loopback()
                || value.is_unspecified()
                || (value.segments()[0] & 0xfe00) == 0xfc00
                || (value.segments()[0] & 0xffc0) == 0xfe80
                || (value.segments()[0] & 0xff00) == 0xff00
                || is_ipv6_documentation(value)
                || value.to_ipv4_mapped().is_some_and(forbidden_v4)
            {
                AddressClass::Forbidden
            } else {
                AddressClass::Allowed
            }
        }
    }
}

fn is_ipv6_documentation(value: std::net::Ipv6Addr) -> bool {
    let segments = value.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
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
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

fn metadata_or_reserved(o: [u8; 4]) -> bool {
    (o[0] == 169 && o[1] == 254)
        || o[0] == 0
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (18..=19).contains(&o[1]))
}

/// A validated complete resolution with policy revision and monotonic timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionRecord {
    target: OutboundTarget,
    addresses: Vec<IpAddr>,
    revision: OutboundPolicyRevision,
    resolved_at: Instant,
}

impl ResolutionRecord {
    /// Creates a record, rejecting empty, duplicate, oversized, or forbidden answers.
    pub fn new(
        target: OutboundTarget,
        addresses: Vec<IpAddr>,
        revision: OutboundPolicyRevision,
        resolved_at: Instant,
    ) -> Result<Self, EgressError> {
        if addresses.is_empty() || addresses.len() > MAX_OUTBOUND_RESOLVED_ADDRESSES {
            return Err(EgressError::ResolutionEmpty);
        }
        let mut unique = BTreeSet::new();
        if addresses
            .iter()
            .any(|address| classify_address(*address).is_forbidden() || !unique.insert(*address))
        {
            return Err(EgressError::ForbiddenAddress);
        }
        Ok(Self {
            target,
            addresses,
            revision,
            resolved_at,
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
    /// Returns the monotonic completion instant.
    #[must_use]
    pub const fn resolved_at(&self) -> Instant {
        self.resolved_at
    }
}

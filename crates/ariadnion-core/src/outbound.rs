// crates/ariadnion-core/src/outbound.rs - Runtime-neutral outbound policy contracts for Ariadnion.
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
//! Runtime-neutral target and outbound authorization contracts.

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;

use crate::{CoreError, ErrorCode};

/// Maximum encoded length of one canonical outbound DNS host.
pub const MAX_OUTBOUND_HOST_BYTES: usize = 253;
/// Maximum number of addresses in one outbound authorization decision.
pub const MAX_OUTBOUND_RESOLVED_ADDRESSES: usize = 32;

/// A canonical ASCII DNS host that is not an IP literal.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutboundHost(Box<str>);

impl OutboundHost {
    /// Parses a canonical lowercase DNS host.
    ///
    /// Hosts must be between 1 and 253 ASCII bytes. Every label must be between
    /// 1 and 63 bytes, start and end with an ASCII letter or digit, and contain
    /// only lowercase ASCII letters, digits, or hyphens. IP literals and a
    /// trailing root dot are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidArgument`] for noncanonical syntax and
    /// [`ErrorCode::ResourceExhausted`] when the byte limit is exceeded.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        validate_host(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the canonical DNS host.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A canonical outbound DNS host and nonzero network port.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutboundTarget {
    host: OutboundHost,
    port: u16,
}

impl OutboundTarget {
    /// Creates one outbound target.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidArgument`] when `port` is zero.
    pub fn new(host: OutboundHost, port: u16) -> Result<Self, CoreError> {
        if port == 0 {
            return Err(invalid_argument("outbound target port is zero"));
        }
        Ok(Self { host, port })
    }

    /// Returns the canonical DNS host.
    #[must_use]
    pub const fn host(&self) -> &OutboundHost {
        &self.host
    }

    /// Returns the nonzero network port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// A nonzero monotonic version of one immutable outbound-policy snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutboundPolicyRevision(u64);

impl OutboundPolicyRevision {
    /// Creates a nonzero policy revision.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidArgument`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, CoreError> {
        if value == 0 {
            return Err(invalid_argument("outbound policy revision is zero"));
        }
        Ok(Self(value))
    }

    /// Returns the revision value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A borrowed complete DNS answer set submitted for one policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundAuthorizationRequest<'a> {
    target: &'a OutboundTarget,
    addresses: &'a [IpAddr],
    revision: OutboundPolicyRevision,
}

impl<'a> OutboundAuthorizationRequest<'a> {
    /// Creates a bounded authorization request without copying addresses.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidArgument`] when the answer set is empty or
    /// contains duplicates and [`ErrorCode::ResourceExhausted`] above
    /// [`MAX_OUTBOUND_RESOLVED_ADDRESSES`].
    pub fn new(
        target: &'a OutboundTarget,
        addresses: &'a [IpAddr],
        revision: OutboundPolicyRevision,
    ) -> Result<Self, CoreError> {
        validate_addresses(addresses)?;
        Ok(Self {
            target,
            addresses,
            revision,
        })
    }

    /// Returns the requested target.
    #[must_use]
    pub const fn target(&self) -> &OutboundTarget {
        self.target
    }

    /// Returns the complete validated address set.
    #[must_use]
    pub const fn addresses(&self) -> &[IpAddr] {
        self.addresses
    }

    /// Returns the policy revision required by the caller.
    #[must_use]
    pub const fn revision(&self) -> OutboundPolicyRevision {
        self.revision
    }
}

/// Stable fail-closed reasons returned by an outbound-policy snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum OutboundDenyReason {
    /// The canonical host or port is not authorized.
    TargetDenied,
    /// At least one resolved address is not authorized.
    AddressDenied,
    /// The policy capability is not available.
    PolicyUnavailable,
    /// The caller and policy revisions do not match.
    PolicyChanged,
}

impl OutboundDenyReason {
    /// Returns the stable machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetDenied => "outbound_target_denied",
            Self::AddressDenied => "outbound_address_denied",
            Self::PolicyUnavailable => "outbound_policy_unavailable",
            Self::PolicyChanged => "outbound_policy_changed",
        }
    }
}

/// A stable outbound authorization decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OutboundPolicyDecision {
    /// The exact target and complete address set are authorized.
    Allow,
    /// Work must stop before a socket is opened.
    Deny(OutboundDenyReason),
}

impl OutboundPolicyDecision {
    /// Returns the stable machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "outbound_allowed",
            Self::Deny(reason) => reason.as_str(),
        }
    }
}

impl Display for OutboundPolicyDecision {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An object-safe immutable outbound-policy snapshot.
///
/// Implementations must return the same decision for the same revision, target,
/// and complete address set. They must fail closed when required policy state is
/// unavailable and must not perform network or persistent-storage I/O inside
/// [`Self::authorize`].
pub trait OutboundPolicyPort: Send + Sync {
    /// Returns the immutable snapshot revision.
    fn revision(&self) -> OutboundPolicyRevision;

    /// Authorizes one complete resolution before any socket is opened.
    fn authorize(&self, request: &OutboundAuthorizationRequest<'_>) -> OutboundPolicyDecision;
}

fn validate_host(value: &str) -> Result<(), CoreError> {
    validate_host_encoding(value)?;
    validate_host_length(value)?;
    validate_host_name(value)?;
    validate_host_labels(value)
}

fn validate_host_encoding(value: &str) -> Result<(), CoreError> {
    if value.is_empty() || !value.is_ascii() {
        return Err(invalid_argument("outbound host is not canonical ASCII"));
    }
    Ok(())
}

fn validate_host_length(value: &str) -> Result<(), CoreError> {
    if value.len() > MAX_OUTBOUND_HOST_BYTES {
        return Err(resource_exhausted("outbound host exceeds its byte limit"));
    }
    Ok(())
}

fn validate_host_name(value: &str) -> Result<(), CoreError> {
    if value.parse::<IpAddr>().is_ok() {
        return Err(invalid_argument("outbound host is an IP literal"));
    }
    Ok(())
}

fn validate_host_labels(value: &str) -> Result<(), CoreError> {
    for label in value.split('.') {
        validate_label(label)?;
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), CoreError> {
    validate_label_size(label)?;
    validate_label_edges(label)?;
    validate_label_bytes(label)
}

fn validate_label_size(label: &str) -> Result<(), CoreError> {
    if label.is_empty() || label.len() > 63 {
        return Err(invalid_argument(
            "outbound host contains an invalid label size",
        ));
    }
    Ok(())
}

fn validate_label_edges(label: &str) -> Result<(), CoreError> {
    let first = label.as_bytes().first().copied();
    let last = label.as_bytes().last().copied();
    if !first.is_some_and(is_label_edge) || !last.is_some_and(is_label_edge) {
        return Err(invalid_argument("outbound host label edge is invalid"));
    }
    Ok(())
}

fn validate_label_bytes(label: &str) -> Result<(), CoreError> {
    if label.bytes().any(is_invalid_label_byte) {
        return Err(invalid_argument("outbound host label byte is invalid"));
    }
    Ok(())
}

const fn is_label_edge(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

const fn is_invalid_label_byte(byte: u8) -> bool {
    !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-'
}

fn validate_addresses(addresses: &[IpAddr]) -> Result<(), CoreError> {
    if addresses.is_empty() {
        return Err(invalid_argument("outbound address set is empty"));
    }
    if addresses.len() > MAX_OUTBOUND_RESOLVED_ADDRESSES {
        return Err(resource_exhausted("outbound address set exceeds its limit"));
    }
    let unique = addresses.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != addresses.len() {
        return Err(invalid_argument(
            "outbound address set contains a duplicate",
        ));
    }
    Ok(())
}

fn invalid_argument(context: &'static str) -> CoreError {
    CoreError::from_code(ErrorCode::InvalidArgument).with_internal_context(context)
}

fn resource_exhausted(context: &'static str) -> CoreError {
    CoreError::from_code(ErrorCode::ResourceExhausted).with_internal_context(context)
}

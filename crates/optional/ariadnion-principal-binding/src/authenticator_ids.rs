// crates/optional/ariadnion-principal-binding/src/authenticator_ids.rs - Rust source for Ariadnion.
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
//! Bounded identifiers, commitments, and versions for authenticator links.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;

use ariadnion_core::TenantId;
use sha2::{Digest, Sha256};

use crate::authenticator_error::{
    PrincipalAuthenticatorError, PrincipalAuthenticatorErrorCode, authenticator_error,
};

const MAX_SOURCE_ID_BYTES: usize = 128;
const AUTHENTICATOR_ID_HEX_BYTES: usize = 64;
const AUTHENTICATOR_ID_DOMAIN: &[u8] = b"ariadnion.principal-authenticator-id.v1";
const SOURCE_COMMITMENT_DOMAIN: &[u8] = b"ariadnion.principal-authenticator-source.v1";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// The exhaustive durable class of an authenticator source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PrincipalAuthenticatorKind {
    /// One durable session-family source.
    SessionFamily,
    /// One durable API-key source.
    ApiKey,
    /// One controlled system authenticator source.
    System,
}

impl PrincipalAuthenticatorKind {
    /// Returns the canonical storage string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionFamily => "session_family",
            Self::ApiKey => "api_key",
            Self::System => "system",
        }
    }

    /// Parses only the canonical storage strings.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::InvalidKind`] for every other value.
    pub fn parse(value: &str) -> Result<Self, PrincipalAuthenticatorError> {
        match value {
            "session_family" => Ok(Self::SessionFamily),
            "api_key" => Ok(Self::ApiKey),
            "system" => Ok(Self::System),
            _ => Err(authenticator_error(
                PrincipalAuthenticatorErrorCode::InvalidKind,
            )),
        }
    }
}

/// A bounded opaque source identifier owned by one authenticator implementation.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrincipalAuthenticatorSourceId(Box<str>);

impl PrincipalAuthenticatorSourceId {
    /// Parses one 1-to-128-byte ASCII identifier using `[A-Za-z0-9._-]`.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::InvalidSourceId`] for an empty,
    /// oversized, non-ASCII, or out-of-alphabet value.
    pub fn parse(value: &str) -> Result<Self, PrincipalAuthenticatorError> {
        if source_id_is_valid(value) {
            return Ok(Self(value.into()));
        }
        Err(authenticator_error(
            PrincipalAuthenticatorErrorCode::InvalidSourceId,
        ))
    }

    /// Returns the validated source value for exact persistence and comparison.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for PrincipalAuthenticatorSourceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorSourceId(<redacted>)")
    }
}

fn source_id_is_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SOURCE_ID_BYTES && value.bytes().all(is_source_id_byte)
}

const fn is_source_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

/// A deterministic tenant-bound identifier for one immutable authenticator source.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrincipalAuthenticatorId(Box<str>);

impl PrincipalAuthenticatorId {
    /// Derives 64 lowercase hexadecimal SHA-256 characters from exact source facts.
    ///
    /// The fixed domain tag and big-endian `u64` length framing bind tenant, kind,
    /// and source without caller-provided entropy or ambiguous concatenation.
    #[must_use]
    pub fn derive(
        tenant_id: &TenantId,
        kind: PrincipalAuthenticatorKind,
        source_id: &PrincipalAuthenticatorSourceId,
    ) -> Self {
        let digest = source_digest(AUTHENTICATOR_ID_DOMAIN, tenant_id, kind, source_id);
        Self(lower_hex(&digest).into_boxed_str())
    }

    /// Parses one exact durable lowercase hexadecimal identifier.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::InvalidAuthenticatorId`] unless
    /// the value is exactly 64 lowercase hexadecimal ASCII bytes.
    pub fn parse(value: &str) -> Result<Self, PrincipalAuthenticatorError> {
        if authenticator_id_is_valid(value) {
            return Ok(Self(value.into()));
        }
        Err(authenticator_error(
            PrincipalAuthenticatorErrorCode::InvalidAuthenticatorId,
        ))
    }

    /// Returns the canonical lowercase hexadecimal representation.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for PrincipalAuthenticatorId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorId(<redacted>)")
    }
}

fn authenticator_id_is_valid(value: &str) -> bool {
    value.len() == AUTHENTICATOR_ID_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A fixed domain-separated commitment to an authenticator source tuple.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PrincipalAuthenticatorSourceCommitment([u8; 32]);

impl PrincipalAuthenticatorSourceCommitment {
    /// Derives the commitment from length-delimited tenant, kind, and source facts.
    #[must_use]
    pub fn derive(
        tenant_id: &TenantId,
        kind: PrincipalAuthenticatorKind,
        source_id: &PrincipalAuthenticatorSourceId,
    ) -> Self {
        Self(source_digest(
            SOURCE_COMMITMENT_DOMAIN,
            tenant_id,
            kind,
            source_id,
        ))
    }

    /// Restores a fixed commitment from trusted-width durable bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns fixed-width bytes for durable hexadecimal encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Debug for PrincipalAuthenticatorSourceCommitment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorSourceCommitment(<redacted>)")
    }
}

/// A non-zero optimistic version for one authenticator-link aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrincipalAuthenticatorVersion(NonZeroU64);

impl PrincipalAuthenticatorVersion {
    /// Returns the only version assigned when a source is first linked.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic version.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::InvalidVersion`] for zero.
    pub fn new(value: u64) -> Result<Self, PrincipalAuthenticatorError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| authenticator_error(PrincipalAuthenticatorErrorCode::InvalidVersion))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic version.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, PrincipalAuthenticatorError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| authenticator_error(PrincipalAuthenticatorErrorCode::VersionExhausted))
    }
}

fn source_digest(
    domain: &[u8],
    tenant_id: &TenantId,
    kind: PrincipalAuthenticatorKind,
    source_id: &PrincipalAuthenticatorSourceId,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    append_digest_field(&mut digest, domain);
    append_digest_field(&mut digest, tenant_id.as_str().as_bytes());
    append_digest_field(&mut digest, kind.as_str().as_bytes());
    append_digest_field(&mut digest, source_id.as_str().as_bytes());
    digest.finalize().into()
}

fn append_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn lower_hex(bytes: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(AUTHENTICATOR_ID_HEX_BYTES);
    for byte in bytes {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

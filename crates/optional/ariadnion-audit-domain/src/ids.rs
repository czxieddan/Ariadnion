// crates/optional/ariadnion-audit-domain/src/ids.rs - Rust source for Ariadnion.
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
//
//! Bounded audit identities and sequences.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;

use crate::error::error;
use crate::{AuditError, AuditErrorCode};

const MAX_IDENTIFIER_BYTES: usize = 128;

/// A bounded path-free audit-event identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditEventId(Box<str>);

impl AuditEventId {
    /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::InvalidArgument`] without retaining rejected input.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        if !valid_identifier(value) {
            return Err(error(AuditErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AuditEventId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditEventId(<opaque>)")
    }
}

/// A non-zero append-only audit sequence number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditSequence(NonZeroU64);

impl AuditSequence {
    /// Returns the first sequence number.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, AuditError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(AuditErrorCode::InvalidArgument))
    }

    /// Returns the numeric sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::SequenceExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, AuditError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AuditErrorCode::SequenceExhausted))
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

// crates/optional/ariadnion-audit-domain/src/error.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Stable redacted failures for audit-domain operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by audit-domain operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AuditErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The sequence cannot be incremented.
    SequenceExhausted,
    /// A persisted chain digest did not match canonical event material.
    DigestMismatch,
    /// A persisted event used an unsupported chain digest schema version.
    UnsupportedVersion,
}

impl AuditErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "AUDIT_INVALID_ARGUMENT",
            Self::SequenceExhausted => "AUDIT_SEQUENCE_EXHAUSTED",
            Self::DigestMismatch => "AUDIT_DIGEST_MISMATCH",
            Self::UnsupportedVersion => "AUDIT_UNSUPPORTED_VERSION",
        }
    }
}

/// A redacted audit-domain error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditError {
    code: AuditErrorCode,
}

impl AuditError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: AuditErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AuditErrorCode {
        self.code
    }
}

impl Display for AuditError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AuditError {}

/// Builds a redacted error without retaining rejected values.
#[must_use]
pub(crate) const fn error(code: AuditErrorCode) -> AuditError {
    AuditError::new(code)
}

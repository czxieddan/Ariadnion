// crates/optional/ariadnion-audit-store/src/error.rs - Rust source for Ariadnion.
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
//! Stable redacted failures for audit-store operations.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by audit-store operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum AuditStoreErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument = 0,
    /// The append crossed a different tenant boundary.
    TenantMismatch = 1,
    /// The append sequence was not the exact next sequence.
    SequenceGap = 2,
    /// The previous chain digest did not match the log tip.
    ChainBreak = 3,
    /// The event identity was already present.
    DuplicateEvent = 4,
    /// The requested export range was empty or inverted.
    EmptyRange = 5,
    /// The stored event digest did not match canonical event material.
    DigestMismatch = 6,
    /// The in-memory verification boundary was exceeded.
    ResourceLimitExceeded = 7,
    /// A persisted chain component used an unsupported digest schema version.
    UnsupportedVersion = 8,
    /// The requested export range was only partially available.
    IncompleteRange = 9,
}

const AUDIT_STORE_ERROR_CODES: [&str; 10] = [
    "AUDIT_STORE_INVALID_ARGUMENT",
    "AUDIT_STORE_TENANT_MISMATCH",
    "AUDIT_STORE_SEQUENCE_GAP",
    "AUDIT_STORE_CHAIN_BREAK",
    "AUDIT_STORE_DUPLICATE_EVENT",
    "AUDIT_STORE_EMPTY_RANGE",
    "AUDIT_STORE_DIGEST_MISMATCH",
    "AUDIT_STORE_RESOURCE_LIMIT_EXCEEDED",
    "AUDIT_STORE_UNSUPPORTED_VERSION",
    "AUDIT_STORE_INCOMPLETE_RANGE",
];

impl AuditStoreErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        AUDIT_STORE_ERROR_CODES[self as usize]
    }
}

/// A redacted audit-store error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditStoreError {
    code: AuditStoreErrorCode,
}

impl AuditStoreError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: AuditStoreErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AuditStoreErrorCode {
        self.code
    }
}

impl Display for AuditStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AuditStoreError {}

/// Builds a redacted error without retaining rejected values.
#[must_use]
pub(crate) const fn error(code: AuditStoreErrorCode) -> AuditStoreError {
    AuditStoreError::new(code)
}

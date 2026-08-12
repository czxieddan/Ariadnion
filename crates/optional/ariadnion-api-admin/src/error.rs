// crates/optional/ariadnion-api-admin/src/error.rs - Rust source for Ariadnion.
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
//! Stable redacted failures for administration commands.

use std::fmt::{self, Debug, Display, Formatter};

/// Stable machine-readable failures returned by administration commands.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AdminErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The authoritative policy denied the command or trusted target state was
    /// incompatible with the requested action.
    AuthorizationDenied,
    /// The command crossed a different tenant boundary.
    TenantMismatch,
    /// The internally evaluated decision did not match its command binding.
    DecisionMismatch,
    /// The request has no authenticated principal.
    Unauthenticated,
    /// The request was cancelled before durable application.
    Cancelled,
    /// The request deadline expired before durable application.
    DeadlineExceeded,
    /// Mutable state or idempotent command material no longer matches.
    Conflict,
    /// A required authoritative adapter is unavailable.
    Unavailable,
    /// Durable commit may have completed and requires identity reconciliation.
    CommitIndeterminate,
    /// Trusted or durable facts failed closed integrity validation.
    IntegrityFailure,
}

impl AdminErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ADMIN_INVALID_ARGUMENT",
            Self::AuthorizationDenied => "ADMIN_AUTHORIZATION_DENIED",
            Self::TenantMismatch => "ADMIN_TENANT_MISMATCH",
            Self::DecisionMismatch => "ADMIN_DECISION_MISMATCH",
            Self::Unauthenticated => "ADMIN_UNAUTHENTICATED",
            Self::Cancelled
            | Self::DeadlineExceeded
            | Self::Conflict
            | Self::Unavailable
            | Self::CommitIndeterminate
            | Self::IntegrityFailure => self.execution_code(),
        }
    }

    const fn execution_code(self) -> &'static str {
        match self {
            Self::Cancelled => "ADMIN_CANCELLED",
            Self::DeadlineExceeded => "ADMIN_DEADLINE_EXCEEDED",
            Self::Conflict => "ADMIN_CONFLICT",
            Self::Unavailable => "ADMIN_UNAVAILABLE",
            Self::CommitIndeterminate => "ADMIN_COMMIT_INDETERMINATE",
            Self::IntegrityFailure => "ADMIN_INTEGRITY_FAILURE",
            Self::InvalidArgument
            | Self::AuthorizationDenied
            | Self::TenantMismatch
            | Self::DecisionMismatch
            | Self::Unauthenticated => self.as_str(),
        }
    }
}

/// A redacted administration error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminError {
    code: AdminErrorCode,
}

impl AdminError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: AdminErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AdminErrorCode {
        self.code
    }
}

impl Display for AdminError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AdminError {}

/// Builds a redacted error without retaining rejected values.
#[must_use]
pub(crate) const fn error(code: AdminErrorCode) -> AdminError {
    AdminError::new(code)
}

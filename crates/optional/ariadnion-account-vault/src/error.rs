// crates/optional/ariadnion-account-vault/src/error.rs - Vault errors for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Stable, redacted vault failures.

use std::fmt::{self, Debug, Display, Formatter};

use ariadnion_core::{CoreError, ErrorCode};

/// Stable machine-readable failures returned by a vault boundary.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum VaultErrorCode {
    /// A typed request or envelope is malformed.
    InvalidArgument,
    /// The request has no authenticated tenant context.
    Unauthenticated,
    /// The module or purpose is not authorized for the referenced secret.
    PermissionDenied,
    /// The referenced secret or lease does not exist.
    NotFound,
    /// The requested version conflicts with authoritative state.
    Conflict,
    /// A supplied value exceeds a documented bound.
    LimitExceeded,
    /// The lease or requested operation has expired.
    Expired,
    /// The request was cancelled before an external effect.
    Cancelled,
    /// The request deadline elapsed before an external effect.
    DeadlineExceeded,
    /// A bounded vault resource cannot accept more work.
    ResourceExhausted,
    /// The configured vault capability is unavailable.
    Unavailable,
    /// Ciphertext or key metadata failed integrity checks.
    IntegrityFailure,
    /// A durable write may have committed and needs idempotent reconciliation.
    CommitIndeterminate,
    /// The adapter failed without a safe external explanation.
    Internal,
}

impl VaultErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        const CODES: [&str; 14] = [
            "VAULT_INVALID_ARGUMENT",
            "VAULT_UNAUTHENTICATED",
            "VAULT_PERMISSION_DENIED",
            "VAULT_NOT_FOUND",
            "VAULT_CONFLICT",
            "VAULT_LIMIT_EXCEEDED",
            "VAULT_EXPIRED",
            "VAULT_CANCELLED",
            "VAULT_DEADLINE_EXCEEDED",
            "VAULT_RESOURCE_EXHAUSTED",
            "VAULT_UNAVAILABLE",
            "VAULT_INTEGRITY_FAILURE",
            "VAULT_COMMIT_INDETERMINATE",
            "VAULT_INTERNAL",
        ];
        CODES[self as usize]
    }
}

/// A redacted vault error containing only a stable machine code.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct VaultError {
    code: VaultErrorCode,
}

impl VaultError {
    /// Creates an error without retaining input, paths, ciphertext, or keys.
    #[must_use]
    pub const fn new(code: VaultErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> VaultErrorCode {
        self.code
    }
}

impl Debug for VaultError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "VaultError({})", self.code.as_str())
    }
}

impl Display for VaultError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for VaultError {}

impl From<CoreError> for VaultError {
    fn from(value: CoreError) -> Self {
        let code = match value.code() {
            ErrorCode::InvalidArgument => VaultErrorCode::InvalidArgument,
            ErrorCode::Conflict => VaultErrorCode::Conflict,
            ErrorCode::Cancelled => VaultErrorCode::Cancelled,
            ErrorCode::DeadlineExceeded => VaultErrorCode::DeadlineExceeded,
            ErrorCode::Unavailable => VaultErrorCode::Unavailable,
            ErrorCode::ResourceExhausted => VaultErrorCode::ResourceExhausted,
            ErrorCode::Internal => VaultErrorCode::Internal,
        };
        Self::new(code)
    }
}

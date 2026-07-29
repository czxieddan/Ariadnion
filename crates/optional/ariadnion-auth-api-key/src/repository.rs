// crates/optional/ariadnion-auth-api-key/src/repository.rs - Rust source for Ariadnion.
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
//! Stable persistence port and durable receipt types for scoped API keys.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::{ApiKey, ApiKeyId, ApiKeyPrefix, ApiKeyTransition, ApiKeyVersion};

const REPOSITORY_ERROR_CODES: [&str; 8] = [
    "API_KEY_REPOSITORY_NOT_FOUND",
    "API_KEY_REPOSITORY_CONFLICT",
    "API_KEY_REPOSITORY_CANCELLED",
    "API_KEY_REPOSITORY_DEADLINE_EXCEEDED",
    "API_KEY_REPOSITORY_RESOURCE_EXHAUSTED",
    "API_KEY_REPOSITORY_UNAVAILABLE",
    "API_KEY_REPOSITORY_COMMIT_INDETERMINATE",
    "API_KEY_REPOSITORY_INTEGRITY_FAILURE",
];

/// Persistence operations required by tenant-bound API-key workflows.
///
/// # Security invariants
///
/// `load`, `compare_and_commit`, and `reconcile_commit` reject anonymous
/// request contexts and authenticated tenant mismatches before storage access.
/// `load_by_prefix` is the sole pre-authentication exception and accepts a
/// tenant only from trusted site routing. Repository errors retain no key
/// identity, prefix, secret digest, scope set, event, or request context.
///
/// Loads authenticate the complete key snapshot, normalized scopes, retained
/// digest history, and contiguous lifecycle events. Writes bind the explicit
/// tenant and user to the aggregate, event, and every companion row before
/// performing I/O. A matching request with a changed durable version or atomic
/// precondition returns a conflict without partial effects.
pub trait ApiKeyRepositoryPort: Send + Sync {
    /// Loads one exact API key inside its tenant and user boundary.
    ///
    /// Crossed tenant or user keys and absent identities return the same
    /// redacted [`ApiKeyRepositoryErrorCode::NotFound`] result. Malformed
    /// ownership, scope, digest-history, or event bindings fail closed.
    fn load(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        api_key_id: &ApiKeyId,
        context: &RequestContext,
    ) -> Result<ApiKey, ApiKeyRepositoryError>;

    /// Loads one API key from its tenant-bound recognizable prefix.
    ///
    /// The prefix is lookup metadata and never contains secret material.
    /// Absent and crossed-boundary prefixes are indistinguishable not-found
    /// results; duplicate ownership or malformed rows are integrity failures.
    ///
    /// This is the sole method that may accept an anonymous `RequestContext`
    /// because it recovers the candidate owner before constant-time secret
    /// verification. The explicit tenant comes from trusted site routing,
    /// never from the presented key. An authenticated context for another
    /// tenant fails closed before the lookup.
    fn load_by_prefix(
        &self,
        tenant_id: &TenantId,
        prefix: &ApiKeyPrefix,
        context: &RequestContext,
    ) -> Result<ApiKey, ApiKeyRepositoryError>;

    /// Atomically compares the previous version and persists one transition.
    ///
    /// The aggregate, normalized scopes, complete retired-digest history,
    /// exact event, audit-chain append, and outbox message commit together or
    /// not at all. Issuance requires tenant-wide key and prefix absence.
    /// Rotation compares the live current and previous digest state; overlap
    /// completion, revocation, and expiry replace the full companion state in
    /// the same transaction. A version or binding race returns
    /// [`ApiKeyRepositoryErrorCode::Conflict`] with zero writes.
    ///
    /// An untrusted commit outcome returns
    /// [`ApiKeyRepositoryErrorCode::CommitIndeterminate`] and requires
    /// read-only reconciliation through a freshly opened repository.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_version: ApiKeyVersion,
        transition: &ApiKeyTransition,
        context: &RequestContext,
    ) -> Result<ApiKeyCommitReceipt, ApiKeyRepositoryError>;

    /// Reconciles an indeterminate commit from exact durable evidence.
    ///
    /// Implementations only read and authenticate the target snapshot,
    /// companion rows, event history, audit-chain membership, and outbox
    /// record. Reconciliation never writes, replays, or synthesizes a
    /// transition. A later state is accepted only when contiguous authenticated
    /// evidence proves the requested transition committed first.
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_version: ApiKeyVersion,
        transition: &ApiKeyTransition,
        context: &RequestContext,
    ) -> Result<ApiKeyCommitReceipt, ApiKeyRepositoryError>;
}

/// Stable machine-readable failures returned by an API-key repository.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum ApiKeyRepositoryErrorCode {
    /// The exact tenant-bound API-key record does not exist.
    NotFound,
    /// The expected version or another atomic precondition changed.
    Conflict,
    /// Cancellation was observed before a commit was attempted.
    Cancelled,
    /// The request deadline elapsed before a commit was attempted.
    DeadlineExceeded,
    /// A deterministic repository resource bound prevented the operation.
    ResourceExhausted,
    /// The repository cannot complete an otherwise valid operation.
    Unavailable,
    /// The commit boundary returned without a trustworthy durable outcome.
    CommitIndeterminate,
    /// Stored state, evidence, or an atomic result is inconsistent.
    IntegrityFailure,
}

impl ApiKeyRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        REPOSITORY_ERROR_CODES[self as usize]
    }
}

/// A redacted repository failure that never retains API-key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyRepositoryError {
    code: ApiKeyRepositoryErrorCode,
}

impl ApiKeyRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: ApiKeyRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> ApiKeyRepositoryErrorCode {
        self.code
    }
}

impl Display for ApiKeyRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ApiKeyRepositoryError {}

/// Bounded durable commit evidence returned by a trusted API-key repository.
///
/// The receipt contains only authenticated identities, version, and trusted
/// time. It never contains a prefix, scope, plaintext secret, or secret digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyCommitReceipt {
    tenant_id: TenantId,
    user_id: UserId,
    api_key_id: ApiKeyId,
    new_version: ApiKeyVersion,
    committed_at: UtcTimestamp,
}

impl ApiKeyCommitReceipt {
    /// Records trusted UTC evidence after an atomic durable commit succeeds.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        user_id: UserId,
        api_key_id: ApiKeyId,
        new_version: ApiKeyVersion,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            api_key_id,
            new_version,
            committed_at,
        }
    }

    /// Returns the authenticated tenant committed by the repository.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the API-key owner committed by the repository.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the committed API-key identity.
    #[must_use]
    pub const fn api_key_id(&self) -> &ApiKeyId {
        &self.api_key_id
    }

    /// Returns the newly committed optimistic version.
    #[must_use]
    pub const fn new_version(&self) -> ApiKeyVersion {
        self.new_version
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

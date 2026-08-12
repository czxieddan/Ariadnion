// crates/optional/ariadnion-principal-binding/src/authenticator_repository.rs - Rust source for Ariadnion.
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
//! Exact durable persistence and reconciliation contracts for authenticator links.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_user_domain::UtcTimestamp;

use crate::{
    PrincipalAuthenticatorEventKind, PrincipalAuthenticatorId, PrincipalAuthenticatorLink,
    PrincipalAuthenticatorTransition, PrincipalAuthenticatorVersion,
};

const REPOSITORY_ERROR_CODES: [&str; 8] = [
    "PRINCIPAL_AUTHENTICATOR_REPOSITORY_NOT_FOUND",
    "PRINCIPAL_AUTHENTICATOR_REPOSITORY_CONFLICT",
    "PRINCIPAL_AUTHENTICATOR_REPOSITORY_CANCELLED",
    "PRINCIPAL_AUTHENTICATOR_REPOSITORY_DEADLINE_EXCEEDED",
    "PRINCIPAL_AUTHENTICATOR_REPOSITORY_RESOURCE_EXHAUSTED",
    "PRINCIPAL_AUTHENTICATOR_REPOSITORY_UNAVAILABLE",
    "PRINCIPAL_AUTHENTICATOR_REPOSITORY_COMMIT_INDETERMINATE",
    "PRINCIPAL_AUTHENTICATOR_REPOSITORY_INTEGRITY_FAILURE",
];

/// Persistence operations required by tenant-bound authenticator-link workflows.
///
/// # Security invariants
///
/// Before I/O, each method verifies that the authenticated [`RequestContext`]
/// tenant equals `tenant_id`. Writes and reconciliation also verify the context
/// principal against the immutable event actor. Tenant and authenticator arguments
/// must equal the target snapshot, optional previous snapshot, and event. The
/// expected version must equal every transition precondition. New links require
/// exact `(tenant_id, authenticator_id)` absence and immutable
/// `(tenant_id, kind, source_id)` absence; terminal tombstones remain occupied.
///
/// Decoded IDs must equal deterministic tenant/kind/source derivation. Snapshot
/// state, versions, timestamps, event kind, source commitment, principal, and
/// principal-binding version are checked before returning. Any caller or durable
/// divergence is `IntegrityFailure`; only a changed validated compare condition
/// is `Conflict`.
///
/// # Atomic commit
///
/// The target snapshot compare-and-swap, immutable event, audit append, and outbox
/// enqueue commit in one transaction or have no effect. Success is returned only
/// after durable commit. An indeterminate result must be reconciled read-only from
/// a fresh session and must never be retried as a write.
pub trait PrincipalAuthenticatorRepositoryPort: Send + Sync {
    /// Loads one exact tenant/authenticator aggregate without alternate-key fallback.
    ///
    /// # Errors
    /// Returns `NotFound` only after exact context validation. Malformed, divergent,
    /// or discontinuous durable evidence returns `IntegrityFailure`.
    fn load(
        &self,
        tenant_id: &TenantId,
        authenticator_id: &PrincipalAuthenticatorId,
        context: &RequestContext,
    ) -> Result<PrincipalAuthenticatorLink, PrincipalAuthenticatorRepositoryError>;

    /// Atomically compares the prior state and commits one exact transition.
    ///
    /// `None` is valid only for first link and requires both durable source keys to
    /// be absent. Existing transitions require the exact previous snapshot and
    /// non-zero version. The adapter validates kind/state/lifecycle invariants on
    /// every insert and update before issuing I/O.
    ///
    /// # Errors
    /// Returns `Conflict` for a changed durable precondition, `CommitIndeterminate`
    /// for an uncertain commit boundary, and `IntegrityFailure` for any mismatch.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        authenticator_id: &PrincipalAuthenticatorId,
        expected_previous_version: Option<PrincipalAuthenticatorVersion>,
        transition: &PrincipalAuthenticatorTransition,
        context: &RequestContext,
    ) -> Result<PrincipalAuthenticatorCommitReceipt, PrincipalAuthenticatorRepositoryError>;

    /// Reconciles one indeterminate commit using exact read-only durable evidence.
    ///
    /// Implementations open a fresh session and never replay, repair, or insert.
    /// The target snapshot, target immutable event, audit append, and outbox record
    /// must all match. A later state is accepted only with a contiguous exact event
    /// path from the target; missing or partial evidence fails closed.
    ///
    /// # Errors
    /// Returns `IntegrityFailure` for missing, behind, duplicate, divergent,
    /// malformed, or partially committed evidence.
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        authenticator_id: &PrincipalAuthenticatorId,
        expected_previous_version: Option<PrincipalAuthenticatorVersion>,
        transition: &PrincipalAuthenticatorTransition,
        context: &RequestContext,
    ) -> Result<PrincipalAuthenticatorCommitReceipt, PrincipalAuthenticatorRepositoryError>;
}

/// Stable machine-readable failures returned by an authenticator-link repository.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum PrincipalAuthenticatorRepositoryErrorCode {
    /// The exact tenant-bound authenticator key does not exist.
    NotFound = 0,
    /// The expected version, absent-key precondition, or atomic condition changed.
    Conflict = 1,
    /// Cancellation was observed before a commit attempt.
    Cancelled = 2,
    /// The request deadline elapsed before a commit attempt.
    DeadlineExceeded = 3,
    /// A deterministic repository resource bound prevented the operation.
    ResourceExhausted = 4,
    /// The repository cannot complete an otherwise valid operation.
    Unavailable = 5,
    /// The commit boundary returned without a trustworthy durable outcome.
    CommitIndeterminate = 6,
    /// Stored state, history, or commit evidence is inconsistent.
    IntegrityFailure = 7,
}

impl PrincipalAuthenticatorRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        REPOSITORY_ERROR_CODES[self as usize]
    }
}

/// A redacted repository failure that never retains identifiers or records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalAuthenticatorRepositoryError {
    code: PrincipalAuthenticatorRepositoryErrorCode,
}

impl PrincipalAuthenticatorRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: PrincipalAuthenticatorRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> PrincipalAuthenticatorRepositoryErrorCode {
        self.code
    }
}

impl Display for PrincipalAuthenticatorRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for PrincipalAuthenticatorRepositoryError {}

/// Bounded durable commit evidence returned by a trusted repository adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalAuthenticatorCommitReceipt {
    tenant_id: TenantId,
    authenticator_id: PrincipalAuthenticatorId,
    new_version: PrincipalAuthenticatorVersion,
    kind: PrincipalAuthenticatorEventKind,
    committed_at: UtcTimestamp,
}

impl PrincipalAuthenticatorCommitReceipt {
    /// Derives trusted receipt facts from the exact committed transition.
    ///
    /// The adapter supplies only trusted durable commit time, so key, version,
    /// and event kind cannot diverge from the transition it committed.
    #[must_use]
    pub fn from_transition(
        transition: &PrincipalAuthenticatorTransition,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id: transition.tenant_id().clone(),
            authenticator_id: transition.authenticator_id().clone(),
            new_version: transition.link().version(),
            kind: transition.event().kind(),
            committed_at,
        }
    }

    /// Returns the committed tenant key.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the committed deterministic authenticator key.
    #[must_use]
    pub const fn authenticator_id(&self) -> &PrincipalAuthenticatorId {
        &self.authenticator_id
    }

    /// Returns the newly committed aggregate version.
    #[must_use]
    pub const fn new_version(&self) -> PrincipalAuthenticatorVersion {
        self.new_version
    }

    /// Returns the committed immutable event kind.
    #[must_use]
    pub const fn kind(&self) -> PrincipalAuthenticatorEventKind {
        self.kind
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

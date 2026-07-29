// crates/optional/ariadnion-auth-session/src/repository.rs - Rust source for Ariadnion.
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
//! Stable persistence port and durable receipt types for browser sessions.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::{
    SessionFamily, SessionFamilyId, SessionFamilyVersion, SessionId, SessionTokenDigest,
    SessionTransition,
};

const REPOSITORY_ERROR_CODES: [&str; 8] = [
    "SESSION_REPOSITORY_NOT_FOUND",
    "SESSION_REPOSITORY_CONFLICT",
    "SESSION_REPOSITORY_CANCELLED",
    "SESSION_REPOSITORY_DEADLINE_EXCEEDED",
    "SESSION_REPOSITORY_RESOURCE_EXHAUSTED",
    "SESSION_REPOSITORY_UNAVAILABLE",
    "SESSION_REPOSITORY_COMMIT_INDETERMINATE",
    "SESSION_REPOSITORY_INTEGRITY_FAILURE",
];

/// Persistence operations required by tenant-bound browser session workflows.
///
/// # Security invariants
///
/// `load`, `compare_and_commit`, and `reconcile_commit` must reject an
/// anonymous [`RequestContext`] or one whose authenticated principal tenant
/// differs from the explicit `tenant_id` with
/// [`SessionRepositoryErrorCode::IntegrityFailure`] before accessing storage.
/// `load_by_token_digest` is the sole pre-authentication exception described
/// on that method. Repository errors remain redacted and never retain
/// identities, token digests, snapshots, events, or request context.
///
/// Loads authenticate the complete family snapshot and contiguous event
/// history, including every rotated leaf required for token-reuse detection.
/// Before either write method performs I/O, the explicit tenant must equal the
/// transition family, every leaf, and event tenant. For authenticated family
/// loads and writes, the explicit user must also equal the family, every leaf,
/// and event user. Any mismatch is an integrity failure. A matching request
/// whose durable family version or another atomic precondition changed is a
/// conflict.
pub trait SessionRepositoryPort: Send + Sync {
    /// Loads one exact browser session family inside its tenant and user boundary.
    ///
    /// The explicit user is part of the storage key and must match every leaf
    /// in the decoded family. Absent and crossed-boundary keys return the same redacted
    /// [`SessionRepositoryErrorCode::NotFound`] result. Malformed subject
    /// bindings, missing leaves, or divergent history fail closed as integrity
    /// failures.
    fn load(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        family_id: &SessionFamilyId,
        context: &RequestContext,
    ) -> Result<SessionFamily, SessionRepositoryError>;

    /// Loads one family from a tenant-bound one-way leaf-token digest.
    ///
    /// The lookup never accepts or retains a plaintext cookie. It searches
    /// current and rotated leaf digests so a rotated-token presentation can be
    /// converted into a durable family-wide reuse revocation. Absent and
    /// crossed-boundary digests are indistinguishable not-found results;
    /// duplicate digest ownership or malformed rows are integrity failures.
    ///
    /// This is the sole method that may accept an anonymous `RequestContext`
    /// because it recovers the authenticated session subject from the opaque
    /// digest. The explicit tenant must come from trusted site routing, never
    /// token or cookie material. An already authenticated context whose tenant
    /// differs from that explicit tenant is an integrity failure. Implementors
    /// must still enforce request identity, cancellation, deadline, resource,
    /// and tenant-isolation checks before querying storage and must never
    /// fabricate a principal for this lookup.
    fn load_by_token_digest(
        &self,
        tenant_id: &TenantId,
        token_digest: SessionTokenDigest,
        context: &RequestContext,
    ) -> Result<SessionFamily, SessionRepositoryError>;

    /// Atomically compares the old family version and persists one transition.
    ///
    /// The family snapshot, complete leaf set and history, exact event,
    /// audit-chain append, and outbox message commit together or not at all.
    /// Issuance uses the initial expected version and requires the family ID,
    /// leaf ID, and tenant token digest to be absent before any insert. Rotation
    /// requires the durable current leaf and digest to match the transition's
    /// predecessor. Reuse detection, revocation, and expiry update every leaf
    /// in the same transaction. A changed version, identity, digest, or leaf
    /// set returns [`SessionRepositoryErrorCode::Conflict`] with zero writes.
    ///
    /// Success is returned only after durable commit. An untrusted commit
    /// boundary returns [`SessionRepositoryErrorCode::CommitIndeterminate`]
    /// and requires read-only reconciliation through a fresh repository
    /// session.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_version: SessionFamilyVersion,
        transition: &SessionTransition,
        context: &RequestContext,
    ) -> Result<SessionCommitReceipt, SessionRepositoryError>;

    /// Reconciles one indeterminate session commit from durable evidence.
    ///
    /// Implementations only read and authenticate the target family snapshot,
    /// exact leaf history, event, audit-chain membership, and outbox record.
    /// Reconciliation never writes, replays, or synthesizes a transition. A
    /// current family may be later only when contiguous authenticated evidence
    /// proves the requested transition committed first. Missing, behind,
    /// malformed, duplicate, or divergent evidence is an integrity failure.
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_version: SessionFamilyVersion,
        transition: &SessionTransition,
        context: &RequestContext,
    ) -> Result<SessionCommitReceipt, SessionRepositoryError>;
}

/// Stable machine-readable failures returned by a session repository.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum SessionRepositoryErrorCode {
    /// The exact tenant- and user-bound session record does not exist.
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
    /// Stored data, evidence, or an atomic result is inconsistent.
    IntegrityFailure,
}

impl SessionRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        REPOSITORY_ERROR_CODES[self as usize]
    }
}

/// A redacted repository failure that never retains session material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionRepositoryError {
    code: SessionRepositoryErrorCode,
}

impl SessionRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: SessionRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> SessionRepositoryErrorCode {
        self.code
    }
}

impl Display for SessionRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for SessionRepositoryError {}

/// Bounded durable commit evidence returned by a trusted session repository.
///
/// The receipt contains only authenticated identifiers, versions, and trusted
/// time. It never contains a plaintext cookie or token digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCommitReceipt {
    tenant_id: TenantId,
    user_id: UserId,
    family_id: SessionFamilyId,
    current_session_id: SessionId,
    new_version: SessionFamilyVersion,
    committed_at: UtcTimestamp,
}

impl SessionCommitReceipt {
    /// Records trusted UTC evidence after an atomic durable commit succeeds.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        user_id: UserId,
        family_id: SessionFamilyId,
        current_session_id: SessionId,
        new_version: SessionFamilyVersion,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            family_id,
            current_session_id,
            new_version,
            committed_at,
        }
    }

    /// Returns the authenticated tenant committed by the repository.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the session subject committed by the repository.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the committed session-family identity.
    #[must_use]
    pub const fn family_id(&self) -> &SessionFamilyId {
        &self.family_id
    }

    /// Returns the current leaf identity after the commit.
    #[must_use]
    pub const fn current_session_id(&self) -> &SessionId {
        &self.current_session_id
    }

    /// Returns the newly committed family version.
    #[must_use]
    pub const fn new_version(&self) -> SessionFamilyVersion {
        self.new_version
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

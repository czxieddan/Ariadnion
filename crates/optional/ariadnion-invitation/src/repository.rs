// crates/optional/ariadnion-invitation/src/repository.rs - Rust source for Ariadnion.
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
//! Stable persistence port and durable receipt types for invitations.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_organization::OrganizationId;
use ariadnion_user_domain::UtcTimestamp;

use crate::{
    Invitation, InvitationId, InvitationTokenDigest, InvitationTransition, InvitationVersion,
};

const REPOSITORY_ERROR_CODES: [&str; 8] = [
    "INVITATION_REPOSITORY_NOT_FOUND",
    "INVITATION_REPOSITORY_CONFLICT",
    "INVITATION_REPOSITORY_CANCELLED",
    "INVITATION_REPOSITORY_DEADLINE_EXCEEDED",
    "INVITATION_REPOSITORY_RESOURCE_EXHAUSTED",
    "INVITATION_REPOSITORY_UNAVAILABLE",
    "INVITATION_REPOSITORY_COMMIT_INDETERMINATE",
    "INVITATION_REPOSITORY_INTEGRITY_FAILURE",
];

/// Persistence operations required by tenant-bound invitation workflows.
///
/// # Security invariants
/// Every method must reject an anonymous [`RequestContext`] or one whose
/// authenticated principal tenant differs from the explicit `tenant_id` with
/// [`InvitationRepositoryErrorCode::IntegrityFailure`] before accessing
/// storage. Repository errors remain redacted and never retain supplied
/// identities, digests, records, or request context.
///
/// Before `compare_and_commit` or `reconcile_commit` performs any I/O, the
/// explicit tenant and organization must equal both the transition invitation
/// snapshot identities and event identities. The snapshot and event invitation
/// identities must also equal each other. Any mismatch returns
/// [`InvitationRepositoryErrorCode::IntegrityFailure`]. A matching request
/// whose durable version or other durable atomic precondition is stale returns
/// [`InvitationRepositoryErrorCode::Conflict`].
pub trait InvitationRepositoryPort: Send + Sync {
    /// Loads one exact invitation inside its tenant and organization boundary.
    ///
    /// Implementations return [`InvitationRepositoryErrorCode::NotFound`] for
    /// absent keys, cross-tenant keys, and cross-organization keys so callers
    /// cannot distinguish another boundary's records. Malformed snapshots or
    /// event history fail closed as integrity failures.
    fn load(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        invitation_id: &InvitationId,
        context: &RequestContext,
    ) -> Result<Invitation, InvitationRepositoryError>;

    /// Loads one invitation from its tenant-bound one-way token digest.
    ///
    /// This lookup supports consumption without accepting or retaining a
    /// plaintext token. Absent, cross-tenant, and cross-organization proofs are
    /// indistinguishable [`InvitationRepositoryErrorCode::NotFound`] results.
    fn load_by_token_digest(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        token_digest: InvitationTokenDigest,
        context: &RequestContext,
    ) -> Result<Invitation, InvitationRepositoryError>;

    /// Atomically compares the old version and persists one transition pair.
    ///
    /// The new invitation snapshot, exact invitation event, audit-chain
    /// append, and outbox message commit together or not at all. A changed
    /// version or another changed atomic precondition returns
    /// [`InvitationRepositoryErrorCode::Conflict`]. Issuance uses the initial
    /// expected version and requires the durable key and tenant token digest
    /// to be absent before inserting the version-one transition. Success is
    /// returned only after durable commit. An untrusted commit boundary returns
    /// [`InvitationRepositoryErrorCode::CommitIndeterminate`] and requires
    /// read-only reconciliation through a fresh repository session.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        expected_previous_version: InvitationVersion,
        transition: &InvitationTransition,
        context: &RequestContext,
    ) -> Result<InvitationCommitReceipt, InvitationRepositoryError>;

    /// Reconciles one indeterminate commit from exact durable evidence.
    ///
    /// Implementations only read and compare the target snapshot, event,
    /// audit-chain membership, and outbox record; reconciliation never writes
    /// or replays the transition. The current invitation may equal the target
    /// or be a later legal snapshot backed by contiguous durable events.
    /// Missing, behind, malformed, duplicate, or divergent evidence returns
    /// [`InvitationRepositoryErrorCode::IntegrityFailure`].
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        expected_previous_version: InvitationVersion,
        transition: &InvitationTransition,
        context: &RequestContext,
    ) -> Result<InvitationCommitReceipt, InvitationRepositoryError>;
}

/// Stable machine-readable failures returned by an invitation repository.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum InvitationRepositoryErrorCode {
    /// The exact tenant- and organization-bound invitation does not exist.
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

impl InvitationRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        REPOSITORY_ERROR_CODES[self as usize]
    }
}

/// A redacted repository failure that never retains records or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationRepositoryError {
    code: InvitationRepositoryErrorCode,
}

impl InvitationRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: InvitationRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> InvitationRepositoryErrorCode {
        self.code
    }
}

impl Display for InvitationRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for InvitationRepositoryError {}

/// Bounded durable commit evidence returned by a trusted repository adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationCommitReceipt {
    tenant_id: TenantId,
    organization_id: OrganizationId,
    invitation_id: InvitationId,
    new_version: InvitationVersion,
    committed_at: UtcTimestamp,
}

impl InvitationCommitReceipt {
    /// Records trusted UTC evidence after an atomic durable commit succeeds.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        organization_id: OrganizationId,
        invitation_id: InvitationId,
        new_version: InvitationVersion,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            organization_id,
            invitation_id,
            new_version,
            committed_at,
        }
    }

    /// Returns the authenticated tenant committed by the repository.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the committed organization identity.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the committed invitation identity.
    #[must_use]
    pub const fn invitation_id(&self) -> &InvitationId {
        &self.invitation_id
    }

    /// Returns the newly committed aggregate version.
    #[must_use]
    pub const fn new_version(&self) -> InvitationVersion {
        self.new_version
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

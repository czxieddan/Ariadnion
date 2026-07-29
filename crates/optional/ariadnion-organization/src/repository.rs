// crates/optional/ariadnion-organization/src/repository.rs - Rust source for Ariadnion.
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
//! Stable persistence port and durable receipt types for organizations.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_user_domain::UtcTimestamp;

use crate::{Organization, OrganizationId, OrganizationTransition, OrganizationVersion};

const REPOSITORY_ERROR_CODES: [&str; 8] = [
    "ORGANIZATION_REPOSITORY_NOT_FOUND",
    "ORGANIZATION_REPOSITORY_CONFLICT",
    "ORGANIZATION_REPOSITORY_CANCELLED",
    "ORGANIZATION_REPOSITORY_DEADLINE_EXCEEDED",
    "ORGANIZATION_REPOSITORY_RESOURCE_EXHAUSTED",
    "ORGANIZATION_REPOSITORY_UNAVAILABLE",
    "ORGANIZATION_REPOSITORY_COMMIT_INDETERMINATE",
    "ORGANIZATION_REPOSITORY_INTEGRITY_FAILURE",
];

/// Persistence operations required by tenant-bound organization workflows.
pub trait OrganizationRepositoryPort: Send + Sync {
    /// Loads the exact organization inside the authenticated tenant boundary.
    ///
    /// Implementations return [`OrganizationRepositoryErrorCode::NotFound`]
    /// for both absent and cross-tenant keys and fail closed on malformed
    /// snapshots or event history.
    fn load(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        context: &RequestContext,
    ) -> Result<Organization, OrganizationRepositoryError>;

    /// Atomically compares the old version and persists one transition pair.
    ///
    /// The new aggregate snapshot, exact organization event, audit-chain
    /// append, and outbox message commit together or not at all. A changed
    /// version returns [`OrganizationRepositoryErrorCode::Conflict`]. Creation
    /// is represented by an initial expected version paired with an initial
    /// aggregate and `Created` event; adapters must require the durable key to
    /// be absent and insert it atomically. Success returns only after durable
    /// commit. An untrusted commit boundary returns
    /// [`OrganizationRepositoryErrorCode::CommitIndeterminate`] and requires
    /// read-only reconciliation through a fresh repository session.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: OrganizationVersion,
        transition: &OrganizationTransition,
        context: &RequestContext,
    ) -> Result<OrganizationCommitReceipt, OrganizationRepositoryError>;

    /// Reconciles one indeterminate commit from exact durable evidence.
    ///
    /// Implementations compare the target event, audit-chain membership, and
    /// outbox record without replaying the transition. The current aggregate
    /// may equal the target or be a later legal snapshot backed by contiguous
    /// durable events. Missing, behind, malformed, duplicate, or divergent
    /// evidence returns [`OrganizationRepositoryErrorCode::IntegrityFailure`].
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: OrganizationVersion,
        transition: &OrganizationTransition,
        context: &RequestContext,
    ) -> Result<OrganizationCommitReceipt, OrganizationRepositoryError>;
}

/// Stable machine-readable failures returned by an organization repository.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum OrganizationRepositoryErrorCode {
    /// The exact tenant-bound organization does not exist.
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

impl OrganizationRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        REPOSITORY_ERROR_CODES[self as usize]
    }
}

/// A redacted repository failure that never retains records or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrganizationRepositoryError {
    code: OrganizationRepositoryErrorCode,
}

impl OrganizationRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: OrganizationRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> OrganizationRepositoryErrorCode {
        self.code
    }
}

impl Display for OrganizationRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for OrganizationRepositoryError {}

/// Bounded durable commit evidence returned by a trusted repository adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationCommitReceipt {
    tenant_id: TenantId,
    organization_id: OrganizationId,
    new_version: OrganizationVersion,
    committed_at: UtcTimestamp,
}

impl OrganizationCommitReceipt {
    /// Records trusted UTC evidence after an atomic durable commit succeeds.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        organization_id: OrganizationId,
        new_version: OrganizationVersion,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            organization_id,
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

    /// Returns the newly committed aggregate version.
    #[must_use]
    pub const fn new_version(&self) -> OrganizationVersion {
        self.new_version
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

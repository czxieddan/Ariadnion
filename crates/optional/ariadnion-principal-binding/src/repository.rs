// crates/optional/ariadnion-principal-binding/src/repository.rs - Rust source for Ariadnion.
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
//! Durable principal-binding persistence and reconciliation contracts.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{PrincipalId, RequestContext, TenantId};
use ariadnion_user_domain::UtcTimestamp;

use crate::{
    PrincipalBinding, PrincipalBindingEventKind, PrincipalBindingTransition,
    PrincipalBindingVersion,
};

const REPOSITORY_ERROR_CODES: [&str; 8] = [
    "PRINCIPAL_BINDING_REPOSITORY_NOT_FOUND",
    "PRINCIPAL_BINDING_REPOSITORY_CONFLICT",
    "PRINCIPAL_BINDING_REPOSITORY_CANCELLED",
    "PRINCIPAL_BINDING_REPOSITORY_DEADLINE_EXCEEDED",
    "PRINCIPAL_BINDING_REPOSITORY_RESOURCE_EXHAUSTED",
    "PRINCIPAL_BINDING_REPOSITORY_UNAVAILABLE",
    "PRINCIPAL_BINDING_REPOSITORY_COMMIT_INDETERMINATE",
    "PRINCIPAL_BINDING_REPOSITORY_INTEGRITY_FAILURE",
];

/// Persistence operations required by tenant-bound principal-binding workflows.
///
/// # Security invariants
///
/// Before I/O, every method requires an authenticated [`RequestContext`] whose
/// principal tenant equals the explicit `tenant_id`. Writes and reconciliation
/// additionally require the context principal to equal the transition event
/// actor. The explicit tenant and principal arguments must equal the transition,
/// new snapshot, optional previous snapshot, and event keys. The supplied
/// expected previous version must equal the transition value and the optional
/// previous snapshot version; provisioning requires all three to be `None`, and
/// existing transitions require all three to be the same non-zero version.
/// Event kind, event version, and target snapshot version must also describe the
/// same legal lifecycle step.
///
/// Unauthenticated, cross-context, argument, transition, snapshot, event, or expected
/// version mismatches return
/// [`PrincipalBindingRepositoryErrorCode::IntegrityFailure`] before I/O. A
/// decoded row whose ownership or commitment diverges is also an integrity
/// failure. [`PrincipalBindingRepositoryErrorCode::Conflict`] is reserved for a
/// durable absent-key or compare-and-swap race after all input validation.
///
/// # Atomic commit
///
/// The target snapshot compare-and-swap, immutable principal-binding event,
/// audit-chain append, and outbox enqueue commit in one transaction or have no
/// effect. Each record is bound to the explicit tenant, principal, event version,
/// actor, request ID, event kind, time, and sensitive subject commitment.
pub trait PrincipalBindingRepositoryPort: Send + Sync {
    /// Loads the exact tenant/principal aggregate without alternate-key lookup.
    ///
    /// After the pre-I/O context checks, an absent exact tenant/principal row
    /// returns [`PrincipalBindingRepositoryErrorCode::NotFound`]. Cross-tenant
    /// arguments fail before I/O. Decoded key divergence, malformed snapshots,
    /// commitment mismatches, or discontinuous lifecycle evidence returns
    /// [`PrincipalBindingRepositoryErrorCode::IntegrityFailure`].
    fn load(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        context: &RequestContext,
    ) -> Result<PrincipalBinding, PrincipalBindingRepositoryError>;

    /// Atomically compares the previous version and commits one transition.
    ///
    /// `None` is valid only for provisioning and atomically requires exact-key
    /// absence. Because erased keys are retained, this prevents principal reuse.
    /// Existing transitions compare both the exact previous snapshot and version.
    /// A changed durable precondition is `Conflict` with zero effects; caller or
    /// transition binding mismatches are pre-I/O integrity failures. The target
    /// snapshot, immutable event, audit append, and outbox record described by
    /// this trait commit atomically.
    ///
    /// Success is returned only after durable commit. An uncertain boundary
    /// returns [`PrincipalBindingRepositoryErrorCode::CommitIndeterminate`]; the
    /// caller must not retry the write and must reconcile through a fresh
    /// repository session before issuing another transition.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        expected_previous_version: Option<PrincipalBindingVersion>,
        transition: &PrincipalBindingTransition,
        context: &RequestContext,
    ) -> Result<PrincipalBindingCommitReceipt, PrincipalBindingRepositoryError>;

    /// Reconciles one indeterminate outcome from exact durable evidence.
    ///
    /// Implementations open a fresh session and perform only read operations.
    /// Reconciliation never replays the transition, writes missing evidence, or
    /// repairs a partial result. It exactly verifies the target snapshot and
    /// immutable event together with the corresponding audit-chain append and
    /// outbox identity and payload.
    ///
    /// The current aggregate may equal the target or be a later legal state only
    /// when contiguous immutable events lead from the exact target evidence to
    /// that later snapshot. A later state never substitutes its own event, audit,
    /// or outbox evidence for the indeterminate target. Missing, behind, duplicate,
    /// divergent, malformed, or partially committed evidence is `IntegrityFailure`.
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        expected_previous_version: Option<PrincipalBindingVersion>,
        transition: &PrincipalBindingTransition,
        context: &RequestContext,
    ) -> Result<PrincipalBindingCommitReceipt, PrincipalBindingRepositoryError>;
}

/// Stable machine-readable failures returned by a principal-binding repository.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum PrincipalBindingRepositoryErrorCode {
    /// The exact tenant-bound principal key does not exist.
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

impl PrincipalBindingRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        REPOSITORY_ERROR_CODES[self as usize]
    }
}

/// A redacted repository failure that never retains identifiers or records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalBindingRepositoryError {
    code: PrincipalBindingRepositoryErrorCode,
}

impl PrincipalBindingRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: PrincipalBindingRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> PrincipalBindingRepositoryErrorCode {
        self.code
    }
}

impl Display for PrincipalBindingRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for PrincipalBindingRepositoryError {}

/// Bounded durable commit evidence returned by a trusted repository adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalBindingCommitReceipt {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    new_version: PrincipalBindingVersion,
    kind: PrincipalBindingEventKind,
    committed_at: UtcTimestamp,
}

impl PrincipalBindingCommitReceipt {
    /// Derives trusted receipt facts from the exact committed transition.
    ///
    /// The adapter supplies only the trusted durable commit time, so receipt key,
    /// version, and event kind cannot diverge from the transition it committed.
    #[must_use]
    pub fn from_transition(
        transition: &PrincipalBindingTransition,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id: transition.tenant_id().clone(),
            principal_id: transition.principal_id().clone(),
            new_version: transition.binding().version(),
            kind: transition.event().kind(),
            committed_at,
        }
    }

    /// Returns the committed tenant key.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the committed principal key.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the newly committed aggregate version.
    #[must_use]
    pub const fn new_version(&self) -> PrincipalBindingVersion {
        self.new_version
    }

    /// Returns the committed event kind.
    #[must_use]
    pub const fn kind(&self) -> PrincipalBindingEventKind {
        self.kind
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

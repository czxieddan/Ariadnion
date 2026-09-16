// crates/optional/ariadnion-account-batch/src/port.rs - Durable account batch port contracts.
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

//! Durable adapter errors, mutation reconciliation, and execution port.

use crate::execution::{
    BatchMutationKind, BatchMutationReceipt, ClaimBatchItems, ClaimReceipt, CompleteClaimedItem,
    ItemCompletionReceipt, SubmissionReceipt, SubmitBatch, TransitionBatch, TransitionReceipt,
};
use crate::{BatchIdentity, BatchStatus, MutationId, OutcomePage, OutcomePageRequest};
use ariadnion_core::{RequestContext, TenantId};
use std::fmt::{self, Display, Formatter};

/// Stable machine-readable failures from the durable batch adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BatchPortErrorCode {
    /// The request has no authenticated principal.
    Unauthenticated,
    /// The authenticated principal is not authorized for the requested access.
    PermissionDenied,
    /// The tenant-scoped batch does not exist.
    NotFound,
    /// The expected revision or mutation binding conflicts with durable state.
    Conflict,
    /// Durable claim evidence is expired, superseded, or already consumed.
    ClaimExpired,
    /// Cancellation won before a durable mutation began.
    Cancelled,
    /// The absolute deadline won before a durable mutation began.
    DeadlineExceeded,
    /// The adapter cannot honor a bounded resource request.
    ResourceExhausted,
    /// The durable adapter is temporarily unavailable.
    Unavailable,
    /// A commit may have succeeded but its exact receipt was not returned.
    CommitIndeterminate,
    /// Durable state violates the batch invariants and must not be used.
    CorruptState,
}

impl BatchPortErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated
            | Self::PermissionDenied
            | Self::NotFound
            | Self::Conflict
            | Self::ClaimExpired
            | Self::Cancelled => coordination_error_code(self),
            Self::DeadlineExceeded
            | Self::ResourceExhausted
            | Self::Unavailable
            | Self::CommitIndeterminate
            | Self::CorruptState => commit_error_code(self),
        }
    }
}

const fn coordination_error_code(code: BatchPortErrorCode) -> &'static str {
    match code {
        BatchPortErrorCode::Unauthenticated => "ACCOUNT_BATCH_PORT_UNAUTHENTICATED",
        BatchPortErrorCode::PermissionDenied => "ACCOUNT_BATCH_PORT_PERMISSION_DENIED",
        BatchPortErrorCode::NotFound => "ACCOUNT_BATCH_PORT_NOT_FOUND",
        BatchPortErrorCode::Conflict => "ACCOUNT_BATCH_PORT_CONFLICT",
        BatchPortErrorCode::ClaimExpired => "ACCOUNT_BATCH_PORT_CLAIM_EXPIRED",
        BatchPortErrorCode::Cancelled => "ACCOUNT_BATCH_PORT_CANCELLED",
        _ => "ACCOUNT_BATCH_PORT_CORRUPT_STATE",
    }
}

const fn commit_error_code(code: BatchPortErrorCode) -> &'static str {
    match code {
        BatchPortErrorCode::DeadlineExceeded => "ACCOUNT_BATCH_PORT_DEADLINE_EXCEEDED",
        BatchPortErrorCode::ResourceExhausted => "ACCOUNT_BATCH_PORT_RESOURCE_EXHAUSTED",
        BatchPortErrorCode::Unavailable => "ACCOUNT_BATCH_PORT_UNAVAILABLE",
        BatchPortErrorCode::CommitIndeterminate => "ACCOUNT_BATCH_PORT_COMMIT_INDETERMINATE",
        BatchPortErrorCode::CorruptState => "ACCOUNT_BATCH_PORT_CORRUPT_STATE",
        _ => "ACCOUNT_BATCH_PORT_CORRUPT_STATE",
    }
}

/// Redacted durable-adapter failure containing no identifiers or item data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchPortError {
    code: BatchPortErrorCode,
}

impl BatchPortError {
    /// Creates a redacted durable-adapter failure.
    #[must_use]
    pub const fn new(code: BatchPortErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> BatchPortErrorCode {
        self.code
    }

    /// Returns whether callers must reconcile instead of retrying the mutation.
    #[must_use]
    pub const fn requires_reconciliation(self) -> bool {
        matches!(self.code, BatchPortErrorCode::CommitIndeterminate)
    }
}

impl Display for BatchPortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for BatchPortError {}

/// One least-privilege durable account-batch access decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AccountBatchAccess {
    /// Creates or exactly replays one immutable administrative batch plan.
    Submit,
    /// Reads one administrative batch status without item payloads.
    Load,
    /// Claims bounded work for an authenticated batch worker.
    Claim,
    /// Completes one item previously assigned to an authenticated batch worker.
    Complete,
    /// Applies one administrative batch lifecycle transition.
    Transition,
    /// Reads one tenant-local mutation receipt after response loss.
    Reconcile,
    /// Lists administrative terminal outcome evidence.
    ListOutcomes,
}

/// Fail-closed authorization boundary for durable account-batch access.
///
/// Implementations evaluate the authenticated principal and exact tenant from
/// `context` against authoritative policy. Authentication alone is not
/// permission. The RNMDB adapter invokes this synchronous port before every
/// storage access and again immediately before each mutation transaction may
/// commit. A precommit invocation holds the repository session lock, so policy
/// implementations must not reenter the same owner or invert its lock order.
/// The precommit decision must remain valid through the immediately following
/// durable commit because the adapter cannot interpose another policy call
/// inside RNMDB's commit operation.
/// A decision that cannot be established must return a stable redacted error;
/// an ordinary denial should return [`BatchPortErrorCode::PermissionDenied`].
pub trait AccountBatchAuthorizationPort: Send + Sync {
    /// Authorizes exactly one access using current authoritative policy.
    fn authorize(
        &self,
        access: AccountBatchAccess,
        context: &RequestContext,
    ) -> Result<(), BatchPortError>;
}

/// Durable persistence and authoritative execution boundary for account batches.
///
/// Every mutation identity is tenant scoped and must be bound atomically to the
/// complete immutable command. Exact mutation replay returns the same receipt;
/// different content under the same mutation identity returns `Conflict`. When a
/// commit may have succeeded but the receipt was lost, implementations return
/// `CommitIndeterminate`. The caller must not invent a new mutation identity or
/// repeat side effects; it reopens the adapter and calls [`Self::reconcile_mutation`].
pub trait AccountBatchPort: Send + Sync {
    /// Atomically creates a plan or returns its existing idempotent binding.
    fn submit(
        &self,
        command: SubmitBatch,
        context: &RequestContext,
    ) -> Result<SubmissionReceipt, BatchPortError>;

    /// Loads the tenant-scoped durable status without item payloads.
    fn load(
        &self,
        identity: &BatchIdentity,
        context: &RequestContext,
    ) -> Result<Option<BatchStatus>, BatchPortError>;

    /// Atomically recovers expired claims and creates one bounded durable claim.
    ///
    /// Items are selected in immutable plan order. An unexpired claim is not
    /// reassigned. At its exclusive expiry the item becomes eligible, and its
    /// adapter-assigned attempt advances exactly once. The adapter must stop at
    /// the plan attempt bound and must not acknowledge a claim before commit.
    fn claim(
        &self,
        command: ClaimBatchItems,
        context: &RequestContext,
    ) -> Result<ClaimReceipt, BatchPortError>;

    /// Atomically completes one claimed immutable account command.
    ///
    /// The adapter verifies the durable claim, owning tenant, lease, deadline,
    /// intent, item, account, and command against authoritative storage. For
    /// `Execute`, it loads the authoritative account, applies the immutable
    /// account transition command, and commits the resulting account snapshot,
    /// lifecycle event, item outcome, progress, and mutation receipt in one
    /// transaction. For `DryRun`, it evaluates the same command but commits no
    /// account snapshot or lifecycle event; only would-apply or rejection evidence,
    /// progress, and the mutation receipt are durable. The result and authoritative
    /// lifecycle event are adapter-produced and are never accepted from callers.
    fn complete_claimed_item(
        &self,
        command: CompleteClaimedItem,
        context: &RequestContext,
    ) -> Result<ItemCompletionReceipt, BatchPortError>;

    /// Atomically applies one revision-checked lifecycle transition.
    fn transition(
        &self,
        command: TransitionBatch,
        context: &RequestContext,
    ) -> Result<TransitionReceipt, BatchPortError>;

    /// Recovers the exact committed result of any mutation after response loss.
    ///
    /// `Some` proves the committed receipt. `None` proves no receipt is currently
    /// durable for this tenant and mutation identity, allowing the exact original
    /// command to be retried with the same identity. Cross-tenant lookup returns
    /// no receipt and must not reveal whether another tenant used the identity.
    fn reconcile_mutation(
        &self,
        tenant_id: &TenantId,
        mutation_id: &MutationId,
        context: &RequestContext,
    ) -> Result<Option<BatchMutationReceipt>, BatchPortError>;

    /// Reconciles a mutation and rejects a receipt of another typed kind.
    ///
    /// This compatibility helper keeps the original reconciliation method while
    /// allowing callers to bind recovery to the operation kind they originally
    /// submitted. Implementations may override it when their durable index can
    /// enforce the kind atomically.
    fn reconcile_mutation_kind(
        &self,
        tenant_id: &TenantId,
        mutation_id: &MutationId,
        expected_kind: BatchMutationKind,
        context: &RequestContext,
    ) -> Result<Option<BatchMutationReceipt>, BatchPortError> {
        Ok(self
            .reconcile_mutation(tenant_id, mutation_id, context)?
            .filter(|receipt| receipt.kind() == expected_kind))
    }

    /// Lists terminal outcome evidence in stable immutable plan order.
    ///
    /// The adapter compares the request revision with the current durable batch
    /// revision before reading outcomes and returns `Conflict` on mismatch. A
    /// caller restarts paging from the newest revision after any intervening
    /// completion, preventing late lower ordinals from being skipped.
    fn list_outcomes(
        &self,
        request: OutcomePageRequest,
        context: &RequestContext,
    ) -> Result<OutcomePage, BatchPortError>;
}

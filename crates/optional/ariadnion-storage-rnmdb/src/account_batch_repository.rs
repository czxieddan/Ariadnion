// crates/optional/ariadnion-storage-rnmdb/src/account_batch_repository.rs - Rust source for Ariadnion.
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
//! Atomic RNMDB persistence for account-batch execution.

mod codec;
mod implementation;
mod persistence;
mod receipt;
mod reconstruction;
mod sql;

use codec::{internal_context, map_storage_error};
use implementation::{claim_tx, complete_tx, submit_tx, transition_tx};
use persistence::{load_mutation, load_plan};
use reconstruction::{list_outcomes, reconstruct_mutation};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_account_batch::{
    AccountBatchPort, BatchAttempt, BatchClaim, BatchClaimLimit, BatchIdentity, BatchIntent,
    BatchItem, BatchItemFailureCode, BatchItemId, BatchItemOrdinal, BatchItemOutcome,
    BatchItemResult, BatchLifecycle, BatchMutationKind, BatchMutationReceipt, BatchPlan,
    BatchPortError, BatchPortErrorCode, BatchResourceLimits, BatchRevision, BatchStatus,
    BatchSubmission, BatchSubmitDisposition, BatchTerminalState, BatchTransition, ClaimAssignment,
    ClaimBatchItems, ClaimId, ClaimReceipt, CompleteClaimedItem, IdempotencyKey,
    ItemCompletionReceipt, MutationId, NoLiveClaims, OperationId, OutcomePage, OutcomePageRequest,
    RevisionEvidence, SubmissionReceipt, SubmitBatch, TransitionBatch, TransitionReceipt,
    UtcSeconds,
};
use ariadnion_account_domain::{
    AccountDomainErrorCode, AccountId, AccountLifecycleChange, AccountStatus,
    AccountTransitionAction, AccountTransitionCommand, AccountVersion, apply_account_lifecycle,
};
use ariadnion_core::{RequestContext, RequestId, TenantId, TraceId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{Row, VectorBatch};
use rnmdb_types::SqlValue;
use sha2::{Digest, Sha256};

use crate::RnmdbSessionOwner;
use crate::identity_transaction::{require_active_identity_transaction, run_identity_transaction};

const PLAN_PROJECTION: &str = "tenant_id, operation_id, batch_id, idempotency_key, plan_digest_hex, intent, created_at, deadline, max_parallel_items, max_claim_items, max_item_attempts, lifecycle, terminal_state, revision, total_items, completed_items, failed_items";
const ITEM_PROJECTION: &str = "tenant_id, operation_id, batch_id, item_ordinal, item_id, account_id, expected_account_version, transition_action, attempt, item_state, claim_id, claim_revision, lease_expires_at, completion_mutation_id, outcome_kind, outcome_failure, outcome_from, outcome_to, outcome_version, outcome_committed_at";
const MUTATION_PROJECTION: &str = "tenant_id, mutation_id, mutation_kind, command_digest_hex, operation_id, batch_id, disposition, claim_id, claim_revision, lease_expires_at, completion_ordinal, observed_at, committed_at, lifecycle, terminal_state, revision, total_items, completed_items, failed_items";
const ACCOUNT_LIFECYCLE_PROJECTION: &str = "account_id, account_version, account_status";

/// Durable account-batch adapter over one serialized embedded RNMDB session.
///
/// The trait does not carry a request context. Callers must authorize the
/// administrative operation before entering this port. Every database access is
/// still executed under RNMDB's tenant context, so cross-tenant rows remain
/// inaccessible even when identifiers collide.
///
/// This synchronous adapter performs blocking embedded storage operations and
/// must run on a blocking worker, never on an asynchronous executor thread.
/// All account effects, outcomes, progress, and mutation receipts commit in one
/// transaction. An indeterminate commit requires reconciliation on a reopened
/// session; it must not be treated as permission to issue a new mutation.
pub struct RnmdbAccountBatchRepository {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbAccountBatchRepository {
    /// Creates an adapter over the supplied serialized session owner.
    #[must_use]
    pub const fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Returns the underlying embedded session owner.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }
}

impl AccountBatchPort for RnmdbAccountBatchRepository {
    fn submit(&self, command: SubmitBatch) -> Result<SubmissionReceipt, BatchPortError> {
        let tenant = command.plan().submission().tenant_id().clone();
        let context = internal_context()?;
        self.session
            .with_identity_transaction_session(&context, &tenant, |session| {
                run_identity_transaction(session, &context, |session| submit_tx(session, &command))
            })
            .map_err(map_storage_error)
    }

    fn load(&self, identity: &BatchIdentity) -> Result<Option<BatchStatus>, BatchPortError> {
        let context = internal_context()?;
        self.session
            .with_identity_storage_session(&context, identity.tenant_id(), |session| {
                load_plan(session, identity).map(|plan| plan.map(|value| value.status))
            })
            .map_err(map_storage_error)
    }

    fn claim(&self, command: ClaimBatchItems) -> Result<ClaimReceipt, BatchPortError> {
        let tenant = command.identity().tenant_id().clone();
        let context = internal_context()?;
        self.session
            .with_identity_transaction_session(&context, &tenant, |session| {
                run_identity_transaction(session, &context, |session| claim_tx(session, &command))
            })
            .map_err(map_storage_error)
    }

    fn complete_claimed_item(
        &self,
        command: CompleteClaimedItem,
    ) -> Result<ItemCompletionReceipt, BatchPortError> {
        let tenant = command.claimed_item().identity().tenant_id().clone();
        let context = internal_context()?;
        self.session
            .with_identity_transaction_session(&context, &tenant, |session| {
                run_identity_transaction(session, &context, |session| {
                    complete_tx(session, &command)
                })
            })
            .map_err(map_storage_error)
    }

    fn transition(&self, command: TransitionBatch) -> Result<TransitionReceipt, BatchPortError> {
        let tenant = command.identity().tenant_id().clone();
        let context = internal_context()?;
        self.session
            .with_identity_transaction_session(&context, &tenant, |session| {
                run_identity_transaction(session, &context, |session| {
                    transition_tx(session, &command)
                })
            })
            .map_err(map_storage_error)
    }

    fn reconcile_mutation(
        &self,
        tenant_id: &TenantId,
        mutation_id: &MutationId,
    ) -> Result<Option<BatchMutationReceipt>, BatchPortError> {
        let context = internal_context()?;
        self.session
            .with_identity_storage_session(&context, tenant_id, |session| {
                load_mutation(session, tenant_id, mutation_id)?
                    .map(|mutation| reconstruct_mutation(session, mutation))
                    .transpose()
            })
            .map_err(map_storage_error)
    }

    fn list_outcomes(&self, request: OutcomePageRequest) -> Result<OutcomePage, BatchPortError> {
        let context = internal_context()?;
        self.session
            .with_identity_storage_session(&context, request.identity().tenant_id(), |session| {
                list_outcomes(session, &request)
            })
            .map_err(map_storage_error)
    }
}

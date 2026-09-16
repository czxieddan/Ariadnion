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

use codec::map_storage_error;
use implementation::{claim_tx, complete_tx, submit_tx, transition_tx};
use persistence::{load_mutation, load_plan};
use reconstruction::{list_outcomes, reconstruct_mutation};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_account_batch::{
    AccountBatchAccess, AccountBatchAuthorizationPort, AccountBatchPort, BatchAttempt, BatchClaim,
    BatchClaimLimit, BatchIdentity, BatchIntent, BatchItem, BatchItemFailureCode, BatchItemId,
    BatchItemOrdinal, BatchItemOutcome, BatchItemResult, BatchLifecycle, BatchMutationKind,
    BatchMutationReceipt, BatchPlan, BatchPortError, BatchPortErrorCode, BatchResourceLimits,
    BatchRevision, BatchStatus, BatchSubmission, BatchSubmitDisposition, BatchTerminalState,
    BatchTransition, ClaimAssignment, ClaimBatchItems, ClaimId, ClaimReceipt, CompleteClaimedItem,
    IdempotencyKey, ItemCompletionReceipt, MutationId, NoLiveClaims, OperationId, OutcomePage,
    OutcomePageRequest, RevisionEvidence, SubmissionReceipt, SubmitBatch, TransitionBatch,
    TransitionReceipt, UtcSeconds,
};
use ariadnion_account_domain::{
    AccountDomainErrorCode, AccountId, AccountLifecycleChange, AccountStatus,
    AccountTransitionAction, AccountTransitionCommand, AccountVersion, apply_account_lifecycle,
};
use ariadnion_core::{ErrorCode, RequestContext, TenantId};
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
/// Every access requires an active authenticated request for the exact target
/// tenant and a current decision from the injected fail-closed policy. Mutations
/// are authorized again inside the transaction immediately before commit.
///
/// This synchronous adapter performs blocking embedded storage operations and
/// must run on a blocking worker, never on an asynchronous executor thread.
/// All account effects, outcomes, progress, and mutation receipts commit in one
/// transaction. An indeterminate commit requires reconciliation on a reopened
/// session; it must not be treated as permission to issue a new mutation.
pub struct RnmdbAccountBatchRepository {
    session: Arc<RnmdbSessionOwner>,
    authorization: Arc<dyn AccountBatchAuthorizationPort>,
}

impl RnmdbAccountBatchRepository {
    /// Creates an adapter over a serialized session and fail-closed policy.
    #[must_use]
    pub fn new(
        session: Arc<RnmdbSessionOwner>,
        authorization: Arc<dyn AccountBatchAuthorizationPort>,
    ) -> Self {
        Self {
            session,
            authorization,
        }
    }

    /// Returns the underlying embedded session owner.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }
}

impl AccountBatchPort for RnmdbAccountBatchRepository {
    fn submit(
        &self,
        command: SubmitBatch,
        context: &RequestContext,
    ) -> Result<SubmissionReceipt, BatchPortError> {
        let tenant = command.plan().submission().tenant_id().clone();
        self.execute_mutation(AccountBatchAccess::Submit, &tenant, context, |session| {
            submit_tx(session, &command)
        })
    }

    fn load(
        &self,
        identity: &BatchIdentity,
        context: &RequestContext,
    ) -> Result<Option<BatchStatus>, BatchPortError> {
        self.execute_read(
            AccountBatchAccess::Load,
            identity.tenant_id(),
            context,
            |session| load_plan(session, identity).map(|plan| plan.map(|value| value.status)),
        )
    }

    fn claim(
        &self,
        command: ClaimBatchItems,
        context: &RequestContext,
    ) -> Result<ClaimReceipt, BatchPortError> {
        let tenant = command.identity().tenant_id().clone();
        self.execute_mutation(AccountBatchAccess::Claim, &tenant, context, |session| {
            claim_tx(session, &command)
        })
    }

    fn complete_claimed_item(
        &self,
        command: CompleteClaimedItem,
        context: &RequestContext,
    ) -> Result<ItemCompletionReceipt, BatchPortError> {
        let tenant = command.claimed_item().identity().tenant_id().clone();
        self.execute_mutation(AccountBatchAccess::Complete, &tenant, context, |session| {
            complete_tx(session, &command)
        })
    }

    fn transition(
        &self,
        command: TransitionBatch,
        context: &RequestContext,
    ) -> Result<TransitionReceipt, BatchPortError> {
        let tenant = command.identity().tenant_id().clone();
        self.execute_mutation(
            AccountBatchAccess::Transition,
            &tenant,
            context,
            |session| transition_tx(session, &command),
        )
    }

    fn reconcile_mutation(
        &self,
        tenant_id: &TenantId,
        mutation_id: &MutationId,
        context: &RequestContext,
    ) -> Result<Option<BatchMutationReceipt>, BatchPortError> {
        self.execute_read(
            AccountBatchAccess::Reconcile,
            tenant_id,
            context,
            |session| {
                load_mutation(session, tenant_id, mutation_id)?
                    .map(|mutation| reconstruct_mutation(session, mutation))
                    .transpose()
            },
        )
    }

    fn list_outcomes(
        &self,
        request: OutcomePageRequest,
        context: &RequestContext,
    ) -> Result<OutcomePage, BatchPortError> {
        self.execute_read(
            AccountBatchAccess::ListOutcomes,
            request.identity().tenant_id(),
            context,
            |session| list_outcomes(session, &request),
        )
    }
}

impl RnmdbAccountBatchRepository {
    fn execute_read<T>(
        &self,
        access: AccountBatchAccess,
        tenant: &TenantId,
        context: &RequestContext,
        operation: impl FnOnce(&mut LocalSession) -> Result<T, StorageError>,
    ) -> Result<T, BatchPortError> {
        authorize_request(self.authorization.as_ref(), access, tenant, context)?;
        self.session
            .with_identity_storage_session(context, tenant, operation)
            .map_err(map_storage_error)
    }

    fn execute_mutation<T>(
        &self,
        access: AccountBatchAccess,
        tenant: &TenantId,
        context: &RequestContext,
        operation: impl FnOnce(&mut LocalSession) -> Result<T, StorageError>,
    ) -> Result<T, BatchPortError> {
        authorize_request(self.authorization.as_ref(), access, tenant, context)?;
        let mut boundary_error = None;
        let result = self
            .session
            .with_identity_transaction_session(context, tenant, |session| {
                run_identity_transaction(session, context, |session| {
                    let value = operation(session)?;
                    record_authorization_boundary(
                        self.authorization.as_ref(),
                        access,
                        tenant,
                        context,
                        &mut boundary_error,
                    )?;
                    Ok(value)
                })
            });
        project_mutation_result(result, boundary_error)
    }
}

fn authorize_request(
    authorization: &dyn AccountBatchAuthorizationPort,
    access: AccountBatchAccess,
    tenant: &TenantId,
    context: &RequestContext,
) -> Result<(), BatchPortError> {
    check_request_context(context)?;
    let principal = context
        .principal()
        .ok_or_else(|| port_error(BatchPortErrorCode::Unauthenticated))?;
    if principal.tenant_id() != tenant {
        return Err(port_error(BatchPortErrorCode::PermissionDenied));
    }
    let decision = authorization.authorize(access, context);
    check_request_context(context)?;
    decision
}

fn check_request_context(context: &RequestContext) -> Result<(), BatchPortError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => port_error(BatchPortErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => port_error(BatchPortErrorCode::DeadlineExceeded),
        _ => port_error(BatchPortErrorCode::CorruptState),
    })
}

fn record_authorization_boundary(
    authorization: &dyn AccountBatchAuthorizationPort,
    access: AccountBatchAccess,
    tenant: &TenantId,
    context: &RequestContext,
    boundary_error: &mut Option<BatchPortError>,
) -> Result<(), StorageError> {
    authorize_request(authorization, access, tenant, context).map_err(|error| {
        *boundary_error = Some(error);
        StorageError::new(StorageErrorCode::InvalidArgument)
    })
}

fn project_mutation_result<T>(
    result: Result<T, StorageError>,
    boundary_error: Option<BatchPortError>,
) -> Result<T, BatchPortError> {
    match result {
        Err(error) if error.code() == StorageErrorCode::InvalidArgument => {
            Err(boundary_error.unwrap_or_else(|| map_storage_error(error)))
        }
        result => result.map_err(map_storage_error),
    }
}

const fn port_error(code: BatchPortErrorCode) -> BatchPortError {
    BatchPortError::new(code)
}

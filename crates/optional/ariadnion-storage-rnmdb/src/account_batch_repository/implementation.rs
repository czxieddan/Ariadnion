// crates/optional/ariadnion-storage-rnmdb/src/account_batch_repository/implementation.rs - Rust source for Ariadnion.
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
//! Transactional account-batch command orchestration.

use super::codec::*;
use super::persistence::*;
use super::receipt::{MutationWrite, insert_claim_assignments, insert_mutation};
use super::reconstruction::{
    reconstruct_claim, reconstruct_completion, reconstruct_submission, reconstruct_transition,
};
use super::*;

pub(super) fn submit_tx(
    session: &mut LocalSession,
    command: &SubmitBatch,
) -> Result<SubmissionReceipt, StorageError> {
    require_active_identity_transaction(session)?;
    let digest = submit_digest(command);
    if let Some(receipt) = replay_submission(session, command, &digest)? {
        return Ok(receipt);
    }
    submit_new(session, command, &digest)
}

fn replay_submission(
    session: &mut LocalSession,
    command: &SubmitBatch,
    digest: &str,
) -> Result<Option<SubmissionReceipt>, StorageError> {
    let existing = load_mutation(
        session,
        command.plan().submission().tenant_id(),
        command.mutation_id(),
    )?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    require_digest(&existing, BatchMutationKind::Submission, digest)?;
    reconstruct_submission(session, existing).map(Some)
}

fn submit_new(
    session: &mut LocalSession,
    command: &SubmitBatch,
    digest: &str,
) -> Result<SubmissionReceipt, StorageError> {
    let identity = command.plan().identity();
    let plan_digest = plan_digest(command.plan());
    let disposition = submit_disposition(session, command.plan(), &plan_digest)?;
    let stored = load_plan(session, &identity)?.ok_or_else(integrity)?;
    let committed_at = trusted_now()?;
    let mutation =
        MutationWrite::submission(command, digest, disposition, &stored.status, committed_at);
    insert_mutation(session, mutation)?;
    SubmissionReceipt::new(command, disposition, stored.status).map_err(|_| integrity())
}

fn submit_disposition(
    session: &mut LocalSession,
    plan: &BatchPlan,
    digest: &str,
) -> Result<BatchSubmitDisposition, StorageError> {
    match load_plan_by_idempotency(session, plan)? {
        Some(existing) => {
            if existing.digest != digest || existing.plan != *plan {
                return Err(conflict());
            }
            Ok(BatchSubmitDisposition::Replayed)
        }
        None => {
            insert_plan(session, plan, digest)?;
            Ok(BatchSubmitDisposition::Created)
        }
    }
}

pub(super) fn claim_tx(
    session: &mut LocalSession,
    command: &ClaimBatchItems,
) -> Result<ClaimReceipt, StorageError> {
    require_active_identity_transaction(session)?;
    let digest = claim_digest(command);
    if let Some(receipt) = replay_claim(session, command, &digest)? {
        return Ok(receipt);
    }
    commit_claim(session, command, &digest)
}

fn replay_claim(
    session: &mut LocalSession,
    command: &ClaimBatchItems,
    digest: &str,
) -> Result<Option<ClaimReceipt>, StorageError> {
    let existing = load_mutation(
        session,
        command.identity().tenant_id(),
        command.mutation_id(),
    )?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    require_digest(&existing, BatchMutationKind::Claim, digest)?;
    reconstruct_claim(session, existing).map(Some)
}

struct PreparedClaim {
    stored: StoredPlan,
    observed_at: UtcSeconds,
    revision: BatchRevision,
    claim: BatchClaim,
    ordinals: Vec<BatchItemOrdinal>,
}

fn prepare_claim(
    session: &mut LocalSession,
    command: &ClaimBatchItems,
) -> Result<PreparedClaim, StorageError> {
    let stored = load_running_plan(session, command)?;
    let observed_at = trusted_now()?;
    validate_claim_time(command, &stored.plan, observed_at)?;
    build_prepared_claim(session, command, stored, observed_at)
}

fn load_running_plan(
    session: &mut LocalSession,
    command: &ClaimBatchItems,
) -> Result<StoredPlan, StorageError> {
    let stored = load_plan(session, command.identity())?.ok_or_else(not_found)?;
    require_revision(&stored.status, command.expected_revision())?;
    if stored.status.lifecycle() != BatchLifecycle::Running {
        return Err(conflict());
    }
    Ok(stored)
}

fn build_prepared_claim(
    session: &mut LocalSession,
    command: &ClaimBatchItems,
    stored: StoredPlan,
    observed_at: UtcSeconds,
) -> Result<PreparedClaim, StorageError> {
    let items = load_items(session, command.identity())?;
    let revision = stored.status.revision().next().map_err(|_| exhausted())?;
    let (assignments, claimed_ordinals) =
        eligible_assignments(&stored.plan, &items, command, observed_at)?;
    let authoritative = authoritative_claim_command(command, observed_at)?;
    let claim = BatchClaim::new(&authoritative, &stored.plan, revision, assignments)
        .map_err(|_| conflict())?;
    Ok(PreparedClaim {
        stored,
        observed_at,
        revision,
        claim,
        ordinals: claimed_ordinals,
    })
}

fn commit_claim(
    session: &mut LocalSession,
    command: &ClaimBatchItems,
    digest: &str,
) -> Result<ClaimReceipt, StorageError> {
    let prepared = prepare_claim(session, command)?;
    persist_claim(
        session,
        command,
        prepared.observed_at,
        prepared.revision,
        &prepared.ordinals,
    )?;
    let status = claimed_status(command, &prepared)?;
    update_status(session, &prepared.stored.status, &status)?;
    insert_mutation(
        session,
        MutationWrite::claim(
            command,
            digest,
            &status,
            prepared.observed_at,
            prepared.observed_at,
        ),
    )?;
    insert_claim_assignments(session, command, &prepared.claim)?;
    ClaimReceipt::new(command.mutation_id().clone(), prepared.claim, status)
        .map_err(|_| integrity())
}

fn claimed_status(
    command: &ClaimBatchItems,
    prepared: &PreparedClaim,
) -> Result<BatchStatus, StorageError> {
    let previous = &prepared.stored.status;
    BatchStatus::new(
        command.identity().clone(),
        previous.lifecycle(),
        prepared.revision,
        previous.total_items(),
        previous.completed_items(),
        previous.failed_items(),
    )
    .map_err(|_| integrity())
}

pub(super) fn complete_tx(
    session: &mut LocalSession,
    command: &CompleteClaimedItem,
) -> Result<ItemCompletionReceipt, StorageError> {
    require_active_identity_transaction(session)?;
    let digest = completion_digest(command);
    if let Some(receipt) = replay_completion(session, command, &digest)? {
        return Ok(receipt);
    }
    commit_completion(session, command, &digest)
}

fn replay_completion(
    session: &mut LocalSession,
    command: &CompleteClaimedItem,
    digest: &str,
) -> Result<Option<ItemCompletionReceipt>, StorageError> {
    let existing = load_mutation(
        session,
        command.claimed_item().identity().tenant_id(),
        command.mutation_id(),
    )?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    require_digest(&existing, BatchMutationKind::ItemCompletion, digest)?;
    reconstruct_completion(session, existing).map(Some)
}

struct PreparedCompletion {
    stored: StoredPlan,
    account: Option<StoredAccountLifecycle>,
    result: BatchItemResult,
    observed_at: UtcSeconds,
}

fn prepare_completion(
    session: &mut LocalSession,
    command: &CompleteClaimedItem,
) -> Result<PreparedCompletion, StorageError> {
    let identity = command.claimed_item().identity();
    let stored = required_plan(session, identity)?;
    let item = required_item(session, identity, command.claimed_item().ordinal())?;
    let observed_at = trusted_now()?;
    validate_claimed_item(command, &stored.plan, &item, observed_at)?;
    let account = load_account_lifecycle(
        session,
        identity.tenant_id(),
        command.claimed_item().account_id(),
    )?;
    let result = authoritative_result(
        account.as_ref(),
        command.claimed_item().command(),
        command.claimed_item().intent(),
    )?;
    Ok(PreparedCompletion {
        stored,
        account,
        result,
        observed_at,
    })
}

fn commit_completion(
    session: &mut LocalSession,
    command: &CompleteClaimedItem,
    digest: &str,
) -> Result<ItemCompletionReceipt, StorageError> {
    let prepared = prepare_completion(session, command)?;
    let outcome = BatchItemOutcome::new(
        command.claimed_item().clone(),
        prepared.result.clone(),
        prepared.observed_at,
    )
    .map_err(|_| integrity())?;
    let status = persist_completion(session, command, digest, &prepared, &outcome)?;
    let evidence = completion_evidence(command.claimed_item().claim_revision(), status.revision())?;
    ItemCompletionReceipt::new_with_revision_evidence(
        command.mutation_id().clone(),
        outcome,
        status,
        evidence,
    )
    .map_err(|_| integrity())
}

fn persist_completion(
    session: &mut LocalSession,
    command: &CompleteClaimedItem,
    digest: &str,
    prepared: &PreparedCompletion,
    outcome: &BatchItemOutcome,
) -> Result<BatchStatus, StorageError> {
    persist_completion_effect(session, command, prepared)?;
    persist_outcome(session, command, outcome)?;
    let status = completion_status(
        session,
        &prepared.stored.status,
        outcome,
        prepared.observed_at,
    )?;
    update_status(session, &prepared.stored.status, &status)?;
    insert_mutation(
        session,
        MutationWrite::completion(
            command,
            digest,
            &status,
            prepared.observed_at,
            prepared.observed_at,
        ),
    )?;
    Ok(status)
}

fn persist_completion_effect(
    session: &mut LocalSession,
    command: &CompleteClaimedItem,
    prepared: &PreparedCompletion,
) -> Result<(), StorageError> {
    let BatchItemResult::Applied { event } = &prepared.result else {
        return Ok(());
    };
    let change = prepared
        .account
        .as_ref()
        .ok_or_else(integrity)?
        .apply(command.claimed_item().command())
        .map_err(map_account_lifecycle_error)?;
    persist_account_transition(session, &change, event, command, prepared.observed_at)
}

pub(super) fn completion_evidence(
    claim_revision: BatchRevision,
    completion_revision: BatchRevision,
) -> Result<RevisionEvidence, StorageError> {
    let gap = completion_revision
        .get()
        .checked_sub(claim_revision.get())
        .and_then(|value| value.checked_sub(1))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(integrity)?;
    RevisionEvidence::new(claim_revision, completion_revision, gap).map_err(|_| integrity())
}

pub(super) fn transition_tx(
    session: &mut LocalSession,
    command: &TransitionBatch,
) -> Result<TransitionReceipt, StorageError> {
    require_active_identity_transaction(session)?;
    let digest = transition_digest(command);
    if let Some(receipt) = replay_transition(session, command, &digest)? {
        return Ok(receipt);
    }
    commit_transition(session, command, &digest)
}

fn replay_transition(
    session: &mut LocalSession,
    command: &TransitionBatch,
    digest: &str,
) -> Result<Option<TransitionReceipt>, StorageError> {
    let existing = load_mutation(
        session,
        command.identity().tenant_id(),
        command.mutation_id(),
    )?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    require_digest(&existing, BatchMutationKind::Transition, digest)?;
    reconstruct_transition(session, existing).map(Some)
}

struct PreparedTransition {
    stored: StoredPlan,
    observed_at: UtcSeconds,
    status: BatchStatus,
}

fn prepare_transition(
    session: &mut LocalSession,
    command: &TransitionBatch,
) -> Result<PreparedTransition, StorageError> {
    let stored = required_plan(session, command.identity())?;
    require_revision(&stored.status, command.expected_revision())?;
    require_transition_deadline(command, stored.plan.submission().deadline())?;
    let observed_at = trusted_now()?;
    let lifecycle = next_lifecycle(
        stored.status.lifecycle(),
        command.transition(),
        observed_at,
        stored.plan.submission().deadline(),
    )?;
    let status = transition_status(session, command, &stored.status, lifecycle, observed_at)?;
    Ok(PreparedTransition {
        stored,
        observed_at,
        status,
    })
}

fn require_transition_deadline(
    command: &TransitionBatch,
    expected: UtcSeconds,
) -> Result<(), StorageError> {
    if command
        .deadline()
        .is_none_or(|deadline| deadline == expected)
    {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn transition_status(
    session: &mut LocalSession,
    command: &TransitionBatch,
    current: &BatchStatus,
    lifecycle: BatchLifecycle,
    observed_at: UtcSeconds,
) -> Result<BatchStatus, StorageError> {
    let revision = current.revision().next().map_err(|_| exhausted())?;
    if matches!(lifecycle, BatchLifecycle::Terminal(_)) {
        return terminal_transition_status(
            session,
            command,
            current,
            lifecycle,
            revision,
            observed_at,
        );
    }
    BatchStatus::new(
        command.identity().clone(),
        lifecycle,
        revision,
        current.total_items(),
        current.completed_items(),
        current.failed_items(),
    )
    .map_err(|_| conflict())
}

fn terminal_transition_status(
    session: &mut LocalSession,
    command: &TransitionBatch,
    current: &BatchStatus,
    lifecycle: BatchLifecycle,
    revision: BatchRevision,
    observed_at: UtcSeconds,
) -> Result<BatchStatus, StorageError> {
    let live = count_live_claims(session, command.identity(), observed_at)?;
    let proof = NoLiveClaims::new(live).map_err(|_| conflict())?;
    BatchStatus::new_terminal(
        command.identity().clone(),
        lifecycle,
        revision,
        current.total_items(),
        current.completed_items(),
        current.failed_items(),
        proof,
    )
    .map_err(|_| conflict())
}

fn commit_transition(
    session: &mut LocalSession,
    command: &TransitionBatch,
    digest: &str,
) -> Result<TransitionReceipt, StorageError> {
    let prepared = prepare_transition(session, command)?;
    update_status(session, &prepared.stored.status, &prepared.status)?;
    insert_mutation(
        session,
        MutationWrite::transition(
            command,
            digest,
            &prepared.status,
            prepared.observed_at,
            prepared.observed_at,
        ),
    )?;
    let authoritative = authoritative_transition(command, &prepared);
    TransitionReceipt::new_with_committed_at(&authoritative, prepared.status, prepared.observed_at)
        .map_err(|_| integrity())
}

fn authoritative_transition(
    command: &TransitionBatch,
    prepared: &PreparedTransition,
) -> TransitionBatch {
    TransitionBatch::with_deadline(
        command.mutation_id().clone(),
        command.identity().clone(),
        command.expected_revision(),
        prepared.observed_at,
        prepared.stored.plan.submission().deadline(),
        command.transition(),
    )
}

fn next_lifecycle(
    current: BatchLifecycle,
    transition: BatchTransition,
    observed_at: UtcSeconds,
    deadline: UtcSeconds,
) -> Result<BatchLifecycle, StorageError> {
    let result = match transition {
        BatchTransition::Start => current.start(observed_at, deadline),
        BatchTransition::RequestCancellation if observed_at < deadline => {
            current.request_cancellation()
        }
        BatchTransition::RequestCancellation => {
            return Err(StorageError::new(StorageErrorCode::DeadlineExceeded));
        }
        BatchTransition::Expire => current.expire(observed_at, deadline),
        BatchTransition::Finish(terminal) => current.finish(terminal),
    };
    result.map_err(|_| conflict())
}

fn validate_claim_time(
    command: &ClaimBatchItems,
    plan: &BatchPlan,
    observed_at: UtcSeconds,
) -> Result<(), StorageError> {
    if observed_at >= command.lease_expires_at()
        || observed_at >= plan.submission().deadline()
        || command.lease_expires_at() > plan.submission().deadline()
    {
        return Err(StorageError::new(StorageErrorCode::DeadlineExceeded));
    }
    Ok(())
}

fn authoritative_claim_command(
    command: &ClaimBatchItems,
    observed_at: UtcSeconds,
) -> Result<ClaimBatchItems, StorageError> {
    ClaimBatchItems::new(
        command.mutation_id().clone(),
        command.identity().clone(),
        command.expected_revision(),
        command.claim_id().clone(),
        observed_at,
        command.lease_expires_at(),
        command.limit(),
    )
    .map_err(|_| StorageError::new(StorageErrorCode::DeadlineExceeded))
}

fn authoritative_result(
    account: Option<&StoredAccountLifecycle>,
    command: AccountTransitionCommand,
    intent: BatchIntent,
) -> Result<BatchItemResult, StorageError> {
    let Some(account) = account else {
        return Ok(BatchItemResult::Rejected(
            BatchItemFailureCode::AccountNotFound,
        ));
    };
    match account.apply(command) {
        Ok(change) => Ok(successful_item_result(change, intent)),
        Err(error) => rejected_item_result(error),
    }
}

pub(super) fn successful_item_result(
    change: AccountLifecycleChange,
    intent: BatchIntent,
) -> BatchItemResult {
    let event = change.event().clone();
    if intent == BatchIntent::Execute {
        BatchItemResult::Applied { event }
    } else {
        BatchItemResult::WouldApply { event }
    }
}

fn rejected_item_result(
    error: ariadnion_account_domain::AccountDomainError,
) -> Result<BatchItemResult, StorageError> {
    let code = match error.code() {
        AccountDomainErrorCode::VersionConflict => BatchItemFailureCode::VersionConflict,
        AccountDomainErrorCode::InvalidTransition | AccountDomainErrorCode::DeletedTerminal => {
            BatchItemFailureCode::InvalidTransition
        }
        AccountDomainErrorCode::VersionExhausted => BatchItemFailureCode::ResourceExhausted,
        _ => return Err(integrity()),
    };
    Ok(BatchItemResult::Rejected(code))
}

struct CompletionCounts {
    completed: u32,
    failed: u32,
    revision: BatchRevision,
}

fn completion_status(
    session: &mut LocalSession,
    current: &BatchStatus,
    outcome: &BatchItemOutcome,
    committed_at: UtcSeconds,
) -> Result<BatchStatus, StorageError> {
    let counts = completion_counts(current, outcome)?;
    if counts.completed != current.total_items() {
        return active_completion_status(current, counts);
    }
    terminal_completion_status(session, current, counts, committed_at)
}

fn completion_counts(
    current: &BatchStatus,
    outcome: &BatchItemOutcome,
) -> Result<CompletionCounts, StorageError> {
    let completed = current
        .completed_items()
        .checked_add(1)
        .ok_or_else(exhausted)?;
    let failed = current
        .failed_items()
        .checked_add(u32::from(matches!(
            outcome.result(),
            BatchItemResult::Rejected(_)
        )))
        .ok_or_else(exhausted)?;
    let revision = current.revision().next().map_err(|_| exhausted())?;
    Ok(CompletionCounts {
        completed,
        failed,
        revision,
    })
}

fn active_completion_status(
    current: &BatchStatus,
    counts: CompletionCounts,
) -> Result<BatchStatus, StorageError> {
    BatchStatus::new(
        current.identity().clone(),
        current.lifecycle(),
        counts.revision,
        current.total_items(),
        counts.completed,
        counts.failed,
    )
    .map_err(|_| integrity())
}

fn terminal_completion_status(
    session: &mut LocalSession,
    current: &BatchStatus,
    counts: CompletionCounts,
    committed_at: UtcSeconds,
) -> Result<BatchStatus, StorageError> {
    let live = count_live_claims(session, current.identity(), committed_at)?;
    let terminal = if counts.failed == 0 {
        BatchTerminalState::Succeeded
    } else {
        BatchTerminalState::CompletedWithFailures
    };
    let lifecycle = current
        .lifecycle()
        .finish(terminal)
        .map_err(|_| conflict())?;
    let proof = NoLiveClaims::new(live).map_err(|_| conflict())?;
    BatchStatus::new_terminal(
        current.identity().clone(),
        lifecycle,
        counts.revision,
        current.total_items(),
        counts.completed,
        counts.failed,
        proof,
    )
    .map_err(|_| integrity())
}

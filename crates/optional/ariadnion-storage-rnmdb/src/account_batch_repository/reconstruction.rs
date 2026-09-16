// crates/optional/ariadnion-storage-rnmdb/src/account_batch_repository/reconstruction.rs - Rust source for Ariadnion.
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
//! Durable account-batch receipt and outcome reconstruction.

use super::codec::*;
use super::implementation::{completion_evidence, successful_item_result};
use super::persistence::*;
use super::*;

pub(super) fn reconstruct_mutation(
    session: &mut LocalSession,
    mutation: StoredMutation,
) -> Result<BatchMutationReceipt, StorageError> {
    match mutation.kind {
        BatchMutationKind::Submission => {
            reconstruct_submission(session, mutation).map(BatchMutationReceipt::Submitted)
        }
        BatchMutationKind::Claim => {
            reconstruct_claim(session, mutation).map(BatchMutationReceipt::Claimed)
        }
        BatchMutationKind::ItemCompletion => {
            reconstruct_completion(session, mutation).map(BatchMutationReceipt::ItemCompleted)
        }
        BatchMutationKind::Transition => {
            reconstruct_transition(session, mutation).map(BatchMutationReceipt::Transitioned)
        }
    }
}

pub(super) fn reconstruct_submission(
    session: &mut LocalSession,
    mutation: StoredMutation,
) -> Result<SubmissionReceipt, StorageError> {
    let stored = load_plan(session, &mutation.identity)?.ok_or_else(integrity)?;
    let command = SubmitBatch::new(mutation.mutation_id, stored.plan);
    let disposition = if mutation.disposition == "created" {
        BatchSubmitDisposition::Created
    } else if mutation.disposition == "replayed" {
        BatchSubmitDisposition::Replayed
    } else {
        return Err(integrity());
    };
    SubmissionReceipt::new(&command, disposition, mutation.status).map_err(|_| integrity())
}

pub(super) fn reconstruct_claim(
    session: &mut LocalSession,
    mutation: StoredMutation,
) -> Result<ClaimReceipt, StorageError> {
    let stored = load_plan(session, &mutation.identity)?.ok_or_else(integrity)?;
    let revision = BatchRevision::new(mutation.claim_revision.ok_or_else(integrity)?);
    let assignments = load_claim_assignments(session, &mutation, &stored.plan)?;
    let request = reconstruct_claim_request(&mutation, assignments.len())?;
    let claim =
        BatchClaim::new(&request, &stored.plan, revision, assignments).map_err(|_| integrity())?;
    ClaimReceipt::new(mutation.mutation_id, claim, mutation.status).map_err(|_| integrity())
}

pub(super) fn reconstruct_claim_request(
    mutation: &StoredMutation,
    assignment_count: usize,
) -> Result<ClaimBatchItems, StorageError> {
    let claim_id = stored_claim_id(mutation.claim_id.as_deref())?;
    let limit = reconstructed_claim_limit(assignment_count)?;
    let revision = mutation.claim_revision.ok_or_else(integrity)?;
    let previous = revision.checked_sub(1).ok_or_else(integrity)?;
    let observed_at = mutation.observed_at.ok_or_else(integrity)?;
    let expires_at = mutation.lease_expires_at.ok_or_else(integrity)?;
    ClaimBatchItems::new(
        mutation.mutation_id.clone(),
        mutation.identity.clone(),
        BatchRevision::new(previous),
        claim_id,
        UtcSeconds::new(observed_at),
        UtcSeconds::new(expires_at),
        limit,
    )
    .map_err(|_| integrity())
}

pub(super) fn stored_claim_id(value: Option<&str>) -> Result<ClaimId, StorageError> {
    ClaimId::parse(value.ok_or_else(integrity)?).map_err(|_| integrity())
}

pub(super) fn reconstructed_claim_limit(count: usize) -> Result<BatchClaimLimit, StorageError> {
    let count = u16::try_from(count.max(1)).map_err(|_| exhausted())?;
    BatchClaimLimit::new(count).map_err(|_| integrity())
}

pub(super) fn load_claim_assignments(
    session: &mut LocalSession,
    mutation: &StoredMutation,
    plan: &BatchPlan,
) -> Result<Vec<ClaimAssignment>, StorageError> {
    let query = format!(
        "SELECT item_ordinal, attempt FROM account_batch_claim_assignments WHERE tenant_id = {} AND mutation_id = {} AND operation_id = {} AND batch_id = {} ORDER BY item_ordinal LIMIT {};",
        sql::text(mutation.identity.tenant_id().as_str()),
        sql::text(mutation.mutation_id.as_str()),
        sql::text(mutation.identity.operation_id().as_str()),
        sql::text(mutation.identity.batch_id().as_str()),
        ariadnion_account_batch::MAX_CLAIM_ITEMS as usize + 1
    );
    let batch = rows(sql::execute(session, query)?)?;
    if batch.rows().len() > usize::from(ariadnion_account_batch::MAX_CLAIM_ITEMS) {
        return Err(integrity());
    }
    batch
        .rows()
        .iter()
        .map(|row| decode_claim_assignment(row, plan))
        .collect()
}

pub(super) fn decode_claim_assignment(
    row: &Row,
    plan: &BatchPlan,
) -> Result<ClaimAssignment, StorageError> {
    let values = row.values();
    if values.len() != 2 {
        return Err(integrity());
    }
    let ordinal = BatchItemOrdinal::new(i64_u32(&values[0])?).map_err(|_| integrity())?;
    let item = plan
        .submission()
        .items()
        .get(ordinal.get() as usize)
        .cloned()
        .ok_or_else(integrity)?;
    let attempt = BatchAttempt::new(i64_u8(&values[1])?).map_err(|_| integrity())?;
    Ok(ClaimAssignment::new(ordinal, item, attempt))
}

pub(super) fn reconstruct_completion(
    session: &mut LocalSession,
    mutation: StoredMutation,
) -> Result<ItemCompletionReceipt, StorageError> {
    let item = load_completed_mutation_item(session, &mutation)?;
    let claim_revision = BatchRevision::new(item.claim_revision.ok_or_else(integrity)?);
    let outcome = reconstruct_outcome(session, &mutation.identity, &item)?;
    let evidence = completion_evidence(claim_revision, mutation.status.revision())?;
    ItemCompletionReceipt::new_with_revision_evidence(
        mutation.mutation_id,
        outcome,
        mutation.status,
        evidence,
    )
    .map_err(|_| integrity())
}

pub(super) fn load_completed_mutation_item(
    session: &mut LocalSession,
    mutation: &StoredMutation,
) -> Result<StoredItem, StorageError> {
    let ordinal = BatchItemOrdinal::new(mutation.completion_ordinal.ok_or_else(integrity)?)
        .map_err(|_| integrity())?;
    let item = load_item(session, &mutation.identity, ordinal)?.ok_or_else(integrity)?;
    if item.completion_mutation_id.as_deref() != Some(mutation.mutation_id.as_str()) {
        return Err(integrity());
    }
    Ok(item)
}

pub(super) fn reconstruct_transition(
    _session: &mut LocalSession,
    mutation: StoredMutation,
) -> Result<TransitionReceipt, StorageError> {
    let transition = decode_transition(&mutation.disposition)?;
    let command = TransitionBatch::new(
        mutation.mutation_id,
        mutation.identity,
        BatchRevision::new(mutation.claim_revision.ok_or_else(integrity)?),
        UtcSeconds::new(mutation.observed_at.ok_or_else(integrity)?),
        transition,
    );
    TransitionReceipt::new_with_committed_at(
        &command,
        mutation.status,
        UtcSeconds::new(mutation.committed_at),
    )
    .map_err(|_| integrity())
}

pub(super) fn reconstruct_outcome(
    session: &mut LocalSession,
    identity: &BatchIdentity,
    item: &StoredItem,
) -> Result<BatchItemOutcome, StorageError> {
    let stored = load_plan(session, identity)?.ok_or_else(integrity)?;
    let mutation = load_item_claim_mutation(session, identity, item)?;
    let assignment = load_item_claim_assignment(session, &mutation, &stored.plan, item)?;
    let claimed = reconstruct_claimed_outcome_item(&stored.plan, item, assignment, &mutation)?;
    let result = decode_outcome_result(item, claimed.command())?;
    BatchItemOutcome::new(
        claimed,
        result,
        UtcSeconds::new(item.outcome_committed_at.ok_or_else(integrity)?),
    )
    .map_err(|_| integrity())
}

pub(super) fn load_item_claim_assignment(
    session: &mut LocalSession,
    mutation: &StoredMutation,
    plan: &BatchPlan,
    item: &StoredItem,
) -> Result<ClaimAssignment, StorageError> {
    let query = format!(
        "SELECT item_ordinal, attempt FROM account_batch_claim_assignments WHERE tenant_id = {} AND mutation_id = {} AND operation_id = {} AND batch_id = {} AND item_ordinal = {} LIMIT 2;",
        sql::text(mutation.identity.tenant_id().as_str()),
        sql::text(mutation.mutation_id.as_str()),
        sql::text(mutation.identity.operation_id().as_str()),
        sql::text(mutation.identity.batch_id().as_str()),
        item.ordinal.get()
    );
    let batch = rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [row] => decode_claim_assignment(row, plan),
        _ => Err(integrity()),
    }
}

pub(super) fn load_item_claim_mutation(
    session: &mut LocalSession,
    identity: &BatchIdentity,
    item: &StoredItem,
) -> Result<StoredMutation, StorageError> {
    let claim_id = item.claim_id.as_deref().ok_or_else(integrity)?;
    let revision = item.claim_revision.ok_or_else(integrity)?;
    let query = format!(
        "SELECT {MUTATION_PROJECTION} FROM account_batch_mutations WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} AND mutation_kind = 'claim' AND claim_id = {} AND claim_revision = {} LIMIT 2;",
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str()),
        sql::text(claim_id),
        sql::text(&revision.to_string())
    );
    let batch = rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [row] => decode_mutation(row),
        _ => Err(integrity()),
    }
}

pub(super) fn reconstruct_claimed_outcome_item(
    plan: &BatchPlan,
    item: &StoredItem,
    assignment: ClaimAssignment,
    mutation: &StoredMutation,
) -> Result<ariadnion_account_batch::ClaimedBatchItem, StorageError> {
    let claim_revision = BatchRevision::new(mutation.claim_revision.ok_or_else(integrity)?);
    let request = reconstruct_claim_request(mutation, 1)?;
    let claim = BatchClaim::new(&request, plan, claim_revision, vec![assignment])
        .map_err(|_| integrity())?;
    let claimed = claim.items().first().cloned().ok_or_else(integrity)?;
    if claimed_matches_item(&claimed, item) {
        Ok(claimed)
    } else {
        Err(integrity())
    }
}

fn claimed_matches_item(
    claimed: &ariadnion_account_batch::ClaimedBatchItem,
    item: &StoredItem,
) -> bool {
    claimed.ordinal() == item.ordinal
        && claimed.item_id() == item.item.id()
        && claimed.account_id() == item.item.account_id()
        && claimed.command() == item.item.command()
        && claimed.attempt().get() == item.attempt
}

pub(super) fn decode_outcome_result(
    item: &StoredItem,
    command: AccountTransitionCommand,
) -> Result<BatchItemResult, StorageError> {
    match item.outcome_kind.as_deref() {
        Some("rejected") => Ok(BatchItemResult::Rejected(decode_failure(
            item.outcome_failure.as_deref().ok_or_else(integrity)?,
        )?)),
        Some(kind @ ("applied" | "would_apply")) => decode_successful_outcome(item, command, kind),
        _ => Err(integrity()),
    }
}

pub(super) fn decode_successful_outcome(
    item: &StoredItem,
    command: AccountTransitionCommand,
    kind: &str,
) -> Result<BatchItemResult, StorageError> {
    let version = preceding_outcome_version(item)?;
    let from = decode_account_status(item.outcome_from.as_deref().ok_or_else(integrity)?)?;
    let change = apply_account_lifecycle(item.item.account_id(), version, from, command)
        .map_err(|_| integrity())?;
    validate_outcome_event(item, change.event())?;
    let intent = if kind == "applied" {
        BatchIntent::Execute
    } else {
        BatchIntent::DryRun
    };
    Ok(successful_item_result(change, intent))
}

pub(super) fn preceding_outcome_version(item: &StoredItem) -> Result<AccountVersion, StorageError> {
    let version = item.outcome_version.ok_or_else(integrity)?;
    let previous = version.checked_sub(1).ok_or_else(integrity)?;
    AccountVersion::new(previous).map_err(|_| integrity())
}

pub(super) fn validate_outcome_event(
    item: &StoredItem,
    event: &ariadnion_account_domain::AccountLifecycleEvent,
) -> Result<(), StorageError> {
    let matches = item.outcome_from.as_deref() == Some(status_label(event.from()))
        && item.outcome_to.as_deref() == Some(status_label(event.to()))
        && item.outcome_version == Some(event.version().get());
    if matches { Ok(()) } else { Err(integrity()) }
}

pub(super) fn list_outcomes(
    session: &mut LocalSession,
    request: &OutcomePageRequest,
) -> Result<OutcomePage, StorageError> {
    validate_outcome_page(session, request)?;
    let limit = usize::from(request.limit().get().get()) + 1;
    let batch = rows(sql::execute(session, outcome_page_query(request, limit))?)?;
    let has_more = batch.rows().len() == limit;
    let outcomes = decode_outcome_page(session, request, &batch)?;
    OutcomePage::new(request, outcomes, has_more).map_err(|_| integrity())
}

pub(super) fn validate_outcome_page(
    session: &mut LocalSession,
    request: &OutcomePageRequest,
) -> Result<(), StorageError> {
    let stored = required_plan(session, request.identity())?;
    require_revision(&stored.status, request.expected_revision())?;
    if stored.status.total_items() != request.total_items() {
        return Err(conflict());
    }
    Ok(())
}

pub(super) fn outcome_page_query(request: &OutcomePageRequest, limit: usize) -> String {
    let after = request
        .after()
        .map(|cursor| cursor.ordinal().get())
        .map_or(String::new(), |value| {
            format!(" AND item_ordinal > {value}")
        });
    format!(
        "SELECT {ITEM_PROJECTION} FROM account_batch_items WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} AND item_state = 'completed'{} ORDER BY item_ordinal LIMIT {};",
        sql::text(request.identity().tenant_id().as_str()),
        sql::text(request.identity().operation_id().as_str()),
        sql::text(request.identity().batch_id().as_str()),
        after,
        limit
    )
}

pub(super) fn decode_outcome_page(
    session: &mut LocalSession,
    request: &OutcomePageRequest,
    batch: &VectorBatch,
) -> Result<Vec<BatchItemOutcome>, StorageError> {
    let take = usize::from(request.limit().get().get());
    let mut outcomes = Vec::with_capacity(take);
    for row in batch.rows().iter().take(take) {
        outcomes.push(reconstruct_outcome(
            session,
            request.identity(),
            &decode_item(row)?,
        )?);
    }
    Ok(outcomes)
}

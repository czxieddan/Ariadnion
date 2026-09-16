// crates/optional/ariadnion-storage-rnmdb/src/account_batch_repository/persistence.rs - Rust source for Ariadnion.
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
//! Bounded account-batch storage projections and atomic row mutations.

use super::codec::*;
use super::*;

#[derive(Clone)]
pub(super) struct StoredPlan {
    pub(super) plan: BatchPlan,
    pub(super) status: BatchStatus,
    pub(super) digest: String,
}

#[derive(Clone)]
pub(super) struct StoredItem {
    pub(super) ordinal: BatchItemOrdinal,
    pub(super) item: BatchItem,
    pub(super) attempt: u8,
    pub(super) state: String,
    pub(super) claim_id: Option<String>,
    pub(super) claim_revision: Option<u64>,
    pub(super) lease_expires_at: Option<u64>,
    pub(super) completion_mutation_id: Option<String>,
    pub(super) outcome_kind: Option<String>,
    pub(super) outcome_failure: Option<String>,
    pub(super) outcome_from: Option<String>,
    pub(super) outcome_to: Option<String>,
    pub(super) outcome_version: Option<u64>,
    pub(super) outcome_committed_at: Option<u64>,
}

#[derive(Clone)]
pub(super) struct StoredMutation {
    pub(super) mutation_id: MutationId,
    pub(super) kind: BatchMutationKind,
    pub(super) digest: String,
    pub(super) identity: BatchIdentity,
    pub(super) disposition: String,
    pub(super) claim_id: Option<String>,
    pub(super) claim_revision: Option<u64>,
    pub(super) lease_expires_at: Option<u64>,
    pub(super) completion_ordinal: Option<u32>,
    pub(super) observed_at: Option<u64>,
    pub(super) committed_at: u64,
    pub(super) status: BatchStatus,
}

pub(super) fn load_plan(
    session: &mut LocalSession,
    identity: &BatchIdentity,
) -> Result<Option<StoredPlan>, StorageError> {
    let query = format!(
        "SELECT {PLAN_PROJECTION} FROM account_batch_plans WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} LIMIT 2;",
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str())
    );
    decode_plan_query(session, query)
}

pub(super) fn required_plan(
    session: &mut LocalSession,
    identity: &BatchIdentity,
) -> Result<StoredPlan, StorageError> {
    load_plan(session, identity)?.ok_or_else(not_found)
}

pub(super) fn load_plan_by_idempotency(
    session: &mut LocalSession,
    plan: &BatchPlan,
) -> Result<Option<StoredPlan>, StorageError> {
    let submission = plan.submission();
    let query = format!(
        "SELECT {PLAN_PROJECTION} FROM account_batch_plans WHERE tenant_id = {} AND idempotency_key = {} LIMIT 2;",
        sql::text(submission.tenant_id().as_str()),
        sql::text(submission.idempotency_key().as_str())
    );
    decode_plan_query(session, query)
}

pub(super) fn decode_plan_query(
    session: &mut LocalSession,
    query: String,
) -> Result<Option<StoredPlan>, StorageError> {
    let batch = rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_plan_row(session, row).map(Some),
        _ => Err(integrity()),
    }
}

pub(super) fn decode_plan_row(
    session: &mut LocalSession,
    row: &Row,
) -> Result<StoredPlan, StorageError> {
    let values = row.values();
    if values.len() != 17 {
        return Err(integrity());
    }
    let (identity, operation, batch) = decode_plan_identity(values)?;
    let items = load_plan_items(session, &identity)?;
    let submission = decode_submission(values, identity.tenant_id().clone(), items)?;
    let plan = BatchPlan::new(operation, batch, submission);
    let status = decode_plan_status(values, identity)?;
    Ok(StoredPlan {
        plan,
        status,
        digest: text_value(&values[4])?.to_owned(),
    })
}

pub(super) fn decode_plan_identity(
    values: &[SqlValue],
) -> Result<(BatchIdentity, OperationId, ariadnion_account_batch::BatchId), StorageError> {
    let tenant = TenantId::parse(text_value(&values[0])?).map_err(|_| integrity())?;
    let operation = OperationId::parse(text_value(&values[1])?).map_err(|_| integrity())?;
    let batch = ariadnion_account_batch::BatchId::parse(text_value(&values[2])?)
        .map_err(|_| integrity())?;
    let identity = BatchIdentity::new(tenant, operation.clone(), batch.clone());
    Ok((identity, operation, batch))
}

pub(super) fn decode_submission(
    values: &[SqlValue],
    tenant: TenantId,
    items: Vec<BatchItem>,
) -> Result<BatchSubmission, StorageError> {
    let resources = decode_resources(values)?;
    let key = IdempotencyKey::parse(text_value(&values[3])?).map_err(|_| integrity())?;
    let intent = decode_intent(text_value(&values[5])?)?;
    let created_at = UtcSeconds::new(i64_u64(&values[6])?);
    let deadline = UtcSeconds::new(i64_u64(&values[7])?);
    BatchSubmission::new(tenant, key, intent, created_at, deadline, resources, items)
        .map_err(|_| integrity())
}

pub(super) fn decode_resources(values: &[SqlValue]) -> Result<BatchResourceLimits, StorageError> {
    BatchResourceLimits::new(
        i64_u16(&values[8])?,
        i64_u16(&values[9])?,
        i64_u8(&values[10])?,
    )
    .map_err(|_| integrity())
}

pub(super) fn decode_plan_status(
    values: &[SqlValue],
    identity: BatchIdentity,
) -> Result<BatchStatus, StorageError> {
    let lifecycle = decode_lifecycle(text_value(&values[11])?, optional_text(&values[12])?)?;
    let revision = BatchRevision::new(parse_u64_text(&values[13])?);
    let total = i64_u32(&values[14])?;
    let completed = i64_u32(&values[15])?;
    let failed = i64_u32(&values[16])?;
    decode_status(identity, lifecycle, revision, total, completed, failed)
}

pub(super) fn load_plan_items(
    session: &mut LocalSession,
    identity: &BatchIdentity,
) -> Result<Vec<BatchItem>, StorageError> {
    load_items(session, identity)?
        .into_iter()
        .map(|value| Ok(value.item))
        .collect()
}

pub(super) fn load_items(
    session: &mut LocalSession,
    identity: &BatchIdentity,
) -> Result<Vec<StoredItem>, StorageError> {
    let query = format!(
        "SELECT {ITEM_PROJECTION} FROM account_batch_items WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} ORDER BY item_ordinal LIMIT {};",
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str()),
        ariadnion_account_batch::MAX_BATCH_ITEMS + 1
    );
    let batch = rows(sql::execute(session, query)?)?;
    if batch.rows().len() > ariadnion_account_batch::MAX_BATCH_ITEMS {
        return Err(exhausted());
    }
    batch.rows().iter().map(decode_item).collect()
}

pub(super) fn load_item(
    session: &mut LocalSession,
    identity: &BatchIdentity,
    ordinal: BatchItemOrdinal,
) -> Result<Option<StoredItem>, StorageError> {
    let query = format!(
        "SELECT {ITEM_PROJECTION} FROM account_batch_items WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} AND item_ordinal = {} LIMIT 2;",
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str()),
        ordinal.get()
    );
    let batch = rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_item(row).map(Some),
        _ => Err(integrity()),
    }
}

pub(super) fn required_item(
    session: &mut LocalSession,
    identity: &BatchIdentity,
    ordinal: BatchItemOrdinal,
) -> Result<StoredItem, StorageError> {
    load_item(session, identity, ordinal)?.ok_or_else(not_found)
}

pub(super) fn decode_item(row: &Row) -> Result<StoredItem, StorageError> {
    let values = row.values();
    if values.len() != 20 {
        return Err(integrity());
    }
    let (ordinal, item) = decode_item_identity(values)?;
    let claim = decode_stored_claim(values)?;
    let outcome = decode_stored_outcome(values)?;
    Ok(StoredItem {
        ordinal,
        item,
        attempt: claim.attempt,
        state: claim.state,
        claim_id: claim.claim_id,
        claim_revision: claim.claim_revision,
        lease_expires_at: claim.lease_expires_at,
        completion_mutation_id: outcome.completion_mutation_id,
        outcome_kind: outcome.kind,
        outcome_failure: outcome.failure,
        outcome_from: outcome.from,
        outcome_to: outcome.to,
        outcome_version: outcome.version,
        outcome_committed_at: outcome.committed_at,
    })
}

pub(super) fn decode_item_identity(
    values: &[SqlValue],
) -> Result<(BatchItemOrdinal, BatchItem), StorageError> {
    let ordinal = BatchItemOrdinal::new(i64_u32(&values[3])?).map_err(|_| integrity())?;
    let item = decode_item_definition(values)?;
    Ok((ordinal, item))
}

pub(super) fn decode_item_definition(values: &[SqlValue]) -> Result<BatchItem, StorageError> {
    let id = BatchItemId::parse(text_value(&values[4])?).map_err(|_| integrity())?;
    let account = AccountId::parse(text_value(&values[5])?).map_err(|_| integrity())?;
    let command = decode_item_command(values)?;
    Ok(BatchItem::new(id, account, command))
}

pub(super) fn decode_item_command(
    values: &[SqlValue],
) -> Result<AccountTransitionCommand, StorageError> {
    let version = AccountVersion::new(parse_u64_text(&values[6])?).map_err(|_| integrity())?;
    let action = decode_action(text_value(&values[7])?)?;
    Ok(AccountTransitionCommand::new(version, action))
}

struct StoredClaimFields {
    attempt: u8,
    state: String,
    claim_id: Option<String>,
    claim_revision: Option<u64>,
    lease_expires_at: Option<u64>,
}

fn decode_stored_claim(values: &[SqlValue]) -> Result<StoredClaimFields, StorageError> {
    Ok(StoredClaimFields {
        attempt: i64_u8(&values[8])?,
        state: text_value(&values[9])?.to_owned(),
        claim_id: optional_text(&values[10])?.map(str::to_owned),
        claim_revision: optional_u64_text(&values[11])?,
        lease_expires_at: optional_i64_u64(&values[12])?,
    })
}

struct StoredOutcomeFields {
    completion_mutation_id: Option<String>,
    kind: Option<String>,
    failure: Option<String>,
    from: Option<String>,
    to: Option<String>,
    version: Option<u64>,
    committed_at: Option<u64>,
}

fn decode_stored_outcome(values: &[SqlValue]) -> Result<StoredOutcomeFields, StorageError> {
    let completion_mutation_id = optional_text(&values[13])?.map(str::to_owned);
    let kind = optional_text(&values[14])?.map(str::to_owned);
    let failure = optional_text(&values[15])?.map(str::to_owned);
    let from = optional_text(&values[16])?.map(str::to_owned);
    let to = optional_text(&values[17])?.map(str::to_owned);
    let version = optional_u64_text(&values[18])?;
    let committed_at = optional_i64_u64(&values[19])?;
    Ok(StoredOutcomeFields {
        completion_mutation_id,
        kind,
        failure,
        from,
        to,
        version,
        committed_at,
    })
}

pub(super) fn insert_plan(
    session: &mut LocalSession,
    plan: &BatchPlan,
    digest: &str,
) -> Result<(), StorageError> {
    let submission = plan.submission();
    let identity = plan.identity();
    let statement = format!(
        "INSERT INTO account_batch_plans ({PLAN_PROJECTION}) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, 'planned', NULL, '0', {}, 0, 0);",
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str()),
        sql::text(submission.idempotency_key().as_str()),
        sql::text(digest),
        sql::text(intent_label(submission.intent())),
        submission.created_at().get(),
        submission.deadline().get(),
        submission.resources().max_parallel_items().get(),
        submission.resources().max_claim_items().get(),
        submission.resources().max_item_attempts().get(),
        submission.items().len()
    );
    sql::require_rows(sql::execute(session, statement)?, 1)?;
    for (ordinal, item) in submission.items().iter().enumerate() {
        insert_item(session, &identity, ordinal, item)?;
    }
    Ok(())
}

pub(super) fn insert_item(
    session: &mut LocalSession,
    identity: &BatchIdentity,
    ordinal: usize,
    item: &BatchItem,
) -> Result<(), StorageError> {
    let ordinal = u32::try_from(ordinal).map_err(|_| exhausted())?;
    let statement = format!(
        "INSERT INTO account_batch_items ({ITEM_PROJECTION}) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, 0, 'pending', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);",
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str()),
        ordinal,
        sql::text(item.id().as_str()),
        sql::text(item.account_id().as_str()),
        sql::text(&item.command().expected_version().get().to_string()),
        sql::text(action_label(item.command().action()))
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

pub(super) fn eligible_assignments(
    plan: &BatchPlan,
    items: &[StoredItem],
    command: &ClaimBatchItems,
    observed_at: UtcSeconds,
) -> Result<(Vec<ClaimAssignment>, Vec<BatchItemOrdinal>), StorageError> {
    let capacity = remaining_claim_capacity(plan, items, command, observed_at);
    let mut assignments = Vec::with_capacity(capacity);
    let mut ordinals = Vec::with_capacity(capacity);
    for stored in items {
        if assignments.len() == capacity {
            break;
        }
        if !item_is_eligible(stored, observed_at) {
            continue;
        }
        let attempt = next_item_attempt(stored, plan)?;
        assignments.push(ClaimAssignment::new(
            stored.ordinal,
            stored.item.clone(),
            attempt,
        ));
        ordinals.push(stored.ordinal);
    }
    Ok((assignments, ordinals))
}

fn remaining_claim_capacity(
    plan: &BatchPlan,
    items: &[StoredItem],
    command: &ClaimBatchItems,
    observed_at: UtcSeconds,
) -> usize {
    let live = items
        .iter()
        .filter(|item| item_has_live_claim(item, observed_at))
        .count();
    let available =
        usize::from(plan.submission().resources().max_parallel_items().get()).saturating_sub(live);
    available.min(usize::from(command.limit().get().get()))
}

fn item_has_live_claim(item: &StoredItem, observed_at: UtcSeconds) -> bool {
    item.state == "claimed"
        && item
            .lease_expires_at
            .is_some_and(|expires| expires > observed_at.get())
}

pub(super) fn item_is_eligible(stored: &StoredItem, observed_at: UtcSeconds) -> bool {
    stored.state == "pending"
        || (stored.state == "claimed"
            && stored
                .lease_expires_at
                .is_some_and(|value| value <= observed_at.get()))
}

pub(super) fn next_item_attempt(
    stored: &StoredItem,
    plan: &BatchPlan,
) -> Result<BatchAttempt, StorageError> {
    if stored.attempt == 0 {
        return Ok(BatchAttempt::first());
    }
    BatchAttempt::new(stored.attempt)
        .map_err(|_| integrity())?
        .next(plan.submission().resources().max_item_attempts())
        .map_err(|_| exhausted())
}

pub(super) fn persist_claim(
    session: &mut LocalSession,
    command: &ClaimBatchItems,
    observed_at: UtcSeconds,
    revision: BatchRevision,
    ordinals: &[BatchItemOrdinal],
) -> Result<(), StorageError> {
    for ordinal in ordinals {
        let statement = format!(
            "UPDATE account_batch_items SET attempt = attempt + 1, item_state = 'claimed', claim_id = {}, claim_revision = {}, lease_expires_at = {} WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} AND item_ordinal = {} AND (item_state = 'pending' OR (item_state = 'claimed' AND lease_expires_at <= {}));",
            sql::text(command.claim_id().as_str()),
            sql::text(&revision.get().to_string()),
            command.lease_expires_at().get(),
            sql::text(command.identity().tenant_id().as_str()),
            sql::text(command.identity().operation_id().as_str()),
            sql::text(command.identity().batch_id().as_str()),
            ordinal.get(),
            observed_at.get()
        );
        sql::require_rows(sql::execute(session, statement)?, 1)?;
    }
    Ok(())
}

pub(super) fn validate_claimed_item(
    command: &CompleteClaimedItem,
    plan: &BatchPlan,
    stored: &StoredItem,
    observed_at: UtcSeconds,
) -> Result<(), StorageError> {
    let claimed = command.claimed_item();
    let valid = claimed_definition_matches(command, plan, stored)
        && claimed_lease_matches(command, stored)
        && observed_at < claimed.lease_expires_at()
        && observed_at < claimed.deadline();
    if valid {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorCode::Conflict))
    }
}

pub(super) fn claimed_definition_matches(
    command: &CompleteClaimedItem,
    plan: &BatchPlan,
    stored: &StoredItem,
) -> bool {
    let claimed = command.claimed_item();
    let planned = plan
        .submission()
        .items()
        .get(claimed.ordinal().get() as usize);
    planned == Some(&stored.item)
        && stored.item.id() == claimed.item_id()
        && stored.item.account_id() == claimed.account_id()
        && stored.item.command() == claimed.command()
        && plan.submission().intent() == claimed.intent()
        && plan.submission().deadline() == claimed.deadline()
}

pub(super) fn claimed_lease_matches(command: &CompleteClaimedItem, stored: &StoredItem) -> bool {
    let claimed = command.claimed_item();
    stored.state == "claimed"
        && stored.attempt == claimed.attempt().get()
        && stored.claim_id.as_deref() == Some(claimed.claim_id().as_str())
        && stored.claim_revision == Some(claimed.claim_revision().get())
        && stored.lease_expires_at == Some(claimed.lease_expires_at().get())
}

pub(super) fn persist_outcome(
    session: &mut LocalSession,
    command: &CompleteClaimedItem,
    outcome: &BatchItemOutcome,
) -> Result<(), StorageError> {
    let (kind, failure, from, to, version) = outcome_fields(outcome.result());
    let identity = command.claimed_item().identity();
    let statement = format!(
        "UPDATE account_batch_items SET item_state = 'completed', completion_mutation_id = {}, outcome_kind = {}, outcome_failure = {}, outcome_from = {}, outcome_to = {}, outcome_version = {}, outcome_committed_at = {} WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} AND item_ordinal = {} AND item_state = 'claimed' AND claim_id = {} AND attempt = {};",
        sql::text(command.mutation_id().as_str()),
        sql::text(kind),
        sql::null_or_text(failure),
        sql::null_or_text(from),
        sql::null_or_text(to),
        sql::null_or_text(version.as_deref()),
        outcome.committed_at().get(),
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str()),
        outcome.ordinal().get(),
        sql::text(outcome.claim_id().as_str()),
        outcome.attempt().get()
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

pub(super) fn outcome_fields(
    result: &BatchItemResult,
) -> (
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
    Option<String>,
) {
    match result {
        BatchItemResult::WouldApply { event } => (
            "would_apply",
            None,
            Some(status_label(event.from())),
            Some(status_label(event.to())),
            Some(event.version().get().to_string()),
        ),
        BatchItemResult::Applied { event } => (
            "applied",
            None,
            Some(status_label(event.from())),
            Some(status_label(event.to())),
            Some(event.version().get().to_string()),
        ),
        BatchItemResult::Rejected(code) => {
            ("rejected", Some(failure_label(*code)), None, None, None)
        }
    }
}

pub(super) fn update_status(
    session: &mut LocalSession,
    previous: &BatchStatus,
    next: &BatchStatus,
) -> Result<(), StorageError> {
    let (lifecycle, terminal) = lifecycle_fields(next.lifecycle());
    let identity = next.identity();
    let statement = format!(
        "UPDATE account_batch_plans SET lifecycle = {}, terminal_state = {}, revision = {}, completed_items = {}, failed_items = {} WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} AND revision = {};",
        sql::text(lifecycle),
        sql::null_or_text(terminal),
        sql::text(&next.revision().get().to_string()),
        next.completed_items(),
        next.failed_items(),
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str()),
        sql::text(&previous.revision().get().to_string())
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

pub(super) fn count_live_claims(
    session: &mut LocalSession,
    identity: &BatchIdentity,
    observed_at: UtcSeconds,
) -> Result<u32, StorageError> {
    let query = format!(
        "SELECT item_ordinal FROM account_batch_items WHERE tenant_id = {} AND operation_id = {} AND batch_id = {} AND item_state = 'claimed' AND lease_expires_at > {} LIMIT {};",
        sql::text(identity.tenant_id().as_str()),
        sql::text(identity.operation_id().as_str()),
        sql::text(identity.batch_id().as_str()),
        observed_at.get(),
        ariadnion_account_batch::MAX_CLAIM_ITEMS as usize + 1
    );
    let batch = rows(sql::execute(session, query)?)?;
    u32::try_from(batch.rows().len()).map_err(|_| exhausted())
}

#[derive(Clone)]
pub(super) struct StoredAccountLifecycle {
    pub(super) id: AccountId,
    pub(super) version: AccountVersion,
    pub(super) status: AccountStatus,
}

impl StoredAccountLifecycle {
    pub(super) fn apply(
        &self,
        command: AccountTransitionCommand,
    ) -> Result<AccountLifecycleChange, ariadnion_account_domain::AccountDomainError> {
        apply_account_lifecycle(&self.id, self.version, self.status, command)
    }
}

pub(super) fn map_account_lifecycle_error(
    error: ariadnion_account_domain::AccountDomainError,
) -> StorageError {
    match error.code() {
        AccountDomainErrorCode::VersionConflict
        | AccountDomainErrorCode::InvalidTransition
        | AccountDomainErrorCode::DeletedTerminal => conflict(),
        _ => integrity(),
    }
}

pub(super) fn load_account_lifecycle(
    session: &mut LocalSession,
    tenant: &TenantId,
    account: &AccountId,
) -> Result<Option<StoredAccountLifecycle>, StorageError> {
    let query = format!(
        "SELECT {ACCOUNT_LIFECYCLE_PROJECTION} FROM account_registry_accounts WHERE tenant_id = {} AND account_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(account.as_str())
    );
    let batch = rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_account_lifecycle(row).map(Some),
        _ => Err(integrity()),
    }
}

pub(super) fn decode_account_lifecycle(row: &Row) -> Result<StoredAccountLifecycle, StorageError> {
    let value = row.values();
    if value.len() != 3 {
        return Err(integrity());
    }
    let id = decode_account_id(&value[0])?;
    let version = decode_account_version(&value[1])?;
    let status = decode_account_status(text_value(&value[2])?)?;
    Ok(StoredAccountLifecycle {
        id,
        version,
        status,
    })
}

pub(super) fn decode_account_id(value: &SqlValue) -> Result<AccountId, StorageError> {
    AccountId::parse(text_value(value)?).map_err(|_| integrity())
}

pub(super) fn decode_account_version(value: &SqlValue) -> Result<AccountVersion, StorageError> {
    AccountVersion::new(parse_u64_text(value)?).map_err(|_| integrity())
}

pub(super) fn persist_account_transition(
    session: &mut LocalSession,
    change: &AccountLifecycleChange,
    event: &ariadnion_account_domain::AccountLifecycleEvent,
    command: &CompleteClaimedItem,
    committed_at: UtcSeconds,
) -> Result<(), StorageError> {
    let statement = format!(
        "UPDATE account_registry_accounts SET account_version = {}, account_status = {} WHERE tenant_id = {} AND account_id = {} AND account_version = {};",
        sql::text(&change.version().get().to_string()),
        sql::text(status_label(change.status())),
        sql::text(command.claimed_item().identity().tenant_id().as_str()),
        sql::text(command.claimed_item().account_id().as_str()),
        sql::text(
            &command
                .claimed_item()
                .command()
                .expected_version()
                .get()
                .to_string()
        )
    );
    sql::require_rows(sql::execute(session, statement)?, 1)?;
    let source = format!(
        "{}:{}:{}",
        command.claimed_item().identity().operation_id().as_str(),
        command.claimed_item().identity().batch_id().as_str(),
        command.claimed_item().ordinal().get()
    );
    let event_insert = format!(
        "INSERT INTO account_lifecycle_events (tenant_id, account_id, account_version, from_status, to_status, source_kind, source_id, committed_at) VALUES ({}, {}, {}, {}, {}, 'account_batch', {}, {});",
        sql::text(command.claimed_item().identity().tenant_id().as_str()),
        sql::text(command.claimed_item().account_id().as_str()),
        sql::text(&event.version().get().to_string()),
        sql::text(status_label(event.from())),
        sql::text(status_label(event.to())),
        sql::text(&source),
        committed_at.get()
    );
    sql::require_rows(sql::execute(session, event_insert)?, 1)
}

pub(super) fn load_mutation(
    session: &mut LocalSession,
    tenant: &TenantId,
    mutation: &MutationId,
) -> Result<Option<StoredMutation>, StorageError> {
    let query = format!(
        "SELECT {MUTATION_PROJECTION} FROM account_batch_mutations WHERE tenant_id = {} AND mutation_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(mutation.as_str())
    );
    let batch = rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_mutation(row).map(Some),
        _ => Err(integrity()),
    }
}

pub(super) fn decode_mutation(row: &Row) -> Result<StoredMutation, StorageError> {
    let value = row.values();
    if value.len() != 19 {
        return Err(integrity());
    }
    let identity = decode_mutation_identity(value)?;
    let receipt = decode_mutation_receipt_fields(value)?;
    let status = decode_mutation_status(value, identity.clone())?;
    Ok(StoredMutation {
        mutation_id: receipt.mutation_id,
        kind: receipt.kind,
        digest: receipt.digest,
        identity,
        disposition: receipt.disposition,
        claim_id: receipt.claim_id,
        claim_revision: receipt.claim_revision,
        lease_expires_at: receipt.lease_expires_at,
        completion_ordinal: receipt.completion_ordinal,
        observed_at: receipt.observed_at,
        committed_at: receipt.committed_at,
        status,
    })
}

pub(super) fn decode_mutation_identity(value: &[SqlValue]) -> Result<BatchIdentity, StorageError> {
    let tenant = TenantId::parse(text_value(&value[0])?).map_err(|_| integrity())?;
    let operation = OperationId::parse(text_value(&value[4])?).map_err(|_| integrity())?;
    let batch =
        ariadnion_account_batch::BatchId::parse(text_value(&value[5])?).map_err(|_| integrity())?;
    Ok(BatchIdentity::new(tenant, operation, batch))
}

struct MutationReceiptFields {
    mutation_id: MutationId,
    kind: BatchMutationKind,
    digest: String,
    disposition: String,
    claim_id: Option<String>,
    claim_revision: Option<u64>,
    lease_expires_at: Option<u64>,
    completion_ordinal: Option<u32>,
    observed_at: Option<u64>,
    committed_at: u64,
}

fn decode_mutation_receipt_fields(
    value: &[SqlValue],
) -> Result<MutationReceiptFields, StorageError> {
    let identity = decode_mutation_header(value)?;
    let timing = decode_mutation_timing(value)?;
    Ok(MutationReceiptFields {
        mutation_id: identity.0,
        kind: identity.1,
        digest: identity.2,
        disposition: identity.3,
        claim_id: timing.0,
        claim_revision: timing.1,
        lease_expires_at: timing.2,
        completion_ordinal: timing.3,
        observed_at: timing.4,
        committed_at: timing.5,
    })
}

pub(super) fn decode_mutation_header(
    value: &[SqlValue],
) -> Result<(MutationId, BatchMutationKind, String, String), StorageError> {
    let mutation_id = MutationId::parse(text_value(&value[1])?).map_err(|_| integrity())?;
    let kind = decode_mutation_kind(text_value(&value[2])?)?;
    let digest = text_value(&value[3])?.to_owned();
    let disposition = text_value(&value[6])?.to_owned();
    Ok((mutation_id, kind, digest, disposition))
}

type MutationTiming = (
    Option<String>,
    Option<u64>,
    Option<u64>,
    Option<u32>,
    Option<u64>,
    u64,
);

pub(super) fn decode_mutation_timing(value: &[SqlValue]) -> Result<MutationTiming, StorageError> {
    let claim_id = optional_text(&value[7])?.map(str::to_owned);
    let claim_revision = optional_u64_text(&value[8])?;
    let lease_expires_at = optional_i64_u64(&value[9])?;
    let completion_ordinal = optional_i64_u32(&value[10])?;
    let observed_at = optional_i64_u64(&value[11])?;
    let committed_at = i64_u64(&value[12])?;
    Ok((
        claim_id,
        claim_revision,
        lease_expires_at,
        completion_ordinal,
        observed_at,
        committed_at,
    ))
}

pub(super) fn decode_mutation_status(
    value: &[SqlValue],
    identity: BatchIdentity,
) -> Result<BatchStatus, StorageError> {
    let lifecycle = decode_lifecycle(text_value(&value[13])?, optional_text(&value[14])?)?;
    let revision = BatchRevision::new(parse_u64_text(&value[15])?);
    let total = i64_u32(&value[16])?;
    let completed = i64_u32(&value[17])?;
    let failed = i64_u32(&value[18])?;
    decode_status(identity, lifecycle, revision, total, completed, failed)
}

pub(super) fn require_digest(
    mutation: &StoredMutation,
    kind: BatchMutationKind,
    digest: &str,
) -> Result<(), StorageError> {
    if mutation.kind == kind && mutation.digest == digest {
        Ok(())
    } else {
        Err(conflict())
    }
}

pub(super) fn require_revision(
    status: &BatchStatus,
    expected: BatchRevision,
) -> Result<(), StorageError> {
    if status.revision() == expected {
        Ok(())
    } else {
        Err(conflict())
    }
}

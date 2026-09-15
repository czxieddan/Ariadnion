// crates/optional/ariadnion-account-batch/src/execution.rs - Durable batch execution contracts.
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

//! Restart-safe persistence and authoritative execution port contracts.

use crate::{
    BatchAttempt, BatchError, BatchErrorCode, BatchIdentity, BatchIntent, BatchItem, BatchItemId,
    BatchItemOrdinal, BatchLifecycle, BatchPlan, BatchRevision, BatchStatus, BatchTerminalState,
    BatchTransition, ClaimId, MAX_CLAIM_ITEMS, MutationId, RevisionEvidence, UtcSeconds, error,
};
use ariadnion_account_domain::{
    AccountId, AccountLifecycleEvent, AccountStatus, AccountTransitionAction,
    AccountTransitionCommand,
};
use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU16;

/// Maximum lifetime of one durable claim lease in seconds.
pub const MAX_CLAIM_LEASE_SECONDS: u64 = 1 << 12;

/// A mutation-identified request to durably submit an immutable plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitBatch {
    mutation_id: MutationId,
    plan: BatchPlan,
}

impl SubmitBatch {
    /// Creates a plan-submission mutation.
    #[must_use]
    pub const fn new(mutation_id: MutationId, plan: BatchPlan) -> Self {
        Self { mutation_id, plan }
    }

    /// Returns the caller-supplied mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns the immutable plan.
    #[must_use]
    pub const fn plan(&self) -> &BatchPlan {
        &self.plan
    }

    /// Consumes the command and returns the immutable plan.
    #[must_use]
    pub fn into_plan(self) -> BatchPlan {
        self.plan
    }
}

/// Whether durable submission created or reused an existing plan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchSubmitDisposition {
    /// The immutable plan was created by this submission.
    Created,
    /// Existing tenant-scoped idempotent content was returned.
    Replayed,
}

/// Durable receipt for plan submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionReceipt {
    mutation_id: MutationId,
    disposition: BatchSubmitDisposition,
    status: BatchStatus,
}

impl SubmissionReceipt {
    /// Creates a durable plan-submission receipt bound to its command.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::ReceiptMismatch`] when the committed status
    /// describes another plan or an invalid newly created state.
    pub fn new(
        command: &SubmitBatch,
        disposition: BatchSubmitDisposition,
        status: BatchStatus,
    ) -> Result<Self, BatchError> {
        validate_submission_binding(command, &status)?;
        validate_submission_disposition(disposition, &status)?;
        Ok(Self {
            mutation_id: command.mutation_id.clone(),
            disposition,
            status,
        })
    }

    /// Returns the committed mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns whether the plan was created or replayed.
    #[must_use]
    pub const fn disposition(&self) -> BatchSubmitDisposition {
        self.disposition
    }

    /// Returns the durable post-commit status.
    #[must_use]
    pub const fn status(&self) -> &BatchStatus {
        &self.status
    }
}

fn validate_submission_binding(
    command: &SubmitBatch,
    status: &BatchStatus,
) -> Result<(), BatchError> {
    if status.identity() != &command.plan.identity() {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    if status.total_items() as usize != command.plan.submission().items().len() {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

fn validate_submission_disposition(
    disposition: BatchSubmitDisposition,
    status: &BatchStatus,
) -> Result<(), BatchError> {
    if disposition == BatchSubmitDisposition::Created {
        validate_created_submission_status(status)?;
    }
    Ok(())
}

fn validate_created_submission_status(status: &BatchStatus) -> Result<(), BatchError> {
    if status.lifecycle() != BatchLifecycle::Planned {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    if status.revision() != BatchRevision::initial() {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

/// A globally bounded maximum for one durable claim.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BatchClaimLimit(NonZeroU16);

impl BatchClaimLimit {
    /// Creates a non-zero claim limit within the global maximum.
    ///
    /// # Errors
    /// Returns a stable argument or resource-limit error.
    pub fn new(value: u16) -> Result<Self, BatchError> {
        let Some(value) = NonZeroU16::new(value) else {
            return Err(error(BatchErrorCode::InvalidArgument));
        };
        if value.get() > MAX_CLAIM_ITEMS {
            return Err(error(BatchErrorCode::ResourceLimitExceeded));
        }
        Ok(Self(value))
    }

    /// Returns the claim limit.
    #[must_use]
    pub const fn get(self) -> NonZeroU16 {
        self.0
    }
}

/// Mutation-identified request for a deterministic durable item claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimBatchItems {
    mutation_id: MutationId,
    identity: BatchIdentity,
    expected_revision: BatchRevision,
    claim_id: ClaimId,
    observed_at: UtcSeconds,
    lease_expires_at: UtcSeconds,
    limit: BatchClaimLimit,
}

impl ClaimBatchItems {
    /// Creates a bounded claim request with an exclusive lease expiry.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::ClaimExpired`] for an empty lease and
    /// [`BatchErrorCode::ResourceLimitExceeded`] for an excessive lease.
    pub fn new(
        mutation_id: MutationId,
        identity: BatchIdentity,
        expected_revision: BatchRevision,
        claim_id: ClaimId,
        observed_at: UtcSeconds,
        lease_expires_at: UtcSeconds,
        limit: BatchClaimLimit,
    ) -> Result<Self, BatchError> {
        validate_claim_window(observed_at, lease_expires_at)?;
        Ok(Self {
            mutation_id,
            identity,
            expected_revision,
            claim_id,
            observed_at,
            lease_expires_at,
            limit,
        })
    }

    /// Returns the caller-supplied mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns the tenant-scoped durable batch identity.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        &self.identity
    }

    /// Returns the expected optimistic revision.
    #[must_use]
    pub const fn expected_revision(&self) -> BatchRevision {
        self.expected_revision
    }

    /// Returns the new durable claim identity.
    #[must_use]
    pub const fn claim_id(&self) -> &ClaimId {
        &self.claim_id
    }

    /// Returns the adapter-independent UTC observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UtcSeconds {
        self.observed_at
    }

    /// Returns the exclusive claim lease expiry.
    #[must_use]
    pub const fn lease_expires_at(&self) -> UtcSeconds {
        self.lease_expires_at
    }

    /// Returns the bounded claim size.
    #[must_use]
    pub const fn limit(&self) -> BatchClaimLimit {
        self.limit
    }
}

fn validate_claim_window(
    observed_at: UtcSeconds,
    lease_expires_at: UtcSeconds,
) -> Result<(), BatchError> {
    let Some(lifetime) = lease_expires_at.get().checked_sub(observed_at.get()) else {
        return Err(error(BatchErrorCode::ClaimExpired));
    };
    if lifetime == 0 {
        return Err(error(BatchErrorCode::ClaimExpired));
    }
    if lifetime > MAX_CLAIM_LEASE_SECONDS {
        return Err(error(BatchErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

/// Adapter-assigned plan item, ordinal, and attempt before claim sealing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimAssignment {
    ordinal: BatchItemOrdinal,
    item: BatchItem,
    attempt: BatchAttempt,
}

impl ClaimAssignment {
    /// Creates one adapter-assigned claim entry.
    #[must_use]
    pub const fn new(ordinal: BatchItemOrdinal, item: BatchItem, attempt: BatchAttempt) -> Self {
        Self {
            ordinal,
            item,
            attempt,
        }
    }
}

/// Restart-safe evidence for one claimed immutable account command.
#[derive(Clone, Eq, PartialEq)]
pub struct ClaimedBatchItem {
    identity: BatchIdentity,
    claim_id: ClaimId,
    claim_revision: BatchRevision,
    lease_expires_at: UtcSeconds,
    deadline: UtcSeconds,
    intent: BatchIntent,
    ordinal: BatchItemOrdinal,
    item: BatchItem,
    attempt: BatchAttempt,
}

impl ClaimedBatchItem {
    /// Returns the tenant-scoped durable batch identity.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        &self.identity
    }

    /// Returns the durable claim identity.
    #[must_use]
    pub const fn claim_id(&self) -> &ClaimId {
        &self.claim_id
    }

    /// Returns the revision committed with this claim.
    #[must_use]
    pub const fn claim_revision(&self) -> BatchRevision {
        self.claim_revision
    }

    /// Returns the exclusive claim lease expiry.
    #[must_use]
    pub const fn lease_expires_at(&self) -> UtcSeconds {
        self.lease_expires_at
    }

    /// Returns the immutable batch deadline.
    #[must_use]
    pub const fn deadline(&self) -> UtcSeconds {
        self.deadline
    }

    /// Returns dry-run or execute intent from the durable plan.
    #[must_use]
    pub const fn intent(&self) -> BatchIntent {
        self.intent
    }

    /// Returns the immutable plan ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> BatchItemOrdinal {
        self.ordinal
    }

    /// Returns the item identity.
    #[must_use]
    pub const fn item_id(&self) -> &BatchItemId {
        self.item.id()
    }

    /// Returns the target account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        self.item.account_id()
    }

    /// Returns the immutable authoritative account command.
    #[must_use]
    pub const fn command(&self) -> AccountTransitionCommand {
        self.item.command()
    }

    /// Returns the adapter-assigned attempt number.
    #[must_use]
    pub const fn attempt(&self) -> BatchAttempt {
        self.attempt
    }
}

impl Debug for ClaimedBatchItem {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedBatchItem")
            .field("identity", &self.identity)
            .field("claim_id", &self.claim_id)
            .field("claim_revision", &self.claim_revision)
            .field("lease_expires_at", &self.lease_expires_at)
            .field("deadline", &self.deadline)
            .field("intent", &self.intent)
            .field("ordinal", &self.ordinal)
            .field("item", &self.item)
            .field("attempt", &self.attempt)
            .finish()
    }
}

/// Constructor-validated durable claim and its restart evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchClaim {
    identity: BatchIdentity,
    claim_id: ClaimId,
    revision: BatchRevision,
    lease_expires_at: UtcSeconds,
    items: Box<[ClaimedBatchItem]>,
}

impl BatchClaim {
    /// Seals adapter assignments against the immutable durable plan.
    ///
    /// # Errors
    /// Returns a stable error for cross-scoped identities, a lease past the
    /// batch deadline, an oversized claim, duplicate assignments, or an item
    /// whose ordinal and immutable command do not match the plan.
    pub fn new(
        request: &ClaimBatchItems,
        plan: &BatchPlan,
        revision: BatchRevision,
        assignments: Vec<ClaimAssignment>,
    ) -> Result<Self, BatchError> {
        validate_claim_context(request, plan, revision)?;
        validate_assignments(plan, request.limit, &assignments)?;
        let items = assignments
            .into_iter()
            .map(|assignment| claimed_item(request, plan, revision, assignment))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            identity: request.identity.clone(),
            claim_id: request.claim_id.clone(),
            revision,
            lease_expires_at: request.lease_expires_at,
            items,
        })
    }

    /// Returns the tenant-scoped durable batch identity.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        &self.identity
    }

    /// Returns the durable claim identity.
    #[must_use]
    pub const fn claim_id(&self) -> &ClaimId {
        &self.claim_id
    }

    /// Returns the revision committed with this claim.
    #[must_use]
    pub const fn revision(&self) -> BatchRevision {
        self.revision
    }

    /// Returns the exclusive lease expiry.
    #[must_use]
    pub const fn lease_expires_at(&self) -> UtcSeconds {
        self.lease_expires_at
    }

    /// Returns the bounded restart-safe claimed items.
    #[must_use]
    pub const fn items(&self) -> &[ClaimedBatchItem] {
        &self.items
    }
}

fn validate_claim_context(
    request: &ClaimBatchItems,
    plan: &BatchPlan,
    revision: BatchRevision,
) -> Result<(), BatchError> {
    validate_claim_identity(request, plan)?;
    validate_claim_revision(request, revision)?;
    validate_claim_limit(request, plan)?;
    validate_claim_deadline(request, plan)
}

fn validate_claim_identity(request: &ClaimBatchItems, plan: &BatchPlan) -> Result<(), BatchError> {
    if request.identity != plan.identity() {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

fn validate_claim_revision(
    request: &ClaimBatchItems,
    revision: BatchRevision,
) -> Result<(), BatchError> {
    if revision != request.expected_revision.next()? {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

fn validate_claim_limit(request: &ClaimBatchItems, plan: &BatchPlan) -> Result<(), BatchError> {
    if request.limit.get() > plan.submission().resources().max_claim_items() {
        return Err(error(BatchErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

fn validate_claim_deadline(request: &ClaimBatchItems, plan: &BatchPlan) -> Result<(), BatchError> {
    if request.observed_at >= plan.submission().deadline() {
        return Err(error(BatchErrorCode::DeadlineExceeded));
    }
    if request.lease_expires_at > plan.submission().deadline() {
        return Err(error(BatchErrorCode::DeadlineExceeded));
    }
    Ok(())
}

fn validate_assignments(
    plan: &BatchPlan,
    limit: BatchClaimLimit,
    assignments: &[ClaimAssignment],
) -> Result<(), BatchError> {
    if assignments.len() > usize::from(limit.get().get()) {
        return Err(error(BatchErrorCode::ResourceLimitExceeded));
    }
    let mut previous = None;
    for assignment in assignments {
        validate_assignment(plan, assignment)?;
        if previous.is_some_and(|ordinal| assignment.ordinal <= ordinal) {
            return Err(error(BatchErrorCode::ReceiptMismatch));
        }
        previous = Some(assignment.ordinal);
    }
    Ok(())
}

fn validate_assignment(plan: &BatchPlan, assignment: &ClaimAssignment) -> Result<(), BatchError> {
    let planned = plan.submission().items().get(assignment.ordinal.index());
    if planned != Some(&assignment.item) {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    if assignment.attempt.get() > plan.submission().resources().max_item_attempts().get() {
        return Err(error(BatchErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

fn claimed_item(
    request: &ClaimBatchItems,
    plan: &BatchPlan,
    revision: BatchRevision,
    assignment: ClaimAssignment,
) -> ClaimedBatchItem {
    ClaimedBatchItem {
        identity: request.identity.clone(),
        claim_id: request.claim_id.clone(),
        claim_revision: revision,
        lease_expires_at: request.lease_expires_at,
        deadline: plan.submission().deadline(),
        intent: plan.submission().intent(),
        ordinal: assignment.ordinal,
        item: assignment.item,
        attempt: assignment.attempt,
    }
}

/// Durable receipt for one claim mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimReceipt {
    mutation_id: MutationId,
    claim: BatchClaim,
    status: BatchStatus,
}

impl ClaimReceipt {
    /// Creates a claim receipt bound to its post-commit status.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::ReceiptMismatch`] for identity or revision
    /// disagreement.
    pub fn new(
        mutation_id: MutationId,
        claim: BatchClaim,
        status: BatchStatus,
    ) -> Result<Self, BatchError> {
        if claim.identity != status.identity || claim.revision != status.revision {
            return Err(error(BatchErrorCode::ReceiptMismatch));
        }
        if status.lifecycle != BatchLifecycle::Running {
            return Err(error(BatchErrorCode::ReceiptMismatch));
        }
        Ok(Self {
            mutation_id,
            claim,
            status,
        })
    }

    /// Returns the committed mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns the durable claim evidence.
    #[must_use]
    pub const fn claim(&self) -> &BatchClaim {
        &self.claim
    }

    /// Returns the durable post-commit status.
    #[must_use]
    pub const fn status(&self) -> &BatchStatus {
        &self.status
    }
}

/// Mutation-identified request to complete one durable claimed command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteClaimedItem {
    mutation_id: MutationId,
    claimed_item: ClaimedBatchItem,
    observed_at: UtcSeconds,
}

impl CompleteClaimedItem {
    /// Creates a completion request from restart-safe claim evidence.
    ///
    /// The request contains no caller-authored result. The durable adapter must
    /// load the authoritative account and produce the result atomically.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::ClaimExpired`] at the lease or batch deadline.
    pub fn new(
        mutation_id: MutationId,
        claimed_item: ClaimedBatchItem,
        observed_at: UtcSeconds,
    ) -> Result<Self, BatchError> {
        if observed_at >= claimed_item.lease_expires_at || observed_at >= claimed_item.deadline {
            return Err(error(BatchErrorCode::ClaimExpired));
        }
        Ok(Self {
            mutation_id,
            claimed_item,
            observed_at,
        })
    }

    /// Returns the caller-supplied mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns the restart-safe durable claim evidence.
    #[must_use]
    pub const fn claimed_item(&self) -> &ClaimedBatchItem {
        &self.claimed_item
    }

    /// Returns the UTC time used for lease and deadline checks.
    #[must_use]
    pub const fn observed_at(&self) -> UtcSeconds {
        self.observed_at
    }
}

/// Stable reason an individual account item could not proceed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchItemFailureCode {
    /// The target account does not exist in the owning tenant.
    AccountNotFound,
    /// The expected account version is stale.
    VersionConflict,
    /// The lifecycle action is invalid from authoritative account state.
    InvalidTransition,
    /// The administrative principal is not authorized for this item.
    PermissionDenied,
    /// Cancellation stopped the item before a durable effect.
    Cancelled,
    /// The batch deadline stopped the item before a durable effect.
    DeadlineExceeded,
    /// The item exhausted its assigned resource allowance.
    ResourceExhausted,
    /// The required account adapter is unavailable.
    AdapterUnavailable,
}

/// Adapter-produced terminal result for one claimed item.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum BatchItemResult {
    /// A dry run determined that the transition would succeed.
    WouldApply {
        /// Authoritative lifecycle fact execution would persist.
        event: AccountLifecycleEvent,
    },
    /// Execution atomically persisted the account transition and event.
    Applied {
        /// Authoritative lifecycle fact persisted with the account snapshot.
        event: AccountLifecycleEvent,
    },
    /// Authoritative validation or execution rejected the item.
    Rejected(BatchItemFailureCode),
}

/// Durable, reconstructable outcome for one claimed item.
#[derive(Clone, Eq, PartialEq)]
pub struct BatchItemOutcome {
    claimed_item: ClaimedBatchItem,
    result: BatchItemResult,
    committed_at: UtcSeconds,
}

impl BatchItemOutcome {
    /// Creates an adapter-produced terminal outcome.
    ///
    /// This constructor is for durable adapter implementations after they have
    /// validated or applied the authoritative command. Callers cannot submit an
    /// outcome through [`crate::AccountBatchPort`].
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::OutcomeIntentMismatch`] when an applied result
    /// is attached to dry-run evidence or a would-apply result to execute evidence.
    /// Returns [`BatchErrorCode::ReceiptMismatch`] when an event does not match
    /// the claimed account, version, or immutable lifecycle command.
    pub fn new(
        claimed_item: ClaimedBatchItem,
        result: BatchItemResult,
        committed_at: UtcSeconds,
    ) -> Result<Self, BatchError> {
        validate_outcome_intent(claimed_item.intent, &result)?;
        validate_outcome_event(&claimed_item, &result)?;
        Ok(Self {
            claimed_item,
            result,
            committed_at,
        })
    }

    /// Returns the tenant-scoped durable batch identity.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        self.claimed_item.identity()
    }

    /// Returns the durable claim identity.
    #[must_use]
    pub const fn claim_id(&self) -> &ClaimId {
        self.claimed_item.claim_id()
    }

    /// Returns the immutable plan ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> BatchItemOrdinal {
        self.claimed_item.ordinal()
    }

    /// Returns the item identity.
    #[must_use]
    pub const fn item_id(&self) -> &BatchItemId {
        self.claimed_item.item_id()
    }

    /// Returns the target account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        self.claimed_item.account_id()
    }

    /// Returns the immutable authoritative account command.
    #[must_use]
    pub const fn command(&self) -> AccountTransitionCommand {
        self.claimed_item.command()
    }

    /// Returns the adapter-assigned attempt number.
    #[must_use]
    pub const fn attempt(&self) -> BatchAttempt {
        self.claimed_item.attempt()
    }

    /// Returns the adapter-produced terminal result.
    #[must_use]
    pub const fn result(&self) -> &BatchItemResult {
        &self.result
    }

    /// Returns the durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcSeconds {
        self.committed_at
    }
}

impl Debug for BatchItemOutcome {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchItemOutcome")
            .field("claimed_item", &self.claimed_item)
            .field("result", &self.result)
            .field("committed_at", &self.committed_at)
            .finish()
    }
}

fn validate_outcome_intent(
    intent: BatchIntent,
    result: &BatchItemResult,
) -> Result<(), BatchError> {
    let compatible = match result {
        BatchItemResult::WouldApply { .. } => intent == BatchIntent::DryRun,
        BatchItemResult::Applied { .. } => intent == BatchIntent::Execute,
        BatchItemResult::Rejected(_) => true,
    };
    if !compatible {
        return Err(error(BatchErrorCode::OutcomeIntentMismatch));
    }
    Ok(())
}

fn validate_outcome_event(
    claimed_item: &ClaimedBatchItem,
    result: &BatchItemResult,
) -> Result<(), BatchError> {
    let Some(event) = outcome_event(result) else {
        return Ok(());
    };
    validate_event_identity(claimed_item, event)?;
    validate_event_version(claimed_item, event)?;
    validate_event_transition(claimed_item, event)
}

fn outcome_event(result: &BatchItemResult) -> Option<&AccountLifecycleEvent> {
    match result {
        BatchItemResult::WouldApply { event } | BatchItemResult::Applied { event } => Some(event),
        BatchItemResult::Rejected(_) => None,
    }
}

fn validate_event_identity(
    claimed_item: &ClaimedBatchItem,
    event: &AccountLifecycleEvent,
) -> Result<(), BatchError> {
    if event.account_id() != claimed_item.account_id() {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

fn validate_event_version(
    claimed_item: &ClaimedBatchItem,
    event: &AccountLifecycleEvent,
) -> Result<(), BatchError> {
    let expected = claimed_item
        .command()
        .expected_version()
        .get()
        .checked_add(1);
    if expected != Some(event.version().get()) {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

fn validate_event_transition(
    claimed_item: &ClaimedBatchItem,
    event: &AccountLifecycleEvent,
) -> Result<(), BatchError> {
    if !event_matches_action(claimed_item.command().action(), event) {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

fn event_matches_action(action: AccountTransitionAction, event: &AccountLifecycleEvent) -> bool {
    matches!(
        (action, event.from(), event.to()),
        (
            AccountTransitionAction::Activate,
            AccountStatus::Provisioning | AccountStatus::Suspended,
            AccountStatus::Active
        ) | (
            AccountTransitionAction::Suspend,
            AccountStatus::Active,
            AccountStatus::Suspended
        ) | (
            AccountTransitionAction::Resume,
            AccountStatus::Suspended,
            AccountStatus::Active
        ) | (
            AccountTransitionAction::Revoke,
            AccountStatus::Provisioning | AccountStatus::Active | AccountStatus::Suspended,
            AccountStatus::Revoked
        ) | (
            AccountTransitionAction::Delete,
            AccountStatus::Revoked,
            AccountStatus::Deleted
        )
    )
}

/// Durable receipt for authoritative item completion and batch progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemCompletionReceipt {
    mutation_id: MutationId,
    outcome: BatchItemOutcome,
    status: BatchStatus,
}

impl ItemCompletionReceipt {
    /// Creates an atomic item-completion receipt.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::ReceiptMismatch`] when the outcome and status
    /// disagree on batch identity or revision order.
    pub fn new(
        mutation_id: MutationId,
        outcome: BatchItemOutcome,
        status: BatchStatus,
    ) -> Result<Self, BatchError> {
        let evidence =
            RevisionEvidence::new(outcome.claimed_item.claim_revision, status.revision, 0)?;
        Self::new_with_revision_evidence(mutation_id, outcome, status, evidence)
    }

    /// Creates a completion receipt when durable mutations committed after the
    /// claim and before this completion.
    ///
    /// The adapter must obtain `intervening_revisions` from authoritative
    /// durable history. This explicit evidence permits concurrent claim
    /// completions without accepting an unexplained revision jump.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::ReceiptMismatch`] when the outcome and status
    /// disagree on batch identity or the supplied revision evidence.
    pub fn new_with_revision_evidence(
        mutation_id: MutationId,
        outcome: BatchItemOutcome,
        status: BatchStatus,
        evidence: RevisionEvidence,
    ) -> Result<Self, BatchError> {
        if outcome.identity() != status.identity() {
            return Err(error(BatchErrorCode::ReceiptMismatch));
        }
        if evidence.claim_revision() != outcome.claimed_item.claim_revision
            || evidence.resulting_revision() != status.revision
        {
            return Err(error(BatchErrorCode::ReceiptMismatch));
        }
        Ok(Self {
            mutation_id,
            outcome,
            status,
        })
    }

    /// Compatibility constructor that converts a bounded legacy count into
    /// typed revision evidence before validating the receipt.
    pub fn new_with_intervening_revisions(
        mutation_id: MutationId,
        outcome: BatchItemOutcome,
        status: BatchStatus,
        intervening_revisions: u64,
    ) -> Result<Self, BatchError> {
        let count = u32::try_from(intervening_revisions)
            .map_err(|_| error(BatchErrorCode::ResourceLimitExceeded))?;
        let evidence =
            RevisionEvidence::new(outcome.claimed_item.claim_revision, status.revision, count)?;
        Self::new_with_revision_evidence(mutation_id, outcome, status, evidence)
    }

    /// Returns the committed mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns the authoritative terminal item outcome.
    #[must_use]
    pub const fn outcome(&self) -> &BatchItemOutcome {
        &self.outcome
    }

    /// Returns the durable post-commit status.
    #[must_use]
    pub const fn status(&self) -> &BatchStatus {
        &self.status
    }
}

/// Mutation-identified request for one durable lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionBatch {
    mutation_id: MutationId,
    identity: BatchIdentity,
    expected_revision: BatchRevision,
    observed_at: UtcSeconds,
    transition: BatchTransition,
    deadline: Option<UtcSeconds>,
}

impl TransitionBatch {
    /// Creates a typed durable lifecycle command.
    #[must_use]
    pub const fn new(
        mutation_id: MutationId,
        identity: BatchIdentity,
        expected_revision: BatchRevision,
        observed_at: UtcSeconds,
        transition: BatchTransition,
    ) -> Self {
        Self {
            mutation_id,
            identity,
            expected_revision,
            observed_at,
            transition,
            deadline: None,
        }
    }

    /// Creates a lifecycle command bound to the immutable batch deadline.
    #[must_use]
    pub const fn with_deadline(
        mutation_id: MutationId,
        identity: BatchIdentity,
        expected_revision: BatchRevision,
        observed_at: UtcSeconds,
        deadline: UtcSeconds,
        transition: BatchTransition,
    ) -> Self {
        Self {
            mutation_id,
            identity,
            expected_revision,
            observed_at,
            transition,
            deadline: Some(deadline),
        }
    }

    /// Returns the caller-supplied mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns the tenant-scoped durable batch identity.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        &self.identity
    }

    /// Returns the expected optimistic revision.
    #[must_use]
    pub const fn expected_revision(&self) -> BatchRevision {
        self.expected_revision
    }

    /// Returns the adapter-independent UTC observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UtcSeconds {
        self.observed_at
    }

    /// Returns the requested lifecycle mutation.
    #[must_use]
    pub const fn transition(&self) -> BatchTransition {
        self.transition
    }
}

/// Durable receipt for one lifecycle mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionReceipt {
    mutation_id: MutationId,
    status: BatchStatus,
    observed_at: UtcSeconds,
    committed_at: UtcSeconds,
}

impl TransitionReceipt {
    /// Creates a durable lifecycle receipt bound to its command.
    ///
    /// # Errors
    /// Returns a stable revision or receipt mismatch error when the committed
    /// state does not represent the requested transition.
    pub fn new(command: &TransitionBatch, status: BatchStatus) -> Result<Self, BatchError> {
        if let Some(deadline) = command.deadline {
            command
                .transition
                .validate_observed_at(command.observed_at, deadline)?;
        }
        Self::new_with_committed_at(command, status, command.observed_at)
    }

    /// Creates a transition receipt with explicit authoritative commit time.
    pub fn new_with_committed_at(
        command: &TransitionBatch,
        status: BatchStatus,
        committed_at: UtcSeconds,
    ) -> Result<Self, BatchError> {
        validate_transition_identity(command, &status)?;
        validate_transition_revision(command, &status)?;
        validate_transition_lifecycle(command, &status)?;
        Ok(Self {
            mutation_id: command.mutation_id.clone(),
            status,
            observed_at: command.observed_at,
            committed_at,
        })
    }

    /// Returns the committed mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns the durable post-commit status.
    #[must_use]
    pub const fn status(&self) -> &BatchStatus {
        &self.status
    }

    /// Returns the adapter observation time attached to this transition receipt.
    ///
    /// A durable adapter must source this value from its authoritative UTC clock
    /// and retain it with the transition record; it is not a completion-time
    /// claim inferred from the returned lifecycle alone.
    #[must_use]
    pub const fn observed_at(&self) -> UtcSeconds {
        self.observed_at
    }

    /// Returns the authoritative durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcSeconds {
        self.committed_at
    }
}

fn validate_transition_identity(
    command: &TransitionBatch,
    status: &BatchStatus,
) -> Result<(), BatchError> {
    if status.identity() != command.identity() {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

fn validate_transition_revision(
    command: &TransitionBatch,
    status: &BatchStatus,
) -> Result<(), BatchError> {
    if status.revision() != command.expected_revision.next()? {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

fn validate_transition_lifecycle(
    command: &TransitionBatch,
    status: &BatchStatus,
) -> Result<(), BatchError> {
    let compatible = match command.transition {
        BatchTransition::Start => status.lifecycle() == BatchLifecycle::Running,
        BatchTransition::RequestCancellation => matches!(
            status.lifecycle(),
            BatchLifecycle::Cancelling | BatchLifecycle::Terminal(BatchTerminalState::Cancelled)
        ),
        BatchTransition::Expire => {
            status.lifecycle() == BatchLifecycle::Terminal(BatchTerminalState::DeadlineExceeded)
        }
        BatchTransition::Finish(terminal) => {
            status.lifecycle() == BatchLifecycle::Terminal(terminal)
        }
    };
    if !compatible {
        return Err(error(BatchErrorCode::ReceiptMismatch));
    }
    Ok(())
}

/// Exact durable result returned by mutation reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchMutationReceipt {
    /// A durable plan submission result.
    Submitted(SubmissionReceipt),
    /// A durable claim and its restart evidence.
    Claimed(ClaimReceipt),
    /// An atomic authoritative item completion result.
    ItemCompleted(ItemCompletionReceipt),
    /// A durable lifecycle transition result.
    Transitioned(TransitionReceipt),
}

/// Stable kind of mutation represented by a reconciliation receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchMutationKind {
    /// Immutable plan submission.
    Submission,
    /// Durable item claim.
    Claim,
    /// Atomic item completion.
    ItemCompletion,
    /// Lifecycle transition.
    Transition,
}

impl BatchMutationReceipt {
    /// Returns the typed mutation kind carried by this receipt.
    #[must_use]
    pub const fn kind(&self) -> BatchMutationKind {
        match self {
            Self::Submitted(_) => BatchMutationKind::Submission,
            Self::Claimed(_) => BatchMutationKind::Claim,
            Self::ItemCompleted(_) => BatchMutationKind::ItemCompletion,
            Self::Transitioned(_) => BatchMutationKind::Transition,
        }
    }
    /// Returns the committed mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        match self {
            Self::Submitted(receipt) => receipt.mutation_id(),
            Self::Claimed(receipt) => receipt.mutation_id(),
            Self::ItemCompleted(receipt) => receipt.mutation_id(),
            Self::Transitioned(receipt) => receipt.mutation_id(),
        }
    }

    /// Returns the tenant-scoped batch identity.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        match self {
            Self::Submitted(receipt) => receipt.status().identity(),
            Self::Claimed(receipt) => receipt.status().identity(),
            Self::ItemCompleted(receipt) => receipt.status().identity(),
            Self::Transitioned(receipt) => receipt.status().identity(),
        }
    }
}

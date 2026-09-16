// crates/optional/ariadnion-account-batch/src/lib.rs - Account batch contracts for Ariadnion.
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

//! Bounded tenant-scoped administrative account batch contracts.
//!
//! This crate owns immutable, secret-free plans and restart-safe execution
//! contracts. A durable adapter owns authoritative account loading, transition
//! application, event persistence, batch progress, and mutation reconciliation.
//! The domain remains independent from transports, databases, and runtimes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_account_domain::{AccountId, AccountTransitionCommand};
use ariadnion_core::TenantId;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::num::{NonZeroU8, NonZeroU16};

mod execution;
mod lifecycle;
pub mod migrations;
mod paging;
mod port;

pub use execution::{
    BatchClaim, BatchClaimLimit, BatchItemFailureCode, BatchItemOutcome, BatchItemResult,
    BatchMutationKind, BatchMutationReceipt, BatchSubmitDisposition, ClaimAssignment,
    ClaimBatchItems, ClaimReceipt, ClaimedBatchItem, CompleteClaimedItem, ItemCompletionReceipt,
    MAX_CLAIM_LEASE_SECONDS, SubmissionReceipt, SubmitBatch, TransitionBatch, TransitionReceipt,
};
pub use lifecycle::{BatchLifecycle, BatchTerminalState, BatchTransition};
pub use paging::{
    MAX_OUTCOME_PAGE_ITEMS, OutcomeCursor, OutcomePage, OutcomePageLimit, OutcomePageRequest,
};
pub use port::{AccountBatchPort, BatchPortError, BatchPortErrorCode};

/// Maximum number of items accepted by one account batch.
pub const MAX_BATCH_ITEMS: usize = 1 << 17;
/// Maximum lifetime of a batch plan in whole seconds.
pub const MAX_BATCH_LIFETIME_SECONDS: u64 = 86_400;
/// Maximum parallel item executions authorized by a plan.
pub const MAX_PARALLEL_ITEMS: u16 = 1 << 10;
/// Maximum items returned by one durable claim.
pub const MAX_CLAIM_ITEMS: u16 = 1 << 12;
/// Maximum attempts authorized for one item.
pub const MAX_ITEM_ATTEMPTS: u8 = 1 << 3;
const MAX_ID_BYTES: usize = 1 << 7;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1 << 8;
const MAX_MUTATION_ID_BYTES: usize = 1 << 7;
const MAX_CLAIM_ID_BYTES: usize = 1 << 7;

/// Stable machine-readable account-batch failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BatchErrorCode {
    /// An argument is empty, malformed, or outside its basic bound.
    InvalidArgument,
    /// A batch contains no work items.
    EmptyBatch,
    /// A batch exceeds the fixed item-count bound.
    TooManyItems,
    /// A batch item identity occurs more than once.
    DuplicateItem,
    /// An account occurs more than once in one immutable plan.
    DuplicateAccount,
    /// Work was requested at or after its deadline.
    DeadlineExceeded,
    /// The requested plan lifetime exceeds the fixed bound.
    LifetimeExceeded,
    /// A requested resource limit exceeds the fixed bound.
    ResourceLimitExceeded,
    /// An idempotency key was rebound to different content.
    IdempotencyConflict,
    /// A lifecycle transition is not valid from the current state.
    InvalidTransition,
    /// An item outcome is incompatible with dry-run or execute intent.
    OutcomeIntentMismatch,
    /// A revision cannot advance without wrapping.
    RevisionExhausted,
    /// Claimed work is no longer protected by its durable lease.
    ClaimExpired,
    /// Durable lifecycle and progress counters contradict each other.
    InvalidStatus,
    /// A receipt does not match its command, claim, or batch identity.
    ReceiptMismatch,
    /// A durable outcome page is oversized, unordered, or cross-scoped.
    InvalidPage,
}

impl BatchErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument
            | Self::EmptyBatch
            | Self::TooManyItems
            | Self::DuplicateItem
            | Self::DuplicateAccount
            | Self::DeadlineExceeded => validation_error_code(self),
            Self::LifetimeExceeded
            | Self::ResourceLimitExceeded
            | Self::IdempotencyConflict
            | Self::InvalidTransition
            | Self::OutcomeIntentMismatch => operation_error_code(self),
            Self::RevisionExhausted
            | Self::ClaimExpired
            | Self::InvalidStatus
            | Self::ReceiptMismatch
            | Self::InvalidPage => evidence_error_code(self),
        }
    }
}

const fn validation_error_code(code: BatchErrorCode) -> &'static str {
    match code {
        BatchErrorCode::InvalidArgument => "ACCOUNT_BATCH_INVALID_ARGUMENT",
        BatchErrorCode::EmptyBatch => "ACCOUNT_BATCH_EMPTY",
        BatchErrorCode::TooManyItems => "ACCOUNT_BATCH_TOO_MANY_ITEMS",
        BatchErrorCode::DuplicateItem => "ACCOUNT_BATCH_DUPLICATE_ITEM",
        BatchErrorCode::DuplicateAccount => "ACCOUNT_BATCH_DUPLICATE_ACCOUNT",
        BatchErrorCode::DeadlineExceeded => "ACCOUNT_BATCH_DEADLINE_EXCEEDED",
        _ => "ACCOUNT_BATCH_INVALID_ARGUMENT",
    }
}

const fn operation_error_code(code: BatchErrorCode) -> &'static str {
    match code {
        BatchErrorCode::LifetimeExceeded => "ACCOUNT_BATCH_LIFETIME_EXCEEDED",
        BatchErrorCode::ResourceLimitExceeded => "ACCOUNT_BATCH_RESOURCE_LIMIT_EXCEEDED",
        BatchErrorCode::IdempotencyConflict => "ACCOUNT_BATCH_IDEMPOTENCY_CONFLICT",
        BatchErrorCode::InvalidTransition => "ACCOUNT_BATCH_INVALID_TRANSITION",
        BatchErrorCode::OutcomeIntentMismatch => "ACCOUNT_BATCH_OUTCOME_INTENT_MISMATCH",
        _ => "ACCOUNT_BATCH_INVALID_ARGUMENT",
    }
}

const fn evidence_error_code(code: BatchErrorCode) -> &'static str {
    match code {
        BatchErrorCode::RevisionExhausted => "ACCOUNT_BATCH_REVISION_EXHAUSTED",
        BatchErrorCode::ClaimExpired => "ACCOUNT_BATCH_CLAIM_EXPIRED",
        BatchErrorCode::InvalidStatus => "ACCOUNT_BATCH_INVALID_STATUS",
        BatchErrorCode::ReceiptMismatch => "ACCOUNT_BATCH_RECEIPT_MISMATCH",
        BatchErrorCode::InvalidPage => "ACCOUNT_BATCH_INVALID_PAGE",
        _ => "ACCOUNT_BATCH_INVALID_ARGUMENT",
    }
}

impl Display for BatchErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted account-batch failure containing only a stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchError {
    code: BatchErrorCode,
}

impl BatchError {
    pub(crate) const fn new(code: BatchErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> BatchErrorCode {
        self.code
    }
}

impl Display for BatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for BatchError {}

pub(crate) const fn error(code: BatchErrorCode) -> BatchError {
    BatchError::new(code)
}

macro_rules! bounded_id {
    ($name:ident, $doc:literal, $limit:expr) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses a non-empty visible ASCII identifier within its byte bound.
            ///
            /// # Errors
            /// Returns [`BatchErrorCode::InvalidArgument`] without retaining or
            /// echoing malformed input.
            pub fn parse(value: &str) -> Result<Self, BatchError> {
                if !valid_visible(value, $limit) {
                    return Err(error(BatchErrorCode::InvalidArgument));
                }
                Ok(Self(value.into()))
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("<opaque>")
            }
        }
    };
}

bounded_id!(
    OperationId,
    "A bounded identity for the durable administrative operation.",
    MAX_ID_BYTES
);
bounded_id!(
    BatchId,
    "A bounded identity for one immutable account batch.",
    MAX_ID_BYTES
);
bounded_id!(
    BatchItemId,
    "A bounded identity for one item within an account batch.",
    MAX_ID_BYTES
);
bounded_id!(
    IdempotencyKey,
    "A tenant-scoped key binding an administrative submission to its content.",
    MAX_IDEMPOTENCY_KEY_BYTES
);
bounded_id!(
    MutationId,
    "A bounded tenant-scoped identity for one durable mutation and its receipt.",
    MAX_MUTATION_ID_BYTES
);
bounded_id!(
    ClaimId,
    "A bounded durable identity for one item claim lease.",
    MAX_CLAIM_ID_BYTES
);

pub(crate) fn valid_visible(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

/// UTC Unix time in whole seconds.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcSeconds(u64);

impl UtcSeconds {
    /// Creates a timestamp from seconds since the Unix epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic revision used for optimistic durable mutations.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchRevision(u64);

impl BatchRevision {
    /// Returns the revision assigned at initial durable submission.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Reconstructs a revision from durable state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next monotonic revision.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::RevisionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, BatchError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(BatchErrorCode::RevisionExhausted))
    }
}

/// One-based durable claim attempt assigned by the adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchAttempt(NonZeroU8);

impl BatchAttempt {
    /// Returns the first durable claim attempt.
    #[must_use]
    pub const fn first() -> Self {
        Self(NonZeroU8::MIN)
    }

    /// Reconstructs a globally bounded attempt number.
    ///
    /// # Errors
    /// Returns a stable argument or resource-limit error.
    pub fn new(value: u8) -> Result<Self, BatchError> {
        let Some(value) = NonZeroU8::new(value) else {
            return Err(error(BatchErrorCode::InvalidArgument));
        };
        if value.get() > MAX_ITEM_ATTEMPTS {
            return Err(error(BatchErrorCode::ResourceLimitExceeded));
        }
        Ok(Self(value))
    }

    /// Returns the one-based attempt number.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0.get()
    }

    /// Advances an expired claim within the immutable plan limit.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::ResourceLimitExceeded`] when no further claim
    /// attempt is authorized.
    pub fn next(self, maximum: NonZeroU8) -> Result<Self, BatchError> {
        if maximum.get() > MAX_ITEM_ATTEMPTS {
            return Err(error(BatchErrorCode::ResourceLimitExceeded));
        }
        if self.0 >= maximum {
            return Err(error(BatchErrorCode::ResourceLimitExceeded));
        }
        let Some(next) = self.0.get().checked_add(1).and_then(NonZeroU8::new) else {
            return Err(error(BatchErrorCode::ResourceLimitExceeded));
        };
        Ok(Self(next))
    }
}

/// Typed evidence that a completion revision was derived from one claimed item.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RevisionEvidence {
    claim_revision: BatchRevision,
    resulting_revision: BatchRevision,
    intervening_revisions: u32,
}

impl RevisionEvidence {
    /// Creates bounded revision evidence for one claimed item completion.
    pub fn new(
        claim_revision: BatchRevision,
        resulting_revision: BatchRevision,
        intervening_revisions: u32,
    ) -> Result<Self, BatchError> {
        let expected = claim_revision
            .next()?
            .get()
            .checked_add(u64::from(intervening_revisions))
            .map(BatchRevision::new)
            .ok_or_else(|| error(BatchErrorCode::RevisionExhausted))?;
        if expected != resulting_revision {
            return Err(error(BatchErrorCode::ReceiptMismatch));
        }
        Ok(Self {
            claim_revision,
            resulting_revision,
            intervening_revisions,
        })
    }

    /// Returns the claim revision used as the evidence origin.
    #[must_use]
    pub const fn claim_revision(self) -> BatchRevision {
        self.claim_revision
    }

    /// Returns the resulting durable revision.
    #[must_use]
    pub const fn resulting_revision(self) -> BatchRevision {
        self.resulting_revision
    }

    /// Returns the number of independently committed revisions accounted for.
    #[must_use]
    pub const fn intervening_revisions(self) -> u32 {
        self.intervening_revisions
    }
}

/// Zero-based immutable plan position for deterministic claims and paging.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchItemOrdinal(u32);

impl BatchItemOrdinal {
    /// Creates an ordinal within the global plan item bound.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::ResourceLimitExceeded`] outside the bound.
    pub fn new(value: u32) -> Result<Self, BatchError> {
        if value as usize >= MAX_BATCH_ITEMS {
            return Err(error(BatchErrorCode::ResourceLimitExceeded));
        }
        Ok(Self(value))
    }

    /// Returns the zero-based ordinal.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// Durable progress summary without account identifiers or failure text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchStatus {
    identity: BatchIdentity,
    lifecycle: BatchLifecycle,
    revision: BatchRevision,
    total_items: u32,
    completed_items: u32,
    failed_items: u32,
}

impl BatchStatus {
    /// Creates a validated durable progress summary.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::InvalidStatus`] when counters contradict the
    /// lifecycle or terminal detail.
    pub fn new(
        identity: BatchIdentity,
        lifecycle: BatchLifecycle,
        revision: BatchRevision,
        total_items: u32,
        completed_items: u32,
        failed_items: u32,
    ) -> Result<Self, BatchError> {
        if matches!(lifecycle, BatchLifecycle::Terminal(_)) {
            return Err(error(BatchErrorCode::InvalidStatus));
        }
        validate_common_counts(total_items, completed_items, failed_items)?;
        validate_lifecycle_counts(lifecycle, total_items, completed_items, failed_items)?;
        Ok(Self {
            identity,
            lifecycle,
            revision,
            total_items,
            completed_items,
            failed_items,
        })
    }

    /// Creates terminal status with explicit proof that no claim lease remains.
    pub fn new_terminal(
        identity: BatchIdentity,
        lifecycle: BatchLifecycle,
        revision: BatchRevision,
        total_items: u32,
        completed_items: u32,
        failed_items: u32,
        claims: NoLiveClaims,
    ) -> Result<Self, BatchError> {
        let _ = claims;
        validate_common_counts(total_items, completed_items, failed_items)?;
        if !matches!(lifecycle, BatchLifecycle::Terminal(_)) {
            return Err(error(BatchErrorCode::InvalidStatus));
        }
        validate_lifecycle_counts(lifecycle, total_items, completed_items, failed_items)?;
        Ok(Self {
            identity,
            lifecycle,
            revision,
            total_items,
            completed_items,
            failed_items,
        })
    }

    /// Returns the tenant-scoped durable identity.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        &self.identity
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> BatchLifecycle {
        self.lifecycle
    }

    /// Returns the optimistic revision.
    #[must_use]
    pub const fn revision(&self) -> BatchRevision {
        self.revision
    }

    /// Returns the immutable plan item count.
    #[must_use]
    pub const fn total_items(&self) -> u32 {
        self.total_items
    }

    /// Returns the terminal item count.
    #[must_use]
    pub const fn completed_items(&self) -> u32 {
        self.completed_items
    }

    /// Returns the rejected item count.
    #[must_use]
    pub const fn failed_items(&self) -> u32 {
        self.failed_items
    }

    /// Verifies that terminal state has no live durable claims.
    ///
    /// The status intentionally does not embed adapter lease rows. A durable
    /// adapter must perform this check in the same authoritative read or
    /// transaction used to publish terminal state.
    pub fn validate_no_live_claims(&self, live_claims: u32) -> Result<(), BatchError> {
        if matches!(self.lifecycle, BatchLifecycle::Terminal(_)) && live_claims != 0 {
            return Err(error(BatchErrorCode::InvalidStatus));
        }
        Ok(())
    }
}

/// Proof token that an authoritative claim lookup found no live leases.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NoLiveClaims(());

impl NoLiveClaims {
    /// Creates proof only when the authoritative count is zero.
    pub fn new(live_claims: u32) -> Result<Self, BatchError> {
        if live_claims == 0 {
            Ok(Self(()))
        } else {
            Err(error(BatchErrorCode::InvalidStatus))
        }
    }
}

fn validate_common_counts(total: u32, completed: u32, failed: u32) -> Result<(), BatchError> {
    if total == 0 || total as usize > MAX_BATCH_ITEMS {
        return Err(error(BatchErrorCode::InvalidStatus));
    }
    if completed > total {
        return Err(error(BatchErrorCode::InvalidStatus));
    }
    if failed > completed {
        return Err(error(BatchErrorCode::InvalidStatus));
    }
    Ok(())
}

fn validate_lifecycle_counts(
    lifecycle: BatchLifecycle,
    total: u32,
    completed: u32,
    failed: u32,
) -> Result<(), BatchError> {
    match lifecycle {
        BatchLifecycle::Planned => require_no_progress(completed, failed),
        BatchLifecycle::Running | BatchLifecycle::Cancelling => {
            require_incomplete(total, completed)
        }
        BatchLifecycle::Terminal(terminal) => {
            validate_terminal_counts(terminal, total, completed, failed)
        }
    }
}

fn require_no_progress(completed: u32, failed: u32) -> Result<(), BatchError> {
    if completed != 0 || failed != 0 {
        return Err(error(BatchErrorCode::InvalidStatus));
    }
    Ok(())
}

fn require_incomplete(total: u32, completed: u32) -> Result<(), BatchError> {
    if completed >= total {
        return Err(error(BatchErrorCode::InvalidStatus));
    }
    Ok(())
}

fn validate_terminal_counts(
    terminal: BatchTerminalState,
    total: u32,
    completed: u32,
    failed: u32,
) -> Result<(), BatchError> {
    match terminal {
        BatchTerminalState::Succeeded => validate_succeeded(total, completed, failed),
        BatchTerminalState::CompletedWithFailures => {
            validate_completed_with_failures(total, completed, failed)
        }
        BatchTerminalState::Cancelled | BatchTerminalState::DeadlineExceeded => {
            require_incomplete(total, completed)
        }
        BatchTerminalState::Failed => require_incomplete(total, completed),
    }
}

fn validate_succeeded(total: u32, completed: u32, failed: u32) -> Result<(), BatchError> {
    if completed != total || failed != 0 {
        return Err(error(BatchErrorCode::InvalidStatus));
    }
    Ok(())
}

fn validate_completed_with_failures(
    total: u32,
    completed: u32,
    failed: u32,
) -> Result<(), BatchError> {
    if completed != total || failed == 0 {
        return Err(error(BatchErrorCode::InvalidStatus));
    }
    Ok(())
}

/// Fixed execution bounds captured by an immutable batch plan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BatchResourceLimits {
    max_parallel_items: NonZeroU16,
    max_claim_items: NonZeroU16,
    max_item_attempts: NonZeroU8,
}

impl BatchResourceLimits {
    /// Creates bounded execution limits.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::InvalidArgument`] for zero and
    /// [`BatchErrorCode::ResourceLimitExceeded`] above a fixed maximum.
    pub fn new(
        max_parallel_items: u16,
        max_claim_items: u16,
        max_item_attempts: u8,
    ) -> Result<Self, BatchError> {
        let Some(max_parallel_items) = NonZeroU16::new(max_parallel_items) else {
            return Err(error(BatchErrorCode::InvalidArgument));
        };
        let Some(max_claim_items) = NonZeroU16::new(max_claim_items) else {
            return Err(error(BatchErrorCode::InvalidArgument));
        };
        let Some(max_item_attempts) = NonZeroU8::new(max_item_attempts) else {
            return Err(error(BatchErrorCode::InvalidArgument));
        };
        validate_resource_limits(max_parallel_items, max_claim_items, max_item_attempts)?;
        Ok(Self {
            max_parallel_items,
            max_claim_items,
            max_item_attempts,
        })
    }

    /// Returns the maximum concurrent item executions.
    #[must_use]
    pub const fn max_parallel_items(self) -> NonZeroU16 {
        self.max_parallel_items
    }

    /// Returns the maximum items in one durable claim.
    #[must_use]
    pub const fn max_claim_items(self) -> NonZeroU16 {
        self.max_claim_items
    }

    /// Returns the maximum attempts permitted for one item.
    #[must_use]
    pub const fn max_item_attempts(self) -> NonZeroU8 {
        self.max_item_attempts
    }
}

fn validate_resource_limits(
    parallel: NonZeroU16,
    claim: NonZeroU16,
    attempts: NonZeroU8,
) -> Result<(), BatchError> {
    if parallel.get() > MAX_PARALLEL_ITEMS
        || claim.get() > MAX_CLAIM_ITEMS
        || attempts.get() > MAX_ITEM_ATTEMPTS
    {
        return Err(error(BatchErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

/// Whether a batch validates effects or durably applies them.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchIntent {
    /// Evaluates every item without modifying the authoritative account.
    DryRun,
    /// Applies authorized account changes through the durable adapter.
    Execute,
}

/// One immutable, version-checked account lifecycle item.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct BatchItem {
    id: BatchItemId,
    account_id: AccountId,
    command: AccountTransitionCommand,
}

impl BatchItem {
    /// Creates one secret-free account lifecycle item.
    #[must_use]
    pub const fn new(
        id: BatchItemId,
        account_id: AccountId,
        command: AccountTransitionCommand,
    ) -> Self {
        Self {
            id,
            account_id,
            command,
        }
    }

    /// Returns the item identity.
    #[must_use]
    pub const fn id(&self) -> &BatchItemId {
        &self.id
    }

    /// Returns the target account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the version-checked lifecycle command.
    #[must_use]
    pub const fn command(&self) -> AccountTransitionCommand {
        self.command
    }
}

impl Debug for BatchItem {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchItem")
            .field("id", &"<opaque>")
            .field("account_id", &"<opaque>")
            .field("command", &self.command)
            .finish()
    }
}

/// A validated tenant-scoped submission before durable identities are assigned.
#[derive(Clone, Eq, PartialEq)]
pub struct BatchSubmission {
    tenant_id: TenantId,
    idempotency_key: IdempotencyKey,
    intent: BatchIntent,
    created_at: UtcSeconds,
    deadline: UtcSeconds,
    resources: BatchResourceLimits,
    items: Box<[BatchItem]>,
}

impl BatchSubmission {
    /// Creates a bounded submission and validates all immutable inputs.
    ///
    /// # Errors
    /// Returns a stable error for an empty or oversized batch, duplicate item
    /// or account identities, an expired window, an excessive lifetime, or an
    /// excessive resource request. Rejected input is never retained in errors.
    pub fn new(
        tenant_id: TenantId,
        idempotency_key: IdempotencyKey,
        intent: BatchIntent,
        created_at: UtcSeconds,
        deadline: UtcSeconds,
        resources: BatchResourceLimits,
        items: Vec<BatchItem>,
    ) -> Result<Self, BatchError> {
        validate_item_count(items.len())?;
        validate_window(created_at, deadline)?;
        validate_unique_items(&items)?;
        Ok(Self {
            tenant_id,
            idempotency_key,
            intent,
            created_at,
            deadline,
            resources,
            items: items.into_boxed_slice(),
        })
    }

    /// Returns the owning tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the tenant-scoped idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Returns whether this plan validates or applies effects.
    #[must_use]
    pub const fn intent(&self) -> BatchIntent {
        self.intent
    }

    /// Returns the immutable creation time.
    #[must_use]
    pub const fn created_at(&self) -> UtcSeconds {
        self.created_at
    }

    /// Returns the absolute UTC deadline.
    #[must_use]
    pub const fn deadline(&self) -> UtcSeconds {
        self.deadline
    }

    /// Returns the immutable execution bounds.
    #[must_use]
    pub const fn resources(&self) -> BatchResourceLimits {
        self.resources
    }

    /// Returns the immutable ordered item slice.
    #[must_use]
    pub const fn items(&self) -> &[BatchItem] {
        &self.items
    }
}

impl Debug for BatchSubmission {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchSubmission")
            .field("tenant_id", &"<opaque>")
            .field("idempotency_key", &"<opaque>")
            .field("intent", &self.intent)
            .field("created_at", &self.created_at)
            .field("deadline", &self.deadline)
            .field("resources", &self.resources)
            .field("item_count", &self.items.len())
            .finish()
    }
}

fn validate_item_count(item_count: usize) -> Result<(), BatchError> {
    if item_count == 0 {
        return Err(error(BatchErrorCode::EmptyBatch));
    }
    if item_count > MAX_BATCH_ITEMS {
        return Err(error(BatchErrorCode::TooManyItems));
    }
    Ok(())
}

fn validate_window(created_at: UtcSeconds, deadline: UtcSeconds) -> Result<(), BatchError> {
    let Some(lifetime) = deadline.get().checked_sub(created_at.get()) else {
        return Err(error(BatchErrorCode::DeadlineExceeded));
    };
    if lifetime == 0 {
        return Err(error(BatchErrorCode::DeadlineExceeded));
    }
    if lifetime > MAX_BATCH_LIFETIME_SECONDS {
        return Err(error(BatchErrorCode::LifetimeExceeded));
    }
    Ok(())
}

fn validate_unique_items(items: &[BatchItem]) -> Result<(), BatchError> {
    let mut item_ids = BTreeSet::new();
    let mut account_ids = BTreeSet::new();
    for item in items {
        if !item_ids.insert(item.id()) {
            return Err(error(BatchErrorCode::DuplicateItem));
        }
        if !account_ids.insert(item.account_id()) {
            return Err(error(BatchErrorCode::DuplicateAccount));
        }
    }
    Ok(())
}

/// An immutable batch plan with adapter-issued durable identities.
#[derive(Clone, Eq, PartialEq)]
pub struct BatchPlan {
    operation_id: OperationId,
    batch_id: BatchId,
    submission: BatchSubmission,
}

impl BatchPlan {
    /// Assigns durable identities to an already validated submission.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        batch_id: BatchId,
        submission: BatchSubmission,
    ) -> Self {
        Self {
            operation_id,
            batch_id,
            submission,
        }
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the immutable batch identity.
    #[must_use]
    pub const fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }

    /// Returns the validated submission captured by this plan.
    #[must_use]
    pub const fn submission(&self) -> &BatchSubmission {
        &self.submission
    }

    /// Returns the tenant, operation, and batch identity tuple.
    #[must_use]
    pub fn identity(&self) -> BatchIdentity {
        BatchIdentity::new(
            self.submission.tenant_id.clone(),
            self.operation_id.clone(),
            self.batch_id.clone(),
        )
    }

    /// Classifies a retry against this durable plan.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::IdempotencyConflict`] when the same tenant and
    /// key are bound to different immutable content.
    pub fn replay_decision(
        &self,
        candidate: &BatchSubmission,
    ) -> Result<BatchReplayDecision, BatchError> {
        if self.submission.tenant_id != candidate.tenant_id
            || self.submission.idempotency_key != candidate.idempotency_key
        {
            return Ok(BatchReplayDecision::CreateNew);
        }
        if self.submission == *candidate {
            return Ok(BatchReplayDecision::ReturnExisting {
                operation_id: self.operation_id.clone(),
                batch_id: self.batch_id.clone(),
            });
        }
        Err(error(BatchErrorCode::IdempotencyConflict))
    }
}

impl Debug for BatchPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchPlan")
            .field("operation_id", &self.operation_id)
            .field("batch_id", &self.batch_id)
            .field("submission", &self.submission)
            .finish()
    }
}

/// Deterministic disposition of an idempotent submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchReplayDecision {
    /// The tenant or key is unrelated and requires a new durable plan.
    CreateNew,
    /// The immutable submission matches and must return existing identities.
    ReturnExisting {
        /// Existing durable operation identity.
        operation_id: OperationId,
        /// Existing immutable batch identity.
        batch_id: BatchId,
    },
}

/// Tenant-scoped durable identity of one account batch.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct BatchIdentity {
    tenant_id: TenantId,
    operation_id: OperationId,
    batch_id: BatchId,
}

impl BatchIdentity {
    /// Creates a tenant-scoped durable batch identity.
    #[must_use]
    pub const fn new(tenant_id: TenantId, operation_id: OperationId, batch_id: BatchId) -> Self {
        Self {
            tenant_id,
            operation_id,
            batch_id,
        }
    }

    /// Returns the owning tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the immutable batch identity.
    #[must_use]
    pub const fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }
}

impl Debug for BatchIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("BatchIdentity(<opaque>)")
    }
}

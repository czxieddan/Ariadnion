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
//! Canonical command encoding and strict persisted-value decoding.

use super::*;

pub(super) fn plan_digest(plan: &BatchPlan) -> String {
    let mut hash = Sha256::new();
    push_hash(&mut hash, plan.operation_id().as_str());
    push_hash(&mut hash, plan.batch_id().as_str());
    let submission = plan.submission();
    push_hash(&mut hash, submission.tenant_id().as_str());
    push_hash(&mut hash, submission.idempotency_key().as_str());
    push_hash(&mut hash, intent_label(submission.intent()));
    push_hash(&mut hash, &submission.created_at().get().to_string());
    push_hash(&mut hash, &submission.deadline().get().to_string());
    push_hash(
        &mut hash,
        &submission
            .resources()
            .max_parallel_items()
            .get()
            .to_string(),
    );
    push_hash(
        &mut hash,
        &submission.resources().max_claim_items().get().to_string(),
    );
    push_hash(
        &mut hash,
        &submission.resources().max_item_attempts().get().to_string(),
    );
    for item in submission.items() {
        push_hash(&mut hash, item.id().as_str());
        push_hash(&mut hash, item.account_id().as_str());
        push_hash(
            &mut hash,
            &item.command().expected_version().get().to_string(),
        );
        push_hash(&mut hash, action_label(item.command().action()));
    }
    hex(hash.finalize().as_slice())
}

pub(super) fn submit_digest(command: &SubmitBatch) -> String {
    plan_digest(command.plan())
}
pub(super) fn claim_digest(command: &ClaimBatchItems) -> String {
    digest_fields(&[
        "claim",
        command.identity().tenant_id().as_str(),
        command.identity().operation_id().as_str(),
        command.identity().batch_id().as_str(),
        &command.expected_revision().get().to_string(),
        command.claim_id().as_str(),
        &command.observed_at().get().to_string(),
        &command.lease_expires_at().get().to_string(),
        &command.limit().get().get().to_string(),
    ])
}
pub(super) fn completion_digest(command: &CompleteClaimedItem) -> String {
    let item = command.claimed_item();
    digest_fields(&[
        "complete",
        item.identity().tenant_id().as_str(),
        item.identity().operation_id().as_str(),
        item.identity().batch_id().as_str(),
        item.claim_id().as_str(),
        &item.claim_revision().get().to_string(),
        &item.ordinal().get().to_string(),
        item.item_id().as_str(),
        item.account_id().as_str(),
        &item.command().expected_version().get().to_string(),
        action_label(item.command().action()),
        &item.attempt().get().to_string(),
        &item.lease_expires_at().get().to_string(),
        intent_label(item.intent()),
        &item.deadline().get().to_string(),
        &command.observed_at().get().to_string(),
    ])
}
pub(super) fn transition_digest(command: &TransitionBatch) -> String {
    let deadline = command
        .deadline()
        .map(|value| value.get().to_string())
        .unwrap_or_default();
    digest_fields(&[
        "transition",
        command.identity().tenant_id().as_str(),
        command.identity().operation_id().as_str(),
        command.identity().batch_id().as_str(),
        &command.expected_revision().get().to_string(),
        &command.observed_at().get().to_string(),
        &deadline,
        transition_label(command.transition()),
    ])
}
pub(super) fn digest_fields(fields: &[&str]) -> String {
    let mut hash = Sha256::new();
    for field in fields {
        push_hash(&mut hash, field);
    }
    hex(hash.finalize().as_slice())
}
pub(super) fn push_hash(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}
pub(super) fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) fn internal_context() -> Result<RequestContext, BatchPortError> {
    Ok(RequestContext::anonymous(
        RequestId::parse("account-batch-rnmdb").map_err(|_| corrupt())?,
        TraceId::parse("account-batch-rnmdb").map_err(|_| corrupt())?,
        None,
    ))
}

pub(super) fn trusted_now() -> Result<UtcSeconds, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| UtcSeconds::new(value.as_secs()))
        .map_err(|_| integrity())
}

pub(super) fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity()),
    }
}
pub(super) fn text_value(value: &SqlValue) -> Result<&str, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(value),
        _ => Err(integrity()),
    }
}
pub(super) fn optional_text(value: &SqlValue) -> Result<Option<&str>, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(Some(value)),
        SqlValue::Null => Ok(None),
        _ => Err(integrity()),
    }
}
pub(super) fn i64_value(value: &SqlValue) -> Result<i64, StorageError> {
    match value {
        SqlValue::Int64(value) => Ok(*value),
        _ => Err(integrity()),
    }
}
pub(super) fn i64_u64(value: &SqlValue) -> Result<u64, StorageError> {
    u64::try_from(i64_value(value)?).map_err(|_| integrity())
}
pub(super) fn i64_u32(value: &SqlValue) -> Result<u32, StorageError> {
    u32::try_from(i64_value(value)?).map_err(|_| integrity())
}
pub(super) fn i64_u16(value: &SqlValue) -> Result<u16, StorageError> {
    u16::try_from(i64_value(value)?).map_err(|_| integrity())
}
pub(super) fn i64_u8(value: &SqlValue) -> Result<u8, StorageError> {
    u8::try_from(i64_value(value)?).map_err(|_| integrity())
}
pub(super) fn optional_i64_u64(value: &SqlValue) -> Result<Option<u64>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        _ => i64_u64(value).map(Some),
    }
}
pub(super) fn optional_i64_u32(value: &SqlValue) -> Result<Option<u32>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        _ => i64_u32(value).map(Some),
    }
}
pub(super) fn parse_u64_text(value: &SqlValue) -> Result<u64, StorageError> {
    text_value(value)?.parse().map_err(|_| integrity())
}
pub(super) fn optional_u64_text(value: &SqlValue) -> Result<Option<u64>, StorageError> {
    optional_text(value)?
        .map(str::parse)
        .transpose()
        .map_err(|_| integrity())
}
pub(super) fn nullable_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "NULL".to_owned(), |value| value.to_string())
}
pub(super) fn nullable_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "NULL".to_owned(), |value| value.to_string())
}

pub(super) fn decode_status(
    identity: BatchIdentity,
    lifecycle: BatchLifecycle,
    revision: BatchRevision,
    total: u32,
    completed: u32,
    failed: u32,
) -> Result<BatchStatus, StorageError> {
    if matches!(lifecycle, BatchLifecycle::Terminal(_)) {
        BatchStatus::new_terminal(
            identity,
            lifecycle,
            revision,
            total,
            completed,
            failed,
            NoLiveClaims::new(0).map_err(|_| integrity())?,
        )
        .map_err(|_| integrity())
    } else {
        BatchStatus::new(identity, lifecycle, revision, total, completed, failed)
            .map_err(|_| integrity())
    }
}

pub(super) fn decode_lifecycle(
    value: &str,
    terminal: Option<&str>,
) -> Result<BatchLifecycle, StorageError> {
    match value {
        "planned" => Ok(BatchLifecycle::Planned),
        "running" => Ok(BatchLifecycle::Running),
        "cancelling" => Ok(BatchLifecycle::Cancelling),
        "terminal" => Ok(BatchLifecycle::Terminal(decode_terminal(
            terminal.ok_or_else(integrity)?,
        )?)),
        _ => Err(integrity()),
    }
}
pub(super) fn decode_terminal(value: &str) -> Result<BatchTerminalState, StorageError> {
    match value {
        "succeeded" => Ok(BatchTerminalState::Succeeded),
        "completed_with_failures" => Ok(BatchTerminalState::CompletedWithFailures),
        "cancelled" => Ok(BatchTerminalState::Cancelled),
        "deadline_exceeded" => Ok(BatchTerminalState::DeadlineExceeded),
        "failed" => Ok(BatchTerminalState::Failed),
        _ => Err(integrity()),
    }
}
pub(super) fn lifecycle_fields(value: BatchLifecycle) -> (&'static str, Option<&'static str>) {
    match value {
        BatchLifecycle::Planned => ("planned", None),
        BatchLifecycle::Running => ("running", None),
        BatchLifecycle::Cancelling => ("cancelling", None),
        BatchLifecycle::Terminal(value) => ("terminal", Some(terminal_label(value))),
    }
}
pub(super) fn terminal_label(value: BatchTerminalState) -> &'static str {
    match value {
        BatchTerminalState::Succeeded => "succeeded",
        BatchTerminalState::CompletedWithFailures => "completed_with_failures",
        BatchTerminalState::Cancelled => "cancelled",
        BatchTerminalState::DeadlineExceeded => "deadline_exceeded",
        BatchTerminalState::Failed => "failed",
    }
}
pub(super) fn decode_intent(value: &str) -> Result<BatchIntent, StorageError> {
    match value {
        "dry_run" => Ok(BatchIntent::DryRun),
        "execute" => Ok(BatchIntent::Execute),
        _ => Err(integrity()),
    }
}
pub(super) fn intent_label(value: BatchIntent) -> &'static str {
    match value {
        BatchIntent::DryRun => "dry_run",
        BatchIntent::Execute => "execute",
    }
}
pub(super) fn decode_action(value: &str) -> Result<AccountTransitionAction, StorageError> {
    match value {
        "activate" => Ok(AccountTransitionAction::Activate),
        "suspend" => Ok(AccountTransitionAction::Suspend),
        "resume" => Ok(AccountTransitionAction::Resume),
        "revoke" => Ok(AccountTransitionAction::Revoke),
        "delete" => Ok(AccountTransitionAction::Delete),
        _ => Err(integrity()),
    }
}
pub(super) fn action_label(value: AccountTransitionAction) -> &'static str {
    match value {
        AccountTransitionAction::Activate => "activate",
        AccountTransitionAction::Suspend => "suspend",
        AccountTransitionAction::Resume => "resume",
        AccountTransitionAction::Revoke => "revoke",
        AccountTransitionAction::Delete => "delete",
    }
}
pub(super) fn decode_account_status(value: &str) -> Result<AccountStatus, StorageError> {
    match value {
        "provisioning" => Ok(AccountStatus::Provisioning),
        "active" => Ok(AccountStatus::Active),
        "suspended" => Ok(AccountStatus::Suspended),
        "revoked" => Ok(AccountStatus::Revoked),
        "deleted" => Ok(AccountStatus::Deleted),
        _ => Err(integrity()),
    }
}
pub(super) fn status_label(value: AccountStatus) -> &'static str {
    match value {
        AccountStatus::Provisioning => "provisioning",
        AccountStatus::Active => "active",
        AccountStatus::Suspended => "suspended",
        AccountStatus::Revoked => "revoked",
        AccountStatus::Deleted => "deleted",
    }
}
pub(super) fn submit_disposition_label(value: BatchSubmitDisposition) -> &'static str {
    match value {
        BatchSubmitDisposition::Created => "created",
        BatchSubmitDisposition::Replayed => "replayed",
    }
}
pub(super) fn transition_label(value: BatchTransition) -> &'static str {
    match value {
        BatchTransition::Start => "start",
        BatchTransition::RequestCancellation => "request_cancellation",
        BatchTransition::Expire => "expire",
        BatchTransition::Finish(terminal) => finish_transition_label(terminal),
    }
}

const fn finish_transition_label(value: BatchTerminalState) -> &'static str {
    match value {
        BatchTerminalState::Succeeded => "finish_succeeded",
        BatchTerminalState::CompletedWithFailures => "finish_completed_with_failures",
        BatchTerminalState::Cancelled => "finish_cancelled",
        BatchTerminalState::DeadlineExceeded => "finish_deadline_exceeded",
        BatchTerminalState::Failed => "finish_failed",
    }
}

pub(super) fn decode_transition(value: &str) -> Result<BatchTransition, StorageError> {
    match value {
        "start" => Ok(BatchTransition::Start),
        "request_cancellation" => Ok(BatchTransition::RequestCancellation),
        "expire" => Ok(BatchTransition::Expire),
        _ => decode_finish_transition(value).map(BatchTransition::Finish),
    }
}

fn decode_finish_transition(value: &str) -> Result<BatchTerminalState, StorageError> {
    match value {
        "finish_succeeded" => Ok(BatchTerminalState::Succeeded),
        "finish_completed_with_failures" => Ok(BatchTerminalState::CompletedWithFailures),
        "finish_cancelled" => Ok(BatchTerminalState::Cancelled),
        "finish_deadline_exceeded" => Ok(BatchTerminalState::DeadlineExceeded),
        "finish_failed" => Ok(BatchTerminalState::Failed),
        _ => Err(integrity()),
    }
}
pub(super) fn decode_mutation_kind(value: &str) -> Result<BatchMutationKind, StorageError> {
    match value {
        "submission" => Ok(BatchMutationKind::Submission),
        "claim" => Ok(BatchMutationKind::Claim),
        "item_completion" => Ok(BatchMutationKind::ItemCompletion),
        "transition" => Ok(BatchMutationKind::Transition),
        _ => Err(integrity()),
    }
}
pub(super) fn failure_label(value: BatchItemFailureCode) -> &'static str {
    match value {
        BatchItemFailureCode::AccountNotFound => "account_not_found",
        BatchItemFailureCode::VersionConflict => "version_conflict",
        BatchItemFailureCode::InvalidTransition => "invalid_transition",
        BatchItemFailureCode::PermissionDenied => "permission_denied",
        other => execution_failure_label(other),
    }
}

const fn execution_failure_label(value: BatchItemFailureCode) -> &'static str {
    match value {
        BatchItemFailureCode::Cancelled => "cancelled",
        BatchItemFailureCode::DeadlineExceeded => "deadline_exceeded",
        BatchItemFailureCode::ResourceExhausted => "resource_exhausted",
        BatchItemFailureCode::AdapterUnavailable => "adapter_unavailable",
        _ => "adapter_unavailable",
    }
}

pub(super) fn decode_failure(value: &str) -> Result<BatchItemFailureCode, StorageError> {
    match value {
        "account_not_found" => Ok(BatchItemFailureCode::AccountNotFound),
        "version_conflict" => Ok(BatchItemFailureCode::VersionConflict),
        "invalid_transition" => Ok(BatchItemFailureCode::InvalidTransition),
        "permission_denied" => Ok(BatchItemFailureCode::PermissionDenied),
        _ => decode_execution_failure(value),
    }
}

fn decode_execution_failure(value: &str) -> Result<BatchItemFailureCode, StorageError> {
    match value {
        "cancelled" => Ok(BatchItemFailureCode::Cancelled),
        "deadline_exceeded" => Ok(BatchItemFailureCode::DeadlineExceeded),
        "resource_exhausted" => Ok(BatchItemFailureCode::ResourceExhausted),
        "adapter_unavailable" => Ok(BatchItemFailureCode::AdapterUnavailable),
        _ => Err(integrity()),
    }
}

pub(super) fn map_storage_error(error: StorageError) -> BatchPortError {
    BatchPortError::new(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(code: StorageErrorCode) -> BatchPortErrorCode {
    match code {
        StorageErrorCode::NotFound => BatchPortErrorCode::NotFound,
        StorageErrorCode::Conflict => BatchPortErrorCode::Conflict,
        StorageErrorCode::Cancelled => BatchPortErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => BatchPortErrorCode::DeadlineExceeded,
        StorageErrorCode::ResourceExhausted => BatchPortErrorCode::ResourceExhausted,
        other => map_adapter_error_code(other),
    }
}

const fn map_adapter_error_code(code: StorageErrorCode) -> BatchPortErrorCode {
    match code {
        StorageErrorCode::CommitIndeterminate => BatchPortErrorCode::CommitIndeterminate,
        StorageErrorCode::IntegrityFailure => BatchPortErrorCode::CorruptState,
        _ => BatchPortErrorCode::Unavailable,
    }
}
pub(super) const fn corrupt() -> BatchPortError {
    BatchPortError::new(BatchPortErrorCode::CorruptState)
}
pub(super) const fn integrity() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}
pub(super) const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}
pub(super) const fn not_found() -> StorageError {
    StorageError::new(StorageErrorCode::NotFound)
}
pub(super) const fn exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

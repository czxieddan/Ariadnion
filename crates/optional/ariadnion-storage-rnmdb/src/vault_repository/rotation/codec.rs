// crates/optional/ariadnion-storage-rnmdb/src/vault_repository/rotation/codec.rs - Rotation persistence codec.
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
//! Exact replay, optimistic revision, and restart reconstruction codecs.

mod history;

use std::time::{Duration, SystemTime};

use ariadnion_account_vault::{
    AccountId, CredentialRotationPlan, RotationJournal, RotationMutationId,
    RotationMutationReceipt, RotationMutationRequest, RotationPhase, RotationRevision,
    RotationSnapshot, RotationTransition, RotationWindow, SecretPath, SecretProvider,
    SecretPurpose, SecretRef, SecretRevokeReceipt, SecretStoreReceipt, SecretVersion, VaultError,
    VaultErrorCode, VaultKeyVersion,
};
use ariadnion_core::TenantId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use hmac::{Hmac, Mac};
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;
use rnmdb_types::SqlValue;
use sha2::Sha256;

use super::super::{VaultKeyCustody, sql};
use crate::identity_transaction::require_active_identity_transaction;

const JOURNAL_PROJECTION: &str = "tenant_id, rotation_id, account_id, previous_reference_digest_hex, previous_secret_provider, previous_secret_path, previous_secret_version, previous_secret_purpose, next_reference_digest_hex, next_secret_provider, next_secret_path, next_secret_version, next_secret_purpose, overlap_seconds, rotation_phase, revision, new_key_version, new_stored_at, activated_at, overlap_ends_at, previous_revoked_at, compensation_revoked_at, updated_at";
const MUTATION_PROJECTION: &str = "tenant_id, mutation_id, rotation_id, request_fingerprint_hex, transition_kind, expected_revision, prior_revision, revision, rotation_phase, committed_at";
const FINGERPRINT_DOMAIN: &[u8] = b"ariadnion.vault.rotation-mutation.v1";

struct StoredJournal {
    snapshot: RotationSnapshot,
}

struct StoredMutation {
    fingerprint: String,
    transition: Box<str>,
    expected_revision: RotationRevision,
    receipt: RotationMutationReceipt,
}

struct MutationInputs<'a> {
    tenant: &'a TenantId,
    request: &'a RotationMutationRequest,
    now: SystemTime,
    fingerprint: &'a str,
    custody: &'a dyn VaultKeyCustody,
}

struct RotationDigests {
    previous: [u8; 32],
    next: [u8; 32],
}

struct JournalState {
    phase: RotationPhase,
    revision: RotationRevision,
    updated_at: SystemTime,
}

struct ReconstructionEvidence {
    store: Option<SecretStoreReceipt>,
    activated: Option<SystemTime>,
    overlap_end: Option<SystemTime>,
    previous_revoke: Option<SecretRevokeReceipt>,
    compensation: Option<SecretRevokeReceipt>,
}

struct MutationIdentity {
    rotation_id: Box<str>,
    fingerprint: String,
    transition: Box<str>,
}

struct MutationReceiptFields {
    expected_revision: RotationRevision,
    prior_revision: RotationRevision,
    revision: RotationRevision,
    phase: RotationPhase,
    committed_at: SystemTime,
}

pub(super) fn mutate(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &RotationMutationRequest,
    now: SystemTime,
    fingerprint_key: &[u8; 32],
    custody: &dyn VaultKeyCustody,
) -> Result<RotationMutationReceipt, StorageError> {
    require_active_identity_transaction(local)?;
    let fingerprint = fingerprint_request(tenant, request, fingerprint_key)?;
    let inputs = MutationInputs {
        tenant,
        request,
        now,
        fingerprint: &fingerprint,
        custody,
    };
    match load_mutation_record(local, tenant, request.mutation_id())? {
        Some(stored) => replay_existing(local, &inputs, stored),
        None => apply_new_mutation(local, &inputs),
    }
}

fn replay_existing(
    local: &mut LocalSession,
    inputs: &MutationInputs<'_>,
    stored: StoredMutation,
) -> Result<RotationMutationReceipt, StorageError> {
    let receipt = replay_mutation(stored, inputs.request, inputs.fingerprint)?;
    validate_receipt_against_journal(local, inputs.tenant, receipt, inputs.custody)
}

fn apply_new_mutation(
    local: &mut LocalSession,
    inputs: &MutationInputs<'_>,
) -> Result<RotationMutationReceipt, StorageError> {
    match inputs.request.transition() {
        RotationTransition::Prepare(plan) => prepare(local, inputs, plan),
        _ => advance(local, inputs),
    }
}

pub(super) fn load_mutation(
    local: &mut LocalSession,
    tenant: &TenantId,
    mutation_id: &RotationMutationId,
    custody: &dyn VaultKeyCustody,
) -> Result<Option<RotationMutationReceipt>, StorageError> {
    let stored = load_mutation_record(local, tenant, mutation_id)?;
    stored
        .map(|value| validate_receipt_against_journal(local, tenant, value.receipt, custody))
        .transpose()
}

pub(super) fn load_snapshot(
    local: &mut LocalSession,
    tenant: &TenantId,
    rotation_id: &str,
    custody: &dyn VaultKeyCustody,
) -> Result<Option<RotationSnapshot>, StorageError> {
    load_journal(local, tenant, rotation_id, custody)
        .map(|stored| stored.map(|value| value.snapshot))
}

fn prepare(
    local: &mut LocalSession,
    inputs: &MutationInputs<'_>,
    plan: &CredentialRotationPlan,
) -> Result<RotationMutationReceipt, StorageError> {
    validate_prepare_request(inputs.request, plan)?;
    require_missing_journal(
        local,
        inputs.tenant,
        inputs.request.rotation_id(),
        inputs.custody,
    )?;
    let digests = rotation_digests(inputs.custody, inputs.tenant, plan)?;
    require_no_overlap(local, inputs.tenant, &digests.previous, &digests.next)?;
    let revision = RotationRevision::ZERO
        .checked_next()
        .map_err(domain_error)?;
    persist_prepared(local, inputs, plan, &digests, revision)
}

fn validate_prepare_request(
    request: &RotationMutationRequest,
    plan: &CredentialRotationPlan,
) -> Result<(), StorageError> {
    if request.expected_revision() != RotationRevision::ZERO
        || request.rotation_id() != plan.rotation_id()
    {
        return Err(sql::conflict());
    }
    Ok(())
}

fn require_missing_journal(
    local: &mut LocalSession,
    tenant: &TenantId,
    rotation_id: &str,
    custody: &dyn VaultKeyCustody,
) -> Result<(), StorageError> {
    if load_journal(local, tenant, rotation_id, custody)?.is_some() {
        return Err(sql::conflict());
    }
    Ok(())
}

fn rotation_digests(
    custody: &dyn VaultKeyCustody,
    tenant: &TenantId,
    plan: &CredentialRotationPlan,
) -> Result<RotationDigests, StorageError> {
    let previous = reference_digest(custody, tenant, plan.previous())?;
    let next = reference_digest(custody, tenant, plan.next())?;
    Ok(RotationDigests { previous, next })
}

fn persist_prepared(
    local: &mut LocalSession,
    inputs: &MutationInputs<'_>,
    plan: &CredentialRotationPlan,
    digests: &RotationDigests,
    revision: RotationRevision,
) -> Result<RotationMutationReceipt, StorageError> {
    let committed_at = sql::time_encode(inputs.now)?;
    insert_journal(
        local,
        inputs.tenant,
        plan,
        &digests.previous,
        &digests.next,
        revision,
        committed_at,
    )?;
    let receipt = RotationMutationReceipt::new(
        inputs.request.mutation_id().clone(),
        inputs.request.rotation_id(),
        RotationRevision::ZERO,
        revision,
        RotationPhase::Prepared,
        inputs.now,
    )
    .map_err(|_| sql::integrity())?;
    insert_mutation(
        local,
        inputs.tenant,
        inputs.request,
        inputs.fingerprint,
        &receipt,
        committed_at,
    )?;
    Ok(receipt)
}

fn advance(
    local: &mut LocalSession,
    inputs: &MutationInputs<'_>,
) -> Result<RotationMutationReceipt, StorageError> {
    let stored = required_journal(
        local,
        inputs.tenant,
        inputs.request.rotation_id(),
        inputs.custody,
    )?;
    require_expected_revision(&stored.snapshot, inputs.request.expected_revision())?;
    require_non_regressing_time(&stored.snapshot, inputs.now)?;
    let mut journal = stored.snapshot.journal().clone();
    apply_transition(&mut journal, inputs.request.transition(), inputs.now)?;
    let revision = stored
        .snapshot
        .revision()
        .checked_next()
        .map_err(domain_error)?;
    persist_advance(local, inputs, journal, revision)
}

fn required_journal(
    local: &mut LocalSession,
    tenant: &TenantId,
    rotation_id: &str,
    custody: &dyn VaultKeyCustody,
) -> Result<StoredJournal, StorageError> {
    load_journal(local, tenant, rotation_id, custody)?
        .ok_or_else(|| StorageError::new(StorageErrorCode::NotFound))
}

fn require_expected_revision(
    snapshot: &RotationSnapshot,
    expected: RotationRevision,
) -> Result<(), StorageError> {
    if snapshot.revision() != expected {
        return Err(sql::conflict());
    }
    Ok(())
}

fn require_non_regressing_time(
    snapshot: &RotationSnapshot,
    now: SystemTime,
) -> Result<(), StorageError> {
    if now < snapshot.updated_at() {
        return Err(sql::conflict());
    }
    Ok(())
}

fn persist_advance(
    local: &mut LocalSession,
    inputs: &MutationInputs<'_>,
    journal: RotationJournal,
    revision: RotationRevision,
) -> Result<RotationMutationReceipt, StorageError> {
    let committed_at = sql::time_encode(inputs.now)?;
    update_journal(
        local,
        inputs.tenant,
        inputs.request.rotation_id(),
        inputs.request.expected_revision(),
        revision,
        &journal,
        committed_at,
    )?;
    let receipt = RotationMutationReceipt::new(
        inputs.request.mutation_id().clone(),
        inputs.request.rotation_id(),
        inputs.request.expected_revision(),
        revision,
        journal.phase(),
        inputs.now,
    )
    .map_err(|_| sql::integrity())?;
    insert_mutation(
        local,
        inputs.tenant,
        inputs.request,
        inputs.fingerprint,
        &receipt,
        committed_at,
    )?;
    Ok(receipt)
}

fn apply_transition(
    journal: &mut RotationJournal,
    transition: &RotationTransition,
    now: SystemTime,
) -> Result<(), StorageError> {
    let result = match transition {
        RotationTransition::Prepare(_) => Err(VaultError::new(VaultErrorCode::Conflict)),
        RotationTransition::RecordNewVersion(receipt) => {
            journal.record_new_version(receipt.clone(), now)
        }
        RotationTransition::Activate(activated_at) => activate(journal, *activated_at, now),
        RotationTransition::Complete(receipt) => journal.revoke_previous(receipt.clone(), now),
        RotationTransition::BeginCompensation => journal
            .begin_compensation()
            .and_then(|request| request.ok_or_else(|| VaultError::new(VaultErrorCode::Conflict)))
            .map(drop),
        RotationTransition::RecordCompensation(receipt) => {
            journal.record_compensation(receipt.clone(), now)
        }
    };
    result.map_err(domain_error)
}

fn activate(
    journal: &mut RotationJournal,
    activated_at: SystemTime,
    now: SystemTime,
) -> Result<(), VaultError> {
    if activated_at > now {
        return Err(VaultError::new(VaultErrorCode::Conflict));
    }
    journal.activate(activated_at)
}

fn replay_mutation(
    stored: StoredMutation,
    request: &RotationMutationRequest,
    fingerprint: &str,
) -> Result<RotationMutationReceipt, StorageError> {
    let exact = stored.fingerprint == fingerprint
        && stored.transition.as_ref() == request.transition().as_str()
        && stored.expected_revision == request.expected_revision()
        && stored.receipt.rotation_id() == request.rotation_id();
    if !exact {
        return Err(sql::conflict());
    }
    Ok(stored.receipt)
}

fn validate_receipt_against_journal(
    local: &mut LocalSession,
    tenant: &TenantId,
    receipt: RotationMutationReceipt,
    custody: &dyn VaultKeyCustody,
) -> Result<RotationMutationReceipt, StorageError> {
    let snapshot = load_journal(local, tenant, receipt.rotation_id(), custody)?
        .ok_or_else(sql::integrity)?
        .snapshot;
    if !history::receipt_matches_snapshot(&snapshot, &receipt) {
        return Err(sql::integrity());
    }
    Ok(receipt)
}

fn insert_journal(
    local: &mut LocalSession,
    tenant: &TenantId,
    plan: &CredentialRotationPlan,
    previous_digest: &[u8; 32],
    next_digest: &[u8; 32],
    revision: RotationRevision,
    committed_at: i64,
) -> Result<(), StorageError> {
    let overlap =
        i64::try_from(plan.overlap().duration().as_secs()).map_err(|_| sql::exhausted())?;
    let statement = format!(
        "INSERT INTO account_vault_rotation_journals (tenant_id, rotation_id, account_id, previous_reference_digest_hex, previous_secret_provider, previous_secret_path, previous_secret_version, previous_secret_purpose, next_reference_digest_hex, next_secret_provider, next_secret_path, next_secret_version, next_secret_purpose, overlap_seconds, rotation_phase, revision, new_key_version, new_stored_at, activated_at, overlap_ends_at, previous_revoked_at, compensation_revoked_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, 'prepared', {}, NULL, NULL, NULL, NULL, NULL, NULL, {});",
        sql::text(tenant.as_str()),
        sql::text(plan.rotation_id()),
        sql::text(plan.account_id().as_str()),
        sql::text(&sql::hex(previous_digest)),
        sql::text(plan.previous().provider().as_str()),
        sql::text(plan.previous().path().as_str()),
        sql::text(&plan.previous().version().get().to_string()),
        sql::text(plan.previous().purpose().as_str()),
        sql::text(&sql::hex(next_digest)),
        sql::text(plan.next().provider().as_str()),
        sql::text(plan.next().path().as_str()),
        sql::text(&plan.next().version().get().to_string()),
        sql::text(plan.next().purpose().as_str()),
        overlap,
        sql::text(&revision.get().to_string()),
        committed_at,
    );
    sql::changed(sql::execute(local, statement)?)
}

fn update_journal(
    local: &mut LocalSession,
    tenant: &TenantId,
    rotation_id: &str,
    expected: RotationRevision,
    revision: RotationRevision,
    journal: &RotationJournal,
    committed_at: i64,
) -> Result<(), StorageError> {
    let store = journal.new_receipt();
    let key = optional_key(store.as_ref())?;
    let stored_at = optional_time(store.as_ref().map(SecretStoreReceipt::committed_at))?;
    let activated_at = optional_time(journal.activated_at())?;
    let overlap_ends_at = optional_time(journal.overlap_expires_at())?;
    let previous_revoked = optional_time(
        journal
            .old_revoke_receipt()
            .as_ref()
            .map(SecretRevokeReceipt::committed_at),
    )?;
    let compensation_revoked = optional_time(
        journal
            .compensation_receipt()
            .as_ref()
            .map(SecretRevokeReceipt::committed_at),
    )?;
    let statement = format!(
        "UPDATE account_vault_rotation_journals SET rotation_phase = {}, revision = {}, new_key_version = {}, new_stored_at = {}, activated_at = {}, overlap_ends_at = {}, previous_revoked_at = {}, compensation_revoked_at = {}, updated_at = {} WHERE tenant_id = {} AND rotation_id = {} AND revision = {};",
        sql::text(phase_label(journal.phase())),
        sql::text(&revision.get().to_string()),
        key,
        stored_at,
        activated_at,
        overlap_ends_at,
        previous_revoked,
        compensation_revoked,
        committed_at,
        sql::text(tenant.as_str()),
        sql::text(rotation_id),
        sql::text(&expected.get().to_string()),
    );
    sql::changed(sql::execute(local, statement)?)
}

fn insert_mutation(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &RotationMutationRequest,
    fingerprint: &str,
    receipt: &RotationMutationReceipt,
    committed_at: i64,
) -> Result<(), StorageError> {
    let statement = format!(
        "INSERT INTO account_vault_rotation_mutations (tenant_id, mutation_id, rotation_id, request_fingerprint_hex, transition_kind, expected_revision, prior_revision, revision, rotation_phase, committed_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {});",
        sql::text(tenant.as_str()),
        sql::text(request.mutation_id().as_str()),
        sql::text(request.rotation_id()),
        sql::text(fingerprint),
        sql::text(request.transition().as_str()),
        sql::text(&request.expected_revision().get().to_string()),
        sql::text(&receipt.prior_revision().get().to_string()),
        sql::text(&receipt.revision().get().to_string()),
        sql::text(phase_label(receipt.phase())),
        committed_at,
    );
    sql::changed(sql::execute(local, statement)?)
}

fn require_no_overlap(
    local: &mut LocalSession,
    tenant: &TenantId,
    previous: &[u8; 32],
    next: &[u8; 32],
) -> Result<(), StorageError> {
    let previous = sql::hex(previous);
    let next = sql::hex(next);
    let query = format!(
        "SELECT rotation_id FROM account_vault_rotation_journals WHERE tenant_id = {} AND rotation_phase != 'completed' AND rotation_phase != 'failed' AND (previous_reference_digest_hex = {} OR previous_reference_digest_hex = {} OR next_reference_digest_hex = {} OR next_reference_digest_hex = {}) LIMIT 1;",
        sql::text(tenant.as_str()),
        sql::text(&previous),
        sql::text(&next),
        sql::text(&previous),
        sql::text(&next),
    );
    let rows = sql::rows(sql::execute(local, query)?)?;
    if rows.rows().is_empty() {
        return Ok(());
    }
    Err(sql::conflict())
}

fn load_journal(
    local: &mut LocalSession,
    tenant: &TenantId,
    rotation_id: &str,
    custody: &dyn VaultKeyCustody,
) -> Result<Option<StoredJournal>, StorageError> {
    let query = format!(
        "SELECT {JOURNAL_PROJECTION} FROM account_vault_rotation_journals WHERE tenant_id = {} AND rotation_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(rotation_id),
    );
    let rows = sql::rows(sql::execute(local, query)?)?;
    match rows.rows() {
        [] => Ok(None),
        [row] => decode_journal(row, tenant, rotation_id, custody).map(Some),
        _ => Err(sql::integrity()),
    }
}

fn decode_journal(
    row: &Row,
    tenant: &TenantId,
    rotation_id: &str,
    custody: &dyn VaultKeyCustody,
) -> Result<StoredJournal, StorageError> {
    let values = row.values();
    require_value_count(values, 23)?;
    let plan = decode_journal_plan(values, tenant, rotation_id, custody)?;
    let state = decode_journal_state(values)?;
    let journal = reconstruct_journal(plan, state.phase, &values[16..22], state.updated_at)?;
    validate_phase_revision(state.phase, state.revision)?;
    Ok(StoredJournal {
        snapshot: RotationSnapshot::new(journal, state.revision, state.updated_at),
    })
}

fn decode_journal_plan(
    values: &[SqlValue],
    tenant: &TenantId,
    rotation_id: &str,
    custody: &dyn VaultKeyCustody,
) -> Result<CredentialRotationPlan, StorageError> {
    validate_journal_identity(values, tenant, rotation_id)?;
    let account = decode_account_id(&values[2])?;
    let previous = decode_verified_reference(&values[3], &values[4..8], custody, tenant)?;
    let next = decode_verified_reference(&values[8], &values[9..13], custody, tenant)?;
    let overlap = decode_overlap(&values[13])?;
    CredentialRotationPlan::new(account, rotation_id, previous, next, overlap)
        .map_err(|_| sql::integrity())
}

fn validate_journal_identity(
    values: &[SqlValue],
    tenant: &TenantId,
    rotation_id: &str,
) -> Result<(), StorageError> {
    sql::require_text(&values[0], tenant.as_str())?;
    sql::require_text(&values[1], rotation_id)
}

fn decode_account_id(value: &SqlValue) -> Result<AccountId, StorageError> {
    let value = sql::string(value)?;
    AccountId::parse(value).map_err(|_| sql::integrity())
}

fn decode_verified_reference(
    digest: &SqlValue,
    values: &[SqlValue],
    custody: &dyn VaultKeyCustody,
    tenant: &TenantId,
) -> Result<SecretRef, StorageError> {
    let expected = decode_digest(digest)?;
    let reference = decode_reference(values)?;
    verify_digest(custody, tenant, &reference, &expected)?;
    Ok(reference)
}

fn decode_journal_state(values: &[SqlValue]) -> Result<JournalState, StorageError> {
    Ok(JournalState {
        phase: decode_phase(&values[14])?,
        revision: decode_positive_revision(&values[15])?,
        updated_at: sql::time(&values[22])?,
    })
}

fn reconstruct_journal(
    plan: CredentialRotationPlan,
    phase: RotationPhase,
    values: &[SqlValue],
    updated_at: SystemTime,
) -> Result<RotationJournal, StorageError> {
    let evidence = decode_reconstruction_evidence(&plan, values)?;
    let mut journal = RotationJournal::new(plan);
    apply_reconstruction_evidence(&mut journal, phase, evidence, updated_at)?;
    if journal.phase() != phase {
        return Err(sql::integrity());
    }
    Ok(journal)
}

fn decode_reconstruction_evidence(
    plan: &CredentialRotationPlan,
    values: &[SqlValue],
) -> Result<ReconstructionEvidence, StorageError> {
    Ok(ReconstructionEvidence {
        store: decode_store_receipt(plan, &values[0..2])?,
        activated: optional_time_value(&values[2])?,
        overlap_end: optional_time_value(&values[3])?,
        previous_revoke: optional_revoke_receipt(plan.previous(), &values[4])?,
        compensation: optional_revoke_receipt(plan.next(), &values[5])?,
    })
}

fn apply_reconstruction_evidence(
    journal: &mut RotationJournal,
    phase: RotationPhase,
    evidence: ReconstructionEvidence,
    updated_at: SystemTime,
) -> Result<(), StorageError> {
    reconstruct_stored(journal, evidence.store, updated_at)?;
    reconstruct_activation(
        journal,
        evidence.activated,
        evidence.overlap_end,
        updated_at,
    )?;
    reconstruct_terminal(
        journal,
        phase,
        evidence.previous_revoke,
        evidence.compensation,
        updated_at,
    )
}

fn reconstruct_stored(
    journal: &mut RotationJournal,
    receipt: Option<SecretStoreReceipt>,
    updated_at: SystemTime,
) -> Result<(), StorageError> {
    if let Some(receipt) = receipt {
        journal
            .record_new_version(receipt, updated_at)
            .map_err(|_| sql::integrity())?;
    }
    Ok(())
}

fn reconstruct_activation(
    journal: &mut RotationJournal,
    activated: Option<SystemTime>,
    overlap_end: Option<SystemTime>,
    updated_at: SystemTime,
) -> Result<(), StorageError> {
    match (activated, overlap_end) {
        (None, None) => Ok(()),
        (Some(activated), Some(expected)) if activated <= updated_at => {
            journal.activate(activated).map_err(|_| sql::integrity())?;
            if journal.overlap_expires_at() != Some(expected) {
                return Err(sql::integrity());
            }
            Ok(())
        }
        _ => Err(sql::integrity()),
    }
}

fn reconstruct_terminal(
    journal: &mut RotationJournal,
    phase: RotationPhase,
    previous: Option<SecretRevokeReceipt>,
    compensation: Option<SecretRevokeReceipt>,
    updated_at: SystemTime,
) -> Result<(), StorageError> {
    match phase {
        RotationPhase::Prepared | RotationPhase::NewVersionStored | RotationPhase::Active => {
            require_no_terminal_receipts(previous, compensation)
        }
        RotationPhase::Completed => {
            reconstruct_completed(journal, previous, compensation, updated_at)
        }
        RotationPhase::Compensating => reconstruct_compensating(journal, previous, compensation),
        RotationPhase::Failed => reconstruct_failed(journal, previous, compensation, updated_at),
    }
}

fn reconstruct_completed(
    journal: &mut RotationJournal,
    previous: Option<SecretRevokeReceipt>,
    compensation: Option<SecretRevokeReceipt>,
    updated_at: SystemTime,
) -> Result<(), StorageError> {
    require_absent(compensation)?;
    journal
        .revoke_previous(previous.ok_or_else(sql::integrity)?, updated_at)
        .map_err(|_| sql::integrity())
}

fn reconstruct_compensating(
    journal: &mut RotationJournal,
    previous: Option<SecretRevokeReceipt>,
    compensation: Option<SecretRevokeReceipt>,
) -> Result<(), StorageError> {
    require_absent(previous)?;
    begin_reconstructed_compensation(journal, compensation)
}

fn reconstruct_failed(
    journal: &mut RotationJournal,
    previous: Option<SecretRevokeReceipt>,
    compensation: Option<SecretRevokeReceipt>,
    updated_at: SystemTime,
) -> Result<(), StorageError> {
    require_absent(previous)?;
    begin_reconstructed_compensation(journal, None)?;
    journal
        .record_compensation(compensation.ok_or_else(sql::integrity)?, updated_at)
        .map_err(|_| sql::integrity())
}

fn require_absent<T>(value: Option<T>) -> Result<(), StorageError> {
    if value.is_some() {
        return Err(sql::integrity());
    }
    Ok(())
}

fn require_no_terminal_receipts(
    previous: Option<SecretRevokeReceipt>,
    compensation: Option<SecretRevokeReceipt>,
) -> Result<(), StorageError> {
    if previous.is_some() || compensation.is_some() {
        return Err(sql::integrity());
    }
    Ok(())
}

fn begin_reconstructed_compensation(
    journal: &mut RotationJournal,
    compensation: Option<SecretRevokeReceipt>,
) -> Result<(), StorageError> {
    if compensation.is_some() {
        return Err(sql::integrity());
    }
    journal
        .begin_compensation()
        .map_err(|_| sql::integrity())?
        .ok_or_else(sql::integrity)
        .map(drop)
}

fn load_mutation_record(
    local: &mut LocalSession,
    tenant: &TenantId,
    mutation_id: &RotationMutationId,
) -> Result<Option<StoredMutation>, StorageError> {
    let query = format!(
        "SELECT {MUTATION_PROJECTION} FROM account_vault_rotation_mutations WHERE tenant_id = {} AND mutation_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(mutation_id.as_str()),
    );
    let rows = sql::rows(sql::execute(local, query)?)?;
    match rows.rows() {
        [] => Ok(None),
        [row] => decode_mutation(row, tenant, mutation_id).map(Some),
        _ => Err(sql::integrity()),
    }
}

fn decode_mutation(
    row: &Row,
    tenant: &TenantId,
    mutation_id: &RotationMutationId,
) -> Result<StoredMutation, StorageError> {
    let values = row.values();
    require_value_count(values, 10)?;
    validate_mutation_scope(values, tenant, mutation_id)?;
    let identity = decode_mutation_identity(values)?;
    let fields = decode_mutation_receipt_fields(values)?;
    validate_mutation_fields(&identity, &fields)?;
    Ok(StoredMutation {
        fingerprint: identity.fingerprint,
        transition: identity.transition,
        expected_revision: fields.expected_revision,
        receipt: RotationMutationReceipt::new(
            mutation_id.clone(),
            &identity.rotation_id,
            fields.prior_revision,
            fields.revision,
            fields.phase,
            fields.committed_at,
        )
        .map_err(|_| sql::integrity())?,
    })
}

fn validate_mutation_scope(
    values: &[SqlValue],
    tenant: &TenantId,
    mutation_id: &RotationMutationId,
) -> Result<(), StorageError> {
    sql::require_text(&values[0], tenant.as_str())?;
    sql::require_text(&values[1], mutation_id.as_str())
}

fn decode_mutation_identity(values: &[SqlValue]) -> Result<MutationIdentity, StorageError> {
    let rotation_id = sql::string(&values[2])?;
    require_rotation_identity(rotation_id)?;
    let fingerprint = sql::string(&values[3])?.to_owned();
    decode_digest(&values[3])?;
    let transition = sql::string(&values[4])?.into();
    Ok(MutationIdentity {
        rotation_id: rotation_id.into(),
        fingerprint,
        transition,
    })
}

fn decode_mutation_receipt_fields(
    values: &[SqlValue],
) -> Result<MutationReceiptFields, StorageError> {
    Ok(MutationReceiptFields {
        expected_revision: decode_revision(&values[5])?,
        prior_revision: decode_revision(&values[6])?,
        revision: decode_positive_revision(&values[7])?,
        phase: decode_phase(&values[8])?,
        committed_at: sql::time(&values[9])?,
    })
}

fn validate_mutation_fields(
    identity: &MutationIdentity,
    fields: &MutationReceiptFields,
) -> Result<(), StorageError> {
    let next_revision = fields.prior_revision.get().checked_add(1);
    if fields.expected_revision != fields.prior_revision
        || next_revision != Some(fields.revision.get())
        || !valid_mutation_phase(&identity.transition, fields.prior_revision, fields.phase)
    {
        return Err(sql::integrity());
    }
    Ok(())
}

fn valid_mutation_phase(
    transition: &str,
    prior_revision: RotationRevision,
    phase: RotationPhase,
) -> bool {
    expected_mutation_phase(transition) == Some(phase)
        && (transition != "prepare" || prior_revision == RotationRevision::ZERO)
}

fn expected_mutation_phase(transition: &str) -> Option<RotationPhase> {
    match transition {
        "prepare" => Some(RotationPhase::Prepared),
        "record-new-version" => Some(RotationPhase::NewVersionStored),
        "activate" => Some(RotationPhase::Active),
        "complete" => Some(RotationPhase::Completed),
        "begin-compensation" => Some(RotationPhase::Compensating),
        "record-compensation" => Some(RotationPhase::Failed),
        _ => None,
    }
}

fn require_rotation_identity(value: &str) -> Result<(), StorageError> {
    if !valid_rotation_identity(value) {
        return Err(sql::integrity());
    }
    Ok(())
}

fn valid_rotation_identity(value: &str) -> bool {
    valid_rotation_identity_bounds(value) && value.bytes().all(valid_rotation_identity_byte)
}

fn valid_rotation_identity_bounds(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= ariadnion_account_vault::MAX_ROTATION_ID_BYTES
        && value.is_ascii()
}

fn valid_rotation_identity_byte(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte)
}

fn validate_phase_revision(
    phase: RotationPhase,
    revision: RotationRevision,
) -> Result<(), StorageError> {
    let revision = revision.get();
    let valid = match phase {
        RotationPhase::Prepared => revision == 1,
        RotationPhase::NewVersionStored => revision == 2,
        RotationPhase::Active => revision == 3,
        RotationPhase::Completed => revision == 4,
        RotationPhase::Compensating => matches!(revision, 3 | 4),
        RotationPhase::Failed => matches!(revision, 4 | 5),
    };
    require_integrity(valid)
}

fn decode_reference(values: &[SqlValue]) -> Result<SecretRef, StorageError> {
    require_value_count(values, 4)?;
    let provider = decode_provider(&values[0])?;
    let path = decode_path(&values[1])?;
    let version = decode_secret_version(&values[2])?;
    let purpose = decode_purpose(&values[3])?;
    Ok(SecretRef::new(provider, path, version, purpose))
}

fn decode_provider(value: &SqlValue) -> Result<SecretProvider, StorageError> {
    let value = sql::string(value)?;
    SecretProvider::parse(value).map_err(|_| sql::integrity())
}

fn decode_path(value: &SqlValue) -> Result<SecretPath, StorageError> {
    let value = sql::string(value)?;
    SecretPath::parse(value).map_err(|_| sql::integrity())
}

fn decode_secret_version(value: &SqlValue) -> Result<SecretVersion, StorageError> {
    let value = sql::unsigned_text(value)?;
    SecretVersion::new(value).map_err(|_| sql::integrity())
}

fn decode_purpose(value: &SqlValue) -> Result<SecretPurpose, StorageError> {
    let value = sql::string(value)?;
    SecretPurpose::parse(value).map_err(|_| sql::integrity())
}

fn decode_store_receipt(
    plan: &CredentialRotationPlan,
    values: &[SqlValue],
) -> Result<Option<SecretStoreReceipt>, StorageError> {
    match (&values[0], &values[1]) {
        (SqlValue::Null, SqlValue::Null) => Ok(None),
        (key, stored_at) => {
            let key = u64::try_from(sql::integer(key)?).map_err(|_| sql::integrity())?;
            let key = VaultKeyVersion::new(key).map_err(|_| sql::integrity())?;
            Ok(Some(SecretStoreReceipt::new(
                plan.next().clone(),
                plan.next().version(),
                key,
                sql::time(stored_at)?,
            )))
        }
    }
}

fn optional_revoke_receipt(
    reference: &SecretRef,
    value: &SqlValue,
) -> Result<Option<SecretRevokeReceipt>, StorageError> {
    optional_time_value(value).map(|value| {
        value.map(|committed_at| {
            SecretRevokeReceipt::new(reference.clone(), reference.version(), committed_at)
        })
    })
}

fn decode_overlap(value: &SqlValue) -> Result<RotationWindow, StorageError> {
    let seconds = u64::try_from(sql::integer(value)?).map_err(|_| sql::integrity())?;
    RotationWindow::new(Duration::from_secs(seconds)).map_err(|_| sql::integrity())
}

fn decode_phase(value: &SqlValue) -> Result<RotationPhase, StorageError> {
    let value = sql::string(value)?;
    parse_phase(value)
}

fn parse_phase(value: &str) -> Result<RotationPhase, StorageError> {
    match value {
        "prepared" => Ok(RotationPhase::Prepared),
        "new-version-stored" => Ok(RotationPhase::NewVersionStored),
        "active" => Ok(RotationPhase::Active),
        "completed" => Ok(RotationPhase::Completed),
        "compensating" => Ok(RotationPhase::Compensating),
        "failed" => Ok(RotationPhase::Failed),
        _ => Err(sql::integrity()),
    }
}

const fn phase_label(phase: RotationPhase) -> &'static str {
    match phase {
        RotationPhase::Prepared => "prepared",
        RotationPhase::NewVersionStored => "new-version-stored",
        RotationPhase::Active => "active",
        RotationPhase::Completed => "completed",
        RotationPhase::Compensating => "compensating",
        RotationPhase::Failed => "failed",
    }
}

fn decode_revision(value: &SqlValue) -> Result<RotationRevision, StorageError> {
    let text = sql::string(value)?;
    let parsed = text.parse::<u64>().map_err(|_| sql::integrity())?;
    if parsed.to_string() != text {
        return Err(sql::integrity());
    }
    Ok(RotationRevision::new(parsed))
}

fn decode_positive_revision(value: &SqlValue) -> Result<RotationRevision, StorageError> {
    let revision = decode_revision(value)?;
    if revision == RotationRevision::ZERO {
        return Err(sql::integrity());
    }
    Ok(revision)
}

fn decode_digest(value: &SqlValue) -> Result<[u8; 32], StorageError> {
    let bytes = sql::decode_hex(sql::string(value)?, 32)?;
    bytes.as_slice().try_into().map_err(|_| sql::integrity())
}

fn verify_digest(
    custody: &dyn VaultKeyCustody,
    tenant: &TenantId,
    reference: &SecretRef,
    expected: &[u8; 32],
) -> Result<(), StorageError> {
    if &reference_digest(custody, tenant, reference)? != expected {
        return Err(sql::integrity());
    }
    Ok(())
}

fn reference_digest(
    custody: &dyn VaultKeyCustody,
    tenant: &TenantId,
    reference: &SecretRef,
) -> Result<[u8; 32], StorageError> {
    custody
        .reference_digest(tenant, reference)
        .map_err(custody_error)
}

fn fingerprint_request(
    tenant: &TenantId,
    request: &RotationMutationRequest,
    key: &[u8; 32],
) -> Result<String, StorageError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| sql::integrity())?;
    frame(&mut mac, FINGERPRINT_DOMAIN);
    frame(&mut mac, tenant.as_str().as_bytes());
    frame(&mut mac, request.mutation_id().as_str().as_bytes());
    frame(&mut mac, request.rotation_id().as_bytes());
    frame(&mut mac, &request.expected_revision().get().to_be_bytes());
    frame(&mut mac, request.transition().as_str().as_bytes());
    frame_transition(&mut mac, request.transition())?;
    Ok(sql::hex(&mac.finalize().into_bytes()))
}

fn frame_transition(
    mac: &mut Hmac<Sha256>,
    transition: &RotationTransition,
) -> Result<(), StorageError> {
    match transition {
        RotationTransition::Prepare(plan) => frame_plan(mac, plan),
        RotationTransition::RecordNewVersion(receipt) => frame_store_receipt(mac, receipt),
        RotationTransition::Activate(at) => frame_time(mac, *at),
        RotationTransition::Complete(receipt) | RotationTransition::RecordCompensation(receipt) => {
            frame_revoke_receipt(mac, receipt)
        }
        RotationTransition::BeginCompensation => Ok(()),
    }
}

fn frame_plan(mac: &mut Hmac<Sha256>, plan: &CredentialRotationPlan) -> Result<(), StorageError> {
    frame(mac, plan.account_id().as_str().as_bytes());
    frame_reference(mac, plan.previous());
    frame_reference(mac, plan.next());
    frame(mac, &plan.overlap().duration().as_secs().to_be_bytes());
    Ok(())
}

fn frame_store_receipt(
    mac: &mut Hmac<Sha256>,
    receipt: &SecretStoreReceipt,
) -> Result<(), StorageError> {
    frame_reference(mac, receipt.reference());
    frame(mac, &receipt.version().get().to_be_bytes());
    frame(mac, &receipt.key_version().get().to_be_bytes());
    frame_time(mac, receipt.committed_at())
}

fn frame_revoke_receipt(
    mac: &mut Hmac<Sha256>,
    receipt: &SecretRevokeReceipt,
) -> Result<(), StorageError> {
    frame_reference(mac, receipt.reference());
    frame(mac, &receipt.version().get().to_be_bytes());
    frame_time(mac, receipt.committed_at())
}

fn frame_reference(mac: &mut Hmac<Sha256>, reference: &SecretRef) {
    frame(mac, reference.provider().as_str().as_bytes());
    frame(mac, reference.path().as_str().as_bytes());
    frame(mac, &reference.version().get().to_be_bytes());
    frame(mac, reference.purpose().as_str().as_bytes());
}

fn frame_time(mac: &mut Hmac<Sha256>, value: SystemTime) -> Result<(), StorageError> {
    let value = sql::time_encode(value)?;
    frame(mac, &value.to_be_bytes());
    Ok(())
}

fn frame(mac: &mut Hmac<Sha256>, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn optional_key(receipt: Option<&SecretStoreReceipt>) -> Result<String, StorageError> {
    receipt
        .map(|value| {
            i64::try_from(value.key_version().get())
                .map(|value| value.to_string())
                .map_err(|_| sql::exhausted())
        })
        .unwrap_or_else(|| Ok("NULL".to_owned()))
}

fn optional_time(value: Option<SystemTime>) -> Result<String, StorageError> {
    value
        .map(|value| sql::time_encode(value).map(|value| value.to_string()))
        .unwrap_or_else(|| Ok("NULL".to_owned()))
}

fn optional_time_value(value: &SqlValue) -> Result<Option<SystemTime>, StorageError> {
    if value == &SqlValue::Null {
        return Ok(None);
    }
    sql::time(value).map(Some)
}

fn require_value_count(values: &[SqlValue], expected: usize) -> Result<(), StorageError> {
    require_integrity(values.len() == expected)
}

fn require_integrity(condition: bool) -> Result<(), StorageError> {
    if !condition {
        return Err(sql::integrity());
    }
    Ok(())
}

fn custody_error(error: VaultError) -> StorageError {
    match error.code() {
        VaultErrorCode::InvalidArgument => StorageError::new(StorageErrorCode::InvalidArgument),
        VaultErrorCode::ResourceExhausted | VaultErrorCode::LimitExceeded => {
            StorageError::new(StorageErrorCode::ResourceExhausted)
        }
        VaultErrorCode::Unavailable => StorageError::new(StorageErrorCode::Unavailable),
        _ => sql::integrity(),
    }
}

fn domain_error(error: VaultError) -> StorageError {
    match error.code() {
        VaultErrorCode::InvalidArgument => StorageError::new(StorageErrorCode::InvalidArgument),
        VaultErrorCode::Conflict => StorageError::new(StorageErrorCode::Conflict),
        VaultErrorCode::LimitExceeded | VaultErrorCode::ResourceExhausted => {
            StorageError::new(StorageErrorCode::ResourceExhausted)
        }
        _ => sql::integrity(),
    }
}

// crates/optional/ariadnion-storage-rnmdb/src/account_import_repository/codec.rs - Account import persistence logic for Ariadnion.
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
//! Canonical request fingerprints and strict durable account-import decoding.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_account_domain::{AccountId, AccountStatus};
use ariadnion_account_import::{
    ConflictStrategy, DurablePublishReceipt, DurablePublishRequest, ImportEntry, ImportGeneration,
    ImportMutationId, MAX_IMPORT_ENTRIES, OpaqueDigest,
};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::StorageError;
use hmac::{Hmac, Mac};
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::sql;
use crate::identity_transaction::require_active_identity_transaction;
use crate::session::check_context;

const GENERATION_PROJECTION: &str = "tenant_id, generation, published_at";
const MUTATION_PROJECTION: &str = "tenant_id, mutation_id, request_fingerprint_hex, expected_generation, committed_generation, published_count, committed_at";
const ACCOUNT_STATE_PROJECTION: &str =
    "tenant_id, account_id, config_version, account_version, account_status, import_generation";
const FINGERPRINT_DOMAIN: &[u8] = b"ariadnion.account-import.publish-intent.hmac-sha256.v2";
const PROVISIONING_POLICY: &[u8] = b"minimal-provisioning-v1";
const REPLACEMENT_POLICY: &[u8] = b"advance-config-and-account-versions-preserve-status-v1";
const INITIAL_VERSION: u64 = 1;
const INITIAL_MAX_CONCURRENCY: u32 = 1;
const INITIAL_STATUS: &str = "provisioning";

pub(super) struct StoredMutation {
    fingerprint: Zeroizing<String>,
    mutation_id: ImportMutationId,
    generation: ImportGeneration,
    published_count: usize,
    committed_at: SystemTime,
}

impl StoredMutation {
    pub(super) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(super) fn into_receipt(self) -> Result<DurablePublishReceipt, StorageError> {
        DurablePublishReceipt::new(
            self.mutation_id,
            self.generation,
            self.published_count,
            self.committed_at,
        )
        .map_err(|_| sql::integrity())
    }
}

struct ExistingAccount {
    config_version: u64,
    account_version: u64,
    status: AccountStatus,
}

pub(super) fn publish(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &DurablePublishRequest,
    context: &RequestContext,
    fingerprint_key: &[u8],
    publication_boundary: impl FnOnce() -> Result<SystemTime, StorageError>,
) -> Result<DurablePublishReceipt, StorageError> {
    require_active_identity_transaction(session)?;
    let fingerprint = request_fingerprint(tenant, request, fingerprint_key)?;
    if let Some(stored) = load_mutation(session, tenant, request.mutation_id())? {
        return replay(stored, &fingerprint);
    }
    publish_new(
        session,
        tenant,
        request,
        context,
        &fingerprint,
        publication_boundary,
    )
}

fn publish_new(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &DurablePublishRequest,
    context: &RequestContext,
    fingerprint: &str,
    publication_boundary: impl FnOnce() -> Result<SystemTime, StorageError>,
) -> Result<DurablePublishReceipt, StorageError> {
    let pending = prepare_new_publication(session, tenant, request, context)?;
    check_context(context)?;
    let (committed_at_raw, committed_at) = publication_boundary().and_then(publication_time)?;
    persist_initial_events(
        session,
        tenant,
        request.mutation_id(),
        committed_at_raw,
        &pending.effects.inserted_accounts,
        context,
    )?;
    persist_generation(
        session,
        tenant,
        pending.previous,
        pending.committed,
        committed_at_raw,
    )?;
    persist_mutation(
        session,
        tenant,
        request,
        fingerprint,
        pending.committed,
        pending.effects.published_count,
        committed_at_raw,
    )?;
    DurablePublishReceipt::new(
        request.mutation_id().clone(),
        pending.committed,
        pending.effects.published_count,
        committed_at,
    )
    .map_err(|_| sql::integrity())
}

struct PendingPublication {
    previous: ImportGeneration,
    committed: ImportGeneration,
    effects: AppliedCounts,
}

fn prepare_new_publication(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &DurablePublishRequest,
    context: &RequestContext,
) -> Result<PendingPublication, StorageError> {
    let expected = request.intent().expected_generation();
    let current = load_generation(session, tenant)?;
    if current != expected {
        return Err(sql::conflict());
    }
    let committed = next_generation(current)?;
    let effects = apply_entries(session, tenant, request, committed, context)?;
    Ok(PendingPublication {
        previous: current,
        committed,
        effects,
    })
}

fn replay(
    stored: StoredMutation,
    request_fingerprint: &str,
) -> Result<DurablePublishReceipt, StorageError> {
    if stored.fingerprint() != request_fingerprint {
        return Err(sql::conflict());
    }
    stored.into_receipt()
}

fn next_generation(current: ImportGeneration) -> Result<ImportGeneration, StorageError> {
    current
        .get()
        .checked_add(1)
        .map(ImportGeneration::new)
        .ok_or_else(sql::exhausted)
}

fn apply_entries(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &DurablePublishRequest,
    generation: ImportGeneration,
    context: &RequestContext,
) -> Result<AppliedCounts, StorageError> {
    let mut counts = AppliedCounts {
        published_count: 0,
        inserted_accounts: Vec::new(),
    };
    for entry in request.intent().entries() {
        check_context(context)?;
        let effect = apply_entry(
            session,
            tenant,
            request.intent().strategy(),
            entry,
            generation,
        )?;
        counts.record(effect, entry.account_id())?;
    }
    Ok(counts)
}

struct AppliedCounts {
    published_count: usize,
    inserted_accounts: Vec<AccountId>,
}

impl AppliedCounts {
    fn record(&mut self, effect: EntryEffect, account_id: &AccountId) -> Result<(), StorageError> {
        if matches!(effect, EntryEffect::Skipped) {
            return Ok(());
        }
        self.published_count = self
            .published_count
            .checked_add(1)
            .ok_or_else(sql::exhausted)?;
        if matches!(effect, EntryEffect::Inserted) {
            self.inserted_accounts.push(account_id.clone());
        }
        Ok(())
    }
}

enum EntryEffect {
    Inserted,
    Replaced,
    Skipped,
}

fn apply_entry(
    session: &mut LocalSession,
    tenant: &TenantId,
    strategy: ConflictStrategy,
    entry: &ImportEntry,
    generation: ImportGeneration,
) -> Result<EntryEffect, StorageError> {
    let existing = load_account_state(session, tenant, entry.account_id())?;
    match (existing, strategy) {
        (None, _) => {
            insert_entry(session, tenant, entry, generation).map(|()| EntryEffect::Inserted)
        }
        (Some(_), ConflictStrategy::Reject) => Err(sql::conflict()),
        (Some(_), ConflictStrategy::SkipExisting) => Ok(EntryEffect::Skipped),
        (Some(existing), ConflictStrategy::ReplaceExisting) => {
            replace_account(session, tenant, entry, generation, existing)
                .map(|()| EntryEffect::Replaced)
        }
    }
}

fn insert_entry(
    session: &mut LocalSession,
    tenant: &TenantId,
    entry: &ImportEntry,
    generation: ImportGeneration,
) -> Result<(), StorageError> {
    insert_account(session, tenant, entry, generation)
}

fn insert_account(
    session: &mut LocalSession,
    tenant: &TenantId,
    entry: &ImportEntry,
    generation: ImportGeneration,
) -> Result<(), StorageError> {
    let secret = entry.secret_ref();
    let statement = format!(
        "INSERT INTO account_registry_accounts (tenant_id, account_id, provider_id, provider_label, account_label, external_account_id, config_version, secret_provider, secret_path, secret_version, secret_purpose, credential_digest_hex, default_model, max_concurrency, account_version, account_status, import_generation) VALUES ({}, {}, {}, {}, {}, NULL, {}, {}, {}, {}, {}, {}, NULL, {}, {}, {}, {});",
        sql::text(tenant.as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(entry.provider_id().as_str()),
        sql::text(entry.provider_id().as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(&INITIAL_VERSION.to_string()),
        sql::text(secret.provider().as_str()),
        sql::text(secret.path().as_str()),
        sql::text(&secret.version().get().to_string()),
        sql::text(secret.purpose().as_str()),
        sql::text(&digest_hex(entry.credential_digest())),
        INITIAL_MAX_CONCURRENCY,
        sql::text(&INITIAL_VERSION.to_string()),
        sql::text(INITIAL_STATUS),
        sql::text(&generation.get().to_string()),
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

fn persist_initial_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    mutation_id: &ImportMutationId,
    publication_time: i64,
    account_ids: &[AccountId],
    context: &RequestContext,
) -> Result<(), StorageError> {
    for account_id in account_ids {
        check_context(context)?;
        persist_initial_event(session, tenant, account_id, mutation_id, publication_time)?;
    }
    Ok(())
}

fn persist_initial_event(
    session: &mut LocalSession,
    tenant: &TenantId,
    account_id: &AccountId,
    mutation_id: &ImportMutationId,
    publication_time: i64,
) -> Result<(), StorageError> {
    let statement = format!(
        "INSERT INTO account_lifecycle_events (tenant_id, account_id, account_version, from_status, to_status, source_kind, source_id, committed_at) VALUES ({}, {}, {}, NULL, {}, 'account_import', {}, {});",
        sql::text(tenant.as_str()),
        sql::text(account_id.as_str()),
        sql::text(&INITIAL_VERSION.to_string()),
        sql::text(INITIAL_STATUS),
        sql::text(mutation_id.as_str()),
        publication_time,
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

fn replace_account(
    session: &mut LocalSession,
    tenant: &TenantId,
    entry: &ImportEntry,
    generation: ImportGeneration,
    existing: ExistingAccount,
) -> Result<(), StorageError> {
    let config_version = existing
        .config_version
        .checked_add(1)
        .ok_or_else(sql::exhausted)?;
    let account_version = existing
        .account_version
        .checked_add(1)
        .ok_or_else(sql::exhausted)?;
    let secret = entry.secret_ref();
    let statement = format!(
        "UPDATE account_registry_accounts SET provider_id = {}, provider_label = {}, account_label = {}, external_account_id = NULL, config_version = {}, secret_provider = {}, secret_path = {}, secret_version = {}, secret_purpose = {}, credential_digest_hex = {}, default_model = NULL, max_concurrency = {}, account_version = {}, import_generation = {} WHERE tenant_id = {} AND account_id = {} AND config_version = {} AND account_version = {} AND account_status = {};",
        sql::text(entry.provider_id().as_str()),
        sql::text(entry.provider_id().as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(&config_version.to_string()),
        sql::text(secret.provider().as_str()),
        sql::text(secret.path().as_str()),
        sql::text(&secret.version().get().to_string()),
        sql::text(secret.purpose().as_str()),
        sql::text(&digest_hex(entry.credential_digest())),
        INITIAL_MAX_CONCURRENCY,
        sql::text(&account_version.to_string()),
        sql::text(&generation.get().to_string()),
        sql::text(tenant.as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(&existing.config_version.to_string()),
        sql::text(&existing.account_version.to_string()),
        sql::text(status_label(existing.status)),
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

fn persist_generation(
    session: &mut LocalSession,
    tenant: &TenantId,
    previous: ImportGeneration,
    committed: ImportGeneration,
    committed_at: i64,
) -> Result<(), StorageError> {
    let statement = if previous == ImportGeneration::initial() {
        format!(
            "INSERT INTO account_registry_generations (tenant_id, generation, published_at) VALUES ({}, {}, {});",
            sql::text(tenant.as_str()),
            sql::text(&committed.get().to_string()),
            committed_at,
        )
    } else {
        format!(
            "UPDATE account_registry_generations SET generation = {}, published_at = {} WHERE tenant_id = {} AND generation = {};",
            sql::text(&committed.get().to_string()),
            committed_at,
            sql::text(tenant.as_str()),
            sql::text(&previous.get().to_string()),
        )
    };
    sql::require_rows(sql::execute(session, statement)?, 1)
}

fn persist_mutation(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &DurablePublishRequest,
    fingerprint: &str,
    committed: ImportGeneration,
    published_count: usize,
    committed_at: i64,
) -> Result<(), StorageError> {
    let published_count = i64::try_from(published_count).map_err(|_| sql::exhausted())?;
    let statement = format!(
        "INSERT INTO account_import_mutations (tenant_id, mutation_id, request_fingerprint_hex, expected_generation, committed_generation, published_count, committed_at) VALUES ({}, {}, {}, {}, {}, {}, {});",
        sql::text(tenant.as_str()),
        sql::text(request.mutation_id().as_str()),
        sql::text(fingerprint),
        sql::text(&request.intent().expected_generation().get().to_string()),
        sql::text(&committed.get().to_string()),
        published_count,
        committed_at,
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

pub(super) fn load_generation(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<ImportGeneration, StorageError> {
    let query = format!(
        "SELECT {GENERATION_PROJECTION} FROM account_registry_generations WHERE tenant_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
    );
    let batch = sql::rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(ImportGeneration::initial()),
        [row] => decode_generation(row, tenant),
        _ => Err(sql::integrity()),
    }
}

fn decode_generation(
    row: &Row,
    expected_tenant: &TenantId,
) -> Result<ImportGeneration, StorageError> {
    let values = row.values();
    if values.len() != 3 {
        return Err(sql::integrity());
    }
    require_tenant(&values[0], expected_tenant)?;
    let generation = sql::parse_u64_text(&values[1])?;
    if generation == 0 {
        return Err(sql::integrity());
    }
    let _published_at = decode_time(&values[2])?;
    Ok(ImportGeneration::new(generation))
}

pub(super) fn load_mutation(
    session: &mut LocalSession,
    tenant: &TenantId,
    mutation_id: &ImportMutationId,
) -> Result<Option<StoredMutation>, StorageError> {
    let query = format!(
        "SELECT {MUTATION_PROJECTION} FROM account_import_mutations WHERE tenant_id = {} AND mutation_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(mutation_id.as_str()),
    );
    let batch = sql::rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_mutation(row, tenant, mutation_id).map(Some),
        _ => Err(sql::integrity()),
    }
}

fn decode_mutation(
    row: &Row,
    expected_tenant: &TenantId,
    expected_mutation: &ImportMutationId,
) -> Result<StoredMutation, StorageError> {
    let values = sql::row_values::<7>(row)?;
    require_tenant(&values[0], expected_tenant)?;
    let mutation_id = require_mutation(&values[1], expected_mutation)?;
    let fingerprint = decode_fingerprint(&values[2])?;
    let generation = decode_mutation_generation(&values[3], &values[4])?;
    let published_count = decode_published_count(&values[5])?;
    Ok(StoredMutation {
        fingerprint,
        mutation_id,
        generation,
        published_count,
        committed_at: decode_time(&values[6])?,
    })
}

fn require_mutation(
    value: &rnmdb_types::SqlValue,
    expected_mutation: &ImportMutationId,
) -> Result<ImportMutationId, StorageError> {
    let mutation_id =
        ImportMutationId::parse(sql::text_value(value)?).map_err(|_| sql::integrity())?;
    if &mutation_id != expected_mutation {
        return Err(sql::integrity());
    }
    Ok(mutation_id)
}

fn decode_fingerprint(value: &rnmdb_types::SqlValue) -> Result<Zeroizing<String>, StorageError> {
    let fingerprint = sql::text_value(value)?;
    if !valid_fingerprint(fingerprint) {
        return Err(sql::integrity());
    }
    Ok(Zeroizing::new(fingerprint.to_owned()))
}

fn decode_mutation_generation(
    expected: &rnmdb_types::SqlValue,
    committed: &rnmdb_types::SqlValue,
) -> Result<ImportGeneration, StorageError> {
    let expected_generation = sql::parse_u64_text(expected)?;
    let committed_generation = sql::parse_u64_text(committed)?;
    if expected_generation.checked_add(1) != Some(committed_generation) {
        return Err(sql::integrity());
    }
    Ok(ImportGeneration::new(committed_generation))
}

fn decode_published_count(value: &rnmdb_types::SqlValue) -> Result<usize, StorageError> {
    let published_count = sql::usize_from_i64(value)?;
    if published_count > MAX_IMPORT_ENTRIES {
        return Err(sql::integrity());
    }
    Ok(published_count)
}

fn load_account_state(
    session: &mut LocalSession,
    tenant: &TenantId,
    account_id: &AccountId,
) -> Result<Option<ExistingAccount>, StorageError> {
    let query = format!(
        "SELECT {ACCOUNT_STATE_PROJECTION} FROM account_registry_accounts WHERE tenant_id = {} AND account_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(account_id.as_str()),
    );
    let batch = sql::rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_account_state(row, tenant, account_id).map(Some),
        _ => Err(sql::integrity()),
    }
}

fn decode_account_state(
    row: &Row,
    expected_tenant: &TenantId,
    expected_account: &AccountId,
) -> Result<ExistingAccount, StorageError> {
    let values = sql::row_values::<6>(row)?;
    require_tenant(&values[0], expected_tenant)?;
    require_account(&values[1], expected_account)?;
    let (config_version, account_version) = decode_account_versions(values)?;
    let status = decode_status(sql::text_value(&values[4])?)?;
    validate_account_lifecycle(status, account_version)?;
    Ok(ExistingAccount {
        config_version,
        account_version,
        status,
    })
}

fn require_account(
    value: &rnmdb_types::SqlValue,
    expected_account: &AccountId,
) -> Result<(), StorageError> {
    let account_id = AccountId::parse(sql::text_value(value)?).map_err(|_| sql::integrity())?;
    if &account_id != expected_account {
        return Err(sql::integrity());
    }
    Ok(())
}

fn decode_account_versions(
    values: &[rnmdb_types::SqlValue; 6],
) -> Result<(u64, u64), StorageError> {
    let config_version = nonzero_text_version(&values[2])?;
    let account_version = nonzero_text_version(&values[3])?;
    let _import_generation = nonzero_text_version(&values[5])?;
    Ok((config_version, account_version))
}

fn validate_account_lifecycle(
    status: AccountStatus,
    account_version: u64,
) -> Result<(), StorageError> {
    if status == AccountStatus::Deleted && account_version == INITIAL_VERSION {
        return Err(sql::integrity());
    }
    Ok(())
}

fn nonzero_text_version(value: &rnmdb_types::SqlValue) -> Result<u64, StorageError> {
    let version = sql::parse_u64_text(value)?;
    if version == 0 {
        return Err(sql::integrity());
    }
    Ok(version)
}

fn require_tenant(value: &rnmdb_types::SqlValue, expected: &TenantId) -> Result<(), StorageError> {
    let tenant = TenantId::parse(sql::text_value(value)?).map_err(|_| sql::integrity())?;
    if &tenant != expected {
        return Err(sql::integrity());
    }
    Ok(())
}

fn decode_status(value: &str) -> Result<AccountStatus, StorageError> {
    match value {
        "provisioning" => Ok(AccountStatus::Provisioning),
        "active" => Ok(AccountStatus::Active),
        "suspended" => Ok(AccountStatus::Suspended),
        "revoked" => Ok(AccountStatus::Revoked),
        "deleted" => Ok(AccountStatus::Deleted),
        _ => Err(sql::integrity()),
    }
}

const fn status_label(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Provisioning => "provisioning",
        AccountStatus::Active => "active",
        AccountStatus::Suspended => "suspended",
        AccountStatus::Revoked => "revoked",
        AccountStatus::Deleted => "deleted",
    }
}

fn publication_time(time: SystemTime) -> Result<(i64, SystemTime), StorageError> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| sql::integrity())?
        .as_secs();
    let raw = i64::try_from(seconds).map_err(|_| sql::exhausted())?;
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(sql::exhausted)?;
    Ok((raw, time))
}

fn decode_time(value: &rnmdb_types::SqlValue) -> Result<SystemTime, StorageError> {
    let seconds = sql::u64_from_i64(value)?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(sql::integrity)
}

fn request_fingerprint(
    tenant: &TenantId,
    request: &DurablePublishRequest,
    key: &[u8],
) -> Result<Zeroizing<String>, StorageError> {
    let mut hash = Hmac::<Sha256>::new_from_slice(key).map_err(|_| sql::integrity())?;
    push_frame(&mut hash, FINGERPRINT_DOMAIN);
    push_frame(&mut hash, tenant.as_str().as_bytes());
    push_frame(&mut hash, request.mutation_id().as_str().as_bytes());
    let intent = request.intent();
    push_frame(&mut hash, &intent.expected_generation().get().to_be_bytes());
    push_frame(&mut hash, strategy_label(intent.strategy()).as_bytes());
    push_frame(&mut hash, PROVISIONING_POLICY);
    push_frame(&mut hash, REPLACEMENT_POLICY);
    let count = u64::try_from(intent.entries().len()).map_err(|_| sql::exhausted())?;
    push_frame(&mut hash, &count.to_be_bytes());
    for entry in intent.entries() {
        fingerprint_entry(&mut hash, entry);
    }
    Ok(Zeroizing::new(bytes_hex(&hash.finalize().into_bytes())))
}

fn fingerprint_entry(hash: &mut Hmac<Sha256>, entry: &ImportEntry) {
    let secret = entry.secret_ref();
    push_frame(hash, entry.account_id().as_str().as_bytes());
    push_frame(hash, entry.provider_id().as_str().as_bytes());
    push_frame(hash, entry.provider_id().as_str().as_bytes());
    push_frame(hash, entry.account_id().as_str().as_bytes());
    push_frame(hash, b"external-account-id:none");
    push_frame(hash, &INITIAL_VERSION.to_be_bytes());
    push_frame(hash, secret.provider().as_str().as_bytes());
    push_frame(hash, secret.path().as_str().as_bytes());
    push_frame(hash, &secret.version().get().to_be_bytes());
    push_frame(hash, secret.purpose().as_str().as_bytes());
    push_frame(hash, &entry.credential_digest().as_bytes());
    push_frame(hash, b"default-model:none");
    push_frame(hash, &INITIAL_MAX_CONCURRENCY.to_be_bytes());
    push_frame(hash, &INITIAL_VERSION.to_be_bytes());
    push_frame(hash, INITIAL_STATUS.as_bytes());
}

fn push_frame(hash: &mut Hmac<Sha256>, value: &[u8]) {
    hash.update(&(value.len() as u64).to_be_bytes());
    hash.update(value);
}

const fn strategy_label(strategy: ConflictStrategy) -> &'static str {
    match strategy {
        ConflictStrategy::Reject => "reject",
        ConflictStrategy::SkipExisting => "skip-existing",
        ConflictStrategy::ReplaceExisting => "replace-existing",
    }
}

fn digest_hex(digest: OpaqueDigest) -> Zeroizing<String> {
    Zeroizing::new(bytes_hex(&digest.as_bytes()))
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

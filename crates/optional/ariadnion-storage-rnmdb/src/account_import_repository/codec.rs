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
//! Strict durable account-import decoding and transaction-scoped persistence.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_account_domain::{
    AccountEffectiveWindow, AccountId, AccountStatus, ModelName, ProviderId, SecretPath,
    SecretProvider, SecretPurpose, SecretRef, SecretVersion,
};
use ariadnion_account_import::{
    AccountCredentialReference, AccountCredentialReferenceRequest, AccountProjectionRequest,
    AccountProjectionSnapshot, ConflictStrategy, DurableAccountIdentity, DurableAccountProjection,
    DurableAccountState, DurablePublishReceipt, DurablePublishRequest, DurableRoutingState,
    ImportEntry, ImportGeneration, ImportMutationId, MAX_ACCOUNT_PROJECTION_ACCOUNTS,
    MAX_IMPORT_ENTRIES, OpaqueDigest,
};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;
use zeroize::Zeroizing;

use super::{effective_window, fingerprint, routing_policy, sql};
use crate::identity_transaction::require_active_identity_transaction;
use crate::session::check_context;

const GENERATION_PROJECTION: &str = "tenant_id, generation, published_at";
const MUTATION_PROJECTION: &str = "tenant_id, mutation_id, request_fingerprint_hex, expected_generation, committed_generation, published_count, committed_at";
const ACCOUNT_STATE_PROJECTION: &str =
    "tenant_id, account_id, config_version, account_version, account_status, import_generation";
const ROUTING_PROJECTION: &str = "tenant_id, account_id, provider_id, default_model, max_concurrency, config_version, account_version, account_status, import_generation";
const CREDENTIAL_REFERENCE_PROJECTION: &str = "tenant_id, account_id, provider_id, config_version, secret_provider, secret_path, secret_version, secret_purpose, account_status, import_generation";
const INITIAL_VERSION: u64 = 1;
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
    let fingerprint = fingerprint::request(tenant, request, fingerprint_key)?;
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

pub(super) fn load_projection_snapshot(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &AccountProjectionRequest,
    context: &RequestContext,
) -> Result<AccountProjectionSnapshot, StorageError> {
    require_active_identity_transaction(session)?;
    let generation = require_projection_generation(session, tenant, request)?;
    let batch = load_projection_rows(session, tenant)?;
    let mut routing = routing_policy::load_for_tenant(session, tenant, context)?;
    let mut windows = effective_window::load_for_tenant(session, tenant, context)?;
    let accounts = decode_projection_rows(
        batch.rows(),
        tenant,
        generation,
        &mut routing,
        &mut windows,
        context,
    )?;
    require_consumed_projection_metadata(&routing, &windows)?;
    AccountProjectionSnapshot::new(generation, accounts).map_err(|_| sql::integrity())
}

fn require_consumed_projection_metadata(
    routing: &routing_policy::RoutingPolicies,
    windows: &effective_window::EffectiveWindows,
) -> Result<(), StorageError> {
    if !routing.is_empty() || !windows.is_empty() {
        return Err(sql::integrity());
    }
    Ok(())
}

pub(super) fn load_credential_reference(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &AccountCredentialReferenceRequest,
    context: &RequestContext,
) -> Result<AccountCredentialReference, StorageError> {
    require_active_identity_transaction(session)?;
    let (generation, batch) = load_credential_reference_data(session, tenant, request, context)?;
    let row = require_credential_reference_row(batch.rows())?;
    let reference = decode_credential_reference(row, tenant, request, generation)?;
    check_context(context)?;
    Ok(reference)
}

fn load_credential_reference_data(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &AccountCredentialReferenceRequest,
    context: &RequestContext,
) -> Result<(ImportGeneration, rnmdb_executor::vector::VectorBatch), StorageError> {
    check_context(context)?;
    let generation = require_expected_generation(session, tenant, request.expected_generation())?;
    let batch = load_credential_reference_rows(session, tenant, request.account_id())?;
    check_context(context)?;
    Ok((generation, batch))
}

fn require_projection_generation(
    session: &mut LocalSession,
    tenant: &TenantId,
    request: &AccountProjectionRequest,
) -> Result<ImportGeneration, StorageError> {
    require_expected_generation(session, tenant, request.expected_generation())
}

fn require_expected_generation(
    session: &mut LocalSession,
    tenant: &TenantId,
    expected_generation: ImportGeneration,
) -> Result<ImportGeneration, StorageError> {
    let generation = load_generation(session, tenant)?;
    if generation != expected_generation {
        return Err(sql::conflict());
    }
    Ok(generation)
}

fn load_credential_reference_rows(
    session: &mut LocalSession,
    tenant: &TenantId,
    account_id: &AccountId,
) -> Result<rnmdb_executor::vector::VectorBatch, StorageError> {
    let query = format!(
        "SELECT {CREDENTIAL_REFERENCE_PROJECTION} FROM account_registry_accounts WHERE tenant_id = {} AND account_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(account_id.as_str()),
    );
    sql::rows(sql::execute(session, query)?)
}

fn require_credential_reference_row(rows: &[Row]) -> Result<&Row, StorageError> {
    match rows {
        [] => Err(credential_mismatch()),
        [row] => Ok(row),
        _ => Err(sql::integrity()),
    }
}

fn decode_credential_reference(
    row: &Row,
    tenant: &TenantId,
    request: &AccountCredentialReferenceRequest,
    generation: ImportGeneration,
) -> Result<AccountCredentialReference, StorageError> {
    let values = sql::row_values::<10>(row)?;
    let binding = decode_credential_binding(values, tenant, request)?;
    let secret_ref = decode_credential_secret_ref(values, request)?;
    validate_credential_reference_lifecycle(values, generation)?;
    AccountCredentialReference::new(
        tenant.clone(),
        binding.account_id,
        binding.provider_id,
        binding.config_version,
        request.purpose().clone(),
        generation,
        secret_ref,
    )
    .map_err(|_| sql::integrity())
}

struct CredentialReferenceBinding {
    account_id: AccountId,
    provider_id: ProviderId,
    config_version: u64,
}

fn decode_credential_binding(
    values: &[rnmdb_types::SqlValue; 10],
    tenant: &TenantId,
    request: &AccountCredentialReferenceRequest,
) -> Result<CredentialReferenceBinding, StorageError> {
    require_tenant(&values[0], tenant)?;
    let account_id = require_credential_account(&values[1], request)?;
    let provider_id = require_credential_provider(&values[2], request)?;
    let config_version = require_credential_config_version(&values[3], request)?;
    Ok(CredentialReferenceBinding {
        account_id,
        provider_id,
        config_version,
    })
}

fn require_credential_account(
    value: &rnmdb_types::SqlValue,
    request: &AccountCredentialReferenceRequest,
) -> Result<AccountId, StorageError> {
    let account_id = parse_account_id(value)?;
    if &account_id != request.account_id() {
        return Err(sql::integrity());
    }
    Ok(account_id)
}

fn require_credential_provider(
    value: &rnmdb_types::SqlValue,
    request: &AccountCredentialReferenceRequest,
) -> Result<ProviderId, StorageError> {
    let provider_id = parse_provider_id(value)?;
    if &provider_id != request.provider_id() {
        return Err(credential_mismatch());
    }
    Ok(provider_id)
}

fn require_credential_config_version(
    value: &rnmdb_types::SqlValue,
    request: &AccountCredentialReferenceRequest,
) -> Result<u64, StorageError> {
    let config_version = nonzero_text_version(value)?;
    if config_version != request.config_version() {
        return Err(credential_mismatch());
    }
    Ok(config_version)
}

fn decode_credential_secret_ref(
    values: &[rnmdb_types::SqlValue; 10],
    request: &AccountCredentialReferenceRequest,
) -> Result<SecretRef, StorageError> {
    let provider = parse_secret_provider(&values[4])?;
    let path = parse_secret_path(&values[5])?;
    let version = parse_secret_version(&values[6])?;
    let purpose = parse_secret_purpose(&values[7])?;
    if &purpose != request.purpose() {
        return Err(credential_mismatch());
    }
    Ok(SecretRef::new(provider, path, version, purpose))
}

fn parse_secret_provider(value: &rnmdb_types::SqlValue) -> Result<SecretProvider, StorageError> {
    SecretProvider::parse(sql::text_value(value)?).map_err(|_| sql::integrity())
}

fn parse_secret_path(value: &rnmdb_types::SqlValue) -> Result<SecretPath, StorageError> {
    SecretPath::parse(sql::text_value(value)?).map_err(|_| sql::integrity())
}

fn parse_secret_version(value: &rnmdb_types::SqlValue) -> Result<SecretVersion, StorageError> {
    SecretVersion::new(nonzero_text_version(value)?).map_err(|_| sql::integrity())
}

fn parse_secret_purpose(value: &rnmdb_types::SqlValue) -> Result<SecretPurpose, StorageError> {
    SecretPurpose::parse(sql::text_value(value)?).map_err(|_| sql::integrity())
}

fn validate_credential_reference_lifecycle(
    values: &[rnmdb_types::SqlValue; 10],
    generation: ImportGeneration,
) -> Result<(), StorageError> {
    require_active_credential_status(&values[8])?;
    let row_generation = ImportGeneration::new(nonzero_text_version(&values[9])?);
    require_projection_row_generation(row_generation, generation)
}

fn require_active_credential_status(value: &rnmdb_types::SqlValue) -> Result<(), StorageError> {
    if decode_status(sql::text_value(value)?)? != AccountStatus::Active {
        return Err(credential_mismatch());
    }
    Ok(())
}

fn load_projection_rows(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<rnmdb_executor::vector::VectorBatch, StorageError> {
    let limit = MAX_ACCOUNT_PROJECTION_ACCOUNTS
        .checked_add(1)
        .ok_or_else(sql::exhausted)?;
    let query = format!(
        "SELECT {ROUTING_PROJECTION} FROM account_registry_accounts WHERE tenant_id = {} ORDER BY account_id LIMIT {limit};",
        sql::text(tenant.as_str()),
    );
    let batch = sql::rows(sql::execute(session, query)?)?;
    if batch.rows().len() > MAX_ACCOUNT_PROJECTION_ACCOUNTS {
        return Err(sql::exhausted());
    }
    Ok(batch)
}

fn decode_projection_rows(
    rows: &[Row],
    tenant: &TenantId,
    generation: ImportGeneration,
    routing: &mut routing_policy::RoutingPolicies,
    windows: &mut effective_window::EffectiveWindows,
    context: &RequestContext,
) -> Result<Vec<DurableAccountProjection>, StorageError> {
    let mut accounts = Vec::with_capacity(rows.len());
    for row in rows {
        check_context(context)?;
        accounts.push(decode_projection(
            row, tenant, generation, routing, windows,
        )?);
    }
    Ok(accounts)
}

fn decode_projection(
    row: &Row,
    tenant: &TenantId,
    generation: ImportGeneration,
    routing: &mut routing_policy::RoutingPolicies,
    windows: &mut effective_window::EffectiveWindows,
) -> Result<DurableAccountProjection, StorageError> {
    let values = sql::row_values::<9>(row)?;
    let account = parse_account_id(&values[1])?;
    let config_version = nonzero_text_version(&values[5])?;
    let routing = routing_policy::take_routing(routing, &account, config_version)?;
    let window = effective_window::take_window(windows, &account, config_version)?;
    let identity = decode_projection_identity(values, tenant, account)?;
    let state = decode_projection_state(values, generation, routing, window)?;
    Ok(DurableAccountProjection::new(identity, state))
}

fn decode_projection_identity(
    values: &[rnmdb_types::SqlValue; 9],
    tenant: &TenantId,
    account: AccountId,
) -> Result<DurableAccountIdentity, StorageError> {
    require_tenant(&values[0], tenant)?;
    let provider = parse_provider_id(&values[2])?;
    let model = decode_model(&values[3])?;
    Ok(DurableAccountIdentity::new(
        tenant.clone(),
        account,
        provider,
        model,
    ))
}

fn decode_projection_state(
    values: &[rnmdb_types::SqlValue; 9],
    generation: ImportGeneration,
    routing: DurableRoutingState,
    effective_window: AccountEffectiveWindow,
) -> Result<DurableAccountState, StorageError> {
    let (max_concurrency, config_version, account_version, import_generation) =
        decode_projection_versions(values)?;
    let status = decode_status(sql::text_value(&values[7])?)?;
    require_projection_row_generation(import_generation, generation)?;
    DurableAccountState::with_routing(
        max_concurrency,
        config_version,
        account_version,
        status,
        import_generation,
        routing,
    )
    .map(|state| state.with_effective_window(effective_window))
    .map_err(|_| sql::integrity())
}

fn decode_projection_versions(
    values: &[rnmdb_types::SqlValue; 9],
) -> Result<(u32, u64, u64, ImportGeneration), StorageError> {
    let raw_concurrency = sql::i64_value(&values[4])?;
    let max_concurrency = u32::try_from(raw_concurrency).map_err(|_| sql::integrity())?;
    let config_version = nonzero_text_version(&values[5])?;
    let account_version = nonzero_text_version(&values[6])?;
    let import_generation = ImportGeneration::new(nonzero_text_version(&values[8])?);
    Ok((
        max_concurrency,
        config_version,
        account_version,
        import_generation,
    ))
}

fn require_projection_row_generation(
    row_generation: ImportGeneration,
    snapshot_generation: ImportGeneration,
) -> Result<(), StorageError> {
    if row_generation > snapshot_generation {
        return Err(sql::integrity());
    }
    Ok(())
}

fn parse_account_id(value: &rnmdb_types::SqlValue) -> Result<AccountId, StorageError> {
    AccountId::parse(sql::text_value(value)?).map_err(|_| sql::integrity())
}

fn parse_provider_id(value: &rnmdb_types::SqlValue) -> Result<ProviderId, StorageError> {
    ProviderId::parse(sql::text_value(value)?).map_err(|_| sql::integrity())
}

fn decode_model(value: &rnmdb_types::SqlValue) -> Result<Option<ModelName>, StorageError> {
    match value {
        rnmdb_types::SqlValue::Null => Ok(None),
        rnmdb_types::SqlValue::Text(value) => ModelName::parse(value)
            .map(Some)
            .map_err(|_| sql::integrity()),
        _ => Err(sql::integrity()),
    }
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
        self.record_inserted(effect, account_id);
        Ok(())
    }

    fn record_inserted(&mut self, effect: EntryEffect, account_id: &AccountId) {
        if matches!(effect, EntryEffect::Inserted) {
            self.inserted_accounts.push(account_id.clone());
        }
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
        "INSERT INTO account_registry_accounts (tenant_id, account_id, provider_id, provider_label, account_label, external_account_id, config_version, secret_provider, secret_path, secret_version, secret_purpose, credential_digest_hex, default_model, max_concurrency, account_version, account_status, import_generation) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});",
        sql::text(tenant.as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(entry.provider_id().as_str()),
        sql::text(entry.provider_label()),
        sql::text(entry.account_label()),
        sql::nullable_text(entry.external_account_id().map(|value| value.as_str())),
        sql::text(&entry.config_version().get().to_string()),
        sql::text(secret.provider().as_str()),
        sql::text(secret.path().as_str()),
        sql::text(&secret.version().get().to_string()),
        sql::text(secret.purpose().as_str()),
        sql::text(&digest_hex(entry.credential_digest())),
        sql::nullable_text(entry.default_model().map(|value| value.as_str())),
        entry.max_concurrency().get(),
        sql::text(&INITIAL_VERSION.to_string()),
        sql::text(INITIAL_STATUS),
        sql::text(&generation.get().to_string()),
    );
    sql::require_rows(sql::execute(session, statement)?, 1)?;
    routing_policy::insert(session, tenant, entry, entry.config_version().get())?;
    effective_window::insert(session, tenant, entry, entry.config_version().get())
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
    let config_version = replacement_config_version(existing.config_version, entry)?;
    let account_version = existing
        .account_version
        .checked_add(1)
        .ok_or_else(sql::exhausted)?;
    let secret = entry.secret_ref();
    let statement = format!(
        "UPDATE account_registry_accounts SET provider_id = {}, provider_label = {}, account_label = {}, external_account_id = {}, config_version = {}, secret_provider = {}, secret_path = {}, secret_version = {}, secret_purpose = {}, credential_digest_hex = {}, default_model = {}, max_concurrency = {}, account_version = {}, import_generation = {} WHERE tenant_id = {} AND account_id = {} AND config_version = {} AND account_version = {} AND account_status = {};",
        sql::text(entry.provider_id().as_str()),
        sql::text(entry.provider_label()),
        sql::text(entry.account_label()),
        sql::nullable_text(entry.external_account_id().map(|value| value.as_str())),
        sql::text(&config_version.to_string()),
        sql::text(secret.provider().as_str()),
        sql::text(secret.path().as_str()),
        sql::text(&secret.version().get().to_string()),
        sql::text(secret.purpose().as_str()),
        sql::text(&digest_hex(entry.credential_digest())),
        sql::nullable_text(entry.default_model().map(|value| value.as_str())),
        entry.max_concurrency().get(),
        sql::text(&account_version.to_string()),
        sql::text(&generation.get().to_string()),
        sql::text(tenant.as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(&existing.config_version.to_string()),
        sql::text(&existing.account_version.to_string()),
        sql::text(status_label(existing.status)),
    );
    sql::require_rows(sql::execute(session, statement)?, 1)?;
    routing_policy::replace(
        session,
        tenant,
        entry,
        existing.config_version,
        config_version,
    )?;
    effective_window::replace(
        session,
        tenant,
        entry,
        existing.config_version,
        config_version,
    )
}

fn replacement_config_version(existing: u64, entry: &ImportEntry) -> Result<u64, StorageError> {
    let next = existing.checked_add(1).ok_or_else(sql::exhausted)?;
    if !entry.has_explicit_configuration() {
        return Ok(next);
    }
    if entry.config_version().get() != next {
        return Err(sql::conflict());
    }
    Ok(entry.config_version().get())
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

fn digest_hex(digest: OpaqueDigest) -> Zeroizing<String> {
    Zeroizing::new(fingerprint::bytes_hex(&digest.as_bytes()))
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn credential_mismatch() -> StorageError {
    StorageError::new(StorageErrorCode::NotFound)
}

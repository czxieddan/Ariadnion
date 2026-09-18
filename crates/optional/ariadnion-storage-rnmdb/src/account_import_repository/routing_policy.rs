// crates/optional/ariadnion-storage-rnmdb/src/account_import_repository/routing_policy.rs - Durable account routing policy persistence for Ariadnion.
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
//! Exact persisted routing priority and weight for durable account projections.

use std::collections::BTreeMap;

use ariadnion_account_domain::{AccountId, RoutingPriority, RoutingWeight};
use ariadnion_account_import::{DurableRoutingState, ImportEntry, MAX_ACCOUNT_PROJECTION_ACCOUNTS};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::StorageError;
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;

use super::sql;
use crate::session::check_context;

const ROUTING_POLICY_PROJECTION: &str = "tenant_id, account_id, config_version, priority, weight";

pub(super) type RoutingPolicies = BTreeMap<AccountId, StoredRoutingPolicy>;

#[derive(Clone, Copy)]
pub(super) struct StoredRoutingPolicy {
    config_version: u64,
    routing: DurableRoutingState,
}

pub(super) fn load_for_tenant(
    session: &mut LocalSession,
    tenant: &TenantId,
    context: &RequestContext,
) -> Result<RoutingPolicies, StorageError> {
    let limit = MAX_ACCOUNT_PROJECTION_ACCOUNTS
        .checked_add(1)
        .ok_or_else(sql::exhausted)?;
    let query = format!(
        "SELECT {ROUTING_POLICY_PROJECTION} FROM account_registry_routing_policy WHERE tenant_id = {} ORDER BY account_id LIMIT {limit};",
        sql::text(tenant.as_str()),
    );
    let batch = sql::rows(sql::execute(session, query)?)?;
    if batch.rows().len() > MAX_ACCOUNT_PROJECTION_ACCOUNTS {
        return Err(sql::exhausted());
    }
    decode_policies(batch.rows(), tenant, context)
}

fn decode_policies(
    rows: &[Row],
    tenant: &TenantId,
    context: &RequestContext,
) -> Result<RoutingPolicies, StorageError> {
    let mut policies = BTreeMap::new();
    for row in rows {
        check_context(context)?;
        let (account, policy) = decode_policy(row, tenant)?;
        if policies.insert(account, policy).is_some() {
            return Err(sql::integrity());
        }
    }
    Ok(policies)
}

fn decode_policy(
    row: &Row,
    tenant: &TenantId,
) -> Result<(AccountId, StoredRoutingPolicy), StorageError> {
    let values = sql::row_values::<5>(row)?;
    require_tenant(&values[0], tenant)?;
    let account = decode_account_id(&values[1])?;
    let policy = decode_stored_policy(values)?;
    Ok((account, policy))
}

fn decode_account_id(value: &rnmdb_types::SqlValue) -> Result<AccountId, StorageError> {
    AccountId::parse(sql::text_value(value)?).map_err(|_| sql::integrity())
}

fn decode_stored_policy(
    values: &[rnmdb_types::SqlValue; 5],
) -> Result<StoredRoutingPolicy, StorageError> {
    let config_version = nonzero_text_version(&values[2])?;
    let priority = decode_priority(&values[3])?;
    let weight = decode_weight(&values[4])?;
    Ok(StoredRoutingPolicy {
        config_version,
        routing: DurableRoutingState::new(priority, weight),
    })
}

fn decode_priority(value: &rnmdb_types::SqlValue) -> Result<RoutingPriority, StorageError> {
    let raw = sql::u64_from_i64(value)?;
    u16::try_from(raw)
        .map(RoutingPriority::new)
        .map_err(|_| sql::integrity())
}

fn decode_weight(value: &rnmdb_types::SqlValue) -> Result<RoutingWeight, StorageError> {
    let raw = sql::u64_from_i64(value)?;
    let weight = u32::try_from(raw).map_err(|_| sql::integrity())?;
    RoutingWeight::new(weight).map_err(|_| sql::integrity())
}

pub(super) fn take_routing(
    policies: &mut RoutingPolicies,
    account: &AccountId,
    config_version: u64,
) -> Result<DurableRoutingState, StorageError> {
    match policies.remove(account) {
        Some(policy) if policy.config_version == config_version => Ok(policy.routing),
        Some(_) => Err(sql::integrity()),
        None => Ok(DurableRoutingState::default()),
    }
}

pub(super) fn insert(
    session: &mut LocalSession,
    tenant: &TenantId,
    entry: &ImportEntry,
    config_version: u64,
) -> Result<(), StorageError> {
    let statement = routing_insert_statement(tenant, entry, config_version);
    sql::require_rows(sql::execute(session, statement)?, 1)
}

pub(super) fn replace(
    session: &mut LocalSession,
    tenant: &TenantId,
    entry: &ImportEntry,
    previous_config_version: u64,
    config_version: u64,
) -> Result<(), StorageError> {
    match load_one(session, tenant, entry.account_id())? {
        Some(policy) if policy.config_version == previous_config_version => update(
            session,
            tenant,
            entry,
            previous_config_version,
            config_version,
        ),
        Some(_) => Err(sql::integrity()),
        None => insert(session, tenant, entry, config_version),
    }
}

fn load_one(
    session: &mut LocalSession,
    tenant: &TenantId,
    account: &AccountId,
) -> Result<Option<StoredRoutingPolicy>, StorageError> {
    let query = format!(
        "SELECT {ROUTING_POLICY_PROJECTION} FROM account_registry_routing_policy WHERE tenant_id = {} AND account_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(account.as_str()),
    );
    let batch = sql::rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_policy(row, tenant).map(|(_, policy)| Some(policy)),
        _ => Err(sql::integrity()),
    }
}

fn update(
    session: &mut LocalSession,
    tenant: &TenantId,
    entry: &ImportEntry,
    previous_config_version: u64,
    config_version: u64,
) -> Result<(), StorageError> {
    let statement = format!(
        "UPDATE account_registry_routing_policy SET config_version = {}, priority = {}, weight = {} WHERE tenant_id = {} AND account_id = {} AND config_version = {};",
        sql::text(&config_version.to_string()),
        entry.routing_priority().get(),
        entry.routing_weight().get(),
        sql::text(tenant.as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(&previous_config_version.to_string()),
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

fn routing_insert_statement(tenant: &TenantId, entry: &ImportEntry, config_version: u64) -> String {
    format!(
        "INSERT INTO account_registry_routing_policy (tenant_id, account_id, config_version, priority, weight) VALUES ({}, {}, {}, {}, {});",
        sql::text(tenant.as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(&config_version.to_string()),
        entry.routing_priority().get(),
        entry.routing_weight().get(),
    )
}

fn require_tenant(value: &rnmdb_types::SqlValue, expected: &TenantId) -> Result<(), StorageError> {
    if sql::text_value(value)? != expected.as_str() {
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

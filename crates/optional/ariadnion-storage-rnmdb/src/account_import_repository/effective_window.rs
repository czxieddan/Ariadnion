// crates/optional/ariadnion-storage-rnmdb/src/account_import_repository/effective_window.rs - Durable account effective windows for Ariadnion.
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
//! Exact version-owned effective intervals for durable account projections.

use std::collections::BTreeMap;

use ariadnion_account_domain::{AccountEffectiveWindow, AccountId, AccountUtcTimestamp};
use ariadnion_account_import::{ImportEntry, MAX_ACCOUNT_PROJECTION_ACCOUNTS};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::StorageError;
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;
use rnmdb_types::SqlValue;

use super::sql;
use crate::session::check_context;

const EFFECTIVE_WINDOW_PROJECTION: &str = "tenant_id, account_id, config_version, effective_start_unix_seconds, effective_end_unix_seconds";

pub(super) type EffectiveWindows = BTreeMap<AccountId, StoredEffectiveWindow>;

#[derive(Clone, Copy)]
pub(super) struct StoredEffectiveWindow {
    config_version: u64,
    window: AccountEffectiveWindow,
}

pub(super) fn load_for_tenant(
    session: &mut LocalSession,
    tenant: &TenantId,
    context: &RequestContext,
) -> Result<EffectiveWindows, StorageError> {
    let limit = MAX_ACCOUNT_PROJECTION_ACCOUNTS
        .checked_add(1)
        .ok_or_else(sql::exhausted)?;
    let query = format!(
        "SELECT {EFFECTIVE_WINDOW_PROJECTION} FROM account_registry_effective_windows WHERE tenant_id = {} ORDER BY account_id LIMIT {limit};",
        sql::text(tenant.as_str()),
    );
    let batch = sql::rows(sql::execute(session, query)?)?;
    if batch.rows().len() > MAX_ACCOUNT_PROJECTION_ACCOUNTS {
        return Err(sql::exhausted());
    }
    decode_windows(batch.rows(), tenant, context)
}

fn decode_windows(
    rows: &[Row],
    tenant: &TenantId,
    context: &RequestContext,
) -> Result<EffectiveWindows, StorageError> {
    let mut windows = BTreeMap::new();
    for row in rows {
        check_context(context)?;
        let (account, window) = decode_window(row, tenant)?;
        if windows.insert(account, window).is_some() {
            return Err(sql::integrity());
        }
    }
    Ok(windows)
}

fn decode_window(
    row: &Row,
    tenant: &TenantId,
) -> Result<(AccountId, StoredEffectiveWindow), StorageError> {
    let values = sql::row_values::<5>(row)?;
    require_tenant(&values[0], tenant)?;
    let account = decode_account_id(&values[1])?;
    let config_version = nonzero_text_version(&values[2])?;
    let start = decode_optional_timestamp(&values[3])?;
    let end = decode_optional_timestamp(&values[4])?;
    let window = AccountEffectiveWindow::new(start, end).map_err(|_| sql::integrity())?;
    Ok((
        account,
        StoredEffectiveWindow {
            config_version,
            window,
        },
    ))
}

fn decode_optional_timestamp(
    value: &SqlValue,
) -> Result<Option<AccountUtcTimestamp>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Int64(seconds) => Ok(Some(AccountUtcTimestamp::from_unix_seconds(*seconds))),
        _ => Err(sql::integrity()),
    }
}

pub(super) fn take_window(
    windows: &mut EffectiveWindows,
    account: &AccountId,
    config_version: u64,
) -> Result<AccountEffectiveWindow, StorageError> {
    match windows.remove(account) {
        Some(stored) if stored.config_version == config_version => Ok(stored.window),
        Some(_) => Err(sql::integrity()),
        None => Err(sql::integrity()),
    }
}

pub(super) fn insert(
    session: &mut LocalSession,
    tenant: &TenantId,
    entry: &ImportEntry,
    config_version: u64,
) -> Result<(), StorageError> {
    let statement = insert_statement(tenant, entry, config_version);
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
        Some(stored) if stored.config_version == previous_config_version => update(
            session,
            tenant,
            entry,
            previous_config_version,
            config_version,
        ),
        Some(_) => Err(sql::integrity()),
        None => Err(sql::integrity()),
    }
}

fn load_one(
    session: &mut LocalSession,
    tenant: &TenantId,
    account: &AccountId,
) -> Result<Option<StoredEffectiveWindow>, StorageError> {
    let query = format!(
        "SELECT {EFFECTIVE_WINDOW_PROJECTION} FROM account_registry_effective_windows WHERE tenant_id = {} AND account_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(account.as_str()),
    );
    let batch = sql::rows(sql::execute(session, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_window(row, tenant).map(|(_, window)| Some(window)),
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
    let window = entry.effective_window();
    let statement = format!(
        "UPDATE account_registry_effective_windows SET config_version = {}, effective_start_unix_seconds = {}, effective_end_unix_seconds = {} WHERE tenant_id = {} AND account_id = {} AND config_version = {};",
        sql::text(&config_version.to_string()),
        nullable_timestamp(window.effective_start()),
        nullable_timestamp(window.effective_end()),
        sql::text(tenant.as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(&previous_config_version.to_string()),
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

fn insert_statement(tenant: &TenantId, entry: &ImportEntry, config_version: u64) -> String {
    let window = entry.effective_window();
    format!(
        "INSERT INTO account_registry_effective_windows (tenant_id, account_id, config_version, effective_start_unix_seconds, effective_end_unix_seconds) VALUES ({}, {}, {}, {}, {});",
        sql::text(tenant.as_str()),
        sql::text(entry.account_id().as_str()),
        sql::text(&config_version.to_string()),
        nullable_timestamp(window.effective_start()),
        nullable_timestamp(window.effective_end()),
    )
}

fn nullable_timestamp(value: Option<AccountUtcTimestamp>) -> String {
    value.map_or_else(
        || "NULL".to_owned(),
        |timestamp| timestamp.unix_seconds().to_string(),
    )
}

fn decode_account_id(value: &SqlValue) -> Result<AccountId, StorageError> {
    AccountId::parse(sql::text_value(value)?).map_err(|_| sql::integrity())
}

fn require_tenant(value: &SqlValue, expected: &TenantId) -> Result<(), StorageError> {
    if sql::text_value(value)? != expected.as_str() {
        return Err(sql::integrity());
    }
    Ok(())
}

fn nonzero_text_version(value: &SqlValue) -> Result<u64, StorageError> {
    let version = sql::parse_u64_text(value)?;
    if version == 0 {
        return Err(sql::integrity());
    }
    Ok(version)
}

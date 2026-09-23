// crates/optional/ariadnion-storage-rnmdb/src/account_proxy_repository/sql.rs - Bounded proxy storage SQL for Ariadnion.
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
//! Fixed-shape statements and strict primitive decoding for proxy snapshots.

use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::VectorBatch;
use rnmdb_types::SqlValue;
use zeroize::Zeroizing;

use crate::session::map_rnmdb_error;

pub(super) fn quote(value: &str) -> Zeroizing<String> {
    let mut quoted = Zeroizing::new(String::with_capacity(value.len() * 2 + 2));
    quoted.push('\'');
    for character in value.chars() {
        quoted.push(character);
        if character == '\'' {
            quoted.push('\'');
        }
    }
    quoted.push('\'');
    quoted
}

pub(super) fn execute(
    session: &mut LocalSession,
    statement: Zeroizing<String>,
) -> Result<CommandOutput, StorageError> {
    if statement.len() > 1 << 14 {
        return Err(integrity());
    }
    session.execute(statement.as_str()).map_err(map_rnmdb_error)
}

pub(super) fn query(
    session: &mut LocalSession,
    statement: String,
) -> Result<VectorBatch, StorageError> {
    match execute(session, Zeroizing::new(statement))? {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity()),
    }
}

pub(super) fn require_affected(output: CommandOutput, expected: usize) -> Result<(), StorageError> {
    match output {
        CommandOutput::RowsAffected(count) if count == expected as u64 => Ok(()),
        _ => Err(integrity()),
    }
}

pub(super) fn text(value: &SqlValue) -> Result<&str, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(value),
        _ => Err(integrity()),
    }
}

pub(super) fn integer(value: &SqlValue) -> Result<i64, StorageError> {
    match value {
        SqlValue::Int64(value) => Ok(*value),
        _ => Err(integrity()),
    }
}

pub(super) fn version(value: &SqlValue) -> Result<u64, StorageError> {
    let text = text(value)?;
    let parsed: u64 = text.parse().map_err(|_| integrity())?;
    if parsed.to_string() != text {
        return Err(integrity());
    }
    Ok(parsed)
}

pub(super) fn require_nulls(values: &[SqlValue]) -> Result<(), StorageError> {
    if values.iter().any(|value| !matches!(value, SqlValue::Null)) {
        return Err(integrity());
    }
    Ok(())
}

pub(super) fn require_tenant(value: &SqlValue, tenant: &str) -> Result<(), StorageError> {
    if text(value)? != tenant {
        return Err(integrity());
    }
    Ok(())
}

pub(super) const fn integrity() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

pub(super) const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

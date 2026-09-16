// crates/optional/ariadnion-storage-rnmdb/src/account_import_repository/sql.rs - Bounded account import SQL for Ariadnion.
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
//! Fixed-shape bounded SQL rendering and exact primitive decoding.

use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{Row, VectorBatch};
use rnmdb_types::SqlValue;
use zeroize::Zeroizing;

use crate::session::map_rnmdb_error;

const MAX_SQL_BYTES: usize = 1 << 20;

pub(super) fn text(value: &str) -> QuotedText {
    let mut output = String::with_capacity(value.len().saturating_add(2));
    output.push('\'');
    for character in value.chars() {
        if character == '\'' {
            output.push_str("''");
        } else {
            output.push(character);
        }
    }
    output.push('\'');
    QuotedText(Zeroizing::new(output))
}

pub(super) struct QuotedText(Zeroizing<String>);

impl std::fmt::Display for QuotedText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0.as_str())
    }
}

pub(super) fn execute(
    session: &mut LocalSession,
    statement: String,
) -> Result<CommandOutput, StorageError> {
    let statement = Zeroizing::new(statement);
    if statement.len() > MAX_SQL_BYTES || !statement.is_ascii() {
        return Err(integrity());
    }
    session.execute(statement.as_str()).map_err(map_rnmdb_error)
}

pub(super) fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity()),
    }
}

pub(super) fn row_values<const N: usize>(row: &Row) -> Result<&[SqlValue; N], StorageError> {
    row.values().try_into().map_err(|_| integrity())
}

pub(super) fn require_rows(output: CommandOutput, expected: u64) -> Result<(), StorageError> {
    match output {
        CommandOutput::RowsAffected(found) if found == expected => Ok(()),
        CommandOutput::RowsAffected(0) => Err(conflict()),
        _ => Err(integrity()),
    }
}

pub(super) fn text_value(value: &SqlValue) -> Result<&str, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(value),
        _ => Err(integrity()),
    }
}

pub(super) fn i64_value(value: &SqlValue) -> Result<i64, StorageError> {
    match value {
        SqlValue::Int64(value) => Ok(*value),
        _ => Err(integrity()),
    }
}

pub(super) fn u64_from_i64(value: &SqlValue) -> Result<u64, StorageError> {
    u64::try_from(i64_value(value)?).map_err(|_| integrity())
}

pub(super) fn usize_from_i64(value: &SqlValue) -> Result<usize, StorageError> {
    usize::try_from(i64_value(value)?).map_err(|_| integrity())
}

pub(super) fn parse_u64_text(value: &SqlValue) -> Result<u64, StorageError> {
    let text = text_value(value)?;
    let parsed: u64 = text.parse().map_err(|_| integrity())?;
    if parsed.to_string() != text {
        return Err(integrity());
    }
    Ok(parsed)
}

pub(super) const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

pub(super) const fn exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

pub(super) const fn integrity() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

// crates/optional/ariadnion-storage-rnmdb/src/vault_repository/sql.rs - Fixed vault SQL boundary for Ariadnion.
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
//! Fixed-shape SQL and strict bounded persisted primitive decoding.

use std::fmt::{self, Display, Formatter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::VectorBatch;
use rnmdb_types::SqlValue;
use zeroize::Zeroizing;

use crate::session::map_rnmdb_error;

const MAX_SQL_BYTES: usize = 1 << 20;

pub(super) struct Text(Zeroizing<String>);

impl Display for Text {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub(super) fn text(value: &str) -> Text {
    let mut output = Zeroizing::new(String::with_capacity(
        value.len().saturating_mul(2).saturating_add(2),
    ));
    output.push('\'');
    for byte in value.bytes() {
        if byte == b'\'' {
            output.push('\'');
        }
        output.push(char::from(byte));
    }
    output.push('\'');
    Text(output)
}

pub(super) fn execute(
    session: &mut LocalSession,
    statement: String,
) -> Result<CommandOutput, StorageError> {
    let statement = Zeroizing::new(statement);
    if statement.len() > MAX_SQL_BYTES {
        return Err(integrity());
    }
    session.execute(&statement).map_err(map_rnmdb_error)
}

pub(super) fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity()),
    }
}

pub(super) fn changed(output: CommandOutput) -> Result<(), StorageError> {
    match output {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(conflict()),
        _ => Err(integrity()),
    }
}

pub(super) fn string(value: &SqlValue) -> Result<&str, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(value),
        _ => Err(integrity()),
    }
}

pub(super) fn unsigned_text(value: &SqlValue) -> Result<u64, StorageError> {
    let value = string(value)?;
    let parsed: u64 = value.parse().map_err(|_| integrity())?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(integrity());
    }
    Ok(parsed)
}

pub(super) fn integer(value: &SqlValue) -> Result<i64, StorageError> {
    match value {
        SqlValue::Int64(value) => Ok(*value),
        _ => Err(integrity()),
    }
}

pub(super) fn now() -> Result<(i64, SystemTime), StorageError> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity())?
        .as_micros();
    let raw = i64::try_from(micros).map_err(|_| exhausted())?;
    Ok((raw, time_raw(raw)?))
}

pub(super) fn time(value: &SqlValue) -> Result<SystemTime, StorageError> {
    time_raw(integer(value)?)
}

pub(super) fn time_raw(value: i64) -> Result<SystemTime, StorageError> {
    let micros = u64::try_from(value).map_err(|_| integrity())?;
    UNIX_EPOCH
        .checked_add(Duration::from_micros(micros))
        .ok_or_else(integrity)
}

pub(super) fn time_encode(value: SystemTime) -> Result<i64, StorageError> {
    let duration = value.duration_since(UNIX_EPOCH).map_err(|_| integrity())?;
    if !duration.subsec_nanos().is_multiple_of(1_000) {
        return Err(integrity());
    }
    i64::try_from(duration.as_micros()).map_err(|_| exhausted())
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

pub(super) fn decode_hex(value: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() / 2 > max {
        return Err(integrity());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        bytes.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
    }
    Ok(bytes)
}

fn nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(integrity()),
    }
}

pub(super) fn require_text(value: &SqlValue, expected: &str) -> Result<(), StorageError> {
    if string(value)? != expected {
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

pub(super) const fn exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

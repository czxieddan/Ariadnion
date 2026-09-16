// crates/optional/ariadnion-storage-rnmdb/src/account_batch_repository/sql.rs - Rust source for Ariadnion.
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
//! Bounded SQL construction for account-batch persistence.

use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};

use crate::session::map_rnmdb_error;

const MAX_SQL_BYTES: usize = 1 << 20;

pub(super) fn text(value: &str) -> String {
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
    output
}

pub(super) const fn null_or_text(value: Option<&str>) -> NullableText<'_> {
    NullableText(value)
}

pub(super) struct NullableText<'a>(Option<&'a str>);

impl std::fmt::Display for NullableText<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(value) => formatter.write_str(&text(value)),
            None => formatter.write_str("NULL"),
        }
    }
}

pub(super) fn execute(
    session: &mut LocalSession,
    statement: String,
) -> Result<CommandOutput, StorageError> {
    if statement.len() > MAX_SQL_BYTES || !statement.is_ascii() {
        return Err(integrity());
    }
    session.execute(&statement).map_err(map_rnmdb_error)
}

pub(super) fn require_rows(output: CommandOutput, expected: u64) -> Result<(), StorageError> {
    match output {
        CommandOutput::RowsAffected(found) if found == expected => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity()),
    }
}

pub(super) const fn integrity() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

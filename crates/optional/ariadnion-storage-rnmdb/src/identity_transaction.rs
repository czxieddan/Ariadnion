// crates/optional/ariadnion-storage-rnmdb/src/identity_transaction.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
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
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Single-lock transaction handling for storage repositories.

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::RnovError;

use crate::session::{check_context, map_rnmdb_error};

pub(crate) type IdentityTransactionResult<T> = Result<T, IdentityTransactionFailure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IdentityTransactionFailure {
    error: StorageError,
    taints_session: bool,
}

impl IdentityTransactionFailure {
    fn ordinary(error: StorageError) -> Self {
        Self {
            error,
            taints_session: false,
        }
    }

    fn tainted(error: StorageError) -> Self {
        Self {
            error,
            taints_session: true,
        }
    }

    #[cfg(feature = "test-hooks")]
    pub(crate) fn injected_commit_indeterminate() -> Self {
        Self::tainted(commit_indeterminate())
    }

    pub(crate) fn taints_session(self) -> bool {
        self.taints_session
    }

    pub(crate) fn into_storage_error(self) -> StorageError {
        self.error
    }
}

pub(crate) fn run_identity_transaction<T>(
    session: &mut LocalSession,
    context: &RequestContext,
    operation: impl FnOnce(&mut LocalSession) -> Result<T, StorageError>,
) -> IdentityTransactionResult<T> {
    run_transaction_with_begin_boundary(session, context, || check_context(context), operation)
}

pub(crate) fn run_transaction_with_begin_boundary<T>(
    session: &mut LocalSession,
    context: &RequestContext,
    after_begin: impl FnOnce() -> Result<(), StorageError>,
    operation: impl FnOnce(&mut LocalSession) -> Result<T, StorageError>,
) -> IdentityTransactionResult<T> {
    begin_transaction(session, context, after_begin)?;
    let result = operation(session);
    finish_identity_transaction(session, context, result)
}

fn begin_transaction(
    session: &mut LocalSession,
    context: &RequestContext,
    after_begin: impl FnOnce() -> Result<(), StorageError>,
) -> IdentityTransactionResult<()> {
    if let Err(error) = check_context(context) {
        return Err(IdentityTransactionFailure::ordinary(error));
    }
    let begin = session.execute("BEGIN");
    project_begin_result(session, context, begin)?;
    let boundary = after_begin();
    match boundary {
        Ok(()) => Ok(()),
        Err(error) => Err(rollback_started_transaction(session, error)),
    }
}

fn project_begin_result(
    session: &LocalSession,
    context: &RequestContext,
    begin: Result<CommandOutput, RnovError>,
) -> Result<(), IdentityTransactionFailure> {
    match begin {
        Ok(_) if session.in_transaction() => Ok(()),
        Ok(_) => Err(IdentityTransactionFailure::tainted(integrity_failure())),
        Err(error) => {
            let error = map_rnmdb_error(error);
            Err(if session.in_transaction() {
                IdentityTransactionFailure::tainted(integrity_failure())
            } else {
                ordinary_failure_with_context(context, error)
            })
        }
    }
}

fn rollback_started_transaction(
    session: &mut LocalSession,
    error: StorageError,
) -> IdentityTransactionFailure {
    match rollback_precommit_error::<()>(session, error) {
        Err(failure) => failure,
        Ok(()) => IdentityTransactionFailure::tainted(integrity_failure()),
    }
}

pub(crate) fn require_active_identity_transaction(
    session: &LocalSession,
) -> Result<(), StorageError> {
    if !session.in_transaction() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn finish_identity_transaction<T>(
    session: &mut LocalSession,
    context: &RequestContext,
    result: Result<T, StorageError>,
) -> IdentityTransactionResult<T> {
    match result {
        Ok(value) => commit_identity_transaction(session, context, value),
        Err(error) => rollback_precommit_error_with_context(session, context, error),
    }
}

fn commit_identity_transaction<T>(
    session: &mut LocalSession,
    context: &RequestContext,
    value: T,
) -> IdentityTransactionResult<T> {
    if let Err(error) = check_context(context) {
        return rollback_precommit_error(session, error);
    }

    match session.execute("COMMIT") {
        Ok(_) if !session.in_transaction() => Ok(value),
        Ok(_) => {
            let _rollback = rollback_after_commit_failure(session);
            Err(IdentityTransactionFailure::tainted(integrity_failure()))
        }
        Err(_) => {
            let error = if rollback_after_commit_failure(session).is_ok() {
                commit_indeterminate()
            } else {
                integrity_failure()
            };
            Err(IdentityTransactionFailure::tainted(error))
        }
    }
}

fn rollback_after_commit_failure(session: &mut LocalSession) -> Result<(), ()> {
    if !session.in_transaction() {
        return Ok(());
    }
    if session.execute("ROLLBACK").is_err() || session.in_transaction() {
        return Err(());
    }
    Ok(())
}

fn rollback_precommit_error<T>(
    session: &mut LocalSession,
    error: StorageError,
) -> IdentityTransactionResult<T> {
    if !session.in_transaction() {
        return Err(IdentityTransactionFailure::tainted(integrity_failure()));
    }
    if session.execute("ROLLBACK").is_err() || session.in_transaction() {
        return Err(IdentityTransactionFailure::tainted(integrity_failure()));
    }
    Err(IdentityTransactionFailure::ordinary(error))
}

fn rollback_precommit_error_with_context<T>(
    session: &mut LocalSession,
    context: &RequestContext,
    error: StorageError,
) -> IdentityTransactionResult<T> {
    match rollback_precommit_error(session, error) {
        Err(failure) if !failure.taints_session() => {
            Err(ordinary_failure_with_context(context, failure.error))
        }
        result => result,
    }
}

fn ordinary_failure_with_context(
    context: &RequestContext,
    fallback: StorageError,
) -> IdentityTransactionFailure {
    let error = match check_context(context) {
        Ok(()) => fallback,
        Err(error) => error,
    };
    IdentityTransactionFailure::ordinary(error)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn commit_indeterminate() -> StorageError {
    StorageError::new(StorageErrorCode::CommitIndeterminate)
}

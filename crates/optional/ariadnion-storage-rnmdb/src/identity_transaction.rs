//! Single-lock transaction handling for identity repositories.

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::LocalSession;

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
    match session.execute("BEGIN") {
        Ok(_) if session.in_transaction() => {}
        Ok(_) => {
            return Err(IdentityTransactionFailure::tainted(integrity_failure()));
        }
        Err(error) => {
            let error = map_rnmdb_error(error);
            return Err(if session.in_transaction() {
                IdentityTransactionFailure::tainted(integrity_failure())
            } else {
                IdentityTransactionFailure::ordinary(error)
            });
        }
    }
    let result = operation(session);
    finish_identity_transaction(session, context, result)
}

fn finish_identity_transaction<T>(
    session: &mut LocalSession,
    context: &RequestContext,
    result: Result<T, StorageError>,
) -> IdentityTransactionResult<T> {
    match result {
        Ok(value) => commit_identity_transaction(session, context, value),
        Err(error) => rollback_precommit_error(session, error),
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

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn commit_indeterminate() -> StorageError {
    StorageError::new(StorageErrorCode::CommitIndeterminate)
}

//! Single-lock transaction handling for identity repositories.

use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::LocalSession;

use crate::session::map_rnmdb_error;

pub(crate) fn run_identity_transaction<T>(
    session: &mut LocalSession,
    operation: impl FnOnce(&mut LocalSession) -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    session.execute("BEGIN").map_err(map_rnmdb_error)?;
    let result = operation(session);
    finish_identity_transaction(session, result)
}

fn finish_identity_transaction<T>(
    session: &mut LocalSession,
    result: Result<T, StorageError>,
) -> Result<T, StorageError> {
    match result {
        Ok(value) => commit_identity_transaction(session, value),
        Err(error) => rollback_precommit_error(session, error),
    }
}

fn commit_identity_transaction<T>(session: &mut LocalSession, value: T) -> Result<T, StorageError> {
    if session.execute("COMMIT").is_ok() {
        return Ok(value);
    }
    if session.in_transaction() {
        let _ = session.execute("ROLLBACK");
    }
    Err(StorageError::new(StorageErrorCode::Unavailable))
}

fn rollback_precommit_error<T>(
    session: &mut LocalSession,
    error: StorageError,
) -> Result<T, StorageError> {
    if !session.in_transaction() || session.execute("ROLLBACK").is_err() {
        return Err(integrity_failure());
    }
    Err(error)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

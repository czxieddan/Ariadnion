//! Serialized ownership of one encrypted RNMDB local session.

use std::fmt::{self, Debug, Formatter};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{StorageError, StorageErrorCode, StorageInstanceId};
use rnmdb_cli::LocalSession;
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_storage::PageCryptoKey;

/// Secret page-key material that is redacted and cleared on drop.
pub struct PageKeyMaterial {
    bytes: [u8; 32],
}

impl PageKeyMaterial {
    /// Takes ownership of exactly 32 key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    fn into_upstream_key(self) -> PageCryptoKey {
        PageCryptoKey::from_bytes(self.bytes)
    }
}

impl Debug for PageKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PageKeyMaterial(<redacted>)")
    }
}

impl Drop for PageKeyMaterial {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Validated options for opening one encrypted database file.
pub struct SessionOpenOptions {
    instance: StorageInstanceId,
    data_root: PathBuf,
    page_key: PageKeyMaterial,
}

impl SessionOpenOptions {
    /// Creates options under an absolute, traversal-free data root.
    pub fn new(
        instance: StorageInstanceId,
        data_root: impl Into<PathBuf>,
        page_key: PageKeyMaterial,
    ) -> Result<Self, StorageError> {
        let data_root = data_root.into();
        validate_data_root(&data_root)?;
        Ok(Self {
            instance,
            data_root,
            page_key,
        })
    }

    fn database_path(&self) -> PathBuf {
        self.data_root
            .join(format!("{}.rnmdb", self.instance.as_str()))
    }
}

impl Debug for SessionOpenOptions {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionOpenOptions")
            .field("instance", &self.instance)
            .field("data_root", &"<redacted>")
            .field("page_key", &self.page_key)
            .finish()
    }
}

/// The sole serialized owner of one long-lived embedded session.
pub struct RnmdbSessionOwner {
    instance: StorageInstanceId,
    session: Mutex<LocalSession>,
}

impl RnmdbSessionOwner {
    /// Opens or creates one encrypted RNMDB file without starting a listener.
    pub fn open(options: SessionOpenOptions) -> Result<Self, StorageError> {
        let path = options.database_path();
        let key = options.page_key.into_upstream_key();
        let session = LocalSession::single_file_with_key(path, key).map_err(map_rnmdb_error)?;
        Ok(Self {
            instance: options.instance,
            session: Mutex::new(session),
        })
    }

    /// Returns the isolated instance identity.
    #[must_use]
    pub const fn instance(&self) -> &StorageInstanceId {
        &self.instance
    }

    /// Persists a complete checkpoint after checking cancellation/deadline.
    pub fn checkpoint(&self, context: &RequestContext) -> Result<(), StorageError> {
        check_context(context)?;
        let mut session = lock_session(&self.session);
        session.checkpoint().map_err(map_rnmdb_error)
    }

    /// Returns whether the embedded session currently owns a transaction.
    pub fn transaction_active(&self, context: &RequestContext) -> Result<bool, StorageError> {
        check_context(context)?;
        Ok(lock_session(&self.session).in_transaction())
    }

    pub(crate) fn begin_transaction(&self, context: &RequestContext) -> Result<(), StorageError> {
        check_context(context)?;
        let mut session = lock_session(&self.session);
        if session.in_transaction() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        session
            .execute("BEGIN")
            .map(|_| ())
            .map_err(map_rnmdb_error)
    }

    pub(crate) fn commit_transaction(&self, context: &RequestContext) -> Result<(), StorageError> {
        self.execute_transaction_command("COMMIT", context)
    }

    pub(crate) fn rollback_transaction(
        &self,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.execute_transaction_command("ROLLBACK", context)
    }

    pub(crate) fn rollback_active_transaction(&self) {
        let mut session = lock_session(&self.session);
        if session.in_transaction() {
            let _ = session.execute("ROLLBACK");
        }
    }

    pub(crate) fn with_session<T>(
        &self,
        context: &RequestContext,
        operation: impl FnOnce(&mut LocalSession) -> Result<T, RnovError>,
    ) -> Result<T, StorageError> {
        check_context(context)?;
        operation(&mut lock_session(&self.session)).map_err(map_rnmdb_error)
    }

    fn execute_transaction_command(
        &self,
        command: &str,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.with_session(context, |session| session.execute(command).map(|_| ()))
    }
}

fn validate_data_root(path: &Path) -> Result<(), StorageError> {
    let valid = path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        });
    if !valid {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    Ok(())
}

fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => StorageError::new(StorageErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => StorageError::new(StorageErrorCode::DeadlineExceeded),
        _ => StorageError::new(StorageErrorCode::Internal),
    })
}

fn map_rnmdb_error(error: RnovError) -> StorageError {
    let code = match error.kind() {
        ErrorKind::Canceled => StorageErrorCode::Cancelled,
        ErrorKind::Config | ErrorKind::InvalidInput => StorageErrorCode::InvalidArgument,
        ErrorKind::Corruption | ErrorKind::Security => StorageErrorCode::IntegrityFailure,
        ErrorKind::NotFound => StorageErrorCode::NotFound,
        ErrorKind::Io | ErrorKind::Storage => StorageErrorCode::Unavailable,
        ErrorKind::Internal => StorageErrorCode::Internal,
    };
    StorageError::new(code)
}

fn lock_session(session: &Mutex<LocalSession>) -> MutexGuard<'_, LocalSession> {
    match session.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

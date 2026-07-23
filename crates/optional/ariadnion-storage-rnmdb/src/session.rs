//! Serialized ownership of one encrypted RNMDB local session.

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{
    StorageError, StorageErrorCode, StorageInstanceId, TransactionScope,
};
use rnmdb_cli::LocalSession;
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_security::ColumnKeyMaterial as UpstreamColumnKeyMaterial;
use rnmdb_storage::PageCryptoKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::RnmdbInstanceProfile;

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

    pub(crate) fn into_upstream_key(self) -> PageCryptoKey {
        PageCryptoKey::from_bytes(self.bytes)
    }
}

impl Debug for PageKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PageKeyMaterial(<redacted>)")
    }
}

impl Zeroize for PageKeyMaterial {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for PageKeyMaterial {}

impl Drop for PageKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Validated options for opening one encrypted database file.
pub struct SessionOpenOptions {
    profile: RnmdbInstanceProfile,
    data_root: PathBuf,
    page_key: PageKeyMaterial,
}

impl SessionOpenOptions {
    /// Creates options under an absolute, traversal-free data root.
    pub fn new(
        profile: RnmdbInstanceProfile,
        data_root: impl Into<PathBuf>,
        page_key: PageKeyMaterial,
    ) -> Result<Self, StorageError> {
        let data_root = data_root.into();
        validate_data_root(&data_root)?;
        profile.validate_session_open()?;
        Ok(Self {
            profile,
            data_root,
            page_key,
        })
    }

    fn database_path(&self) -> PathBuf {
        self.data_root
            .join(format!("{}.rnmdb", self.profile.instance().as_str()))
    }
}

impl Debug for SessionOpenOptions {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionOpenOptions")
            .field("profile", &self.profile)
            .field("data_root", &"<redacted>")
            .field("page_key", &self.page_key)
            .finish()
    }
}

/// The sole serialized owner of one long-lived embedded session.
pub struct RnmdbSessionOwner {
    profile: RnmdbInstanceProfile,
    transaction_scope: TransactionScope,
    session: Mutex<LocalSession>,
    tainted: AtomicBool,
    configured_columns: Mutex<BTreeSet<ColumnEncryptionTarget>>,
}

impl RnmdbSessionOwner {
    /// Opens or creates one encrypted RNMDB file without starting a listener.
    pub fn open(options: SessionOpenOptions) -> Result<Self, StorageError> {
        let path = options.database_path();
        let key = options.page_key.into_upstream_key();
        let session = LocalSession::single_file_with_key(path, key).map_err(map_rnmdb_error)?;
        Ok(Self {
            profile: options.profile,
            transaction_scope: TransactionScope::new(),
            session: Mutex::new(session),
            tainted: AtomicBool::new(false),
            configured_columns: Mutex::new(BTreeSet::new()),
        })
    }

    /// Returns the isolated instance identity.
    #[must_use]
    pub const fn instance(&self) -> &StorageInstanceId {
        self.profile.instance()
    }

    /// Returns the isolated instance profile applied at session open.
    #[must_use]
    pub const fn profile(&self) -> &RnmdbInstanceProfile {
        &self.profile
    }

    pub(crate) const fn transaction_scope(&self) -> &TransactionScope {
        &self.transaction_scope
    }

    /// Persists a complete checkpoint after checking cancellation/deadline.
    pub fn checkpoint(&self, context: &RequestContext) -> Result<(), StorageError> {
        check_context(context)?;
        self.ensure_usable()?;
        let mut session = lock_session(&self.session);
        check_context(context)?;
        self.ensure_usable()?;
        session.checkpoint().map_err(map_rnmdb_error)
    }

    /// Returns whether the embedded session currently owns a transaction.
    pub fn transaction_active(&self, context: &RequestContext) -> Result<bool, StorageError> {
        check_context(context)?;
        self.ensure_usable()?;
        let session = lock_session(&self.session);
        check_context(context)?;
        self.ensure_usable()?;
        Ok(session.in_transaction())
    }

    pub(crate) fn begin_transaction(&self, context: &RequestContext) -> Result<(), StorageError> {
        check_context(context)?;
        self.ensure_usable()?;
        let mut session = lock_session(&self.session);
        check_context(context)?;
        self.ensure_usable()?;
        self.begin_transaction_on_session(&mut session)
    }

    pub(crate) fn commit_transaction(&self, context: &RequestContext) -> Result<(), StorageError> {
        self.execute_transaction_command("COMMIT", commit_indeterminate(), context)
    }

    pub(crate) fn rollback_transaction(
        &self,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.execute_transaction_command("ROLLBACK", integrity_failure(), context)
    }

    pub(crate) fn rollback_active_transaction(&self) -> Result<(), StorageError> {
        let mut session = lock_session(&self.session);
        if !session.in_transaction() {
            return Ok(());
        }
        let result = session.execute("ROLLBACK").map_err(map_rnmdb_error);
        if result.is_err() || session.in_transaction() {
            self.mark_tainted();
            return Err(integrity_failure());
        }
        result.map(|_| ())
    }

    pub(crate) fn shutdown_before(&self, deadline: SystemTime) -> Result<bool, StorageError> {
        check_shutdown_deadline(deadline)?;
        self.ensure_usable()?;
        let mut session = lock_session(&self.session);
        self.shutdown_on_session(&mut session, deadline)
    }

    fn begin_transaction_on_session(&self, session: &mut LocalSession) -> Result<(), StorageError> {
        if session.in_transaction() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        let result = session.execute("BEGIN").map_err(map_rnmdb_error);
        if session.in_transaction() {
            if result.is_ok() {
                return Ok(());
            }
            return Err(self.taint_begin_failure(session));
        }
        if result.is_ok() {
            self.mark_tainted();
            return Err(integrity_failure());
        }
        result.map(|_| ())
    }

    fn taint_begin_failure(&self, session: &mut LocalSession) -> StorageError {
        // A successful best-effort rollback cannot make an ambiguous BEGIN reusable.
        let _ = session.execute("ROLLBACK");
        self.mark_tainted();
        integrity_failure()
    }

    fn shutdown_on_session(
        &self,
        session: &mut LocalSession,
        deadline: SystemTime,
    ) -> Result<bool, StorageError> {
        check_shutdown_deadline(deadline)?;
        self.ensure_usable()?;
        let rolled_back = match rollback_for_shutdown(session) {
            Ok(rolled_back) => rolled_back,
            Err(error) => {
                self.mark_tainted();
                return Err(error);
            }
        };
        check_shutdown_deadline(deadline)?;
        session.checkpoint().map_err(map_rnmdb_error)?;
        check_shutdown_deadline(deadline)?;
        Ok(rolled_back)
    }

    pub(crate) fn with_session<T>(
        &self,
        context: &RequestContext,
        operation: impl FnOnce(&mut LocalSession) -> Result<T, RnovError>,
    ) -> Result<T, StorageError> {
        check_context(context)?;
        self.ensure_usable()?;
        let mut session = lock_session(&self.session);
        check_context(context)?;
        self.ensure_usable()?;
        operation(&mut session).map_err(map_rnmdb_error)
    }

    pub(crate) fn with_storage_session<T>(
        &self,
        context: &RequestContext,
        operation: impl FnOnce(&mut LocalSession) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        check_context(context)?;
        self.ensure_usable()?;
        let mut session = lock_session(&self.session);
        check_context(context)?;
        self.ensure_usable()?;
        operation(&mut session)
    }

    pub(crate) fn with_identity_session<T>(
        &self,
        context: &RequestContext,
        operation: impl FnOnce(
            &mut LocalSession,
        ) -> crate::identity_transaction::IdentityTransactionResult<T>,
    ) -> Result<T, StorageError> {
        check_context(context)?;
        self.ensure_usable()?;
        let mut session = lock_session(&self.session);
        check_context(context)?;
        self.ensure_usable()?;
        if session.in_transaction() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        let result = operation(&mut session);
        if session.in_transaction() {
            self.mark_tainted();
            return Err(integrity_failure());
        }
        result.map_err(|error| {
            if error.taints_session() {
                self.mark_tainted();
            }
            error.into_storage_error()
        })
    }

    /// Configures one managed column while holding the configuration lock.
    ///
    /// The lock order is configured-columns then session. No adapter path may
    /// acquire these locks in the reverse order.
    pub(crate) fn configure_column_encryption_once(
        &self,
        target: ColumnEncryptionTarget,
        key: UpstreamColumnKeyMaterial,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let mut configured = lock_configured_columns(&self.configured_columns);
        if configured.contains(&target) {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        self.with_session(context, |session| {
            session.configure_column_encryption(target.schema, target.table, target.column, key)
        })?;
        configured.insert(target);
        Ok(())
    }

    fn execute_transaction_command(
        &self,
        command: &str,
        command_failure: StorageError,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        check_context(context)?;
        self.ensure_usable()?;
        let mut session = lock_session(&self.session);
        check_context(context)?;
        self.ensure_usable()?;
        if session.execute(command).is_err() {
            self.mark_tainted();
            return Err(command_failure);
        }
        if session.in_transaction() {
            self.mark_tainted();
            return Err(integrity_failure());
        }
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), StorageError> {
        if self.tainted.load(Ordering::Acquire) {
            return Err(integrity_failure());
        }
        Ok(())
    }

    fn mark_tainted(&self) {
        self.tainted.store(true, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ColumnEncryptionTarget {
    schema: &'static str,
    table: &'static str,
    column: &'static str,
}

impl ColumnEncryptionTarget {
    pub(crate) const fn new(
        schema: &'static str,
        table: &'static str,
        column: &'static str,
    ) -> Self {
        Self {
            schema,
            table,
            column,
        }
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

pub(crate) fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => StorageError::new(StorageErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => StorageError::new(StorageErrorCode::DeadlineExceeded),
        _ => StorageError::new(StorageErrorCode::Internal),
    })
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn commit_indeterminate() -> StorageError {
    StorageError::new(StorageErrorCode::CommitIndeterminate)
}

fn rollback_for_shutdown(session: &mut LocalSession) -> Result<bool, StorageError> {
    if !session.in_transaction() {
        return Ok(false);
    }
    session
        .execute("ROLLBACK")
        .map_err(|_| integrity_failure())?;
    if session.in_transaction() {
        return Err(integrity_failure());
    }
    Ok(true)
}

fn check_shutdown_deadline(deadline: SystemTime) -> Result<(), StorageError> {
    if deadline <= SystemTime::now() {
        return Err(StorageError::new(StorageErrorCode::DeadlineExceeded));
    }
    Ok(())
}

pub(crate) fn map_rnmdb_error(error: RnovError) -> StorageError {
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

fn lock_configured_columns(
    columns: &Mutex<BTreeSet<ColumnEncryptionTarget>>,
) -> MutexGuard<'_, BTreeSet<ColumnEncryptionTarget>> {
    match columns.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

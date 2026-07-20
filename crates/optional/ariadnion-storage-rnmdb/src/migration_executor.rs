//! Fail-closed RNMDB execution for new-target application migrations.

use std::fmt::{self, Debug, Formatter};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{
    MigrationDescriptor, MigrationExecutorPort, MigrationPlan, MigrationPreflight,
    MigrationReceipt, SchemaVersion, StorageError, StorageErrorCode, StorageInstanceId,
};
use rnmdb_cli::CommandOutput;
use rnmdb_executor::vector::{ColumnSchema, Row};
use rnmdb_types::{SqlType, SqlValue};

use crate::codec::UtcTimestampMicros;
use crate::location::StorageFileLocation;
use crate::maintenance::{RnmdbMaintenance, VerificationSummary};
use crate::migration::{
    MigrationApplyStatus, RnmdbMigrationRunner, platform_initial_migration,
    platform_secret_references_migration,
};
use crate::session::{PageKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

const PLATFORM_INITIAL_ID: &str = "platform.0001.initial";
const PLATFORM_SECRET_REFERENCES_ID: &str = "platform.0002.secret-references";
const PLATFORM_DOMAIN: &str = "platform";
const MIGRATION_LEDGER_QUERY: &str = "SELECT migration_id, domain, from_version, to_version, checksum FROM platform_schema_migrations LIMIT 1025;";

/// Single-use page-key inputs for one new-target migration operation.
///
/// RNMDB consumes a page key independently while authenticating the source,
/// opening the copied target, and authenticating the completed target. The
/// caller therefore supplies three separately owned values containing the
/// same key. Each value is removed from its slot at most once and its
/// Ariadnion-owned bytes are cleared by [`PageKeyMaterial`] on drop.
pub struct RnmdbMigrationPageKeys {
    source_authentication: PageKeyMaterial,
    target_session: PageKeyMaterial,
    target_authentication: PageKeyMaterial,
}

impl RnmdbMigrationPageKeys {
    /// Creates the three single-use inputs required by one migration run.
    #[must_use]
    pub const fn new(
        source_authentication: PageKeyMaterial,
        target_session: PageKeyMaterial,
        target_authentication: PageKeyMaterial,
    ) -> Self {
        Self {
            source_authentication,
            target_session,
            target_authentication,
        }
    }

    fn into_parts(self) -> (PageKeyMaterial, PageKeyMaterial, PageKeyMaterial) {
        (
            self.source_authentication,
            self.target_session,
            self.target_authentication,
        )
    }
}

impl Debug for RnmdbMigrationPageKeys {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RnmdbMigrationPageKeys(<redacted>)")
    }
}

/// One-shot RNMDB adapter for [`MigrationExecutorPort`].
///
/// An executor is bound to one validated data root and one distinct source and
/// target identity. It copies the source with RNMDB's exclusive-create backup
/// primitive, applies only compiled migration descriptors, and never removes
/// either file after failure. Callers must quiesce source writes between
/// preflight and application; the final target is independently authenticated
/// and its complete migration ledger is checked before a receipt is returned.
pub struct RnmdbMigrationExecutor {
    data_root: PathBuf,
    source: StorageFileLocation,
    target: StorageFileLocation,
    source_key: Mutex<Option<PageKeyMaterial>>,
    target_session_key: Mutex<Option<PageKeyMaterial>>,
    target_authentication_key: Mutex<Option<PageKeyMaterial>>,
    state: Mutex<ExecutionState>,
}

impl RnmdbMigrationExecutor {
    /// Binds a one-shot executor to distinct files below one validated root.
    ///
    /// # Errors
    ///
    /// Equal identities return [`StorageErrorCode::Conflict`]. A relative or
    /// traversal-bearing data root returns
    /// [`StorageErrorCode::InvalidArgument`]. Any supplied key material is
    /// cleared if construction fails.
    pub fn new(
        data_root: impl Into<PathBuf>,
        source: StorageInstanceId,
        target: StorageInstanceId,
        keys: RnmdbMigrationPageKeys,
    ) -> Result<Self, StorageError> {
        ensure_distinct_instances(&source, &target)?;
        let data_root = data_root.into();
        let source = StorageFileLocation::new(data_root.clone(), source)?;
        let target = StorageFileLocation::new(data_root.clone(), target)?;
        let (source_key, target_session_key, target_authentication_key) = keys.into_parts();
        Ok(Self {
            data_root,
            source,
            target,
            source_key: Mutex::new(Some(source_key)),
            target_session_key: Mutex::new(Some(target_session_key)),
            target_authentication_key: Mutex::new(Some(target_authentication_key)),
            state: Mutex::new(ExecutionState::Ready),
        })
    }

    fn validate_bound_operation(
        &self,
        source: &StorageInstanceId,
        target: &StorageInstanceId,
    ) -> Result<(), StorageError> {
        let matches = self.source.instance() == source && self.target.instance() == target;
        if !matches {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        Ok(())
    }

    fn perform_preflight(
        &self,
        context: &RequestContext,
    ) -> Result<MigrationPreflight, StorageError> {
        require_missing_target(&self.target)?;
        let key = take_key(&self.source_key)?;
        let verification = RnmdbMaintenance::verify(&self.source, key, context)?;
        require_authenticated(&verification)?;
        Ok(MigrationPreflight::new(true, true, false))
    }

    fn apply_plan(
        &self,
        plan: &MigrationPlan,
        context: &RequestContext,
    ) -> Result<Arc<RnmdbSessionOwner>, StorageError> {
        require_missing_target(&self.target)?;
        let key = take_key(&self.target_session_key)?;
        RnmdbMaintenance::backup(&self.source, &self.target, context)?;
        let options =
            SessionOpenOptions::new(self.target.instance().clone(), self.data_root.clone(), key)?;
        let session = Arc::new(RnmdbSessionOwner::open(options)?);
        apply_known_plan(&session, plan, context)?;
        Ok(session)
    }

    fn verify_completed_target(
        &self,
        session: &RnmdbSessionOwner,
        expected: SchemaVersion,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let key = take_key(&self.target_authentication_key)?;
        let verification = RnmdbMaintenance::verify(&self.target, key, context)?;
        require_authenticated(&verification)?;
        verify_application_version(session, expected, context)
    }

    fn claim_preflight(&self) -> Result<(), StorageError> {
        let mut state = lock_fail_closed(&self.state)?;
        if !matches!(*state, ExecutionState::Ready) {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        *state = ExecutionState::Preflighting;
        Ok(())
    }

    fn record_preflight(&self, plan: MigrationPlan) -> Result<(), StorageError> {
        let mut state = lock_fail_closed(&self.state)?;
        if !matches!(*state, ExecutionState::Preflighting) {
            return Err(StorageError::new(StorageErrorCode::Internal));
        }
        *state = ExecutionState::Prepared(plan);
        Ok(())
    }

    fn claim_application(&self, plan: &MigrationPlan) -> Result<(), StorageError> {
        let mut state = lock_fail_closed(&self.state)?;
        match &*state {
            ExecutionState::Prepared(prepared) if prepared == plan => {}
            ExecutionState::Prepared(_) => {
                return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
            }
            _ => return Err(StorageError::new(StorageErrorCode::Conflict)),
        }
        *state = ExecutionState::Applying;
        Ok(())
    }

    fn record_application(
        &self,
        plan: MigrationPlan,
        session: Arc<RnmdbSessionOwner>,
    ) -> Result<(), StorageError> {
        let mut state = lock_fail_closed(&self.state)?;
        if !matches!(*state, ExecutionState::Applying) {
            return Err(StorageError::new(StorageErrorCode::Internal));
        }
        *state = ExecutionState::Applied { plan, session };
        Ok(())
    }

    fn claim_verification(
        &self,
        expected: SchemaVersion,
    ) -> Result<Arc<RnmdbSessionOwner>, StorageError> {
        let mut state = lock_fail_closed(&self.state)?;
        let session = match &*state {
            ExecutionState::Applied { plan, session } if plan.target() == expected => {
                session.clone()
            }
            ExecutionState::Applied { .. } => {
                return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
            }
            _ => return Err(StorageError::new(StorageErrorCode::Conflict)),
        };
        *state = ExecutionState::Verifying;
        Ok(session)
    }

    fn record_verification(&self) -> Result<(), StorageError> {
        let mut state = lock_fail_closed(&self.state)?;
        if !matches!(*state, ExecutionState::Verifying) {
            return Err(StorageError::new(StorageErrorCode::Internal));
        }
        *state = ExecutionState::Complete;
        Ok(())
    }
}

impl Debug for RnmdbMigrationExecutor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbMigrationExecutor")
            .field("data_root", &"<redacted>")
            .field("source", self.source.instance())
            .field("target", self.target.instance())
            .field("page_keys", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl MigrationExecutorPort for RnmdbMigrationExecutor {
    fn preflight(
        &self,
        source: &StorageInstanceId,
        target: &StorageInstanceId,
        plan: &MigrationPlan,
        context: &RequestContext,
    ) -> Result<MigrationPreflight, StorageError> {
        self.validate_bound_operation(source, target)?;
        validate_known_plan(plan)?;
        check_context(context)?;
        self.claim_preflight()?;
        let preflight = self.perform_preflight(context)?;
        self.record_preflight(plan.clone())?;
        Ok(preflight)
    }

    fn apply_to_new_target(
        &self,
        source: &StorageInstanceId,
        target: &StorageInstanceId,
        plan: &MigrationPlan,
        preflight: MigrationPreflight,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.validate_bound_operation(source, target)?;
        validate_known_plan(plan)?;
        require_permitted_preflight(&preflight, plan)?;
        check_context(context)?;
        self.claim_application(plan)?;
        let session = self.apply_plan(plan, context)?;
        self.record_application(plan.clone(), session)
    }

    fn verify_target(
        &self,
        source: &StorageInstanceId,
        target: &StorageInstanceId,
        expected: SchemaVersion,
        context: &RequestContext,
    ) -> Result<MigrationReceipt, StorageError> {
        self.validate_bound_operation(source, target)?;
        check_context(context)?;
        let session = self.claim_verification(expected)?;
        self.verify_completed_target(&session, expected, context)?;
        let receipt =
            MigrationReceipt::new(source.clone(), target.clone(), expected, SystemTime::now());
        self.record_verification()?;
        Ok(receipt)
    }
}

enum ExecutionState {
    Ready,
    Preflighting,
    Prepared(MigrationPlan),
    Applying,
    Applied {
        plan: MigrationPlan,
        session: Arc<RnmdbSessionOwner>,
    },
    Verifying,
    Complete,
}

#[derive(Clone, Copy)]
enum KnownMigration {
    PlatformInitial,
    PlatformSecretReferences,
}

fn ensure_distinct_instances(
    source: &StorageInstanceId,
    target: &StorageInstanceId,
) -> Result<(), StorageError> {
    if source == target {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn require_missing_target(target: &StorageFileLocation) -> Result<(), StorageError> {
    let exists = target
        .path()
        .try_exists()
        .map_err(|_| StorageError::new(StorageErrorCode::Unavailable))?;
    if exists {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn require_authenticated(verification: &VerificationSummary) -> Result<(), StorageError> {
    if !verification.is_valid() || !verification.encryption_authenticated() {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn require_permitted_preflight(
    preflight: &MigrationPreflight,
    plan: &MigrationPlan,
) -> Result<(), StorageError> {
    if !preflight.permits(plan) {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn validate_known_plan(plan: &MigrationPlan) -> Result<(), StorageError> {
    if plan.steps().is_empty() || plan.requires_backup() {
        return Err(StorageError::new(StorageErrorCode::MigrationRequired));
    }
    for descriptor in plan.steps() {
        KnownMigration::from_descriptor(descriptor)?;
    }
    Ok(())
}

impl KnownMigration {
    fn from_descriptor(descriptor: &MigrationDescriptor) -> Result<Self, StorageError> {
        let (known, expected) = match descriptor.id().as_str() {
            PLATFORM_INITIAL_ID => (Self::PlatformInitial, platform_initial_migration()?),
            PLATFORM_SECRET_REFERENCES_ID => (
                Self::PlatformSecretReferences,
                platform_secret_references_migration()?,
            ),
            _ => return Err(StorageError::new(StorageErrorCode::MigrationRequired)),
        };
        if descriptor != &expected {
            return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
        }
        Ok(known)
    }
}

fn apply_known_plan(
    session: &Arc<RnmdbSessionOwner>,
    plan: &MigrationPlan,
    context: &RequestContext,
) -> Result<(), StorageError> {
    let applied_at = current_utc_micros()?;
    let runner = RnmdbMigrationRunner::new(session.clone());
    for descriptor in plan.steps() {
        let migration = KnownMigration::from_descriptor(descriptor)?;
        apply_known_migration(&runner, migration, applied_at, context)?;
    }
    Ok(())
}

fn apply_known_migration(
    runner: &RnmdbMigrationRunner,
    migration: KnownMigration,
    applied_at: UtcTimestampMicros,
    context: &RequestContext,
) -> Result<(), StorageError> {
    let status = match migration {
        KnownMigration::PlatformInitial => runner.apply_platform_initial(applied_at, context)?,
        KnownMigration::PlatformSecretReferences => {
            runner.apply_platform_secret_references(applied_at, context)?
        }
    };
    if status != MigrationApplyStatus::Applied {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn current_utc_micros() -> Result<UtcTimestampMicros, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::new(StorageErrorCode::Internal))?;
    let micros = i64::try_from(duration.as_micros())
        .map_err(|_| StorageError::new(StorageErrorCode::Internal))?;
    UtcTimestampMicros::new(micros)
}

fn verify_application_version(
    session: &RnmdbSessionOwner,
    expected: SchemaVersion,
    context: &RequestContext,
) -> Result<(), StorageError> {
    let output = session.with_session(context, |local| local.execute(MIGRATION_LEDGER_QUERY))?;
    validate_migration_ledger(output, expected)
}

fn validate_migration_ledger(
    output: CommandOutput,
    expected_version: SchemaVersion,
) -> Result<(), StorageError> {
    let CommandOutput::Rows(batch) = output else {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    };
    validate_ledger_columns(batch.columns())?;
    let descriptors = expected_ledger(expected_version)?;
    if batch.rows().len() != descriptors.len() {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    for descriptor in &descriptors {
        require_one_ledger_row(batch.rows(), descriptor)?;
    }
    Ok(())
}

fn expected_ledger(version: SchemaVersion) -> Result<Vec<MigrationDescriptor>, StorageError> {
    match version.get() {
        2 => Ok(vec![platform_initial_migration()?]),
        3 => Ok(vec![
            platform_initial_migration()?,
            platform_secret_references_migration()?,
        ]),
        _ => Err(StorageError::new(StorageErrorCode::MigrationRequired)),
    }
}

fn validate_ledger_columns(columns: &[ColumnSchema]) -> Result<(), StorageError> {
    let expected = [
        ("migration_id", SqlType::Text),
        ("domain", SqlType::Text),
        ("from_version", SqlType::Int64),
        ("to_version", SqlType::Int64),
        ("checksum", SqlType::Text),
    ];
    if columns.len() != expected.len() {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    for (column, (name, data_type)) in columns.iter().zip(expected) {
        if column.name() != name || column.data_type() != &data_type {
            return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
        }
    }
    Ok(())
}

fn require_one_ledger_row(
    rows: &[Row],
    descriptor: &MigrationDescriptor,
) -> Result<(), StorageError> {
    let mut matches = 0_usize;
    for row in rows {
        if ledger_row_matches(row, descriptor)? {
            matches += 1;
        }
    }
    if matches != 1 {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn ledger_row_matches(row: &Row, descriptor: &MigrationDescriptor) -> Result<bool, StorageError> {
    let [
        SqlValue::Text(id),
        SqlValue::Text(domain),
        SqlValue::Int64(from),
        SqlValue::Int64(to),
        SqlValue::Text(checksum),
    ] = row.values()
    else {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    };
    let expected_from = i64::try_from(descriptor.from().get())
        .map_err(|_| StorageError::new(StorageErrorCode::IntegrityFailure))?;
    let expected_to = i64::try_from(descriptor.to().get())
        .map_err(|_| StorageError::new(StorageErrorCode::IntegrityFailure))?;
    let expected_checksum = descriptor.checksum().to_string();
    Ok(id.as_str() == descriptor.id().as_str()
        && domain.as_str() == PLATFORM_DOMAIN
        && *from == expected_from
        && *to == expected_to
        && checksum.as_str() == expected_checksum)
}

fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| {
        let code = match error.code() {
            ErrorCode::Cancelled => StorageErrorCode::Cancelled,
            ErrorCode::DeadlineExceeded => StorageErrorCode::DeadlineExceeded,
            _ => StorageErrorCode::Internal,
        };
        StorageError::new(code)
    })
}

fn take_key(slot: &Mutex<Option<PageKeyMaterial>>) -> Result<PageKeyMaterial, StorageError> {
    lock_fail_closed(slot)?
        .take()
        .ok_or_else(|| StorageError::new(StorageErrorCode::Conflict))
}

fn lock_fail_closed<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, StorageError> {
    mutex
        .lock()
        .map_err(|_| StorageError::new(StorageErrorCode::Unavailable))
}

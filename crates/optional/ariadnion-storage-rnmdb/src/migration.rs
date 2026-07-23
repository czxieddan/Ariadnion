//! Verified application migrations expressed as fixed Rust data.

use std::sync::Arc;

use ariadnion_audit_domain::migrations::IDENTITY_AUDIT_MIGRATION_ID;
use ariadnion_auth_api_key::migrations::IDENTITY_API_KEYS_MIGRATION_ID;
use ariadnion_auth_password::migrations::IDENTITY_PASSWORD_MIGRATION_ID;
use ariadnion_auth_session::migrations::IDENTITY_SESSIONS_MIGRATION_ID;
use ariadnion_core::RequestContext;
use ariadnion_invitation::migrations::IDENTITY_INVITATION_MIGRATION_ID;
use ariadnion_organization::migrations::IDENTITY_ORGANIZATION_MIGRATION_ID;
use ariadnion_storage_domain::{MigrationDescriptor, StorageError, StorageErrorCode};
use ariadnion_user_domain::migrations::IDENTITY_USERS_MIGRATION_ID;
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_executor::vector::{ColumnSchema, Row};
use rnmdb_types::{SqlType, SqlValue};

use crate::migration_definition::{
    MigrationLookupOrder, PLATFORM_INITIAL_ID, PLATFORM_OUTBOX_ID, PLATFORM_SECRET_REFERENCES_ID,
    RnmdbMigrationDefinition, compiled_migration_definitions,
};
use crate::{RnmdbSessionOwner, UtcTimestampMicros};

const MAX_LEDGER_LITERAL_BYTES: usize = 256;

/// Result of applying one immutable migration definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationApplyStatus {
    /// The migration was committed and checkpointed by the durable session.
    Applied,
    /// The same identity and checksum were already durably recorded.
    AlreadyApplied,
}

/// Executes verified migrations through one serialized embedded session.
pub struct RnmdbMigrationRunner {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbMigrationRunner {
    /// Creates a runner for one isolated long-lived session owner.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Returns the serialized embedded session used by this runner.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }

    /// Applies the initial platform migration exactly once.
    ///
    /// The session mutex remains held from `BEGIN` through `COMMIT` or
    /// `ROLLBACK`, so no other adapter operation can enter the migration
    /// transaction. A successful durable commit performs RNMDB's checkpoint.
    /// Cancellation or deadline expiry before lock acquisition returns a
    /// stable storage error without opening a transaction.
    pub fn apply_platform_initial(
        &self,
        applied_at: UtcTimestampMicros,
        context: &RequestContext,
    ) -> Result<MigrationApplyStatus, StorageError> {
        self.apply(&platform_initial_migration()?, applied_at, context)
    }

    /// Applies the encrypted secret-reference schema exactly once.
    ///
    /// The initial platform migration must already be present. This creates
    /// schema metadata only; callers inject the column key before encrypted
    /// locators are written or read.
    pub fn apply_platform_secret_references(
        &self,
        applied_at: UtcTimestampMicros,
        context: &RequestContext,
    ) -> Result<MigrationApplyStatus, StorageError> {
        self.apply(
            &platform_secret_references_migration()?,
            applied_at,
            context,
        )
    }

    /// Applies the transactional outbox schema exactly once.
    ///
    /// The schema stores tenant-scoped events, idempotency boundaries, and
    /// recoverable lease state. It does not start a dispatcher or perform an
    /// external side effect while the migration transaction is active.
    pub fn apply_platform_outbox(
        &self,
        applied_at: UtcTimestampMicros,
        context: &RequestContext,
    ) -> Result<MigrationApplyStatus, StorageError> {
        self.apply(&platform_outbox_migration()?, applied_at, context)
    }

    /// Applies an exact descriptor only when it is present in the compiled registry.
    ///
    /// The caller cannot supply SQL. Descriptor metadata is compared in full
    /// before the registry's fixed statement slice can enter a transaction.
    /// Every non-applied transaction path is rolled back.
    ///
    /// # Errors
    ///
    /// Returns [`StorageErrorCode::MigrationRequired`] for an unknown identity,
    /// [`StorageErrorCode::IntegrityFailure`] for metadata or ledger mismatch,
    /// and the stable mapped storage error for session or execution failure.
    pub fn apply(
        &self,
        descriptor: &MigrationDescriptor,
        applied_at: UtcTimestampMicros,
        context: &RequestContext,
    ) -> Result<MigrationApplyStatus, StorageError> {
        let definitions = compiled_migration_definitions()?;
        let definition = definitions.definition_for(descriptor)?;
        let lookup = migration_lookup(definition.descriptor())?;
        let insert = migration_insert(definition.descriptor(), applied_at)?;
        self.session.with_session(context, |session| {
            run_migration_transaction(session, definition, &lookup, &insert)
        })
    }
}

/// Returns the initial platform migration after fixed digest verification.
///
/// Schema version one is the empty Ariadnion application baseline. This
/// transition installs the migration ledger and advances the platform schema
/// to version two without requiring a backup of an empty target.
pub fn platform_initial_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(PLATFORM_INITIAL_ID)
}

/// Returns the encrypted secret-reference migration after digest verification.
pub fn platform_secret_references_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(PLATFORM_SECRET_REFERENCES_ID)
}

/// Returns the transactional outbox migration after digest verification.
pub fn platform_outbox_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(PLATFORM_OUTBOX_ID)
}

/// Returns the durable user migration after canonical digest verification.
///
/// The migration remains outside module startup. Callers must request the
/// version-four to version-five transition explicitly through the registry.
pub fn identity_users_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(IDENTITY_USERS_MIGRATION_ID)
}

/// Returns the durable identity audit migration after canonical digest verification.
///
/// The migration remains outside module startup. Callers must request the
/// version-five to version-six transition explicitly through the registry.
pub fn identity_audit_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(IDENTITY_AUDIT_MIGRATION_ID)
}

/// Returns the durable organization migration after canonical digest verification.
///
/// The migration remains outside module startup. Callers must request the
/// version-six to version-seven transition explicitly through the registry.
pub fn identity_organization_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(IDENTITY_ORGANIZATION_MIGRATION_ID)
}

/// Returns the durable invitation migration after canonical digest verification.
///
/// The migration remains outside module startup. Callers must request the
/// version-seven to version-eight transition explicitly through the registry.
pub fn identity_invitation_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(IDENTITY_INVITATION_MIGRATION_ID)
}

/// Returns the durable password migration after canonical digest verification.
///
/// The migration remains outside module startup. Callers must request the
/// version-eight to version-nine transition explicitly through the registry.
pub fn identity_password_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(IDENTITY_PASSWORD_MIGRATION_ID)
}

/// Returns the durable browser-session migration after canonical digest verification.
///
/// The migration remains outside module startup. Callers must request the
/// version-nine to version-ten transition explicitly through the registry.
pub fn identity_session_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(IDENTITY_SESSIONS_MIGRATION_ID)
}

/// Returns the durable scoped API-key migration after canonical digest verification.
///
/// The migration remains outside module startup. Callers must request the
/// version-ten to version-eleven transition explicitly through the registry.
pub fn identity_api_key_migration() -> Result<MigrationDescriptor, StorageError> {
    compiled_migration_definitions()?.descriptor(IDENTITY_API_KEYS_MIGRATION_ID)
}

fn migration_insert(
    descriptor: &MigrationDescriptor,
    applied_at: UtcTimestampMicros,
) -> Result<String, StorageError> {
    let migration_id = ledger_literal(descriptor.id().as_str())?;
    let domain = ledger_literal(descriptor.domain().as_str())?;
    let checksum = ledger_literal(&descriptor.checksum().to_string())?;
    let timestamp = ledger_literal(&applied_at.to_sql_timestamp().to_rfc3339_string())?;
    let binary_version = ledger_literal(env!("CARGO_PKG_VERSION"))?;
    let (from, to) = ledger_versions(descriptor)?;
    Ok(format!(
        "INSERT INTO platform_schema_migrations (migration_id, domain, from_version, to_version, checksum, applied_at, binary_version) VALUES ({migration_id}, {domain}, {from}, {to}, {checksum}, CAST({timestamp} AS TIMESTAMP), {binary_version});"
    ))
}

fn migration_lookup(descriptor: &MigrationDescriptor) -> Result<String, StorageError> {
    let migration_id = ledger_literal(descriptor.id().as_str())?;
    Ok(format!(
        "SELECT migration_id, domain, from_version, to_version, checksum FROM platform_schema_migrations WHERE migration_id = {migration_id};"
    ))
}

fn ledger_literal(value: &str) -> Result<String, StorageError> {
    if value.len() > MAX_LEDGER_LITERAL_BYTES || !value.is_ascii() || value.contains('\'') {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(format!("'{value}'"))
}

fn ledger_versions(descriptor: &MigrationDescriptor) -> Result<(i64, i64), StorageError> {
    let from = i64::try_from(descriptor.from().get())
        .map_err(|_| StorageError::new(StorageErrorCode::ResourceExhausted))?;
    let to = i64::try_from(descriptor.to().get())
        .map_err(|_| StorageError::new(StorageErrorCode::ResourceExhausted))?;
    Ok((from, to))
}

fn run_migration_transaction(
    session: &mut LocalSession,
    definition: &RnmdbMigrationDefinition,
    lookup: &str,
    insert: &str,
) -> Result<MigrationApplyStatus, RnovError> {
    session.execute("BEGIN")?;
    let result = apply_migration_body(session, definition, lookup, insert);
    finish_migration_transaction(session, result)
}

fn apply_migration_body(
    session: &mut LocalSession,
    definition: &RnmdbMigrationDefinition,
    lookup: &str,
    insert: &str,
) -> Result<MigrationApplyStatus, RnovError> {
    match definition.lookup_order() {
        MigrationLookupOrder::CreateLedgerBeforeLookup => {
            apply_ledger_creating_body(session, definition, lookup, insert)
        }
        MigrationLookupOrder::LookupBeforeStatements => {
            apply_lookup_first_body(session, definition, lookup, insert)
        }
    }
}

fn apply_ledger_creating_body(
    session: &mut LocalSession,
    definition: &RnmdbMigrationDefinition,
    lookup: &str,
    insert: &str,
) -> Result<MigrationApplyStatus, RnovError> {
    execute_migration_statements(session, definition)?;
    let output = session.execute(lookup)?;
    if migration_record_exists(output, definition.descriptor())? {
        return Ok(MigrationApplyStatus::AlreadyApplied);
    }
    record_migration(session, insert)
}

fn apply_lookup_first_body(
    session: &mut LocalSession,
    definition: &RnmdbMigrationDefinition,
    lookup: &str,
    insert: &str,
) -> Result<MigrationApplyStatus, RnovError> {
    let output = session.execute(lookup)?;
    if migration_record_exists(output, definition.descriptor())? {
        return Ok(MigrationApplyStatus::AlreadyApplied);
    }
    execute_migration_statements(session, definition)?;
    record_migration(session, insert)
}

fn execute_migration_statements(
    session: &mut LocalSession,
    definition: &RnmdbMigrationDefinition,
) -> Result<(), RnovError> {
    for statement in definition.statements() {
        session.execute(statement)?;
    }
    Ok(())
}

fn record_migration(
    session: &mut LocalSession,
    insert: &str,
) -> Result<MigrationApplyStatus, RnovError> {
    require_single_insert(session.execute(insert)?)?;
    Ok(MigrationApplyStatus::Applied)
}

fn finish_migration_transaction(
    session: &mut LocalSession,
    result: Result<MigrationApplyStatus, RnovError>,
) -> Result<MigrationApplyStatus, RnovError> {
    match result {
        Ok(MigrationApplyStatus::Applied) => commit_migration(session),
        Ok(MigrationApplyStatus::AlreadyApplied) => rollback_existing_migration(session),
        Err(error) => rollback_with_error(session, error),
    }
}

fn commit_migration(session: &mut LocalSession) -> Result<MigrationApplyStatus, RnovError> {
    if let Err(error) = session.execute("COMMIT") {
        return rollback_with_error(session, error);
    }
    Ok(MigrationApplyStatus::Applied)
}

fn rollback_existing_migration(
    session: &mut LocalSession,
) -> Result<MigrationApplyStatus, RnovError> {
    session.execute("ROLLBACK")?;
    Ok(MigrationApplyStatus::AlreadyApplied)
}

fn rollback_with_error<T>(session: &mut LocalSession, error: RnovError) -> Result<T, RnovError> {
    session.execute("ROLLBACK")?;
    Err(error)
}

fn migration_record_exists(
    output: CommandOutput,
    descriptor: &MigrationDescriptor,
) -> Result<bool, RnovError> {
    let CommandOutput::Rows(batch) = output else {
        return Err(migration_corruption("migration lookup did not return rows"));
    };
    validate_ledger_columns(batch.columns())?;
    match batch.rows() {
        [] => Ok(false),
        [row] => validate_ledger_row(row, descriptor).map(|()| true),
        _ => Err(migration_corruption("migration identity is not unique")),
    }
}

fn validate_ledger_columns(columns: &[ColumnSchema]) -> Result<(), RnovError> {
    let expected = [
        ("migration_id", SqlType::Text),
        ("domain", SqlType::Text),
        ("from_version", SqlType::Int64),
        ("to_version", SqlType::Int64),
        ("checksum", SqlType::Text),
    ];
    if columns.len() != expected.len() {
        return Err(migration_corruption(
            "migration lookup column count changed",
        ));
    }
    for (column, (name, data_type)) in columns.iter().zip(expected) {
        if column.name() != name || column.data_type() != &data_type {
            return Err(migration_corruption("migration lookup schema changed"));
        }
    }
    Ok(())
}

fn validate_ledger_row(row: &Row, descriptor: &MigrationDescriptor) -> Result<(), RnovError> {
    let from = descriptor_version_i64(descriptor.from().get())?;
    let to = descriptor_version_i64(descriptor.to().get())?;
    let expected = [
        SqlValue::Text(descriptor.id().as_str().into()),
        SqlValue::Text(descriptor.domain().as_str().into()),
        SqlValue::Int64(from),
        SqlValue::Int64(to),
        SqlValue::Text(descriptor.checksum().to_string()),
    ];
    if row.values() != expected.as_slice() {
        return Err(migration_corruption(
            "migration record does not match its definition",
        ));
    }
    Ok(())
}

fn descriptor_version_i64(version: u64) -> Result<i64, RnovError> {
    i64::try_from(version)
        .map_err(|_| migration_corruption("migration version exceeds RNMDB INT64"))
}

fn require_single_insert(output: CommandOutput) -> Result<(), RnovError> {
    if output != CommandOutput::RowsAffected(1) {
        return Err(migration_corruption(
            "migration ledger insert count changed",
        ));
    }
    Ok(())
}

fn migration_corruption(message: &'static str) -> RnovError {
    RnovError::new(ErrorKind::Corruption, message)
}

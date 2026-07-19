//! Verified application migrations expressed as fixed Rust data.

use std::sync::Arc;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{
    MigrationChecksum, MigrationDescriptor, MigrationId, SchemaVersion, StorageError,
    StorageErrorCode,
};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_executor::vector::{ColumnSchema, Row};
use rnmdb_sql::ast::Statement;
use rnmdb_sql::parser::parse_statement;
use rnmdb_types::{SqlType, SqlValue};
use sha2::{Digest, Sha256};

use crate::{RnmdbSessionOwner, UtcTimestampMicros};

const PLATFORM_INITIAL_ID: &str = "platform.0001.initial";
const PLATFORM_DOMAIN: &str = "platform";
const MAX_LEDGER_LITERAL_BYTES: usize = 256;
const PLATFORM_INITIAL_STATEMENTS: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS platform_schema_migrations (migration_id TEXT NOT NULL, domain TEXT NOT NULL, from_version INT64 NOT NULL, to_version INT64 NOT NULL, checksum TEXT NOT NULL, applied_at TIMESTAMP NOT NULL, binary_version TEXT NOT NULL);",
    "CREATE UNIQUE INDEX IF NOT EXISTS platform_schema_migrations_id_uq ON platform_schema_migrations (migration_id);",
];
const PLATFORM_INITIAL_SHA256: [u8; 32] = [
    0xa1, 0x73, 0xea, 0x15, 0xd5, 0x5b, 0x21, 0xcf, 0xf7, 0xa1, 0x3e, 0xa6, 0xab, 0xa8, 0x1a, 0x7b,
    0xca, 0x75, 0x39, 0x48, 0x4e, 0x40, 0x04, 0x2c, 0x3d, 0x05, 0xf7, 0x96, 0xe6, 0xc5, 0x2f, 0xee,
];

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
        let descriptor = platform_initial_migration()?;
        let lookup = migration_lookup(&descriptor)?;
        let insert = platform_initial_insert(&descriptor, applied_at)?;
        self.session.with_session(context, |session| {
            run_migration_transaction(
                session,
                &descriptor,
                &PLATFORM_INITIAL_STATEMENTS,
                &lookup,
                &insert,
            )
        })
    }
}

/// Returns the initial platform migration after parsing and digest verification.
///
/// Schema version one is the empty Ariadnion application baseline. This
/// transition installs the migration ledger and advances the platform schema
/// to version two without requiring a backup of an empty target.
pub fn platform_initial_migration() -> Result<MigrationDescriptor, StorageError> {
    MigrationDescriptor::new(
        MigrationId::parse(PLATFORM_INITIAL_ID)?,
        SchemaVersion::new(1)?,
        SchemaVersion::new(2)?,
        verified_platform_initial_checksum()?,
        false,
    )
}

fn platform_initial_insert(
    descriptor: &MigrationDescriptor,
    applied_at: UtcTimestampMicros,
) -> Result<String, StorageError> {
    let migration_id = ledger_literal(descriptor.id().as_str())?;
    let domain = ledger_literal(PLATFORM_DOMAIN)?;
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
    descriptor: &MigrationDescriptor,
    statements: &[&str],
    lookup: &str,
    insert: &str,
) -> Result<MigrationApplyStatus, RnovError> {
    session.execute("BEGIN")?;
    let result = apply_migration_body(session, descriptor, statements, lookup, insert);
    finish_migration_transaction(session, result)
}

fn apply_migration_body(
    session: &mut LocalSession,
    descriptor: &MigrationDescriptor,
    statements: &[&str],
    lookup: &str,
    insert: &str,
) -> Result<MigrationApplyStatus, RnovError> {
    for statement in statements {
        session.execute(statement)?;
    }
    let output = session.execute(lookup)?;
    if migration_record_exists(output, descriptor)? {
        return Ok(MigrationApplyStatus::AlreadyApplied);
    }
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
        SqlValue::Text(PLATFORM_DOMAIN.into()),
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

fn verified_platform_initial_checksum() -> Result<MigrationChecksum, StorageError> {
    validate_platform_initial_statements()?;
    let actual = calculate_checksum(&PLATFORM_INITIAL_STATEMENTS)?;
    if actual != PLATFORM_INITIAL_SHA256 {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(MigrationChecksum::new(actual))
}

fn validate_platform_initial_statements() -> Result<(), StorageError> {
    for (index, sql) in PLATFORM_INITIAL_STATEMENTS.iter().enumerate() {
        validate_platform_statement(index, sql)?;
    }
    Ok(())
}

fn validate_platform_statement(index: usize, sql: &str) -> Result<(), StorageError> {
    let statement =
        parse_statement(sql).map_err(|_| StorageError::new(StorageErrorCode::IntegrityFailure))?;
    let allowed = match (index, statement) {
        (0, Statement::CreateTable { .. }) => true,
        (1, Statement::CreateIndex { unique: true, .. }) => true,
        _ => false,
    };
    if !allowed {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn calculate_checksum(statements: &[&str]) -> Result<[u8; 32], StorageError> {
    let mut hasher = Sha256::new();
    for statement in statements {
        let length = u64::try_from(statement.len())
            .map_err(|_| StorageError::new(StorageErrorCode::ResourceExhausted))?;
        hasher.update(length.to_be_bytes());
        hasher.update(statement.as_bytes());
    }
    Ok(hasher.finalize().into())
}

//! Verified application migrations expressed as fixed Rust data.

use ariadnion_storage_domain::{
    MigrationChecksum, MigrationDescriptor, MigrationId, SchemaVersion, StorageError,
    StorageErrorCode,
};
use rnmdb_sql::ast::Statement;
use rnmdb_sql::parser::parse_statement;
use sha2::{Digest, Sha256};

const PLATFORM_INITIAL_ID: &str = "platform.0001.initial";
const PLATFORM_INITIAL_STATEMENTS: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS platform_schema_migrations (migration_id TEXT NOT NULL, domain TEXT NOT NULL, from_version INT64 NOT NULL, to_version INT64 NOT NULL, checksum TEXT NOT NULL, applied_at TIMESTAMP NOT NULL, binary_version TEXT NOT NULL);",
    "CREATE UNIQUE INDEX IF NOT EXISTS platform_schema_migrations_id_uq ON platform_schema_migrations (migration_id);",
];
const PLATFORM_INITIAL_SHA256: [u8; 32] = [
    0xa1, 0x73, 0xea, 0x15, 0xd5, 0x5b, 0x21, 0xcf, 0xf7, 0xa1, 0x3e, 0xa6, 0xab, 0xa8, 0x1a, 0x7b,
    0xca, 0x75, 0x39, 0x48, 0x4e, 0x40, 0x04, 0x2c, 0x3d, 0x05, 0xf7, 0x96, 0xe6, 0xc5, 0x2f, 0xee,
];

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

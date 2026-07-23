//! RNMDB storage adapter with explicit upstream capability coverage.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::any::type_name;

mod audit_repository;
mod backup;
mod codec;
mod file_integrity;
mod identity_transaction;
mod index;
mod inspection;
mod instance;
mod location;
mod maintenance;
mod migration;
mod migration_definition;
mod migration_executor;
mod module;
mod outbox;
mod query;
mod restore;
mod secret_reference;
mod secret_reference_repository;
mod security;
mod session;
mod transaction;
mod udf;
mod upgrade;
mod user_repository;

pub use audit_repository::{MAX_AUDIT_MEMBERSHIP_DISTANCE, RnmdbAuditRepository};
pub use backup::{RnmdbBackupAdapter, RnmdbBackupEnvironment};
pub use codec::{CurrencyCode, MoneyValue, NormalizedJson, StorageUuid, UtcTimestampMicros};
pub use index::{FixedIndexDefinition, RnmdbIndexManager, RnmdbIndexMethod};
pub use inspection::{RnmdbInspectionAdapter, RnmdbInspectionResolver};
pub use instance::{RnmdbInstanceProfile, RnmdbInstanceRegistry, RnmdbInstanceResourceLimits};
pub use location::StorageFileLocation;
pub use maintenance::{
    BackupSummary, NewTargetSummary, RestorePreflight, RnmdbMaintenance, UpgradeSummary,
    VerificationSummary,
};
pub use migration::{
    MigrationApplyStatus, RnmdbMigrationRunner, identity_audit_migration, identity_users_migration,
    platform_initial_migration, platform_outbox_migration, platform_secret_references_migration,
};
pub use migration_definition::canonical_migration_checksum;
pub use migration_executor::{RnmdbMigrationExecutor, RnmdbMigrationPageKeys};
pub use module::{StorageRnmdbModule, StorageRnmdbModuleOptions};
pub use outbox::{OutboxLeaseKeyMaterial, RnmdbOutboxRepository};
pub use query::{
    FixedRnmdbReadQuery, QueryPlanDiagnostic, QueryPlanFormat, RnmdbFixedQueryExecutor,
    RnmdbQueryDiagnostics,
};
pub use restore::{
    RnmdbRestoreAdapter, RnmdbRestoreDomainVerification, RnmdbRestoreEnvironment,
    RnmdbShadowComparison,
};
pub use secret_reference::{
    NewSecretReference, SecretKeyVersion, SecretLocator, SecretReference, SecretReferenceId,
    SecretReferenceKind, SecretReferenceUpdate,
};
pub use secret_reference_repository::RnmdbSecretReferenceRepository;
pub use security::{RnmdbColumnSecurity, SecretLocatorKeyMaterial};
pub use session::{PageKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};
pub use transaction::RnmdbTransactionManager;
pub use udf::{
    FIXED_UDF_RESULT_BYTES, FixedScalarSignature, FixedScalarType, FixedScalarUdfDefinition,
    FixedUdfResourceLimits, LockedDownUdfCapabilities, MAX_FIXED_UDF_ARGUMENTS,
    MAX_FIXED_UDF_IMPORTS, MAX_FIXED_UDF_INSTRUCTIONS, MAX_FIXED_UDF_MEMORY_BYTES,
    MAX_FIXED_UDF_MODULE_BYTES, MAX_FIXED_UDF_NAME_BYTES, MAX_FIXED_UDF_TIMEOUT_MILLIS,
    RnmdbScalarUdfRegistrar,
};
pub use upgrade::{
    RnmdbRetainedSourceInspection, RnmdbUpgradeAdapter, RnmdbUpgradeDomainVerification,
    RnmdbUpgradeEnvironment,
};
pub use user_repository::{AuditSubjectKeyMaterial, RnmdbUserRepository};

/// The reviewed upstream source revision compiled by this adapter.
pub const REVIEWED_RNMDB_COMMIT: &str = "f07f1da2c1a193ad3732ee779d228ac8ec3dbffd";

/// One compile-time link between an RNMDB package and an adapter boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamCrateUse {
    package: &'static str,
    symbol: &'static str,
    purpose: &'static str,
}

impl UpstreamCrateUse {
    /// Returns the exact Cargo package name.
    #[must_use]
    pub const fn package(self) -> &'static str {
        self.package
    }

    /// Returns a public upstream type compiled into the adapter.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        self.symbol
    }

    /// Returns the stable adapter responsibility for this package.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        self.purpose
    }
}

/// Returns compile-time evidence that all reviewed RNMDB crates are linked.
///
/// This inventory is the starting coverage gate. Concrete adapter modules use
/// the same packages for session, codec, transaction, index, security,
/// maintenance, and sandbox behavior as those paths are implemented.
#[must_use]
pub fn upstream_crate_inventory() -> [UpstreamCrateUse; 15] {
    [
        crate_use::<rnmdb_common::config::EngineConfig>(
            "rnmdb-common",
            "engine configuration and safe error mapping",
        ),
        crate_use::<rnmdb_types::SqlValue>("rnmdb-types", "value codecs"),
        crate_use::<rnmdb_sql::ast::Statement>("rnmdb-sql", "bounded SQL parsing"),
        crate_use::<rnmdb_planner::logical::LogicalPlan>("rnmdb-planner", "query plan diagnostics"),
        crate_use::<rnmdb_executor::row::RowCodec>("rnmdb-executor", "row execution codecs"),
        crate_use::<rnmdb_txn::IsolationLevel>("rnmdb-txn", "transaction isolation"),
        crate_use::<rnmdb_index::IndexKey>("rnmdb-index", "index keys and access paths"),
        crate_use::<rnmdb_fts::SimpleTokenizer>("rnmdb-fts", "full-text tokenization"),
        crate_use::<rnmdb_catalog::Catalog>("rnmdb-catalog", "schema and policy catalog"),
        crate_use::<rnmdb_storage::StorageCapability>(
            "rnmdb-storage",
            "encrypted single-file persistence",
        ),
        crate_use::<rnmdb_udf::UdfBudget>("rnmdb-udf", "sandboxed scalar functions"),
        crate_use::<rnmdb_security::AuditEventKind>(
            "rnmdb-security",
            "access control, encryption, and audit",
        ),
        crate_use::<rnmdb_instance::ResourceLimits>(
            "rnmdb-instance",
            "tenant instance resource isolation",
        ),
        crate_use::<rnmdb_server::EmbeddedRuntimeMode>(
            "rnmdb-server",
            "disabled-by-default maintenance runtime",
        ),
        crate_use::<rnmdb_cli::LocalSession>("rnmdb-cli", "long-lived embedded session"),
    ]
}

fn crate_use<T>(package: &'static str, purpose: &'static str) -> UpstreamCrateUse {
    UpstreamCrateUse {
        package,
        symbol: type_name::<T>(),
        purpose,
    }
}

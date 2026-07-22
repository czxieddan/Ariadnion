//! Immutable RNMDB migration definitions and compatibility evidence.

mod canonical;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use ariadnion_storage_domain::{
    MigrationCatalog, MigrationChecksum, MigrationDescriptor, MigrationDomain, MigrationId,
    MigrationPlan, SchemaVersion, StorageError, StorageErrorCode,
};
use sha2::{Digest, Sha256};

use self::canonical::CanonicalAstV1;

pub(crate) const PLATFORM_INITIAL_ID: &str = "platform.0001.initial";
pub(crate) const PLATFORM_SECRET_REFERENCES_ID: &str = "platform.0002.secret-references";
pub(crate) const PLATFORM_OUTBOX_ID: &str = "platform.0003.outbox";

const PLATFORM_DOMAIN: &str = "platform";
const PLATFORM_INITIAL_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS platform_schema_migrations (migration_id TEXT NOT NULL, domain TEXT NOT NULL, from_version INT64 NOT NULL, to_version INT64 NOT NULL, checksum TEXT NOT NULL, applied_at TIMESTAMP NOT NULL, binary_version TEXT NOT NULL);",
    "CREATE UNIQUE INDEX IF NOT EXISTS platform_schema_migrations_id_uq ON platform_schema_migrations (migration_id);",
];
const PLATFORM_INITIAL_SHA256: [u8; 32] = [
    0xa1, 0x73, 0xea, 0x15, 0xd5, 0x5b, 0x21, 0xcf, 0xf7, 0xa1, 0x3e, 0xa6, 0xab, 0xa8, 0x1a, 0x7b,
    0xca, 0x75, 0x39, 0x48, 0x4e, 0x40, 0x04, 0x2c, 0x3d, 0x05, 0xf7, 0x96, 0xe6, 0xc5, 0x2f, 0xee,
];
const PLATFORM_SECRET_REFERENCES_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS platform_secret_references (tenant_id TEXT NOT NULL, reference_id TEXT NOT NULL, purpose TEXT NOT NULL, locator TEXT NOT NULL ENCRYPTED, key_version INT64 NOT NULL);",
    "CREATE UNIQUE INDEX IF NOT EXISTS platform_secret_references_tenant_reference_uq ON platform_secret_references (tenant_id, reference_id);",
];
const PLATFORM_SECRET_REFERENCES_SHA256: [u8; 32] = [
    0x33, 0x01, 0x2e, 0xa2, 0x7b, 0xb5, 0xa2, 0xbe, 0xa3, 0x4c, 0x96, 0x0d, 0xd8, 0xb6, 0x1f, 0xf2,
    0x1c, 0x2a, 0x9c, 0xf4, 0x31, 0x57, 0x06, 0x88, 0xaf, 0x0d, 0xee, 0x64, 0x71, 0xd4, 0xc9, 0xe6,
];
const PLATFORM_OUTBOX_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS platform_outbox (tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, topic TEXT NOT NULL, idempotency_key TEXT NOT NULL, payload_hex TEXT NOT NULL, created_at TIMESTAMP NOT NULL, available_at TIMESTAMP NOT NULL, attempt INT64 NOT NULL, state TEXT NOT NULL, lease_token TEXT, lease_worker TEXT, lease_expires_at TIMESTAMP, delivered_at TIMESTAMP, failed_at TIMESTAMP);",
    "CREATE UNIQUE INDEX IF NOT EXISTS platform_outbox_tenant_event_uq ON platform_outbox (tenant_id, event_id);",
    "CREATE UNIQUE INDEX IF NOT EXISTS platform_outbox_tenant_idempotency_uq ON platform_outbox (tenant_id, idempotency_key);",
    "CREATE INDEX IF NOT EXISTS platform_outbox_claim_idx ON platform_outbox (tenant_id, state);",
];
const PLATFORM_OUTBOX_SHA256: [u8; 32] = [
    0xaa, 0x2d, 0xf5, 0x8a, 0xe0, 0x36, 0x0e, 0xb2, 0xd9, 0xe4, 0x3b, 0x06, 0x96, 0x13, 0x13, 0xf4,
    0x0c, 0x81, 0x23, 0x1c, 0x8d, 0x3e, 0x87, 0xd9, 0xbf, 0xff, 0xae, 0x01, 0xf6, 0x6d, 0xd6, 0x48,
];

/// Returns the versioned SHA-256 checksum of an explicitly allowed parsed AST.
///
/// SQL spelling, comments, optional trailing semicolons, and insignificant
/// whitespace never enter the digest. Unsupported top-level or nested AST
/// variants fail closed. Before parsing, a conservative lexical budget rejects
/// combined delimiter nesting and depth-producing expression tokens above 64;
/// a combined per-statement array/range type-wrapper token budget rejects more
/// than 16, even when those wrappers belong to independent shallow columns.
/// These budgets can reject unusually complex shallow SQL to keep parser and
/// AST-drop recursion bounded.
///
/// # Errors
///
/// Returns [`StorageErrorCode::InvalidArgument`] for an empty definition,
/// [`StorageErrorCode::ResourceExhausted`] when a documented encoding bound is
/// exceeded, or [`StorageErrorCode::IntegrityFailure`] when parsing fails or
/// any statement, field, type, or expression is outside the allowlist.
pub fn canonical_migration_checksum(
    statements: &[&str],
) -> Result<MigrationChecksum, StorageError> {
    CanonicalAstV1::checksum(statements)
}

/// One immutable migration that may be executed by the RNMDB adapter.
pub(crate) struct RnmdbMigrationDefinition {
    descriptor: MigrationDescriptor,
    statements: &'static [&'static str],
    lookup_order: MigrationLookupOrder,
}

impl RnmdbMigrationDefinition {
    pub(crate) const fn descriptor(&self) -> &MigrationDescriptor {
        &self.descriptor
    }

    pub(crate) const fn statements(&self) -> &'static [&'static str] {
        self.statements
    }

    pub(crate) const fn lookup_order(&self) -> MigrationLookupOrder {
        self.lookup_order
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationLookupOrder {
    CreateLedgerBeforeLookup,
    LookupBeforeStatements,
}

pub(crate) struct CanonicalMigrationDefinitionInput {
    pub(crate) id: &'static str,
    pub(crate) domain: &'static str,
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) statements: &'static [&'static str],
    pub(crate) expected_checksum: [u8; 32],
    pub(crate) requires_backup: bool,
}

pub(crate) trait MigrationDefinitionChecksumScheme {
    fn verified_checksum(
        self,
        input: &CanonicalMigrationDefinitionInput,
    ) -> Result<MigrationChecksum, StorageError>;

    fn lookup_order(self) -> MigrationLookupOrder;
}

pub(crate) fn compile_migration_definition<S: MigrationDefinitionChecksumScheme + Copy>(
    input: CanonicalMigrationDefinitionInput,
    scheme: S,
) -> Result<RnmdbMigrationDefinition, StorageError> {
    let checksum = scheme.verified_checksum(&input)?;
    let descriptor = MigrationDescriptor::new(
        MigrationId::parse(input.id)?,
        MigrationDomain::parse(input.domain)?,
        SchemaVersion::new(input.from)?,
        SchemaVersion::new(input.to)?,
        checksum,
        input.requires_backup,
    )?;
    Ok(RnmdbMigrationDefinition {
        descriptor,
        statements: input.statements,
        lookup_order: scheme.lookup_order(),
    })
}

impl MigrationDefinitionChecksumScheme for CanonicalAstV1 {
    fn verified_checksum(
        self,
        input: &CanonicalMigrationDefinitionInput,
    ) -> Result<MigrationChecksum, StorageError> {
        let checksum = Self::checksum(input.statements)?;
        if checksum.as_bytes() != &input.expected_checksum {
            return Err(integrity_failure());
        }
        Ok(checksum)
    }

    fn lookup_order(self) -> MigrationLookupOrder {
        MigrationLookupOrder::LookupBeforeStatements
    }
}

/// The complete immutable set of migrations compiled into this adapter.
pub(crate) struct RnmdbMigrationDefinitions {
    definitions: BTreeMap<MigrationId, RnmdbMigrationDefinition>,
    bootstrap_ids: BTreeSet<MigrationId>,
}

impl RnmdbMigrationDefinitions {
    fn compile() -> Result<Self, StorageError> {
        let mut definitions = BTreeMap::new();
        let mut bootstrap_ids = BTreeSet::new();
        for legacy in LegacyPlatformMigration::ALL {
            let definition = compile_legacy_platform_definition(legacy)?;
            let id = definition.descriptor().id().clone();
            if definitions.insert(id.clone(), definition).is_some() {
                return Err(integrity_failure());
            }
            bootstrap_ids.insert(id);
        }
        Ok(Self {
            definitions,
            bootstrap_ids,
        })
    }

    pub(crate) fn descriptor(&self, id: &str) -> Result<MigrationDescriptor, StorageError> {
        let id = MigrationId::parse(id)?;
        self.definitions
            .get(&id)
            .map(|definition| definition.descriptor().clone())
            .ok_or_else(integrity_failure)
    }

    pub(crate) fn definition_for(
        &self,
        descriptor: &MigrationDescriptor,
    ) -> Result<&RnmdbMigrationDefinition, StorageError> {
        let definition = self
            .definitions
            .get(descriptor.id())
            .ok_or_else(migration_required)?;
        if definition.descriptor() != descriptor {
            return Err(integrity_failure());
        }
        Ok(definition)
    }

    pub(crate) fn validate_plan(&self, plan: &MigrationPlan) -> Result<(), StorageError> {
        let expected = self.catalog()?.plan(plan.source(), plan.target())?;
        if &expected != plan {
            return Err(integrity_failure());
        }
        Ok(())
    }

    pub(crate) fn startup_plan(&self) -> Result<MigrationPlan, StorageError> {
        let catalog = self.bootstrap_catalog()?;
        let source = catalog
            .migrations()
            .first()
            .map(MigrationDescriptor::from)
            .ok_or_else(integrity_failure)?;
        let target = catalog
            .migrations()
            .last()
            .map(MigrationDescriptor::to)
            .ok_or_else(integrity_failure)?;
        let plan = catalog.plan(source, target)?;
        if plan.requires_backup() {
            return Err(migration_required());
        }
        Ok(plan)
    }

    pub(crate) fn ledger_descriptors(
        &self,
        version: SchemaVersion,
    ) -> Result<Vec<MigrationDescriptor>, StorageError> {
        let baseline = self.baseline()?;
        if version == baseline {
            return Ok(Vec::new());
        }
        self.catalog()
            .and_then(|catalog| catalog.plan(baseline, version))
            .map(|plan| plan.steps().to_vec())
    }

    fn catalog(&self) -> Result<MigrationCatalog, StorageError> {
        MigrationCatalog::new(self.descriptors_for(self.definitions.keys())?)
    }

    fn bootstrap_catalog(&self) -> Result<MigrationCatalog, StorageError> {
        MigrationCatalog::new(self.descriptors_for(self.bootstrap_ids.iter())?)
    }

    fn descriptors_for<'a>(
        &self,
        ids: impl Iterator<Item = &'a MigrationId>,
    ) -> Result<Vec<MigrationDescriptor>, StorageError> {
        ids.map(|id| {
            self.definitions
                .get(id)
                .map(|definition| definition.descriptor().clone())
                .ok_or_else(integrity_failure)
        })
        .collect()
    }

    fn baseline(&self) -> Result<SchemaVersion, StorageError> {
        self.definitions
            .values()
            .map(|definition| definition.descriptor().from())
            .min()
            .ok_or_else(integrity_failure)
    }
}

pub(crate) fn compiled_migration_definitions()
-> Result<&'static RnmdbMigrationDefinitions, StorageError> {
    static DEFINITIONS: OnceLock<Result<RnmdbMigrationDefinitions, StorageError>> = OnceLock::new();
    match DEFINITIONS.get_or_init(RnmdbMigrationDefinitions::compile) {
        Ok(definitions) => Ok(definitions),
        Err(error) => Err(*error),
    }
}

#[derive(Clone, Copy)]
enum LegacyPlatformMigration {
    Initial,
    SecretReferences,
    Outbox,
}

impl LegacyPlatformMigration {
    const ALL: [Self; 3] = [Self::Initial, Self::SecretReferences, Self::Outbox];

    const fn parts(self) -> LegacyPlatformParts {
        match self {
            Self::Initial => LegacyPlatformParts {
                id: PLATFORM_INITIAL_ID,
                from: 1,
                to: 2,
                statements: PLATFORM_INITIAL_STATEMENTS,
                checksum: PLATFORM_INITIAL_SHA256,
            },
            Self::SecretReferences => LegacyPlatformParts {
                id: PLATFORM_SECRET_REFERENCES_ID,
                from: 2,
                to: 3,
                statements: PLATFORM_SECRET_REFERENCES_STATEMENTS,
                checksum: PLATFORM_SECRET_REFERENCES_SHA256,
            },
            Self::Outbox => LegacyPlatformParts {
                id: PLATFORM_OUTBOX_ID,
                from: 3,
                to: 4,
                statements: PLATFORM_OUTBOX_STATEMENTS,
                checksum: PLATFORM_OUTBOX_SHA256,
            },
        }
    }
}

struct LegacyPlatformParts {
    id: &'static str,
    from: u64,
    to: u64,
    statements: &'static [&'static str],
    checksum: [u8; 32],
}

#[derive(Clone, Copy)]
struct LegacyRawV0(LegacyPlatformMigration);

impl MigrationDefinitionChecksumScheme for LegacyRawV0 {
    fn verified_checksum(
        self,
        input: &CanonicalMigrationDefinitionInput,
    ) -> Result<MigrationChecksum, StorageError> {
        let checksum = legacy_raw_v0_platform_checksum(self.0)?;
        if checksum.as_bytes() != &input.expected_checksum {
            return Err(integrity_failure());
        }
        Ok(checksum)
    }

    fn lookup_order(self) -> MigrationLookupOrder {
        match self.0 {
            LegacyPlatformMigration::Initial => MigrationLookupOrder::CreateLedgerBeforeLookup,
            LegacyPlatformMigration::SecretReferences | LegacyPlatformMigration::Outbox => {
                MigrationLookupOrder::LookupBeforeStatements
            }
        }
    }
}

fn compile_legacy_platform_definition(
    migration: LegacyPlatformMigration,
) -> Result<RnmdbMigrationDefinition, StorageError> {
    let parts = migration.parts();
    let input = CanonicalMigrationDefinitionInput {
        id: parts.id,
        domain: PLATFORM_DOMAIN,
        from: parts.from,
        to: parts.to,
        statements: parts.statements,
        expected_checksum: parts.checksum,
        requires_backup: false,
    };
    compile_migration_definition(input, LegacyRawV0(migration))
}

// Legacy raw hashing is permanently scoped to these three exact shipped
// platform definitions. No caller can supply statements, metadata, or a digest.
fn legacy_raw_v0_platform_checksum(
    migration: LegacyPlatformMigration,
) -> Result<MigrationChecksum, StorageError> {
    let parts = migration.parts();
    CanonicalAstV1::validate(parts.statements)?;
    let mut hasher = Sha256::new();
    for source in parts.statements {
        let length = u64::try_from(source.len()).map_err(|_| resource_exhausted())?;
        hasher.update(length.to_be_bytes());
        hasher.update(source.as_bytes());
    }
    Ok(MigrationChecksum::new(hasher.finalize().into()))
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn migration_required() -> StorageError {
    StorageError::new(StorageErrorCode::MigrationRequired)
}

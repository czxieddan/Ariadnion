//! Immutable migration metadata for durable scoped API keys.

/// Stable identifier of the durable API-key migration.
pub const IDENTITY_API_KEYS_MIGRATION_ID: &str = "identity.0007.api-keys";

/// Stable domain recorded for the durable API-key migration.
pub const IDENTITY_API_KEYS_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the API-key migration.
pub const IDENTITY_API_KEYS_MIGRATION_FROM_VERSION: u64 = 10;

/// Global schema version produced by the API-key migration.
pub const IDENTITY_API_KEYS_MIGRATION_TO_VERSION: u64 = 11;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_API_KEYS_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered single-statement definitions for API-key state and events.
pub const IDENTITY_API_KEYS_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_api_keys (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, api_key_id TEXT NOT NULL, prefix TEXT NOT NULL, current_secret_digest TEXT NOT NULL, previous_secret_digest TEXT, rotation_started_at INT64, previous_secret_expires_at INT64, issued_at INT64 NOT NULL, expires_at INT64, version TEXT NOT NULL, state TEXT NOT NULL);",
    "CREATE TABLE identity_api_key_scopes (tenant_id TEXT NOT NULL, api_key_id TEXT NOT NULL, scope TEXT NOT NULL);",
    "CREATE TABLE identity_api_key_retired_secrets (tenant_id TEXT NOT NULL, api_key_id TEXT NOT NULL, ordinal INT64 NOT NULL, secret_digest TEXT NOT NULL);",
    "CREATE TABLE identity_api_key_events (tenant_id TEXT NOT NULL, api_key_id TEXT NOT NULL, user_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, state TEXT NOT NULL, current_secret_digest TEXT NOT NULL, previous_secret_digest TEXT, rotation_started_at INT64, previous_secret_expires_at INT64);",
    "CREATE UNIQUE INDEX identity_api_keys_tenant_key_uq ON identity_api_keys (tenant_id, api_key_id);",
    "CREATE UNIQUE INDEX identity_api_keys_tenant_prefix_uq ON identity_api_keys (tenant_id, prefix);",
    "CREATE UNIQUE INDEX identity_api_key_scopes_tenant_key_scope_uq ON identity_api_key_scopes (tenant_id, api_key_id, scope);",
    "CREATE UNIQUE INDEX identity_api_key_retired_secrets_tenant_key_ordinal_uq ON identity_api_key_retired_secrets (tenant_id, api_key_id, ordinal);",
    "CREATE UNIQUE INDEX identity_api_key_retired_secrets_tenant_key_digest_uq ON identity_api_key_retired_secrets (tenant_id, api_key_id, secret_digest);",
    "CREATE UNIQUE INDEX identity_api_key_events_tenant_key_version_uq ON identity_api_key_events (tenant_id, api_key_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered API-key statements.
pub const IDENTITY_API_KEYS_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x5a, 0x5e, 0x0e, 0x24, 0x58, 0x31, 0x64, 0x1a, 0x32, 0x54, 0x3a, 0x34, 0x31, 0x7b, 0xba, 0xa1,
    0x84, 0x9b, 0x3a, 0xb0, 0xe3, 0x31, 0x1f, 0x8b, 0x48, 0x2d, 0xf3, 0xd3, 0x74, 0x75, 0xc2, 0xa1,
];

/// Singular aliases matching the aggregate name used by repository wiring.
pub const IDENTITY_API_KEY_MIGRATION_ID: &str = IDENTITY_API_KEYS_MIGRATION_ID;

/// Singular alias for the durable API-key migration domain.
pub const IDENTITY_API_KEY_MIGRATION_DOMAIN: &str = IDENTITY_API_KEYS_MIGRATION_DOMAIN;

/// Singular alias for the source schema version.
pub const IDENTITY_API_KEY_MIGRATION_FROM_VERSION: u64 = IDENTITY_API_KEYS_MIGRATION_FROM_VERSION;

/// Singular alias for the target schema version.
pub const IDENTITY_API_KEY_MIGRATION_TO_VERSION: u64 = IDENTITY_API_KEYS_MIGRATION_TO_VERSION;

/// Singular alias for the backup prerequisite flag.
pub const IDENTITY_API_KEY_MIGRATION_REQUIRES_BACKUP: bool =
    IDENTITY_API_KEYS_MIGRATION_REQUIRES_BACKUP;

/// Singular alias for the immutable statement sequence.
pub const IDENTITY_API_KEY_MIGRATION_STATEMENTS: &[&str] = IDENTITY_API_KEYS_MIGRATION_STATEMENTS;

/// Singular alias for the canonical checksum bytes.
pub const IDENTITY_API_KEY_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] =
    IDENTITY_API_KEYS_MIGRATION_CANONICAL_V1_SHA256;

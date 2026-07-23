//! Immutable migration metadata for durable password authentication state.

/// Stable identifier of the durable password migration.
pub const IDENTITY_PASSWORD_MIGRATION_ID: &str = "identity.0005.password";

/// Stable domain recorded for the durable password migration.
pub const IDENTITY_PASSWORD_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the password migration.
pub const IDENTITY_PASSWORD_MIGRATION_FROM_VERSION: u64 = 8;

/// Global schema version produced by the password migration.
pub const IDENTITY_PASSWORD_MIGRATION_TO_VERSION: u64 = 9;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_PASSWORD_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered fixed statements for password credentials, resets, and events.
///
/// Versions and policy versions use exactly 20 decimal digits, digests use 64
/// lowercase hexadecimal characters, and UTC timestamps use signed Unix
/// seconds. Repository decoding must enforce those bounds. PHC records retain
/// only one-way verifier material; no column can hold a plaintext password or
/// raw reset token.
pub const IDENTITY_PASSWORD_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_password_credentials (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, version TEXT NOT NULL, hash_policy_version TEXT NOT NULL, phc_record TEXT NOT NULL);",
    "CREATE TABLE identity_password_resets (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, reset_id TEXT NOT NULL, token_digest_hex TEXT NOT NULL, issued_at INT64 NOT NULL, expires_at INT64 NOT NULL, version TEXT NOT NULL, purpose TEXT NOT NULL, state TEXT NOT NULL, password_hash_digest_hex TEXT);",
    "CREATE TABLE identity_password_reset_events (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, reset_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, purpose TEXT NOT NULL, password_hash_digest_hex TEXT);",
    "CREATE UNIQUE INDEX identity_password_credentials_tenant_user_uq ON identity_password_credentials (tenant_id, user_id);",
    "CREATE UNIQUE INDEX identity_password_resets_tenant_reset_uq ON identity_password_resets (tenant_id, reset_id);",
    "CREATE UNIQUE INDEX identity_password_resets_tenant_token_digest_uq ON identity_password_resets (tenant_id, token_digest_hex);",
    "CREATE UNIQUE INDEX identity_password_reset_events_tenant_reset_version_uq ON identity_password_reset_events (tenant_id, reset_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered password statements.
pub const IDENTITY_PASSWORD_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x0f, 0x57, 0xc1, 0x3c, 0xb6, 0x79, 0xc5, 0x01, 0x43, 0x38, 0x79, 0xf8, 0xf9, 0x1a, 0xf3, 0x93,
    0x09, 0x52, 0x5b, 0x76, 0x41, 0xdc, 0x73, 0xe0, 0x6d, 0xd1, 0x6c, 0x1a, 0x9e, 0xa0, 0x90, 0x4d,
];

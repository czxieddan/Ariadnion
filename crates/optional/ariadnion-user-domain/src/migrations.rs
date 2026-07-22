//! Immutable migration metadata for durable user identity state.

/// Stable identifier of the initial durable user migration.
pub const IDENTITY_USERS_MIGRATION_ID: &str = "identity.0001.users";

/// Stable domain recorded for the durable user migration.
pub const IDENTITY_USERS_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the durable user migration.
pub const IDENTITY_USERS_MIGRATION_FROM_VERSION: u64 = 4;

/// Global schema version produced by the durable user migration.
pub const IDENTITY_USERS_MIGRATION_TO_VERSION: u64 = 5;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_USERS_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered single-statement definitions for durable users and lifecycle events.
pub const IDENTITY_USERS_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_users (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, version TEXT NOT NULL, state TEXT NOT NULL, deletion_requested_at INT64, deletion_not_before INT64, recovery_state TEXT);",
    "CREATE TABLE identity_user_events (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, request_id TEXT NOT NULL, deletion_not_before INT64, recovery_state TEXT);",
    "CREATE UNIQUE INDEX identity_users_tenant_user_uq ON identity_users (tenant_id, user_id);",
    "CREATE UNIQUE INDEX identity_user_events_tenant_user_version_uq ON identity_user_events (tenant_id, user_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered durable user statements.
pub const IDENTITY_USERS_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x6d, 0x4e, 0x52, 0xf0, 0x58, 0xcb, 0x69, 0x5a, 0xf4, 0xae, 0x74, 0x2a, 0x9f, 0xbb, 0xb7, 0x82,
    0xa9, 0x75, 0x0c, 0xb8, 0x1f, 0x9f, 0xd6, 0x1f, 0x5c, 0x92, 0x85, 0x45, 0x75, 0x7a, 0xdc, 0x75,
];

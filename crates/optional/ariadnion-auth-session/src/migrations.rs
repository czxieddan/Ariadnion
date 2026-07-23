//! Immutable migration metadata for durable browser session families.

/// Stable identifier of the durable browser-session migration.
pub const IDENTITY_SESSIONS_MIGRATION_ID: &str = "identity.0006.sessions";

/// Stable domain recorded for the durable browser-session migration.
pub const IDENTITY_SESSIONS_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the session migration.
pub const IDENTITY_SESSIONS_MIGRATION_FROM_VERSION: u64 = 9;

/// Global schema version produced by the session migration.
pub const IDENTITY_SESSIONS_MIGRATION_TO_VERSION: u64 = 10;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_SESSIONS_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered fixed statements for session families, leaves, and events.
///
/// Versions use exactly 20 decimal digits, token digests use 64 lowercase
/// hexadecimal characters, and timestamps use signed Unix seconds. Repository
/// decoding must enforce those bounds. No column can hold a plaintext token,
/// cookie, or presentation proof.
pub const IDENTITY_SESSIONS_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_session_families (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, family_id TEXT NOT NULL, current_session_id TEXT NOT NULL, issued_at INT64 NOT NULL, absolute_expires_at INT64 NOT NULL, version TEXT NOT NULL, state TEXT NOT NULL);",
    "CREATE TABLE identity_session_leaves (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, family_id TEXT NOT NULL, session_id TEXT NOT NULL, ordinal INT64 NOT NULL, predecessor_session_id TEXT, token_digest_hex TEXT NOT NULL, issued_at INT64 NOT NULL, last_seen_at INT64 NOT NULL, idle_expires_at INT64 NOT NULL, version TEXT NOT NULL, state TEXT NOT NULL);",
    "CREATE TABLE identity_session_events (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, family_id TEXT NOT NULL, session_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL);",
    "CREATE UNIQUE INDEX identity_session_families_tenant_family_uq ON identity_session_families (tenant_id, family_id);",
    "CREATE UNIQUE INDEX identity_session_leaves_tenant_family_session_uq ON identity_session_leaves (tenant_id, family_id, session_id);",
    "CREATE UNIQUE INDEX identity_session_leaves_tenant_family_ordinal_uq ON identity_session_leaves (tenant_id, family_id, ordinal);",
    "CREATE UNIQUE INDEX identity_session_leaves_tenant_family_digest_uq ON identity_session_leaves (tenant_id, family_id, token_digest_hex);",
    "CREATE UNIQUE INDEX identity_session_events_tenant_family_version_uq ON identity_session_events (tenant_id, family_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered session statements.
pub const IDENTITY_SESSIONS_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x09, 0x6c, 0x3c, 0x1c, 0xd2, 0x37, 0xfc, 0xf7, 0xb8, 0xc2, 0xec, 0xe4, 0x06, 0x3c, 0x8d, 0x5d,
    0x98, 0xa9, 0x45, 0xdc, 0xe1, 0xb9, 0xee, 0xea, 0x28, 0xd5, 0xcb, 0x56, 0x31, 0x0b, 0xa6, 0x9d,
];

/// Singular alias matching the aggregate name used by repository wiring.
pub const IDENTITY_SESSION_MIGRATION_ID: &str = IDENTITY_SESSIONS_MIGRATION_ID;

/// Singular alias for the durable session migration domain.
pub const IDENTITY_SESSION_MIGRATION_DOMAIN: &str = IDENTITY_SESSIONS_MIGRATION_DOMAIN;

/// Singular alias for the source schema version.
pub const IDENTITY_SESSION_MIGRATION_FROM_VERSION: u64 = IDENTITY_SESSIONS_MIGRATION_FROM_VERSION;

/// Singular alias for the target schema version.
pub const IDENTITY_SESSION_MIGRATION_TO_VERSION: u64 = IDENTITY_SESSIONS_MIGRATION_TO_VERSION;

/// Singular alias for the backup prerequisite flag.
pub const IDENTITY_SESSION_MIGRATION_REQUIRES_BACKUP: bool =
    IDENTITY_SESSIONS_MIGRATION_REQUIRES_BACKUP;

/// Singular alias for the immutable statement sequence.
pub const IDENTITY_SESSION_MIGRATION_STATEMENTS: &[&str] = IDENTITY_SESSIONS_MIGRATION_STATEMENTS;

/// Singular alias for the canonical checksum bytes.
pub const IDENTITY_SESSION_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] =
    IDENTITY_SESSIONS_MIGRATION_CANONICAL_V1_SHA256;

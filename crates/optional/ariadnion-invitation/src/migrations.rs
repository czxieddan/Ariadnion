//! Immutable migration metadata for durable invitation state.

/// Stable identifier of the durable invitation migration.
pub const IDENTITY_INVITATION_MIGRATION_ID: &str = "identity.0004.invitations";

/// Stable domain recorded for the durable invitation migration.
pub const IDENTITY_INVITATION_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the invitation migration.
pub const IDENTITY_INVITATION_MIGRATION_FROM_VERSION: u64 = 7;

/// Global schema version produced by the invitation migration.
pub const IDENTITY_INVITATION_MIGRATION_TO_VERSION: u64 = 8;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_INVITATION_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered fixed statements for durable invitations and lifecycle events.
///
/// Bounded identities use ASCII `TEXT`, versions use exactly 20 decimal
/// digits, digests use exactly 64 lowercase hexadecimal characters, and UTC
/// timestamps use signed Unix seconds in `INT64`. Typed repository decoding
/// must enforce those bounds before calling the snapshot constructor.
pub const IDENTITY_INVITATION_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_invitations (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, invitation_id TEXT NOT NULL, issuer_id TEXT NOT NULL, subject_digest_hex TEXT NOT NULL, token_digest_hex TEXT NOT NULL, issued_at INT64 NOT NULL, expires_at INT64 NOT NULL, version TEXT NOT NULL, state TEXT NOT NULL, consumed_by TEXT);",
    "CREATE TABLE identity_invitation_events (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, invitation_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, request_id TEXT NOT NULL, user_id TEXT);",
    "CREATE UNIQUE INDEX identity_invitations_tenant_organization_invitation_uq ON identity_invitations (tenant_id, organization_id, invitation_id);",
    "CREATE UNIQUE INDEX identity_invitations_tenant_token_digest_uq ON identity_invitations (tenant_id, token_digest_hex);",
    "CREATE UNIQUE INDEX identity_invitation_events_tenant_organization_invitation_version_uq ON identity_invitation_events (tenant_id, organization_id, invitation_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered invitation statements.
pub const IDENTITY_INVITATION_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0xb5, 0xf9, 0xc7, 0xd1, 0x82, 0xbc, 0xf5, 0xf1, 0x88, 0x69, 0x23, 0xc0, 0x03, 0x31, 0x94, 0x12,
    0x90, 0x0a, 0x98, 0x46, 0xa6, 0x37, 0x67, 0xdc, 0x5d, 0x62, 0x3a, 0xc5, 0x52, 0xa1, 0xce, 0xa6,
];

//! Immutable migration metadata for durable organization governance state.

/// Stable identifier of the durable organization migration.
pub const IDENTITY_ORGANIZATION_MIGRATION_ID: &str = "identity.0003.organizations";

/// Stable domain recorded for the durable organization migration.
pub const IDENTITY_ORGANIZATION_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the organization migration.
pub const IDENTITY_ORGANIZATION_MIGRATION_FROM_VERSION: u64 = 6;

/// Global schema version produced by the organization migration.
pub const IDENTITY_ORGANIZATION_MIGRATION_TO_VERSION: u64 = 7;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_ORGANIZATION_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered single-statement definitions for organization governance state.
pub const IDENTITY_ORGANIZATION_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_organizations (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, version TEXT NOT NULL, state TEXT NOT NULL);",
    "CREATE TABLE identity_organization_memberships (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, membership_id TEXT NOT NULL, user_id TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, origin TEXT NOT NULL, expires_at INT64);",
    "CREATE TABLE identity_organization_teams (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, team_id TEXT NOT NULL);",
    "CREATE TABLE identity_organization_team_assignments (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, membership_id TEXT NOT NULL, team_id TEXT NOT NULL);",
    "CREATE TABLE identity_organization_events (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, request_id TEXT NOT NULL, organization_state TEXT, membership_id TEXT, membership_kind TEXT, removed_team_assignments INT64, team_id TEXT, ownership_transfer_id TEXT, previous_owner_id TEXT, new_owner_id TEXT, approver_id TEXT);",
    "CREATE UNIQUE INDEX identity_organizations_tenant_organization_uq ON identity_organizations (tenant_id, organization_id);",
    "CREATE UNIQUE INDEX identity_organization_memberships_tenant_organization_membership_uq ON identity_organization_memberships (tenant_id, organization_id, membership_id);",
    "CREATE UNIQUE INDEX identity_organization_memberships_tenant_organization_user_uq ON identity_organization_memberships (tenant_id, organization_id, user_id);",
    "CREATE UNIQUE INDEX identity_organization_teams_tenant_organization_team_uq ON identity_organization_teams (tenant_id, organization_id, team_id);",
    "CREATE UNIQUE INDEX identity_organization_assignments_tenant_organization_membership_team_uq ON identity_organization_team_assignments (tenant_id, organization_id, membership_id, team_id);",
    "CREATE UNIQUE INDEX identity_organization_events_tenant_organization_version_uq ON identity_organization_events (tenant_id, organization_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered organization statements.
pub const IDENTITY_ORGANIZATION_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x20, 0x96, 0xe7, 0xf1, 0xc2, 0x21, 0x00, 0x05, 0xf0, 0x6b, 0x09, 0xae, 0x0a, 0xb6, 0xf0, 0xd8,
    0x20, 0x47, 0x9e, 0x5b, 0xe2, 0x78, 0x5f, 0xf9, 0x74, 0x02, 0xe3, 0x92, 0x7b, 0xf4, 0xba, 0x83,
];

/// Plural alias matching the aggregate table naming convention.
pub const IDENTITY_ORGANIZATIONS_MIGRATION_ID: &str = IDENTITY_ORGANIZATION_MIGRATION_ID;

/// Plural alias matching the aggregate table naming convention.
pub const IDENTITY_ORGANIZATIONS_MIGRATION_DOMAIN: &str = IDENTITY_ORGANIZATION_MIGRATION_DOMAIN;

/// Plural alias matching the aggregate table naming convention.
pub const IDENTITY_ORGANIZATIONS_MIGRATION_FROM_VERSION: u64 =
    IDENTITY_ORGANIZATION_MIGRATION_FROM_VERSION;

/// Plural alias matching the aggregate table naming convention.
pub const IDENTITY_ORGANIZATIONS_MIGRATION_TO_VERSION: u64 =
    IDENTITY_ORGANIZATION_MIGRATION_TO_VERSION;

/// Plural alias matching the aggregate table naming convention.
pub const IDENTITY_ORGANIZATIONS_MIGRATION_REQUIRES_BACKUP: bool =
    IDENTITY_ORGANIZATION_MIGRATION_REQUIRES_BACKUP;

/// Plural alias matching the aggregate table naming convention.
pub const IDENTITY_ORGANIZATIONS_MIGRATION_STATEMENTS: &[&str] =
    IDENTITY_ORGANIZATION_MIGRATION_STATEMENTS;

/// Plural alias matching the aggregate table naming convention.
pub const IDENTITY_ORGANIZATIONS_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] =
    IDENTITY_ORGANIZATION_MIGRATION_CANONICAL_V1_SHA256;

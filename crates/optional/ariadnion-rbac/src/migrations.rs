//! Immutable migration metadata for durable scoped authorization policies.

/// Stable identifier of the durable RBAC migration.
pub const IDENTITY_RBAC_MIGRATION_ID: &str = "identity.0008.rbac";

/// Stable domain recorded for the durable RBAC migration.
pub const IDENTITY_RBAC_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the RBAC migration.
pub const IDENTITY_RBAC_MIGRATION_FROM_VERSION: u64 = 11;

/// Global schema version produced by the RBAC migration.
pub const IDENTITY_RBAC_MIGRATION_TO_VERSION: u64 = 12;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_RBAC_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered fixed statements for authorization policies, roles, and assignments.
///
/// Policy versions use exactly 20 decimal digits in `TEXT`, collection order
/// uses contiguous non-negative `INT64` ordinals, and UTC timestamps use signed
/// Unix seconds in `INT64`. Repository decoding must enforce those constraints
/// and validate nullable scope columns through the typed snapshot boundary.
/// The schema contains no authorization decision or credential material.
pub const IDENTITY_RBAC_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_rbac_policies (tenant_id TEXT NOT NULL, version TEXT NOT NULL);",
    "CREATE TABLE identity_rbac_roles (tenant_id TEXT NOT NULL, role_ordinal INT64 NOT NULL, role_id TEXT NOT NULL);",
    "CREATE TABLE identity_rbac_role_rules (tenant_id TEXT NOT NULL, role_id TEXT NOT NULL, rule_ordinal INT64 NOT NULL, permission_id TEXT NOT NULL, effect TEXT NOT NULL);",
    "CREATE TABLE identity_rbac_assignments (tenant_id TEXT NOT NULL, assignment_ordinal INT64 NOT NULL, assignment_id TEXT NOT NULL, principal_id TEXT NOT NULL, membership_id TEXT NOT NULL, role_id TEXT NOT NULL, scope_kind TEXT NOT NULL, scope_organization_id TEXT, scope_parent_resource_id TEXT, scope_resource_kind TEXT, scope_resource_id TEXT, expires_at INT64);",
    "CREATE TABLE identity_rbac_policy_events (tenant_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, request_id TEXT NOT NULL);",
    "CREATE UNIQUE INDEX identity_rbac_policies_tenant_uq ON identity_rbac_policies (tenant_id);",
    "CREATE UNIQUE INDEX identity_rbac_roles_tenant_role_uq ON identity_rbac_roles (tenant_id, role_id);",
    "CREATE UNIQUE INDEX identity_rbac_roles_tenant_ordinal_uq ON identity_rbac_roles (tenant_id, role_ordinal);",
    "CREATE UNIQUE INDEX identity_rbac_role_rules_tenant_role_permission_uq ON identity_rbac_role_rules (tenant_id, role_id, permission_id);",
    "CREATE UNIQUE INDEX identity_rbac_role_rules_tenant_role_ordinal_uq ON identity_rbac_role_rules (tenant_id, role_id, rule_ordinal);",
    "CREATE UNIQUE INDEX identity_rbac_assignments_tenant_assignment_uq ON identity_rbac_assignments (tenant_id, assignment_id);",
    "CREATE UNIQUE INDEX identity_rbac_assignments_tenant_ordinal_uq ON identity_rbac_assignments (tenant_id, assignment_ordinal);",
    "CREATE UNIQUE INDEX identity_rbac_policy_events_tenant_version_uq ON identity_rbac_policy_events (tenant_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered RBAC statements.
pub const IDENTITY_RBAC_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x8d, 0x10, 0x1e, 0x2a, 0xb6, 0x1a, 0x3f, 0x65, 0xb4, 0x59, 0xf3, 0xab, 0xe7, 0x66, 0x5e, 0x51,
    0x12, 0x9a, 0xd7, 0xda, 0x7b, 0xfa, 0xc9, 0xf9, 0x29, 0x63, 0x51, 0xf4, 0xf6, 0x82, 0x99, 0x57,
];

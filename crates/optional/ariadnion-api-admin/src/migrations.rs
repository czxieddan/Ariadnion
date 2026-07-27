//! Immutable migration metadata for durable administration command execution.

/// Stable identifier of the administration command-ledger migration.
pub const IDENTITY_ADMIN_COMMAND_MIGRATION_ID: &str = "identity.0012.admin-command-ledger";

/// Stable domain recorded for the administration command-ledger migration.
pub const IDENTITY_ADMIN_COMMAND_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the command-ledger migration.
pub const IDENTITY_ADMIN_COMMAND_MIGRATION_FROM_VERSION: u64 = 15;

/// Global schema version produced by the command-ledger migration.
pub const IDENTITY_ADMIN_COMMAND_MIGRATION_TO_VERSION: u64 = 16;

/// Whether the runner requires another backup before this additive migration.
pub const IDENTITY_ADMIN_COMMAND_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Fixed table, index, tenant-policy, and least-privilege grant statements.
///
/// Policy versions use the same exactly 20-digit `TEXT` encoding as the
/// authoritative RBAC store. Trusted evaluation and application instants use
/// signed Unix seconds in `INT64`. Stable intent columns and the canonical
/// fingerprint remain separate from first-attempt timing and request evidence.
pub const IDENTITY_ADMIN_COMMAND_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_admin_commands (tenant_id TEXT NOT NULL, command_id TEXT NOT NULL, decision_id TEXT NOT NULL, actor_id TEXT NOT NULL, policy_version TEXT NOT NULL, action TEXT NOT NULL, target_kind TEXT NOT NULL, target_parent_id TEXT, target_id TEXT NOT NULL, reason_code TEXT NOT NULL, fingerprint_hex TEXT NOT NULL, evaluated_at INT64 NOT NULL, request_id TEXT NOT NULL, applied_at INT64, state TEXT NOT NULL);",
    "CREATE UNIQUE INDEX identity_admin_commands_tenant_command_uq ON identity_admin_commands (tenant_id, command_id);",
    "CREATE UNIQUE INDEX identity_admin_commands_tenant_decision_uq ON identity_admin_commands (tenant_id, decision_id);",
    "CREATE POLICY tenant_identity_admin_commands ON identity_admin_commands USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_admin_commands TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_admin_commands TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_admin_commands TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the command-ledger statement sequence.
pub const IDENTITY_ADMIN_COMMAND_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x5f, 0x21, 0xe8, 0x20, 0xbd, 0xef, 0xb8, 0x23, 0x94, 0x7c, 0xee, 0xcb, 0xd7, 0x1d, 0x48, 0xfa,
    0x1e, 0x75, 0x46, 0x21, 0x02, 0xd9, 0x68, 0x9f, 0x57, 0xd7, 0xe9, 0x49, 0xa4, 0xcc, 0x1c, 0x0f,
];

// crates/optional/ariadnion-rbac/src/migrations.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
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

/// Stable identifier of the additive tenant-enforcement migration.
pub const IDENTITY_TENANT_ENFORCEMENT_MIGRATION_ID: &str = "identity.0011.tenant-enforcement";

/// Stable domain recorded for tenant enforcement.
pub const IDENTITY_TENANT_ENFORCEMENT_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before tenant enforcement.
pub const IDENTITY_TENANT_ENFORCEMENT_MIGRATION_FROM_VERSION: u64 = 14;

/// Global schema version produced by tenant enforcement.
pub const IDENTITY_TENANT_ENFORCEMENT_MIGRATION_TO_VERSION: u64 = 15;

/// Whether the runner requires another backup before this additive migration.
pub const IDENTITY_TENANT_ENFORCEMENT_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Database role used only inside a trusted tenant-bound session scope.
pub const IDENTITY_RUNTIME_ROLE: &str = "ariadnion_identity_runtime";

/// Fixed role, policy, index, and least-privilege grant statements.
///
/// Every policy fails closed when `current_tenant()` is SQL `NULL`. Immutable
/// event and evidence tables receive no update or delete privilege. Snapshot
/// tables receive only the mutation privileges used by their repository, and
/// replaceable companion sets receive delete only where atomic replacement is
/// part of the domain persistence contract.
pub const IDENTITY_TENANT_ENFORCEMENT_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE ROLE ariadnion_identity_runtime;",
    "CREATE UNIQUE INDEX identity_session_leaves_tenant_digest_uq ON identity_session_leaves (tenant_id, token_digest_hex);",
    "CREATE POLICY tenant_identity_users ON identity_users USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_users TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_users TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_users TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_user_events ON identity_user_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_user_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_user_events TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_audit_events ON identity_audit_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_audit_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_audit_events TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_audit_heads ON identity_audit_heads USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_audit_heads TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_audit_heads TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_audit_heads TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_organizations ON identity_organizations USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_organizations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_organizations TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_organizations TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_organization_memberships ON identity_organization_memberships USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_organization_memberships TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_organization_memberships TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_organization_memberships TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_organization_teams ON identity_organization_teams USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_organization_teams TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_organization_teams TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_organization_teams TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_organization_team_assignments ON identity_organization_team_assignments USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_organization_team_assignments TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_organization_team_assignments TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_organization_team_assignments TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_organization_events ON identity_organization_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_organization_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_organization_events TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_invitations ON identity_invitations USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_invitations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_invitations TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_invitations TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_invitation_events ON identity_invitation_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_invitation_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_invitation_events TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_password_credentials ON identity_password_credentials USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_password_credentials TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_password_credentials TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_password_credentials TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_password_resets ON identity_password_resets USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_password_resets TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_password_resets TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_password_resets TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_password_reset_events ON identity_password_reset_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_password_reset_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_password_reset_events TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_password_reset_commit_evidence ON identity_password_reset_commit_evidence USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_password_reset_commit_evidence TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_password_reset_commit_evidence TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_session_families ON identity_session_families USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_session_families TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_session_families TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_session_families TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_session_leaves ON identity_session_leaves USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_session_leaves TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_session_leaves TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_session_leaves TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_session_events ON identity_session_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_session_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_session_events TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_api_keys ON identity_api_keys USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_api_keys TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_api_keys TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_api_keys TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_api_key_scopes ON identity_api_key_scopes USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_api_key_scopes TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_api_key_scopes TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_api_key_scopes TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_api_key_retired_secrets ON identity_api_key_retired_secrets USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_api_key_retired_secrets TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_api_key_retired_secrets TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_api_key_retired_secrets TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_api_key_events ON identity_api_key_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_api_key_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_api_key_events TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_rbac_policies ON identity_rbac_policies USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_rbac_policies TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_rbac_policies TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_rbac_policies TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_rbac_roles ON identity_rbac_roles USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_rbac_roles TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_rbac_roles TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_rbac_roles TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_rbac_role_rules ON identity_rbac_role_rules USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_rbac_role_rules TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_rbac_role_rules TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_rbac_role_rules TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_rbac_assignments ON identity_rbac_assignments USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_rbac_assignments TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_rbac_assignments TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE identity_rbac_assignments TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_rbac_policy_events ON identity_rbac_policy_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_rbac_policy_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_rbac_policy_events TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_platform_outbox ON platform_outbox USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE platform_outbox TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE platform_outbox TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE platform_outbox TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the tenant-enforcement statement sequence.
pub const IDENTITY_TENANT_ENFORCEMENT_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0xb2, 0xf8, 0x6a, 0xbc, 0x6d, 0x50, 0x48, 0x13, 0x0d, 0xe5, 0x78, 0xd3, 0xe4, 0x0d, 0x36, 0xfc,
    0xf2, 0x18, 0xf2, 0x12, 0x1c, 0xa4, 0x2d, 0xb1, 0xf9, 0x34, 0x58, 0x52, 0x77, 0x48, 0xfe, 0xc1,
];

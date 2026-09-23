// crates/optional/ariadnion-account-import/src/migrations.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Immutable migration metadata for the durable account registry.

/// Stable identifier of the initial durable account-registry migration.
pub const ACCOUNT_REGISTRY_MIGRATION_ID: &str = "account.0001.registry";

/// Stable domain recorded for the durable account-registry migration.
pub const ACCOUNT_REGISTRY_MIGRATION_DOMAIN: &str = "account";

/// Global schema version required before the account-registry migration.
pub const ACCOUNT_REGISTRY_MIGRATION_FROM_VERSION: u64 = 20;

/// Global schema version produced by the account-registry migration.
pub const ACCOUNT_REGISTRY_MIGRATION_TO_VERSION: u64 = 21;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const ACCOUNT_REGISTRY_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered single-statement definitions for account publication and lifecycle state.
pub const ACCOUNT_REGISTRY_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE account_registry_generations (tenant_id TEXT NOT NULL, generation TEXT NOT NULL, published_at INT64 NOT NULL);",
    "CREATE TABLE account_registry_accounts (tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, provider_id TEXT NOT NULL, provider_label TEXT NOT NULL, account_label TEXT NOT NULL, external_account_id TEXT, config_version TEXT NOT NULL, secret_provider TEXT NOT NULL, secret_path TEXT NOT NULL ENCRYPTED, secret_version TEXT NOT NULL, secret_purpose TEXT NOT NULL, credential_digest_hex TEXT NOT NULL, default_model TEXT, max_concurrency INT64 NOT NULL, account_version TEXT NOT NULL, account_status TEXT NOT NULL, import_generation TEXT NOT NULL);",
    "CREATE TABLE account_import_mutations (tenant_id TEXT NOT NULL, mutation_id TEXT NOT NULL, request_fingerprint_hex TEXT NOT NULL, expected_generation TEXT NOT NULL, committed_generation TEXT NOT NULL, published_count INT64 NOT NULL, committed_at INT64 NOT NULL);",
    "CREATE TABLE account_lifecycle_events (tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, account_version TEXT NOT NULL, from_status TEXT, to_status TEXT NOT NULL, source_kind TEXT NOT NULL, source_id TEXT NOT NULL, committed_at INT64 NOT NULL);",
    "CREATE UNIQUE INDEX account_registry_generations_tenant_uq ON account_registry_generations (tenant_id);",
    "CREATE UNIQUE INDEX account_registry_accounts_identity_uq ON account_registry_accounts (tenant_id, account_id);",
    "CREATE UNIQUE INDEX account_import_mutations_identity_uq ON account_import_mutations (tenant_id, mutation_id);",
    "CREATE UNIQUE INDEX account_lifecycle_events_version_uq ON account_lifecycle_events (tenant_id, account_id, account_version);",
    "CREATE POLICY tenant_account_registry_generations ON account_registry_generations USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_registry_accounts ON account_registry_accounts USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_import_mutations ON account_import_mutations USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_lifecycle_events ON account_lifecycle_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE account_registry_generations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_registry_generations TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_registry_generations TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_registry_accounts TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_registry_accounts TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_registry_accounts TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_import_mutations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_import_mutations TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_lifecycle_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_lifecycle_events TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered account-registry statements.
pub const ACCOUNT_REGISTRY_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x08, 0xef, 0x75, 0xdb, 0x22, 0xac, 0x97, 0xe9, 0xfa, 0x79, 0xce, 0x4c, 0x94, 0xda, 0x9d, 0xa2,
    0x82, 0xa0, 0xd3, 0x0b, 0x89, 0x8d, 0x20, 0x20, 0x5c, 0x9f, 0x5f, 0x7b, 0x88, 0x0b, 0x82, 0x3e,
];

/// Stable identifier of the additive durable routing-policy migration.
pub const ACCOUNT_ROUTING_POLICY_MIGRATION_ID: &str = "account.0002.routing-policy";

/// Stable domain recorded for durable account routing policy.
pub const ACCOUNT_ROUTING_POLICY_MIGRATION_DOMAIN: &str = "account";

/// Global schema version required before durable routing policy is installed.
pub const ACCOUNT_ROUTING_POLICY_MIGRATION_FROM_VERSION: u64 = 24;

/// Global schema version produced by durable routing policy persistence.
pub const ACCOUNT_ROUTING_POLICY_MIGRATION_TO_VERSION: u64 = 25;

/// Whether the additive routing-policy migration requires another backup.
pub const ACCOUNT_ROUTING_POLICY_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Fixed schema, tenant-policy, and runtime grant statements.
pub const ACCOUNT_ROUTING_POLICY_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE account_registry_routing_policy (tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, config_version TEXT NOT NULL, priority INT64 NOT NULL, weight INT64 NOT NULL);",
    "CREATE UNIQUE INDEX account_registry_routing_policy_identity_uq ON account_registry_routing_policy (tenant_id, account_id);",
    "CREATE POLICY tenant_account_registry_routing_policy ON account_registry_routing_policy USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE account_registry_routing_policy TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_registry_routing_policy TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_registry_routing_policy TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered routing-policy statements.
pub const ACCOUNT_ROUTING_POLICY_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x9a, 0x1b, 0xef, 0xa7, 0x38, 0xe3, 0x7c, 0x4e, 0xc7, 0xc8, 0x3f, 0xfa, 0x50, 0xdc, 0x90, 0xec,
    0x20, 0x2c, 0x77, 0xc5, 0x80, 0xd0, 0x98, 0xb1, 0x0d, 0xe2, 0xc8, 0x1f, 0xac, 0x8a, 0x22, 0x34,
];

/// Stable identifier of the additive durable effective-window migration.
pub const ACCOUNT_EFFECTIVE_WINDOW_MIGRATION_ID: &str = "account.0003.effective-window";

/// Stable domain recorded for durable account effective windows.
pub const ACCOUNT_EFFECTIVE_WINDOW_MIGRATION_DOMAIN: &str = "account";

/// Global schema version required before effective-window persistence is installed.
pub const ACCOUNT_EFFECTIVE_WINDOW_MIGRATION_FROM_VERSION: u64 = 25;

/// Global schema version produced by durable effective-window persistence.
pub const ACCOUNT_EFFECTIVE_WINDOW_MIGRATION_TO_VERSION: u64 = 26;

/// Whether the additive effective-window migration requires another backup.
pub const ACCOUNT_EFFECTIVE_WINDOW_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Fixed schema, tenant-policy, and runtime grant statements.
pub const ACCOUNT_EFFECTIVE_WINDOW_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE account_registry_effective_windows (tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, config_version TEXT NOT NULL, effective_start_unix_seconds INT64, effective_end_unix_seconds INT64);",
    "CREATE UNIQUE INDEX account_registry_effective_windows_identity_uq ON account_registry_effective_windows (tenant_id, account_id);",
    "CREATE POLICY tenant_account_registry_effective_windows ON account_registry_effective_windows USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE account_registry_effective_windows TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_registry_effective_windows TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_registry_effective_windows TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered effective-window statements.
pub const ACCOUNT_EFFECTIVE_WINDOW_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x53, 0xc1, 0xb2, 0x17, 0x0c, 0x6f, 0x41, 0xf2, 0x26, 0xce, 0xc0, 0xc6, 0xd7, 0x04, 0xfc, 0xbb,
    0x0a, 0x76, 0x0f, 0xf2, 0x42, 0x34, 0xb9, 0x6c, 0x81, 0x33, 0xf2, 0x26, 0x25, 0xb4, 0x38, 0xc3,
];

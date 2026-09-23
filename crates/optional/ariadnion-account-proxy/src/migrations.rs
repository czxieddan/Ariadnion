// crates/optional/ariadnion-account-proxy/src/migrations.rs - Durable proxy snapshot migration metadata for Ariadnion.
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
//! Immutable migration metadata for durable account proxy snapshots.

/// Stable identifier of the durable account-proxy migration.
pub const ACCOUNT_PROXY_MIGRATION_ID: &str = "account-proxy.0001.snapshots";

/// Stable domain recorded for the durable account-proxy migration.
pub const ACCOUNT_PROXY_MIGRATION_DOMAIN: &str = "account-proxy";

/// Global schema version required before durable proxy snapshots are installed.
pub const ACCOUNT_PROXY_MIGRATION_FROM_VERSION: u64 = 26;

/// Global schema version produced by durable proxy snapshot persistence.
pub const ACCOUNT_PROXY_MIGRATION_TO_VERSION: u64 = 27;

/// The migration runs against a retained source and does not require another backup.
pub const ACCOUNT_PROXY_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Fixed schema, tenant policy, and runtime grant statements.
pub const ACCOUNT_PROXY_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE account_proxy_generations (tenant_id TEXT NOT NULL, generation TEXT NOT NULL, profile_count INT64 NOT NULL);",
    "CREATE TABLE account_proxy_profiles (tenant_id TEXT NOT NULL, profile_id TEXT NOT NULL, generation TEXT NOT NULL, scheme TEXT NOT NULL, host TEXT, port INT64, auth_provider TEXT, auth_path TEXT ENCRYPTED, auth_version TEXT, auth_purpose TEXT, region_policy TEXT NOT NULL, connect_timeout_ms INT64 NOT NULL, request_timeout_ms INT64 NOT NULL, max_connections INT64 NOT NULL, max_redirects INT64 NOT NULL);",
    "CREATE UNIQUE INDEX account_proxy_generations_tenant_uq ON account_proxy_generations (tenant_id);",
    "CREATE UNIQUE INDEX account_proxy_profiles_identity_uq ON account_proxy_profiles (tenant_id, profile_id);",
    "CREATE POLICY tenant_account_proxy_generations ON account_proxy_generations USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_proxy_profiles ON account_proxy_profiles USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE account_proxy_generations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_proxy_generations TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_proxy_generations TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_proxy_profiles TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_proxy_profiles TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_proxy_profiles TO ariadnion_identity_runtime;",
    "GRANT DELETE ON TABLE account_proxy_profiles TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered proxy snapshot statements.
pub const ACCOUNT_PROXY_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0xb3, 0x7b, 0xef, 0x18, 0xb6, 0xf2, 0xa7, 0x08, 0xb0, 0x6b, 0xe9, 0x7d, 0x73, 0x7a, 0x80, 0x18,
    0x4f, 0x37, 0x1b, 0x46, 0xa9, 0xe4, 0x9e, 0x0c, 0xec, 0x8d, 0x95, 0xd6, 0xe7, 0x4f, 0xc6, 0x0a,
];

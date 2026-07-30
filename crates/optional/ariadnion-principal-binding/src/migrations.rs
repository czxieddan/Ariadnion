// crates/optional/ariadnion-principal-binding/src/migrations.rs - Rust source for Ariadnion.
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
//! Immutable RNMDB schema migration definition for principal bindings.

/// Stable identifier of the durable principal-binding migration.
pub const IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_ID: &str = "identity.0013.principal-bindings";

/// Stable domain recorded for the durable principal-binding migration.
pub const IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the principal-binding migration.
pub const IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_FROM_VERSION: u64 = 16;

/// Global schema version produced by the principal-binding migration.
pub const IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_TO_VERSION: u64 = 17;

/// Whether the runner requires another backup before this additive migration.
pub const IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Fixed table, tenant-first index, policy, and least-privilege grant statements.
///
/// The snapshot keeps direct subject columns nullable so erasure can destroy
/// them without deleting the principal key or commitment. Event rows never
/// contain those direct identifiers. The unkeyed commitment remains sensitive
/// pseudonymous correlation evidence: known candidate tuples can be tested
/// offline, and retained rows are not anonymous after direct-field erasure. The
/// runtime role receives no delete grant.
pub const IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_principal_bindings (tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, user_id TEXT, organization_id TEXT, membership_id TEXT, subject_commitment_hex TEXT NOT NULL, version TEXT NOT NULL, state TEXT NOT NULL, provisioned_at INT64 NOT NULL, revoked_at INT64, erased_at INT64);",
    "CREATE TABLE identity_principal_binding_events (tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, request_id TEXT NOT NULL, subject_commitment_hex TEXT NOT NULL);",
    "CREATE UNIQUE INDEX identity_principal_bindings_tenant_principal_uq ON identity_principal_bindings (tenant_id, principal_id);",
    "CREATE UNIQUE INDEX identity_principal_binding_events_tenant_principal_version_uq ON identity_principal_binding_events (tenant_id, principal_id, version);",
    "CREATE POLICY tenant_identity_principal_bindings ON identity_principal_bindings USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_principal_bindings TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_principal_bindings TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_principal_bindings TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_principal_binding_events ON identity_principal_binding_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_principal_binding_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_principal_binding_events TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered principal-binding statements.
pub const IDENTITY_PRINCIPAL_BINDINGS_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0xfb, 0x45, 0xcb, 0xba, 0xd0, 0x8c, 0xf7, 0xb4, 0xbe, 0x6f, 0x00, 0xdd, 0xb5, 0xc8, 0x29, 0x7c,
    0xa8, 0xd6, 0xe4, 0x99, 0x90, 0x8e, 0x2c, 0x54, 0xb8, 0x03, 0x34, 0x08, 0xd5, 0x22, 0xfd, 0x83,
];

/// Stable identifier of the forward principal-authenticator migration.
pub const IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_ID: &str =
    "identity.0014.principal-authenticators";

/// Stable domain recorded for the principal-authenticator migration.
pub const IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the principal-authenticator migration.
pub const IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_FROM_VERSION: u64 = 17;

/// Global schema version produced by the principal-authenticator migration.
pub const IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_TO_VERSION: u64 = 18;

/// Whether the runner requires another backup before this additive migration.
pub const IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Fixed tables, tenant-first indexes, policies, and least-privilege grants.
///
/// RNMDB's reviewed SQL revision represents composite keys through unique indexes
/// and does not expose SQL `PRIMARY KEY` or `CHECK` syntax. The two tenant-first
/// unique indexes below are the durable primary and immutable-source boundaries.
/// Adapters must run the same exhaustive kind, state, version, timestamp, derived
/// ID, and source-commitment validation used by typed rehydration before every
/// insert or update. Rows that fail those checks are integrity failures. Revoked
/// snapshots remain as tombstones, events expose only a domain-separated source
/// commitment, and the runtime role has no delete grant.
pub const IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_principal_authenticators (tenant_id TEXT NOT NULL, authenticator_id TEXT NOT NULL, authenticator_kind TEXT NOT NULL, source_id TEXT NOT NULL, principal_id TEXT NOT NULL, principal_binding_version TEXT NOT NULL, version TEXT NOT NULL, state TEXT NOT NULL, linked_at INT64 NOT NULL, revoked_at INT64);",
    "CREATE TABLE identity_principal_authenticator_events (tenant_id TEXT NOT NULL, authenticator_id TEXT NOT NULL, authenticator_kind TEXT NOT NULL, source_commitment_hex TEXT NOT NULL, principal_id TEXT NOT NULL, principal_binding_version TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, request_id TEXT NOT NULL);",
    "CREATE UNIQUE INDEX identity_principal_authenticators_tenant_id_uq ON identity_principal_authenticators (tenant_id, authenticator_id);",
    "CREATE UNIQUE INDEX identity_principal_authenticators_tenant_source_uq ON identity_principal_authenticators (tenant_id, authenticator_kind, source_id);",
    "CREATE INDEX identity_principal_authenticators_tenant_principal_state_idx ON identity_principal_authenticators (tenant_id, principal_id, state);",
    "CREATE UNIQUE INDEX identity_principal_authenticator_events_tenant_id_version_uq ON identity_principal_authenticator_events (tenant_id, authenticator_id, version);",
    "CREATE POLICY tenant_identity_principal_authenticators ON identity_principal_authenticators USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_principal_authenticators TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_principal_authenticators TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE identity_principal_authenticators TO ariadnion_identity_runtime;",
    "CREATE POLICY tenant_identity_principal_authenticator_events ON identity_principal_authenticator_events USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE identity_principal_authenticator_events TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE identity_principal_authenticator_events TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered principal-authenticator statements.
pub const IDENTITY_PRINCIPAL_AUTHENTICATORS_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x8b, 0x48, 0x50, 0x70, 0x2c, 0xb8, 0x39, 0x3e, 0x52, 0x9f, 0x26, 0x72, 0xf2, 0x14, 0xf5, 0xa8,
    0x5d, 0xc5, 0x80, 0xeb, 0xdb, 0xd0, 0xf8, 0xe3, 0xb8, 0xa2, 0x98, 0xf3, 0x07, 0x30, 0xf2, 0x76,
];

// crates/optional/ariadnion-api-files/src/migrations.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Immutable migration metadata for the durable file catalog.

/// Stable identifier of the initial durable file-catalog migration.
pub const FILES_CATALOG_MIGRATION_ID: &str = "files.0001.catalog";

/// Stable domain recorded for the durable file-catalog migration.
pub const FILES_CATALOG_MIGRATION_DOMAIN: &str = "files";

/// Global schema version required before the file-catalog migration.
pub const FILES_CATALOG_MIGRATION_FROM_VERSION: u64 = 19;

/// Global schema version produced by the file-catalog migration.
pub const FILES_CATALOG_MIGRATION_TO_VERSION: u64 = 20;

/// Whether the runner requires another backup before this additive migration.
pub const FILES_CATALOG_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Dedicated least-privilege database role for file-catalog runtime access.
pub const FILES_RUNTIME_ROLE: &str = "ariadnion_files_runtime";

/// Fixed table, index, tenant-policy, role, and least-privilege grant statements.
///
/// Catalog entries remain immutable and reserve references permanently. Committed
/// delete operation outcomes are the append-only tombstone authority. Operation
/// rows retain only keyed idempotency lookups and request commitments; raw
/// idempotency keys, content bytes, and storage locators are excluded.
pub const FILES_CATALOG_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE files_catalog_entries (tenant_id TEXT NOT NULL, owner_principal_id TEXT NOT NULL, reference_hex TEXT NOT NULL, display_name TEXT NOT NULL, media_type TEXT NOT NULL, byte_length INT64 NOT NULL, digest_hex TEXT NOT NULL);",
    "CREATE TABLE files_catalog_operations (tenant_id TEXT NOT NULL, owner_principal_id TEXT NOT NULL, operation_kind TEXT NOT NULL, idempotency_lookup_hex TEXT NOT NULL, request_commitment_hex TEXT NOT NULL, reference_hex TEXT NOT NULL, commitment_key_version INT64 NOT NULL, outcome TEXT NOT NULL);",
    "CREATE UNIQUE INDEX files_catalog_entries_reference_uq ON files_catalog_entries (reference_hex);",
    "CREATE UNIQUE INDEX files_catalog_operations_tenant_principal_kind_idempotency_uq ON files_catalog_operations (tenant_id, owner_principal_id, operation_kind, idempotency_lookup_hex);",
    "CREATE INDEX files_catalog_entries_tenant_principal_reference_idx ON files_catalog_entries (tenant_id, owner_principal_id, reference_hex);",
    "CREATE INDEX files_catalog_operations_tenant_principal_outcome_reference_idx ON files_catalog_operations (tenant_id, owner_principal_id, outcome, reference_hex);",
    "CREATE ROLE ariadnion_files_runtime;",
    "CREATE POLICY tenant_files_catalog_entries ON files_catalog_entries USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE files_catalog_entries TO ariadnion_files_runtime;",
    "GRANT INSERT ON TABLE files_catalog_entries TO ariadnion_files_runtime;",
    "CREATE POLICY tenant_files_catalog_operations ON files_catalog_operations USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE files_catalog_operations TO ariadnion_files_runtime;",
    "GRANT INSERT ON TABLE files_catalog_operations TO ariadnion_files_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered file-catalog statement sequence.
pub const FILES_CATALOG_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0xa5, 0xbc, 0x6a, 0x04, 0x41, 0x99, 0x34, 0x79, 0xb3, 0x0c, 0x5a, 0xba, 0xdc, 0x15, 0xfa, 0x4b,
    0x37, 0x98, 0x7a, 0x3e, 0x2a, 0xe8, 0x7e, 0x34, 0x50, 0xcb, 0x43, 0x4b, 0x27, 0x96, 0xaa, 0x6c,
];

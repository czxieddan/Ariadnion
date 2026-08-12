// crates/optional/ariadnion-audit-domain/src/migrations.rs - Rust source for Ariadnion.
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
//! Immutable migration metadata for durable identity audit chains.

/// Stable identifier of the durable identity audit migration.
pub const IDENTITY_AUDIT_MIGRATION_ID: &str = "identity.0002.audit";

/// Stable domain recorded for the durable identity audit migration.
pub const IDENTITY_AUDIT_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the identity audit migration.
pub const IDENTITY_AUDIT_MIGRATION_FROM_VERSION: u64 = 5;

/// Global schema version produced by the identity audit migration.
pub const IDENTITY_AUDIT_MIGRATION_TO_VERSION: u64 = 6;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_AUDIT_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered single-statement definitions for durable identity audit chains.
pub const IDENTITY_AUDIT_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_audit_events (tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, sequence TEXT NOT NULL, actor_id TEXT NOT NULL, occurred_at INT64 NOT NULL, event_kind TEXT NOT NULL, subject_kind TEXT NOT NULL, subject_digest TEXT NOT NULL, reason_code TEXT NOT NULL, payload_digest TEXT NOT NULL, previous_chain_digest TEXT, chain_digest_version INT64 NOT NULL, chain_digest TEXT NOT NULL);",
    "CREATE TABLE identity_audit_heads (tenant_id TEXT NOT NULL, last_sequence TEXT NOT NULL, chain_digest_version INT64 NOT NULL, chain_digest TEXT NOT NULL);",
    "CREATE UNIQUE INDEX identity_audit_events_tenant_event_uq ON identity_audit_events (tenant_id, event_id);",
    "CREATE UNIQUE INDEX identity_audit_events_tenant_sequence_uq ON identity_audit_events (tenant_id, sequence);",
    "CREATE UNIQUE INDEX identity_audit_heads_tenant_uq ON identity_audit_heads (tenant_id);",
];

/// Canonical-AST-v1 SHA-256 of the ordered identity audit statements.
pub const IDENTITY_AUDIT_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x07, 0x27, 0xf5, 0xa4, 0xf5, 0x5a, 0x7b, 0xdd, 0x13, 0xde, 0x0e, 0x3d, 0x4e, 0x34, 0xbd, 0xc0,
    0x26, 0x22, 0xe5, 0x89, 0xcd, 0xea, 0x77, 0xc7, 0x48, 0x7b, 0xe5, 0xb7, 0xa5, 0x07, 0xe4, 0x6e,
];

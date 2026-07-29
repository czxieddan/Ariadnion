// crates/optional/ariadnion-auth-password/src/migrations.rs - Rust source for Ariadnion.
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
//! Immutable migration metadata for durable password authentication state.

/// Stable identifier of the durable password migration.
pub const IDENTITY_PASSWORD_MIGRATION_ID: &str = "identity.0005.password";

/// Stable domain recorded for the durable password migration.
pub const IDENTITY_PASSWORD_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the password migration.
pub const IDENTITY_PASSWORD_MIGRATION_FROM_VERSION: u64 = 8;

/// Global schema version produced by the password migration.
pub const IDENTITY_PASSWORD_MIGRATION_TO_VERSION: u64 = 9;

/// Whether the migration runner requires a separate backup prerequisite.
///
/// This additive migration runs only against a new target while the source is
/// retained, so the migration itself does not require another backup.
pub const IDENTITY_PASSWORD_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered fixed statements for password credentials, resets, and events.
///
/// Versions and policy versions use exactly 20 decimal digits, digests use 64
/// lowercase hexadecimal characters, and UTC timestamps use signed Unix
/// seconds. Repository decoding must enforce those bounds. PHC records retain
/// only one-way verifier material; no column can hold a plaintext password or
/// raw reset token.
pub const IDENTITY_PASSWORD_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_password_credentials (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, version TEXT NOT NULL, hash_policy_version TEXT NOT NULL, phc_record TEXT NOT NULL);",
    "CREATE TABLE identity_password_resets (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, reset_id TEXT NOT NULL, token_digest_hex TEXT NOT NULL, issued_at INT64 NOT NULL, expires_at INT64 NOT NULL, version TEXT NOT NULL, purpose TEXT NOT NULL, state TEXT NOT NULL, password_hash_digest_hex TEXT);",
    "CREATE TABLE identity_password_reset_events (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, reset_id TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL, occurred_at INT64 NOT NULL, actor_id TEXT NOT NULL, purpose TEXT NOT NULL, password_hash_digest_hex TEXT);",
    "CREATE UNIQUE INDEX identity_password_credentials_tenant_user_uq ON identity_password_credentials (tenant_id, user_id);",
    "CREATE UNIQUE INDEX identity_password_resets_tenant_reset_uq ON identity_password_resets (tenant_id, reset_id);",
    "CREATE UNIQUE INDEX identity_password_resets_tenant_token_digest_uq ON identity_password_resets (tenant_id, token_digest_hex);",
    "CREATE UNIQUE INDEX identity_password_reset_events_tenant_reset_version_uq ON identity_password_reset_events (tenant_id, reset_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered password statements.
pub const IDENTITY_PASSWORD_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x0f, 0x57, 0xc1, 0x3c, 0xb6, 0x79, 0xc5, 0x01, 0x43, 0x38, 0x79, 0xf8, 0xf9, 0x1a, 0xf3, 0x93,
    0x09, 0x52, 0x5b, 0x76, 0x41, 0xdc, 0x73, 0xe0, 0x6d, 0xd1, 0x6c, 0x1a, 0x9e, 0xa0, 0x90, 0x4d,
];

/// Stable identifier of the additive password commit-evidence migration.
pub const IDENTITY_PASSWORD_COMMIT_EVIDENCE_MIGRATION_ID: &str =
    "identity.0010.password-commit-evidence";

/// Stable domain recorded for the password commit-evidence migration.
pub const IDENTITY_PASSWORD_COMMIT_EVIDENCE_MIGRATION_DOMAIN: &str = "identity";

/// Global schema version required before the commit-evidence migration.
pub const IDENTITY_PASSWORD_COMMIT_EVIDENCE_MIGRATION_FROM_VERSION: u64 = 13;

/// Global schema version produced by the commit-evidence migration.
pub const IDENTITY_PASSWORD_COMMIT_EVIDENCE_MIGRATION_TO_VERSION: u64 = 14;

/// Whether the runner requires another backup before this additive migration.
///
/// The migration adds only a companion table and index to a copied target, so
/// the retained source remains the rollback boundary.
pub const IDENTITY_PASSWORD_COMMIT_EVIDENCE_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Ordered fixed statements for atomic password-reset commit evidence.
///
/// Every reset transition records the issuance-bound credential version and
/// request identity. Credential result fields and the password-hash digest are
/// nullable only for issuance, revocation, and expiry. Adapters fail closed on
/// any other missing or unexpected tuple. The table contains no PHC record,
/// plaintext password, or raw reset token.
pub const IDENTITY_PASSWORD_COMMIT_EVIDENCE_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE identity_password_reset_commit_evidence (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, reset_id TEXT NOT NULL, version TEXT NOT NULL, request_id TEXT NOT NULL, issued_credential_version TEXT NOT NULL, resulting_credential_version TEXT, resulting_hash_policy_version TEXT, password_hash_digest_hex TEXT);",
    "CREATE UNIQUE INDEX identity_password_reset_commit_evidence_tenant_reset_version_uq ON identity_password_reset_commit_evidence (tenant_id, reset_id, version);",
];

/// Canonical-AST-v1 SHA-256 of the ordered commit-evidence statements.
pub const IDENTITY_PASSWORD_COMMIT_EVIDENCE_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0xd5, 0x5c, 0xfe, 0x2e, 0xe5, 0x91, 0xc4, 0x8d, 0xa6, 0x33, 0x29, 0xaa, 0x70, 0xc6, 0xed, 0xeb,
    0xb3, 0x53, 0x5a, 0x5e, 0x66, 0xfa, 0xc4, 0xcc, 0x5c, 0x05, 0x7b, 0x81, 0xe5, 0xea, 0x94, 0x22,
];

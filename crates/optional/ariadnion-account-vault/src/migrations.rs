// crates/optional/ariadnion-account-vault/src/migrations.rs - Rust source for Ariadnion.
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
//! Immutable migration metadata for encrypted account-vault persistence.

/// Stable identifier of the initial encrypted account-vault migration.
pub const ACCOUNT_VAULT_MIGRATION_ID: &str = "account-vault.0001.envelopes";

/// Stable domain recorded for the encrypted account-vault migration.
pub const ACCOUNT_VAULT_MIGRATION_DOMAIN: &str = "account-vault";

/// Global schema version required before the account-vault migration.
pub const ACCOUNT_VAULT_MIGRATION_FROM_VERSION: u64 = 22;

/// Global schema version produced by the account-vault migration.
pub const ACCOUNT_VAULT_MIGRATION_TO_VERSION: u64 = 23;

/// Whether the additive migration requires another backup.
///
/// The migration is applied only to a new target while the prior target remains
/// available, so it does not require an additional in-place backup.
pub const ACCOUNT_VAULT_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Fixed schema, tenant-policy, and least-privilege statements.
pub const ACCOUNT_VAULT_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE account_vault_secrets (tenant_id TEXT NOT NULL, reference_digest_hex TEXT NOT NULL, secret_provider TEXT NOT NULL, secret_path TEXT NOT NULL ENCRYPTED, secret_version TEXT NOT NULL, secret_purpose TEXT NOT NULL, key_version INT64 NOT NULL, nonce_hex TEXT NOT NULL ENCRYPTED, ciphertext_hex TEXT NOT NULL ENCRYPTED, envelope_digest_hex TEXT NOT NULL, lifecycle_state TEXT NOT NULL, created_at INT64 NOT NULL, revoked_at INT64, revoke_reason TEXT);",
    "CREATE TABLE account_vault_key_versions (tenant_id TEXT NOT NULL, key_version INT64 NOT NULL, external_key_reference TEXT NOT NULL ENCRYPTED, lifecycle_state TEXT NOT NULL, activated_at INT64 NOT NULL, retired_at INT64);",
    "CREATE TABLE account_vault_mutations (tenant_id TEXT NOT NULL, mutation_id TEXT NOT NULL, request_fingerprint_hex TEXT NOT NULL, mutation_kind TEXT NOT NULL, reference_digest_hex TEXT NOT NULL, secret_provider TEXT NOT NULL, secret_path TEXT NOT NULL ENCRYPTED, secret_version TEXT NOT NULL, disposition TEXT NOT NULL, key_version INT64, revoke_reason TEXT, committed_at INT64 NOT NULL);",
    "CREATE TABLE account_vault_access_events (tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, lease_id_digest_hex TEXT NOT NULL, reference_digest_hex TEXT NOT NULL, module_id TEXT NOT NULL, secret_purpose TEXT NOT NULL, issued_at INT64 NOT NULL, expires_at INT64 NOT NULL, outcome TEXT NOT NULL, occurred_at INT64 NOT NULL);",
    "CREATE TABLE account_vault_rotations (tenant_id TEXT NOT NULL, rotation_id TEXT NOT NULL, previous_reference_digest_hex TEXT NOT NULL, new_reference_digest_hex TEXT NOT NULL, rotation_phase TEXT NOT NULL, activated_at INT64, overlap_ends_at INT64, revoked_at INT64, failure_code TEXT, revision TEXT NOT NULL, updated_at INT64 NOT NULL);",
    "CREATE UNIQUE INDEX account_vault_secrets_reference_uq ON account_vault_secrets (tenant_id, reference_digest_hex);",
    "CREATE UNIQUE INDEX account_vault_key_versions_identity_uq ON account_vault_key_versions (tenant_id, key_version);",
    "CREATE UNIQUE INDEX account_vault_mutations_identity_uq ON account_vault_mutations (tenant_id, mutation_id);",
    "CREATE INDEX account_vault_mutations_reference_ix ON account_vault_mutations (tenant_id, reference_digest_hex, committed_at);",
    "CREATE UNIQUE INDEX account_vault_access_events_identity_uq ON account_vault_access_events (tenant_id, event_id);",
    "CREATE INDEX account_vault_access_events_reference_ix ON account_vault_access_events (tenant_id, reference_digest_hex, occurred_at);",
    "CREATE UNIQUE INDEX account_vault_rotations_identity_uq ON account_vault_rotations (tenant_id, rotation_id);",
    "CREATE POLICY tenant_account_vault_secrets ON account_vault_secrets USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_vault_key_versions ON account_vault_key_versions USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_vault_mutations ON account_vault_mutations USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_vault_access_events ON account_vault_access_events USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_vault_rotations ON account_vault_rotations USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE account_vault_secrets TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_vault_secrets TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_vault_secrets TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_vault_key_versions TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_vault_mutations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_vault_mutations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_vault_access_events TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_vault_rotations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_vault_rotations TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_vault_rotations TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered migration statement sequence.
pub const ACCOUNT_VAULT_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0x38, 0x5b, 0x7d, 0x66, 0x42, 0xae, 0x73, 0x4a, 0x1d, 0xa0, 0x1d, 0x44, 0x04, 0x3d, 0xf6, 0x20,
    0x12, 0x71, 0xae, 0x8d, 0x85, 0xe5, 0x56, 0x43, 0xb6, 0x22, 0x4c, 0x44, 0x16, 0x4f, 0xc0, 0x8b,
];

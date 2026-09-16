// crates/optional/ariadnion-account-batch/src/migrations.rs - Rust source for Ariadnion.
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
//! Immutable migration metadata for durable account-batch execution.

/// Stable identifier of the initial durable account-batch migration.
pub const ACCOUNT_BATCH_MIGRATION_ID: &str = "account-batch.0001.execution";
/// Stable domain recorded for the durable account-batch migration.
pub const ACCOUNT_BATCH_MIGRATION_DOMAIN: &str = "account-batch";
/// Global schema version required before the account-batch migration.
pub const ACCOUNT_BATCH_MIGRATION_FROM_VERSION: u64 = 21;
/// Global schema version produced by the account-batch migration.
pub const ACCOUNT_BATCH_MIGRATION_TO_VERSION: u64 = 22;
/// Whether the additive migration requires another backup.
pub const ACCOUNT_BATCH_MIGRATION_REQUIRES_BACKUP: bool = false;

/// Fixed schema, tenant-policy, and least-privilege statements.
pub const ACCOUNT_BATCH_MIGRATION_STATEMENTS: &[&str] = &[
    "CREATE TABLE account_batch_plans (tenant_id TEXT NOT NULL, operation_id TEXT NOT NULL, batch_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, plan_digest_hex TEXT NOT NULL, intent TEXT NOT NULL, created_at INT64 NOT NULL, deadline INT64 NOT NULL, max_parallel_items INT64 NOT NULL, max_claim_items INT64 NOT NULL, max_item_attempts INT64 NOT NULL, lifecycle TEXT NOT NULL, terminal_state TEXT, revision TEXT NOT NULL, total_items INT64 NOT NULL, completed_items INT64 NOT NULL, failed_items INT64 NOT NULL);",
    "CREATE TABLE account_batch_items (tenant_id TEXT NOT NULL, operation_id TEXT NOT NULL, batch_id TEXT NOT NULL, item_ordinal INT64 NOT NULL, item_id TEXT NOT NULL, account_id TEXT NOT NULL, expected_account_version TEXT NOT NULL, transition_action TEXT NOT NULL, attempt INT64 NOT NULL, item_state TEXT NOT NULL, claim_id TEXT, claim_revision TEXT, lease_expires_at INT64, completion_mutation_id TEXT, outcome_kind TEXT, outcome_failure TEXT, outcome_from TEXT, outcome_to TEXT, outcome_version TEXT, outcome_committed_at INT64);",
    "CREATE TABLE account_batch_mutations (tenant_id TEXT NOT NULL, mutation_id TEXT NOT NULL, mutation_kind TEXT NOT NULL, command_digest_hex TEXT NOT NULL, operation_id TEXT NOT NULL, batch_id TEXT NOT NULL, disposition TEXT NOT NULL, claim_id TEXT, claim_revision TEXT, lease_expires_at INT64, completion_ordinal INT64, observed_at INT64, committed_at INT64 NOT NULL, lifecycle TEXT NOT NULL, terminal_state TEXT, revision TEXT NOT NULL, total_items INT64 NOT NULL, completed_items INT64 NOT NULL, failed_items INT64 NOT NULL);",
    "CREATE TABLE account_batch_claim_assignments (tenant_id TEXT NOT NULL, mutation_id TEXT NOT NULL, operation_id TEXT NOT NULL, batch_id TEXT NOT NULL, item_ordinal INT64 NOT NULL, attempt INT64 NOT NULL);",
    "CREATE UNIQUE INDEX account_batch_plans_identity_uq ON account_batch_plans (tenant_id, operation_id, batch_id);",
    "CREATE UNIQUE INDEX account_batch_plans_idempotency_uq ON account_batch_plans (tenant_id, idempotency_key);",
    "CREATE UNIQUE INDEX account_batch_items_ordinal_uq ON account_batch_items (tenant_id, operation_id, batch_id, item_ordinal);",
    "CREATE UNIQUE INDEX account_batch_items_id_uq ON account_batch_items (tenant_id, operation_id, batch_id, item_id);",
    "CREATE UNIQUE INDEX account_batch_items_account_uq ON account_batch_items (tenant_id, operation_id, batch_id, account_id);",
    "CREATE UNIQUE INDEX account_batch_mutations_identity_uq ON account_batch_mutations (tenant_id, mutation_id);",
    "CREATE UNIQUE INDEX account_batch_claim_assignments_identity_uq ON account_batch_claim_assignments (tenant_id, mutation_id, item_ordinal);",
    "CREATE POLICY tenant_account_batch_plans ON account_batch_plans USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_batch_items ON account_batch_items USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_batch_mutations ON account_batch_mutations USING (tenant_id = current_tenant());",
    "CREATE POLICY tenant_account_batch_claim_assignments ON account_batch_claim_assignments USING (tenant_id = current_tenant());",
    "GRANT SELECT ON TABLE account_batch_plans TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_batch_plans TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_batch_plans TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_batch_items TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_batch_items TO ariadnion_identity_runtime;",
    "GRANT UPDATE ON TABLE account_batch_items TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_batch_mutations TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_batch_mutations TO ariadnion_identity_runtime;",
    "GRANT SELECT ON TABLE account_batch_claim_assignments TO ariadnion_identity_runtime;",
    "GRANT INSERT ON TABLE account_batch_claim_assignments TO ariadnion_identity_runtime;",
];

/// Canonical-AST-v1 SHA-256 of the ordered migration statement sequence.
pub const ACCOUNT_BATCH_MIGRATION_CANONICAL_V1_SHA256: [u8; 32] = [
    0xda, 0xf2, 0xbd, 0x1b, 0x4f, 0xef, 0x92, 0x72, 0x25, 0x01, 0x93, 0xd7, 0xe4, 0xff, 0x12, 0xf4,
    0xd9, 0x4a, 0x96, 0xd2, 0xb6, 0xdf, 0xdc, 0x95, 0x97, 0xf9, 0x7e, 0x8c, 0x18, 0xda, 0x5b, 0x2d,
];

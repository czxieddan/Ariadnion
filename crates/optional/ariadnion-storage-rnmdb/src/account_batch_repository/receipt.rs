// crates/optional/ariadnion-storage-rnmdb/src/account_batch_repository.rs - Rust source for Ariadnion.
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
//! Durable mutation receipt insertion.

use super::codec::*;
use super::*;

pub(super) struct MutationWrite<'a> {
    tenant: &'a TenantId,
    mutation_id: &'a MutationId,
    kind: &'static str,
    digest: &'a str,
    identity: BatchIdentity,
    disposition: &'static str,
    claim_id: Option<&'a str>,
    claim_revision: Option<u64>,
    lease_expires_at: Option<u64>,
    completion_ordinal: Option<u32>,
    observed_at: Option<u64>,
    committed_at: UtcSeconds,
    status: &'a BatchStatus,
}

impl<'a> MutationWrite<'a> {
    pub(super) fn submission(
        command: &'a SubmitBatch,
        digest: &'a str,
        disposition: BatchSubmitDisposition,
        status: &'a BatchStatus,
        committed_at: UtcSeconds,
    ) -> Self {
        Self {
            tenant: command.plan().submission().tenant_id(),
            mutation_id: command.mutation_id(),
            kind: "submission",
            digest,
            identity: command.plan().identity(),
            disposition: submit_disposition_label(disposition),
            claim_id: None,
            claim_revision: None,
            lease_expires_at: None,
            completion_ordinal: None,
            observed_at: None,
            committed_at,
            status,
        }
    }
    pub(super) fn claim(
        command: &'a ClaimBatchItems,
        digest: &'a str,
        status: &'a BatchStatus,
        observed_at: UtcSeconds,
        committed_at: UtcSeconds,
    ) -> Self {
        Self {
            tenant: command.identity().tenant_id(),
            mutation_id: command.mutation_id(),
            kind: "claim",
            digest,
            identity: command.identity().clone(),
            disposition: "committed",
            claim_id: Some(command.claim_id().as_str()),
            claim_revision: Some(status.revision().get()),
            lease_expires_at: Some(command.lease_expires_at().get()),
            completion_ordinal: None,
            observed_at: Some(observed_at.get()),
            committed_at,
            status,
        }
    }
    pub(super) fn completion(
        command: &'a CompleteClaimedItem,
        digest: &'a str,
        status: &'a BatchStatus,
        observed_at: UtcSeconds,
        committed_at: UtcSeconds,
    ) -> Self {
        Self {
            tenant: command.claimed_item().identity().tenant_id(),
            mutation_id: command.mutation_id(),
            kind: "item_completion",
            digest,
            identity: command.claimed_item().identity().clone(),
            disposition: "committed",
            claim_id: Some(command.claimed_item().claim_id().as_str()),
            claim_revision: Some(command.claimed_item().claim_revision().get()),
            lease_expires_at: Some(command.claimed_item().lease_expires_at().get()),
            completion_ordinal: Some(command.claimed_item().ordinal().get()),
            observed_at: Some(observed_at.get()),
            committed_at,
            status,
        }
    }
    pub(super) fn transition(
        command: &'a TransitionBatch,
        digest: &'a str,
        status: &'a BatchStatus,
        observed_at: UtcSeconds,
        committed_at: UtcSeconds,
    ) -> Self {
        Self {
            tenant: command.identity().tenant_id(),
            mutation_id: command.mutation_id(),
            kind: "transition",
            digest,
            identity: command.identity().clone(),
            disposition: transition_label(command.transition()),
            claim_id: None,
            claim_revision: Some(command.expected_revision().get()),
            lease_expires_at: None,
            completion_ordinal: None,
            observed_at: Some(observed_at.get()),
            committed_at,
            status,
        }
    }
}

pub(super) fn insert_mutation(
    session: &mut LocalSession,
    mutation: MutationWrite<'_>,
) -> Result<(), StorageError> {
    let (lifecycle, terminal) = lifecycle_fields(mutation.status.lifecycle());
    let claim_revision = mutation.claim_revision.map(|value| value.to_string());
    let statement = format!(
        "INSERT INTO account_batch_mutations ({MUTATION_PROJECTION}) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});",
        sql::text(mutation.tenant.as_str()),
        sql::text(mutation.mutation_id.as_str()),
        sql::text(mutation.kind),
        sql::text(mutation.digest),
        sql::text(mutation.identity.operation_id().as_str()),
        sql::text(mutation.identity.batch_id().as_str()),
        sql::text(mutation.disposition),
        sql::null_or_text(mutation.claim_id),
        sql::null_or_text(claim_revision.as_deref()),
        nullable_u64(mutation.lease_expires_at),
        nullable_u32(mutation.completion_ordinal),
        nullable_u64(mutation.observed_at),
        mutation.committed_at.get(),
        sql::text(lifecycle),
        sql::null_or_text(terminal),
        sql::text(&mutation.status.revision().get().to_string()),
        mutation.status.total_items(),
        mutation.status.completed_items(),
        mutation.status.failed_items()
    );
    sql::require_rows(sql::execute(session, statement)?, 1)
}

pub(super) fn insert_claim_assignments(
    session: &mut LocalSession,
    command: &ClaimBatchItems,
    claim: &BatchClaim,
) -> Result<(), StorageError> {
    for item in claim.items() {
        let statement = format!(
            "INSERT INTO account_batch_claim_assignments (tenant_id, mutation_id, operation_id, batch_id, item_ordinal, attempt) VALUES ({}, {}, {}, {}, {}, {});",
            sql::text(command.identity().tenant_id().as_str()),
            sql::text(command.mutation_id().as_str()),
            sql::text(command.identity().operation_id().as_str()),
            sql::text(command.identity().batch_id().as_str()),
            item.ordinal().get(),
            item.attempt().get()
        );
        sql::require_rows(sql::execute(session, statement)?, 1)?;
    }
    Ok(())
}

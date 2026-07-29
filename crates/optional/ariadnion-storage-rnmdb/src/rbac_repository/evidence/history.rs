// crates/optional/ariadnion-storage-rnmdb/src/rbac_repository/evidence/history.rs - Rust source for Ariadnion.
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
//! Bounded complete-history verification for authorization policies.

use std::collections::BTreeMap;

use ariadnion_audit_domain::AuditSequence;
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_rbac::{AuthorizationPolicy, PolicyVersion};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;

#[cfg(feature = "test-hooks")]
use super::super::HistoryTestHooks;
use super::super::decode::PersistedPolicyEvent;
use super::super::{
    AuditSubjectKeyMaterial, MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS, integrity_failure, sql,
};
use super::snapshot::snapshot_digest;
use super::{
    TransitionEvidence, decode_outbox_row, event_context, fixed_outbox_values, required_text, rows,
    validated_outbox_rows, verify_exact_audit,
};
use crate::UtcTimestampMicros;
use crate::audit_repository::load_event_by_id;
use crate::session::check_context;

const MAX_RBAC_OUTBOX_PAYLOAD_BYTES: usize = 1_024;
const MAX_HISTORY_PAYLOAD_BYTES: usize = 67_108_864;

pub(in crate::rbac_repository) fn verify_complete_history(
    session: &mut LocalSession,
    events: &[PersistedPolicyEvent],
    current: &AuthorizationPolicy,
    key: &AuditSubjectKeyMaterial,
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<(), StorageError> {
    check_context(context)?;
    let candidates = load_history_candidates(session, current.tenant_id(), key, context)?;
    let mut candidates = index_history_candidates(candidates)?;
    let current_digest = snapshot_digest(&current.snapshot_state())?;
    let matched = match_history_candidates(events, current_digest, &mut candidates)?;
    verify_history_audits(
        session,
        &matched,
        context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    check_context(context)
}

fn load_history_candidates(
    session: &mut LocalSession,
    tenant: &TenantId,
    key: &AuditSubjectKeyMaterial,
    context: &RequestContext,
) -> Result<Vec<TransitionEvidence>, StorageError> {
    let maximum = usize::try_from(MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS)
        .map_err(|_| integrity_failure())?;
    let mut history = HistoryLoad::new(maximum);
    loop {
        let batch = load_history_page(session, tenant, history.cursor(), context)?;
        let page = validated_outbox_rows(&batch)?;
        if retain_history_page(&mut history, page, key, context)? {
            break;
        }
    }
    check_context(context)?;
    Ok(history.into_candidates())
}

fn retain_history_page(
    history: &mut HistoryLoad,
    page: &[Row],
    key: &AuditSubjectKeyMaterial,
    context: &RequestContext,
) -> Result<bool, StorageError> {
    if page.is_empty() {
        return Ok(true);
    }
    history.retain_page(page, key, context)?;
    Ok(page.len() < sql::OUTBOX_HISTORY_PAGE_ROWS)
}

fn load_history_page(
    session: &mut LocalSession,
    tenant: &TenantId,
    cursor: Option<sql::OutboxHistoryCursor<'_>>,
    context: &RequestContext,
) -> Result<rnmdb_executor::vector::VectorBatch, StorageError> {
    check_context(context)?;
    let batch = rows(sql::load_outbox_history_page(session, tenant, cursor)?)?;
    check_context(context)?;
    Ok(batch)
}

struct HistoryLoad {
    candidates: Vec<TransitionEvidence>,
    cursor: Option<HistoryCursor>,
    payload_bytes: usize,
    maximum_rows: usize,
}

impl HistoryLoad {
    fn new(maximum_rows: usize) -> Self {
        Self {
            candidates: Vec::new(),
            cursor: None,
            payload_bytes: 0,
            maximum_rows,
        }
    }

    fn cursor(&self) -> Option<sql::OutboxHistoryCursor<'_>> {
        self.cursor.as_ref().map(HistoryCursor::as_sql_cursor)
    }

    fn retain_page(
        &mut self,
        rows: &[Row],
        key: &AuditSubjectKeyMaterial,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let retained = self
            .candidates
            .len()
            .checked_add(rows.len())
            .ok_or_else(resource_exhausted)?;
        if retained > self.maximum_rows {
            return Err(resource_exhausted());
        }
        for row in rows {
            self.retain_row(row, key)?;
        }
        check_context(context)
    }

    fn retain_row(&mut self, row: &Row, key: &AuditSubjectKeyMaterial) -> Result<(), StorageError> {
        let metadata = HistoryRowMetadata::from_row(row)?;
        metadata.validate_after(self.cursor.as_ref())?;
        let payload_bytes = self
            .payload_bytes
            .checked_add(metadata.payload_bytes)
            .ok_or_else(resource_exhausted)?;
        if payload_bytes > MAX_HISTORY_PAYLOAD_BYTES {
            return Err(resource_exhausted());
        }
        let candidate = decode_outbox_row(row, key)?;
        self.candidates.push(candidate);
        self.cursor = Some(metadata.cursor);
        self.payload_bytes = payload_bytes;
        Ok(())
    }

    fn into_candidates(self) -> Vec<TransitionEvidence> {
        self.candidates
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct HistoryCursor {
    created_at: UtcTimestampMicros,
    event_id: String,
}

impl HistoryCursor {
    fn as_sql_cursor(&self) -> sql::OutboxHistoryCursor<'_> {
        sql::OutboxHistoryCursor::new(self.created_at, &self.event_id)
    }
}

struct HistoryRowMetadata {
    cursor: HistoryCursor,
    payload_bytes: usize,
}

impl HistoryRowMetadata {
    fn from_row(row: &Row) -> Result<Self, StorageError> {
        let values = fixed_outbox_values(row)?;
        let event_id = required_text(&values[1])?.to_owned();
        let created_at =
            UtcTimestampMicros::try_from_sql_value(&values[5]).map_err(|_| integrity_failure())?;
        let payload_bytes = bounded_payload_bytes(required_text(&values[4])?)?;
        Ok(Self {
            cursor: HistoryCursor {
                created_at,
                event_id,
            },
            payload_bytes,
        })
    }

    fn validate_after(&self, previous: Option<&HistoryCursor>) -> Result<(), StorageError> {
        if previous.is_some_and(|previous| self.cursor <= *previous) {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

fn bounded_payload_bytes(payload: &str) -> Result<usize, StorageError> {
    if payload.len() > MAX_RBAC_OUTBOX_PAYLOAD_BYTES * 2 {
        return Err(resource_exhausted());
    }
    if !payload.len().is_multiple_of(2) {
        return Err(integrity_failure());
    }
    Ok(payload.len() / 2)
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

fn index_history_candidates(
    candidates: Vec<TransitionEvidence>,
) -> Result<BTreeMap<PolicyVersion, TransitionEvidence>, StorageError> {
    let mut indexed = BTreeMap::new();
    for candidate in candidates {
        let version = candidate.identity.new_version;
        if indexed.insert(version, candidate).is_some() {
            return Err(integrity_failure());
        }
    }
    Ok(indexed)
}

fn match_history_candidates(
    events: &[PersistedPolicyEvent],
    current_digest: [u8; 32],
    candidates: &mut BTreeMap<PolicyVersion, TransitionEvidence>,
) -> Result<Vec<TransitionEvidence>, StorageError> {
    if candidates.len() != events.len() {
        return Err(integrity_failure());
    }
    let mut matched = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let candidate = take_event_candidate(candidates, event)?;
        validate_current_digest(index, events.len(), &candidate, current_digest)?;
        matched.push(candidate);
    }
    if !candidates.is_empty() {
        return Err(integrity_failure());
    }
    Ok(matched)
}

fn validate_current_digest(
    index: usize,
    event_count: usize,
    candidate: &TransitionEvidence,
    current_digest: [u8; 32],
) -> Result<(), StorageError> {
    if index + 1 == event_count && candidate.identity.snapshot_digest != current_digest {
        return Err(integrity_failure());
    }
    Ok(())
}

fn take_event_candidate(
    candidates: &mut BTreeMap<PolicyVersion, TransitionEvidence>,
    event: &PersistedPolicyEvent,
) -> Result<TransitionEvidence, StorageError> {
    let candidate = candidates
        .remove(&event.version())
        .ok_or_else(integrity_failure)?;
    if !candidate.identity.matches_event(event) {
        return Err(integrity_failure());
    }
    Ok(candidate)
}

fn verify_history_audits(
    session: &mut LocalSession,
    evidence: &[TransitionEvidence],
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<(), StorageError> {
    let anchor = load_history_audit_anchor(
        session,
        evidence,
        context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    let anchor = evidence.get(anchor).ok_or_else(integrity_failure)?;
    verify_history_membership(
        session,
        anchor,
        context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    check_context(context)
}

fn load_history_audit_anchor(
    session: &mut LocalSession,
    evidence: &[TransitionEvidence],
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<usize, StorageError> {
    let mut anchor = None;
    for (index, candidate) in evidence.iter().enumerate() {
        let sequence = load_history_audit_sequence(
            session,
            candidate,
            context,
            #[cfg(feature = "test-hooks")]
            history_test_hooks,
        )?;
        if anchor.is_none_or(|(_, current)| sequence < current) {
            anchor = Some((index, sequence));
        }
    }
    check_context(context)?;
    anchor.map(|(index, _)| index).ok_or_else(integrity_failure)
}

fn load_history_audit_sequence(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<AuditSequence, StorageError> {
    check_context(context)?;
    let persisted = load_event_by_id(
        session,
        &evidence.identity.tenant,
        &evidence.identity.audit_id,
    )?;
    #[cfg(feature = "test-hooks")]
    history_test_hooks.cancel_after_audit_query_if_armed(context);
    check_context(context)?;
    let persisted = persisted.ok_or_else(integrity_failure)?;
    verify_exact_audit(evidence, &persisted)?;
    check_context(context)?;
    Ok(persisted.sequence())
}

fn verify_history_membership(
    session: &mut LocalSession,
    evidence: &TransitionEvidence,
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<(), StorageError> {
    check_context(context)?;
    let event_context = event_context(context, &evidence.identity);
    let (persisted, _) = crate::audit_repository::load_durable_event_with_head(
        session,
        &evidence.identity.tenant,
        &evidence.identity.audit_id,
        &event_context,
    )?;
    check_context(context)?;
    verify_exact_audit(evidence, &persisted)?;
    check_context(context)?;
    #[cfg(feature = "test-hooks")]
    history_test_hooks.record_audit_membership_scan();
    Ok(())
}

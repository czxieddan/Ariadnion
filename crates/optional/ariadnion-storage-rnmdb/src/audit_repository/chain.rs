// crates/optional/ariadnion-storage-rnmdb/src/audit_repository/chain.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Bounded durable-membership verification for audit reads.

use ariadnion_audit_domain::{AuditEvent, AuditSequence};
use ariadnion_audit_store::{
    AuditChainHead, AuditExportCursor, MAX_AUDIT_EXPORT_EVENTS, verify_audit_batch,
};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::LocalSession;

use super::durable_read::{AuditReadQuery, ReadBoundary};
use super::{
    MAX_AUDIT_MEMBERSHIP_DISTANCE, decode_event_page, event_range_sql, integrity_failure,
    load_event_by_sequence, map_domain_error, map_store_error,
};

pub(super) fn validate_durable_membership(
    session: &mut LocalSession,
    context: &RequestContext,
    head: &AuditChainHead,
    target: &AuditEvent,
) -> Result<(), StorageError> {
    let boundary = ReadBoundary::unobserved(context);
    validate_durable_membership_observed(session, &boundary, head, target)
}

pub(super) fn validate_durable_membership_observed(
    session: &mut LocalSession,
    boundary: &ReadBoundary<'_>,
    head: &AuditChainHead,
    target: &AuditEvent,
) -> Result<(), StorageError> {
    let (last_sequence, mut scan) = prepare_membership_scan(session, boundary, head, target)?;
    scan_membership_suffix(session, boundary, target, last_sequence, &mut scan)?;
    boundary.check()?;
    check_membership_result(scan.previous.as_ref(), head, scan.target_seen)
}

fn prepare_membership_scan(
    session: &mut LocalSession,
    boundary: &ReadBoundary<'_>,
    head: &AuditChainHead,
    target: &AuditEvent,
) -> Result<(AuditSequence, MembershipScan), StorageError> {
    boundary.check()?;
    let last_sequence = head.last_sequence().ok_or_else(integrity_failure)?;
    validate_target_bound(head, target, last_sequence)?;
    let from_genesis = membership_starts_at_genesis(target.sequence(), last_sequence)?;
    let scan = initialize_scan(session, boundary, target, from_genesis)?;
    boundary.check()?;
    Ok((last_sequence, scan))
}

fn scan_membership_suffix(
    session: &mut LocalSession,
    boundary: &ReadBoundary<'_>,
    target: &AuditEvent,
    last_sequence: AuditSequence,
    scan: &mut MembershipScan,
) -> Result<(), StorageError> {
    while sequence_within_head(scan.next, last_sequence) {
        boundary.check()?;
        let cursor = membership_cursor(scan.next, last_sequence)?;
        validate_membership_page(session, boundary, target.tenant_id(), cursor, target, scan)?;
    }
    Ok(())
}

fn validate_target_bound(
    head: &AuditChainHead,
    target: &AuditEvent,
    last_sequence: AuditSequence,
) -> Result<(), StorageError> {
    if target.tenant_id() != head.tenant_id() || target.sequence().get() > last_sequence.get() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn membership_starts_at_genesis(
    target: AuditSequence,
    last_sequence: AuditSequence,
) -> Result<bool, StorageError> {
    let first = AuditSequence::initial().get();
    let prefix = target
        .get()
        .checked_sub(first)
        .ok_or_else(integrity_failure)?;
    let suffix = last_sequence
        .get()
        .checked_sub(target.get())
        .ok_or_else(integrity_failure)?;
    if suffix > MAX_AUDIT_MEMBERSHIP_DISTANCE {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    if prefix > MAX_AUDIT_MEMBERSHIP_DISTANCE {
        return validate_anchor_budget(suffix);
    }
    validate_full_budget(prefix, suffix)
}

fn validate_full_budget(prefix: u64, suffix: u64) -> Result<bool, StorageError> {
    let total = prefix.checked_add(suffix).ok_or_else(integrity_failure)?;
    if total > MAX_AUDIT_MEMBERSHIP_DISTANCE {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(true)
}

fn validate_anchor_budget(suffix: u64) -> Result<bool, StorageError> {
    let total = suffix.checked_add(1).ok_or_else(integrity_failure)?;
    if total > MAX_AUDIT_MEMBERSHIP_DISTANCE {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(false)
}

struct MembershipScan {
    previous: Option<AuditEvent>,
    next: Option<u64>,
    target_seen: bool,
}

fn initialize_scan(
    session: &mut LocalSession,
    boundary: &ReadBoundary<'_>,
    target: &AuditEvent,
    from_genesis: bool,
) -> Result<MembershipScan, StorageError> {
    if from_genesis {
        return Ok(MembershipScan {
            previous: None,
            next: Some(AuditSequence::initial().get()),
            target_seen: false,
        });
    }
    validate_persisted_event_link_observed(session, boundary, target)?;
    Ok(MembershipScan {
        previous: Some(target.clone()),
        next: target.sequence().get().checked_add(1),
        target_seen: true,
    })
}

fn validate_membership_page(
    session: &mut LocalSession,
    boundary: &ReadBoundary<'_>,
    tenant_id: &TenantId,
    cursor: AuditExportCursor,
    target: &AuditEvent,
    scan: &mut MembershipScan,
) -> Result<(), StorageError> {
    let events = load_membership_page(session, boundary, tenant_id, cursor)?;
    if events.is_empty() {
        return Err(integrity_failure());
    }
    for candidate in events {
        apply_membership_candidate(candidate, target, scan)?;
    }
    boundary.check()
}

fn load_membership_page(
    session: &mut LocalSession,
    boundary: &ReadBoundary<'_>,
    tenant_id: &TenantId,
    cursor: AuditExportCursor,
) -> Result<Vec<AuditEvent>, StorageError> {
    let sql = event_range_sql(tenant_id, cursor)?;
    let output = boundary.execute(session, &sql, AuditReadQuery::Chain)?;
    boundary.before_decode(AuditReadQuery::Chain);
    decode_event_page(output, tenant_id)
}

fn apply_membership_candidate(
    candidate: AuditEvent,
    target: &AuditEvent,
    scan: &mut MembershipScan,
) -> Result<(), StorageError> {
    validate_membership_event(&candidate, scan.previous.as_ref(), scan.next)?;
    scan.target_seen |= validate_target_candidate(&candidate, target)?;
    scan.next = candidate.sequence().get().checked_add(1);
    scan.previous = Some(candidate);
    Ok(())
}

fn validate_target_candidate(
    candidate: &AuditEvent,
    target: &AuditEvent,
) -> Result<bool, StorageError> {
    if candidate.sequence() != target.sequence() {
        return Ok(false);
    }
    if candidate != target {
        return Err(integrity_failure());
    }
    Ok(true)
}

fn validate_membership_event(
    candidate: &AuditEvent,
    previous: Option<&AuditEvent>,
    next: Option<u64>,
) -> Result<(), StorageError> {
    if Some(candidate.sequence().get()) != next {
        return Err(integrity_failure());
    }
    let predecessor = match previous {
        Some(event) => AuditChainHead::from_event(event).map_err(map_store_error)?,
        None => AuditChainHead::empty(candidate.tenant_id().clone()),
    };
    verify_audit_batch(&predecessor, std::slice::from_ref(candidate))
        .map_err(map_store_error)
        .map(|_| ())
}

fn check_membership_result(
    previous: Option<&AuditEvent>,
    head: &AuditChainHead,
    target_seen: bool,
) -> Result<(), StorageError> {
    let Some(last) = previous else {
        return Err(integrity_failure());
    };
    if !target_seen
        || head.last_sequence() != Some(last.sequence())
        || head.chain_digest() != Some(last.chain_digest())
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn membership_cursor(
    next: Option<u64>,
    last_sequence: AuditSequence,
) -> Result<AuditExportCursor, StorageError> {
    let sequence = next.ok_or_else(integrity_failure)?;
    let end = sequence
        .checked_add((MAX_AUDIT_EXPORT_EVENTS - 1) as u64)
        .map_or(last_sequence.get(), |value| value.min(last_sequence.get()));
    let start = AuditSequence::new(sequence).map_err(map_domain_error)?;
    let finish = AuditSequence::new(end).map_err(map_domain_error)?;
    AuditExportCursor::through(start, finish).map_err(map_store_error)
}

fn sequence_within_head(next: Option<u64>, head: AuditSequence) -> bool {
    next.is_some_and(|sequence| sequence <= head.get())
}

pub(super) fn validate_persisted_event_link(
    session: &mut LocalSession,
    event: &AuditEvent,
) -> Result<(), StorageError> {
    let head = load_predecessor_head(session, event)?;
    verify_audit_batch(&head, std::slice::from_ref(event))
        .map(|_| ())
        .map_err(map_store_error)
}

pub(super) fn validate_persisted_event_link_observed(
    session: &mut LocalSession,
    boundary: &ReadBoundary<'_>,
    event: &AuditEvent,
) -> Result<(), StorageError> {
    let head = load_predecessor_head_observed(session, boundary, event)?;
    verify_audit_batch(&head, std::slice::from_ref(event))
        .map(|_| ())
        .map_err(map_store_error)
}

fn load_predecessor_head(
    session: &mut LocalSession,
    event: &AuditEvent,
) -> Result<AuditChainHead, StorageError> {
    if event.sequence() == AuditSequence::initial() {
        return Ok(AuditChainHead::empty(event.tenant_id().clone()));
    }
    let sequence = predecessor_sequence(event.sequence())?;
    let predecessor = load_event_by_sequence(session, event.tenant_id(), sequence)?
        .ok_or_else(integrity_failure)?;
    AuditChainHead::from_event(&predecessor).map_err(map_store_error)
}

fn load_predecessor_head_observed(
    session: &mut LocalSession,
    boundary: &ReadBoundary<'_>,
    event: &AuditEvent,
) -> Result<AuditChainHead, StorageError> {
    boundary.check()?;
    if event.sequence() == AuditSequence::initial() {
        return Ok(AuditChainHead::empty(event.tenant_id().clone()));
    }
    let sequence = predecessor_sequence(event.sequence())?;
    let predecessor = super::durable_read::load_event_by_sequence(
        session,
        event.tenant_id(),
        sequence,
        AuditReadQuery::Chain,
        boundary,
    )?
    .ok_or_else(integrity_failure)?;
    AuditChainHead::from_event(&predecessor).map_err(map_store_error)
}

fn predecessor_sequence(sequence: AuditSequence) -> Result<AuditSequence, StorageError> {
    let value = sequence
        .get()
        .checked_sub(1)
        .ok_or_else(integrity_failure)?;
    AuditSequence::new(value).map_err(map_domain_error)
}

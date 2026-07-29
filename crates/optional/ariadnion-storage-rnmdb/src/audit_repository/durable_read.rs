// crates/optional/ariadnion-storage-rnmdb/src/audit_repository/durable_read.rs - Rust source for Ariadnion.
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
//! Cancellation-aware phased loading for one durable audit event.

use ariadnion_audit_domain::{AuditEvent, AuditEventId, AuditSequence};
use ariadnion_audit_store::AuditChainHead;
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::StorageError;
use rnmdb_cli::{CommandOutput, LocalSession};

use super::{
    StoredHead, chain, decode_event_presence, decode_optional_event, decode_stored_head,
    event_by_id_sql, event_by_sequence_sql, event_presence_sql, execute, head_columns,
    head_select_sql, integrity_failure, map_store_error, not_found, rows, validate_columns,
};
use crate::session::check_context;

/// Classifies I/O performed while authenticating one exact audit event.
#[derive(Clone, Copy)]
pub(crate) enum AuditReadQuery {
    ExactEvent,
    Head,
    Chain,
}

/// Observes query and decode boundaries without owning storage behavior.
pub(crate) trait AuditReadObserver {
    fn before_query(&self, _query: AuditReadQuery) {}

    fn after_query(&self, _query: AuditReadQuery, _context: &RequestContext) {}

    fn before_decode(&self, _query: AuditReadQuery) {}
}

struct NoopAuditReadObserver;

impl AuditReadObserver for NoopAuditReadObserver {}

const NOOP_OBSERVER: NoopAuditReadObserver = NoopAuditReadObserver;

pub(super) struct ReadBoundary<'a> {
    context: &'a RequestContext,
    observer: &'a dyn AuditReadObserver,
}

impl<'a> ReadBoundary<'a> {
    pub(super) const fn unobserved(context: &'a RequestContext) -> Self {
        Self {
            context,
            observer: &NOOP_OBSERVER,
        }
    }

    #[cfg(feature = "test-hooks")]
    const fn observed(context: &'a RequestContext, observer: &'a dyn AuditReadObserver) -> Self {
        Self { context, observer }
    }

    pub(super) fn check(&self) -> Result<(), StorageError> {
        check_context(self.context)
    }

    pub(super) fn execute(
        &self,
        session: &mut LocalSession,
        sql: &str,
        query: AuditReadQuery,
    ) -> Result<CommandOutput, StorageError> {
        self.check()?;
        self.observer.before_query(query);
        let output = execute(session, sql);
        self.observer.after_query(query, self.context);
        self.check()?;
        output
    }

    pub(super) fn before_decode(&self, query: AuditReadQuery) {
        self.observer.before_decode(query);
    }
}

pub(super) fn load_durable_event_with_head(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    event_id: &AuditEventId,
    context: &RequestContext,
) -> Result<(AuditEvent, AuditChainHead), StorageError> {
    let boundary = ReadBoundary::unobserved(context);
    load_with_boundary(session, tenant_id, event_id, &boundary)
}

#[cfg(feature = "test-hooks")]
pub(super) fn load_durable_event_with_head_observed(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    event_id: &AuditEventId,
    context: &RequestContext,
    observer: &dyn AuditReadObserver,
) -> Result<(AuditEvent, AuditChainHead), StorageError> {
    let boundary = ReadBoundary::observed(context, observer);
    load_with_boundary(session, tenant_id, event_id, &boundary)
}

fn load_with_boundary(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    event_id: &AuditEventId,
    boundary: &ReadBoundary<'_>,
) -> Result<(AuditEvent, AuditChainHead), StorageError> {
    let event = load_event_by_id(session, tenant_id, event_id, boundary)?.ok_or_else(not_found)?;
    let head = load_head(session, tenant_id, boundary)?;
    chain::validate_durable_membership_observed(session, boundary, &head, &event)?;
    boundary.check()?;
    Ok((event, head))
}

fn load_event_by_id(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    event_id: &AuditEventId,
    boundary: &ReadBoundary<'_>,
) -> Result<Option<AuditEvent>, StorageError> {
    let sql = event_by_id_sql(tenant_id, event_id)?;
    let output = boundary.execute(session, &sql, AuditReadQuery::ExactEvent)?;
    boundary.before_decode(AuditReadQuery::ExactEvent);
    decode_optional_event(output, tenant_id, Some(event_id), None)
}

fn load_head(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    boundary: &ReadBoundary<'_>,
) -> Result<AuditChainHead, StorageError> {
    let sql = head_select_sql(tenant_id)?;
    let output = boundary.execute(session, &sql, AuditReadQuery::Head)?;
    boundary.before_decode(AuditReadQuery::Head);
    decode_head(output, session, tenant_id, boundary)
}

fn decode_head(
    output: CommandOutput,
    session: &mut LocalSession,
    tenant_id: &TenantId,
    boundary: &ReadBoundary<'_>,
) -> Result<AuditChainHead, StorageError> {
    let batch = rows(output)?;
    validate_columns(batch.columns(), &head_columns())?;
    match batch.rows() {
        [] => load_empty_head(session, tenant_id, boundary),
        [row] => rehydrate_head(
            session,
            tenant_id,
            decode_stored_head(row, tenant_id)?,
            boundary,
        ),
        _ => Err(integrity_failure()),
    }
}

fn load_empty_head(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    boundary: &ReadBoundary<'_>,
) -> Result<AuditChainHead, StorageError> {
    if tenant_has_event(session, tenant_id, None, boundary)? {
        return Err(integrity_failure());
    }
    Ok(AuditChainHead::empty(tenant_id.clone()))
}

fn rehydrate_head(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    stored: StoredHead,
    boundary: &ReadBoundary<'_>,
) -> Result<AuditChainHead, StorageError> {
    let event = load_event_by_sequence(
        session,
        tenant_id,
        stored.last_sequence,
        AuditReadQuery::Head,
        boundary,
    )?
    .ok_or_else(integrity_failure)?;
    let head = AuditChainHead::rehydrate(
        stored.tenant_id,
        stored.last_sequence,
        stored.chain_version,
        stored.chain_digest,
        &event,
    )
    .map_err(map_store_error)?;
    chain::validate_persisted_event_link_observed(session, boundary, &event)?;
    reject_events_after_head(session, tenant_id, stored.last_sequence, boundary)?;
    Ok(head)
}

fn reject_events_after_head(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    last_sequence: AuditSequence,
    boundary: &ReadBoundary<'_>,
) -> Result<(), StorageError> {
    if tenant_has_event(session, tenant_id, Some(last_sequence), boundary)? {
        return Err(integrity_failure());
    }
    Ok(())
}

fn tenant_has_event(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    after: Option<AuditSequence>,
    boundary: &ReadBoundary<'_>,
) -> Result<bool, StorageError> {
    let sql = event_presence_sql(tenant_id, after)?;
    let output = boundary.execute(session, &sql, AuditReadQuery::Head)?;
    boundary.before_decode(AuditReadQuery::Head);
    decode_event_presence(output)
}

pub(super) fn load_event_by_sequence(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    sequence: AuditSequence,
    query: AuditReadQuery,
    boundary: &ReadBoundary<'_>,
) -> Result<Option<AuditEvent>, StorageError> {
    let sql = event_by_sequence_sql(tenant_id, sequence)?;
    let output = boundary.execute(session, &sql, query)?;
    boundary.before_decode(query);
    decode_optional_event(output, tenant_id, None, Some(sequence))
}

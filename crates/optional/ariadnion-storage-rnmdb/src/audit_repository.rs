//! Durable tenant-local identity audit repository.

use std::sync::Arc;

use ariadnion_audit_domain::{
    AuditChainDigest, AuditError, AuditEvent, AuditEventBinding, AuditEventContent, AuditEventId,
    AuditEventKind, AuditEventRequest, AuditPayloadDigest, AuditSequence, AuditSubject,
    AuditSubjectDigest, AuditSubjectKind, rehydrate_audit_event,
};
use ariadnion_audit_store::{
    AuditChainHead, AuditExportCursor, AuditStoreError, AuditStoreErrorCode,
    MAX_AUDIT_EXPORT_EVENTS, export_audit_batch, verify_audit_batch,
};
use ariadnion_core::{PrincipalContext, PrincipalId, RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use crate::RnmdbSessionOwner;
use crate::identity_transaction::run_identity_transaction;
use crate::session::map_rnmdb_error;

const EVENT_TABLE: &str = "identity_audit_events";
const HEAD_TABLE: &str = "identity_audit_heads";
const EVENT_PROJECTION: &str = "tenant_id, event_id, sequence, actor_id, occurred_at, event_kind, subject_kind, subject_digest, reason_code, payload_digest, previous_chain_digest, chain_digest_version, chain_digest";
const HEAD_PROJECTION: &str = "tenant_id, last_sequence, chain_digest_version, chain_digest";
const MAX_AUDIT_SQL_BYTES: usize = 16_384;
const SEQUENCE_TEXT_BYTES: usize = 20;
const DIGEST_TEXT_BYTES: usize = 64;

/// Persists and verifies one authenticated tenant's immutable identity audit chain.
pub struct RnmdbAuditRepository {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbAuditRepository {
    /// Creates a repository over one serialized embedded RNMDB session.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Appends one canonical event after an exact durable-head comparison.
    ///
    /// The event insert and head creation or compare-and-swap execute under one
    /// session lock and one transaction. An exact replay of the event already
    /// at the durable head is idempotent. A different event with the same
    /// tenant-local identity is a conflict. The event actor must match the
    /// authenticated principal before the transaction begins.
    ///
    /// # Errors
    ///
    /// Returns a stable storage error for unauthenticated or cross-tenant
    /// access, a stale head, malformed chain material, persistence failure, or
    /// transaction failure. Every error after `BEGIN` attempts rollback.
    pub fn append(
        &self,
        expected_head: &AuditChainHead,
        event: &AuditEvent,
        context: &RequestContext,
    ) -> Result<AuditChainHead, StorageError> {
        let principal = authenticated_principal(context)?;
        validate_append_identity(principal, expected_head, event)?;
        self.session.with_storage_session(context, |session| {
            run_identity_transaction(session, |session| {
                append_in_transaction(session, principal, expected_head, event)
            })
        })
    }

    /// Loads and authenticates the current durable head for one tenant.
    ///
    /// A tenant without committed audit events returns an empty head. A stored
    /// head is accepted only when its boundary event rehydrates exactly.
    ///
    /// # Errors
    ///
    /// Returns a stable storage error for unauthenticated or cross-tenant
    /// access, malformed persisted values, broken boundary state, or I/O.
    pub fn load_head(
        &self,
        tenant_id: &TenantId,
        context: &RequestContext,
    ) -> Result<AuditChainHead, StorageError> {
        validate_authenticated_tenant(context, tenant_id)?;
        self.session.with_storage_session(context, |session| {
            load_head_from_session(session, tenant_id)
        })
    }

    /// Loads one exact tenant-local audit event by identity.
    ///
    /// Persisted columns, labels, canonical decimal and hexadecimal encodings,
    /// the durable head bound, and the immediate chain link are all validated
    /// before returning the event.
    ///
    /// # Errors
    ///
    /// Returns [`StorageErrorCode::NotFound`] when the event is absent, or a
    /// stable storage error for authentication, integrity, or I/O failures.
    pub fn load_event(
        &self,
        tenant_id: &TenantId,
        event_id: &AuditEventId,
        context: &RequestContext,
    ) -> Result<AuditEvent, StorageError> {
        validate_authenticated_tenant(context, tenant_id)?;
        self.session.with_storage_session(context, |session| {
            load_durable_event_by_id(session, tenant_id, event_id)
        })
    }

    /// Exports one exact bounded sequence page after durable chain verification.
    ///
    /// The cursor is capped by the audit-store contract. The predecessor event
    /// and every exported row are rehydrated from authenticated storage, then
    /// the audit-store verifies continuity and exact page coverage.
    ///
    /// # Errors
    ///
    /// Returns a stable storage error when authentication fails, the exact
    /// range is unavailable, persisted material is malformed, or I/O fails.
    pub fn export(
        &self,
        tenant_id: &TenantId,
        cursor: AuditExportCursor,
        context: &RequestContext,
    ) -> Result<Box<[AuditEvent]>, StorageError> {
        validate_authenticated_tenant(context, tenant_id)?;
        self.session.with_storage_session(context, |session| {
            export_from_session(session, tenant_id, cursor)
        })
    }
}

pub(crate) fn append_in_transaction(
    session: &mut LocalSession,
    principal: &PrincipalContext,
    expected_head: &AuditChainHead,
    event: &AuditEvent,
) -> Result<AuditChainHead, StorageError> {
    require_active_transaction(session)?;
    validate_append_identity(principal, expected_head, event)?;
    let existing = load_event_by_id(session, event.tenant_id(), event.id())?;
    match existing {
        Some(existing) => resolve_existing_append(session, expected_head, event, existing),
        None => append_new_event(session, expected_head, event),
    }
}

fn append_new_event(
    session: &mut LocalSession,
    expected_head: &AuditChainHead,
    event: &AuditEvent,
) -> Result<AuditChainHead, StorageError> {
    reject_duplicate_sequence(session, event)?;
    let persisted_head = load_head_from_session(session, event.tenant_id())?;
    if &persisted_head != expected_head {
        return Err(conflict());
    }
    let candidate_head = verify_candidate(expected_head, event)?;
    insert_event(session, event)?;
    change_head(session, expected_head, &candidate_head)?;
    Ok(candidate_head)
}

fn require_active_transaction(session: &LocalSession) -> Result<(), StorageError> {
    if !session.in_transaction() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn reject_duplicate_sequence(
    session: &mut LocalSession,
    event: &AuditEvent,
) -> Result<(), StorageError> {
    if load_event_by_sequence(session, event.tenant_id(), event.sequence())?.is_some() {
        return Err(conflict());
    }
    Ok(())
}

fn resolve_existing_append(
    session: &mut LocalSession,
    expected_head: &AuditChainHead,
    event: &AuditEvent,
    existing: AuditEvent,
) -> Result<AuditChainHead, StorageError> {
    if &existing != event {
        return Err(conflict());
    }
    let candidate_head = verify_candidate(expected_head, event)?;
    let persisted_head = load_head_from_session(session, event.tenant_id())?;
    if persisted_head != candidate_head {
        return Err(conflict());
    }
    Ok(candidate_head)
}

fn verify_candidate(
    expected_head: &AuditChainHead,
    event: &AuditEvent,
) -> Result<AuditChainHead, StorageError> {
    verify_audit_batch(expected_head, std::slice::from_ref(event)).map_err(map_store_error)
}

fn export_from_session(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    cursor: AuditExportCursor,
) -> Result<Box<[AuditEvent]>, StorageError> {
    let durable_head = load_head_from_session(session, tenant_id)?;
    validate_export_bound(&durable_head, cursor)?;
    let head = export_base_head(session, tenant_id, cursor.start())?;
    let sql = event_range_sql(tenant_id, cursor)?;
    let events = decode_event_page(execute(session, &sql)?, tenant_id)?;
    export_audit_batch(&head, &events, cursor).map_err(map_store_error)
}

fn export_base_head(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    start: AuditSequence,
) -> Result<AuditChainHead, StorageError> {
    if start == AuditSequence::initial() {
        return Ok(AuditChainHead::empty(tenant_id.clone()));
    }
    let value = start.get().checked_sub(1).ok_or_else(integrity_failure)?;
    let sequence = AuditSequence::new(value).map_err(map_domain_error)?;
    let event = load_event_by_sequence(session, tenant_id, sequence)?.ok_or_else(not_found)?;
    validate_persisted_event_link(session, &event)?;
    AuditChainHead::from_event(&event).map_err(map_store_error)
}

pub(crate) fn load_head_from_session(
    session: &mut LocalSession,
    tenant_id: &TenantId,
) -> Result<AuditChainHead, StorageError> {
    let sql = head_select_sql(tenant_id)?;
    let batch = rows(execute(session, &sql)?)?;
    validate_columns(batch.columns(), &head_columns())?;
    match batch.rows() {
        [] => load_empty_head(session, tenant_id),
        [row] => decode_head_row(session, row, tenant_id),
        _ => Err(integrity_failure()),
    }
}

fn decode_head_row(
    session: &mut LocalSession,
    row: &Row,
    expected_tenant: &TenantId,
) -> Result<AuditChainHead, StorageError> {
    let stored = decode_stored_head(row, expected_tenant)?;
    rehydrate_stored_head(session, expected_tenant, stored)
}

struct StoredHead {
    tenant_id: TenantId,
    last_sequence: AuditSequence,
    chain_version: u16,
    chain_digest: AuditChainDigest,
}

fn decode_stored_head(row: &Row, expected_tenant: &TenantId) -> Result<StoredHead, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(sequence),
        SqlValue::Int64(version),
        SqlValue::Text(digest),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    let tenant_id = TenantId::parse(tenant).map_err(|_| integrity_failure())?;
    validate_stored_tenant(&tenant_id, expected_tenant)?;
    Ok(StoredHead {
        tenant_id,
        last_sequence: decode_sequence(sequence)?,
        chain_version: decode_chain_version(*version)?,
        chain_digest: AuditChainDigest::new(decode_digest(digest)?),
    })
}

fn validate_stored_tenant(
    tenant_id: &TenantId,
    expected_tenant: &TenantId,
) -> Result<(), StorageError> {
    if tenant_id != expected_tenant {
        return Err(integrity_failure());
    }
    Ok(())
}

fn rehydrate_stored_head(
    session: &mut LocalSession,
    expected_tenant: &TenantId,
    stored: StoredHead,
) -> Result<AuditChainHead, StorageError> {
    let boundary = load_head_boundary(session, expected_tenant, stored.last_sequence)?;
    let head = AuditChainHead::rehydrate(
        stored.tenant_id,
        stored.last_sequence,
        stored.chain_version,
        stored.chain_digest,
        &boundary,
    )
    .map_err(map_store_error)?;
    validate_persisted_event_link(session, &boundary)?;
    reject_events_after_head(session, expected_tenant, stored.last_sequence)?;
    Ok(head)
}

fn load_head_boundary(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    last_sequence: AuditSequence,
) -> Result<AuditEvent, StorageError> {
    load_event_by_sequence(session, tenant_id, last_sequence)?.ok_or_else(integrity_failure)
}

fn load_empty_head(
    session: &mut LocalSession,
    tenant_id: &TenantId,
) -> Result<AuditChainHead, StorageError> {
    if tenant_has_event(session, tenant_id, None)? {
        return Err(integrity_failure());
    }
    Ok(AuditChainHead::empty(tenant_id.clone()))
}

fn reject_events_after_head(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    last_sequence: AuditSequence,
) -> Result<(), StorageError> {
    if tenant_has_event(session, tenant_id, Some(last_sequence))? {
        return Err(integrity_failure());
    }
    Ok(())
}

fn load_durable_event_by_id(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    event_id: &AuditEventId,
) -> Result<AuditEvent, StorageError> {
    let event = load_event_by_id(session, tenant_id, event_id)?.ok_or_else(not_found)?;
    let head = load_head_from_session(session, tenant_id)?;
    validate_durable_membership(&head, &event)?;
    validate_persisted_event_link(session, &event)?;
    Ok(event)
}

fn validate_durable_membership(
    head: &AuditChainHead,
    event: &AuditEvent,
) -> Result<(), StorageError> {
    let last_sequence = head.last_sequence().ok_or_else(integrity_failure)?;
    if event.tenant_id() != head.tenant_id() || event.sequence().get() > last_sequence.get() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_persisted_event_link(
    session: &mut LocalSession,
    event: &AuditEvent,
) -> Result<(), StorageError> {
    let head = load_predecessor_head(session, event)?;
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

fn predecessor_sequence(sequence: AuditSequence) -> Result<AuditSequence, StorageError> {
    let value = sequence
        .get()
        .checked_sub(1)
        .ok_or_else(integrity_failure)?;
    AuditSequence::new(value).map_err(map_domain_error)
}

fn validate_export_bound(
    head: &AuditChainHead,
    cursor: AuditExportCursor,
) -> Result<(), StorageError> {
    let Some(last_sequence) = head.last_sequence() else {
        return Err(not_found());
    };
    if cursor.end_inclusive().get() > last_sequence.get() {
        return Err(not_found());
    }
    Ok(())
}

pub(crate) fn load_event_by_id(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    event_id: &AuditEventId,
) -> Result<Option<AuditEvent>, StorageError> {
    let sql = event_by_id_sql(tenant_id, event_id)?;
    decode_optional_event(execute(session, &sql)?, tenant_id, Some(event_id), None)
}

fn load_event_by_sequence(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    sequence: AuditSequence,
) -> Result<Option<AuditEvent>, StorageError> {
    let sql = event_by_sequence_sql(tenant_id, sequence)?;
    decode_optional_event(execute(session, &sql)?, tenant_id, None, Some(sequence))
}

fn tenant_has_event(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    after: Option<AuditSequence>,
) -> Result<bool, StorageError> {
    let sql = event_presence_sql(tenant_id, after)?;
    let batch = rows(execute(session, &sql)?)?;
    validate_columns(batch.columns(), &event_presence_columns())?;
    match batch.rows() {
        [] => Ok(false),
        [row] => match row.values() {
            [SqlValue::Text(_)] => Ok(true),
            _ => Err(integrity_failure()),
        },
        _ => Err(integrity_failure()),
    }
}

fn decode_optional_event(
    output: CommandOutput,
    expected_tenant: &TenantId,
    expected_event: Option<&AuditEventId>,
    expected_sequence: Option<AuditSequence>,
) -> Result<Option<AuditEvent>, StorageError> {
    let batch = rows(output)?;
    validate_columns(batch.columns(), &event_columns())?;
    match batch.rows() {
        [] => Ok(None),
        [row] => {
            decode_event_row(row, expected_tenant, expected_event, expected_sequence).map(Some)
        }
        _ => Err(integrity_failure()),
    }
}

fn decode_event_page(
    output: CommandOutput,
    expected_tenant: &TenantId,
) -> Result<Vec<AuditEvent>, StorageError> {
    let batch = rows(output)?;
    validate_columns(batch.columns(), &event_columns())?;
    if batch.rows().len() > MAX_AUDIT_EXPORT_EVENTS {
        return Err(integrity_failure());
    }
    batch
        .rows()
        .iter()
        .map(|row| decode_event_row(row, expected_tenant, None, None))
        .collect()
}

fn decode_event_row(
    row: &Row,
    expected_tenant: &TenantId,
    expected_event: Option<&AuditEventId>,
    expected_sequence: Option<AuditSequence>,
) -> Result<AuditEvent, StorageError> {
    let values = audit_row_values(row)?;
    let identity =
        decode_event_identity(values, expected_tenant, expected_event, expected_sequence)?;
    let binding = decode_event_binding(values, identity)?;
    let content = decode_event_content(values)?;
    rehydrate_persisted_event(values, binding, content)
}

struct DecodedEventIdentity {
    tenant_id: TenantId,
    event_id: AuditEventId,
    sequence: AuditSequence,
}

fn decode_event_identity(
    values: AuditRowValues<'_>,
    expected_tenant: &TenantId,
    expected_event: Option<&AuditEventId>,
    expected_sequence: Option<AuditSequence>,
) -> Result<DecodedEventIdentity, StorageError> {
    let tenant_id = TenantId::parse(values.tenant).map_err(|_| integrity_failure())?;
    let event_id = AuditEventId::parse(values.event).map_err(map_domain_error)?;
    let sequence = decode_sequence(values.sequence)?;
    verify_event_identity(
        &tenant_id,
        &event_id,
        sequence,
        expected_tenant,
        expected_event,
        expected_sequence,
    )?;
    Ok(DecodedEventIdentity {
        tenant_id,
        event_id,
        sequence,
    })
}

fn decode_event_binding(
    values: AuditRowValues<'_>,
    identity: DecodedEventIdentity,
) -> Result<AuditEventBinding, StorageError> {
    let actor = PrincipalId::parse(values.actor).map_err(|_| integrity_failure())?;
    let occurred_at = UtcTimestamp::from_unix_seconds(values.occurred_at);
    Ok(AuditEventBinding::new(
        identity.event_id,
        identity.tenant_id,
        actor,
        occurred_at,
        identity.sequence,
    ))
}

fn decode_event_content(values: AuditRowValues<'_>) -> Result<AuditEventContent, StorageError> {
    let subject = AuditSubject::from_digest(
        decode_subject_kind(values.subject_kind)?,
        AuditSubjectDigest::new(decode_digest(values.subject_digest)?),
    );
    let payload = AuditPayloadDigest::new(decode_digest(values.payload_digest)?);
    let previous = decode_optional_digest(values.previous_digest)?;
    AuditEventContent::new(
        decode_event_kind(values.event_kind)?,
        subject,
        values.reason_code,
        payload,
        previous,
    )
    .map_err(map_domain_error)
}

fn rehydrate_persisted_event(
    values: AuditRowValues<'_>,
    binding: AuditEventBinding,
    content: AuditEventContent,
) -> Result<AuditEvent, StorageError> {
    let request = AuditEventRequest::new(binding, content);
    let version = decode_chain_version(values.chain_version)?;
    let digest = AuditChainDigest::new(decode_digest(values.chain_digest)?);
    rehydrate_audit_event(request, version, digest).map_err(map_domain_error)
}

#[derive(Clone, Copy)]
struct AuditRowValues<'a> {
    tenant: &'a str,
    event: &'a str,
    sequence: &'a str,
    actor: &'a str,
    occurred_at: i64,
    event_kind: &'a str,
    subject_kind: &'a str,
    subject_digest: &'a str,
    reason_code: &'a str,
    payload_digest: &'a str,
    previous_digest: Option<&'a str>,
    chain_version: i64,
    chain_digest: &'a str,
}

fn audit_row_values(row: &Row) -> Result<AuditRowValues<'_>, StorageError> {
    let values = fixed_audit_values(row)?;
    let identity = audit_identity_columns(values)?;
    let content = audit_content_columns(values)?;
    let chain = audit_chain_columns(values)?;
    Ok(AuditRowValues {
        tenant: identity.tenant,
        event: identity.event,
        sequence: identity.sequence,
        actor: identity.actor,
        occurred_at: identity.occurred_at,
        event_kind: content.event_kind,
        subject_kind: content.subject_kind,
        subject_digest: content.subject_digest,
        reason_code: content.reason_code,
        payload_digest: content.payload_digest,
        previous_digest: content.previous_digest,
        chain_version: chain.chain_version,
        chain_digest: chain.chain_digest,
    })
}

struct AuditIdentityColumns<'a> {
    tenant: &'a str,
    event: &'a str,
    sequence: &'a str,
    actor: &'a str,
    occurred_at: i64,
}

struct AuditContentColumns<'a> {
    event_kind: &'a str,
    subject_kind: &'a str,
    subject_digest: &'a str,
    reason_code: &'a str,
    payload_digest: &'a str,
    previous_digest: Option<&'a str>,
}

struct AuditChainColumns<'a> {
    chain_version: i64,
    chain_digest: &'a str,
}

fn fixed_audit_values(row: &Row) -> Result<&[SqlValue; 13], StorageError> {
    row.values().try_into().map_err(|_| integrity_failure())
}

fn audit_identity_columns(
    values: &[SqlValue; 13],
) -> Result<AuditIdentityColumns<'_>, StorageError> {
    Ok(AuditIdentityColumns {
        tenant: required_text(&values[0])?,
        event: required_text(&values[1])?,
        sequence: required_text(&values[2])?,
        actor: required_text(&values[3])?,
        occurred_at: required_i64(&values[4])?,
    })
}

fn audit_content_columns(values: &[SqlValue; 13]) -> Result<AuditContentColumns<'_>, StorageError> {
    Ok(AuditContentColumns {
        event_kind: required_text(&values[5])?,
        subject_kind: required_text(&values[6])?,
        subject_digest: required_text(&values[7])?,
        reason_code: required_text(&values[8])?,
        payload_digest: required_text(&values[9])?,
        previous_digest: optional_text(&values[10])?,
    })
}

fn audit_chain_columns(values: &[SqlValue; 13]) -> Result<AuditChainColumns<'_>, StorageError> {
    Ok(AuditChainColumns {
        chain_version: required_i64(&values[11])?,
        chain_digest: required_text(&values[12])?,
    })
}

fn required_text(value: &SqlValue) -> Result<&str, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(value),
        _ => Err(integrity_failure()),
    }
}

fn required_i64(value: &SqlValue) -> Result<i64, StorageError> {
    match value {
        SqlValue::Int64(value) => Ok(*value),
        _ => Err(integrity_failure()),
    }
}

fn verify_event_identity(
    tenant_id: &TenantId,
    event_id: &AuditEventId,
    sequence: AuditSequence,
    expected_tenant: &TenantId,
    expected_event: Option<&AuditEventId>,
    expected_sequence: Option<AuditSequence>,
) -> Result<(), StorageError> {
    if tenant_id != expected_tenant {
        return Err(integrity_failure());
    }
    if expected_event.is_some_and(|expected| event_id != expected) {
        return Err(integrity_failure());
    }
    if expected_sequence.is_some_and(|expected| sequence != expected) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn insert_event(session: &mut LocalSession, event: &AuditEvent) -> Result<(), StorageError> {
    let sql = event_insert_sql(event)?;
    require_single_change(execute(session, &sql)?)
}

fn change_head(
    session: &mut LocalSession,
    expected: &AuditChainHead,
    candidate: &AuditChainHead,
) -> Result<(), StorageError> {
    let sql = head_change_sql(expected, candidate)?;
    require_head_change(execute(session, &sql)?)
}

fn head_change_sql(
    expected: &AuditChainHead,
    candidate: &AuditChainHead,
) -> Result<String, StorageError> {
    match (
        expected.last_sequence(),
        expected.chain_digest_version(),
        expected.chain_digest(),
    ) {
        (None, None, None) => head_insert_sql(candidate),
        (Some(sequence), Some(version), Some(digest)) => {
            head_update_sql(candidate, sequence, version, digest)
        }
        _ => Err(integrity_failure()),
    }
}

fn event_by_id_sql(tenant_id: &TenantId, event_id: &AuditEventId) -> Result<String, StorageError> {
    let mut sql = format!("SELECT {EVENT_PROJECTION} FROM {EVENT_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND event_id = ");
    push_text_literal(&mut sql, event_id.as_str());
    sql.push_str(" LIMIT 2;");
    finish_sql(sql)
}

fn event_by_sequence_sql(
    tenant_id: &TenantId,
    sequence: AuditSequence,
) -> Result<String, StorageError> {
    let mut sql = format!("SELECT {EVENT_PROJECTION} FROM {EVENT_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND sequence = ");
    push_text_literal(&mut sql, &encode_sequence(sequence));
    sql.push_str(" LIMIT 2;");
    finish_sql(sql)
}

fn event_presence_sql(
    tenant_id: &TenantId,
    after: Option<AuditSequence>,
) -> Result<String, StorageError> {
    let mut sql = format!("SELECT event_id FROM {EVENT_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    if let Some(sequence) = after {
        sql.push_str(" AND sequence > ");
        push_text_literal(&mut sql, &encode_sequence(sequence));
    }
    sql.push_str(" LIMIT 1;");
    finish_sql(sql)
}

fn event_range_sql(
    tenant_id: &TenantId,
    cursor: AuditExportCursor,
) -> Result<String, StorageError> {
    let mut sql = format!("SELECT {EVENT_PROJECTION} FROM {EVENT_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND sequence >= ");
    push_text_literal(&mut sql, &encode_sequence(cursor.start()));
    sql.push_str(" AND sequence <= ");
    push_text_literal(&mut sql, &encode_sequence(cursor.end_inclusive()));
    sql.push_str(" ORDER BY sequence LIMIT 1025;");
    finish_sql(sql)
}

fn head_select_sql(tenant_id: &TenantId) -> Result<String, StorageError> {
    let mut sql = format!("SELECT {HEAD_PROJECTION} FROM {HEAD_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" LIMIT 2;");
    finish_sql(sql)
}

fn event_insert_sql(event: &AuditEvent) -> Result<String, StorageError> {
    let mut sql = format!("INSERT INTO {EVENT_TABLE} ({EVENT_PROJECTION}) VALUES (");
    push_text_literal(&mut sql, event.tenant_id().as_str());
    push_text_value(&mut sql, event.id().as_str());
    push_text_value(&mut sql, &encode_sequence(event.sequence()));
    push_text_value(&mut sql, event.actor().as_str());
    push_i64_value(&mut sql, event.occurred_at().unix_seconds());
    push_text_value(&mut sql, event_kind_label(event.kind()));
    push_text_value(&mut sql, subject_kind_label(event.subject().kind()));
    push_text_value(&mut sql, &encode_digest(event.subject().digest().bytes()));
    push_text_value(&mut sql, event.reason_code());
    push_text_value(&mut sql, &encode_digest(event.payload_digest().bytes()));
    push_optional_digest_value(&mut sql, event.previous_chain_digest());
    push_i64_value(&mut sql, i64::from(event.chain_digest_version()));
    push_text_value(&mut sql, &encode_digest(event.chain_digest().bytes()));
    sql.push_str(");");
    finish_sql(sql)
}

fn head_insert_sql(candidate: &AuditChainHead) -> Result<String, StorageError> {
    let (sequence, version, digest) = complete_head(candidate)?;
    let mut sql = format!(
        "INSERT INTO {HEAD_TABLE} (tenant_id, last_sequence, chain_digest_version, chain_digest) VALUES ("
    );
    push_text_literal(&mut sql, candidate.tenant_id().as_str());
    push_text_value(&mut sql, &encode_sequence(sequence));
    push_i64_value(&mut sql, i64::from(version));
    push_text_value(&mut sql, &encode_digest(digest.bytes()));
    sql.push_str(");");
    finish_sql(sql)
}

fn head_update_sql(
    candidate: &AuditChainHead,
    old_sequence: AuditSequence,
    old_version: u16,
    old_digest: AuditChainDigest,
) -> Result<String, StorageError> {
    let (sequence, version, digest) = complete_head(candidate)?;
    let mut sql = format!("UPDATE {HEAD_TABLE} SET last_sequence = ");
    push_text_literal(&mut sql, &encode_sequence(sequence));
    sql.push_str(", chain_digest_version = ");
    sql.push_str(&version.to_string());
    sql.push_str(", chain_digest = ");
    push_text_literal(&mut sql, &encode_digest(digest.bytes()));
    push_head_cas_predicate(&mut sql, candidate, old_sequence, old_version, old_digest);
    finish_sql(sql)
}

fn push_head_cas_predicate(
    sql: &mut String,
    candidate: &AuditChainHead,
    sequence: AuditSequence,
    version: u16,
    digest: AuditChainDigest,
) {
    sql.push_str(" WHERE tenant_id = ");
    push_text_literal(sql, candidate.tenant_id().as_str());
    sql.push_str(" AND last_sequence = ");
    push_text_literal(sql, &encode_sequence(sequence));
    sql.push_str(" AND chain_digest_version = ");
    sql.push_str(&version.to_string());
    sql.push_str(" AND chain_digest = ");
    push_text_literal(sql, &encode_digest(digest.bytes()));
    sql.push(';');
}

fn complete_head(
    head: &AuditChainHead,
) -> Result<(AuditSequence, u16, AuditChainDigest), StorageError> {
    match (
        head.last_sequence(),
        head.chain_digest_version(),
        head.chain_digest(),
    ) {
        (Some(sequence), Some(version), Some(digest)) => Ok((sequence, version, digest)),
        _ => Err(integrity_failure()),
    }
}

fn authenticated_principal(context: &RequestContext) -> Result<&PrincipalContext, StorageError> {
    context.principal().ok_or_else(integrity_failure)
}

fn validate_authenticated_tenant(
    context: &RequestContext,
    expected: &TenantId,
) -> Result<(), StorageError> {
    if authenticated_principal(context)?.tenant_id() != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_append_identity(
    principal: &PrincipalContext,
    expected_head: &AuditChainHead,
    event: &AuditEvent,
) -> Result<(), StorageError> {
    if expected_head.tenant_id() != principal.tenant_id()
        || event.tenant_id() != principal.tenant_id()
        || event.actor() != principal.principal_id()
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn decode_sequence(value: &str) -> Result<AuditSequence, StorageError> {
    if value.len() != SEQUENCE_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let number = value.parse::<u64>().map_err(|_| integrity_failure())?;
    let sequence = AuditSequence::new(number).map_err(map_domain_error)?;
    if encode_sequence(sequence) != value {
        return Err(integrity_failure());
    }
    Ok(sequence)
}

fn encode_sequence(sequence: AuditSequence) -> String {
    format!("{:020}", sequence.get())
}

fn decode_chain_version(value: i64) -> Result<u16, StorageError> {
    u16::try_from(value).map_err(|_| integrity_failure())
}

fn decode_optional_digest(value: Option<&str>) -> Result<Option<AuditChainDigest>, StorageError> {
    value
        .map(|digest| decode_digest(digest).map(AuditChainDigest::new))
        .transpose()
}

fn decode_digest(value: &str) -> Result<[u8; 32], StorageError> {
    if value.len() != DIGEST_TEXT_BYTES {
        return Err(integrity_failure());
    }
    let mut decoded = [0_u8; 32];
    for (target, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        *target = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_hex_nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(integrity_failure()),
    }
}

fn encode_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(DIGEST_TEXT_BYTES);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_event_kind(value: &str) -> Result<AuditEventKind, StorageError> {
    match value {
        "issued" => Ok(AuditEventKind::Issued),
        "consumed" => Ok(AuditEventKind::Consumed),
        "rotated" => Ok(AuditEventKind::Rotated),
        "revoked" => Ok(AuditEventKind::Revoked),
        "expired" => Ok(AuditEventKind::Expired),
        "reuse_detected" => Ok(AuditEventKind::ReuseDetected),
        "administered" => Ok(AuditEventKind::Administered),
        _ => Err(integrity_failure()),
    }
}

const fn event_kind_label(kind: AuditEventKind) -> &'static str {
    match kind {
        AuditEventKind::Issued => "issued",
        AuditEventKind::Consumed => "consumed",
        AuditEventKind::Rotated => "rotated",
        AuditEventKind::Revoked => "revoked",
        AuditEventKind::Expired => "expired",
        AuditEventKind::ReuseDetected => "reuse_detected",
        AuditEventKind::Administered => "administered",
    }
}

fn decode_subject_kind(value: &str) -> Result<AuditSubjectKind, StorageError> {
    match value {
        "user" => Ok(AuditSubjectKind::User),
        "organization" => Ok(AuditSubjectKind::Organization),
        "invitation" => Ok(AuditSubjectKind::Invitation),
        "session_family" => Ok(AuditSubjectKind::SessionFamily),
        "api_key" => Ok(AuditSubjectKind::ApiKey),
        "password_reset" => Ok(AuditSubjectKind::PasswordReset),
        "administration" => Ok(AuditSubjectKind::Administration),
        _ => Err(integrity_failure()),
    }
}

const fn subject_kind_label(kind: AuditSubjectKind) -> &'static str {
    match kind {
        AuditSubjectKind::User => "user",
        AuditSubjectKind::Organization => "organization",
        AuditSubjectKind::Invitation => "invitation",
        AuditSubjectKind::SessionFamily => "session_family",
        AuditSubjectKind::ApiKey => "api_key",
        AuditSubjectKind::PasswordReset => "password_reset",
        AuditSubjectKind::Administration => "administration",
    }
}

fn optional_text(value: &SqlValue) -> Result<Option<&str>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(value) => Ok(Some(value)),
        _ => Err(integrity_failure()),
    }
}

fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity_failure()),
    }
}

fn validate_columns(
    columns: &[ColumnSchema],
    expected: &[(&str, SqlType)],
) -> Result<(), StorageError> {
    if columns.len() != expected.len() {
        return Err(integrity_failure());
    }
    for (column, (name, data_type)) in columns.iter().zip(expected) {
        if column.name() != *name || column.data_type() != data_type {
            return Err(integrity_failure());
        }
    }
    Ok(())
}

fn event_columns() -> [(&'static str, SqlType); 13] {
    [
        ("tenant_id", SqlType::Text),
        ("event_id", SqlType::Text),
        ("sequence", SqlType::Text),
        ("actor_id", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("event_kind", SqlType::Text),
        ("subject_kind", SqlType::Text),
        ("subject_digest", SqlType::Text),
        ("reason_code", SqlType::Text),
        ("payload_digest", SqlType::Text),
        ("previous_chain_digest", SqlType::Text),
        ("chain_digest_version", SqlType::Int64),
        ("chain_digest", SqlType::Text),
    ]
}

fn event_presence_columns() -> [(&'static str, SqlType); 1] {
    [("event_id", SqlType::Text)]
}

fn head_columns() -> [(&'static str, SqlType); 4] {
    [
        ("tenant_id", SqlType::Text),
        ("last_sequence", SqlType::Text),
        ("chain_digest_version", SqlType::Int64),
        ("chain_digest", SqlType::Text),
    ]
}

fn execute(session: &mut LocalSession, sql: &str) -> Result<CommandOutput, StorageError> {
    session.execute(sql).map_err(map_rnmdb_error)
}

fn require_single_change(output: CommandOutput) -> Result<(), StorageError> {
    if output != CommandOutput::RowsAffected(1) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_head_change(output: CommandOutput) -> Result<(), StorageError> {
    match output {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(conflict()),
        _ => Err(integrity_failure()),
    }
}

fn push_text_value(sql: &mut String, value: &str) {
    sql.push_str(", ");
    push_text_literal(sql, value);
}

fn push_i64_value(sql: &mut String, value: i64) {
    sql.push_str(", ");
    sql.push_str(&value.to_string());
}

fn push_optional_digest_value(sql: &mut String, digest: Option<AuditChainDigest>) {
    sql.push_str(", ");
    match digest {
        Some(digest) => push_text_literal(sql, &encode_digest(digest.bytes())),
        None => sql.push_str("NULL"),
    }
}

fn push_text_literal(sql: &mut String, value: &str) {
    sql.push('\'');
    for character in value.chars() {
        if character == '\'' {
            sql.push_str("''");
        } else {
            sql.push(character);
        }
    }
    sql.push('\'');
}

fn finish_sql(sql: String) -> Result<String, StorageError> {
    if sql.len() > MAX_AUDIT_SQL_BYTES || !sql.is_ascii() {
        return Err(integrity_failure());
    }
    Ok(sql)
}

fn map_domain_error(_error: AuditError) -> StorageError {
    integrity_failure()
}

fn map_store_error(error: AuditStoreError) -> StorageError {
    let code = match error.code() {
        AuditStoreErrorCode::EmptyRange | AuditStoreErrorCode::IncompleteRange => {
            StorageErrorCode::NotFound
        }
        AuditStoreErrorCode::ResourceLimitExceeded => StorageErrorCode::ResourceExhausted,
        _ => StorageErrorCode::IntegrityFailure,
    };
    StorageError::new(code)
}

const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

const fn not_found() -> StorageError {
    StorageError::new(StorageErrorCode::NotFound)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

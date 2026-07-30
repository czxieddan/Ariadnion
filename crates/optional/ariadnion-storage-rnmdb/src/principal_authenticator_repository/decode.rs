// crates/optional/ariadnion-storage-rnmdb/src/principal_authenticator_repository/decode.rs - Rust source for Ariadnion.
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
//! Strict bounded decoding for principal-authenticator snapshots and history.

use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_principal_binding::{
    PrincipalAuthenticatorEvent, PrincipalAuthenticatorEventData, PrincipalAuthenticatorEventKind,
    PrincipalAuthenticatorId, PrincipalAuthenticatorKind, PrincipalAuthenticatorLink,
    PrincipalAuthenticatorSnapshot, PrincipalAuthenticatorSnapshotData,
    PrincipalAuthenticatorSourceCommitment, PrincipalAuthenticatorSourceId,
    PrincipalAuthenticatorState, PrincipalAuthenticatorTransition, PrincipalAuthenticatorVersion,
    PrincipalBindingVersion,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use super::{integrity_failure, sql};

const VERSION_TEXT_BYTES: usize = 20;
const COMMITMENT_TEXT_BYTES: usize = 64;

pub(super) struct LoadedPrincipalAuthenticator {
    pub(super) link: PrincipalAuthenticatorLink,
    pub(super) events: Vec<PersistedPrincipalAuthenticatorEvent>,
}

pub(super) struct PersistedPrincipalAuthenticatorEvent(PrincipalAuthenticatorEvent);

impl PersistedPrincipalAuthenticatorEvent {
    pub(super) const fn event(&self) -> &PrincipalAuthenticatorEvent {
        &self.0
    }

    pub(super) fn matches_transition(&self, transition: &PrincipalAuthenticatorTransition) -> bool {
        &self.0 == transition.event()
    }
}

enum SnapshotLookup<'a> {
    Id(&'a PrincipalAuthenticatorId),
    Source(
        PrincipalAuthenticatorKind,
        &'a PrincipalAuthenticatorSourceId,
    ),
}

pub(super) fn load_link_by_id(
    session: &mut LocalSession,
    tenant: &TenantId,
    authenticator: &PrincipalAuthenticatorId,
) -> Result<PrincipalAuthenticatorLink, StorageError> {
    load_link_with_history_by_id(session, tenant, authenticator).map(|loaded| loaded.link)
}

pub(super) fn load_link_with_history_by_id(
    session: &mut LocalSession,
    tenant: &TenantId,
    authenticator: &PrincipalAuthenticatorId,
) -> Result<LoadedPrincipalAuthenticator, StorageError> {
    let output = sql::load_snapshot_by_id(session, tenant, authenticator)?;
    load_link_with_history(session, tenant, SnapshotLookup::Id(authenticator), output)
}

pub(super) fn load_link_by_source(
    session: &mut LocalSession,
    tenant: &TenantId,
    kind: PrincipalAuthenticatorKind,
    source: &PrincipalAuthenticatorSourceId,
) -> Result<PrincipalAuthenticatorLink, StorageError> {
    load_link_with_history_by_source(session, tenant, kind, source).map(|loaded| loaded.link)
}

/// Loads and structurally authenticates the bounded source-link history.
///
/// The result contains at most the required `Linked` event and one terminal
/// `Revoked` event. This decoder validates row shape, tenant/source identity,
/// lifecycle continuity, and final snapshot agreement. Audit and outbox
/// authentication is performed by the repository reconciliation seam.
pub(super) fn load_link_with_history_by_source(
    session: &mut LocalSession,
    tenant: &TenantId,
    kind: PrincipalAuthenticatorKind,
    source: &PrincipalAuthenticatorSourceId,
) -> Result<LoadedPrincipalAuthenticator, StorageError> {
    let output = sql::load_snapshot_by_source(session, tenant, kind, source)?;
    load_link_with_history(
        session,
        tenant,
        SnapshotLookup::Source(kind, source),
        output,
    )
}

fn load_link_with_history(
    session: &mut LocalSession,
    tenant: &TenantId,
    lookup: SnapshotLookup<'_>,
    output: CommandOutput,
) -> Result<LoadedPrincipalAuthenticator, StorageError> {
    let snapshot = rows(output)?;
    let link = decode_snapshot(one_snapshot_row(&snapshot)?, tenant, lookup)?;
    let events = load_and_verify_events(session, &link)?;
    Ok(LoadedPrincipalAuthenticator { link, events })
}

pub(super) fn classify_creation_insert_error(
    session: &mut LocalSession,
    link: &PrincipalAuthenticatorLink,
    original: StorageError,
) -> StorageError {
    match creation_key_exists(session, link) {
        Ok(true) => StorageError::new(StorageErrorCode::Conflict),
        Ok(false) => original,
        Err(error) => error,
    }
}

fn creation_key_exists(
    session: &mut LocalSession,
    link: &PrincipalAuthenticatorLink,
) -> Result<bool, StorageError> {
    let by_id = load_link_by_id(session, link.tenant_id(), link.authenticator_id());
    if found_or_error(by_id)? {
        return Ok(true);
    }
    let by_source = load_link_by_source(session, link.tenant_id(), link.kind(), link.source_id());
    found_or_error(by_source)
}

fn found_or_error(
    result: Result<PrincipalAuthenticatorLink, StorageError>,
) -> Result<bool, StorageError> {
    match result {
        Ok(_) => Ok(true),
        Err(error) if error.code() == StorageErrorCode::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn one_snapshot_row(batch: &VectorBatch) -> Result<&Row, StorageError> {
    validate_columns(batch.columns(), &snapshot_columns())?;
    match batch.rows() {
        [] => Err(StorageError::new(StorageErrorCode::NotFound)),
        [row] => Ok(row),
        _ => Err(integrity_failure()),
    }
}

fn decode_snapshot(
    row: &Row,
    tenant: &TenantId,
    lookup: SnapshotLookup<'_>,
) -> Result<PrincipalAuthenticatorLink, StorageError> {
    let fields = snapshot_fields(row)?;
    validate_snapshot_boundary(&fields, tenant, &lookup)?;
    let data = decode_snapshot_data(fields, tenant)?;
    PrincipalAuthenticatorLink::rehydrate(PrincipalAuthenticatorSnapshot::new(data))
        .map_err(|_| integrity_failure())
}

fn decode_snapshot_data(
    fields: SnapshotFields<'_>,
    tenant: &TenantId,
) -> Result<PrincipalAuthenticatorSnapshotData, StorageError> {
    let identity = decode_snapshot_identity(&fields)?;
    let lifecycle = decode_snapshot_lifecycle(&fields)?;
    Ok(PrincipalAuthenticatorSnapshotData {
        tenant_id: tenant.clone(),
        authenticator_id: identity.authenticator_id,
        authenticator_kind: identity.authenticator_kind,
        source_id: identity.source_id,
        principal_id: identity.principal_id,
        principal_binding_version: identity.principal_binding_version,
        version: lifecycle.version,
        state: lifecycle.state,
        linked_at: UtcTimestamp::from_unix_seconds(fields.linked_at),
        revoked_at: lifecycle.revoked_at,
    })
}

struct SnapshotIdentity {
    authenticator_id: PrincipalAuthenticatorId,
    authenticator_kind: PrincipalAuthenticatorKind,
    source_id: PrincipalAuthenticatorSourceId,
    principal_id: PrincipalId,
    principal_binding_version: PrincipalBindingVersion,
}

fn decode_snapshot_identity(fields: &SnapshotFields<'_>) -> Result<SnapshotIdentity, StorageError> {
    Ok(SnapshotIdentity {
        authenticator_id: PrincipalAuthenticatorId::parse(fields.authenticator)
            .map_err(|_| integrity_failure())?,
        authenticator_kind: decode_kind(fields.kind)?,
        source_id: PrincipalAuthenticatorSourceId::parse(fields.source)
            .map_err(|_| integrity_failure())?,
        principal_id: PrincipalId::parse(fields.principal).map_err(|_| integrity_failure())?,
        principal_binding_version: decode_binding_version(fields.binding_version)?,
    })
}

struct SnapshotLifecycle {
    version: PrincipalAuthenticatorVersion,
    state: PrincipalAuthenticatorState,
    revoked_at: Option<UtcTimestamp>,
}

fn decode_snapshot_lifecycle(
    fields: &SnapshotFields<'_>,
) -> Result<SnapshotLifecycle, StorageError> {
    Ok(SnapshotLifecycle {
        version: decode_version(fields.version)?,
        state: decode_state(fields.state)?,
        revoked_at: decode_optional_timestamp(fields.revoked_at)?,
    })
}

struct SnapshotFields<'a> {
    tenant: &'a str,
    authenticator: &'a str,
    kind: &'a str,
    source: &'a str,
    principal: &'a str,
    binding_version: &'a str,
    version: &'a str,
    state: &'a str,
    linked_at: i64,
    revoked_at: &'a SqlValue,
}

fn snapshot_fields(row: &Row) -> Result<SnapshotFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(authenticator),
        SqlValue::Text(kind),
        SqlValue::Text(source),
        SqlValue::Text(principal),
        SqlValue::Text(binding_version),
        SqlValue::Text(version),
        SqlValue::Text(state),
        SqlValue::Int64(linked_at),
        revoked_at,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(SnapshotFields {
        tenant,
        authenticator,
        kind,
        source,
        principal,
        binding_version,
        version,
        state,
        linked_at: *linked_at,
        revoked_at,
    })
}

fn validate_snapshot_boundary(
    fields: &SnapshotFields<'_>,
    tenant: &TenantId,
    lookup: &SnapshotLookup<'_>,
) -> Result<(), StorageError> {
    if fields.tenant != tenant.as_str() {
        return Err(integrity_failure());
    }
    let valid = match lookup {
        SnapshotLookup::Id(authenticator) => fields.authenticator == authenticator.as_str(),
        SnapshotLookup::Source(kind, source) => {
            fields.kind == kind.as_str() && fields.source == source.as_str()
        }
    };
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn load_and_verify_events(
    session: &mut LocalSession,
    link: &PrincipalAuthenticatorLink,
) -> Result<Vec<PersistedPrincipalAuthenticatorEvent>, StorageError> {
    let output = sql::load_events(session, link.tenant_id(), link.authenticator_id())?;
    let batch = rows(output)?;
    validate_columns(batch.columns(), &event_columns())?;
    validate_event_count(batch.rows(), link)?;
    let events = decode_event_rows(batch.rows(), link)?;
    validate_history_times(link, &events)?;
    Ok(events)
}

fn validate_event_count(
    rows: &[Row],
    link: &PrincipalAuthenticatorLink,
) -> Result<(), StorageError> {
    let expected = usize::try_from(link.version().get()).map_err(|_| integrity_failure())?;
    let valid = rows.len() == expected && (1..=2).contains(&expected);
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn decode_event_rows(
    rows: &[Row],
    link: &PrincipalAuthenticatorLink,
) -> Result<Vec<PersistedPrincipalAuthenticatorEvent>, StorageError> {
    rows.iter()
        .enumerate()
        .map(|(index, row)| decode_event(row, link, index))
        .collect()
}

fn decode_event(
    row: &Row,
    link: &PrincipalAuthenticatorLink,
    index: usize,
) -> Result<PersistedPrincipalAuthenticatorEvent, StorageError> {
    let fields = event_fields(row)?;
    let version = decode_expected_event_version(fields.version, index)?;
    let event = rehydrate_event(fields, version)?;
    validate_event_matrix(index, &event, link)?;
    Ok(PersistedPrincipalAuthenticatorEvent(event))
}

fn rehydrate_event(
    fields: EventFields<'_>,
    version: PrincipalAuthenticatorVersion,
) -> Result<PrincipalAuthenticatorEvent, StorageError> {
    let identity = decode_event_identity(&fields)?;
    let context = decode_event_context(&fields)?;
    PrincipalAuthenticatorEvent::rehydrate(PrincipalAuthenticatorEventData {
        tenant_id: identity.tenant_id,
        authenticator_id: identity.authenticator_id,
        authenticator_kind: identity.authenticator_kind,
        source_commitment: identity.source_commitment,
        principal_id: identity.principal_id,
        principal_binding_version: identity.principal_binding_version,
        version,
        kind: context.kind,
        occurred_at: UtcTimestamp::from_unix_seconds(fields.occurred_at),
        actor: context.actor,
        request_id: context.request_id,
    })
    .map_err(|_| integrity_failure())
}

struct EventIdentity {
    tenant_id: TenantId,
    authenticator_id: PrincipalAuthenticatorId,
    authenticator_kind: PrincipalAuthenticatorKind,
    source_commitment: PrincipalAuthenticatorSourceCommitment,
    principal_id: PrincipalId,
    principal_binding_version: PrincipalBindingVersion,
}

fn decode_event_identity(fields: &EventFields<'_>) -> Result<EventIdentity, StorageError> {
    Ok(EventIdentity {
        tenant_id: TenantId::parse(fields.tenant).map_err(|_| integrity_failure())?,
        authenticator_id: PrincipalAuthenticatorId::parse(fields.authenticator)
            .map_err(|_| integrity_failure())?,
        authenticator_kind: decode_kind(fields.authenticator_kind)?,
        source_commitment: PrincipalAuthenticatorSourceCommitment::from_bytes(decode_fixed_hex(
            fields.commitment,
        )?),
        principal_id: PrincipalId::parse(fields.principal).map_err(|_| integrity_failure())?,
        principal_binding_version: decode_binding_version(fields.binding_version)?,
    })
}

struct EventContext {
    kind: PrincipalAuthenticatorEventKind,
    actor: PrincipalId,
    request_id: RequestId,
}

fn decode_event_context(fields: &EventFields<'_>) -> Result<EventContext, StorageError> {
    Ok(EventContext {
        kind: decode_event_kind(fields.kind)?,
        actor: PrincipalId::parse(fields.actor).map_err(|_| integrity_failure())?,
        request_id: RequestId::parse(fields.request).map_err(|_| integrity_failure())?,
    })
}

struct EventFields<'a> {
    tenant: &'a str,
    authenticator: &'a str,
    authenticator_kind: &'a str,
    commitment: &'a str,
    principal: &'a str,
    binding_version: &'a str,
    version: &'a str,
    kind: &'a str,
    occurred_at: i64,
    actor: &'a str,
    request: &'a str,
}

fn event_fields(row: &Row) -> Result<EventFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(authenticator),
        SqlValue::Text(authenticator_kind),
        SqlValue::Text(commitment),
        SqlValue::Text(principal),
        SqlValue::Text(binding_version),
        SqlValue::Text(version),
        SqlValue::Text(kind),
        SqlValue::Int64(occurred_at),
        SqlValue::Text(actor),
        SqlValue::Text(request),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(EventFields {
        tenant,
        authenticator,
        authenticator_kind,
        commitment,
        principal,
        binding_version,
        version,
        kind,
        occurred_at: *occurred_at,
        actor,
        request,
    })
}

fn decode_expected_event_version(
    value: &str,
    index: usize,
) -> Result<PrincipalAuthenticatorVersion, StorageError> {
    let version = decode_version(value)?;
    let expected = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(integrity_failure)?;
    (version.get() == expected)
        .then_some(version)
        .ok_or_else(integrity_failure)
}

fn validate_event_matrix(
    index: usize,
    event: &PrincipalAuthenticatorEvent,
    link: &PrincipalAuthenticatorLink,
) -> Result<(), StorageError> {
    let expected_kind = expected_event_kind(index)?;
    let valid = event_aggregate_identity_matches(event, link)
        && event_principal_identity_matches(event, link)
        && event.kind() == expected_kind;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn expected_event_kind(index: usize) -> Result<PrincipalAuthenticatorEventKind, StorageError> {
    match index {
        0 => Ok(PrincipalAuthenticatorEventKind::Linked),
        1 => Ok(PrincipalAuthenticatorEventKind::Revoked),
        _ => Err(integrity_failure()),
    }
}

fn event_aggregate_identity_matches(
    event: &PrincipalAuthenticatorEvent,
    link: &PrincipalAuthenticatorLink,
) -> bool {
    event.tenant_id() == link.tenant_id()
        && event.authenticator_id() == link.authenticator_id()
        && event.authenticator_kind() == link.kind()
}

fn event_principal_identity_matches(
    event: &PrincipalAuthenticatorEvent,
    link: &PrincipalAuthenticatorLink,
) -> bool {
    event.principal_id() == link.principal_id()
        && event.principal_binding_version() == link.principal_binding_version()
        && event.source_commitment()
            == &PrincipalAuthenticatorSourceCommitment::derive(
                link.tenant_id(),
                link.kind(),
                link.source_id(),
            )
}

fn validate_history_times(
    link: &PrincipalAuthenticatorLink,
    events: &[PersistedPrincipalAuthenticatorEvent],
) -> Result<(), StorageError> {
    let linked = events
        .first()
        .is_some_and(|event| event.event().occurred_at() == link.linked_at());
    let revoked = optional_event_time(events.get(1), link.revoked_at());
    (linked && revoked)
        .then_some(())
        .ok_or_else(integrity_failure)
}

fn optional_event_time(
    event: Option<&PersistedPrincipalAuthenticatorEvent>,
    timestamp: Option<UtcTimestamp>,
) -> bool {
    match (event, timestamp) {
        (Some(event), Some(timestamp)) => event.event().occurred_at() == timestamp,
        (None, None) => true,
        _ => false,
    }
}

fn decode_version(value: &str) -> Result<PrincipalAuthenticatorVersion, StorageError> {
    let parsed = decode_canonical_u64(value)?;
    PrincipalAuthenticatorVersion::new(parsed).map_err(|_| integrity_failure())
}

fn decode_binding_version(value: &str) -> Result<PrincipalBindingVersion, StorageError> {
    let parsed = decode_canonical_u64(value)?;
    PrincipalBindingVersion::new(parsed).map_err(|_| integrity_failure())
}

fn decode_canonical_u64(value: &str) -> Result<u64, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let parsed = value.parse::<u64>().map_err(|_| integrity_failure())?;
    if format!("{parsed:020}") != value {
        return Err(integrity_failure());
    }
    Ok(parsed)
}

fn decode_kind(value: &str) -> Result<PrincipalAuthenticatorKind, StorageError> {
    PrincipalAuthenticatorKind::parse(value).map_err(|_| integrity_failure())
}

fn decode_state(value: &str) -> Result<PrincipalAuthenticatorState, StorageError> {
    match value {
        "active" => Ok(PrincipalAuthenticatorState::Active),
        "revoked" => Ok(PrincipalAuthenticatorState::Revoked),
        _ => Err(integrity_failure()),
    }
}

fn decode_event_kind(value: &str) -> Result<PrincipalAuthenticatorEventKind, StorageError> {
    match value {
        "linked" => Ok(PrincipalAuthenticatorEventKind::Linked),
        "revoked" => Ok(PrincipalAuthenticatorEventKind::Revoked),
        _ => Err(integrity_failure()),
    }
}

fn decode_optional_timestamp(value: &SqlValue) -> Result<Option<UtcTimestamp>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Int64(value) => Ok(Some(UtcTimestamp::from_unix_seconds(*value))),
        _ => Err(integrity_failure()),
    }
}

fn decode_fixed_hex(value: &str) -> Result<[u8; 32], StorageError> {
    if value.len() != COMMITMENT_TEXT_BYTES {
        return Err(integrity_failure());
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
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
    let valid = columns.len() == expected.len()
        && columns.iter().zip(expected).all(|(column, expected)| {
            column.name() == expected.0 && column.data_type() == &expected.1
        });
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn snapshot_columns() -> [(&'static str, SqlType); 10] {
    [
        ("tenant_id", SqlType::Text),
        ("authenticator_id", SqlType::Text),
        ("authenticator_kind", SqlType::Text),
        ("source_id", SqlType::Text),
        ("principal_id", SqlType::Text),
        ("principal_binding_version", SqlType::Text),
        ("version", SqlType::Text),
        ("state", SqlType::Text),
        ("linked_at", SqlType::Int64),
        ("revoked_at", SqlType::Int64),
    ]
}

fn event_columns() -> [(&'static str, SqlType); 11] {
    [
        ("tenant_id", SqlType::Text),
        ("authenticator_id", SqlType::Text),
        ("authenticator_kind", SqlType::Text),
        ("source_commitment_hex", SqlType::Text),
        ("principal_id", SqlType::Text),
        ("principal_binding_version", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
        ("request_id", SqlType::Text),
    ]
}

// crates/optional/ariadnion-storage-rnmdb/src/principal_binding_repository/decode.rs - Rust source for Ariadnion.
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
//! Strict bounded decoding for principal-binding snapshots and history.

use ariadnion_core::{PrincipalContext, PrincipalId, RequestId, TenantId};
use ariadnion_organization::{MembershipId, OrganizationId};
use ariadnion_principal_binding::{
    PrincipalBinding, PrincipalBindingEvent, PrincipalBindingEventData, PrincipalBindingEventKind,
    PrincipalBindingIdentity, PrincipalBindingSnapshot, PrincipalBindingSnapshotData,
    PrincipalBindingState, PrincipalBindingTransition, PrincipalBindingVersion, SubjectCommitment,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use super::{integrity_failure, sql};

const VERSION_TEXT_BYTES: usize = 20;
const COMMITMENT_TEXT_BYTES: usize = 64;

pub(super) struct LoadedPrincipalBinding {
    pub(super) binding: PrincipalBinding,
    pub(super) events: Vec<PersistedPrincipalBindingEvent>,
}

pub(super) struct PersistedPrincipalBindingEvent(PrincipalBindingEvent);

impl PersistedPrincipalBindingEvent {
    pub(super) const fn event(&self) -> &PrincipalBindingEvent {
        &self.0
    }

    pub(super) fn matches_transition(&self, transition: &PrincipalBindingTransition) -> bool {
        &self.0 == transition.event()
    }
}

pub(super) fn load_binding(
    session: &mut LocalSession,
    tenant: &TenantId,
    principal: &PrincipalId,
) -> Result<PrincipalBinding, StorageError> {
    load_binding_with_history(session, tenant, principal).map(|loaded| loaded.binding)
}

pub(super) fn load_binding_with_history(
    session: &mut LocalSession,
    tenant: &TenantId,
    principal: &PrincipalId,
) -> Result<LoadedPrincipalBinding, StorageError> {
    let snapshot = rows(sql::load_snapshot(session, tenant, principal)?)?;
    let binding = decode_snapshot(one_snapshot_row(&snapshot)?, tenant, principal)?;
    let events = load_and_verify_events(session, &binding)?;
    Ok(LoadedPrincipalBinding { binding, events })
}

pub(super) fn ensure_creation_absent(
    session: &mut LocalSession,
    tenant: &TenantId,
    principal: &PrincipalId,
) -> Result<(), StorageError> {
    match load_binding_with_history(session, tenant, principal) {
        Err(error) if error.code() == StorageErrorCode::NotFound => Ok(()),
        Ok(_) => Err(StorageError::new(StorageErrorCode::Conflict)),
        Err(error) => Err(error),
    }
}

pub(super) fn classify_creation_insert_error(
    session: &mut LocalSession,
    tenant: &TenantId,
    principal: &PrincipalId,
    original: StorageError,
) -> StorageError {
    match load_binding_with_history(session, tenant, principal) {
        Ok(_) => StorageError::new(StorageErrorCode::Conflict),
        Err(error) if error.code() == StorageErrorCode::NotFound => original,
        Err(error) => error,
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
    principal: &PrincipalId,
) -> Result<PrincipalBinding, StorageError> {
    let fields = snapshot_fields(row)?;
    validate_snapshot_boundary(fields.tenant, fields.principal, tenant, principal)?;
    let data = decode_snapshot_data(fields, tenant, principal)?;
    PrincipalBinding::rehydrate(PrincipalBindingSnapshot::new(data))
        .map_err(|_| integrity_failure())
}

fn decode_snapshot_data(
    fields: SnapshotFields<'_>,
    tenant: &TenantId,
    principal: &PrincipalId,
) -> Result<PrincipalBindingSnapshotData, StorageError> {
    Ok(PrincipalBindingSnapshotData {
        tenant_id: tenant.clone(),
        principal_id: principal.clone(),
        subject_commitment: SubjectCommitment::from_bytes(decode_fixed_hex(fields.commitment)?),
        version: decode_version(fields.version)?,
        state: decode_state(fields.state)?,
        identity: decode_identity(fields.identity, tenant, principal)?,
        provisioned_at: UtcTimestamp::from_unix_seconds(fields.provisioned_at),
        revoked_at: decode_optional_timestamp(fields.revoked_at)?,
        erased_at: decode_optional_timestamp(fields.erased_at)?,
    })
}

struct SnapshotFields<'a> {
    tenant: &'a str,
    principal: &'a str,
    identity: [&'a SqlValue; 3],
    commitment: &'a str,
    version: &'a str,
    state: &'a str,
    provisioned_at: i64,
    revoked_at: &'a SqlValue,
    erased_at: &'a SqlValue,
}

fn snapshot_fields(row: &Row) -> Result<SnapshotFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(principal),
        user,
        organization,
        membership,
        SqlValue::Text(commitment),
        SqlValue::Text(version),
        SqlValue::Text(state),
        SqlValue::Int64(provisioned_at),
        revoked_at,
        erased_at,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(SnapshotFields {
        tenant,
        principal,
        identity: [user, organization, membership],
        commitment,
        version,
        state,
        provisioned_at: *provisioned_at,
        revoked_at,
        erased_at,
    })
}

fn decode_identity(
    values: [&SqlValue; 3],
    tenant: &TenantId,
    principal: &PrincipalId,
) -> Result<Option<PrincipalBindingIdentity>, StorageError> {
    match values {
        [SqlValue::Null, SqlValue::Null, SqlValue::Null] => Ok(None),
        [
            SqlValue::Text(user),
            SqlValue::Text(organization),
            SqlValue::Text(membership),
        ] => {
            let identity = PrincipalBindingIdentity::new(
                tenant,
                principal,
                PrincipalContext::new(tenant.clone(), principal.clone()),
                UserId::parse(user).map_err(|_| integrity_failure())?,
                OrganizationId::parse(organization).map_err(|_| integrity_failure())?,
                MembershipId::parse(membership).map_err(|_| integrity_failure())?,
            )
            .map_err(|_| integrity_failure())?;
            Ok(Some(identity))
        }
        _ => Err(integrity_failure()),
    }
}

fn load_and_verify_events(
    session: &mut LocalSession,
    binding: &PrincipalBinding,
) -> Result<Vec<PersistedPrincipalBindingEvent>, StorageError> {
    let output = sql::load_events(session, binding.tenant_id(), binding.principal_id())?;
    let batch = rows(output)?;
    validate_columns(batch.columns(), &event_columns())?;
    validate_event_count(batch.rows(), binding)?;
    let events = decode_event_rows(batch.rows(), binding)?;
    validate_history_times(binding, &events)?;
    Ok(events)
}

fn validate_event_count(rows: &[Row], binding: &PrincipalBinding) -> Result<(), StorageError> {
    let expected = usize::try_from(binding.version().get()).map_err(|_| integrity_failure())?;
    let valid = rows.len() == expected && (1..=3).contains(&expected);
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn decode_event_rows(
    rows: &[Row],
    binding: &PrincipalBinding,
) -> Result<Vec<PersistedPrincipalBindingEvent>, StorageError> {
    rows.iter()
        .enumerate()
        .map(|(index, row)| decode_event(row, binding, index))
        .collect()
}

fn decode_event(
    row: &Row,
    binding: &PrincipalBinding,
    index: usize,
) -> Result<PersistedPrincipalBindingEvent, StorageError> {
    let fields = event_fields(row)?;
    validate_event_boundary(&fields, binding)?;
    let event = rehydrate_event(fields, binding, index)?;
    validate_event_matrix(index, &event, binding)?;
    Ok(PersistedPrincipalBindingEvent(event))
}

fn rehydrate_event(
    fields: EventFields<'_>,
    binding: &PrincipalBinding,
    index: usize,
) -> Result<PrincipalBindingEvent, StorageError> {
    let version = decode_expected_event_version(fields.version, index)?;
    let data = decode_event_data(fields, binding, version)?;
    PrincipalBindingEvent::rehydrate(data).map_err(|_| integrity_failure())
}

fn decode_expected_event_version(
    value: &str,
    index: usize,
) -> Result<PrincipalBindingVersion, StorageError> {
    let version = decode_version(value)?;
    let expected_version = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(integrity_failure)?;
    if version.get() != expected_version {
        return Err(integrity_failure());
    }
    Ok(version)
}

fn decode_event_data(
    fields: EventFields<'_>,
    binding: &PrincipalBinding,
    version: PrincipalBindingVersion,
) -> Result<PrincipalBindingEventData, StorageError> {
    Ok(PrincipalBindingEventData {
        tenant_id: binding.tenant_id().clone(),
        principal_id: binding.principal_id().clone(),
        version,
        kind: decode_event_kind(fields.kind)?,
        occurred_at: UtcTimestamp::from_unix_seconds(fields.occurred_at),
        actor: PrincipalId::parse(fields.actor).map_err(|_| integrity_failure())?,
        request_id: RequestId::parse(fields.request).map_err(|_| integrity_failure())?,
        subject_commitment: SubjectCommitment::from_bytes(decode_fixed_hex(fields.commitment)?),
    })
}

struct EventFields<'a> {
    tenant: &'a str,
    principal: &'a str,
    version: &'a str,
    kind: &'a str,
    occurred_at: i64,
    actor: &'a str,
    request: &'a str,
    commitment: &'a str,
}

fn event_fields(row: &Row) -> Result<EventFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(principal),
        SqlValue::Text(version),
        SqlValue::Text(kind),
        SqlValue::Int64(occurred_at),
        SqlValue::Text(actor),
        SqlValue::Text(request),
        SqlValue::Text(commitment),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(EventFields {
        tenant,
        principal,
        version,
        kind,
        occurred_at: *occurred_at,
        actor,
        request,
        commitment,
    })
}

fn validate_event_boundary(
    fields: &EventFields<'_>,
    binding: &PrincipalBinding,
) -> Result<(), StorageError> {
    let valid = fields.tenant == binding.tenant_id().as_str()
        && fields.principal == binding.principal_id().as_str()
        && fields.commitment == sql::encode_commitment(binding.subject_commitment());
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_event_matrix(
    index: usize,
    event: &PrincipalBindingEvent,
    binding: &PrincipalBinding,
) -> Result<(), StorageError> {
    let expected = expected_event_kind(index)?;
    let valid = event.kind() == expected && event_identity_matches(event, binding);
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn expected_event_kind(index: usize) -> Result<PrincipalBindingEventKind, StorageError> {
    match index {
        0 => Ok(PrincipalBindingEventKind::Provisioned),
        1 => Ok(PrincipalBindingEventKind::Revoked),
        2 => Ok(PrincipalBindingEventKind::Erased),
        _ => Err(integrity_failure()),
    }
}

fn event_identity_matches(event: &PrincipalBindingEvent, binding: &PrincipalBinding) -> bool {
    event.tenant_id() == binding.tenant_id()
        && event.principal_id() == binding.principal_id()
        && event.subject_commitment() == binding.subject_commitment()
}

fn validate_history_times(
    binding: &PrincipalBinding,
    events: &[PersistedPrincipalBindingEvent],
) -> Result<(), StorageError> {
    let provisioned = events
        .first()
        .is_some_and(|event| event.event().occurred_at() == binding.provisioned_at());
    let revoked = optional_event_time(events.get(1), binding.revoked_at());
    let erased = optional_event_time(events.get(2), binding.erased_at());
    (provisioned && revoked && erased)
        .then_some(())
        .ok_or_else(integrity_failure)
}

fn optional_event_time(
    event: Option<&PersistedPrincipalBindingEvent>,
    timestamp: Option<UtcTimestamp>,
) -> bool {
    match (event, timestamp) {
        (Some(event), Some(timestamp)) => event.event().occurred_at() == timestamp,
        (None, None) => true,
        _ => false,
    }
}

fn validate_snapshot_boundary(
    found_tenant: &str,
    found_principal: &str,
    tenant: &TenantId,
    principal: &PrincipalId,
) -> Result<(), StorageError> {
    let valid = found_tenant == tenant.as_str() && found_principal == principal.as_str();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn decode_version(value: &str) -> Result<PrincipalBindingVersion, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let version = PrincipalBindingVersion::new(value.parse().map_err(|_| integrity_failure())?)
        .map_err(|_| integrity_failure())?;
    if sql::encode_version(version) != value {
        return Err(integrity_failure());
    }
    Ok(version)
}

fn decode_state(value: &str) -> Result<PrincipalBindingState, StorageError> {
    match value {
        "active" => Ok(PrincipalBindingState::Active),
        "revoked" => Ok(PrincipalBindingState::Revoked),
        "erased" => Ok(PrincipalBindingState::Erased),
        _ => Err(integrity_failure()),
    }
}

fn decode_event_kind(value: &str) -> Result<PrincipalBindingEventKind, StorageError> {
    match value {
        "provisioned" => Ok(PrincipalBindingEventKind::Provisioned),
        "revoked" => Ok(PrincipalBindingEventKind::Revoked),
        "erased" => Ok(PrincipalBindingEventKind::Erased),
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

fn snapshot_columns() -> [(&'static str, SqlType); 11] {
    [
        ("tenant_id", SqlType::Text),
        ("principal_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("membership_id", SqlType::Text),
        ("subject_commitment_hex", SqlType::Text),
        ("version", SqlType::Text),
        ("state", SqlType::Text),
        ("provisioned_at", SqlType::Int64),
        ("revoked_at", SqlType::Int64),
        ("erased_at", SqlType::Int64),
    ]
}

fn event_columns() -> [(&'static str, SqlType); 8] {
    [
        ("tenant_id", SqlType::Text),
        ("principal_id", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
        ("request_id", SqlType::Text),
        ("subject_commitment_hex", SqlType::Text),
    ]
}

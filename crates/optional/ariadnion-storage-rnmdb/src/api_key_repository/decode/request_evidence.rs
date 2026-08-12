// crates/optional/ariadnion-storage-rnmdb/src/api_key_repository/decode/request_evidence.rs - Rust source for Ariadnion.
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
//! Strict request-history decoding and bounded API-key transition replay.

use ariadnion_auth_api_key::{
    ApiKey, ApiKeyAction, ApiKeyCommand, ApiKeyEventKind, ApiKeyId, ApiKeyIssueBinding,
    ApiKeyIssueRequest, ApiKeyRotation, ApiKeyTransition, ApiKeyValidityWindow, ApiKeyVersion,
    issue_api_key, transition_api_key_owned,
};
use ariadnion_core::{RequestId, TenantId};
use ariadnion_storage_domain::StorageError;
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;
use rnmdb_types::{SqlType, SqlValue};

use super::{PersistedEvent, integrity_failure, sql};
use crate::api_key_repository::MAX_API_KEY_EVENT_ROWS;

pub(in crate::api_key_repository) struct PersistedApiKeyTransition {
    expected_previous_version: ApiKeyVersion,
    transition: ApiKeyTransition,
    request_id: RequestId,
}

impl PersistedApiKeyTransition {
    pub(in crate::api_key_repository) const fn expected_previous_version(&self) -> ApiKeyVersion {
        self.expected_previous_version
    }

    pub(in crate::api_key_repository) const fn transition(&self) -> &ApiKeyTransition {
        &self.transition
    }

    pub(in crate::api_key_repository) const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
}

pub(in crate::api_key_repository) fn visit_transition_history(
    session: &mut LocalSession,
    durable: &ApiKey,
    mut visitor: impl FnMut(&mut LocalSession, &PersistedApiKeyTransition) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let events = super::load_events(session, durable)?;
    super::verify_event_history(&events, durable)?;
    let requests = load_request_history(session, durable, events.len())?;
    replay_transition_history(session, durable, &events, &requests, &mut visitor)
}

fn load_request_history(
    session: &mut LocalSession,
    durable: &ApiKey,
    expected: usize,
) -> Result<Vec<RequestEvidence>, StorageError> {
    let batch = super::rows(sql::load_request_evidence(
        session,
        durable.tenant_id(),
        durable.id(),
    )?)?;
    super::validate_columns(batch.columns(), request_evidence_columns())?;
    decode_request_rows(batch.rows(), durable, expected)
}

struct RequestEvidence {
    request_id: RequestId,
}

struct RequestFields<'a> {
    tenant: &'a str,
    key: &'a str,
    version: &'a str,
    request_id: &'a str,
}

struct ParsedRequestFields {
    tenant: TenantId,
    key: ApiKeyId,
    version: ApiKeyVersion,
    request_id: RequestId,
}

fn decode_request_rows(
    rows: &[Row],
    durable: &ApiKey,
    expected: usize,
) -> Result<Vec<RequestEvidence>, StorageError> {
    validate_request_cardinality(rows, expected)?;
    let mut requests = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let version = expected_request_version(index)?;
        requests.push(decode_request_row(row, durable, version)?);
    }
    Ok(requests)
}

fn validate_request_cardinality(rows: &[Row], expected: usize) -> Result<(), StorageError> {
    let valid = !rows.is_empty() && rows.len() == expected && rows.len() <= MAX_API_KEY_EVENT_ROWS;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn expected_request_version(index: usize) -> Result<ApiKeyVersion, StorageError> {
    let ordinal = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(integrity_failure)?;
    ApiKeyVersion::new(ordinal).map_err(|_| integrity_failure())
}

fn decode_request_row(
    row: &Row,
    durable: &ApiKey,
    expected_version: ApiKeyVersion,
) -> Result<RequestEvidence, StorageError> {
    let fields = extract_request_fields(row)?;
    let fields = parse_request_fields(fields)?;
    validate_request_boundary(&fields, durable, expected_version)?;
    Ok(RequestEvidence {
        request_id: fields.request_id,
    })
}

fn extract_request_fields(row: &Row) -> Result<RequestFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(key),
        SqlValue::Text(version),
        SqlValue::Text(request_id),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(RequestFields {
        tenant,
        key,
        version,
        request_id,
    })
}

fn parse_request_fields(fields: RequestFields<'_>) -> Result<ParsedRequestFields, StorageError> {
    Ok(ParsedRequestFields {
        tenant: TenantId::parse(fields.tenant).map_err(|_| integrity_failure())?,
        key: ApiKeyId::parse(fields.key).map_err(|_| integrity_failure())?,
        version: super::parse_version(fields.version)?,
        request_id: RequestId::parse(fields.request_id).map_err(|_| integrity_failure())?,
    })
}

fn validate_request_boundary(
    fields: &ParsedRequestFields,
    durable: &ApiKey,
    expected_version: ApiKeyVersion,
) -> Result<(), StorageError> {
    let valid = fields.tenant == *durable.tenant_id()
        && fields.key == *durable.id()
        && fields.version == expected_version;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn request_evidence_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("api_key_id", SqlType::Text),
        ("version", SqlType::Text),
        ("request_id", SqlType::Text),
    ]
}

fn replay_transition_history(
    session: &mut LocalSession,
    durable: &ApiKey,
    events: &[PersistedEvent],
    requests: &[RequestEvidence],
    visitor: &mut impl FnMut(&mut LocalSession, &PersistedApiKeyTransition) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let issuance = replay_initial_transition(durable, events, requests)?;
    let mut current = visit_transition(session, issuance, visitor)?;
    for index in 1..events.len() {
        let transition = replay_next_transition(durable, events, requests, index, current)?;
        current = visit_transition(session, transition, visitor)?;
    }
    let valid = current == *durable && requests.len() == events.len();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn replay_initial_transition(
    durable: &ApiKey,
    events: &[PersistedEvent],
    requests: &[RequestEvidence],
) -> Result<PersistedApiKeyTransition, StorageError> {
    let event = events.first().ok_or_else(integrity_failure)?;
    let request = requests.first().ok_or_else(integrity_failure)?;
    Ok(PersistedApiKeyTransition {
        expected_previous_version: ApiKeyVersion::initial(),
        transition: replay_issuance(durable, event)?,
        request_id: request.request_id.clone(),
    })
}

fn replay_next_transition(
    durable: &ApiKey,
    events: &[PersistedEvent],
    requests: &[RequestEvidence],
    index: usize,
    current: ApiKey,
) -> Result<PersistedApiKeyTransition, StorageError> {
    let expected_previous_version = current.version();
    let transition = replay_later_transition(durable, events, index, current)?;
    Ok(PersistedApiKeyTransition {
        expected_previous_version,
        transition,
        request_id: request_at(requests, index)?.request_id.clone(),
    })
}

fn visit_transition(
    session: &mut LocalSession,
    persisted: PersistedApiKeyTransition,
    visitor: &mut impl FnMut(&mut LocalSession, &PersistedApiKeyTransition) -> Result<(), StorageError>,
) -> Result<ApiKey, StorageError> {
    visitor(session, &persisted)?;
    Ok(persisted.transition.into_key())
}

fn request_at(
    requests: &[RequestEvidence],
    index: usize,
) -> Result<&RequestEvidence, StorageError> {
    requests.get(index).ok_or_else(integrity_failure)
}

fn replay_issuance(
    durable: &ApiKey,
    event: &PersistedEvent,
) -> Result<ApiKeyTransition, StorageError> {
    let request = ApiKeyIssueRequest::new(
        ApiKeyIssueBinding::new(
            durable.id().clone(),
            durable.owner().clone(),
            event.actor.clone(),
            durable.prefix().clone(),
        ),
        event.current_secret,
        durable.scopes().to_vec(),
        ApiKeyValidityWindow::new(durable.issued_at(), durable.expires_at()),
    )
    .map_err(|_| integrity_failure())?;
    let transition = issue_api_key(request).map_err(|_| integrity_failure())?;
    validate_replayed_snapshot(durable, event, transition)
}

fn replay_later_transition(
    durable: &ApiKey,
    events: &[PersistedEvent],
    index: usize,
    previous: ApiKey,
) -> Result<ApiKeyTransition, StorageError> {
    let event = events.get(index).ok_or_else(integrity_failure)?;
    let transition = replay_event(previous, event)?;
    validate_replayed_snapshot(durable, event, transition)
}

fn validate_replayed_snapshot(
    durable: &ApiKey,
    event: &PersistedEvent,
    transition: ApiKeyTransition,
) -> Result<ApiKeyTransition, StorageError> {
    let valid = replayed_immutable_fields_match(transition.key(), durable)
        && replayed_event_fields_match(transition.key(), event);
    valid.then_some(transition).ok_or_else(integrity_failure)
}

fn replayed_immutable_fields_match(replayed: &ApiKey, durable: &ApiKey) -> bool {
    replayed.id() == durable.id()
        && replayed.owner() == durable.owner()
        && replayed.prefix() == durable.prefix()
        && replayed.scopes() == durable.scopes()
        && replayed.issued_at() == durable.issued_at()
        && replayed.expires_at() == durable.expires_at()
}

fn replayed_event_fields_match(replayed: &ApiKey, event: &PersistedEvent) -> bool {
    replayed.current_secret() == event.current_secret
        && replayed.previous_secret() == event.previous_secret
        && replayed.rotation_started_at() == event.rotation_started_at
        && replayed.previous_secret_expires_at() == event.previous_secret_expires_at
        && replayed.version() == event.version
        && replayed.state() == event.state
}

fn replay_event(
    previous: ApiKey,
    event: &PersistedEvent,
) -> Result<ApiKeyTransition, StorageError> {
    let action = replay_action(&previous, event)?;
    let version = previous.version();
    transition_api_key_owned(
        previous,
        ApiKeyCommand::new(version, event.actor.clone(), event.occurred_at, action),
    )
    .map_err(|_| integrity_failure())
}

fn replay_action(previous: &ApiKey, event: &PersistedEvent) -> Result<ApiKeyAction, StorageError> {
    match event.kind {
        ApiKeyEventKind::Rotated => Ok(ApiKeyAction::Rotate(ApiKeyRotation::new(
            previous.id().clone(),
            previous.owner().clone(),
            event.current_secret,
            event
                .previous_secret_expires_at
                .ok_or_else(integrity_failure)?,
        ))),
        ApiKeyEventKind::RotationCompleted => Ok(ApiKeyAction::CompleteRotation),
        ApiKeyEventKind::Revoked => Ok(ApiKeyAction::Revoke {
            owner: previous.owner().clone(),
        }),
        ApiKeyEventKind::Expired => Ok(ApiKeyAction::Expire {
            owner: previous.owner().clone(),
        }),
        ApiKeyEventKind::Issued => Err(integrity_failure()),
    }
}

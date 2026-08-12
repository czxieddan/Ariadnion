// crates/optional/ariadnion-storage-rnmdb/src/session_repository/decode.rs - Rust source for Ariadnion.
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
//! Strict bounded decoding for browser session-family snapshots.

use ariadnion_auth_session::{
    MAX_ROTATED_SESSIONS, SessionEventKind, SessionFamily, SessionFamilyId, SessionFamilySnapshot,
    SessionFamilyState, SessionFamilyVersion, SessionId, SessionSnapshot, SessionState,
    SessionSubject, SessionTokenDigest, SessionTransition, SessionVersion,
};
use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use super::{CommitRequest, integrity_failure, sql};

const VERSION_TEXT_BYTES: usize = 20;
const DIGEST_TEXT_BYTES: usize = 64;

pub(super) fn load_family(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<SessionFamily, StorageError> {
    load_family_with_history(session, tenant, user, family).map(|loaded| loaded.family)
}

pub(super) struct LoadedSessionFamily {
    pub(super) family: SessionFamily,
    pub(super) events: Vec<PersistedSessionEvent>,
}

pub(super) fn load_family_with_history(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<LoadedSessionFamily, StorageError> {
    let decoded = decode_family(session, tenant, user, family)?;
    let events = load_events(session, &decoded)?;
    Ok(LoadedSessionFamily {
        family: decoded,
        events,
    })
}

fn decode_family(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<SessionFamily, StorageError> {
    let fields = load_family_fields(session, tenant, user, family)?;
    let leaves = decode_leaves(session, tenant, user, family)?;
    let snapshot = assemble_snapshot(fields, leaves)?;
    SessionFamily::from_snapshot(snapshot).map_err(|_| integrity_failure())
}

fn load_family_fields(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<FamilyFields, StorageError> {
    let family_batch = rows(sql::load_family(session, tenant, user, family)?)?;
    let fields = decode_family_row(one_row(&family_batch, family_columns())?, tenant, user)?;
    if fields.family_id != *family {
        return Err(integrity_failure());
    }
    Ok(fields)
}

pub(super) fn load_family_by_token(
    session: &mut LocalSession,
    tenant: &TenantId,
    digest: SessionTokenDigest,
) -> Result<SessionFamily, StorageError> {
    let batch = rows(sql::load_token_owners(session, tenant, digest)?)?;
    let owner = decode_token_owner(one_row(&batch, token_owner_columns())?, digest)?;
    let family = load_family(session, tenant, &owner.user_id, &owner.family_id)?;
    if family_contains(&family, &owner.session_id, digest) {
        Ok(family)
    } else {
        Err(integrity_failure())
    }
}

pub(super) fn ensure_issuance_absent(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    ensure_family_absent(session, request)?;
    ensure_digest_absent(session, request)
}

fn ensure_family_absent(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let output =
        sql::load_family_owner(session, request.tenant_id, request.transition.family().id())?;
    let batch = rows(output)?;
    validate_columns(batch.columns(), family_owner_columns())?;
    match batch.rows() {
        [] => Ok(()),
        [_] => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

fn ensure_digest_absent(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let digest = request.transition.family().current().token_digest();
    let batch = rows(sql::load_token_owners(session, request.tenant_id, digest)?)?;
    validate_columns(batch.columns(), token_owner_columns())?;
    match batch.rows() {
        [] => Ok(()),
        [_] => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

struct FamilyFields {
    family_id: SessionFamilyId,
    current_session_id: SessionId,
    issued_at: UtcTimestamp,
    absolute_expires_at: UtcTimestamp,
    version: SessionFamilyVersion,
    state: SessionFamilyState,
    subject: SessionSubject,
}

fn decode_family_row(
    row: &Row,
    tenant: &TenantId,
    user: &UserId,
) -> Result<FamilyFields, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_user),
        SqlValue::Text(family_id),
        SqlValue::Text(current_session_id),
        SqlValue::Int64(issued_at),
        SqlValue::Int64(absolute_expires_at),
        SqlValue::Text(version),
        SqlValue::Text(state),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_boundary(found_tenant, found_user, tenant, user)?;
    Ok(FamilyFields {
        family_id: parse_family_id(family_id)?,
        current_session_id: parse_session_id(current_session_id)?,
        issued_at: UtcTimestamp::from_unix_seconds(*issued_at),
        absolute_expires_at: UtcTimestamp::from_unix_seconds(*absolute_expires_at),
        version: parse_family_version(version)?,
        state: parse_family_state(state)?,
        subject: SessionSubject::new(tenant.clone(), user.clone()),
    })
}

fn decode_leaves(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<Vec<SessionSnapshot>, StorageError> {
    let batch = rows(sql::load_leaves(session, tenant, user, family)?)?;
    validate_columns(batch.columns(), leaf_columns())?;
    if batch.rows().is_empty() || batch.rows().len() > MAX_ROTATED_SESSIONS + 1 {
        return Err(integrity_failure());
    }
    batch
        .rows()
        .iter()
        .enumerate()
        .map(|(ordinal, row)| decode_leaf(row, tenant, user, family, ordinal))
        .collect()
}

fn decode_leaf(
    row: &Row,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
    ordinal: usize,
) -> Result<SessionSnapshot, StorageError> {
    let fields = leaf_fields(row)?;
    validate_leaf_boundary(
        fields.tenant,
        fields.user,
        fields.family,
        tenant,
        user,
        family,
    )?;
    validate_ordinal(fields.ordinal, ordinal)?;
    decode_leaf_fields(fields, tenant, user, family)
}

struct LeafFields<'a> {
    tenant: &'a str,
    user: &'a str,
    family: &'a str,
    session_id: &'a str,
    ordinal: i64,
    predecessor: &'a SqlValue,
    token_digest: &'a str,
    issued_at: i64,
    last_seen_at: i64,
    idle_expires_at: i64,
    version: &'a str,
    state: &'a str,
}

fn leaf_fields(row: &Row) -> Result<LeafFields<'_>, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_user),
        SqlValue::Text(found_family),
        SqlValue::Text(session_id),
        SqlValue::Int64(found_ordinal),
        predecessor,
        SqlValue::Text(token_digest),
        SqlValue::Int64(issued_at),
        SqlValue::Int64(last_seen_at),
        SqlValue::Int64(idle_expires_at),
        SqlValue::Text(version),
        SqlValue::Text(state),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(LeafFields {
        tenant: found_tenant,
        user: found_user,
        family: found_family,
        session_id,
        ordinal: *found_ordinal,
        predecessor,
        token_digest,
        issued_at: *issued_at,
        last_seen_at: *last_seen_at,
        idle_expires_at: *idle_expires_at,
        version,
        state,
    })
}

fn decode_leaf_fields(
    fields: LeafFields<'_>,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<SessionSnapshot, StorageError> {
    let id = parse_session_id(fields.session_id)?;
    let token_digest = SessionTokenDigest::new(decode_digest(fields.token_digest)?);
    let issued_at = UtcTimestamp::from_unix_seconds(fields.issued_at);
    let last_seen_at = UtcTimestamp::from_unix_seconds(fields.last_seen_at);
    let idle_expires_at = UtcTimestamp::from_unix_seconds(fields.idle_expires_at);
    let version = parse_session_version(fields.version)?;
    let state = parse_session_state(fields.state)?;
    let predecessor_id = parse_optional_session_id(fields.predecessor)?;
    Ok(SessionSnapshot {
        family_id: family.clone(),
        subject: SessionSubject::new(tenant.clone(), user.clone()),
        id,
        token_digest,
        issued_at,
        last_seen_at,
        idle_expires_at,
        version,
        state,
        predecessor_id,
    })
}

fn assemble_snapshot(
    fields: FamilyFields,
    mut leaves: Vec<SessionSnapshot>,
) -> Result<SessionFamilySnapshot, StorageError> {
    let current = leaves.pop().ok_or_else(integrity_failure)?;
    if current.id != fields.current_session_id {
        return Err(integrity_failure());
    }
    Ok(SessionFamilySnapshot {
        id: fields.family_id,
        subject: fields.subject,
        issued_at: fields.issued_at,
        absolute_expires_at: fields.absolute_expires_at,
        version: fields.version,
        state: fields.state,
        current,
        rotated: leaves,
    })
}

fn load_events(
    session: &mut LocalSession,
    family: &SessionFamily,
) -> Result<Vec<PersistedSessionEvent>, StorageError> {
    let batch = rows(sql::load_events(
        session,
        family.tenant_id(),
        family.user_id(),
        family.id(),
    )?)?;
    validate_columns(batch.columns(), event_columns())?;
    let events = decode_events(batch.rows())?;
    verify_event_history(family, &events)?;
    Ok(events)
}

fn decode_events(rows: &[Row]) -> Result<Vec<PersistedSessionEvent>, StorageError> {
    if rows.is_empty() || rows.len() > MAX_ROTATED_SESSIONS + 2 {
        return Err(integrity_failure());
    }
    rows.iter().map(decode_session_event).collect()
}

fn verify_event_history(
    family: &SessionFamily,
    events: &[PersistedSessionEvent],
) -> Result<(), StorageError> {
    let expected = usize::try_from(family.version().get()).map_err(|_| integrity_failure())?;
    if events.len() != expected {
        return Err(integrity_failure());
    }
    verify_issuance_event(family, &events[0])?;
    verify_rotation_events(family, events)?;
    verify_terminal_event(family, events)
}

fn verify_issuance_event(
    family: &SessionFamily,
    event: &PersistedSessionEvent,
) -> Result<(), StorageError> {
    let first = family.rotated().first().unwrap_or_else(|| family.current());
    let valid = event.matches_boundary(family)
        && event.session_id == *first.id()
        && event.version == SessionFamilyVersion::initial()
        && event.kind == SessionEventKind::Issued
        && event.occurred_at == family.issued_at();
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_rotation_events(
    family: &SessionFamily,
    events: &[PersistedSessionEvent],
) -> Result<(), StorageError> {
    let leaves: Vec<_> = family
        .rotated()
        .iter()
        .chain(std::iter::once(family.current()))
        .collect();
    for (index, successor) in leaves.iter().enumerate().skip(1) {
        verify_rotation_event(family, &events[index], successor, index)?;
    }
    Ok(())
}

fn verify_rotation_event(
    family: &SessionFamily,
    event: &PersistedSessionEvent,
    successor: &ariadnion_auth_session::Session,
    index: usize,
) -> Result<(), StorageError> {
    let version = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .and_then(|value| SessionFamilyVersion::new(value).ok())
        .ok_or_else(integrity_failure)?;
    let valid = event.matches_boundary(family)
        && event.session_id == *successor.id()
        && event.version == version
        && event.kind == SessionEventKind::Rotated
        && event.occurred_at == successor.issued_at();
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_terminal_event(
    family: &SessionFamily,
    events: &[PersistedSessionEvent],
) -> Result<(), StorageError> {
    if family.state() == SessionFamilyState::Active {
        return Ok(());
    }
    let index = family.rotated().len() + 1;
    let event = events.get(index).ok_or_else(integrity_failure)?;
    if terminal_event_matches(family, event) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn terminal_event_matches(family: &SessionFamily, event: &PersistedSessionEvent) -> bool {
    event.matches_boundary(family)
        && event.session_id == *family.current().id()
        && event.version == family.version()
        && terminal_kind_matches(family, event.kind)
        && terminal_time_matches(family, event)
}

fn terminal_kind_matches(family: &SessionFamily, kind: SessionEventKind) -> bool {
    match family.state() {
        SessionFamilyState::Active => false,
        SessionFamilyState::Revoked => match kind {
            SessionEventKind::ReuseRevoked => !family.rotated().is_empty(),
            SessionEventKind::Revoked => true,
            _ => false,
        },
        SessionFamilyState::Expired => kind == SessionEventKind::Expired,
    }
}

fn terminal_time_matches(family: &SessionFamily, event: &PersistedSessionEvent) -> bool {
    match event.kind {
        SessionEventKind::ReuseRevoked | SessionEventKind::Revoked => {
            event.occurred_at >= family.current().last_seen_at()
        }
        SessionEventKind::Expired => {
            event.occurred_at >= family.absolute_expires_at()
                || event.occurred_at >= family.current().idle_expires_at()
        }
        SessionEventKind::Issued | SessionEventKind::Rotated => false,
    }
}

#[derive(Clone)]
pub(super) struct PersistedSessionEvent {
    tenant: String,
    user: String,
    family_id: SessionFamilyId,
    session_id: SessionId,
    version: SessionFamilyVersion,
    kind: SessionEventKind,
    occurred_at: UtcTimestamp,
    actor: PrincipalId,
}

impl PersistedSessionEvent {
    fn matches_boundary(&self, family: &SessionFamily) -> bool {
        (self.tenant.as_str(), self.user.as_str(), &self.family_id)
            == (
                family.tenant_id().as_str(),
                family.user_id().as_str(),
                family.id(),
            )
    }

    pub(super) fn kind(&self) -> SessionEventKind {
        self.kind
    }

    pub(super) fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub(super) fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub(super) fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    pub(super) fn matches_transition(&self, transition: &SessionTransition) -> bool {
        let event = transition.event();
        (
            self.family_id.as_str(),
            self.session_id.as_str(),
            self.version,
            self.kind,
            self.occurred_at,
            self.actor.as_str(),
        ) == (
            event.family_id().as_str(),
            event.session_id().as_str(),
            event.version(),
            event.kind(),
            event.occurred_at(),
            event.actor().as_str(),
        )
    }
}

fn decode_session_event(row: &Row) -> Result<PersistedSessionEvent, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(user),
        SqlValue::Text(family_id),
        SqlValue::Text(session_id),
        SqlValue::Text(version),
        SqlValue::Text(kind),
        SqlValue::Int64(occurred_at),
        SqlValue::Text(actor),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(PersistedSessionEvent {
        tenant: tenant.clone(),
        user: user.clone(),
        family_id: parse_family_id(family_id)?,
        session_id: parse_session_id(session_id)?,
        version: parse_family_version(version)?,
        kind: parse_event_kind(kind)?,
        occurred_at: UtcTimestamp::from_unix_seconds(*occurred_at),
        actor: PrincipalId::parse(actor).map_err(|_| integrity_failure())?,
    })
}

pub(super) fn family_at_version(
    durable: &SessionFamily,
    version: SessionFamilyVersion,
) -> Result<SessionFamily, StorageError> {
    if version == durable.version() {
        return Ok(durable.clone());
    }
    historical_active_family(durable, version)
}

fn historical_active_family(
    durable: &SessionFamily,
    version: SessionFamilyVersion,
) -> Result<SessionFamily, StorageError> {
    let snapshot = durable.snapshot_state();
    let leaves = ordered_leaf_snapshots(&snapshot);
    let current_index = version_index(version)?;
    let current = leaves
        .get(current_index)
        .ok_or_else(integrity_failure)
        .and_then(|leaf| historical_leaf(leaf, SessionState::Active))?;
    let rotated = leaves[..current_index]
        .iter()
        .map(|leaf| historical_leaf(leaf, SessionState::Rotated))
        .collect::<Result<Vec<_>, _>>()?;
    SessionFamily::from_snapshot(SessionFamilySnapshot {
        id: snapshot.id,
        subject: snapshot.subject,
        issued_at: snapshot.issued_at,
        absolute_expires_at: snapshot.absolute_expires_at,
        version,
        state: SessionFamilyState::Active,
        current,
        rotated,
    })
    .map_err(|_| integrity_failure())
}

fn ordered_leaf_snapshots(snapshot: &SessionFamilySnapshot) -> Vec<&SessionSnapshot> {
    snapshot
        .rotated
        .iter()
        .chain(std::iter::once(&snapshot.current))
        .collect()
}

fn version_index(version: SessionFamilyVersion) -> Result<usize, StorageError> {
    version
        .get()
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(integrity_failure)
}

fn historical_leaf(
    source: &SessionSnapshot,
    state: SessionState,
) -> Result<SessionSnapshot, StorageError> {
    let version = match state {
        SessionState::Active => Ok(SessionVersion::initial()),
        SessionState::Rotated => SessionVersion::new(2).map_err(|_| integrity_failure()),
        SessionState::Revoked | SessionState::Expired => Err(integrity_failure()),
    };
    Ok(SessionSnapshot {
        family_id: source.family_id.clone(),
        subject: source.subject.clone(),
        id: source.id.clone(),
        token_digest: source.token_digest,
        issued_at: source.issued_at,
        last_seen_at: source.last_seen_at,
        idle_expires_at: source.idle_expires_at,
        version: version?,
        state,
        predecessor_id: source.predecessor_id.clone(),
    })
}

fn parse_event_kind(value: &str) -> Result<SessionEventKind, StorageError> {
    match value {
        "issued" => Ok(SessionEventKind::Issued),
        "rotated" => Ok(SessionEventKind::Rotated),
        "reuse_revoked" => Ok(SessionEventKind::ReuseRevoked),
        "revoked" => Ok(SessionEventKind::Revoked),
        "expired" => Ok(SessionEventKind::Expired),
        _ => Err(integrity_failure()),
    }
}

struct TokenOwner {
    user_id: UserId,
    family_id: SessionFamilyId,
    session_id: SessionId,
}

fn decode_token_owner(row: &Row, expected: SessionTokenDigest) -> Result<TokenOwner, StorageError> {
    let fields = token_owner_fields(row)?;
    validate_token_digest(fields.digest, expected)?;
    Ok(TokenOwner {
        user_id: UserId::parse(fields.user).map_err(|_| integrity_failure())?,
        family_id: parse_family_id(fields.family)?,
        session_id: parse_session_id(fields.session)?,
    })
}

struct TokenOwnerFields<'a> {
    user: &'a str,
    family: &'a str,
    session: &'a str,
    digest: &'a str,
}

fn token_owner_fields(row: &Row) -> Result<TokenOwnerFields<'_>, StorageError> {
    let [
        SqlValue::Text(user),
        SqlValue::Text(family),
        SqlValue::Text(session),
        SqlValue::Text(digest),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(TokenOwnerFields {
        user,
        family,
        session,
        digest,
    })
}

fn validate_token_digest(digest: &str, expected: SessionTokenDigest) -> Result<(), StorageError> {
    if decode_digest(digest)? != expected.bytes() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn family_contains(
    family: &SessionFamily,
    session: &SessionId,
    digest: SessionTokenDigest,
) -> bool {
    std::iter::once(family.current())
        .chain(family.rotated())
        .any(|leaf| leaf.id() == session && leaf.token_digest() == digest)
}

fn validate_boundary(
    found_tenant: &str,
    found_user: &str,
    tenant: &TenantId,
    user: &UserId,
) -> Result<(), StorageError> {
    if found_tenant == tenant.as_str() && found_user == user.as_str() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_leaf_boundary(
    found_tenant: &str,
    found_user: &str,
    found_family: &str,
    tenant: &TenantId,
    user: &UserId,
    family: &SessionFamilyId,
) -> Result<(), StorageError> {
    validate_boundary(found_tenant, found_user, tenant, user)?;
    if found_family == family.as_str() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_ordinal(found: i64, expected: usize) -> Result<(), StorageError> {
    if usize::try_from(found).is_ok_and(|value| value == expected) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn one_row<'a>(
    batch: &'a VectorBatch,
    expected: &[(&str, SqlType)],
) -> Result<&'a Row, StorageError> {
    validate_columns(batch.columns(), expected)?;
    match batch.rows() {
        [] => Err(StorageError::new(StorageErrorCode::NotFound)),
        [row] => Ok(row),
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
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn parse_family_id(value: &str) -> Result<SessionFamilyId, StorageError> {
    SessionFamilyId::parse(value).map_err(|_| integrity_failure())
}

fn parse_session_id(value: &str) -> Result<SessionId, StorageError> {
    SessionId::parse(value).map_err(|_| integrity_failure())
}

fn parse_optional_session_id(value: &SqlValue) -> Result<Option<SessionId>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(value) => parse_session_id(value).map(Some),
        _ => Err(integrity_failure()),
    }
}

fn parse_family_version(value: &str) -> Result<SessionFamilyVersion, StorageError> {
    let value = parse_version(value)?;
    SessionFamilyVersion::new(value).map_err(|_| integrity_failure())
}

fn parse_session_version(value: &str) -> Result<SessionVersion, StorageError> {
    let value = parse_version(value)?;
    SessionVersion::new(value).map_err(|_| integrity_failure())
}

fn parse_version(value: &str) -> Result<u64, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    value.parse().map_err(|_| integrity_failure())
}

fn decode_digest(value: &str) -> Result<[u8; 32], StorageError> {
    if value.len() != DIGEST_TEXT_BYTES {
        return Err(integrity_failure());
    }
    let mut output = [0_u8; 32];
    for (target, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *target = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
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

fn parse_family_state(value: &str) -> Result<SessionFamilyState, StorageError> {
    match value {
        "active" => Ok(SessionFamilyState::Active),
        "revoked" => Ok(SessionFamilyState::Revoked),
        "expired" => Ok(SessionFamilyState::Expired),
        _ => Err(integrity_failure()),
    }
}

fn parse_session_state(value: &str) -> Result<SessionState, StorageError> {
    match value {
        "active" => Ok(SessionState::Active),
        "rotated" => Ok(SessionState::Rotated),
        "revoked" => Ok(SessionState::Revoked),
        "expired" => Ok(SessionState::Expired),
        _ => Err(integrity_failure()),
    }
}

fn family_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("family_id", SqlType::Text),
        ("current_session_id", SqlType::Text),
        ("issued_at", SqlType::Int64),
        ("absolute_expires_at", SqlType::Int64),
        ("version", SqlType::Text),
        ("state", SqlType::Text),
    ]
}

fn leaf_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("family_id", SqlType::Text),
        ("session_id", SqlType::Text),
        ("ordinal", SqlType::Int64),
        ("predecessor_session_id", SqlType::Text),
        ("token_digest_hex", SqlType::Text),
        ("issued_at", SqlType::Int64),
        ("last_seen_at", SqlType::Int64),
        ("idle_expires_at", SqlType::Int64),
        ("version", SqlType::Text),
        ("state", SqlType::Text),
    ]
}

fn event_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("family_id", SqlType::Text),
        ("session_id", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
    ]
}

fn token_owner_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("user_id", SqlType::Text),
        ("family_id", SqlType::Text),
        ("session_id", SqlType::Text),
        ("token_digest_hex", SqlType::Text),
    ]
}

fn family_owner_columns() -> &'static [(&'static str, SqlType)] {
    &[("user_id", SqlType::Text), ("family_id", SqlType::Text)]
}

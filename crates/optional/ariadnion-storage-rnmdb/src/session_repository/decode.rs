//! Strict bounded decoding for browser session-family snapshots.

use ariadnion_auth_session::{
    MAX_ROTATED_SESSIONS, SessionFamily, SessionFamilyId, SessionFamilySnapshot,
    SessionFamilyState, SessionFamilyVersion, SessionId, SessionSnapshot, SessionState,
    SessionSubject, SessionTokenDigest, SessionVersion,
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
    let decoded = decode_family(session, tenant, user, family)?;
    verify_events(session, &decoded)?;
    Ok(decoded)
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
    validate_leaf_boundary(found_tenant, found_user, found_family, tenant, user, family)?;
    validate_ordinal(*found_ordinal, ordinal)?;
    Ok(SessionSnapshot {
        family_id: family.clone(),
        subject: SessionSubject::new(tenant.clone(), user.clone()),
        id: parse_session_id(session_id)?,
        token_digest: SessionTokenDigest::new(decode_digest(token_digest)?),
        issued_at: UtcTimestamp::from_unix_seconds(*issued_at),
        last_seen_at: UtcTimestamp::from_unix_seconds(*last_seen_at),
        idle_expires_at: UtcTimestamp::from_unix_seconds(*idle_expires_at),
        version: parse_session_version(version)?,
        state: parse_session_state(state)?,
        predecessor_id: parse_optional_session_id(predecessor)?,
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

fn verify_events(session: &mut LocalSession, family: &SessionFamily) -> Result<(), StorageError> {
    let batch = rows(sql::load_events(
        session,
        family.tenant_id(),
        family.user_id(),
        family.id(),
    )?)?;
    validate_columns(batch.columns(), event_columns())?;
    let [row] = batch.rows() else {
        return Err(integrity_failure());
    };
    verify_issuance_event(row, family)
}

fn verify_issuance_event(row: &Row, family: &SessionFamily) -> Result<(), StorageError> {
    let event = decode_issuance_event(row)?;
    if event.matches(family) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

struct PersistedIssuanceEvent {
    tenant: String,
    user: String,
    family_id: SessionFamilyId,
    session_id: SessionId,
    version: SessionFamilyVersion,
    kind: String,
    occurred_at: UtcTimestamp,
    _actor: PrincipalId,
}

impl PersistedIssuanceEvent {
    fn matches(&self, family: &SessionFamily) -> bool {
        (
            self.tenant.as_str(),
            self.user.as_str(),
            &self.family_id,
            &self.session_id,
            self.version,
            self.kind.as_str(),
            self.occurred_at,
        ) == (
            family.tenant_id().as_str(),
            family.user_id().as_str(),
            family.id(),
            family.current().id(),
            family.version(),
            "issued",
            family.issued_at(),
        )
    }
}

fn decode_issuance_event(row: &Row) -> Result<PersistedIssuanceEvent, StorageError> {
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
    Ok(PersistedIssuanceEvent {
        tenant: tenant.clone(),
        user: user.clone(),
        family_id: parse_family_id(family_id)?,
        session_id: parse_session_id(session_id)?,
        version: parse_family_version(version)?,
        kind: kind.clone(),
        occurred_at: UtcTimestamp::from_unix_seconds(*occurred_at),
        _actor: PrincipalId::parse(actor).map_err(|_| integrity_failure())?,
    })
}

struct TokenOwner {
    user_id: UserId,
    family_id: SessionFamilyId,
    session_id: SessionId,
}

fn decode_token_owner(row: &Row, expected: SessionTokenDigest) -> Result<TokenOwner, StorageError> {
    let [
        SqlValue::Text(user),
        SqlValue::Text(family),
        SqlValue::Text(session),
        SqlValue::Text(digest),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    if decode_digest(digest)? != expected.bytes() {
        return Err(integrity_failure());
    }
    Ok(TokenOwner {
        user_id: UserId::parse(user).map_err(|_| integrity_failure())?,
        family_id: parse_family_id(family)?,
        session_id: parse_session_id(session)?,
    })
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

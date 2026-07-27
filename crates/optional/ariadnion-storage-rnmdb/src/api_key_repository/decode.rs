//! Strict bounded decoding for durable scoped API keys.

use ariadnion_auth_api_key::{
    ApiKey, ApiKeyEventKind, ApiKeyId, ApiKeyOwner, ApiKeyPrefix, ApiKeyScope, ApiKeySecretDigest,
    ApiKeySnapshot, ApiKeyState, ApiKeyVersion, MAX_API_KEY_SCOPES, MAX_RETIRED_SECRETS,
};
use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use super::{CommitRequest, MAX_API_KEY_EVENT_ROWS, integrity_failure, sql};

const VERSION_TEXT_BYTES: usize = 20;
const DIGEST_TEXT_BYTES: usize = 64;

pub(super) fn load_key(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    key: &ApiKeyId,
) -> Result<ApiKey, StorageError> {
    let batch = rows(sql::load_key(session, tenant, user, key)?)?;
    let fields = decode_key_row(one_row(&batch, key_columns())?, tenant, Some(user))?;
    if fields.id != *key {
        return Err(integrity_failure());
    }
    assemble_key(session, fields)
}

pub(super) fn load_key_by_id(
    session: &mut LocalSession,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<ApiKey, StorageError> {
    let batch = rows(sql::load_key_by_id(session, tenant, key)?)?;
    let fields = decode_key_row(one_row(&batch, key_columns())?, tenant, None)?;
    if fields.id != *key {
        return Err(integrity_failure());
    }
    assemble_key(session, fields)
}

pub(super) fn load_key_by_prefix(
    session: &mut LocalSession,
    tenant: &TenantId,
    prefix: &ApiKeyPrefix,
) -> Result<ApiKey, StorageError> {
    let batch = rows(sql::load_key_by_prefix(session, tenant, prefix)?)?;
    let fields = decode_key_row(one_row(&batch, key_columns())?, tenant, None)?;
    if fields.prefix != *prefix {
        return Err(integrity_failure());
    }
    assemble_key(session, fields)
}

fn assemble_key(session: &mut LocalSession, fields: KeyFields) -> Result<ApiKey, StorageError> {
    let scopes = decode_scopes(session, &fields.owner, &fields.id)?;
    let retired = decode_retired(session, fields.owner.tenant_id(), &fields.id)?;
    let snapshot = fields.snapshot(scopes, retired);
    let key = ApiKey::from_snapshot(snapshot).map_err(|_| integrity_failure())?;
    verify_events(session, &key)?;
    Ok(key)
}

struct KeyFields {
    id: ApiKeyId,
    owner: ApiKeyOwner,
    prefix: ApiKeyPrefix,
    current_secret: ApiKeySecretDigest,
    previous_secret: Option<ApiKeySecretDigest>,
    rotation_started_at: Option<UtcTimestamp>,
    previous_secret_expires_at: Option<UtcTimestamp>,
    issued_at: UtcTimestamp,
    expires_at: Option<UtcTimestamp>,
    version: ApiKeyVersion,
    state: ApiKeyState,
}

impl KeyFields {
    fn snapshot(
        self,
        scopes: Vec<ApiKeyScope>,
        retired_secrets: Vec<ApiKeySecretDigest>,
    ) -> ApiKeySnapshot {
        ApiKeySnapshot {
            id: self.id,
            owner: self.owner,
            prefix: self.prefix,
            current_secret: self.current_secret,
            previous_secret: self.previous_secret,
            rotation_started_at: self.rotation_started_at,
            previous_secret_expires_at: self.previous_secret_expires_at,
            retired_secrets,
            scopes,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            version: self.version,
            state: self.state,
        }
    }
}

fn decode_key_row(
    row: &Row,
    tenant: &TenantId,
    expected_user: Option<&UserId>,
) -> Result<KeyFields, StorageError> {
    let values = row.values();
    require_value_count(values, 12)?;
    let identity = decode_key_identity(values, tenant, expected_user)?;
    let secrets = decode_key_secrets(values)?;
    let timing = decode_key_timing(values)?;
    let lifecycle = decode_key_lifecycle(values)?;
    Ok(KeyFields {
        id: identity.id,
        owner: identity.owner,
        prefix: identity.prefix,
        current_secret: secrets.current,
        previous_secret: secrets.previous,
        rotation_started_at: timing.rotation_started_at,
        previous_secret_expires_at: timing.previous_secret_expires_at,
        issued_at: timing.issued_at,
        expires_at: timing.expires_at,
        version: lifecycle.version,
        state: lifecycle.state,
    })
}

struct KeyIdentity {
    id: ApiKeyId,
    owner: ApiKeyOwner,
    prefix: ApiKeyPrefix,
}

fn decode_key_identity(
    values: &[SqlValue],
    tenant: &TenantId,
    expected_user: Option<&UserId>,
) -> Result<KeyIdentity, StorageError> {
    let owner = decode_key_owner(values, tenant, expected_user)?;
    let id = parse_key_id(text_at(values, 2)?)?;
    let prefix = ApiKeyPrefix::parse(text_at(values, 3)?).map_err(|_| integrity_failure())?;
    Ok(KeyIdentity { id, owner, prefix })
}

fn decode_key_owner(
    values: &[SqlValue],
    tenant: &TenantId,
    expected_user: Option<&UserId>,
) -> Result<ApiKeyOwner, StorageError> {
    let found_tenant = text_at(values, 0)?;
    let found_user = text_at(values, 1)?;
    validate_key_boundary(found_tenant, found_user, tenant, expected_user)?;
    Ok(ApiKeyOwner::new(tenant.clone(), parse_user(found_user)?))
}

struct KeySecrets {
    current: ApiKeySecretDigest,
    previous: Option<ApiKeySecretDigest>,
}

fn decode_key_secrets(values: &[SqlValue]) -> Result<KeySecrets, StorageError> {
    Ok(KeySecrets {
        current: parse_digest_value(text_at(values, 4)?)?,
        previous: parse_optional_digest(value_at(values, 5)?)?,
    })
}

struct KeyTiming {
    rotation_started_at: Option<UtcTimestamp>,
    previous_secret_expires_at: Option<UtcTimestamp>,
    issued_at: UtcTimestamp,
    expires_at: Option<UtcTimestamp>,
}

fn decode_key_timing(values: &[SqlValue]) -> Result<KeyTiming, StorageError> {
    Ok(KeyTiming {
        rotation_started_at: parse_optional_time(value_at(values, 6)?)?,
        previous_secret_expires_at: parse_optional_time(value_at(values, 7)?)?,
        issued_at: UtcTimestamp::from_unix_seconds(int_at(values, 8)?),
        expires_at: parse_optional_time(value_at(values, 9)?)?,
    })
}

struct KeyLifecycle {
    version: ApiKeyVersion,
    state: ApiKeyState,
}

fn decode_key_lifecycle(values: &[SqlValue]) -> Result<KeyLifecycle, StorageError> {
    Ok(KeyLifecycle {
        version: parse_version(text_at(values, 10)?)?,
        state: parse_state(text_at(values, 11)?)?,
    })
}

fn decode_scopes(
    session: &mut LocalSession,
    owner: &ApiKeyOwner,
    key: &ApiKeyId,
) -> Result<Vec<ApiKeyScope>, StorageError> {
    let batch = rows(sql::load_scopes(session, owner.tenant_id(), key)?)?;
    validate_columns(batch.columns(), scope_columns())?;
    validate_scope_count(batch.rows().len())?;
    let scopes = batch
        .rows()
        .iter()
        .map(|row| decode_scope(row, owner.tenant_id(), key))
        .collect::<Result<Vec<_>, _>>()?;
    validate_normalized_scopes(&scopes)?;
    Ok(scopes)
}

fn validate_scope_count(count: usize) -> Result<(), StorageError> {
    let valid = count > 0 && count <= MAX_API_KEY_SCOPES;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn decode_scope(row: &Row, tenant: &TenantId, key: &ApiKeyId) -> Result<ApiKeyScope, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_key),
        SqlValue::Text(scope),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_companion_boundary(found_tenant, found_key, tenant, key)?;
    ApiKeyScope::parse(scope).map_err(|_| integrity_failure())
}

fn validate_normalized_scopes(scopes: &[ApiKeyScope]) -> Result<(), StorageError> {
    if scopes.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn decode_retired(
    session: &mut LocalSession,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<Vec<ApiKeySecretDigest>, StorageError> {
    let batch = rows(sql::load_retired(session, tenant, key)?)?;
    validate_columns(batch.columns(), retired_columns())?;
    if batch.rows().len() > MAX_RETIRED_SECRETS {
        return Err(integrity_failure());
    }
    batch
        .rows()
        .iter()
        .enumerate()
        .map(|(ordinal, row)| decode_retired_row(row, tenant, key, ordinal))
        .collect()
}

fn decode_retired_row(
    row: &Row,
    tenant: &TenantId,
    key: &ApiKeyId,
    expected_ordinal: usize,
) -> Result<ApiKeySecretDigest, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_key),
        SqlValue::Int64(ordinal),
        SqlValue::Text(digest),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_companion_boundary(found_tenant, found_key, tenant, key)?;
    validate_ordinal(*ordinal, expected_ordinal)?;
    parse_digest_value(digest)
}

fn verify_events(session: &mut LocalSession, key: &ApiKey) -> Result<(), StorageError> {
    let events = load_events(session, key)?;
    verify_event_history(&events, key)
}

fn load_events(
    session: &mut LocalSession,
    key: &ApiKey,
) -> Result<Vec<PersistedEvent>, StorageError> {
    let batch = rows(sql::load_events(session, key.tenant_id(), key.id())?)?;
    validate_columns(batch.columns(), event_columns())?;
    decode_events(batch.rows(), key)
}

fn verify_event_history(events: &[PersistedEvent], key: &ApiKey) -> Result<(), StorageError> {
    verify_first_event(events, key)?;
    verify_contiguous_events(events, key)?;
    verify_retired_history(events, key)?;
    verify_final_event(events.last().ok_or_else(integrity_failure)?, key)
}

pub(super) fn verify_target_event(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
) -> Result<(), StorageError> {
    let target = request.transition.key();
    let events = load_events(session, durable)?;
    let index = target
        .version()
        .get()
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(integrity_failure)?;
    let persisted = events.get(index).ok_or_else(integrity_failure)?;
    persisted
        .matches_transition(request)
        .then_some(())
        .ok_or_else(integrity_failure)?;
    verify_retired_history(&events[..=index], target)
}

fn verify_first_event(events: &[PersistedEvent], key: &ApiKey) -> Result<(), StorageError> {
    let first = events.first().ok_or_else(integrity_failure)?;
    verify_issuance_event(first, key)
}

fn decode_events(rows: &[Row], key: &ApiKey) -> Result<Vec<PersistedEvent>, StorageError> {
    let expected = usize::try_from(key.version().get()).map_err(|_| integrity_failure())?;
    if rows.is_empty() || rows.len() != expected || rows.len() > MAX_API_KEY_EVENT_ROWS {
        return Err(integrity_failure());
    }
    rows.iter().map(decode_event).collect()
}

struct PersistedEvent {
    tenant: TenantId,
    key: ApiKeyId,
    user: UserId,
    version: ApiKeyVersion,
    kind: ApiKeyEventKind,
    occurred_at: UtcTimestamp,
    actor: PrincipalId,
    state: ApiKeyState,
    current_secret: ApiKeySecretDigest,
    previous_secret: Option<ApiKeySecretDigest>,
    rotation_started_at: Option<UtcTimestamp>,
    previous_secret_expires_at: Option<UtcTimestamp>,
}

fn decode_event(row: &Row) -> Result<PersistedEvent, StorageError> {
    let values = row.values();
    require_value_count(values, 12)?;
    let boundary = decode_event_boundary(values)?;
    let transition = decode_event_transition(values)?;
    let snapshot = decode_event_snapshot(values)?;
    Ok(PersistedEvent {
        tenant: boundary.tenant,
        key: boundary.key,
        user: boundary.user,
        version: transition.version,
        kind: transition.kind,
        occurred_at: transition.occurred_at,
        actor: transition.actor,
        state: snapshot.state,
        current_secret: snapshot.current_secret,
        previous_secret: snapshot.previous_secret,
        rotation_started_at: snapshot.rotation_started_at,
        previous_secret_expires_at: snapshot.previous_secret_expires_at,
    })
}

struct EventBoundary {
    tenant: TenantId,
    key: ApiKeyId,
    user: UserId,
}

fn decode_event_boundary(values: &[SqlValue]) -> Result<EventBoundary, StorageError> {
    Ok(EventBoundary {
        tenant: TenantId::parse(text_at(values, 0)?).map_err(|_| integrity_failure())?,
        key: parse_key_id(text_at(values, 1)?)?,
        user: parse_user(text_at(values, 2)?)?,
    })
}

struct EventTransition {
    version: ApiKeyVersion,
    kind: ApiKeyEventKind,
    occurred_at: UtcTimestamp,
    actor: PrincipalId,
}

fn decode_event_transition(values: &[SqlValue]) -> Result<EventTransition, StorageError> {
    Ok(EventTransition {
        version: parse_version(text_at(values, 3)?)?,
        kind: parse_event_kind(text_at(values, 4)?)?,
        occurred_at: UtcTimestamp::from_unix_seconds(int_at(values, 5)?),
        actor: PrincipalId::parse(text_at(values, 6)?).map_err(|_| integrity_failure())?,
    })
}

struct EventSnapshot {
    state: ApiKeyState,
    current_secret: ApiKeySecretDigest,
    previous_secret: Option<ApiKeySecretDigest>,
    rotation_started_at: Option<UtcTimestamp>,
    previous_secret_expires_at: Option<UtcTimestamp>,
}

fn decode_event_snapshot(values: &[SqlValue]) -> Result<EventSnapshot, StorageError> {
    let core = decode_event_snapshot_core(values)?;
    let overlap = decode_event_overlap(values)?;
    Ok(EventSnapshot {
        state: core.state,
        current_secret: core.current_secret,
        previous_secret: overlap.previous_secret,
        rotation_started_at: overlap.rotation_started_at,
        previous_secret_expires_at: overlap.previous_secret_expires_at,
    })
}

struct EventSnapshotCore {
    state: ApiKeyState,
    current_secret: ApiKeySecretDigest,
}

fn decode_event_snapshot_core(values: &[SqlValue]) -> Result<EventSnapshotCore, StorageError> {
    Ok(EventSnapshotCore {
        state: parse_state(text_at(values, 7)?)?,
        current_secret: parse_digest_value(text_at(values, 8)?)?,
    })
}

struct EventOverlap {
    previous_secret: Option<ApiKeySecretDigest>,
    rotation_started_at: Option<UtcTimestamp>,
    previous_secret_expires_at: Option<UtcTimestamp>,
}

fn decode_event_overlap(values: &[SqlValue]) -> Result<EventOverlap, StorageError> {
    Ok(EventOverlap {
        previous_secret: parse_optional_digest(value_at(values, 9)?)?,
        rotation_started_at: parse_optional_time(value_at(values, 10)?)?,
        previous_secret_expires_at: parse_optional_time(value_at(values, 11)?)?,
    })
}

fn verify_issuance_event(event: &PersistedEvent, key: &ApiKey) -> Result<(), StorageError> {
    let valid = event.matches_boundary(key)
        && event.version == ApiKeyVersion::initial()
        && event.kind == ApiKeyEventKind::Issued
        && event.occurred_at == key.issued_at()
        && event.state == ApiKeyState::Active
        && event.previous_secret.is_none()
        && event.rotation_started_at.is_none()
        && event.previous_secret_expires_at.is_none();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn verify_contiguous_events(events: &[PersistedEvent], key: &ApiKey) -> Result<(), StorageError> {
    for (index, event) in events.iter().enumerate() {
        let expected = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .and_then(|value| ApiKeyVersion::new(value).ok())
            .ok_or_else(integrity_failure)?;
        validate_event_sequence_entry(event, key, index, expected)?;
    }
    verify_adjacent_events(events, key)
}

fn verify_adjacent_events(events: &[PersistedEvent], key: &ApiKey) -> Result<(), StorageError> {
    events
        .windows(2)
        .try_for_each(|pair| verify_event_pair(pair, key))
}

fn verify_event_pair(pair: &[PersistedEvent], key: &ApiKey) -> Result<(), StorageError> {
    let [previous, current] = pair else {
        return Err(integrity_failure());
    };
    match current.kind {
        ApiKeyEventKind::Rotated => verify_rotation_event(previous, current),
        ApiKeyEventKind::RotationCompleted => verify_completion_event(previous, current),
        ApiKeyEventKind::Revoked | ApiKeyEventKind::Expired => {
            verify_terminal_event(previous, current, key)
        }
        _ => Err(integrity_failure()),
    }
}

fn verify_rotation_event(
    previous: &PersistedEvent,
    current: &PersistedEvent,
) -> Result<(), StorageError> {
    let valid = previous_event_can_rotate(previous) && rotation_overlap_matches(previous, current);
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn previous_event_can_rotate(previous: &PersistedEvent) -> bool {
    previous.state == ApiKeyState::Active
        && previous.previous_secret.is_none()
        && previous.rotation_started_at.is_none()
        && previous.previous_secret_expires_at.is_none()
}

fn rotation_overlap_matches(previous: &PersistedEvent, current: &PersistedEvent) -> bool {
    let overlap_ends_after_start = current
        .previous_secret_expires_at
        .is_some_and(|expires| expires.unix_seconds() > current.occurred_at.unix_seconds());
    current.state == ApiKeyState::Rotating
        && current.current_secret != previous.current_secret
        && current.previous_secret == Some(previous.current_secret)
        && current.rotation_started_at == Some(current.occurred_at)
        && overlap_ends_after_start
}

fn verify_completion_event(
    previous: &PersistedEvent,
    current: &PersistedEvent,
) -> Result<(), StorageError> {
    let overlap_ended = previous
        .previous_secret_expires_at
        .is_some_and(|expires| current.occurred_at.unix_seconds() >= expires.unix_seconds());
    let valid = previous.kind == ApiKeyEventKind::Rotated
        && previous.state == ApiKeyState::Rotating
        && current.state == ApiKeyState::Active
        && current.current_secret == previous.current_secret
        && current.previous_secret.is_none()
        && current.rotation_started_at.is_none()
        && current.previous_secret_expires_at.is_none()
        && overlap_ended;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn verify_terminal_event(
    previous: &PersistedEvent,
    current: &PersistedEvent,
    key: &ApiKey,
) -> Result<(), StorageError> {
    let source_is_usable = matches!(previous.state, ApiKeyState::Active | ApiKeyState::Rotating);
    let valid = source_is_usable
        && terminal_kind_matches(current)
        && terminal_timing_matches(current, key)
        && current.current_secret == previous.current_secret
        && current.previous_secret.is_none()
        && current.rotation_started_at.is_none()
        && current.previous_secret_expires_at.is_none();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn terminal_kind_matches(event: &PersistedEvent) -> bool {
    matches!(
        (event.kind, event.state),
        (ApiKeyEventKind::Revoked, ApiKeyState::Revoked)
            | (ApiKeyEventKind::Expired, ApiKeyState::Expired)
    )
}

fn terminal_timing_matches(event: &PersistedEvent, key: &ApiKey) -> bool {
    match event.kind {
        ApiKeyEventKind::Revoked => {
            event.occurred_at.unix_seconds() >= key.issued_at().unix_seconds()
        }
        ApiKeyEventKind::Expired => key
            .expires_at()
            .is_some_and(|expires| event.occurred_at.unix_seconds() >= expires.unix_seconds()),
        _ => false,
    }
}

fn verify_retired_history(events: &[PersistedEvent], key: &ApiKey) -> Result<(), StorageError> {
    let retired = events
        .windows(2)
        .filter_map(retired_previous_secret)
        .collect::<Result<Vec<_>, _>>()?;
    (retired == key.retired_secrets())
        .then_some(())
        .ok_or_else(integrity_failure)
}

fn retired_previous_secret(
    pair: &[PersistedEvent],
) -> Option<Result<ApiKeySecretDigest, StorageError>> {
    let [previous, current] = pair else {
        return Some(Err(integrity_failure()));
    };
    match current.kind {
        ApiKeyEventKind::RotationCompleted => {
            Some(previous.previous_secret.ok_or_else(integrity_failure))
        }
        ApiKeyEventKind::Revoked | ApiKeyEventKind::Expired => previous.previous_secret.map(Ok),
        _ => None,
    }
}

fn validate_event_sequence_entry(
    event: &PersistedEvent,
    key: &ApiKey,
    index: usize,
    expected: ApiKeyVersion,
) -> Result<(), StorageError> {
    let kind_is_contiguous = if index == 0 {
        event.kind == ApiKeyEventKind::Issued
    } else {
        event.kind != ApiKeyEventKind::Issued
    };
    let valid = event.version == expected
        && event.matches_boundary(key)
        && kind_is_contiguous
        && event_kind_matches_state(event.kind, event.state);
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn event_kind_matches_state(kind: ApiKeyEventKind, state: ApiKeyState) -> bool {
    matches!(
        (kind, state),
        (ApiKeyEventKind::Issued, ApiKeyState::Active)
            | (ApiKeyEventKind::Rotated, ApiKeyState::Rotating)
            | (ApiKeyEventKind::RotationCompleted, ApiKeyState::Active)
            | (ApiKeyEventKind::Revoked, ApiKeyState::Revoked)
            | (ApiKeyEventKind::Expired, ApiKeyState::Expired)
    )
}

fn verify_final_event(event: &PersistedEvent, key: &ApiKey) -> Result<(), StorageError> {
    let valid = event.matches_boundary(key)
        && event.version == key.version()
        && event.state == key.state()
        && event.current_secret == key.current_secret()
        && event.previous_secret == key.previous_secret()
        && event.rotation_started_at == key.rotation_started_at()
        && event.previous_secret_expires_at == key.previous_secret_expires_at();
    valid.then_some(()).ok_or_else(integrity_failure)
}

impl PersistedEvent {
    fn matches_boundary(&self, key: &ApiKey) -> bool {
        self.tenant == *key.tenant_id() && self.user == *key.user_id() && self.key == *key.id()
    }

    fn matches_transition(&self, request: &CommitRequest<'_>) -> bool {
        let key = request.transition.key();
        let event = request.transition.event();
        self.matches_event(key, event) && self.matches_snapshot(key)
    }

    fn matches_event(&self, key: &ApiKey, event: &ariadnion_auth_api_key::ApiKeyEvent) -> bool {
        self.matches_boundary(key)
            && self.version == event.version()
            && self.kind == event.kind()
            && self.occurred_at == event.occurred_at()
            && self.actor == *event.actor()
    }

    fn matches_snapshot(&self, key: &ApiKey) -> bool {
        self.state == key.state()
            && self.current_secret == key.current_secret()
            && self.previous_secret == key.previous_secret()
            && self.rotation_started_at == key.rotation_started_at()
            && self.previous_secret_expires_at == key.previous_secret_expires_at()
    }
}

pub(super) fn ensure_issuance_absent(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    ensure_key_absent(
        rows(sql::load_key_owners(
            session,
            request.tenant_id,
            request.transition.key().id(),
        )?)?,
        request.tenant_id,
        request.transition.key().id(),
    )?;
    ensure_prefix_absent(
        rows(sql::load_prefix_owners(
            session,
            request.tenant_id,
            request.transition.key().prefix(),
        )?)?,
        request.tenant_id,
        request.transition.key().prefix(),
    )
}

fn ensure_key_absent(
    batch: VectorBatch,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<(), StorageError> {
    let row = duplicate_row(batch)?;
    let Some(row) = row else {
        return Ok(());
    };
    let owner = decode_owner_row(row)?;
    if owner.tenant == *tenant && owner.key == *key {
        Err(StorageError::new(StorageErrorCode::Conflict))
    } else {
        Err(integrity_failure())
    }
}

fn ensure_prefix_absent(
    batch: VectorBatch,
    tenant: &TenantId,
    prefix: &ApiKeyPrefix,
) -> Result<(), StorageError> {
    let row = duplicate_row(batch)?;
    let Some(row) = row else {
        return Ok(());
    };
    let owner = decode_owner_row(row)?;
    if owner.tenant == *tenant && owner.prefix == *prefix {
        Err(StorageError::new(StorageErrorCode::Conflict))
    } else {
        Err(integrity_failure())
    }
}

fn duplicate_row(batch: VectorBatch) -> Result<Option<Row>, StorageError> {
    validate_columns(batch.columns(), owner_columns())?;
    match batch.rows() {
        [] => Ok(None),
        [row] => Ok(Some(row.clone())),
        _ => Err(integrity_failure()),
    }
}

struct PersistedOwner {
    tenant: TenantId,
    _user: UserId,
    key: ApiKeyId,
    prefix: ApiKeyPrefix,
}

fn decode_owner_row(row: Row) -> Result<PersistedOwner, StorageError> {
    let values = row.values();
    require_value_count(values, 4)?;
    let (tenant, user) = decode_owner_boundary(values)?;
    let (key, prefix) = decode_owner_identity(values)?;
    Ok(PersistedOwner {
        tenant,
        _user: user,
        key,
        prefix,
    })
}

fn decode_owner_boundary(values: &[SqlValue]) -> Result<(TenantId, UserId), StorageError> {
    let tenant = TenantId::parse(text_at(values, 0)?).map_err(|_| integrity_failure())?;
    let user = parse_user(text_at(values, 1)?)?;
    Ok((tenant, user))
}

fn decode_owner_identity(values: &[SqlValue]) -> Result<(ApiKeyId, ApiKeyPrefix), StorageError> {
    let key = parse_key_id(text_at(values, 2)?)?;
    let prefix = ApiKeyPrefix::parse(text_at(values, 3)?).map_err(|_| integrity_failure())?;
    Ok((key, prefix))
}

fn validate_key_boundary(
    found_tenant: &str,
    found_user: &str,
    tenant: &TenantId,
    expected_user: Option<&UserId>,
) -> Result<(), StorageError> {
    let tenant_matches = found_tenant == tenant.as_str();
    let user_matches = expected_user.is_none_or(|user| found_user == user.as_str());
    if tenant_matches && user_matches {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_companion_boundary(
    found_tenant: &str,
    found_key: &str,
    tenant: &TenantId,
    key: &ApiKeyId,
) -> Result<(), StorageError> {
    if found_tenant == tenant.as_str() && found_key == key.as_str() {
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

fn require_value_count(values: &[SqlValue], expected: usize) -> Result<(), StorageError> {
    if values.len() == expected {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn value_at(values: &[SqlValue], index: usize) -> Result<&SqlValue, StorageError> {
    values.get(index).ok_or_else(integrity_failure)
}

fn text_at(values: &[SqlValue], index: usize) -> Result<&str, StorageError> {
    match value_at(values, index)? {
        SqlValue::Text(value) => Ok(value),
        _ => Err(integrity_failure()),
    }
}

fn int_at(values: &[SqlValue], index: usize) -> Result<i64, StorageError> {
    match value_at(values, index)? {
        SqlValue::Int64(value) => Ok(*value),
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

fn parse_key_id(value: &str) -> Result<ApiKeyId, StorageError> {
    ApiKeyId::parse(value).map_err(|_| integrity_failure())
}

fn parse_user(value: &str) -> Result<UserId, StorageError> {
    UserId::parse(value).map_err(|_| integrity_failure())
}

fn parse_version(value: &str) -> Result<ApiKeyVersion, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let number = value.parse().map_err(|_| integrity_failure())?;
    ApiKeyVersion::new(number).map_err(|_| integrity_failure())
}

fn parse_digest_value(value: &str) -> Result<ApiKeySecretDigest, StorageError> {
    Ok(ApiKeySecretDigest::new(decode_digest(value)?))
}

fn parse_optional_digest(value: &SqlValue) -> Result<Option<ApiKeySecretDigest>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(value) => parse_digest_value(value).map(Some),
        _ => Err(integrity_failure()),
    }
}

fn parse_optional_time(value: &SqlValue) -> Result<Option<UtcTimestamp>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Int64(value) => Ok(Some(UtcTimestamp::from_unix_seconds(*value))),
        _ => Err(integrity_failure()),
    }
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

fn parse_state(value: &str) -> Result<ApiKeyState, StorageError> {
    match value {
        "active" => Ok(ApiKeyState::Active),
        "rotating" => Ok(ApiKeyState::Rotating),
        "revoked" => Ok(ApiKeyState::Revoked),
        "expired" => Ok(ApiKeyState::Expired),
        _ => Err(integrity_failure()),
    }
}

fn parse_event_kind(value: &str) -> Result<ApiKeyEventKind, StorageError> {
    match value {
        "issued" => Ok(ApiKeyEventKind::Issued),
        "rotated" => Ok(ApiKeyEventKind::Rotated),
        "rotation_completed" => Ok(ApiKeyEventKind::RotationCompleted),
        "revoked" => Ok(ApiKeyEventKind::Revoked),
        "expired" => Ok(ApiKeyEventKind::Expired),
        _ => Err(integrity_failure()),
    }
}

fn key_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("api_key_id", SqlType::Text),
        ("prefix", SqlType::Text),
        ("current_secret_digest", SqlType::Text),
        ("previous_secret_digest", SqlType::Text),
        ("rotation_started_at", SqlType::Int64),
        ("previous_secret_expires_at", SqlType::Int64),
        ("issued_at", SqlType::Int64),
        ("expires_at", SqlType::Int64),
        ("version", SqlType::Text),
        ("state", SqlType::Text),
    ]
}

fn scope_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("api_key_id", SqlType::Text),
        ("scope", SqlType::Text),
    ]
}

fn retired_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("api_key_id", SqlType::Text),
        ("ordinal", SqlType::Int64),
        ("secret_digest", SqlType::Text),
    ]
}

fn event_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("api_key_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
        ("state", SqlType::Text),
        ("current_secret_digest", SqlType::Text),
        ("previous_secret_digest", SqlType::Text),
        ("rotation_started_at", SqlType::Int64),
        ("previous_secret_expires_at", SqlType::Int64),
    ]
}

fn owner_columns() -> &'static [(&'static str, SqlType)] {
    &[
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("api_key_id", SqlType::Text),
        ("prefix", SqlType::Text),
    ]
}

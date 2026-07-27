//! Strict contiguous decoding for authorization-policy events.

use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_rbac::{AuthorizationPolicyEventKind, PolicyVersion};
use ariadnion_storage_domain::StorageError;
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_executor::vector::Row;
use rnmdb_types::{SqlType, SqlValue};

use super::decode_version;
use crate::rbac_repository::integrity_failure;

pub(in crate::rbac_repository) struct PersistedPolicyEvent {
    tenant_id: TenantId,
    version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
    occurred_at: UtcTimestamp,
    actor: PrincipalId,
    request_id: RequestId,
}

impl PersistedPolicyEvent {
    pub(in crate::rbac_repository) const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub(in crate::rbac_repository) const fn version(&self) -> PolicyVersion {
        self.version
    }

    pub(in crate::rbac_repository) const fn kind(&self) -> AuthorizationPolicyEventKind {
        self.kind
    }

    pub(in crate::rbac_repository) const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    pub(in crate::rbac_repository) const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub(in crate::rbac_repository) const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
}

pub(super) fn decode_events(
    rows: &[Row],
    tenant: &TenantId,
) -> Result<Vec<PersistedPolicyEvent>, StorageError> {
    rows.iter()
        .enumerate()
        .map(|(index, row)| decode_event(row, tenant, index))
        .collect()
}

fn decode_event(
    row: &Row,
    tenant: &TenantId,
    index: usize,
) -> Result<PersistedPolicyEvent, StorageError> {
    let fields = event_row_fields(row)?;
    let version = decode_version(fields.version)?;
    validate_identity(fields.tenant, tenant, version, index)?;
    let tenant_id = TenantId::parse(fields.tenant).map_err(|_| integrity_failure())?;
    let kind = decode_kind(fields.kind, version)?;
    let occurred_at = UtcTimestamp::from_unix_seconds(fields.occurred_at);
    let actor = PrincipalId::parse(fields.actor).map_err(|_| integrity_failure())?;
    let request_id = RequestId::parse(fields.request).map_err(|_| integrity_failure())?;
    Ok(PersistedPolicyEvent {
        tenant_id,
        version,
        kind,
        occurred_at,
        actor,
        request_id,
    })
}

struct EventRowFields<'a> {
    tenant: &'a str,
    version: &'a str,
    kind: &'a str,
    occurred_at: i64,
    actor: &'a str,
    request: &'a str,
}

fn event_row_fields(row: &Row) -> Result<EventRowFields<'_>, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(version),
        SqlValue::Text(kind),
        SqlValue::Int64(occurred_at),
        SqlValue::Text(actor),
        SqlValue::Text(request),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(EventRowFields {
        tenant: found_tenant,
        version,
        kind,
        occurred_at: *occurred_at,
        actor,
        request,
    })
}

fn validate_identity(
    found_tenant: &str,
    tenant: &TenantId,
    version: PolicyVersion,
    index: usize,
) -> Result<(), StorageError> {
    let expected = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1));
    if found_tenant != tenant.as_str() || expected != Some(version.get()) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn decode_kind(
    value: &str,
    version: PolicyVersion,
) -> Result<AuthorizationPolicyEventKind, StorageError> {
    match (value, version.get()) {
        ("published", 1) => Ok(AuthorizationPolicyEventKind::Published),
        ("replaced", 2..) => Ok(AuthorizationPolicyEventKind::Replaced),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn event_columns() -> [(&'static str, SqlType); 6] {
    [
        ("tenant_id", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
        ("request_id", SqlType::Text),
    ]
}

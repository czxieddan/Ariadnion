//! Fixed tenant-bound SQL for durable invitation state.

use ariadnion_core::TenantId;
use ariadnion_invitation::{
    Invitation, InvitationEventKind, InvitationId, InvitationTokenDigest, InvitationVersion,
};
use ariadnion_organization::OrganizationId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};

use super::{CommitRequest, integrity_failure};
use crate::session::map_rnmdb_error;

pub(super) const SNAPSHOT_PROJECTION: &str = "tenant_id, organization_id, invitation_id, issuer_id, subject_digest_hex, token_digest_hex, issued_at, expires_at, version, state, consumed_by";
pub(super) const COLLISION_PROJECTION: &str =
    "tenant_id, organization_id, invitation_id, token_digest_hex";
pub(super) const EVENT_PROJECTION: &str = "tenant_id, organization_id, invitation_id, version, kind, occurred_at, actor_id, request_id, user_id";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";

const MAX_SQL_BYTES: usize = 16_384;

pub(super) fn load_by_id(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    invitation: &InvitationId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = select_prefix(tenant, organization);
    sql.push_str(" AND invitation_id = ");
    push_text(&mut sql, invitation.as_str());
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_by_token(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    token: InvitationTokenDigest,
) -> Result<CommandOutput, StorageError> {
    let mut sql = select_prefix(tenant, organization);
    sql.push_str(" AND token_digest_hex = ");
    push_text(&mut sql, &encode_digest(token.bytes()));
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_creation_collisions(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<CommandOutput, StorageError> {
    let invitation = request.transition.invitation();
    let mut sql =
        format!("SELECT {COLLISION_PROJECTION} FROM identity_invitations WHERE tenant_id = ");
    push_text(&mut sql, request.tenant_id.as_str());
    sql.push_str(" AND ((organization_id = ");
    push_text(&mut sql, request.organization_id.as_str());
    sql.push_str(" AND invitation_id = ");
    push_text(&mut sql, invitation.id().as_str());
    sql.push_str(") OR token_digest_hex = ");
    push_text(&mut sql, &encode_digest(invitation.token_digest().bytes()));
    sql.push_str(") LIMIT 3;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    invitation: &InvitationId,
) -> Result<CommandOutput, StorageError> {
    let mut sql =
        format!("SELECT {EVENT_PROJECTION} FROM identity_invitation_events WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND organization_id = ");
    push_text(&mut sql, organization.as_str());
    sql.push_str(" AND invitation_id = ");
    push_text(&mut sql, invitation.as_str());
    sql.push_str(" ORDER BY version LIMIT 3;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_outbox(
    session: &mut LocalSession,
    tenant: &TenantId,
    event_id: &str,
    idempotency_key: &str,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!("SELECT {OUTBOX_PROJECTION} FROM platform_outbox WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND (event_id = ");
    push_text(&mut sql, event_id);
    sql.push_str(" OR idempotency_key = ");
    push_text(&mut sql, idempotency_key);
    sql.push_str(") LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn insert_snapshot(
    session: &mut LocalSession,
    invitation: &Invitation,
) -> Result<(), StorageError> {
    let mut sql = String::from(
        "INSERT INTO identity_invitations (tenant_id, organization_id, invitation_id, issuer_id, subject_digest_hex, token_digest_hex, issued_at, expires_at, version, state, consumed_by) VALUES (",
    );
    push_text(&mut sql, invitation.tenant_id().as_str());
    push_value(&mut sql, invitation.organization_id().as_str());
    push_value(&mut sql, invitation.id().as_str());
    push_value(&mut sql, invitation.issuer().as_str());
    push_value(
        &mut sql,
        &encode_digest(invitation.subject_digest().bytes()),
    );
    push_value(&mut sql, &encode_digest(invitation.token_digest().bytes()));
    push_i64_value(&mut sql, invitation.issued_at().unix_seconds());
    push_i64_value(&mut sql, invitation.expires_at().unix_seconds());
    push_value(&mut sql, &encode_version(invitation.version()));
    push_value(&mut sql, state_label(invitation.state()));
    sql.push_str(", NULL);");
    require_single_insert(session, sql)
}

pub(super) fn update_snapshot(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let invitation = request.transition.invitation();
    let mut sql = String::from("UPDATE identity_invitations SET version = ");
    push_text(&mut sql, &encode_version(invitation.version()));
    sql.push_str(", state = ");
    push_text(&mut sql, state_label(invitation.state()));
    sql.push_str(", consumed_by = ");
    push_optional_text(&mut sql, invitation.consumed_by().map(|user| user.as_str()));
    push_snapshot_scope(&mut sql, request, invitation.id());
    sql.push_str(" AND version = ");
    push_text(&mut sql, &encode_version(request.expected_previous_version));
    sql.push(';');
    match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn insert_event(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let event = request.transition.event();
    let mut sql = format!("INSERT INTO identity_invitation_events ({EVENT_PROJECTION}) VALUES (");
    push_text(&mut sql, event.tenant_id().as_str());
    push_value(&mut sql, event.organization_id().as_str());
    push_value(&mut sql, event.invitation_id().as_str());
    push_value(&mut sql, &encode_version(event.version()));
    push_value(&mut sql, event_kind_label(event.kind()));
    push_i64_value(&mut sql, event.occurred_at().unix_seconds());
    push_value(&mut sql, event.actor().as_str());
    push_value(&mut sql, request.context.request_id().as_str());
    sql.push_str(", ");
    push_optional_text(&mut sql, event.user_id().map(|user| user.as_str()));
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn encode_version(version: InvitationVersion) -> String {
    format!("{:020}", version.get())
}

pub(super) fn encode_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn select_prefix(tenant: &TenantId, organization: &OrganizationId) -> String {
    let mut sql =
        format!("SELECT {SNAPSHOT_PROJECTION} FROM identity_invitations WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND organization_id = ");
    push_text(&mut sql, organization.as_str());
    sql
}

fn push_snapshot_scope(sql: &mut String, request: &CommitRequest<'_>, invitation: &InvitationId) {
    sql.push_str(" WHERE tenant_id = ");
    push_text(sql, request.tenant_id.as_str());
    sql.push_str(" AND organization_id = ");
    push_text(sql, request.organization_id.as_str());
    sql.push_str(" AND invitation_id = ");
    push_text(sql, invitation.as_str());
}

fn require_single_insert(session: &mut LocalSession, sql: String) -> Result<(), StorageError> {
    if execute(session, &finish(sql)?)? == CommandOutput::RowsAffected(1) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn push_value(sql: &mut String, value: &str) {
    sql.push_str(", ");
    push_text(sql, value);
}

fn push_i64_value(sql: &mut String, value: i64) {
    sql.push_str(", ");
    sql.push_str(&value.to_string());
}

fn push_optional_text(sql: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_text(sql, value),
        None => sql.push_str("NULL"),
    }
}

fn push_text(sql: &mut String, value: &str) {
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

fn finish(sql: String) -> Result<String, StorageError> {
    if sql.len() > MAX_SQL_BYTES || !sql.is_ascii() {
        return Err(integrity_failure());
    }
    Ok(sql)
}

fn execute(session: &mut LocalSession, sql: &str) -> Result<CommandOutput, StorageError> {
    session.execute(sql).map_err(map_rnmdb_error)
}

pub(super) const fn state_label(state: ariadnion_invitation::InvitationState) -> &'static str {
    match state {
        ariadnion_invitation::InvitationState::Issued => "issued",
        ariadnion_invitation::InvitationState::Consumed => "consumed",
        ariadnion_invitation::InvitationState::Revoked => "revoked",
        ariadnion_invitation::InvitationState::Expired => "expired",
    }
}

pub(super) const fn event_kind_label(kind: InvitationEventKind) -> &'static str {
    match kind {
        InvitationEventKind::Issued => "issued",
        InvitationEventKind::Consumed => "consumed",
        InvitationEventKind::Revoked => "revoked",
        InvitationEventKind::Expired => "expired",
    }
}

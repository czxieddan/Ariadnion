// crates/optional/ariadnion-storage-rnmdb/src/password_repository/sql.rs - Rust source for Ariadnion.
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
//! Fixed tenant- and user-bound SQL for password recovery persistence.

use ariadnion_auth_password::{
    PasswordCredentialReplacement, PasswordCredentialVersion, PasswordHashRecordDigest,
    PasswordReset, PasswordResetEventKind, PasswordResetId, PasswordResetPurpose,
    PasswordResetState, PasswordResetTokenDigest,
};
use ariadnion_core::TenantId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UserId;
use rnmdb_cli::{CommandOutput, LocalSession};
use zeroize::Zeroizing;

use super::{CommitRequest, integrity_failure};
use crate::session::map_rnmdb_error;

pub(super) const CREDENTIAL_PROJECTION: &str =
    "tenant_id, user_id, version, hash_policy_version, phc_record";
pub(super) const RESET_PROJECTION: &str = "tenant_id, user_id, reset_id, token_digest_hex, issued_at, expires_at, version, purpose, state, password_hash_digest_hex";
pub(super) const EVENT_PROJECTION: &str = "tenant_id, user_id, reset_id, version, kind, occurred_at, actor_id, purpose, password_hash_digest_hex";
pub(super) const COMMIT_EVIDENCE_PROJECTION: &str = "tenant_id, user_id, reset_id, version, request_id, issued_credential_version, resulting_credential_version, resulting_hash_policy_version, password_hash_digest_hex";
pub(super) const COLLISION_PROJECTION: &str = "tenant_id, user_id, reset_id, token_digest_hex";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";

const MAX_SQL_BYTES: usize = 16_384;

pub(super) fn load_credential(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = select_credential_prefix(tenant, user);
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_reset_by_id(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    reset: &PasswordResetId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = select_reset_prefix(tenant, user);
    sql.push_str(" AND reset_id = ");
    push_text(&mut sql, reset.as_str());
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_reset_by_token(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    token: PasswordResetTokenDigest,
) -> Result<CommandOutput, StorageError> {
    let mut sql = select_reset_prefix(tenant, user);
    sql.push_str(" AND token_digest_hex = ");
    push_text(&mut sql, &encode_digest(token.bytes()));
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_issuance_collisions(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<CommandOutput, StorageError> {
    let reset = request.transition().reset();
    let mut sql = Zeroizing::new(format!(
        "SELECT {COLLISION_PROJECTION} FROM identity_password_resets WHERE tenant_id = "
    ));
    push_text(&mut sql, request.tenant_id.as_str());
    sql.push_str(" AND (reset_id = ");
    push_text(&mut sql, reset.id().as_str());
    sql.push_str(" OR token_digest_hex = ");
    push_text(&mut sql, &encode_digest(reset.token_digest().bytes()));
    sql.push_str(") LIMIT 3;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    reset: &PasswordResetId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = scoped_projection(
        "identity_password_reset_events",
        EVENT_PROJECTION,
        tenant,
        user,
    );
    sql.push_str(" AND reset_id = ");
    push_text(&mut sql, reset.as_str());
    sql.push_str(" ORDER BY version LIMIT 3;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_commit_evidence(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    reset: &PasswordResetId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = scoped_projection(
        "identity_password_reset_commit_evidence",
        COMMIT_EVIDENCE_PROJECTION,
        tenant,
        user,
    );
    sql.push_str(" AND reset_id = ");
    push_text(&mut sql, reset.as_str());
    sql.push_str(" ORDER BY version LIMIT 3;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_outbox(
    session: &mut LocalSession,
    tenant: &TenantId,
    event_id: &str,
    idempotency_key: &str,
) -> Result<CommandOutput, StorageError> {
    let mut sql = Zeroizing::new(format!(
        "SELECT {OUTBOX_PROJECTION} FROM platform_outbox WHERE tenant_id = "
    ));
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND (event_id = ");
    push_text(&mut sql, event_id);
    sql.push_str(" OR idempotency_key = ");
    push_text(&mut sql, idempotency_key);
    sql.push_str(") LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn insert_reset(
    session: &mut LocalSession,
    reset: &PasswordReset,
) -> Result<(), StorageError> {
    let mut sql = Zeroizing::new(String::from(
        "INSERT INTO identity_password_resets (tenant_id, user_id, reset_id, token_digest_hex, issued_at, expires_at, version, purpose, state, password_hash_digest_hex) VALUES (",
    ));
    push_text(&mut sql, reset.tenant_id().as_str());
    push_value(&mut sql, reset.user_id().as_str());
    push_value(&mut sql, reset.id().as_str());
    push_value(&mut sql, &encode_digest(reset.token_digest().bytes()));
    push_i64_value(&mut sql, reset.issued_at().unix_seconds());
    push_i64_value(&mut sql, reset.expires_at().unix_seconds());
    push_value(&mut sql, &encode_version(reset.version().get()));
    push_value(&mut sql, purpose_label(reset.purpose()));
    push_value(&mut sql, state_label(reset.state()));
    sql.push_str(", ");
    push_optional_digest(&mut sql, reset.password_hash_digest());
    sql.push_str(");");
    require_single_change(session, sql)
}

pub(super) fn update_reset(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let reset = request.transition().reset();
    let mut sql = Zeroizing::new(String::from(
        "UPDATE identity_password_resets SET version = ",
    ));
    push_text(&mut sql, &encode_version(reset.version().get()));
    sql.push_str(", state = ");
    push_text(&mut sql, state_label(reset.state()));
    sql.push_str(", password_hash_digest_hex = ");
    push_optional_digest(&mut sql, reset.password_hash_digest());
    push_scope(&mut sql, request.tenant_id, request.user_id, reset.id());
    sql.push_str(" AND version = ");
    push_text(
        &mut sql,
        &encode_version(request.expected_previous_reset_version.get()),
    );
    sql.push(';');
    require_cas(session, sql)
}

pub(super) fn update_credential(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    replacement: &PasswordCredentialReplacement,
) -> Result<(), StorageError> {
    let target = replacement.credential();
    let mut sql = Zeroizing::new(String::from(
        "UPDATE identity_password_credentials SET version = ",
    ));
    push_text(&mut sql, &encode_version(target.version().get()));
    sql.push_str(", hash_policy_version = ");
    push_text(
        &mut sql,
        &encode_version(target.hash_policy_version().get()),
    );
    sql.push_str(", phc_record = ");
    push_text(&mut sql, target.hash_record().as_str());
    sql.push_str(" WHERE tenant_id = ");
    push_text(&mut sql, request.tenant_id.as_str());
    sql.push_str(" AND user_id = ");
    push_text(&mut sql, request.user_id.as_str());
    sql.push_str(" AND version = ");
    push_text(
        &mut sql,
        &encode_version(replacement.expected_version().get()),
    );
    sql.push(';');
    require_cas(session, sql)
}

pub(super) fn insert_event(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let event = request.transition().event();
    let mut sql = Zeroizing::new(format!(
        "INSERT INTO identity_password_reset_events ({EVENT_PROJECTION}) VALUES ("
    ));
    push_text(&mut sql, event.tenant_id().as_str());
    push_value(&mut sql, event.user_id().as_str());
    push_value(&mut sql, event.reset_id().as_str());
    push_value(&mut sql, &encode_version(event.version().get()));
    push_value(&mut sql, event_kind_label(event.kind()));
    push_i64_value(&mut sql, event.occurred_at().unix_seconds());
    push_value(&mut sql, event.actor().as_str());
    push_value(&mut sql, purpose_label(event.purpose()));
    sql.push_str(", ");
    push_optional_digest(&mut sql, event.password_hash_digest());
    sql.push_str(");");
    require_single_change(session, sql)
}

pub(super) fn insert_commit_evidence(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let event = request.transition().event();
    let replacement = request.commit.credential_replacement();
    let mut sql = Zeroizing::new(format!(
        "INSERT INTO identity_password_reset_commit_evidence ({COMMIT_EVIDENCE_PROJECTION}) VALUES ("
    ));
    push_text(&mut sql, event.tenant_id().as_str());
    push_value(&mut sql, event.user_id().as_str());
    push_value(&mut sql, event.reset_id().as_str());
    push_value(&mut sql, &encode_version(event.version().get()));
    push_value(&mut sql, request.context.request_id().as_str());
    push_value(
        &mut sql,
        &encode_version(event.issued_credential_version().get()),
    );
    sql.push_str(", ");
    push_optional_version(&mut sql, replacement.map(|value| value.resulting_version()));
    sql.push_str(", ");
    push_optional_u64(
        &mut sql,
        replacement.map(|value| value.resulting_hash_policy_version().get()),
    );
    sql.push_str(", ");
    push_optional_digest(&mut sql, event.password_hash_digest());
    sql.push_str(");");
    require_single_change(session, sql)
}

pub(super) fn encode_version(value: u64) -> String {
    format!("{value:020}")
}

pub(super) fn encode_digest(bytes: [u8; 32]) -> String {
    hex(&bytes)
}

fn select_credential_prefix(tenant: &TenantId, user: &UserId) -> Zeroizing<String> {
    scoped_projection(
        "identity_password_credentials",
        CREDENTIAL_PROJECTION,
        tenant,
        user,
    )
}

fn select_reset_prefix(tenant: &TenantId, user: &UserId) -> Zeroizing<String> {
    scoped_projection("identity_password_resets", RESET_PROJECTION, tenant, user)
}

fn scoped_projection(
    table: &str,
    projection: &str,
    tenant: &TenantId,
    user: &UserId,
) -> Zeroizing<String> {
    let mut sql = Zeroizing::new(format!(
        "SELECT {projection} FROM {table} WHERE tenant_id = "
    ));
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND user_id = ");
    push_text(&mut sql, user.as_str());
    sql
}

fn push_scope(sql: &mut String, tenant: &TenantId, user: &UserId, reset: &PasswordResetId) {
    sql.push_str(" WHERE tenant_id = ");
    push_text(sql, tenant.as_str());
    sql.push_str(" AND user_id = ");
    push_text(sql, user.as_str());
    sql.push_str(" AND reset_id = ");
    push_text(sql, reset.as_str());
}

fn require_cas(session: &mut LocalSession, sql: Zeroizing<String>) -> Result<(), StorageError> {
    match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

fn require_single_change(
    session: &mut LocalSession,
    sql: Zeroizing<String>,
) -> Result<(), StorageError> {
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

fn push_optional_version(sql: &mut String, value: Option<PasswordCredentialVersion>) {
    push_optional_u64(sql, value.map(PasswordCredentialVersion::get));
}

fn push_optional_u64(sql: &mut String, value: Option<u64>) {
    match value {
        Some(value) => push_text(sql, &encode_version(value)),
        None => sql.push_str("NULL"),
    }
}

fn push_optional_digest(sql: &mut String, value: Option<PasswordHashRecordDigest>) {
    match value {
        Some(value) => push_text(sql, &encode_digest(value.bytes())),
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

fn finish(sql: Zeroizing<String>) -> Result<Zeroizing<String>, StorageError> {
    if sql.len() > MAX_SQL_BYTES || !sql.is_ascii() {
        return Err(integrity_failure());
    }
    Ok(sql)
}

fn execute(session: &mut LocalSession, sql: &str) -> Result<CommandOutput, StorageError> {
    session.execute(sql).map_err(map_rnmdb_error)
}

pub(super) const fn purpose_label(purpose: PasswordResetPurpose) -> &'static str {
    match purpose {
        PasswordResetPurpose::PasswordRecovery => "password_recovery",
    }
}

pub(super) const fn state_label(state: PasswordResetState) -> &'static str {
    match state {
        PasswordResetState::Issued => "issued",
        PasswordResetState::Consumed => "consumed",
        PasswordResetState::Revoked => "revoked",
        PasswordResetState::Expired => "expired",
    }
}

pub(super) const fn event_kind_label(kind: PasswordResetEventKind) -> &'static str {
    match kind {
        PasswordResetEventKind::Issued => "issued",
        PasswordResetEventKind::Consumed => "consumed",
        PasswordResetEventKind::Revoked => "revoked",
        PasswordResetEventKind::Expired => "expired",
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

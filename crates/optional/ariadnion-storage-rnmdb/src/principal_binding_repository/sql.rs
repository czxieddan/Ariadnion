// crates/optional/ariadnion-storage-rnmdb/src/principal_binding_repository/sql.rs - Rust source for Ariadnion.
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
//! Fixed tenant-bound SQL for principal-binding snapshots and events.

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_principal_binding::{
    PrincipalBinding, PrincipalBindingEvent, PrincipalBindingEventKind, PrincipalBindingState,
    PrincipalBindingVersion, SubjectCommitment,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};

use super::integrity_failure;
use crate::session::map_rnmdb_error;

pub(super) const SNAPSHOT_PROJECTION: &str = "tenant_id, principal_id, user_id, organization_id, membership_id, subject_commitment_hex, version, state, provisioned_at, revoked_at, erased_at";
pub(super) const EVENT_PROJECTION: &str = "tenant_id, principal_id, version, kind, occurred_at, actor_id, request_id, subject_commitment_hex";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";

const MAX_SQL_BYTES: usize = 16_384;

pub(super) fn load_snapshot(
    session: &mut LocalSession,
    tenant: &TenantId,
    principal: &PrincipalId,
) -> Result<CommandOutput, StorageError> {
    let mut sql =
        format!("SELECT {SNAPSHOT_PROJECTION} FROM identity_principal_bindings WHERE tenant_id = ");
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND principal_id = ");
    push_text(&mut sql, principal.as_str());
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    principal: &PrincipalId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = format!(
        "SELECT {EVENT_PROJECTION} FROM identity_principal_binding_events WHERE tenant_id = "
    );
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND principal_id = ");
    push_text(&mut sql, principal.as_str());
    sql.push_str(" ORDER BY version LIMIT 4;");
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
    binding: &PrincipalBinding,
) -> Result<(), StorageError> {
    let mut sql = String::from(
        "INSERT INTO identity_principal_bindings (tenant_id, principal_id, user_id, organization_id, membership_id, subject_commitment_hex, version, state, provisioned_at, revoked_at, erased_at) VALUES (",
    );
    push_text(&mut sql, binding.tenant_id().as_str());
    push_value(&mut sql, binding.principal_id().as_str());
    push_identity_values(&mut sql, binding);
    push_value(&mut sql, &encode_commitment(binding.subject_commitment()));
    push_value(&mut sql, &encode_version(binding.version()));
    push_value(&mut sql, state_label(binding.state()));
    push_i64_value(&mut sql, binding.provisioned_at().unix_seconds());
    push_optional_i64_value(
        &mut sql,
        binding.revoked_at().map(|value| value.unix_seconds()),
    );
    push_optional_i64_value(
        &mut sql,
        binding.erased_at().map(|value| value.unix_seconds()),
    );
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn update_snapshot(
    session: &mut LocalSession,
    binding: &PrincipalBinding,
    expected: PrincipalBindingVersion,
) -> Result<(), StorageError> {
    let mut sql = String::from("UPDATE identity_principal_bindings SET user_id = ");
    push_optional_text(
        &mut sql,
        binding
            .identity()
            .map(|identity| identity.user_id().as_str()),
    );
    sql.push_str(", organization_id = ");
    push_optional_text(
        &mut sql,
        binding
            .identity()
            .map(|identity| identity.organization_id().as_str()),
    );
    sql.push_str(", membership_id = ");
    push_optional_text(
        &mut sql,
        binding
            .identity()
            .map(|identity| identity.membership_id().as_str()),
    );
    sql.push_str(", subject_commitment_hex = ");
    push_text(&mut sql, &encode_commitment(binding.subject_commitment()));
    sql.push_str(", version = ");
    push_text(&mut sql, &encode_version(binding.version()));
    sql.push_str(", state = ");
    push_text(&mut sql, state_label(binding.state()));
    sql.push_str(", provisioned_at = ");
    sql.push_str(&binding.provisioned_at().unix_seconds().to_string());
    sql.push_str(", revoked_at = ");
    push_optional_i64(
        &mut sql,
        binding.revoked_at().map(|value| value.unix_seconds()),
    );
    sql.push_str(", erased_at = ");
    push_optional_i64(
        &mut sql,
        binding.erased_at().map(|value| value.unix_seconds()),
    );
    sql.push_str(" WHERE tenant_id = ");
    push_text(&mut sql, binding.tenant_id().as_str());
    sql.push_str(" AND principal_id = ");
    push_text(&mut sql, binding.principal_id().as_str());
    sql.push_str(" AND version = ");
    push_text(&mut sql, &encode_version(expected));
    sql.push(';');
    match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn insert_event(
    session: &mut LocalSession,
    event: &PrincipalBindingEvent,
) -> Result<(), StorageError> {
    let mut sql =
        format!("INSERT INTO identity_principal_binding_events ({EVENT_PROJECTION}) VALUES (");
    push_text(&mut sql, event.tenant_id().as_str());
    push_value(&mut sql, event.principal_id().as_str());
    push_value(&mut sql, &encode_version(event.version()));
    push_value(&mut sql, event_kind_label(event.kind()));
    push_i64_value(&mut sql, event.occurred_at().unix_seconds());
    push_value(&mut sql, event.actor().as_str());
    push_value(&mut sql, event.request_id().as_str());
    push_value(&mut sql, &encode_commitment(event.subject_commitment()));
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn encode_version(version: PrincipalBindingVersion) -> String {
    format!("{:020}", version.get())
}

pub(super) fn encode_commitment(commitment: &SubjectCommitment) -> String {
    hex(commitment.as_bytes())
}

pub(super) const fn state_label(state: PrincipalBindingState) -> &'static str {
    match state {
        PrincipalBindingState::Active => "active",
        PrincipalBindingState::Revoked => "revoked",
        PrincipalBindingState::Erased => "erased",
    }
}

pub(super) const fn event_kind_label(kind: PrincipalBindingEventKind) -> &'static str {
    match kind {
        PrincipalBindingEventKind::Provisioned => "provisioned",
        PrincipalBindingEventKind::Revoked => "revoked",
        PrincipalBindingEventKind::Erased => "erased",
    }
}

fn push_identity_values(sql: &mut String, binding: &PrincipalBinding) {
    push_optional_value(
        sql,
        binding
            .identity()
            .map(|identity| identity.user_id().as_str()),
    );
    push_optional_value(
        sql,
        binding
            .identity()
            .map(|identity| identity.organization_id().as_str()),
    );
    push_optional_value(
        sql,
        binding
            .identity()
            .map(|identity| identity.membership_id().as_str()),
    );
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

fn push_optional_value(sql: &mut String, value: Option<&str>) {
    sql.push_str(", ");
    push_optional_text(sql, value);
}

fn push_i64_value(sql: &mut String, value: i64) {
    sql.push_str(", ");
    sql.push_str(&value.to_string());
}

fn push_optional_i64_value(sql: &mut String, value: Option<i64>) {
    sql.push_str(", ");
    push_optional_i64(sql, value);
}

fn push_optional_text(sql: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_text(sql, value),
        None => sql.push_str("NULL"),
    }
}

fn push_optional_i64(sql: &mut String, value: Option<i64>) {
    match value {
        Some(value) => sql.push_str(&value.to_string()),
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

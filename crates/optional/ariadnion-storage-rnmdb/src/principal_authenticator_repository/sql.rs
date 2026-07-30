// crates/optional/ariadnion-storage-rnmdb/src/principal_authenticator_repository/sql.rs - Rust source for Ariadnion.
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
//! Fixed tenant-first SQL for principal-authenticator snapshots and events.

use ariadnion_core::TenantId;
use ariadnion_principal_binding::{
    PrincipalAuthenticatorEvent, PrincipalAuthenticatorEventKind, PrincipalAuthenticatorId,
    PrincipalAuthenticatorKind, PrincipalAuthenticatorLink, PrincipalAuthenticatorSourceCommitment,
    PrincipalAuthenticatorSourceId, PrincipalAuthenticatorState, PrincipalAuthenticatorVersion,
    PrincipalBindingVersion,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use zeroize::Zeroizing;

use super::integrity_failure;
use crate::session::map_rnmdb_error;

pub(super) const SNAPSHOT_PROJECTION: &str = "tenant_id, authenticator_id, authenticator_kind, source_id, principal_id, principal_binding_version, version, state, linked_at, revoked_at";
pub(super) const EVENT_PROJECTION: &str = "tenant_id, authenticator_id, authenticator_kind, source_commitment_hex, principal_id, principal_binding_version, version, kind, occurred_at, actor_id, request_id";
pub(super) const OUTBOX_PROJECTION: &str = "tenant_id, event_id, topic, idempotency_key, payload_hex, created_at, available_at, attempt, state, lease_token, lease_worker, lease_expires_at, delivered_at, failed_at";

const MAX_SQL_BYTES: usize = 16_384;

pub(super) fn load_snapshot_by_id(
    session: &mut LocalSession,
    tenant: &TenantId,
    authenticator: &PrincipalAuthenticatorId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = Zeroizing::new(format!(
        "SELECT {SNAPSHOT_PROJECTION} FROM identity_principal_authenticators WHERE tenant_id = "
    ));
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND authenticator_id = ");
    push_text(&mut sql, authenticator.as_str());
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_snapshot_by_source(
    session: &mut LocalSession,
    tenant: &TenantId,
    kind: PrincipalAuthenticatorKind,
    source: &PrincipalAuthenticatorSourceId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = Zeroizing::new(format!(
        "SELECT {SNAPSHOT_PROJECTION} FROM identity_principal_authenticators WHERE tenant_id = "
    ));
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND authenticator_kind = ");
    push_text(&mut sql, kind.as_str());
    sql.push_str(" AND source_id = ");
    push_text(&mut sql, source.as_str());
    sql.push_str(" LIMIT 2;");
    execute(session, &finish(sql)?)
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    authenticator: &PrincipalAuthenticatorId,
) -> Result<CommandOutput, StorageError> {
    let mut sql = Zeroizing::new(format!(
        "SELECT {EVENT_PROJECTION} FROM identity_principal_authenticator_events WHERE tenant_id = "
    ));
    push_text(&mut sql, tenant.as_str());
    sql.push_str(" AND authenticator_id = ");
    push_text(&mut sql, authenticator.as_str());
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

pub(super) fn insert_snapshot(
    session: &mut LocalSession,
    link: &PrincipalAuthenticatorLink,
) -> Result<(), StorageError> {
    let mut sql = Zeroizing::new(String::from(
        "INSERT INTO identity_principal_authenticators (tenant_id, authenticator_id, authenticator_kind, source_id, principal_id, principal_binding_version, version, state, linked_at, revoked_at) VALUES (",
    ));
    push_text(&mut sql, link.tenant_id().as_str());
    push_value(&mut sql, link.authenticator_id().as_str());
    push_value(&mut sql, link.kind().as_str());
    push_value(&mut sql, link.source_id().as_str());
    push_value(&mut sql, link.principal_id().as_str());
    push_value(
        &mut sql,
        &encode_binding_version(link.principal_binding_version()),
    );
    push_value(&mut sql, &encode_version(link.version()));
    push_value(&mut sql, state_label(link.state()));
    push_i64_value(&mut sql, link.linked_at().unix_seconds());
    push_optional_i64_value(
        &mut sql,
        link.revoked_at().map(|value| value.unix_seconds()),
    );
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn update_snapshot(
    session: &mut LocalSession,
    link: &PrincipalAuthenticatorLink,
    expected: PrincipalAuthenticatorVersion,
) -> Result<(), StorageError> {
    let mut sql = Zeroizing::new(String::from(
        "UPDATE identity_principal_authenticators SET version = ",
    ));
    push_text(&mut sql, &encode_version(link.version()));
    sql.push_str(", state = ");
    push_text(&mut sql, state_label(link.state()));
    sql.push_str(", linked_at = ");
    sql.push_str(&link.linked_at().unix_seconds().to_string());
    sql.push_str(", revoked_at = ");
    push_optional_i64(
        &mut sql,
        link.revoked_at().map(|value| value.unix_seconds()),
    );
    push_immutable_snapshot_predicate(&mut sql, link);
    sql.push_str(" AND version = ");
    push_text(&mut sql, &encode_version(expected));
    sql.push(';');
    match execute(session, &finish(sql)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(StorageError::new(StorageErrorCode::Conflict)),
        _ => Err(integrity_failure()),
    }
}

fn push_immutable_snapshot_predicate(sql: &mut String, link: &PrincipalAuthenticatorLink) {
    sql.push_str(" WHERE tenant_id = ");
    push_text(sql, link.tenant_id().as_str());
    sql.push_str(" AND authenticator_id = ");
    push_text(sql, link.authenticator_id().as_str());
    sql.push_str(" AND authenticator_kind = ");
    push_text(sql, link.kind().as_str());
    sql.push_str(" AND source_id = ");
    push_text(sql, link.source_id().as_str());
    sql.push_str(" AND principal_id = ");
    push_text(sql, link.principal_id().as_str());
    sql.push_str(" AND principal_binding_version = ");
    push_text(
        sql,
        &encode_binding_version(link.principal_binding_version()),
    );
}

pub(super) fn insert_event(
    session: &mut LocalSession,
    event: &PrincipalAuthenticatorEvent,
) -> Result<(), StorageError> {
    let mut sql = Zeroizing::new(format!(
        "INSERT INTO identity_principal_authenticator_events ({EVENT_PROJECTION}) VALUES ("
    ));
    push_text(&mut sql, event.tenant_id().as_str());
    push_value(&mut sql, event.authenticator_id().as_str());
    push_value(&mut sql, event.authenticator_kind().as_str());
    push_value(&mut sql, &encode_commitment(event.source_commitment()));
    push_value(&mut sql, event.principal_id().as_str());
    push_value(
        &mut sql,
        &encode_binding_version(event.principal_binding_version()),
    );
    push_value(&mut sql, &encode_version(event.version()));
    push_value(&mut sql, event_kind_label(event.kind()));
    push_i64_value(&mut sql, event.occurred_at().unix_seconds());
    push_value(&mut sql, event.actor().as_str());
    push_value(&mut sql, event.request_id().as_str());
    sql.push_str(");");
    require_single_insert(session, sql)
}

pub(super) fn encode_version(version: PrincipalAuthenticatorVersion) -> String {
    encode_u64(version.get())
}

pub(super) fn encode_binding_version(version: PrincipalBindingVersion) -> String {
    encode_u64(version.get())
}

pub(super) fn encode_commitment(commitment: &PrincipalAuthenticatorSourceCommitment) -> String {
    hex(commitment.as_bytes())
}

pub(super) const fn state_label(state: PrincipalAuthenticatorState) -> &'static str {
    match state {
        PrincipalAuthenticatorState::Active => "active",
        PrincipalAuthenticatorState::Revoked => "revoked",
    }
}

pub(super) const fn event_kind_label(kind: PrincipalAuthenticatorEventKind) -> &'static str {
    match kind {
        PrincipalAuthenticatorEventKind::Linked => "linked",
        PrincipalAuthenticatorEventKind::Revoked => "revoked",
    }
}

fn encode_u64(value: u64) -> String {
    format!("{value:020}")
}

fn require_single_insert(
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

fn push_optional_i64_value(sql: &mut String, value: Option<i64>) {
    sql.push_str(", ");
    push_optional_i64(sql, value);
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

fn finish(sql: Zeroizing<String>) -> Result<Zeroizing<String>, StorageError> {
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

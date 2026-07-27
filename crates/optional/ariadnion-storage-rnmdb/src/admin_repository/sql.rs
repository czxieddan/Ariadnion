//! Fixed tenant-bound SQL for the administration command ledger.

use ariadnion_api_admin::{AdminCommand, AdminCommandIntent};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::{CommandOutput, LocalSession};

use super::fingerprint::{self, StableMaterial};
use crate::session::map_rnmdb_error;

pub(super) const LEDGER_PROJECTION: &str = "tenant_id, command_id, decision_id, actor_id, policy_version, action, target_kind, target_parent_id, target_id, reason_code, fingerprint_hex, evaluated_at, request_id, applied_at, state";

const MAX_SQL_BYTES: usize = 16_384;

pub(super) fn load_candidates(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
) -> Result<CommandOutput, StorageError> {
    let mut statement =
        format!("SELECT {LEDGER_PROJECTION} FROM identity_admin_commands WHERE tenant_id = ");
    push_text(&mut statement, intent.tenant_id().as_str());
    statement.push_str(" AND (command_id = ");
    push_text(&mut statement, intent.command_id().as_str());
    statement.push_str(" OR decision_id = ");
    push_text(&mut statement, intent.decision_id().as_str());
    statement.push_str(") LIMIT 3;");
    execute(session, &finish(statement)?)
}

pub(super) fn insert_pending(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
    command: &AdminCommand,
    request_id: &str,
) -> Result<(), StorageError> {
    let material = StableMaterial::from_intent(intent);
    let target = fingerprint::target_parts(intent.target());
    let mut statement =
        format!("INSERT INTO identity_admin_commands ({LEDGER_PROJECTION}) VALUES (");
    push_text(&mut statement, material.tenant_id);
    push_value(&mut statement, material.command_id);
    push_value(&mut statement, material.decision_id);
    push_value(&mut statement, material.actor_id);
    push_value(
        &mut statement,
        &fingerprint::encode_policy_version(material.policy_version),
    );
    push_value(&mut statement, fingerprint::action_label(material.action));
    push_value(&mut statement, target.kind);
    push_optional_value(&mut statement, target.parent_id);
    push_value(&mut statement, target.target_id);
    push_value(&mut statement, material.reason_code);
    push_value(&mut statement, &fingerprint::fingerprint(&material));
    push_i64_value(&mut statement, command.occurred_at().unix_seconds());
    push_value(&mut statement, request_id);
    statement.push_str(", NULL, 'pending');");
    require_single_insert(session, finish(statement)?)
}

pub(super) fn finalize(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
    applied_at: UtcTimestamp,
) -> Result<(), StorageError> {
    let material = StableMaterial::from_intent(intent);
    let fingerprint = fingerprint::fingerprint(&material);
    let mut statement = String::from("UPDATE identity_admin_commands SET applied_at = ");
    statement.push_str(&applied_at.unix_seconds().to_string());
    statement.push_str(", state = 'applied' WHERE tenant_id = ");
    push_text(&mut statement, material.tenant_id);
    statement.push_str(" AND command_id = ");
    push_text(&mut statement, material.command_id);
    statement.push_str(" AND decision_id = ");
    push_text(&mut statement, material.decision_id);
    statement.push_str(" AND fingerprint_hex = ");
    push_text(&mut statement, &fingerprint);
    statement.push_str(" AND state = 'pending' AND applied_at IS NULL;");
    match execute(session, &finish(statement)?)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(conflict()),
        _ => Err(integrity_failure()),
    }
}

fn require_single_insert(
    session: &mut LocalSession,
    statement: String,
) -> Result<(), StorageError> {
    match execute(session, &statement)? {
        CommandOutput::RowsAffected(1) => Ok(()),
        CommandOutput::RowsAffected(0) => Err(conflict()),
        _ => Err(integrity_failure()),
    }
}

fn push_value(statement: &mut String, value: &str) {
    statement.push_str(", ");
    push_text(statement, value);
}

fn push_optional_value(statement: &mut String, value: Option<&str>) {
    statement.push_str(", ");
    if let Some(value) = value {
        push_text(statement, value);
    } else {
        statement.push_str("NULL");
    }
}

fn push_i64_value(statement: &mut String, value: i64) {
    statement.push_str(", ");
    statement.push_str(&value.to_string());
}

fn push_text(statement: &mut String, value: &str) {
    statement.push('\'');
    for character in value.chars() {
        if character == '\'' {
            statement.push_str("''");
        } else {
            statement.push(character);
        }
    }
    statement.push('\'');
}

fn finish(statement: String) -> Result<String, StorageError> {
    if statement.len() > MAX_SQL_BYTES || !statement.is_ascii() {
        return Err(integrity_failure());
    }
    Ok(statement)
}

fn execute(session: &mut LocalSession, statement: &str) -> Result<CommandOutput, StorageError> {
    session.execute(statement).map_err(map_rnmdb_error)
}

const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

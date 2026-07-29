// crates/optional/ariadnion-storage-rnmdb/src/admin_repository/decode.rs - Rust source for Ariadnion.
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
//! Strict decoding and replay reconciliation for command-ledger rows.

use ariadnion_api_admin::{
    AdminActionKind, AdminCommandId, AdminCommandIntent, AdminCommandReceipt, AdminTarget,
    AdminTargetKind,
};
use ariadnion_auth_api_key::ApiKeyId;
use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_invitation::InvitationId;
use ariadnion_organization::OrganizationId;
use ariadnion_rbac::{DecisionId, PolicyVersion};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use super::{fingerprint, sql};

const VERSION_TEXT_BYTES: usize = 20;
const FINGERPRINT_HEX_BYTES: usize = 64;
const MAX_REASON_BYTES: usize = 64;

pub(super) struct LedgerRecord {
    command_id: AdminCommandId,
    tenant_id: TenantId,
    decision_id: DecisionId,
    actor_id: PrincipalId,
    policy_version: PolicyVersion,
    action: AdminActionKind,
    target: AdminTarget,
    reason_code: Box<str>,
    applied_at: UtcTimestamp,
}

impl LedgerRecord {
    fn matches_intent(&self, intent: &AdminCommandIntent) -> bool {
        (
            &self.command_id,
            &self.tenant_id,
            &self.decision_id,
            &self.actor_id,
            self.policy_version,
            self.action,
            &self.target,
            self.reason_code.as_ref(),
        ) == (
            intent.command_id(),
            intent.tenant_id(),
            intent.decision_id(),
            intent.actor(),
            intent.expected_policy_version(),
            intent.action(),
            intent.target(),
            intent.reason_code(),
        )
    }

    fn receipt(&self) -> AdminCommandReceipt {
        AdminCommandReceipt::new(
            self.command_id.clone(),
            self.tenant_id.clone(),
            self.decision_id.clone(),
            self.policy_version,
            self.applied_at,
        )
    }
}

pub(super) fn load_candidates(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
) -> Result<Vec<LedgerRecord>, StorageError> {
    let batch = rows(sql::load_candidates(session, intent)?)?;
    validate_columns(batch.columns())?;
    if batch.rows().len() > 2 {
        return Err(integrity_failure());
    }
    batch
        .rows()
        .iter()
        .map(|row| decode_record(row, intent.tenant_id()))
        .collect()
}

pub(super) fn resolve_candidates(
    records: &[LedgerRecord],
    intent: &AdminCommandIntent,
) -> Result<Option<AdminCommandReceipt>, StorageError> {
    match records {
        [] => Ok(None),
        [record] => resolve_single(record, intent),
        [first, second] => resolve_collision(first, second, intent),
        _ => Err(integrity_failure()),
    }
}

fn resolve_single(
    record: &LedgerRecord,
    intent: &AdminCommandIntent,
) -> Result<Option<AdminCommandReceipt>, StorageError> {
    let queried_identity =
        record.command_id == *intent.command_id() || record.decision_id == *intent.decision_id();
    if !queried_identity {
        return Err(integrity_failure());
    }
    if record.matches_intent(intent) {
        return Ok(Some(record.receipt()));
    }
    Err(conflict())
}

fn resolve_collision(
    first: &LedgerRecord,
    second: &LedgerRecord,
    intent: &AdminCommandIntent,
) -> Result<Option<AdminCommandReceipt>, StorageError> {
    let first_matches_query =
        first.command_id == *intent.command_id() || first.decision_id == *intent.decision_id();
    let second_matches_query =
        second.command_id == *intent.command_id() || second.decision_id == *intent.decision_id();
    if !first_matches_query || !second_matches_query {
        return Err(integrity_failure());
    }
    Err(conflict())
}

struct RawLedgerFields<'a> {
    tenant_id: &'a str,
    command_id: &'a str,
    decision_id: &'a str,
    actor_id: &'a str,
    policy_version: &'a str,
    action: &'a str,
    target_kind: &'a str,
    target_parent_id: &'a SqlValue,
    target_id: &'a str,
    reason_code: &'a str,
    fingerprint_hex: &'a str,
    evaluated_at: i64,
    request_id: &'a str,
    applied_at: &'a SqlValue,
    state: &'a str,
}

struct DecodedIdentity {
    tenant_id: TenantId,
    command_id: AdminCommandId,
    decision_id: DecisionId,
    actor_id: PrincipalId,
    policy_version: PolicyVersion,
}

struct DecodedCommandMaterial {
    action: AdminActionKind,
    target: AdminTarget,
    reason_code: Box<str>,
}

fn decode_record(row: &Row, expected_tenant: &TenantId) -> Result<LedgerRecord, StorageError> {
    let raw = raw_fields(row)?;
    let identity = decode_identity(&raw, expected_tenant)?;
    let material = decode_command_material(&raw)?;
    let _request_id = RequestId::parse(raw.request_id).map_err(|_| integrity_failure())?;
    let applied_at = decode_applied_at(raw.state, raw.applied_at, raw.evaluated_at)?;
    let record = LedgerRecord {
        command_id: identity.command_id,
        tenant_id: identity.tenant_id,
        decision_id: identity.decision_id,
        actor_id: identity.actor_id,
        policy_version: identity.policy_version,
        action: material.action,
        target: material.target,
        reason_code: material.reason_code,
        applied_at,
    };
    validate_fingerprint(raw.fingerprint_hex, &record)?;
    Ok(record)
}

fn decode_identity(
    raw: &RawLedgerFields<'_>,
    expected_tenant: &TenantId,
) -> Result<DecodedIdentity, StorageError> {
    Ok(DecodedIdentity {
        tenant_id: parse_tenant(raw.tenant_id, expected_tenant)?,
        command_id: AdminCommandId::parse(raw.command_id).map_err(|_| integrity_failure())?,
        decision_id: DecisionId::parse(raw.decision_id).map_err(|_| integrity_failure())?,
        actor_id: PrincipalId::parse(raw.actor_id).map_err(|_| integrity_failure())?,
        policy_version: decode_policy_version(raw.policy_version)?,
    })
}

fn decode_command_material(
    raw: &RawLedgerFields<'_>,
) -> Result<DecodedCommandMaterial, StorageError> {
    let action = decode_action(raw.action)?;
    let target = decode_target(raw.target_kind, raw.target_parent_id, raw.target_id)?;
    validate_action_target(action, target.kind())?;
    Ok(DecodedCommandMaterial {
        action,
        target,
        reason_code: decode_reason_code(raw.reason_code)?,
    })
}

fn raw_fields(row: &Row) -> Result<RawLedgerFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant_id),
        SqlValue::Text(command_id),
        SqlValue::Text(decision_id),
        SqlValue::Text(actor_id),
        SqlValue::Text(policy_version),
        SqlValue::Text(action),
        SqlValue::Text(target_kind),
        target_parent_id,
        SqlValue::Text(target_id),
        SqlValue::Text(reason_code),
        SqlValue::Text(fingerprint_hex),
        SqlValue::Int64(evaluated_at),
        SqlValue::Text(request_id),
        applied_at,
        SqlValue::Text(state),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(RawLedgerFields {
        tenant_id,
        command_id,
        decision_id,
        actor_id,
        policy_version,
        action,
        target_kind,
        target_parent_id,
        target_id,
        reason_code,
        fingerprint_hex,
        evaluated_at: *evaluated_at,
        request_id,
        applied_at,
        state,
    })
}

fn parse_tenant(value: &str, expected: &TenantId) -> Result<TenantId, StorageError> {
    let tenant = TenantId::parse(value).map_err(|_| integrity_failure())?;
    if tenant != *expected {
        return Err(integrity_failure());
    }
    Ok(tenant)
}

fn decode_policy_version(value: &str) -> Result<PolicyVersion, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let parsed = value.parse::<u64>().map_err(|_| integrity_failure())?;
    let version = PolicyVersion::new(parsed).map_err(|_| integrity_failure())?;
    if fingerprint::encode_policy_version(version) != value {
        return Err(integrity_failure());
    }
    Ok(version)
}

fn decode_action(value: &str) -> Result<AdminActionKind, StorageError> {
    match value {
        "suspend_user" => Ok(AdminActionKind::SuspendUser),
        "restore_user" => Ok(AdminActionKind::RestoreUser),
        "freeze_organization" => Ok(AdminActionKind::FreezeOrganization),
        "unfreeze_organization" => Ok(AdminActionKind::UnfreezeOrganization),
        "revoke_invitation" => Ok(AdminActionKind::RevokeInvitation),
        "revoke_api_key" => Ok(AdminActionKind::RevokeApiKey),
        _ => Err(integrity_failure()),
    }
}

fn decode_target(kind: &str, parent: &SqlValue, id: &str) -> Result<AdminTarget, StorageError> {
    match kind {
        "user" => decode_user_target(parent, id),
        "organization" => decode_organization_target(parent, id),
        "invitation" => decode_invitation_target(parent, id),
        "api_key" => decode_api_key_target(parent, id),
        _ => Err(integrity_failure()),
    }
}

fn decode_user_target(parent: &SqlValue, id: &str) -> Result<AdminTarget, StorageError> {
    require_no_parent(parent)?;
    UserId::parse(id)
        .map(AdminTarget::User)
        .map_err(|_| integrity_failure())
}

fn decode_organization_target(parent: &SqlValue, id: &str) -> Result<AdminTarget, StorageError> {
    require_no_parent(parent)?;
    OrganizationId::parse(id)
        .map(AdminTarget::Organization)
        .map_err(|_| integrity_failure())
}

fn decode_invitation_target(parent: &SqlValue, id: &str) -> Result<AdminTarget, StorageError> {
    let SqlValue::Text(organization_id) = parent else {
        return Err(integrity_failure());
    };
    Ok(AdminTarget::Invitation {
        organization_id: OrganizationId::parse(organization_id).map_err(|_| integrity_failure())?,
        invitation_id: InvitationId::parse(id).map_err(|_| integrity_failure())?,
    })
}

fn decode_api_key_target(parent: &SqlValue, id: &str) -> Result<AdminTarget, StorageError> {
    require_no_parent(parent)?;
    ApiKeyId::parse(id)
        .map(AdminTarget::ApiKey)
        .map_err(|_| integrity_failure())
}

fn require_no_parent(value: &SqlValue) -> Result<(), StorageError> {
    if !matches!(value, SqlValue::Null) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_action_target(
    action: AdminActionKind,
    target: AdminTargetKind,
) -> Result<(), StorageError> {
    let valid = match action {
        AdminActionKind::SuspendUser | AdminActionKind::RestoreUser => {
            target == AdminTargetKind::User
        }
        AdminActionKind::FreezeOrganization | AdminActionKind::UnfreezeOrganization => {
            target == AdminTargetKind::Organization
        }
        AdminActionKind::RevokeInvitation => target == AdminTargetKind::Invitation,
        AdminActionKind::RevokeApiKey => target == AdminTargetKind::ApiKey,
    };
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn decode_reason_code(value: &str) -> Result<Box<str>, StorageError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_REASON_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    valid
        .then(|| Box::<str>::from(value))
        .ok_or_else(integrity_failure)
}

fn decode_applied_at(
    state: &str,
    value: &SqlValue,
    evaluated_at: i64,
) -> Result<UtcTimestamp, StorageError> {
    let ("applied", SqlValue::Int64(applied_at)) = (state, value) else {
        return Err(integrity_failure());
    };
    if *applied_at < evaluated_at {
        return Err(integrity_failure());
    }
    Ok(UtcTimestamp::from_unix_seconds(*applied_at))
}

fn validate_fingerprint(value: &str, record: &LedgerRecord) -> Result<(), StorageError> {
    if !valid_fingerprint_hex(value) {
        return Err(integrity_failure());
    }
    let material = fingerprint::StableMaterial {
        command_id: record.command_id.as_str(),
        tenant_id: record.tenant_id.as_str(),
        actor_id: record.actor_id.as_str(),
        decision_id: record.decision_id.as_str(),
        policy_version: record.policy_version,
        action: record.action,
        target: &record.target,
        reason_code: &record.reason_code,
    };
    if fingerprint::fingerprint(&material) != value {
        return Err(integrity_failure());
    }
    Ok(())
}

fn valid_fingerprint_hex(value: &str) -> bool {
    value.len() == FINGERPRINT_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity_failure()),
    }
}

fn validate_columns(columns: &[ColumnSchema]) -> Result<(), StorageError> {
    let expected = [
        ("tenant_id", SqlType::Text),
        ("command_id", SqlType::Text),
        ("decision_id", SqlType::Text),
        ("actor_id", SqlType::Text),
        ("policy_version", SqlType::Text),
        ("action", SqlType::Text),
        ("target_kind", SqlType::Text),
        ("target_parent_id", SqlType::Text),
        ("target_id", SqlType::Text),
        ("reason_code", SqlType::Text),
        ("fingerprint_hex", SqlType::Text),
        ("evaluated_at", SqlType::Int64),
        ("request_id", SqlType::Text),
        ("applied_at", SqlType::Int64),
        ("state", SqlType::Text),
    ];
    let valid = columns.len() == expected.len()
        && columns.iter().zip(expected).all(|(column, expected)| {
            column.name() == expected.0 && column.data_type() == &expected.1
        });
    valid.then_some(()).ok_or_else(integrity_failure)
}

const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

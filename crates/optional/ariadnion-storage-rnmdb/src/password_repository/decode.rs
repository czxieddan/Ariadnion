// crates/optional/ariadnion-storage-rnmdb/src/password_repository/decode.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Strict bounded decoding for password credentials and reset history.

use ariadnion_auth_password::{
    PasswordCredential, PasswordCredentialSnapshot, PasswordCredentialSubject,
    PasswordCredentialVersion, PasswordHashPolicyVersion, PasswordHashRecord,
    PasswordHashRecordDigest, PasswordReset, PasswordResetEventKind, PasswordResetId,
    PasswordResetPurpose, PasswordResetSnapshot, PasswordResetState, PasswordResetSubject,
    PasswordResetTokenDigest, PasswordResetValidityWindow, PasswordResetVersion,
};
use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use super::{CommitRequest, integrity_failure, sql};

const VERSION_TEXT_BYTES: usize = 20;
const DIGEST_TEXT_BYTES: usize = 64;

pub(super) struct LoadedReset {
    pub(super) reset: PasswordReset,
    events: Vec<PersistedEvent>,
    evidence: Vec<PersistedCommitEvidence>,
}

pub(super) fn load_credential(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
) -> Result<PasswordCredential, StorageError> {
    let batch = rows(sql::load_credential(session, tenant, user)?)?;
    let row = one_row(&batch, &credential_columns())?;
    decode_credential(row, tenant, user)
}

pub(super) fn load_reset(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    reset: &PasswordResetId,
) -> Result<PasswordReset, StorageError> {
    load_reset_with_history(session, tenant, user, reset).map(|loaded| loaded.reset)
}

pub(super) fn load_reset_with_history(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    reset: &PasswordResetId,
) -> Result<LoadedReset, StorageError> {
    let batch = rows(sql::load_reset_by_id(session, tenant, user, reset)?)?;
    let row = one_row(&batch, &reset_columns())?;
    let decoded = decode_reset_fields(row, tenant, user)?;
    if &decoded.reset_id != reset {
        return Err(integrity_failure());
    }
    load_history(session, decoded)
}

pub(super) fn load_reset_by_token(
    session: &mut LocalSession,
    tenant: &TenantId,
    user: &UserId,
    token: PasswordResetTokenDigest,
) -> Result<PasswordReset, StorageError> {
    let batch = rows(sql::load_reset_by_token(session, tenant, user, token)?)?;
    let row = one_row(&batch, &reset_columns())?;
    let decoded = decode_reset_fields(row, tenant, user)?;
    if decoded.token_digest != token {
        return Err(integrity_failure());
    }
    load_history(session, decoded).map(|loaded| loaded.reset)
}

pub(super) fn ensure_issuance_absent(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let batch = rows(sql::load_issuance_collisions(session, request)?)?;
    validate_columns(batch.columns(), &collision_columns())?;
    if batch.rows().len() > 2 {
        return Err(integrity_failure());
    }
    classify_collisions(session, request, batch.rows())
}

pub(super) fn verify_target_records(
    request: &CommitRequest<'_>,
    loaded: &LoadedReset,
) -> Result<(), StorageError> {
    let index = event_index(request.transition().reset().version())?;
    let event_matches = loaded
        .events
        .get(index)
        .is_some_and(|event| event.matches(request));
    let evidence_matches = loaded
        .evidence
        .get(index)
        .is_some_and(|evidence| evidence.matches(request));
    if event_matches && evidence_matches {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn load_history(
    session: &mut LocalSession,
    fields: ResetFields,
) -> Result<LoadedReset, StorageError> {
    let evidence = decode_evidence(
        sql::load_commit_evidence(session, &fields.tenant, &fields.user, &fields.reset_id)?,
        &fields.tenant,
        &fields.user,
        &fields.reset_id,
    )?;
    let issued_version = evidence
        .first()
        .map(|value| value.issued_credential_version)
        .ok_or_else(integrity_failure)?;
    let reset = fields.into_reset(issued_version)?;
    let events = decode_events(
        sql::load_events(session, reset.tenant_id(), reset.user_id(), reset.id())?,
        &reset,
    )?;
    verify_history(&reset, &events, &evidence)?;
    Ok(LoadedReset {
        reset,
        events,
        evidence,
    })
}

fn decode_credential(
    row: &Row,
    tenant: &TenantId,
    user: &UserId,
) -> Result<PasswordCredential, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_user),
        SqlValue::Text(version),
        SqlValue::Text(policy_version),
        SqlValue::Text(phc_record),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_boundary(found_tenant, found_user, tenant, user)?;
    let snapshot = PasswordCredentialSnapshot {
        subject: PasswordCredentialSubject::new(tenant.clone(), user.clone()),
        version: decode_credential_version(version)?,
        hash_policy_version: decode_policy_version(policy_version)?,
        hash_record: PasswordHashRecord::parse(phc_record).map_err(|_| integrity_failure())?,
    };
    PasswordCredential::from_snapshot(snapshot).map_err(|_| integrity_failure())
}

fn decode_reset_fields(
    row: &Row,
    tenant: &TenantId,
    user: &UserId,
) -> Result<ResetFields, StorageError> {
    let fields = reset_row_fields(row)?;
    validate_boundary(fields.tenant, fields.user, tenant, user)?;
    decode_reset_values(fields, tenant, user)
}

struct ResetRowFields<'a> {
    tenant: &'a str,
    user: &'a str,
    reset_id: &'a str,
    token_digest: &'a str,
    issued_at: i64,
    expires_at: i64,
    version: &'a str,
    purpose: &'a str,
    state: &'a str,
    password_hash_digest: &'a SqlValue,
}

fn reset_row_fields(row: &Row) -> Result<ResetRowFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(user),
        SqlValue::Text(reset_id),
        SqlValue::Text(token_digest),
        SqlValue::Int64(issued_at),
        SqlValue::Int64(expires_at),
        SqlValue::Text(version),
        SqlValue::Text(purpose),
        SqlValue::Text(state),
        password_hash_digest,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(ResetRowFields {
        tenant,
        user,
        reset_id,
        token_digest,
        issued_at: *issued_at,
        expires_at: *expires_at,
        version,
        purpose,
        state,
        password_hash_digest,
    })
}

fn decode_reset_values(
    fields: ResetRowFields<'_>,
    tenant: &TenantId,
    user: &UserId,
) -> Result<ResetFields, StorageError> {
    let reset_id = PasswordResetId::parse(fields.reset_id).map_err(|_| integrity_failure())?;
    let token_digest = PasswordResetTokenDigest::from_bytes(decode_digest(fields.token_digest)?);
    let issued_at = UtcTimestamp::from_unix_seconds(fields.issued_at);
    let expires_at = UtcTimestamp::from_unix_seconds(fields.expires_at);
    let version = decode_reset_version(fields.version)?;
    let purpose = decode_purpose(fields.purpose)?;
    let state = decode_state(fields.state)?;
    let password_hash_digest = decode_optional_digest(fields.password_hash_digest)?;
    Ok(ResetFields {
        tenant: tenant.clone(),
        user: user.clone(),
        reset_id,
        token_digest,
        issued_at,
        expires_at,
        version,
        purpose,
        state,
        password_hash_digest,
    })
}

struct ResetFields {
    tenant: TenantId,
    user: UserId,
    reset_id: PasswordResetId,
    token_digest: PasswordResetTokenDigest,
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
    version: PasswordResetVersion,
    purpose: PasswordResetPurpose,
    state: PasswordResetState,
    password_hash_digest: Option<PasswordHashRecordDigest>,
}

impl ResetFields {
    fn into_reset(
        self,
        issued_credential_version: PasswordCredentialVersion,
    ) -> Result<PasswordReset, StorageError> {
        PasswordReset::from_snapshot(PasswordResetSnapshot {
            reset_id: self.reset_id,
            subject: PasswordResetSubject::new(self.tenant, self.user),
            token_digest: self.token_digest,
            issued_credential_version,
            validity: PasswordResetValidityWindow::new(self.issued_at, self.expires_at),
            version: self.version,
            purpose: self.purpose,
            state: self.state,
            password_hash_digest: self.password_hash_digest,
        })
        .map_err(|_| integrity_failure())
    }
}

#[derive(Clone)]
struct PersistedEvent {
    version: PasswordResetVersion,
    kind: PasswordResetEventKind,
    occurred_at: UtcTimestamp,
    actor: PrincipalId,
    purpose: PasswordResetPurpose,
    password_hash_digest: Option<PasswordHashRecordDigest>,
}

impl PersistedEvent {
    fn matches(&self, request: &CommitRequest<'_>) -> bool {
        let event = request.transition().event();
        (
            self.version,
            self.kind,
            self.occurred_at,
            &self.actor,
            self.purpose,
            self.password_hash_digest,
        ) == (
            event.version(),
            event.kind(),
            event.occurred_at(),
            event.actor(),
            event.purpose(),
            event.password_hash_digest(),
        )
    }
}

#[derive(Clone)]
struct PersistedCommitEvidence {
    version: PasswordResetVersion,
    request_id: RequestId,
    issued_credential_version: PasswordCredentialVersion,
    resulting_credential_version: Option<PasswordCredentialVersion>,
    resulting_hash_policy_version: Option<PasswordHashPolicyVersion>,
    password_hash_digest: Option<PasswordHashRecordDigest>,
}

impl PersistedCommitEvidence {
    fn matches(&self, request: &CommitRequest<'_>) -> bool {
        let event = request.transition().event();
        let replacement = request.commit.credential_replacement();
        (
            self.version,
            &self.request_id,
            self.issued_credential_version,
            self.resulting_credential_version,
            self.resulting_hash_policy_version,
            self.password_hash_digest,
        ) == (
            event.version(),
            request.context.request_id(),
            event.issued_credential_version(),
            replacement.map(|value| value.resulting_version()),
            replacement.map(|value| value.resulting_hash_policy_version()),
            event.password_hash_digest(),
        )
    }
}

fn decode_events(
    output: CommandOutput,
    reset: &PasswordReset,
) -> Result<Vec<PersistedEvent>, StorageError> {
    let batch = rows(output)?;
    validate_columns(batch.columns(), &event_columns())?;
    if batch.rows().len() > 2 {
        return Err(integrity_failure());
    }
    batch
        .rows()
        .iter()
        .map(|row| decode_event(row, reset))
        .collect()
}

fn decode_event(row: &Row, reset: &PasswordReset) -> Result<PersistedEvent, StorageError> {
    let fields = event_row_fields(row)?;
    validate_reset_identity(fields.tenant, fields.user, fields.reset_id, reset)?;
    decode_event_values(fields)
}

struct EventRowFields<'a> {
    tenant: &'a str,
    user: &'a str,
    reset_id: &'a str,
    version: &'a str,
    kind: &'a str,
    occurred_at: i64,
    actor: &'a str,
    purpose: &'a str,
    password_hash_digest: &'a SqlValue,
}

fn event_row_fields(row: &Row) -> Result<EventRowFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(user),
        SqlValue::Text(reset_id),
        SqlValue::Text(version),
        SqlValue::Text(kind),
        SqlValue::Int64(occurred_at),
        SqlValue::Text(actor),
        SqlValue::Text(purpose),
        password_hash_digest,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(EventRowFields {
        tenant,
        user,
        reset_id,
        version,
        kind,
        occurred_at: *occurred_at,
        actor,
        purpose,
        password_hash_digest,
    })
}

fn decode_event_values(fields: EventRowFields<'_>) -> Result<PersistedEvent, StorageError> {
    let version = decode_reset_version(fields.version)?;
    let kind = decode_event_kind(fields.kind)?;
    let occurred_at = UtcTimestamp::from_unix_seconds(fields.occurred_at);
    let actor = PrincipalId::parse(fields.actor).map_err(|_| integrity_failure())?;
    let purpose = decode_purpose(fields.purpose)?;
    let password_hash_digest = decode_optional_digest(fields.password_hash_digest)?;
    Ok(PersistedEvent {
        version,
        kind,
        occurred_at,
        actor,
        purpose,
        password_hash_digest,
    })
}

fn decode_evidence(
    output: CommandOutput,
    tenant: &TenantId,
    user: &UserId,
    reset: &PasswordResetId,
) -> Result<Vec<PersistedCommitEvidence>, StorageError> {
    let batch = rows(output)?;
    validate_columns(batch.columns(), &evidence_columns())?;
    if batch.rows().len() > 2 {
        return Err(integrity_failure());
    }
    batch
        .rows()
        .iter()
        .map(|row| decode_evidence_row(row, tenant, user, reset))
        .collect()
}

fn decode_evidence_row(
    row: &Row,
    expected_tenant: &TenantId,
    expected_user: &UserId,
    expected_reset: &PasswordResetId,
) -> Result<PersistedCommitEvidence, StorageError> {
    let fields = evidence_fields(row)?;
    validate_evidence_identity(&fields, expected_tenant, expected_user, expected_reset)?;
    decode_evidence_values(fields)
}

fn validate_evidence_identity(
    fields: &EvidenceFields<'_>,
    expected_tenant: &TenantId,
    expected_user: &UserId,
    expected_reset: &PasswordResetId,
) -> Result<(), StorageError> {
    let valid = fields.tenant == expected_tenant.as_str()
        && fields.user == expected_user.as_str()
        && fields.reset_id == expected_reset.as_str();
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn decode_evidence_values(
    fields: EvidenceFields<'_>,
) -> Result<PersistedCommitEvidence, StorageError> {
    Ok(PersistedCommitEvidence {
        version: decode_reset_version(fields.version)?,
        request_id: RequestId::parse(fields.request_id).map_err(|_| integrity_failure())?,
        issued_credential_version: decode_credential_version(fields.issued_version)?,
        resulting_credential_version: decode_optional_credential_version(fields.resulting_version)?,
        resulting_hash_policy_version: decode_optional_policy_version(fields.resulting_policy)?,
        password_hash_digest: decode_optional_digest(fields.password_hash_digest)?,
    })
}

struct EvidenceFields<'a> {
    tenant: &'a str,
    user: &'a str,
    reset_id: &'a str,
    version: &'a str,
    request_id: &'a str,
    issued_version: &'a str,
    resulting_version: &'a SqlValue,
    resulting_policy: &'a SqlValue,
    password_hash_digest: &'a SqlValue,
}

fn evidence_fields(row: &Row) -> Result<EvidenceFields<'_>, StorageError> {
    let (identity, transition) = row.values().split_at(5);
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(user),
        SqlValue::Text(reset_id),
        SqlValue::Text(version),
        SqlValue::Text(request_id),
    ] = identity
    else {
        return Err(integrity_failure());
    };
    let [
        SqlValue::Text(issued_version),
        resulting_version,
        resulting_policy,
        password_hash_digest,
    ] = transition
    else {
        return Err(integrity_failure());
    };
    Ok(EvidenceFields {
        tenant,
        user,
        reset_id,
        version,
        request_id,
        issued_version,
        resulting_version,
        resulting_policy,
        password_hash_digest,
    })
}

fn verify_history(
    reset: &PasswordReset,
    events: &[PersistedEvent],
    evidence: &[PersistedCommitEvidence],
) -> Result<(), StorageError> {
    let expected = usize::try_from(reset.version().get()).map_err(|_| integrity_failure())?;
    if events.len() != expected || evidence.len() != expected {
        return Err(integrity_failure());
    }
    for (index, (event, commit)) in events.iter().zip(evidence).enumerate() {
        verify_history_entry(reset, index, event, commit)?;
    }
    verify_terminal_history(reset, events)
}

fn verify_history_entry(
    reset: &PasswordReset,
    index: usize,
    event: &PersistedEvent,
    evidence: &PersistedCommitEvidence,
) -> Result<(), StorageError> {
    let expected_version = expected_history_version(index)?;
    verify_history_bindings(reset, expected_version, event, evidence)?;
    verify_evidence_result(reset, event.kind, evidence)
}

fn expected_history_version(index: usize) -> Result<PasswordResetVersion, StorageError> {
    let one_based = u64::try_from(index).map_err(|_| integrity_failure())? + 1;
    PasswordResetVersion::new(one_based).map_err(|_| integrity_failure())
}

fn verify_history_bindings(
    reset: &PasswordReset,
    expected_version: PasswordResetVersion,
    event: &PersistedEvent,
    evidence: &PersistedCommitEvidence,
) -> Result<(), StorageError> {
    let valid = event.version == expected_version
        && evidence.version == expected_version
        && event.purpose == PasswordResetPurpose::PasswordRecovery
        && evidence.issued_credential_version == reset.issued_credential_version()
        && event.password_hash_digest == evidence.password_hash_digest;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_evidence_result(
    reset: &PasswordReset,
    kind: PasswordResetEventKind,
    evidence: &PersistedCommitEvidence,
) -> Result<(), StorageError> {
    let valid = match kind {
        PasswordResetEventKind::Consumed => consumed_result_matches(reset, evidence)?,
        PasswordResetEventKind::Issued
        | PasswordResetEventKind::Revoked
        | PasswordResetEventKind::Expired => empty_result_matches(evidence),
    };
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn consumed_result_matches(
    reset: &PasswordReset,
    evidence: &PersistedCommitEvidence,
) -> Result<bool, StorageError> {
    let expected_version = reset
        .issued_credential_version()
        .next()
        .map_err(|_| integrity_failure())?;
    Ok(
        evidence.resulting_credential_version == Some(expected_version)
            && evidence.resulting_hash_policy_version.is_some()
            && evidence.password_hash_digest.is_some(),
    )
}

fn empty_result_matches(evidence: &PersistedCommitEvidence) -> bool {
    evidence.resulting_credential_version.is_none()
        && evidence.resulting_hash_policy_version.is_none()
        && evidence.password_hash_digest.is_none()
}

fn verify_terminal_history(
    reset: &PasswordReset,
    events: &[PersistedEvent],
) -> Result<(), StorageError> {
    let Some(first) = events.first() else {
        return Err(integrity_failure());
    };
    let issuance_valid = issuance_history_matches(reset, first);
    let terminal_valid = terminal_history_matches(reset, events.get(1));
    if issuance_valid && terminal_valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn issuance_history_matches(reset: &PasswordReset, event: &PersistedEvent) -> bool {
    event.kind == PasswordResetEventKind::Issued
        && event.occurred_at == reset.issued_at()
        && event.password_hash_digest.is_none()
}

fn terminal_history_matches(reset: &PasswordReset, event: Option<&PersistedEvent>) -> bool {
    match event {
        None => reset.state() == PasswordResetState::Issued,
        Some(event) => terminal_matches(reset, event),
    }
}

fn terminal_matches(reset: &PasswordReset, event: &PersistedEvent) -> bool {
    let lifecycle = matches!(
        (reset.state(), event.kind),
        (
            PasswordResetState::Consumed,
            PasswordResetEventKind::Consumed
        ) | (PasswordResetState::Revoked, PasswordResetEventKind::Revoked)
            | (PasswordResetState::Expired, PasswordResetEventKind::Expired)
    );
    lifecycle
        && terminal_time_matches(reset, event)
        && event.password_hash_digest == reset.password_hash_digest()
}

fn terminal_time_matches(reset: &PasswordReset, event: &PersistedEvent) -> bool {
    match event.kind {
        PasswordResetEventKind::Consumed | PasswordResetEventKind::Revoked => {
            event.occurred_at >= reset.issued_at() && event.occurred_at < reset.expires_at()
        }
        PasswordResetEventKind::Expired => event.occurred_at >= reset.expires_at(),
        PasswordResetEventKind::Issued => false,
    }
}

fn classify_collisions(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    rows: &[Row],
) -> Result<(), StorageError> {
    let mut scan = CollisionScan::default();
    for row in rows {
        let collision = decode_collision(row, request.tenant_id)?;
        let classification = classify_collision_row(request, &collision);
        merge_collision(&mut scan, classification);
    }
    if scan.integrity_failure {
        return Err(integrity_failure());
    }
    classify_exact_id(session, request, scan.exact_id)
}

#[derive(Default)]
struct CollisionScan {
    exact_id: bool,
    integrity_failure: bool,
}

enum CollisionClass {
    ExactId,
    CrossUserExactId,
    TokenCollision,
    Unexplained,
}

fn classify_collision_row(request: &CommitRequest<'_>, collision: &Collision) -> CollisionClass {
    let target = request.transition().reset();
    match (
        collision.reset_id == *target.id(),
        collision.user_id == *request.user_id,
        collision.token_digest == target.token_digest(),
    ) {
        (true, true, _) => CollisionClass::ExactId,
        (true, false, _) => CollisionClass::CrossUserExactId,
        (false, _, true) => CollisionClass::TokenCollision,
        (false, _, false) => CollisionClass::Unexplained,
    }
}

fn merge_collision(scan: &mut CollisionScan, classification: CollisionClass) {
    match classification {
        CollisionClass::ExactId => scan.exact_id = true,
        CollisionClass::CrossUserExactId
        | CollisionClass::TokenCollision
        | CollisionClass::Unexplained => scan.integrity_failure = true,
    }
}

fn classify_exact_id(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    exact_id: bool,
) -> Result<(), StorageError> {
    if !exact_id {
        return Ok(());
    }
    let target = request.transition().reset();
    let _loaded =
        load_reset_with_history(session, request.tenant_id, request.user_id, target.id())?;
    Err(StorageError::new(StorageErrorCode::Conflict))
}

struct Collision {
    user_id: UserId,
    reset_id: PasswordResetId,
    token_digest: PasswordResetTokenDigest,
}

fn decode_collision(row: &Row, tenant: &TenantId) -> Result<Collision, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(user),
        SqlValue::Text(reset),
        SqlValue::Text(token),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    if found_tenant != tenant.as_str() {
        return Err(integrity_failure());
    }
    Ok(Collision {
        user_id: UserId::parse(user).map_err(|_| integrity_failure())?,
        reset_id: PasswordResetId::parse(reset).map_err(|_| integrity_failure())?,
        token_digest: PasswordResetTokenDigest::from_bytes(decode_digest(token)?),
    })
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

fn validate_reset_identity(
    tenant: &str,
    user: &str,
    reset_id: &str,
    reset: &PasswordReset,
) -> Result<(), StorageError> {
    let valid = tenant == reset.tenant_id().as_str()
        && user == reset.user_id().as_str()
        && reset_id == reset.id().as_str();
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn event_index(version: PasswordResetVersion) -> Result<usize, StorageError> {
    version
        .get()
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(integrity_failure)
}

fn decode_credential_version(value: &str) -> Result<PasswordCredentialVersion, StorageError> {
    PasswordCredentialVersion::new(decode_version_number(value)?).map_err(|_| integrity_failure())
}

fn decode_policy_version(value: &str) -> Result<PasswordHashPolicyVersion, StorageError> {
    PasswordHashPolicyVersion::new(decode_version_number(value)?).map_err(|_| integrity_failure())
}

fn decode_reset_version(value: &str) -> Result<PasswordResetVersion, StorageError> {
    PasswordResetVersion::new(decode_version_number(value)?).map_err(|_| integrity_failure())
}

fn decode_version_number(value: &str) -> Result<u64, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let parsed = value.parse::<u64>().map_err(|_| integrity_failure())?;
    if sql::encode_version(parsed) == value {
        Ok(parsed)
    } else {
        Err(integrity_failure())
    }
}

fn decode_optional_credential_version(
    value: &SqlValue,
) -> Result<Option<PasswordCredentialVersion>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(value) => decode_credential_version(value).map(Some),
        _ => Err(integrity_failure()),
    }
}

fn decode_optional_policy_version(
    value: &SqlValue,
) -> Result<Option<PasswordHashPolicyVersion>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(value) => decode_policy_version(value).map(Some),
        _ => Err(integrity_failure()),
    }
}

fn decode_digest(value: &str) -> Result<[u8; 32], StorageError> {
    if value.len() != DIGEST_TEXT_BYTES {
        return Err(integrity_failure());
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn decode_optional_digest(
    value: &SqlValue,
) -> Result<Option<PasswordHashRecordDigest>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(value) => decode_digest(value)
            .map(PasswordHashRecordDigest::from_bytes)
            .map(Some),
        _ => Err(integrity_failure()),
    }
}

fn hex_nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(integrity_failure()),
    }
}

fn decode_purpose(value: &str) -> Result<PasswordResetPurpose, StorageError> {
    match value {
        "password_recovery" => Ok(PasswordResetPurpose::PasswordRecovery),
        _ => Err(integrity_failure()),
    }
}

fn decode_state(value: &str) -> Result<PasswordResetState, StorageError> {
    match value {
        "issued" => Ok(PasswordResetState::Issued),
        "consumed" => Ok(PasswordResetState::Consumed),
        "revoked" => Ok(PasswordResetState::Revoked),
        "expired" => Ok(PasswordResetState::Expired),
        _ => Err(integrity_failure()),
    }
}

fn decode_event_kind(value: &str) -> Result<PasswordResetEventKind, StorageError> {
    match value {
        "issued" => Ok(PasswordResetEventKind::Issued),
        "consumed" => Ok(PasswordResetEventKind::Consumed),
        "revoked" => Ok(PasswordResetEventKind::Revoked),
        "expired" => Ok(PasswordResetEventKind::Expired),
        _ => Err(integrity_failure()),
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

fn credential_columns() -> [(&'static str, SqlType); 5] {
    [
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("version", SqlType::Text),
        ("hash_policy_version", SqlType::Text),
        ("phc_record", SqlType::Text),
    ]
}

fn reset_columns() -> [(&'static str, SqlType); 10] {
    [
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("reset_id", SqlType::Text),
        ("token_digest_hex", SqlType::Text),
        ("issued_at", SqlType::Int64),
        ("expires_at", SqlType::Int64),
        ("version", SqlType::Text),
        ("purpose", SqlType::Text),
        ("state", SqlType::Text),
        ("password_hash_digest_hex", SqlType::Text),
    ]
}

fn event_columns() -> [(&'static str, SqlType); 9] {
    [
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("reset_id", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
        ("purpose", SqlType::Text),
        ("password_hash_digest_hex", SqlType::Text),
    ]
}

fn evidence_columns() -> [(&'static str, SqlType); 9] {
    [
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("reset_id", SqlType::Text),
        ("version", SqlType::Text),
        ("request_id", SqlType::Text),
        ("issued_credential_version", SqlType::Text),
        ("resulting_credential_version", SqlType::Text),
        ("resulting_hash_policy_version", SqlType::Text),
        ("password_hash_digest_hex", SqlType::Text),
    ]
}

fn collision_columns() -> [(&'static str, SqlType); 4] {
    [
        ("tenant_id", SqlType::Text),
        ("user_id", SqlType::Text),
        ("reset_id", SqlType::Text),
        ("token_digest_hex", SqlType::Text),
    ]
}

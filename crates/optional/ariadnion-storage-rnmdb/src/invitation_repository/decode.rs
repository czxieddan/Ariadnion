// crates/optional/ariadnion-storage-rnmdb/src/invitation_repository/decode.rs - Rust source for Ariadnion.
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
//! Strict bounded decoding for invitation snapshots.

pub(super) mod event;

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_invitation::{
    Invitation, InvitationId, InvitationIssueBinding, InvitationProofDigests,
    InvitationSnapshotState, InvitationState, InvitationSubjectDigest, InvitationTokenDigest,
    InvitationValidityWindow, InvitationVersion,
};
use ariadnion_organization::OrganizationId;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use super::{CommitRequest, integrity_failure, sql};

const VERSION_TEXT_BYTES: usize = 20;
const DIGEST_TEXT_BYTES: usize = 64;

pub(super) fn load_invitation(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    invitation: &InvitationId,
) -> Result<Invitation, StorageError> {
    load_invitation_with_history(session, tenant, organization, invitation)
        .map(|loaded| loaded.invitation)
}

pub(super) struct LoadedInvitation {
    pub(super) invitation: Invitation,
    pub(super) events: Vec<event::PersistedInvitationEvent>,
}

pub(super) fn load_invitation_with_history(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    invitation: &InvitationId,
) -> Result<LoadedInvitation, StorageError> {
    let batch = rows(sql::load_by_id(session, tenant, organization, invitation)?)?;
    let row = one_snapshot_row(&batch)?;
    let decoded = decode_snapshot(row, tenant, organization)?;
    if decoded.id() != invitation {
        return Err(integrity_failure());
    }
    let events = event::load_and_verify(session, &decoded)?;
    Ok(LoadedInvitation {
        invitation: decoded,
        events,
    })
}

pub(super) fn load_invitation_by_token(
    session: &mut LocalSession,
    tenant: &TenantId,
    organization: &OrganizationId,
    token: InvitationTokenDigest,
) -> Result<Invitation, StorageError> {
    let batch = rows(sql::load_by_token(session, tenant, organization, token)?)?;
    let decoded = decode_snapshot(one_snapshot_row(&batch)?, tenant, organization)?;
    if decoded.token_digest() != token {
        return Err(integrity_failure());
    }
    let _events = event::load_and_verify(session, &decoded)?;
    Ok(decoded)
}

pub(super) fn ensure_creation_absent(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    match creation_collision(session, request)? {
        CreationCollision::None => Ok(()),
        CreationCollision::ExactId => Err(StorageError::new(StorageErrorCode::Conflict)),
        CreationCollision::TokenDigest => Err(integrity_failure()),
    }
}

pub(super) fn classify_creation_insert_error(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    original: StorageError,
) -> Result<(), StorageError> {
    match creation_collision(session, request) {
        Ok(CreationCollision::ExactId) => Err(StorageError::new(StorageErrorCode::Conflict)),
        Ok(CreationCollision::TokenDigest) => Err(integrity_failure()),
        Err(error) if error.code() == StorageErrorCode::IntegrityFailure => Err(error),
        Ok(CreationCollision::None) | Err(_) => Err(original),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationCollision {
    None,
    ExactId,
    TokenDigest,
}

fn creation_collision(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<CreationCollision, StorageError> {
    let output = sql::load_creation_collisions(session, request)?;
    let batch = rows(output)?;
    validate_collision_columns(batch.columns())?;
    if batch.rows().len() > 2 {
        return Err(integrity_failure());
    }
    let collision = classify_collision_rows(batch.rows(), request)?;
    verify_exact_id_collision(session, request, collision)
}

fn classify_collision_rows(
    rows: &[Row],
    request: &CommitRequest<'_>,
) -> Result<CreationCollision, StorageError> {
    let mut collision = CreationCollision::None;
    for row in rows {
        collision = merge_creation_collision(collision, classify_collision_row(row, request)?)?;
    }
    Ok(collision)
}

fn merge_creation_collision(
    current: CreationCollision,
    candidate: CreationCollision,
) -> Result<CreationCollision, StorageError> {
    match (current, candidate) {
        (_, CreationCollision::None) => Err(integrity_failure()),
        (CreationCollision::TokenDigest, _) | (_, CreationCollision::TokenDigest) => {
            Ok(CreationCollision::TokenDigest)
        }
        (_, CreationCollision::ExactId) => Ok(CreationCollision::ExactId),
    }
}

fn classify_collision_row(
    row: &Row,
    request: &CommitRequest<'_>,
) -> Result<CreationCollision, StorageError> {
    let existing = decode_collision_row(row, request.tenant_id)?;
    let candidate = request.transition.invitation();
    let exact = existing.organization == request.organization_id.as_str()
        && existing.invitation.as_str() == candidate.id().as_str();
    if exact {
        return Ok(CreationCollision::ExactId);
    }
    if existing.token_digest == candidate.token_digest() {
        Ok(CreationCollision::TokenDigest)
    } else {
        Err(integrity_failure())
    }
}

fn verify_exact_id_collision(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    collision: CreationCollision,
) -> Result<CreationCollision, StorageError> {
    if collision == CreationCollision::ExactId {
        let invitation = request.transition.invitation();
        let _loaded = load_invitation_with_history(
            session,
            request.tenant_id,
            request.organization_id,
            invitation.id(),
        )?;
    }
    Ok(collision)
}

struct CollisionEvidence<'a> {
    organization: &'a str,
    invitation: InvitationId,
    token_digest: InvitationTokenDigest,
}

fn decode_collision_row<'a>(
    row: &'a Row,
    tenant: &TenantId,
) -> Result<CollisionEvidence<'a>, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(organization),
        SqlValue::Text(invitation),
        SqlValue::Text(token_digest),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    if found_tenant != tenant.as_str() {
        return Err(integrity_failure());
    }
    Ok(CollisionEvidence {
        organization,
        invitation: InvitationId::parse(invitation).map_err(|_| integrity_failure())?,
        token_digest: InvitationTokenDigest::new(decode_digest(token_digest)?),
    })
}

fn one_snapshot_row(batch: &VectorBatch) -> Result<&Row, StorageError> {
    validate_columns(batch.columns())?;
    match batch.rows() {
        [] => Err(StorageError::new(StorageErrorCode::NotFound)),
        [row] => Ok(row),
        _ => Err(integrity_failure()),
    }
}

fn decode_snapshot(
    row: &Row,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<Invitation, StorageError> {
    let fields = snapshot_fields(row)?;
    validate_boundary(fields.tenant, fields.organization, tenant, organization)?;
    decode_snapshot_fields(fields, tenant, organization)
}

struct SnapshotFields<'a> {
    tenant: &'a str,
    organization: &'a str,
    invitation: &'a str,
    issuer: &'a str,
    subject_digest: &'a str,
    token_digest: &'a str,
    issued_at: i64,
    expires_at: i64,
    version: &'a str,
    state: &'a str,
    consumed_by: &'a SqlValue,
}

fn snapshot_fields(row: &Row) -> Result<SnapshotFields<'_>, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(found_organization),
        SqlValue::Text(invitation),
        SqlValue::Text(issuer),
        SqlValue::Text(subject_digest),
        SqlValue::Text(token_digest),
        SqlValue::Int64(issued_at),
        SqlValue::Int64(expires_at),
        SqlValue::Text(version),
        SqlValue::Text(state),
        consumed_by,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(SnapshotFields {
        tenant: found_tenant,
        organization: found_organization,
        invitation,
        issuer,
        subject_digest,
        token_digest,
        issued_at: *issued_at,
        expires_at: *expires_at,
        version,
        state,
        consumed_by,
    })
}

fn decode_snapshot_fields(
    fields: SnapshotFields<'_>,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<Invitation, StorageError> {
    let snapshot = InvitationSnapshotState::new(
        InvitationIssueBinding::new(
            InvitationId::parse(fields.invitation).map_err(|_| integrity_failure())?,
            tenant.clone(),
            organization.clone(),
            PrincipalId::parse(fields.issuer).map_err(|_| integrity_failure())?,
        ),
        InvitationProofDigests::new(
            InvitationSubjectDigest::new(decode_digest(fields.subject_digest)?),
            InvitationTokenDigest::new(decode_digest(fields.token_digest)?),
        ),
        InvitationValidityWindow::new(
            UtcTimestamp::from_unix_seconds(fields.issued_at),
            UtcTimestamp::from_unix_seconds(fields.expires_at),
        ),
        decode_version(fields.version)?,
        decode_state(fields.state)?,
        decode_consumer(fields.consumed_by)?,
    );
    Invitation::from_snapshot(snapshot).map_err(|_| integrity_failure())
}

fn validate_boundary(
    found_tenant: &str,
    found_organization: &str,
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<(), StorageError> {
    if found_tenant == tenant.as_str() && found_organization == organization.as_str() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn decode_version(value: &str) -> Result<InvitationVersion, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let version = InvitationVersion::new(value.parse().map_err(|_| integrity_failure())?)
        .map_err(|_| integrity_failure())?;
    if sql::encode_version(version) != value {
        return Err(integrity_failure());
    }
    Ok(version)
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

fn hex_nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(integrity_failure()),
    }
}

fn decode_state(value: &str) -> Result<InvitationState, StorageError> {
    match value {
        "issued" => Ok(InvitationState::Issued),
        "consumed" => Ok(InvitationState::Consumed),
        "revoked" => Ok(InvitationState::Revoked),
        "expired" => Ok(InvitationState::Expired),
        _ => Err(integrity_failure()),
    }
}

fn decode_consumer(value: &SqlValue) -> Result<Option<UserId>, StorageError> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(value) => UserId::parse(value)
            .map(Some)
            .map_err(|_| integrity_failure()),
        _ => Err(integrity_failure()),
    }
}

fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity_failure()),
    }
}

fn validate_columns(columns: &[ColumnSchema]) -> Result<(), StorageError> {
    let expected = snapshot_columns();
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

fn validate_collision_columns(columns: &[ColumnSchema]) -> Result<(), StorageError> {
    let expected = [
        ("tenant_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("invitation_id", SqlType::Text),
        ("token_digest_hex", SqlType::Text),
    ];
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

fn snapshot_columns() -> [(&'static str, SqlType); 11] {
    [
        ("tenant_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("invitation_id", SqlType::Text),
        ("issuer_id", SqlType::Text),
        ("subject_digest_hex", SqlType::Text),
        ("token_digest_hex", SqlType::Text),
        ("issued_at", SqlType::Int64),
        ("expires_at", SqlType::Int64),
        ("version", SqlType::Text),
        ("state", SqlType::Text),
        ("consumed_by", SqlType::Text),
    ]
}

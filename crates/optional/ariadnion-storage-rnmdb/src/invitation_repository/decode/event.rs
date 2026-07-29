// crates/optional/ariadnion-storage-rnmdb/src/invitation_repository/decode/event.rs - Rust source for Ariadnion.
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
//! Strict decoding for the fixed two-event invitation lifecycle.

use ariadnion_core::{PrincipalId, RequestId};
use ariadnion_invitation::{
    Invitation, InvitationEventKind, InvitationState, InvitationTransition, InvitationVersion,
};
use ariadnion_storage_domain::StorageError;
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

use super::super::{integrity_failure, sql};

pub(in crate::invitation_repository) struct PersistedInvitationEvent {
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    version: InvitationVersion,
    kind: InvitationEventKind,
    request_id: RequestId,
    user_id: Option<UserId>,
}

impl PersistedInvitationEvent {
    pub(in crate::invitation_repository) const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub(in crate::invitation_repository) const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    pub(in crate::invitation_repository) const fn version(&self) -> InvitationVersion {
        self.version
    }

    pub(in crate::invitation_repository) const fn kind(&self) -> InvitationEventKind {
        self.kind
    }

    pub(in crate::invitation_repository) const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub(in crate::invitation_repository) const fn user_id(&self) -> Option<&UserId> {
        self.user_id.as_ref()
    }

    pub(in crate::invitation_repository) fn matches_transition(
        &self,
        transition: &InvitationTransition,
        request_id: &RequestId,
    ) -> bool {
        let event = transition.event();
        (
            self.actor(),
            self.occurred_at(),
            self.version(),
            self.kind(),
            self.request_id(),
            self.user_id(),
        ) == (
            event.actor(),
            event.occurred_at(),
            event.version(),
            event.kind(),
            request_id,
            event.user_id(),
        )
    }
}

pub(super) fn load_and_verify(
    session: &mut LocalSession,
    invitation: &Invitation,
) -> Result<Vec<PersistedInvitationEvent>, StorageError> {
    let output = sql::load_events(
        session,
        invitation.tenant_id(),
        invitation.organization_id(),
        invitation.id(),
    )?;
    let events = decode_events(output, invitation)?;
    verify_history(invitation, &events)?;
    Ok(events)
}

fn decode_events(
    output: CommandOutput,
    invitation: &Invitation,
) -> Result<Vec<PersistedInvitationEvent>, StorageError> {
    let batch = rows(output)?;
    validate_columns(batch.columns())?;
    if batch.rows().len() > 2 {
        return Err(integrity_failure());
    }
    batch
        .rows()
        .iter()
        .map(|row| decode_event(row, invitation))
        .collect()
}

fn decode_event(
    row: &Row,
    invitation: &Invitation,
) -> Result<PersistedInvitationEvent, StorageError> {
    let fields = event_fields(row)?;
    validate_identity(
        fields.tenant,
        fields.organization,
        fields.invitation_id,
        invitation,
    )?;
    Ok(PersistedInvitationEvent {
        actor: PrincipalId::parse(fields.actor).map_err(|_| integrity_failure())?,
        occurred_at: UtcTimestamp::from_unix_seconds(fields.occurred_at),
        version: decode_version(fields.version)?,
        kind: decode_kind(fields.kind)?,
        request_id: RequestId::parse(fields.request_id).map_err(|_| integrity_failure())?,
        user_id: decode_user(fields.user_id)?,
    })
}

struct EventFields<'a> {
    tenant: &'a str,
    organization: &'a str,
    invitation_id: &'a str,
    version: &'a str,
    kind: &'a str,
    occurred_at: i64,
    actor: &'a str,
    request_id: &'a str,
    user_id: &'a SqlValue,
}

fn event_fields(row: &Row) -> Result<EventFields<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(organization),
        SqlValue::Text(invitation_id),
        SqlValue::Text(version),
        SqlValue::Text(kind),
        SqlValue::Int64(occurred_at),
        SqlValue::Text(actor),
        SqlValue::Text(request_id),
        user_id,
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(EventFields {
        tenant,
        organization,
        invitation_id,
        version,
        kind,
        occurred_at: *occurred_at,
        actor,
        request_id,
        user_id,
    })
}

fn validate_identity(
    tenant: &str,
    organization: &str,
    invitation_id: &str,
    invitation: &Invitation,
) -> Result<(), StorageError> {
    let actual = (tenant, organization, invitation_id);
    let expected = (
        invitation.tenant_id().as_str(),
        invitation.organization_id().as_str(),
        invitation.id().as_str(),
    );
    if actual == expected {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_history(
    invitation: &Invitation,
    events: &[PersistedInvitationEvent],
) -> Result<(), StorageError> {
    let expected = usize::try_from(invitation.version().get()).map_err(|_| integrity_failure())?;
    if events.len() != expected {
        return Err(integrity_failure());
    }
    let (issued, remaining) = events.split_first().ok_or_else(integrity_failure)?;
    verify_issuance(invitation, issued)?;
    verify_history_tail(invitation, remaining)
}

fn verify_history_tail(
    invitation: &Invitation,
    remaining: &[PersistedInvitationEvent],
) -> Result<(), StorageError> {
    match remaining {
        [] if invitation.version() == InvitationVersion::initial() => Ok(()),
        [terminal] => verify_terminal(invitation, terminal),
        _ => Err(integrity_failure()),
    }
}

fn verify_issuance(
    invitation: &Invitation,
    event: &PersistedInvitationEvent,
) -> Result<(), StorageError> {
    let actual = (
        event.version(),
        event.kind(),
        event.actor(),
        event.occurred_at(),
        event.user_id(),
    );
    let expected = (
        InvitationVersion::initial(),
        InvitationEventKind::Issued,
        invitation.issuer(),
        invitation.issued_at(),
        None,
    );
    if actual == expected {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_terminal(
    invitation: &Invitation,
    event: &PersistedInvitationEvent,
) -> Result<(), StorageError> {
    let version_two = InvitationVersion::new(2).map_err(|_| integrity_failure())?;
    if event.version() != version_two || !terminal_matrix_matches(invitation, event) {
        return Err(integrity_failure());
    }
    validate_terminal_time(invitation, event)
}

fn terminal_matrix_matches(invitation: &Invitation, event: &PersistedInvitationEvent) -> bool {
    match (invitation.state(), event.kind()) {
        (InvitationState::Consumed, InvitationEventKind::Consumed) => {
            invitation.consumed_by() == event.user_id()
        }
        (InvitationState::Revoked, InvitationEventKind::Revoked)
        | (InvitationState::Expired, InvitationEventKind::Expired) => {
            invitation.consumed_by().is_none() && event.user_id().is_none()
        }
        _ => false,
    }
}

fn validate_terminal_time(
    invitation: &Invitation,
    event: &PersistedInvitationEvent,
) -> Result<(), StorageError> {
    let occurred_at = event.occurred_at();
    let valid = match event.kind() {
        InvitationEventKind::Consumed | InvitationEventKind::Revoked => {
            occurred_at >= invitation.issued_at() && occurred_at < invitation.expires_at()
        }
        InvitationEventKind::Expired => occurred_at >= invitation.expires_at(),
        InvitationEventKind::Issued => false,
    };
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn decode_version(value: &str) -> Result<InvitationVersion, StorageError> {
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let version = InvitationVersion::new(value.parse().map_err(|_| integrity_failure())?)
        .map_err(|_| integrity_failure())?;
    if sql::encode_version(version) == value {
        Ok(version)
    } else {
        Err(integrity_failure())
    }
}

fn decode_kind(value: &str) -> Result<InvitationEventKind, StorageError> {
    match value {
        "issued" => Ok(InvitationEventKind::Issued),
        "consumed" => Ok(InvitationEventKind::Consumed),
        "revoked" => Ok(InvitationEventKind::Revoked),
        "expired" => Ok(InvitationEventKind::Expired),
        _ => Err(integrity_failure()),
    }
}

fn decode_user(value: &SqlValue) -> Result<Option<UserId>, StorageError> {
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
    let expected = event_columns();
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

fn event_columns() -> [(&'static str, SqlType); 9] {
    [
        ("tenant_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("invitation_id", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
        ("request_id", SqlType::Text),
        ("user_id", SqlType::Text),
    ]
}

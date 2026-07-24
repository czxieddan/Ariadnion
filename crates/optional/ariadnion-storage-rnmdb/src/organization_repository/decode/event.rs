//! Strict nullable-matrix decoding for organization events.

use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_organization::{
    CreateOrganizationCommand, MembershipId, MembershipKind, MembershipOrigin, Organization,
    OrganizationEvent, OrganizationEventKind, OrganizationFounder, OrganizationId,
    OrganizationVersion, OwnershipTransferId, TeamId, create_organization,
};
use ariadnion_storage_domain::StorageError;
use ariadnion_user_domain::{UserId, UtcTimestamp};
use rnmdb_executor::vector::Row;
use rnmdb_types::{SqlType, SqlValue};

use super::{decode_version, optional_i64, optional_text};
use crate::organization_repository::integrity_failure;

pub(super) struct PersistedOrganizationEvent {
    pub(super) event: OrganizationEvent,
    request_id: RequestId,
}

impl PersistedOrganizationEvent {
    pub(super) fn replay_creation(&self) -> Result<Organization, StorageError> {
        let OrganizationEventKind::Created {
            founder_membership_id,
            founder_user_id,
        } = self.event.kind()
        else {
            return Err(integrity_failure());
        };
        let transition = create_organization(CreateOrganizationCommand::new(
            self.event.organization_id().clone(),
            self.event.tenant_id().clone(),
            OrganizationFounder::new(founder_membership_id.clone(), founder_user_id.clone()),
            OrganizationVersion::initial(),
            self.event.actor().clone(),
            self.event.occurred_at(),
        ))
        .map_err(|_| integrity_failure())?;
        Ok(transition.into_parts().0)
    }

    pub(super) const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub(super) const fn event(&self) -> &OrganizationEvent {
        &self.event
    }
}

pub(super) fn decode_events(
    rows: &[Row],
    tenant: &TenantId,
    organization: &OrganizationId,
) -> Result<Vec<PersistedOrganizationEvent>, StorageError> {
    rows.iter()
        .enumerate()
        .map(|(index, row)| decode_event(row, tenant, organization, index))
        .collect()
}

fn decode_event(
    row: &Row,
    tenant: &TenantId,
    organization: &OrganizationId,
    index: usize,
) -> Result<PersistedOrganizationEvent, StorageError> {
    let values = EventValues::from_row(row)?;
    values.validate_identity(tenant, organization, index)?;
    let kind = values.decode_kind()?;
    values.into_event(kind)
}

impl EventValues<'_> {
    fn into_event(
        self,
        kind: OrganizationEventKind,
    ) -> Result<PersistedOrganizationEvent, StorageError> {
        let event = OrganizationEvent::from_persisted(
            TenantId::parse(self.tenant).map_err(|_| integrity_failure())?,
            OrganizationId::parse(self.organization).map_err(|_| integrity_failure())?,
            PrincipalId::parse(self.actor).map_err(|_| integrity_failure())?,
            UtcTimestamp::from_unix_seconds(self.occurred_at),
            decode_version(self.version)?,
            kind,
        )
        .map_err(|_| integrity_failure())?;
        Ok(PersistedOrganizationEvent {
            event,
            request_id: RequestId::parse(self.request).map_err(|_| integrity_failure())?,
        })
    }
}

struct EventValues<'a> {
    tenant: &'a str,
    organization: &'a str,
    version: &'a str,
    kind: &'a str,
    occurred_at: i64,
    actor: &'a str,
    request: &'a str,
    variant: [Option<&'a str>; 10],
    removed: Option<i64>,
    expires_at: Option<i64>,
}

impl<'a> EventValues<'a> {
    fn from_row(row: &'a Row) -> Result<Self, StorageError> {
        let [
            SqlValue::Text(tenant),
            SqlValue::Text(organization),
            SqlValue::Text(version),
            SqlValue::Text(kind),
            SqlValue::Int64(occurred_at),
            SqlValue::Text(actor),
            SqlValue::Text(request),
            _,
            _,
            _,
            removed,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            membership_expires_at,
        ] = row.values()
        else {
            return Err(integrity_failure());
        };
        let variant = decode_variant_values(&row.values()[7..=17])?;
        Ok(Self {
            tenant,
            organization,
            version,
            kind,
            occurred_at: *occurred_at,
            actor,
            request,
            variant,
            removed: optional_i64(removed)?,
            expires_at: optional_i64(membership_expires_at)?,
        })
    }

    fn validate_identity(
        &self,
        tenant: &TenantId,
        organization: &OrganizationId,
        index: usize,
    ) -> Result<(), StorageError> {
        let version = decode_version(self.version)?;
        let expected = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1));
        if self.tenant != tenant.as_str()
            || self.organization != organization.as_str()
            || expected != Some(version.get())
        {
            return Err(integrity_failure());
        }
        Ok(())
    }

    fn decode_kind(&self) -> Result<OrganizationEventKind, StorageError> {
        match self.kind {
            "created" | "state_changed" => self.decode_organization_kind(),
            "membership_added"
            | "membership_suspended"
            | "membership_activated"
            | "membership_left" => self.decode_membership_event_kind(),
            "team_created" | "team_assigned" => self.decode_team_kind(),
            "ownership_transferred" => self.ownership_transferred(),
            _ => Err(integrity_failure()),
        }
    }

    fn decode_organization_kind(&self) -> Result<OrganizationEventKind, StorageError> {
        match self.kind {
            "created" => self.created(),
            "state_changed" => self.state_changed(),
            _ => Err(integrity_failure()),
        }
    }

    fn decode_membership_event_kind(&self) -> Result<OrganizationEventKind, StorageError> {
        match self.kind {
            "membership_added" => self.membership_added(),
            "membership_suspended" => self.membership_suspended(),
            "membership_activated" => self.membership_activated(),
            "membership_left" => self.membership_left(),
            _ => Err(integrity_failure()),
        }
    }

    fn decode_team_kind(&self) -> Result<OrganizationEventKind, StorageError> {
        match self.kind {
            "team_created" => self.team_created(),
            "team_assigned" => self.team_assigned(),
            _ => Err(integrity_failure()),
        }
    }

    fn created(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[1, 8], false, false)?;
        Ok(OrganizationEventKind::Created {
            founder_membership_id: membership_id(self.variant[1])?,
            founder_user_id: user_id(self.variant[8])?,
        })
    }

    fn state_changed(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[0], false, false)?;
        let state = match self.variant[0] {
            Some("active") => ariadnion_organization::OrganizationState::Active,
            Some("frozen") => ariadnion_organization::OrganizationState::Frozen,
            _ => return Err(integrity_failure()),
        };
        Ok(OrganizationEventKind::StateChanged { state })
    }

    fn membership_added(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[1, 2, 8, 9], false, true)?;
        Ok(OrganizationEventKind::MembershipAdded {
            membership_id: membership_id(self.variant[1])?,
            user_id: user_id(self.variant[8])?,
            kind: membership_kind(self.variant[2])?,
            origin: membership_origin(self.variant[9])?,
            expires_at: self.expires_at.map(UtcTimestamp::from_unix_seconds),
        })
    }

    fn membership_suspended(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[1], true, false)?;
        Ok(OrganizationEventKind::MembershipSuspended {
            membership_id: membership_id(self.variant[1])?,
            removed_team_assignments: removed_count(self.removed)?,
        })
    }

    fn membership_activated(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[1], false, false)?;
        Ok(OrganizationEventKind::MembershipActivated {
            membership_id: membership_id(self.variant[1])?,
        })
    }

    fn membership_left(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[1], true, false)?;
        Ok(OrganizationEventKind::MembershipLeft {
            membership_id: membership_id(self.variant[1])?,
            removed_team_assignments: removed_count(self.removed)?,
        })
    }

    fn team_created(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[3], false, false)?;
        Ok(OrganizationEventKind::TeamCreated {
            team_id: team_id(self.variant[3])?,
        })
    }

    fn team_assigned(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[1, 3], false, false)?;
        Ok(OrganizationEventKind::TeamAssigned {
            membership_id: membership_id(self.variant[1])?,
            team_id: team_id(self.variant[3])?,
        })
    }

    fn ownership_transferred(&self) -> Result<OrganizationEventKind, StorageError> {
        self.require_only(&[4, 5, 6, 7], false, false)?;
        Ok(OrganizationEventKind::OwnershipTransferred {
            transfer_id: OwnershipTransferId::parse(required(self.variant[4])?)
                .map_err(|_| integrity_failure())?,
            previous_owner_id: membership_id(self.variant[5])?,
            new_owner_id: membership_id(self.variant[6])?,
            approver: PrincipalId::parse(required(self.variant[7])?)
                .map_err(|_| integrity_failure())?,
        })
    }

    fn require_only(
        &self,
        required_indexes: &[usize],
        removed_required: bool,
        expires_optional: bool,
    ) -> Result<(), StorageError> {
        for (index, value) in self.variant.iter().enumerate() {
            if value.is_some() != required_indexes.contains(&index) {
                return Err(integrity_failure());
            }
        }
        if self.removed.is_some() != removed_required
            || (!expires_optional && self.expires_at.is_some())
        {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

fn decode_variant_values(values: &[SqlValue]) -> Result<[Option<&str>; 10], StorageError> {
    let [
        organization_state,
        membership_id,
        membership_kind,
        _,
        team_id,
        transfer_id,
        previous_owner,
        new_owner,
        approver,
        membership_user,
        membership_origin,
    ] = values
    else {
        return Err(integrity_failure());
    };
    let leading = decode_leading_variants([
        organization_state,
        membership_id,
        membership_kind,
        team_id,
        transfer_id,
    ])?;
    let trailing = decode_trailing_variants([
        previous_owner,
        new_owner,
        approver,
        membership_user,
        membership_origin,
    ])?;
    Ok([
        leading[0],
        leading[1],
        leading[2],
        leading[3],
        leading[4],
        trailing[0],
        trailing[1],
        trailing[2],
        trailing[3],
        trailing[4],
    ])
}

fn decode_leading_variants(values: [&SqlValue; 5]) -> Result<[Option<&str>; 5], StorageError> {
    Ok([
        optional_text(values[0])?,
        optional_text(values[1])?,
        optional_text(values[2])?,
        optional_text(values[3])?,
        optional_text(values[4])?,
    ])
}

fn decode_trailing_variants(values: [&SqlValue; 5]) -> Result<[Option<&str>; 5], StorageError> {
    Ok([
        optional_text(values[0])?,
        optional_text(values[1])?,
        optional_text(values[2])?,
        optional_text(values[3])?,
        optional_text(values[4])?,
    ])
}

fn required(value: Option<&str>) -> Result<&str, StorageError> {
    value.ok_or_else(integrity_failure)
}

fn membership_id(value: Option<&str>) -> Result<MembershipId, StorageError> {
    MembershipId::parse(required(value)?).map_err(|_| integrity_failure())
}

fn user_id(value: Option<&str>) -> Result<UserId, StorageError> {
    UserId::parse(required(value)?).map_err(|_| integrity_failure())
}

fn team_id(value: Option<&str>) -> Result<TeamId, StorageError> {
    TeamId::parse(required(value)?).map_err(|_| integrity_failure())
}

fn membership_kind(value: Option<&str>) -> Result<MembershipKind, StorageError> {
    match value {
        Some("owner") => Ok(MembershipKind::Owner),
        Some("member") => Ok(MembershipKind::Member),
        _ => Err(integrity_failure()),
    }
}

fn membership_origin(value: Option<&str>) -> Result<MembershipOrigin, StorageError> {
    match value {
        Some("invitation") => Ok(MembershipOrigin::Invitation),
        Some("administrative") => Ok(MembershipOrigin::Administrative),
        _ => Err(integrity_failure()),
    }
}

fn removed_count(value: Option<i64>) -> Result<usize, StorageError> {
    usize::try_from(value.ok_or_else(integrity_failure)?).map_err(|_| integrity_failure())
}

pub(super) fn event_columns() -> [(&'static str, SqlType); 19] {
    [
        ("tenant_id", SqlType::Text),
        ("organization_id", SqlType::Text),
        ("version", SqlType::Text),
        ("kind", SqlType::Text),
        ("occurred_at", SqlType::Int64),
        ("actor_id", SqlType::Text),
        ("request_id", SqlType::Text),
        ("organization_state", SqlType::Text),
        ("membership_id", SqlType::Text),
        ("membership_kind", SqlType::Text),
        ("removed_team_assignments", SqlType::Int64),
        ("team_id", SqlType::Text),
        ("ownership_transfer_id", SqlType::Text),
        ("previous_owner_id", SqlType::Text),
        ("new_owner_id", SqlType::Text),
        ("approver_id", SqlType::Text),
        ("membership_user_id", SqlType::Text),
        ("membership_origin", SqlType::Text),
        ("membership_expires_at", SqlType::Int64),
    ]
}

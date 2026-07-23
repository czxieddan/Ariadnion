//! Exact optimistic-version reachability for persisted organization snapshots.

use crate::error::{OrganizationError, OrganizationErrorCode, error};
use crate::ids::OrganizationVersion;

use super::{
    MAX_TEAM_ASSIGNMENTS, MembershipKind, MembershipSnapshot, MembershipState,
    OrganizationSnapshot, OrganizationState,
};

pub(super) fn validate_version_reachability(
    version: OrganizationVersion,
    snapshot: &OrganizationSnapshot,
) -> Result<(), OrganizationError> {
    let minimum = minimum_snapshot_version(snapshot)?;
    let offset = version
        .get()
        .checked_sub(minimum)
        .ok_or_else(invalid_argument)?;
    if offset == 0 || offset % 2 == 0 {
        return Ok(());
    }
    if minimum_odd_cycle(snapshot).is_some_and(|cycle| offset >= cycle) {
        return Ok(());
    }
    Err(invalid_argument())
}

fn minimum_snapshot_version(snapshot: &OrganizationSnapshot) -> Result<u64, OrganizationError> {
    let mut minimum = 1_u64;
    minimum = add_version_cost(minimum, snapshot.memberships.len() - 1)?;
    minimum = add_version_cost(minimum, snapshot.teams.len())?;
    minimum = add_version_cost(minimum, membership_version_cost(snapshot)?)?;
    minimum = add_founder_kind_version_cost(minimum, snapshot)?;
    add_state_version_cost(minimum, snapshot.state)
}

fn add_founder_kind_version_cost(
    value: u64,
    snapshot: &OrganizationSnapshot,
) -> Result<u64, OrganizationError> {
    let founder_was_demoted = snapshot
        .memberships
        .first()
        .is_some_and(|membership| membership.kind() == MembershipKind::Member);
    if founder_was_demoted {
        return add_version_cost(value, 1);
    }
    Ok(value)
}

fn membership_version_cost(snapshot: &OrganizationSnapshot) -> Result<usize, OrganizationError> {
    let mut cost = 0_usize;
    for membership in &snapshot.memberships {
        cost = add_membership_version_cost(cost, membership)?;
    }
    Ok(cost)
}

fn add_membership_version_cost(
    cost: usize,
    membership: &MembershipSnapshot,
) -> Result<usize, OrganizationError> {
    let mut next = cost
        .checked_add(membership.team_ids().len())
        .ok_or_else(invalid_argument)?;
    if membership.state() != MembershipState::Active {
        next = next.checked_add(1).ok_or_else(invalid_argument)?;
    }
    Ok(next)
}

fn add_state_version_cost(value: u64, state: OrganizationState) -> Result<u64, OrganizationError> {
    if state == OrganizationState::Frozen {
        return add_version_cost(value, 1);
    }
    Ok(value)
}

fn add_version_cost(value: u64, cost: usize) -> Result<u64, OrganizationError> {
    let cost = u64::try_from(cost).map_err(|_| invalid_argument())?;
    value.checked_add(cost).ok_or_else(invalid_argument)
}

// Organization state always supplies a two-step round trip. Odd offsets need
// one reversible odd cycle, after which additional state round trips suffice.
fn minimum_odd_cycle(snapshot: &OrganizationSnapshot) -> Option<u64> {
    let mut minimum = ownership_odd_cycle(snapshot);
    for membership in &snapshot.memberships {
        if let Some(candidate) = membership_odd_cycle(snapshot, membership) {
            minimum = Some(minimum.map_or(candidate, |current| current.min(candidate)));
        }
    }
    minimum
}

fn ownership_odd_cycle(snapshot: &OrganizationSnapshot) -> Option<u64> {
    let mut participants = snapshot
        .memberships
        .iter()
        .filter(|membership| membership.expires_at().is_none());
    if participants.clone().count() < 3 {
        return None;
    }
    let has_owner = participants
        .clone()
        .any(|membership| membership.kind() == MembershipKind::Owner);
    let has_member = participants.any(|membership| membership.kind() == MembershipKind::Member);
    (has_owner && has_member).then_some(3)
}

fn membership_odd_cycle(
    snapshot: &OrganizationSnapshot,
    membership: &MembershipSnapshot,
) -> Option<u64> {
    match membership.state() {
        MembershipState::Active => active_membership_odd_cycle(snapshot, membership),
        // An inactive membership was active before its terminal transition. A
        // registered team permits assign-suspend-activate as a three-step loop.
        MembershipState::Suspended | MembershipState::Left => {
            (!snapshot.teams.is_empty()).then_some(3)
        }
    }
}

fn active_membership_odd_cycle(
    snapshot: &OrganizationSnapshot,
    membership: &MembershipSnapshot,
) -> Option<u64> {
    if !membership_can_suspend(snapshot, membership) {
        return None;
    }
    let assignments = membership.team_ids().len();
    if assignments % 2 == 1 {
        return u64::try_from(assignments.checked_add(2)?).ok();
    }
    let has_spare_team = assignments < MAX_TEAM_ASSIGNMENTS && snapshot.teams.len() > assignments;
    if has_spare_team {
        return u64::try_from(assignments.checked_add(3)?).ok();
    }
    None
}

fn membership_can_suspend(
    snapshot: &OrganizationSnapshot,
    membership: &MembershipSnapshot,
) -> bool {
    membership.kind() != MembershipKind::Owner || snapshot_active_owner_count(snapshot) > 1
}

fn snapshot_active_owner_count(snapshot: &OrganizationSnapshot) -> usize {
    snapshot
        .memberships
        .iter()
        .filter(|membership| {
            membership.kind() == MembershipKind::Owner
                && membership.state() == MembershipState::Active
        })
        .count()
}

fn invalid_argument() -> OrganizationError {
    error(OrganizationErrorCode::InvalidArgument)
}

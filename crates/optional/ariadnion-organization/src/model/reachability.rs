// crates/optional/ariadnion-organization/src/model/reachability.rs - Rust source for Ariadnion.
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
//! Exact optimistic-version reachability for persisted organization snapshots.

use crate::error::{OrganizationError, OrganizationErrorCode, error};
use crate::ids::OrganizationVersion;

use super::{
    MembershipKind, MembershipSnapshot, MembershipState, OrganizationSnapshot, OrganizationState,
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
    if minimum_odd_history_surcharge(snapshot).is_some_and(|cost| offset >= cost) {
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

// Organization state supplies every two-step round trip. An odd offset needs
// one odd historical surcharge before further state round trips are added.
fn minimum_odd_history_surcharge(snapshot: &OrganizationSnapshot) -> Option<u64> {
    let mut minimum = ownership_odd_surcharge(snapshot);
    let owner_count = snapshot_owner_count(snapshot);
    for membership in &snapshot.memberships {
        if let Some(candidate) = membership_odd_surcharge(snapshot, membership, owner_count) {
            minimum = Some(minimum.map_or(candidate, |current| current.min(candidate)));
        }
    }
    minimum
}

fn ownership_odd_surcharge(snapshot: &OrganizationSnapshot) -> Option<u64> {
    if supports_one_step_ownership_surcharge(snapshot) {
        return Some(1);
    }
    ownership_triangle_surcharge(snapshot)
}

fn supports_one_step_ownership_surcharge(snapshot: &OrganizationSnapshot) -> bool {
    let eligible_count = snapshot
        .memberships
        .iter()
        .filter(|membership| membership.expires_at().is_none())
        .count();
    if eligible_count < 3 {
        return false;
    }
    let founder_is_owner = snapshot
        .memberships
        .first()
        .is_some_and(|membership| membership.kind() == MembershipKind::Owner);
    if !founder_is_owner {
        return true;
    }
    let mut participants = snapshot
        .memberships
        .iter()
        .skip(1)
        .filter(|membership| membership.expires_at().is_none());
    let has_owner = participants
        .clone()
        .any(|membership| membership.kind() == MembershipKind::Owner);
    let has_member = participants.any(|membership| membership.kind() == MembershipKind::Member);
    has_owner && has_member
}

fn ownership_triangle_surcharge(snapshot: &OrganizationSnapshot) -> Option<u64> {
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

fn membership_odd_surcharge(
    snapshot: &OrganizationSnapshot,
    membership: &MembershipSnapshot,
    owner_count: usize,
) -> Option<u64> {
    if !membership_can_suspend(membership, owner_count) {
        return None;
    }
    match membership.state() {
        // The detour can run before the final assignment set is constructed.
        MembershipState::Active => (!snapshot.teams.is_empty()).then_some(3),
        // One transient assignment is cleared by the final suspension.
        MembershipState::Suspended => (!snapshot.teams.is_empty()).then_some(1),
        // Suspending before leaving costs one more step than leaving directly.
        MembershipState::Left => Some(1),
    }
}

fn membership_can_suspend(membership: &MembershipSnapshot, owner_count: usize) -> bool {
    membership.kind() != MembershipKind::Owner || owner_count > 1
}

fn snapshot_owner_count(snapshot: &OrganizationSnapshot) -> usize {
    snapshot
        .memberships
        .iter()
        .filter(|membership| membership.kind() == MembershipKind::Owner)
        .count()
}

fn invalid_argument() -> OrganizationError {
    error(OrganizationErrorCode::InvalidArgument)
}

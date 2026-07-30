// crates/optional/ariadnion-storage-rnmdb/src/authoritative_policy/target.rs - Rust source for Ariadnion.
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
//! Fail-closed mapping from administration aggregates to authorization state.

use ariadnion_api_admin::AdminTarget;
use ariadnion_auth_api_key::{ApiKey, ApiKeyState};
use ariadnion_core::TenantId;
use ariadnion_invitation::{Invitation, InvitationState};
use ariadnion_organization::{Organization, OrganizationState};
use ariadnion_rbac::ResourceState;
use ariadnion_storage_domain::StorageError;
use ariadnion_user_domain::{User, UserLifecycleState, UtcTimestamp};
use rnmdb_cli::LocalSession;

use crate::api_key_repository::load_api_key_in_session;
use crate::invitation_repository::load_invitation_in_session;
use crate::organization_repository::load_organization_in_session;
use crate::user_repository::load_user_in_session;

pub(super) enum LoadedAdminTarget {
    User(User),
    Organization(Organization),
    Invitation(Invitation),
    ApiKey(ApiKey),
}

impl LoadedAdminTarget {
    pub(super) fn load(
        session: &mut LocalSession,
        tenant: &TenantId,
        target: &AdminTarget,
    ) -> Result<Self, StorageError> {
        match target {
            AdminTarget::User(user_id) => {
                load_user_in_session(session, tenant, user_id).map(Self::User)
            }
            AdminTarget::Organization(organization_id) => {
                load_organization_in_session(session, tenant, organization_id)
                    .map(Self::Organization)
            }
            AdminTarget::Invitation {
                organization_id,
                invitation_id,
            } => load_invitation_in_session(session, tenant, organization_id, invitation_id)
                .map(Self::Invitation),
            AdminTarget::ApiKey(api_key_id) => {
                load_api_key_in_session(session, tenant, api_key_id).map(Self::ApiKey)
            }
        }
    }

    pub(super) fn resource_state_at(&self, observed_at: UtcTimestamp) -> ResourceState {
        match self {
            Self::User(user) => user_state(user.lifecycle_state()),
            Self::Organization(organization) => organization_state(organization.state()),
            Self::Invitation(invitation) => invitation_state(invitation, observed_at),
            Self::ApiKey(key) => api_key_state(key, observed_at),
        }
    }
}

const fn user_state(state: UserLifecycleState) -> ResourceState {
    match state {
        UserLifecycleState::Active => ResourceState::Active,
        UserLifecycleState::Suspended => ResourceState::Restricted,
        UserLifecycleState::DeletionPending | UserLifecycleState::Invited => {
            ResourceState::Unavailable
        }
        UserLifecycleState::Deleted => ResourceState::Deleted,
    }
}

const fn organization_state(state: OrganizationState) -> ResourceState {
    match state {
        OrganizationState::Active => ResourceState::Active,
        OrganizationState::Frozen => ResourceState::Restricted,
    }
}

fn invitation_state(invitation: &Invitation, observed_at: UtcTimestamp) -> ResourceState {
    if invitation.state() == InvitationState::Issued && observed_at < invitation.expires_at() {
        ResourceState::Active
    } else {
        ResourceState::Unavailable
    }
}

fn api_key_state(key: &ApiKey, observed_at: UtcTimestamp) -> ResourceState {
    if !matches!(key.state(), ApiKeyState::Active | ApiKeyState::Rotating) {
        return ResourceState::Unavailable;
    }
    if key
        .expires_at()
        .is_some_and(|expires_at| observed_at >= expires_at)
    {
        return ResourceState::Unavailable;
    }
    ResourceState::Active
}

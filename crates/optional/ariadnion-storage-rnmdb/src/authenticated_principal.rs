// crates/optional/ariadnion-storage-rnmdb/src/authenticated_principal.rs - Rust source for Ariadnion.
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
//! Durable authentication-evidence validation for administration entrypoints.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_api_admin::{AdminError, AdminErrorCode, AuthenticatedPrincipalPort};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_job_runner::ManagedSystemAuthenticatorPort;
use ariadnion_organization::{MembershipState, OrganizationState};
use ariadnion_principal_binding::{
    AuthenticatedPrincipalEvidence, PrincipalAuthenticatorKind, PrincipalAuthenticatorSourceId,
    PrincipalBinding,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{UserId, UserLifecycleState, UtcTimestamp};
use rnmdb_cli::LocalSession;

use crate::RnmdbSessionOwner;
use crate::organization_repository::load_organization_in_session;
use crate::principal_authenticator_repository::{
    load_principal_authenticator_by_id_in_session,
    load_principal_authenticator_by_source_in_session,
};
use crate::principal_binding_repository::load_principal_binding_in_session;
use crate::user_repository::load_user_in_session;

/// Revalidates exact transient authenticator evidence against RNMDB state.
pub struct RnmdbAuthenticatedPrincipalValidator {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbAuthenticatedPrincipalValidator {
    /// Creates a validator over one live serialized RNMDB owner.
    #[must_use]
    pub const fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }
}

impl AuthenticatedPrincipalPort for RnmdbAuthenticatedPrincipalValidator {
    fn validate(
        &self,
        evidence: &AuthenticatedPrincipalEvidence,
        context: &RequestContext,
    ) -> Result<(), AdminError> {
        self.session
            .with_identity_storage_session(context, evidence.tenant_id(), |session| {
                validate_evidence_in_session(session, evidence)
            })
            .map_err(map_authentication_error)
    }
}

/// Loads one managed system identity and its active durable evidence from RNMDB.
pub struct RnmdbManagedSystemAuthenticator {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbManagedSystemAuthenticator {
    /// Creates a managed-system loader over one live serialized RNMDB owner.
    #[must_use]
    pub const fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }
}

impl ManagedSystemAuthenticatorPort for RnmdbManagedSystemAuthenticator {
    fn authenticate(
        &self,
        tenant_id: &TenantId,
        source_id: &PrincipalAuthenticatorSourceId,
        context: &RequestContext,
    ) -> Result<AuthenticatedPrincipalEvidence, AdminError> {
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                load_managed_system_evidence(session, tenant_id, source_id)
            })
            .map_err(map_authentication_error)
    }
}

fn validate_evidence_in_session(
    session: &mut LocalSession,
    evidence: &AuthenticatedPrincipalEvidence,
) -> Result<(), StorageError> {
    let link = load_principal_authenticator_by_id_in_session(
        session,
        evidence.tenant_id(),
        evidence.authenticator_id(),
    )?;
    let binding =
        load_principal_binding_in_session(session, evidence.tenant_id(), evidence.principal_id())?;
    evidence
        .validate_against(&link, &binding)
        .map_err(|_| unauthenticated())
}

fn load_managed_system_evidence(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    source_id: &PrincipalAuthenticatorSourceId,
) -> Result<AuthenticatedPrincipalEvidence, StorageError> {
    let link = load_principal_authenticator_by_source_in_session(
        session,
        tenant_id,
        PrincipalAuthenticatorKind::System,
        source_id,
    )?;
    let binding = load_principal_binding_in_session(session, tenant_id, link.principal_id())?;
    let evidence = AuthenticatedPrincipalEvidence::from_active_link(&link, &binding)
        .map_err(|_| unauthenticated())?;
    validate_managed_subject(session, tenant_id, &binding, trusted_time()?)?;
    Ok(evidence)
}

fn validate_managed_subject(
    session: &mut LocalSession,
    tenant_id: &TenantId,
    binding: &PrincipalBinding,
    now: UtcTimestamp,
) -> Result<(), StorageError> {
    let identity = binding.identity().ok_or_else(integrity_failure)?;
    let user = load_user_in_session(session, tenant_id, identity.user_id())?;
    let organization =
        load_organization_in_session(session, tenant_id, identity.organization_id())?;
    let membership = organization
        .membership(identity.membership_id())
        .ok_or_else(integrity_failure)?;
    validate_managed_states(user.lifecycle_state(), organization.state())?;
    validate_managed_membership(
        membership.user_id(),
        identity.user_id(),
        membership.state(),
        membership.expires_at(),
        now,
    )
}

fn validate_managed_states(
    user: UserLifecycleState,
    organization: OrganizationState,
) -> Result<(), StorageError> {
    if user != UserLifecycleState::Active || organization != OrganizationState::Active {
        return Err(unauthenticated());
    }
    Ok(())
}

fn validate_managed_membership(
    actual_user: &UserId,
    expected_user: &UserId,
    state: MembershipState,
    expires_at: Option<UtcTimestamp>,
    now: UtcTimestamp,
) -> Result<(), StorageError> {
    if actual_user != expected_user || state != MembershipState::Active {
        return Err(unauthenticated());
    }
    if expires_at.is_some_and(|expires_at| now >= expires_at) {
        return Err(unauthenticated());
    }
    Ok(())
}

fn trusted_time() -> Result<UtcTimestamp, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure())?;
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| integrity_failure())?;
    Ok(UtcTimestamp::from_unix_seconds(seconds))
}

fn map_authentication_error(error: StorageError) -> AdminError {
    let code = match error.code() {
        StorageErrorCode::NotFound | StorageErrorCode::Conflict => AdminErrorCode::Unauthenticated,
        StorageErrorCode::Cancelled => AdminErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => AdminErrorCode::DeadlineExceeded,
        StorageErrorCode::Unavailable
        | StorageErrorCode::ResourceExhausted
        | StorageErrorCode::MigrationRequired => AdminErrorCode::Unavailable,
        _ => AdminErrorCode::IntegrityFailure,
    };
    AdminError::new(code)
}

const fn unauthenticated() -> StorageError {
    StorageError::new(StorageErrorCode::NotFound)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

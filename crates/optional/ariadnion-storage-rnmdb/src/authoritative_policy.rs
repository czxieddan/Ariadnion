// crates/optional/ariadnion-storage-rnmdb/src/authoritative_policy.rs - Rust source for Ariadnion.
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
//! Authoritative administration facts loaded from one tenant-scoped boundary.

mod target;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_api_admin::{
    AdminCommand, AdminError, AdminErrorCode, AdminTarget, AuthoritativeAuthorizationSnapshot,
    AuthoritativePolicyPort,
};
use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_organization::Organization;
use ariadnion_principal_binding::{
    PrincipalBinding, PrincipalBindingIdentity, PrincipalBindingState,
};
use ariadnion_rbac::{
    AuthorizationPolicy, AuthorizationSubject, MembershipAuthorizationContext,
    MembershipAuthorizationIdentity, ResourceState,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::{User, UtcTimestamp};
use rnmdb_cli::LocalSession;

use self::target::LoadedAdminTarget;
use crate::organization_repository::load_organization_in_session;
use crate::principal_binding_repository::load_principal_binding_in_session;
use crate::rbac_repository::load_authenticated_policy_in_session;
use crate::session::check_context;
use crate::user_repository::load_user_in_session;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Loads trusted subject, policy, target, and time facts from RNMDB.
pub struct RnmdbAuthoritativePolicyPort {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbAuthoritativePolicyPort {
    /// Opens the port over a newly created serialized RNMDB session.
    ///
    /// # Errors
    /// Returns a redacted storage error when the encrypted database cannot be opened.
    pub fn open(
        options: SessionOpenOptions,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let session = RnmdbSessionOwner::open(options).map(Arc::new)?;
        Ok(Self::new(session, audit_subject_key))
    }

    /// Creates the port over one serialized session and audit verification key.
    #[must_use]
    pub const fn new(
        session: Arc<RnmdbSessionOwner>,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Self {
        Self {
            session,
            audit_subject_key,
        }
    }
}

impl AuthoritativePolicyPort for RnmdbAuthoritativePolicyPort {
    fn load_for(
        &self,
        tenant: &TenantId,
        target: &AdminTarget,
        context: &RequestContext,
    ) -> Result<AuthoritativeAuthorizationSnapshot, AdminError> {
        let principal = validate_initial_context(tenant, context)?.clone();
        let loaded = self
            .session
            .with_identity_storage_session(context, tenant, |session| {
                Ok(load_initial_snapshot(
                    session,
                    tenant,
                    target,
                    &principal,
                    context,
                    &self.audit_subject_key,
                ))
            })
            .map_err(map_storage_error)?;
        loaded.map_err(map_initial_fact_error)
    }
}

pub(crate) struct TransactionAuthorizationFacts {
    pub(crate) policy: AuthorizationPolicy,
    pub(crate) subject: AuthorizationSubject,
    pub(crate) resource_state: ResourceState,
    pub(crate) evaluated_at: UtcTimestamp,
}

pub(crate) fn load_transaction_authorization_facts(
    session: &mut LocalSession,
    command: &AdminCommand,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<TransactionAuthorizationFacts, StorageError> {
    load_transaction_facts(session, command, context, key).map_err(map_transaction_fact_error)
}

fn load_initial_snapshot(
    session: &mut LocalSession,
    tenant: &TenantId,
    target: &AdminTarget,
    principal: &PrincipalContext,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<AuthoritativeAuthorizationSnapshot, AuthorityFactError> {
    let binding = load_binding(session, tenant, principal.principal_id())?;
    let identity = active_identity(&binding)?;
    validate_initial_identity(&identity, principal)?;
    let facts = load_pending_facts(session, tenant, target, identity, context, key)?.finish()?;
    Ok(AuthoritativeAuthorizationSnapshot::new(
        facts.policy,
        facts.subject,
        facts.resource_state,
        facts.evaluated_at,
    ))
}

fn load_transaction_facts(
    session: &mut LocalSession,
    command: &AdminCommand,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<TransactionAuthorizationFacts, AuthorityFactError> {
    let binding = load_binding(session, command.tenant_id(), command.actor())?;
    let identity = active_identity(&binding)?;
    validate_transaction_identity(&identity, command.authorization_subject())?;
    load_pending_facts(
        session,
        command.tenant_id(),
        command.target(),
        identity,
        context,
        key,
    )?
    .finish()
}

struct PendingAuthorizationFacts {
    aggregates: SubjectAggregates,
    policy: AuthorizationPolicy,
    target: LoadedAdminTarget,
}

impl PendingAuthorizationFacts {
    fn finish(self) -> Result<TransactionAuthorizationFacts, AuthorityFactError> {
        let evaluated_at = trusted_authorization_time().map_err(AuthorityFactError::Storage)?;
        let subject = self.aggregates.into_subject(evaluated_at)?;
        Ok(TransactionAuthorizationFacts {
            policy: self.policy,
            subject,
            resource_state: self.target.resource_state_at(evaluated_at),
            evaluated_at,
        })
    }
}

fn load_pending_facts(
    session: &mut LocalSession,
    tenant: &TenantId,
    target: &AdminTarget,
    identity: PrincipalBindingIdentity,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<PendingAuthorizationFacts, AuthorityFactError> {
    let aggregates = load_subject_aggregates(session, tenant, identity)?;
    let policy = load_policy(session, tenant, context, key)?;
    let target = LoadedAdminTarget::load(session, tenant, target).map_err(target_error)?;
    Ok(PendingAuthorizationFacts {
        aggregates,
        policy,
        target,
    })
}

struct SubjectAggregates {
    identity: PrincipalBindingIdentity,
    user: User,
    organization: Organization,
}

impl SubjectAggregates {
    fn into_subject(
        self,
        evaluated_at: UtcTimestamp,
    ) -> Result<AuthorizationSubject, AuthorityFactError> {
        let membership = self
            .organization
            .membership(self.identity.membership_id())
            .ok_or(AuthorityFactError::MissingReference)?;
        if membership.user_id() != self.identity.user_id() {
            return Err(AuthorityFactError::Malformed);
        }
        let membership = MembershipAuthorizationContext::new(
            MembershipAuthorizationIdentity::new(
                self.identity.principal().tenant_id().clone(),
                self.identity.organization_id().clone(),
                self.identity.membership_id().clone(),
                self.identity.user_id().clone(),
            ),
            self.organization.state(),
            membership.state(),
            membership.expires_at(),
            membership.active_team_ids_at(evaluated_at).to_vec(),
        )
        .map_err(|_| AuthorityFactError::Malformed)?;
        Ok(AuthorizationSubject::new(
            self.identity.principal().clone(),
            self.identity.user_id().clone(),
            self.user.lifecycle_state(),
            Some(membership),
        ))
    }
}

fn load_subject_aggregates(
    session: &mut LocalSession,
    tenant: &TenantId,
    identity: PrincipalBindingIdentity,
) -> Result<SubjectAggregates, AuthorityFactError> {
    let user =
        load_user_in_session(session, tenant, identity.user_id()).map_err(reference_error)?;
    let organization = load_organization_in_session(session, tenant, identity.organization_id())
        .map_err(reference_error)?;
    Ok(SubjectAggregates {
        identity,
        user,
        organization,
    })
}

fn load_binding(
    session: &mut LocalSession,
    tenant: &TenantId,
    principal: &ariadnion_core::PrincipalId,
) -> Result<PrincipalBinding, AuthorityFactError> {
    load_principal_binding_in_session(session, tenant, principal).map_err(binding_error)
}

fn active_identity(
    binding: &PrincipalBinding,
) -> Result<PrincipalBindingIdentity, AuthorityFactError> {
    if binding.state() != PrincipalBindingState::Active {
        return Err(AuthorityFactError::InactiveBinding);
    }
    binding
        .identity()
        .cloned()
        .ok_or(AuthorityFactError::Malformed)
}

fn validate_initial_identity(
    identity: &PrincipalBindingIdentity,
    principal: &PrincipalContext,
) -> Result<(), AuthorityFactError> {
    if identity.principal() != principal {
        return Err(AuthorityFactError::Malformed);
    }
    Ok(())
}

fn validate_transaction_identity(
    identity: &PrincipalBindingIdentity,
    witness: &AuthorizationSubject,
) -> Result<(), AuthorityFactError> {
    validate_transaction_principal(identity, witness)?;
    validate_transaction_membership(identity, witness)
}

fn validate_transaction_principal(
    identity: &PrincipalBindingIdentity,
    witness: &AuthorizationSubject,
) -> Result<(), AuthorityFactError> {
    if identity.principal() != witness.principal() {
        return Err(AuthorityFactError::Changed);
    }
    if identity.user_id() != witness.user_id() {
        return Err(AuthorityFactError::Changed);
    }
    Ok(())
}

fn validate_transaction_membership(
    identity: &PrincipalBindingIdentity,
    witness: &AuthorizationSubject,
) -> Result<(), AuthorityFactError> {
    let membership = witness.membership().ok_or(AuthorityFactError::Changed)?;
    if identity.organization_id() != membership.organization_id() {
        return Err(AuthorityFactError::Changed);
    }
    if identity.membership_id() != membership.membership_id() {
        return Err(AuthorityFactError::Changed);
    }
    Ok(())
}

fn load_policy(
    session: &mut LocalSession,
    tenant: &TenantId,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<AuthorizationPolicy, AuthorityFactError> {
    load_authenticated_policy_in_session(session, tenant, context, key).map_err(policy_error)
}

fn validate_initial_context<'a>(
    tenant: &TenantId,
    context: &'a RequestContext,
) -> Result<&'a PrincipalContext, AdminError> {
    check_context(context).map_err(map_storage_error)?;
    let principal = context
        .principal()
        .ok_or_else(|| AdminError::new(AdminErrorCode::Unauthenticated))?;
    if principal.tenant_id() != tenant {
        return Err(AdminError::new(AdminErrorCode::TenantMismatch));
    }
    Ok(principal)
}

fn trusted_authorization_time() -> Result<UtcTimestamp, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure())?;
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| integrity_failure())?;
    Ok(UtcTimestamp::from_unix_seconds(seconds))
}

enum AuthorityFactError {
    MissingBinding,
    InactiveBinding,
    MissingReference,
    MissingPolicy,
    MissingTarget,
    Changed,
    Malformed,
    Storage(StorageError),
}

fn binding_error(error: StorageError) -> AuthorityFactError {
    classify_storage_error(error, AuthorityFactError::MissingBinding)
}

fn reference_error(error: StorageError) -> AuthorityFactError {
    classify_storage_error(error, AuthorityFactError::MissingReference)
}

fn policy_error(error: StorageError) -> AuthorityFactError {
    classify_storage_error(error, AuthorityFactError::MissingPolicy)
}

fn target_error(error: StorageError) -> AuthorityFactError {
    classify_storage_error(error, AuthorityFactError::MissingTarget)
}

fn classify_storage_error(error: StorageError, missing: AuthorityFactError) -> AuthorityFactError {
    match error.code() {
        StorageErrorCode::NotFound => missing,
        StorageErrorCode::IntegrityFailure | StorageErrorCode::Internal => {
            AuthorityFactError::Malformed
        }
        _ => AuthorityFactError::Storage(error),
    }
}

fn map_initial_fact_error(error: AuthorityFactError) -> AdminError {
    let code = match error {
        AuthorityFactError::MissingBinding | AuthorityFactError::InactiveBinding => {
            AdminErrorCode::Unauthenticated
        }
        AuthorityFactError::MissingPolicy | AuthorityFactError::MissingTarget => {
            AdminErrorCode::AuthorizationDenied
        }
        AuthorityFactError::Storage(error) => return map_storage_error(error),
        AuthorityFactError::MissingReference
        | AuthorityFactError::Changed
        | AuthorityFactError::Malformed => AdminErrorCode::IntegrityFailure,
    };
    AdminError::new(code)
}

fn map_transaction_fact_error(error: AuthorityFactError) -> StorageError {
    match error {
        AuthorityFactError::Malformed => integrity_failure(),
        AuthorityFactError::Storage(error) => error,
        AuthorityFactError::MissingBinding
        | AuthorityFactError::InactiveBinding
        | AuthorityFactError::MissingReference
        | AuthorityFactError::MissingPolicy
        | AuthorityFactError::MissingTarget
        | AuthorityFactError::Changed => conflict(),
    }
}

fn map_storage_error(error: StorageError) -> AdminError {
    let code = match error.code() {
        StorageErrorCode::Cancelled => AdminErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => AdminErrorCode::DeadlineExceeded,
        StorageErrorCode::Unavailable
        | StorageErrorCode::ResourceExhausted
        | StorageErrorCode::MigrationRequired => AdminErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => AdminErrorCode::CommitIndeterminate,
        StorageErrorCode::NotFound | StorageErrorCode::Conflict => AdminErrorCode::Conflict,
        _ => AdminErrorCode::IntegrityFailure,
    };
    AdminError::new(code)
}

const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

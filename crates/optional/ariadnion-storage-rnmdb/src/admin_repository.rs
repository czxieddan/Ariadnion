// crates/optional/ariadnion-storage-rnmdb/src/admin_repository.rs - Rust source for Ariadnion.
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
//! Atomic durable execution of authoritative administration commands.

mod decode;
mod fingerprint;
mod sql;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_api_admin::{
    AdminActionKind, AdminCommand, AdminCommandExecution, AdminCommandIntent, AdminCommandReceipt,
    AdminCommandRepositoryPort, AdminError, AdminErrorCode, AdminTarget,
};
use ariadnion_auth_api_key::{
    ApiKeyAction, ApiKeyCommand, ApiKeyTransition, ApiKeyVersion, transition_api_key,
};
use ariadnion_core::RequestContext;
use ariadnion_invitation::{
    InvitationAction, InvitationCommand, InvitationTransition, InvitationVersion,
    transition as transition_invitation,
};
use ariadnion_organization::{
    OrganizationAction, OrganizationCommand, OrganizationState, OrganizationTransition,
    OrganizationVersion, transition as transition_organization,
};
use ariadnion_rbac::{
    AuthorizationPolicy, AuthorizationSubject, MembershipAuthorizationContext,
    MembershipAuthorizationIdentity,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use ariadnion_user_domain::{
    UserTransition, UserTransitionAction, UserTransitionCommand, UserVersion,
    transition as transition_user,
};
use rnmdb_cli::LocalSession;

use crate::api_key_repository::{commit_api_key_in_session, load_api_key_in_session};
use crate::identity_transaction::run_identity_transaction;
use crate::invitation_repository::{commit_invitation_in_session, load_invitation_in_session};
use crate::organization_repository::{
    commit_organization_in_session, load_organization_in_session,
};
use crate::rbac_repository::load_authenticated_policy_in_session;
use crate::session::check_context;
use crate::user_repository::{commit_user_in_session, load_user_in_session};
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Executes tenant-bound administration commands with durable idempotency.
pub struct RnmdbAdminCommandRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
}

impl RnmdbAdminCommandRepository {
    /// Opens a repository over a newly created serialized RNMDB session.
    ///
    /// A repository whose commit result was indeterminate owns a tainted
    /// session and must be discarded. Reopen the same database with fresh key
    /// material before reconciling the command identity through
    /// [`AdminCommandRepositoryPort::find_replay`].
    ///
    /// # Errors
    ///
    /// Returns a redacted storage error when the encrypted database cannot be
    /// opened with the supplied validated options.
    pub fn open(
        options: SessionOpenOptions,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let session = RnmdbSessionOwner::open(options).map(Arc::new)?;
        Ok(Self::new(session, audit_subject_key))
    }

    /// Creates a repository over one serialized session and audit subject key.
    ///
    /// Wrapping a tainted owner does not recover it; use [`Self::open`] after
    /// an indeterminate commit.
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

impl AdminCommandRepositoryPort for RnmdbAdminCommandRepository {
    fn find_replay(
        &self,
        intent: &AdminCommandIntent,
        context: &RequestContext,
    ) -> Result<Option<AdminCommandReceipt>, AdminError> {
        validate_intent_context(intent, context)?;
        self.session
            .with_identity_storage_session(context, intent.tenant_id(), |session| {
                check_context(context)?;
                let records = decode::load_candidates(session, intent)?;
                check_context(context)?;
                decode::resolve_candidates(&records, intent)
            })
            .map_err(map_storage_error)
    }

    fn execute_once(
        &self,
        intent: &AdminCommandIntent,
        command: &AdminCommand,
        context: &RequestContext,
    ) -> Result<AdminCommandExecution, AdminError> {
        validate_intent_context(intent, context)?;
        validate_command_binding(intent, command)?;
        self.session
            .with_identity_transaction_session(context, intent.tenant_id(), |session| {
                run_identity_transaction(session, context, |session| {
                    execute_in_transaction(
                        session,
                        intent,
                        command,
                        context,
                        &self.audit_subject_key,
                    )
                })
            })
            .map_err(map_storage_error)
    }
}

fn execute_in_transaction(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
    command: &AdminCommand,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<AdminCommandExecution, StorageError> {
    match load_replay_in_transaction(session, intent, context)? {
        Some(receipt) => Ok(AdminCommandExecution::replayed(receipt)),
        None => execute_new_command(session, intent, command, context, key),
    }
}

fn load_replay_in_transaction(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
    context: &RequestContext,
) -> Result<Option<AdminCommandReceipt>, StorageError> {
    check_context(context)?;
    let records = decode::load_candidates(session, intent)?;
    check_context(context)?;
    decode::resolve_candidates(&records, intent)
}

fn execute_new_command(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
    command: &AdminCommand,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<AdminCommandExecution, StorageError> {
    let mutation = prepare_mutation(session, command)?;
    recheck_authorization(session, command, context, key)?;
    check_context(context)?;
    match insert_pending_or_replay(session, intent, command, context)? {
        Some(receipt) => Ok(AdminCommandExecution::replayed(receipt)),
        None => apply_reserved_command(session, intent, command, context, key, mutation),
    }
}

fn apply_reserved_command(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
    command: &AdminCommand,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
    mutation: PreparedMutation,
) -> Result<AdminCommandExecution, StorageError> {
    check_context(context)?;
    let applied_at = apply_mutation(session, mutation, command, context, key)?;
    check_context(context)?;
    validate_application_time(command, applied_at)?;
    sql::finalize(session, intent, applied_at)?;
    check_context(context)?;
    Ok(AdminCommandExecution::applied(command_receipt(
        intent, applied_at,
    )))
}

fn insert_pending_or_replay(
    session: &mut LocalSession,
    intent: &AdminCommandIntent,
    command: &AdminCommand,
    context: &RequestContext,
) -> Result<Option<AdminCommandReceipt>, StorageError> {
    let result = sql::insert_pending(session, intent, command, context.request_id().as_str());
    let Err(original) = result else {
        return Ok(None);
    };
    check_context(context)?;
    let records = decode::load_candidates(session, intent)?;
    match decode::resolve_candidates(&records, intent)? {
        Some(receipt) => Ok(Some(receipt)),
        None => Err(original),
    }
}

fn recheck_authorization(
    session: &mut LocalSession,
    command: &AdminCommand,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<(), StorageError> {
    check_context(context)?;
    let facts = load_current_authorization_facts(session, command, context, key)?;
    check_context(context)?;
    validate_current_authorization(command, facts)
}

struct CurrentAuthorizationFacts {
    policy: AuthorizationPolicy,
    subject: AuthorizationSubject,
    evaluated_at: UtcTimestamp,
}

fn load_current_authorization_facts(
    session: &mut LocalSession,
    command: &AdminCommand,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<CurrentAuthorizationFacts, StorageError> {
    let policy = load_authenticated_policy_in_session(session, command.tenant_id(), context, key)?;
    let evaluated_at = trusted_authorization_time()?;
    let subject = load_current_subject(session, command.authorization_subject(), evaluated_at)?;
    Ok(CurrentAuthorizationFacts {
        policy,
        subject,
        evaluated_at,
    })
}

fn validate_current_authorization(
    command: &AdminCommand,
    facts: CurrentAuthorizationFacts,
) -> Result<(), StorageError> {
    if facts.policy.tenant_id() != command.tenant_id() {
        return Err(integrity_failure());
    }
    if !command.remains_authorized(&facts.policy, facts.subject, facts.evaluated_at) {
        return Err(conflict());
    }
    Ok(())
}

fn load_current_subject(
    session: &mut LocalSession,
    witness: &AuthorizationSubject,
    evaluated_at: UtcTimestamp,
) -> Result<AuthorizationSubject, StorageError> {
    let user = load_user_in_session(session, witness.principal().tenant_id(), witness.user_id())?;
    let membership = load_current_membership(session, witness, evaluated_at)?;
    Ok(AuthorizationSubject::new(
        witness.principal().clone(),
        witness.user_id().clone(),
        user.lifecycle_state(),
        membership,
    ))
}

fn load_current_membership(
    session: &mut LocalSession,
    witness: &AuthorizationSubject,
    evaluated_at: UtcTimestamp,
) -> Result<Option<MembershipAuthorizationContext>, StorageError> {
    match witness.membership() {
        Some(expected) => {
            load_present_membership(session, witness, expected, evaluated_at).map(Some)
        }
        None => Ok(None),
    }
}

fn load_present_membership(
    session: &mut LocalSession,
    witness: &AuthorizationSubject,
    expected: &MembershipAuthorizationContext,
    evaluated_at: UtcTimestamp,
) -> Result<MembershipAuthorizationContext, StorageError> {
    validate_expected_membership(witness, expected)?;
    let organization =
        load_organization_in_session(session, expected.tenant_id(), expected.organization_id())?;
    let membership = organization
        .membership(expected.membership_id())
        .ok_or_else(conflict)?;
    validate_current_membership(witness, membership)?;
    let identity = MembershipAuthorizationIdentity::new(
        expected.tenant_id().clone(),
        expected.organization_id().clone(),
        expected.membership_id().clone(),
        witness.user_id().clone(),
    );
    MembershipAuthorizationContext::new(
        identity,
        organization.state(),
        membership.state(),
        membership.expires_at(),
        membership.active_team_ids_at(evaluated_at).to_vec(),
    )
    .map_err(|_| integrity_failure())
}

fn validate_expected_membership(
    witness: &AuthorizationSubject,
    expected: &MembershipAuthorizationContext,
) -> Result<(), StorageError> {
    if expected.user_id() != witness.user_id() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_current_membership(
    witness: &AuthorizationSubject,
    membership: &ariadnion_organization::Membership,
) -> Result<(), StorageError> {
    if membership.user_id() != witness.user_id() {
        return Err(conflict());
    }
    Ok(())
}

fn trusted_authorization_time() -> Result<UtcTimestamp, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure())?;
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| integrity_failure())?;
    Ok(UtcTimestamp::from_unix_seconds(seconds))
}

enum PreparedMutation {
    User {
        expected_version: UserVersion,
        transition: UserTransition,
    },
    Organization {
        expected_version: OrganizationVersion,
        transition: OrganizationTransition,
    },
    Invitation {
        expected_version: InvitationVersion,
        transition: InvitationTransition,
    },
    ApiKey {
        expected_version: ApiKeyVersion,
        transition: ApiKeyTransition,
    },
}

fn prepare_mutation(
    session: &mut LocalSession,
    command: &AdminCommand,
) -> Result<PreparedMutation, StorageError> {
    match command.target() {
        AdminTarget::User(user_id) => prepare_user_mutation(session, command, user_id),
        AdminTarget::Organization(organization_id) => {
            prepare_organization_mutation(session, command, organization_id)
        }
        AdminTarget::Invitation {
            organization_id,
            invitation_id,
        } => prepare_invitation_mutation(session, command, organization_id, invitation_id),
        AdminTarget::ApiKey(api_key_id) => prepare_api_key_mutation(session, command, api_key_id),
    }
}

fn prepare_user_mutation(
    session: &mut LocalSession,
    command: &AdminCommand,
    user_id: &ariadnion_user_domain::UserId,
) -> Result<PreparedMutation, StorageError> {
    let user = load_user_in_session(session, command.tenant_id(), user_id)?;
    let action = match command.action() {
        AdminActionKind::SuspendUser => UserTransitionAction::Suspend {
            occurred_at: command.occurred_at(),
        },
        AdminActionKind::RestoreUser => UserTransitionAction::Resume {
            occurred_at: command.occurred_at(),
        },
        _ => return Err(integrity_failure()),
    };
    let expected_version = user.version();
    let transition = transition_user(&user, UserTransitionCommand::new(expected_version, action))
        .map_err(|_| conflict())?;
    Ok(PreparedMutation::User {
        expected_version,
        transition,
    })
}

fn prepare_organization_mutation(
    session: &mut LocalSession,
    command: &AdminCommand,
    organization_id: &ariadnion_organization::OrganizationId,
) -> Result<PreparedMutation, StorageError> {
    let organization = load_organization_in_session(session, command.tenant_id(), organization_id)?;
    let state = match command.action() {
        AdminActionKind::FreezeOrganization => OrganizationState::Frozen,
        AdminActionKind::UnfreezeOrganization => OrganizationState::Active,
        _ => return Err(integrity_failure()),
    };
    let expected_version = organization.version();
    let transition = transition_organization(
        &organization,
        OrganizationCommand::new(
            expected_version,
            command.actor().clone(),
            command.occurred_at(),
            OrganizationAction::ChangeState { state },
        ),
    )
    .map_err(|_| conflict())?;
    Ok(PreparedMutation::Organization {
        expected_version,
        transition,
    })
}

fn prepare_invitation_mutation(
    session: &mut LocalSession,
    command: &AdminCommand,
    organization_id: &ariadnion_organization::OrganizationId,
    invitation_id: &ariadnion_invitation::InvitationId,
) -> Result<PreparedMutation, StorageError> {
    if command.action() != AdminActionKind::RevokeInvitation {
        return Err(integrity_failure());
    }
    let invitation =
        load_invitation_in_session(session, command.tenant_id(), organization_id, invitation_id)?;
    let expected_version = invitation.version();
    let transition = transition_invitation(
        &invitation,
        InvitationCommand::new(
            expected_version,
            command.actor().clone(),
            command.occurred_at(),
            InvitationAction::Revoke,
        ),
    )
    .map_err(|_| conflict())?;
    Ok(PreparedMutation::Invitation {
        expected_version,
        transition,
    })
}

fn prepare_api_key_mutation(
    session: &mut LocalSession,
    command: &AdminCommand,
    api_key_id: &ariadnion_auth_api_key::ApiKeyId,
) -> Result<PreparedMutation, StorageError> {
    if command.action() != AdminActionKind::RevokeApiKey {
        return Err(integrity_failure());
    }
    let key = load_api_key_in_session(session, command.tenant_id(), api_key_id)?;
    let expected_version = key.version();
    let transition = transition_api_key(
        &key,
        ApiKeyCommand::new(
            expected_version,
            command.actor().clone(),
            command.occurred_at(),
            ApiKeyAction::Revoke {
                owner: key.owner().clone(),
            },
        ),
    )
    .map_err(|_| conflict())?;
    Ok(PreparedMutation::ApiKey {
        expected_version,
        transition,
    })
}

fn apply_mutation(
    session: &mut LocalSession,
    mutation: PreparedMutation,
    command: &AdminCommand,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
) -> Result<UtcTimestamp, StorageError> {
    match mutation {
        PreparedMutation::User {
            expected_version,
            transition,
        } => commit_user_in_session(
            session,
            command.tenant_id(),
            expected_version,
            &transition,
            context,
            key,
        )
        .map(|receipt| receipt.committed_at()),
        PreparedMutation::Organization {
            expected_version,
            transition,
        } => commit_organization_in_session(
            session,
            command.tenant_id(),
            expected_version,
            &transition,
            context,
            key,
        )
        .map(|receipt| receipt.committed_at()),
        PreparedMutation::Invitation {
            expected_version,
            transition,
        } => commit_invitation_in_session(session, expected_version, &transition, context, key)
            .map(|receipt| receipt.committed_at()),
        PreparedMutation::ApiKey {
            expected_version,
            transition,
        } => commit_api_key_in_session(session, expected_version, &transition, context, key)
            .map(|receipt| receipt.committed_at()),
    }
}

fn validate_intent_context(
    intent: &AdminCommandIntent,
    context: &RequestContext,
) -> Result<(), AdminError> {
    check_context(context).map_err(map_storage_error)?;
    let principal = context
        .principal()
        .ok_or_else(|| AdminError::new(AdminErrorCode::Unauthenticated))?;
    if principal.tenant_id() != intent.tenant_id() {
        return Err(AdminError::new(AdminErrorCode::TenantMismatch));
    }
    if principal.principal_id() != intent.actor() {
        return Err(AdminError::new(AdminErrorCode::DecisionMismatch));
    }
    Ok(())
}

fn validate_command_binding(
    intent: &AdminCommandIntent,
    command: &AdminCommand,
) -> Result<(), AdminError> {
    let stable_fields_match = (
        command.id(),
        command.tenant_id(),
        command.actor(),
        command.decision_id(),
        command.policy_version(),
        command.action(),
        command.target(),
        command.reason_code(),
    ) == (
        intent.command_id(),
        intent.tenant_id(),
        intent.actor(),
        intent.decision_id(),
        intent.expected_policy_version(),
        intent.action(),
        intent.target(),
        intent.reason_code(),
    );
    let matches = stable_fields_match
        && command.authorization_subject().principal().tenant_id() == command.tenant_id()
        && command.authorization_subject().principal().principal_id() == command.actor();
    matches
        .then_some(())
        .ok_or_else(|| AdminError::new(AdminErrorCode::IntegrityFailure))
}

fn validate_application_time(
    command: &AdminCommand,
    applied_at: UtcTimestamp,
) -> Result<(), StorageError> {
    if applied_at < command.occurred_at() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn command_receipt(intent: &AdminCommandIntent, applied_at: UtcTimestamp) -> AdminCommandReceipt {
    AdminCommandReceipt::new(
        intent.command_id().clone(),
        intent.tenant_id().clone(),
        intent.decision_id().clone(),
        intent.expected_policy_version(),
        applied_at,
    )
}

fn map_storage_error(error: StorageError) -> AdminError {
    let code = match error.code() {
        StorageErrorCode::NotFound | StorageErrorCode::Conflict => AdminErrorCode::Conflict,
        StorageErrorCode::Cancelled => AdminErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => AdminErrorCode::DeadlineExceeded,
        StorageErrorCode::Unavailable
        | StorageErrorCode::ResourceExhausted
        | StorageErrorCode::MigrationRequired => AdminErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => AdminErrorCode::CommitIndeterminate,
        StorageErrorCode::InvalidArgument
        | StorageErrorCode::IntegrityFailure
        | StorageErrorCode::Internal => AdminErrorCode::IntegrityFailure,
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

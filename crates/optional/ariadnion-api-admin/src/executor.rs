// crates/optional/ariadnion-api-admin/src/executor.rs - Rust source for Ariadnion.
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
//! Authoritative just-in-time administration command execution.

use ariadnion_core::{ErrorCode, PrincipalContext, RequestContext};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;
use ariadnion_rbac::{AuthorizationRequest, DecisionId, PolicyVersion, ResourceState, evaluate};

use crate::error::error;
use crate::model::{
    AdminCommandBinding, AdminCommandRequest, accept_admin_command, authorization_target,
    expected_target_state, parse_reason_code, validate_action_target,
};
use crate::{
    AdminActionKind, AdminCommandExecution, AdminCommandReceipt, AdminCommandRepositoryPort,
    AdminError, AdminErrorCode, AdminExecutionPort, AdminTarget, AuthenticatedPrincipalPort,
    AuthoritativeAuthorizationSnapshot, AuthoritativePolicyPort,
};

/// Bounded caller intent that contains no reusable authorization decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminExecutionRequest {
    command_id: crate::AdminCommandId,
    decision_id: DecisionId,
    expected_policy_version: PolicyVersion,
    action: AdminActionKind,
    target: AdminTarget,
    reason_code: Box<str>,
}

impl AdminExecutionRequest {
    /// Creates one bounded execution intent.
    ///
    /// # Errors
    ///
    /// Returns [`AdminErrorCode::InvalidArgument`] for an invalid reason code
    /// or an action that cannot operate on the supplied target kind.
    pub fn new(
        command_id: crate::AdminCommandId,
        decision_id: DecisionId,
        expected_policy_version: PolicyVersion,
        action: AdminActionKind,
        target: AdminTarget,
        reason_code: &str,
    ) -> Result<Self, AdminError> {
        validate_action_target(action, &target)?;
        Ok(Self {
            command_id,
            decision_id,
            expected_policy_version,
            action,
            target,
            reason_code: parse_reason_code(reason_code)?,
        })
    }
}

/// Authenticated stable material used to reconcile command replays.
///
/// The executor constructs this value from the authenticated principal and a
/// bounded protocol intent. It deliberately excludes trusted evaluation time
/// and mutable authorization facts, so an exact retry remains stable after the
/// first mutation changes policy, target state, or the current time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminCommandIntent {
    command_id: crate::AdminCommandId,
    tenant_id: ariadnion_core::TenantId,
    actor: ariadnion_core::PrincipalId,
    decision_id: DecisionId,
    expected_policy_version: PolicyVersion,
    action: AdminActionKind,
    target: AdminTarget,
    reason_code: Box<str>,
}

impl AdminCommandIntent {
    pub(crate) fn from_request(
        request: &AdminExecutionRequest,
        principal: &PrincipalContext,
    ) -> Self {
        Self {
            command_id: request.command_id.clone(),
            tenant_id: principal.tenant_id().clone(),
            actor: principal.principal_id().clone(),
            decision_id: request.decision_id.clone(),
            expected_policy_version: request.expected_policy_version,
            action: request.action,
            target: request.target.clone(),
            reason_code: request.reason_code.clone(),
        }
    }

    /// Returns the opaque command identity.
    #[must_use]
    pub const fn command_id(&self) -> &crate::AdminCommandId {
        &self.command_id
    }

    /// Returns the authenticated tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &ariadnion_core::TenantId {
        &self.tenant_id
    }

    /// Returns the authenticated actor.
    #[must_use]
    pub const fn actor(&self) -> &ariadnion_core::PrincipalId {
        &self.actor
    }

    /// Returns the caller-provided one-time decision identity.
    #[must_use]
    pub const fn decision_id(&self) -> &DecisionId {
        &self.decision_id
    }

    /// Returns the policy version expected by the caller.
    #[must_use]
    pub const fn expected_policy_version(&self) -> PolicyVersion {
        self.expected_policy_version
    }

    /// Returns the administration action.
    #[must_use]
    pub const fn action(&self) -> AdminActionKind {
        self.action
    }

    /// Returns the exact tenant-bound target.
    #[must_use]
    pub const fn target(&self) -> &AdminTarget {
        &self.target
    }

    /// Returns the bounded stable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }

    fn matches_command(&self, command: &crate::AdminCommand) -> bool {
        (
            command.id(),
            command.tenant_id(),
            command.actor(),
            command.decision_id(),
            command.policy_version(),
            command.action(),
            command.target(),
            command.reason_code(),
        ) == (
            self.command_id(),
            self.tenant_id(),
            self.actor(),
            self.decision_id(),
            self.expected_policy_version(),
            self.action(),
            self.target(),
            self.reason_code(),
        )
    }
}

/// Coordinates authoritative policy evaluation and one durable command attempt.
pub struct AdminCommandExecutor<A, P, R> {
    authenticated_principals: A,
    policies: P,
    repository: R,
}

impl<A, P, R> AdminCommandExecutor<A, P, R>
where
    A: AuthenticatedPrincipalPort,
    P: AuthoritativePolicyPort,
    R: AdminCommandRepositoryPort,
{
    /// Creates an executor over authentication, policy, and command ports.
    #[must_use]
    pub const fn new(authenticated_principals: A, policies: P, repository: R) -> Self {
        Self {
            authenticated_principals,
            policies,
            repository,
        }
    }

    /// Evaluates and applies one command without accepting a serialized decision.
    ///
    /// The active request and authenticated principal are checked before I/O.
    /// Policy, subject, membership, target state, and evaluation time are loaded
    /// together. The repository must recheck mutable facts in its transaction.
    ///
    /// # Errors
    ///
    /// Returns stable redacted failures for inactive or anonymous requests,
    /// stale policy, denied authorization, fact mismatch, durable conflict,
    /// storage failure, or an invalid durable receipt.
    pub fn execute(
        &self,
        request: AdminExecutionRequest,
        evidence: &AuthenticatedPrincipalEvidence,
        context: &RequestContext,
    ) -> Result<AdminCommandReceipt, AdminError> {
        let (principal, authenticated) = prepare_execution(evidence, context)?;
        self.authenticated_principals
            .validate(evidence, &authenticated)?;
        check_context(&authenticated)?;
        self.execute_authenticated(request, &principal, &authenticated)
    }

    fn execute_authenticated(
        &self,
        request: AdminExecutionRequest,
        principal: &PrincipalContext,
        context: &RequestContext,
    ) -> Result<AdminCommandReceipt, AdminError> {
        let intent = AdminCommandIntent::from_request(&request, principal);
        if let Some(receipt) = self.find_replay(&intent, context)? {
            return Ok(receipt);
        }
        let snapshot = self.load_authoritative_snapshot(&request, principal, context)?;
        let command = authorize_command(request, snapshot, principal)?;
        self.execute_authorized_command(&intent, &command, context)
    }

    fn find_replay(
        &self,
        intent: &AdminCommandIntent,
        context: &RequestContext,
    ) -> Result<Option<AdminCommandReceipt>, AdminError> {
        let receipt = self.repository.find_replay(intent, context)?;
        check_context(context)?;
        if let Some(receipt) = receipt {
            validate_replay_receipt(&receipt, intent)?;
            return Ok(Some(receipt));
        }
        Ok(None)
    }

    fn load_authoritative_snapshot(
        &self,
        request: &AdminExecutionRequest,
        principal: &PrincipalContext,
        context: &RequestContext,
    ) -> Result<AuthoritativeAuthorizationSnapshot, AdminError> {
        let snapshot = self
            .policies
            .load_for(principal.tenant_id(), &request.target, context)?;
        check_context(context)?;
        validate_snapshot(&snapshot, principal, request.expected_policy_version)?;
        Ok(snapshot)
    }

    fn execute_authorized_command(
        &self,
        intent: &AdminCommandIntent,
        command: &crate::AdminCommand,
        context: &RequestContext,
    ) -> Result<AdminCommandReceipt, AdminError> {
        check_context(context)?;
        let execution = self.repository.execute_once(intent, command, context)?;
        validate_execution(execution, intent, command)
    }
}

impl<A, P, R> crate::port::private::Sealed for AdminCommandExecutor<A, P, R>
where
    A: AuthenticatedPrincipalPort,
    P: AuthoritativePolicyPort,
    R: AdminCommandRepositoryPort,
{
}

impl<A, P, R> AdminExecutionPort for AdminCommandExecutor<A, P, R>
where
    A: AuthenticatedPrincipalPort,
    P: AuthoritativePolicyPort,
    R: AdminCommandRepositoryPort,
{
    fn execute(
        &self,
        request: AdminExecutionRequest,
        evidence: &AuthenticatedPrincipalEvidence,
        context: &RequestContext,
    ) -> Result<AdminCommandReceipt, AdminError> {
        AdminCommandExecutor::execute(self, request, evidence, context)
    }
}

fn prepare_execution(
    evidence: &AuthenticatedPrincipalEvidence,
    context: &RequestContext,
) -> Result<(PrincipalContext, RequestContext), AdminError> {
    check_context(context)?;
    let principal = PrincipalContext::new(
        evidence.tenant_id().clone(),
        evidence.principal_id().clone(),
    );
    let authenticated = RequestContext::new(
        context.request_id().clone(),
        context.trace_id().clone(),
        Some(principal.clone()),
        context.deadline(),
        context.cancellation(),
    );
    Ok((principal, authenticated))
}

fn authorize_command(
    request: AdminExecutionRequest,
    snapshot: AuthoritativeAuthorizationSnapshot,
    principal: &PrincipalContext,
) -> Result<crate::AdminCommand, AdminError> {
    validate_resource_state(request.action, snapshot.resource_state())?;
    let subject = snapshot.subject().clone();
    let target = authorization_target(
        request.action,
        principal.tenant_id().clone(),
        &request.target,
        snapshot.resource_state(),
    )?;
    let authorization = AuthorizationRequest::new(
        request.decision_id.clone(),
        request.expected_policy_version,
        subject.clone(),
        target,
        snapshot.evaluated_at(),
    );
    let decision = evaluate(snapshot.policy(), &authorization);
    let binding = AdminCommandBinding::new(
        request.command_id,
        principal.tenant_id().clone(),
        principal.principal_id().clone(),
        snapshot.evaluated_at(),
        request.decision_id,
        request.expected_policy_version,
    );
    let command = AdminCommandRequest::new(
        binding,
        request.action,
        request.target,
        &request.reason_code,
        subject,
        decision,
    )?;
    accept_admin_command(command)
}

fn validate_snapshot(
    snapshot: &AuthoritativeAuthorizationSnapshot,
    principal: &PrincipalContext,
    expected: PolicyVersion,
) -> Result<(), AdminError> {
    if snapshot.policy().version() != expected {
        return Err(error(AdminErrorCode::Conflict));
    }
    let subject = snapshot.subject().principal();
    if snapshot.policy().tenant_id() != principal.tenant_id()
        || subject.tenant_id() != principal.tenant_id()
        || subject.principal_id() != principal.principal_id()
    {
        return Err(error(AdminErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn validate_resource_state(
    action: AdminActionKind,
    actual: ResourceState,
) -> Result<(), AdminError> {
    let (_, expected) = expected_target_state(action);
    if actual != expected {
        return Err(error(AdminErrorCode::AuthorizationDenied));
    }
    Ok(())
}

fn validate_replay_receipt(
    receipt: &AdminCommandReceipt,
    intent: &AdminCommandIntent,
) -> Result<(), AdminError> {
    if !receipt.matches_intent(intent) {
        return Err(error(AdminErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn validate_execution(
    execution: AdminCommandExecution,
    intent: &AdminCommandIntent,
    command: &crate::AdminCommand,
) -> Result<AdminCommandReceipt, AdminError> {
    if !intent.matches_command(command) || !execution.receipt().matches_intent(intent) {
        return Err(error(AdminErrorCode::IntegrityFailure));
    }
    if execution.is_applied() && execution.receipt().applied_at() < command.occurred_at() {
        return Err(error(AdminErrorCode::IntegrityFailure));
    }
    Ok(execution.into_receipt())
}

fn check_context(context: &RequestContext) -> Result<(), AdminError> {
    context.check_active().map_err(|failure| {
        let code = match failure.code() {
            ErrorCode::Cancelled => AdminErrorCode::Cancelled,
            ErrorCode::DeadlineExceeded => AdminErrorCode::DeadlineExceeded,
            _ => AdminErrorCode::IntegrityFailure,
        };
        error(code)
    })
}

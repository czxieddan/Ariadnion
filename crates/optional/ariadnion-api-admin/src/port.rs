// crates/optional/ariadnion-api-admin/src/port.rs - Rust source for Ariadnion.
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
//! Trusted authorization and durable command execution boundaries.

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;
use ariadnion_rbac::{
    AuthorizationPolicy, AuthorizationSubject, DecisionId, PolicyVersion, ResourceState,
};
use ariadnion_user_domain::UtcTimestamp;

use crate::{
    AdminCommand, AdminCommandId, AdminCommandIntent, AdminError, AdminExecutionRequest,
    AdminTarget,
};

pub(crate) mod private {
    pub trait Sealed {}
}

/// Revalidates transient authentication evidence against authoritative state.
pub trait AuthenticatedPrincipalPort: Send + Sync {
    /// Validates the exact active authenticator and principal-binding linkage.
    ///
    /// Implementations must perform this check on every execution attempt,
    /// including exact command replay. They must not infer identity from policy
    /// assignments or accept a constructor-provided principal as evidence.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error for inactive, missing, mismatched,
    /// unavailable, cancelled, expired, or malformed authoritative evidence.
    fn validate(
        &self,
        evidence: &AuthenticatedPrincipalEvidence,
        context: &RequestContext,
    ) -> Result<(), AdminError>;
}

/// Shared object-safe entrypoint for authoritative administration execution.
///
/// Protocol adapters receive this facade instead of policy or repository ports,
/// so they cannot evaluate roles locally or bypass durable command handling.
/// Implementations are sealed to [`crate::AdminCommandExecutor`].
pub trait AdminExecutionPort: private::Sealed + Send + Sync {
    /// Evaluates current authoritative facts and durably executes one request.
    ///
    /// # Errors
    ///
    /// Returns the same stable redacted failures as
    /// [`crate::AdminCommandExecutor::execute`].
    fn execute(
        &self,
        request: AdminExecutionRequest,
        evidence: &AuthenticatedPrincipalEvidence,
        context: &RequestContext,
    ) -> Result<AdminCommandReceipt, AdminError>;
}

/// One authoritative authorization snapshot loaded immediately before evaluation.
///
/// Implementations must source the policy, subject lifecycle, membership facts,
/// target state, and time from trusted adapters rather than protocol payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritativeAuthorizationSnapshot {
    policy: AuthorizationPolicy,
    subject: AuthorizationSubject,
    resource_state: ResourceState,
    evaluated_at: UtcTimestamp,
}

impl AuthoritativeAuthorizationSnapshot {
    /// Creates a trusted snapshot returned by an authoritative adapter.
    #[must_use]
    pub const fn new(
        policy: AuthorizationPolicy,
        subject: AuthorizationSubject,
        resource_state: ResourceState,
        evaluated_at: UtcTimestamp,
    ) -> Self {
        Self {
            policy,
            subject,
            resource_state,
            evaluated_at,
        }
    }

    /// Returns the active immutable policy.
    #[must_use]
    pub const fn policy(&self) -> &AuthorizationPolicy {
        &self.policy
    }

    /// Returns authenticated user and membership facts.
    #[must_use]
    pub const fn subject(&self) -> &AuthorizationSubject {
        &self.subject
    }

    /// Returns the current trusted target state.
    #[must_use]
    pub const fn resource_state(&self) -> ResourceState {
        self.resource_state
    }

    /// Returns the trusted UTC evaluation instant.
    #[must_use]
    pub const fn evaluated_at(&self) -> UtcTimestamp {
        self.evaluated_at
    }
}

/// Loads all authorization facts needed for one exact administration target.
pub trait AuthoritativePolicyPort: Send + Sync {
    /// Loads the current policy, subject, target state, and trusted time.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when facts cannot be authenticated,
    /// bounded, or loaded before the request deadline.
    fn load_for(
        &self,
        tenant: &TenantId,
        target: &AdminTarget,
        context: &RequestContext,
    ) -> Result<AuthoritativeAuthorizationSnapshot, AdminError>;
}

/// Durable receipt for the first application or exact replay of one command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminCommandReceipt {
    command_id: AdminCommandId,
    tenant_id: TenantId,
    decision_id: DecisionId,
    policy_version: PolicyVersion,
    applied_at: UtcTimestamp,
}

impl AdminCommandReceipt {
    /// Creates a receipt from durable command-ledger facts.
    #[must_use]
    pub const fn new(
        command_id: AdminCommandId,
        tenant_id: TenantId,
        decision_id: DecisionId,
        policy_version: PolicyVersion,
        applied_at: UtcTimestamp,
    ) -> Self {
        Self {
            command_id,
            tenant_id,
            decision_id,
            policy_version,
            applied_at,
        }
    }

    /// Returns the opaque command identity.
    #[must_use]
    pub const fn command_id(&self) -> &AdminCommandId {
        &self.command_id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the consumed authorization decision identity.
    #[must_use]
    pub const fn decision_id(&self) -> &DecisionId {
        &self.decision_id
    }

    /// Returns the policy version rechecked by the mutation transaction.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Returns the trusted durable application time.
    #[must_use]
    pub const fn applied_at(&self) -> UtcTimestamp {
        self.applied_at
    }

    pub(crate) fn matches_intent(&self, intent: &AdminCommandIntent) -> bool {
        self.command_id == *intent.command_id()
            && self.tenant_id == *intent.tenant_id()
            && self.decision_id == *intent.decision_id()
            && self.policy_version == intent.expected_policy_version()
    }
}

/// Repository result that preserves the first-application time invariant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminCommandExecution {
    /// This invocation performed the first durable mutation.
    Applied(AdminCommandReceipt),
    /// Another invocation already durably applied the exact stable material.
    Replayed(AdminCommandReceipt),
}

impl AdminCommandExecution {
    /// Reports that this invocation performed the first durable mutation.
    ///
    /// The executor rejects this outcome when the receipt application time is
    /// earlier than the command's trusted evaluation time.
    #[must_use]
    pub const fn applied(receipt: AdminCommandReceipt) -> Self {
        Self::Applied(receipt)
    }

    /// Reports that a concurrent invocation already applied the exact command.
    ///
    /// Repository implementations may return this only after comparing all
    /// stable material, excluding the fresh evaluation time, in one transaction.
    #[must_use]
    pub const fn replayed(receipt: AdminCommandReceipt) -> Self {
        Self::Replayed(receipt)
    }

    /// Returns whether this invocation performed the first durable mutation.
    #[must_use]
    pub const fn is_applied(&self) -> bool {
        matches!(self, Self::Applied(_))
    }

    /// Returns the original durable receipt.
    #[must_use]
    pub const fn receipt(&self) -> &AdminCommandReceipt {
        match self {
            Self::Applied(receipt) | Self::Replayed(receipt) => receipt,
        }
    }

    pub(crate) fn into_receipt(self) -> AdminCommandReceipt {
        match self {
            Self::Applied(receipt) | Self::Replayed(receipt) => receipt,
        }
    }
}

/// Applies an accepted command once and returns its original receipt on replay.
pub trait AdminCommandRepositoryPort: Send + Sync {
    /// Reconciles an authenticated stable intent before policy I/O.
    ///
    /// Implementations must query durable command and decision identities. They
    /// return `Ok(None)` only when neither identity exists, return the original
    /// receipt only when every stable field matches, and return
    /// [`crate::AdminErrorCode::Conflict`] for changed command material or
    /// decision reuse. A malformed, partially committed, or identity-inconsistent
    /// row fails with [`crate::AdminErrorCode::IntegrityFailure`]. This method is
    /// the command identity's owner for reconciling an indeterminate prior commit.
    ///
    /// # Errors
    ///
    /// Returns stable redacted errors for conflict, cancellation, deadline,
    /// unavailable storage, or durable integrity failure.
    fn find_replay(
        &self,
        intent: &AdminCommandIntent,
        context: &RequestContext,
    ) -> Result<Option<AdminCommandReceipt>, AdminError>;

    /// Executes one command within its durable idempotency transaction.
    ///
    /// Implementations must recheck the active policy version, target state,
    /// both identities, and all stable material in the mutation transaction.
    /// The transaction persists the mutation, consumed decision, stable intent,
    /// and receipt atomically. An exact concurrent winner returns its original
    /// receipt with [`AdminCommandExecution::Replayed`]; changed material or
    /// decision reuse returns conflict. [`AdminCommandExecution::Applied`] is
    /// reserved for a first mutation whose application time is no earlier than
    /// the command's trusted evaluation time. If commit acknowledgement is lost,
    /// return [`crate::AdminErrorCode::CommitIndeterminate`]; the next request
    /// reconciles the durable result through [`Self::find_replay`].
    ///
    /// # Errors
    ///
    /// Returns stable redacted errors for conflicts, interruption, unavailable
    /// storage, integrity failure, or indeterminate commit outcome.
    fn execute_once(
        &self,
        intent: &AdminCommandIntent,
        command: &AdminCommand,
        context: &RequestContext,
    ) -> Result<AdminCommandExecution, AdminError>;
}

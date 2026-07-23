//! Tenant-bound orchestration for existing user lifecycle aggregates.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_core::{PrincipalId, RequestContext, RequestId, TenantId, TraceId};
use ariadnion_user_domain::{
    User, UserId, UserTransition, UserTransitionCommand, UserVersion, UtcTimestamp,
    transition as domain_transition,
};

use crate::error::{
    integrity_failure, map_context_error, map_domain_error, map_repository_error, unauthenticated,
};
use crate::{UserRepositoryError, UserServiceError, UserServiceErrorCode};

/// Persistence operations required by the existing-user lifecycle service.
pub trait UserRepositoryPort: Send + Sync {
    /// Loads the exact user inside the supplied authenticated tenant boundary.
    ///
    /// Implementations return `NotFound` for an absent exact key, interruption
    /// codes for cancellation/deadline/resource limits, `Unavailable` for a
    /// deterministic transient access failure, and `IntegrityFailure` for
    /// malformed data.
    fn load(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        context: &RequestContext,
    ) -> Result<User, UserRepositoryError>;

    /// Atomically compares the old version and persists one transition pair.
    ///
    /// The new immutable [`User`] and its exactly corresponding lifecycle event
    /// must commit together or not at all. The comparison uses
    /// `expected_previous_version` under the same atomic boundary. A changed
    /// version returns repository `Conflict`; no partial user or event write is
    /// permitted. Success returns a receipt only after durable commit.
    /// `CommitIndeterminate` is reserved for a commit boundary whose durable
    /// result cannot be trusted. Cancellation, deadline, resource, and ordinary
    /// unavailable failures are definitive and must not use that code.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: UserVersion,
        transition: &UserTransition,
        context: &RequestContext,
    ) -> Result<UserCommitReceipt, UserRepositoryError>;

    /// Reconciles one indeterminate commit from durable evidence.
    ///
    /// Implementations must perform a read-only comparison of the target
    /// lifecycle event, audit chain membership, and outbox record. The current
    /// user snapshot may be the exact target or a later legal version from
    /// subsequent activity backed by its exact durable lifecycle event; a
    /// same-version snapshot must equal the target. Missing, behind, duplicate,
    /// malformed, or divergent evidence returns `IntegrityFailure`; this
    /// operation must never replay the transition. Adapters that invalidate a
    /// session after `CommitIndeterminate` require this read through a freshly
    /// opened repository instance.
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: UserVersion,
        transition: &UserTransition,
        context: &RequestContext,
    ) -> Result<UserCommitReceipt, UserRepositoryError>;
}

/// Bounded durable commit evidence returned by a trusted repository adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserCommitReceipt {
    tenant_id: TenantId,
    user_id: UserId,
    new_version: UserVersion,
    committed_at: UtcTimestamp,
}

impl UserCommitReceipt {
    /// Records trusted UTC evidence after an atomic durable commit succeeds.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        user_id: UserId,
        new_version: UserVersion,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            new_version,
            committed_at,
        }
    }

    /// Returns the authenticated tenant committed by the repository.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the committed user identity.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the newly committed aggregate version.
    #[must_use]
    pub const fn new_version(&self) -> UserVersion {
        self.new_version
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

/// One accepted domain transition coupled to its durable commit receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedUserTransition {
    transition: UserTransition,
    receipt: UserCommitReceipt,
}

/// A validated transition retained for commit retry or indeterminate recovery.
///
/// The prepared value owns the exact expected previous version and immutable
/// domain transition produced by [`UserService::prepare_transition`]. Callers
/// must retain it when a commit reports an indeterminate repository failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedUserTransition {
    expected_previous_version: UserVersion,
    transition: UserTransition,
    request_binding: PreparedRequestBinding,
}

impl PreparedUserTransition {
    /// Returns the version compared by the durable commit.
    #[must_use]
    pub const fn expected_previous_version(&self) -> UserVersion {
        self.expected_previous_version
    }

    /// Returns the exact immutable transition prepared for this attempt.
    #[must_use]
    pub const fn transition(&self) -> &UserTransition {
        &self.transition
    }
}

/// A redacted one-shot transition failure with optional recovery material.
///
/// Only a commit-indeterminate repository result retains the exact prepared
/// transition. Formatting never exposes that transition or its tenant,
/// principal, request, or trace bindings.
#[derive(Clone, Eq, PartialEq)]
pub struct UserTransitionError {
    error: UserServiceError,
    prepared: Option<Box<PreparedUserTransition>>,
}

impl UserTransitionError {
    fn ordinary(error: UserServiceError) -> Self {
        Self {
            error,
            prepared: None,
        }
    }

    fn indeterminate(error: UserServiceError, prepared: PreparedUserTransition) -> Self {
        Self {
            error,
            prepared: Some(Box::new(prepared)),
        }
    }

    /// Returns the stable redacted service error code.
    #[must_use]
    pub const fn code(&self) -> UserServiceErrorCode {
        self.error.code()
    }

    /// Returns the exact transition needed for indeterminate reconciliation.
    ///
    /// This is `Some` only when [`Self::code`] is
    /// [`UserServiceErrorCode::RepositoryCommitIndeterminate`]. The retained
    /// request binding still requires the original context at reconciliation
    /// time.
    #[must_use]
    pub fn prepared_transition(&self) -> Option<&PreparedUserTransition> {
        self.prepared.as_deref()
    }

    /// Consumes the failure and returns indeterminate recovery material.
    #[must_use]
    pub fn into_prepared_transition(self) -> Option<PreparedUserTransition> {
        self.prepared.map(|prepared| *prepared)
    }
}

impl Debug for UserTransitionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserTransitionError")
            .field("code", &self.error.code())
            .field("has_prepared_transition", &self.prepared.is_some())
            .finish()
    }
}

impl fmt::Display for UserTransitionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for UserTransitionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedRequestBinding {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    request_id: RequestId,
    trace_id: TraceId,
}

impl PreparedRequestBinding {
    fn from_context(context: &RequestContext) -> Result<Self, UserServiceError> {
        let principal = context.principal().ok_or_else(unauthenticated)?;
        Ok(Self {
            tenant_id: principal.tenant_id().clone(),
            principal_id: principal.principal_id().clone(),
            request_id: context.request_id().clone(),
            trace_id: context.trace_id().clone(),
        })
    }

    fn matches(&self, context: &RequestContext) -> bool {
        context.principal().is_some_and(|principal| {
            principal.tenant_id() == &self.tenant_id
                && principal.principal_id() == &self.principal_id
                && context.request_id() == &self.request_id
                && context.trace_id() == &self.trace_id
        })
    }
}

impl CommittedUserTransition {
    /// Returns the committed immutable aggregate and lifecycle event.
    #[must_use]
    pub const fn transition(&self) -> &UserTransition {
        &self.transition
    }

    /// Returns the repository's validated durable commit evidence.
    #[must_use]
    pub const fn receipt(&self) -> &UserCommitReceipt {
        &self.receipt
    }

    /// Consumes the result into its transition and receipt.
    #[must_use]
    pub fn into_parts(self) -> (UserTransition, UserCommitReceipt) {
        (self.transition, self.receipt)
    }
}

/// Applies lifecycle commands to existing users inside the authenticated tenant.
pub struct UserService {
    repository: Arc<dyn UserRepositoryPort>,
}

impl UserService {
    /// Creates a service over one repository implementation.
    #[must_use]
    pub fn new(repository: Arc<dyn UserRepositoryPort>) -> Self {
        Self { repository }
    }

    /// Applies and atomically commits one existing-user lifecycle command.
    ///
    /// The tenant comes only from [`RequestContext`]. The service checks
    /// cancellation and deadline state before loading and again immediately
    /// before compare-and-commit. It never creates users or invitations.
    ///
    /// # Errors
    /// Returns stable redacted service codes for unauthenticated requests,
    /// missing or inconsistent records, repository failures, interruption, or
    /// deterministic domain rejection. A commit-indeterminate failure
    /// reported after compare-and-commit means the durable write may already
    /// exist. In that case [`UserTransitionError`] retains the exact prepared
    /// transition for [`UserService::reconcile_prepared`]; callers must not
    /// blindly retry the command. Cancellation, deadline, resource, ordinary
    /// unavailable, and integrity failures are deterministic and do not retain
    /// recovery material.
    pub fn transition(
        &self,
        user_id: &UserId,
        command: UserTransitionCommand,
        context: &RequestContext,
    ) -> Result<CommittedUserTransition, UserTransitionError> {
        let prepared = self
            .prepare_transition(user_id, command, context)
            .map_err(UserTransitionError::ordinary)?;
        match self.commit_prepared(&prepared, context) {
            Ok(committed) => Ok(committed),
            Err(error) if error.code() == UserServiceErrorCode::RepositoryCommitIndeterminate => {
                Err(UserTransitionError::indeterminate(error, prepared))
            }
            Err(error) => Err(UserTransitionError::ordinary(error)),
        }
    }

    /// Prepares one exact transition without writing durable state.
    ///
    /// The returned value retains the loaded version and generated transition
    /// so an indeterminate commit can be reconciled without recomputing it. The
    /// authenticated tenant, principal, request, and trace are bound into the
    /// prepared value and cannot be substituted at commit time.
    ///
    /// # Errors
    /// Returns a stable redacted service error when the context is inactive or
    /// unauthenticated, the tenant-bound user is missing or inconsistent, the
    /// repository is unavailable, or the deterministic domain transition is
    /// rejected. No durable write is attempted by this method.
    pub fn prepare_transition(
        &self,
        user_id: &UserId,
        command: UserTransitionCommand,
        context: &RequestContext,
    ) -> Result<PreparedUserTransition, UserServiceError> {
        let loaded = self.load_current(user_id, context)?;
        let expected_previous_version = loaded.user.version();
        let transition = domain_transition(&loaded.user, command).map_err(map_domain_error)?;
        validate_transition(&loaded.tenant_id, user_id, &transition)?;
        let request_binding = PreparedRequestBinding::from_context(context)?;
        Ok(PreparedUserTransition {
            expected_previous_version,
            transition,
            request_binding,
        })
    }

    /// Commits a previously prepared transition under its original identity.
    ///
    /// The context must retain the exact tenant, principal, request, and trace
    /// binding captured during preparation. Cancellation or deadline expiry is
    /// checked before the repository call.
    ///
    /// # Errors
    /// Returns a stable redacted service error for an inactive or substituted
    /// context, version conflict, unavailable persistence, or inconsistent
    /// durable evidence. A [`UserServiceErrorCode::RepositoryCommitIndeterminate`]
    /// result is recoverable by retaining `prepared`; callers must reconcile it
    /// rather than invoking this method again.
    pub fn commit_prepared(
        &self,
        prepared: &PreparedUserTransition,
        context: &RequestContext,
    ) -> Result<CommittedUserTransition, UserServiceError> {
        check_context(context)?;
        let tenant_id = authenticated_tenant(context)?;
        validate_prepared(&tenant_id, prepared, context)?;
        self.commit(
            &tenant_id,
            prepared.expected_previous_version,
            prepared.transition.clone(),
            context,
        )
    }

    /// Reconciles a previously prepared indeterminate commit without writing.
    ///
    /// The original identity binding is revalidated before the repository
    /// reads exact lifecycle, audit, and outbox evidence. This method never
    /// replays the transition. If the previous adapter tainted its session at
    /// the ambiguous commit boundary, construct a fresh repository and service
    /// over a newly opened session before calling this method.
    ///
    /// # Errors
    /// Returns a stable redacted service error for an inactive or substituted
    /// context, unavailable persistence, or missing, malformed, duplicate, or
    /// divergent durable evidence.
    pub fn reconcile_prepared(
        &self,
        prepared: &PreparedUserTransition,
        context: &RequestContext,
    ) -> Result<CommittedUserTransition, UserServiceError> {
        check_context(context)?;
        let tenant_id = authenticated_tenant(context)?;
        validate_prepared(&tenant_id, prepared, context)?;
        let receipt = self
            .repository
            .reconcile_commit(
                &tenant_id,
                prepared.expected_previous_version,
                &prepared.transition,
                context,
            )
            .map_err(map_repository_error)?;
        validate_receipt(&tenant_id, &prepared.transition, &receipt)?;
        Ok(CommittedUserTransition {
            transition: prepared.transition.clone(),
            receipt,
        })
    }

    /// Reconciles a previously indeterminate repository commit.
    ///
    /// The tenant comes only from the authenticated request context. The
    /// supplied transition is checked against that tenant before the read-only
    /// repository call, and the returned receipt must exactly identify the
    /// transition's tenant, user, and new version.
    ///
    /// # Errors
    /// Returns stable redacted service codes for inactive or unauthenticated
    /// contexts, cross-tenant material, unavailable persistence, or durable
    /// evidence that is missing, malformed, duplicate, or divergent.
    pub fn reconcile_commit(
        &self,
        expected_previous_version: UserVersion,
        transition: UserTransition,
        context: &RequestContext,
    ) -> Result<CommittedUserTransition, UserServiceError> {
        check_context(context)?;
        let tenant_id = authenticated_tenant(context)?;
        validate_transition(&tenant_id, transition.user().id(), &transition)?;
        validate_version_step(expected_previous_version, &transition)?;
        let receipt = self
            .repository
            .reconcile_commit(&tenant_id, expected_previous_version, &transition, context)
            .map_err(map_repository_error)?;
        validate_receipt(&tenant_id, &transition, &receipt)?;
        Ok(CommittedUserTransition {
            transition,
            receipt,
        })
    }

    fn load_current(
        &self,
        user_id: &UserId,
        context: &RequestContext,
    ) -> Result<LoadedUser, UserServiceError> {
        check_context(context)?;
        let tenant_id = authenticated_tenant(context)?;
        let user = self
            .repository
            .load(&tenant_id, user_id, context)
            .map_err(map_repository_error)?;
        validate_loaded_user(&tenant_id, user_id, &user)?;
        Ok(LoadedUser { tenant_id, user })
    }

    fn commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: UserVersion,
        transition: UserTransition,
        context: &RequestContext,
    ) -> Result<CommittedUserTransition, UserServiceError> {
        check_context(context)?;
        let receipt = self
            .repository
            .compare_and_commit(tenant_id, expected_previous_version, &transition, context)
            .map_err(map_repository_error)?;
        validate_receipt(tenant_id, &transition, &receipt)?;
        Ok(CommittedUserTransition {
            transition,
            receipt,
        })
    }
}

impl Debug for UserService {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserService")
            .field("repository", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct LoadedUser {
    tenant_id: TenantId,
    user: User,
}

fn authenticated_tenant(context: &RequestContext) -> Result<TenantId, UserServiceError> {
    context
        .principal()
        .map(|principal| principal.tenant_id().clone())
        .ok_or_else(unauthenticated)
}

fn validate_loaded_user(
    tenant_id: &TenantId,
    user_id: &UserId,
    user: &User,
) -> Result<(), UserServiceError> {
    if user.tenant_id() != tenant_id || user.id() != user_id {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_transition(
    tenant_id: &TenantId,
    user_id: &UserId,
    transition: &UserTransition,
) -> Result<(), UserServiceError> {
    let user = transition.user();
    let event = transition.event();
    let aggregate_matches = user.tenant_id() == tenant_id && user.id() == user_id;
    let event_matches = event.tenant_id() == tenant_id
        && event.user_id() == user_id
        && event.version() == user.version();
    if !aggregate_matches || !event_matches {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_prepared(
    tenant_id: &TenantId,
    prepared: &PreparedUserTransition,
    context: &RequestContext,
) -> Result<(), UserServiceError> {
    validate_transition(
        tenant_id,
        prepared.transition.user().id(),
        &prepared.transition,
    )?;
    validate_version_step(prepared.expected_previous_version, &prepared.transition)?;
    if !prepared.request_binding.matches(context) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_version_step(
    expected_previous_version: UserVersion,
    transition: &UserTransition,
) -> Result<(), UserServiceError> {
    let expected = expected_previous_version
        .next()
        .map_err(|_| integrity_failure())?;
    if transition.user().version() != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_receipt(
    tenant_id: &TenantId,
    transition: &UserTransition,
    receipt: &UserCommitReceipt,
) -> Result<(), UserServiceError> {
    let user = transition.user();
    let matches = receipt.tenant_id() == tenant_id
        && receipt.user_id() == user.id()
        && receipt.new_version() == user.version();
    if !matches {
        return Err(integrity_failure());
    }
    Ok(())
}

fn check_context(context: &RequestContext) -> Result<(), UserServiceError> {
    context.check_active().map_err(map_context_error)
}

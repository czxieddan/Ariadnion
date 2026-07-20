//! Tenant-bound orchestration for existing user lifecycle aggregates.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_user_domain::{
    User, UserId, UserTransition, UserTransitionCommand, UserVersion, UtcTimestamp,
    transition as domain_transition,
};

use crate::error::{
    integrity_failure, map_context_error, map_domain_error, map_repository_error, unauthenticated,
};
use crate::{UserRepositoryError, UserServiceError};

/// Persistence operations required by the existing-user lifecycle service.
pub trait UserRepositoryPort: Send + Sync {
    /// Loads the exact user inside the supplied authenticated tenant boundary.
    ///
    /// Implementations return `NotFound` for an absent exact key, `Unavailable`
    /// for transient access failure, and `IntegrityFailure` for malformed data.
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
    fn compare_and_commit(
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
    /// deterministic domain rejection. A repository-integrity failure reported
    /// after compare-and-commit is indeterminate because the durable write may
    /// already exist; callers must reconcile by reading and must not blindly
    /// retry the command.
    pub fn transition(
        &self,
        user_id: &UserId,
        command: UserTransitionCommand,
        context: &RequestContext,
    ) -> Result<CommittedUserTransition, UserServiceError> {
        let loaded = self.load_current(user_id, context)?;
        let expected_previous_version = loaded.user.version();
        let transition = domain_transition(&loaded.user, command).map_err(map_domain_error)?;
        validate_transition(&loaded.tenant_id, user_id, &transition)?;
        self.commit(
            &loaded.tenant_id,
            expected_previous_version,
            transition,
            context,
        )
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

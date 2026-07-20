//! Pure user lifecycle types and deterministic state transitions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU64;

use ariadnion_core::TenantId;

const MAX_USER_ID_BYTES: usize = 128;

/// Stable machine-readable failures returned by user lifecycle operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum UserDomainErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The command expected a different optimistic user version.
    VersionConflict,
    /// The monotonic user version cannot be incremented.
    VersionExhausted,
    /// The requested lifecycle transition is not valid from the current state.
    InvalidTransition,
    /// Recovery evidence is absent, expired, or bound to another aggregate.
    RecoveryUnauthorized,
    /// Final deletion was requested before the stored not-before boundary.
    DeletionNotReady,
    /// A deleted user received another lifecycle command.
    DeletedTerminal,
}

impl UserDomainErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "USER_INVALID_ARGUMENT",
            Self::VersionConflict => "USER_VERSION_CONFLICT",
            Self::VersionExhausted => "USER_VERSION_EXHAUSTED",
            Self::InvalidTransition => "USER_INVALID_TRANSITION",
            Self::RecoveryUnauthorized => "USER_RECOVERY_UNAUTHORIZED",
            Self::DeletionNotReady => "USER_DELETION_NOT_READY",
            Self::DeletedTerminal => "USER_DELETED_TERMINAL",
        }
    }
}

/// A redacted user-domain error that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserDomainError {
    code: UserDomainErrorCode,
}

impl UserDomainError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: UserDomainErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> UserDomainErrorCode {
        self.code
    }
}

impl Display for UserDomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for UserDomainError {}

/// A bounded, path-free user aggregate identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UserId(Box<str>);

impl UserId {
    /// Parses a non-empty ASCII identity of at most 128 bytes.
    ///
    /// # Errors
    /// Returns [`UserDomainErrorCode::InvalidArgument`] without retaining the
    /// rejected value when its length or alphabet is invalid.
    pub fn parse(value: &str) -> Result<Self, UserDomainError> {
        if !valid_user_id(value) {
            return Err(error(UserDomainErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for UserId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("UserId(<opaque>)")
    }
}

/// A non-zero optimistic version for one user aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UserVersion(NonZeroU64);

impl UserVersion {
    /// Returns the version assigned to a newly invited user.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic version.
    ///
    /// # Errors
    /// Returns [`UserDomainErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, UserDomainError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(UserDomainErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic version.
    ///
    /// # Errors
    /// Returns [`UserDomainErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, UserDomainError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(UserDomainErrorCode::VersionExhausted))
    }
}

/// A UTC instant represented as signed seconds from the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcTimestamp(i64);

impl UtcTimestamp {
    /// Creates a UTC timestamp from signed Unix seconds.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Returns signed seconds from the Unix epoch.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }
}

/// A validated earliest UTC instant at which deletion may complete.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeletionNotBefore(UtcTimestamp);

impl DeletionNotBefore {
    /// Creates a boundary strictly later than the deletion request time.
    ///
    /// # Errors
    /// Returns [`UserDomainErrorCode::InvalidArgument`] when the boundary does
    /// not provide a positive cooling-off interval.
    pub fn new(
        requested_at: UtcTimestamp,
        boundary: UtcTimestamp,
    ) -> Result<Self, UserDomainError> {
        if boundary <= requested_at {
            return Err(error(UserDomainErrorCode::InvalidArgument));
        }
        Ok(Self(boundary))
    }

    /// Returns the UTC boundary.
    #[must_use]
    pub const fn timestamp(self) -> UtcTimestamp {
        self.0
    }
}

/// The complete public lifecycle state set for a user aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UserLifecycleState {
    /// The user can only consume the associated one-time invitation.
    Invited,
    /// The user may perform activity permitted by authorization policy.
    Active,
    /// New user activity must remain blocked.
    Suspended,
    /// Activity is blocked while the deletion cooling-off period runs.
    DeletionPending,
    /// The user has entered the irreversible terminal lifecycle state.
    Deleted,
}

/// The state restored when an authorized pending deletion is recovered.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeletionRecoveryState {
    /// Restore an active user to active operation.
    Active,
    /// Preserve the suspension that preceded the deletion request.
    Suspended,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingDeletion {
    not_before: DeletionNotBefore,
    recovery_state: DeletionRecoveryState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum UserState {
    Invited,
    Active,
    Suspended,
    DeletionPending(PendingDeletion),
    Deleted,
}

impl UserState {
    const fn lifecycle(&self) -> UserLifecycleState {
        match self {
            Self::Invited => UserLifecycleState::Invited,
            Self::Active => UserLifecycleState::Active,
            Self::Suspended => UserLifecycleState::Suspended,
            Self::DeletionPending(_) => UserLifecycleState::DeletionPending,
            Self::Deleted => UserLifecycleState::Deleted,
        }
    }
}

/// An immutable user aggregate with stable identity and tenant ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    id: UserId,
    tenant_id: TenantId,
    version: UserVersion,
    state: UserState,
}

impl User {
    /// Creates a newly invited user at the initial optimistic version.
    #[must_use]
    pub fn invited(id: UserId, tenant_id: TenantId) -> Self {
        Self {
            id,
            tenant_id,
            version: UserVersion::initial(),
            state: UserState::Invited,
        }
    }

    /// Returns the immutable aggregate identity.
    #[must_use]
    pub const fn id(&self) -> &UserId {
        &self.id
    }

    /// Returns the immutable owning tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the current optimistic version.
    #[must_use]
    pub const fn version(&self) -> UserVersion {
        self.version
    }

    /// Returns the current public lifecycle state.
    #[must_use]
    pub const fn lifecycle_state(&self) -> UserLifecycleState {
        self.state.lifecycle()
    }

    /// Returns the deletion boundary only while deletion is pending.
    #[must_use]
    pub const fn deletion_not_before(&self) -> Option<DeletionNotBefore> {
        match &self.state {
            UserState::DeletionPending(pending) => Some(pending.not_before),
            _ => None,
        }
    }
}

/// Time-bounded authorization evidence for one pending-deletion version.
///
/// A trusted authorization adapter constructs this value after policy
/// evaluation. The domain transition additionally verifies the tenant, user,
/// pending version, and validity interval, preventing cross-user use and replay
/// after another transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionRecoveryAuthorization {
    user_id: UserId,
    tenant_id: TenantId,
    pending_version: UserVersion,
    valid_from: UtcTimestamp,
    valid_until: UtcTimestamp,
}

impl DeletionRecoveryAuthorization {
    /// Creates authorization evidence bound to one user aggregate version.
    ///
    /// The caller must be a trusted adapter that has already evaluated policy.
    ///
    /// # Errors
    /// Returns [`UserDomainErrorCode::InvalidArgument`] for an inverted
    /// validity interval.
    pub fn new(
        user_id: UserId,
        tenant_id: TenantId,
        pending_version: UserVersion,
        valid_from: UtcTimestamp,
        valid_until: UtcTimestamp,
    ) -> Result<Self, UserDomainError> {
        if valid_until < valid_from {
            return Err(error(UserDomainErrorCode::InvalidArgument));
        }
        Ok(Self {
            user_id,
            tenant_id,
            pending_version,
            valid_from,
            valid_until,
        })
    }

    fn permits(&self, user: &User, observed_at: UtcTimestamp) -> bool {
        self.user_id == user.id
            && self.tenant_id == user.tenant_id
            && self.pending_version == user.version
            && observed_at >= self.valid_from
            && observed_at <= self.valid_until
    }
}

/// A requested user lifecycle change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserTransitionAction {
    /// Consumes the invited state and activates the user.
    Activate,
    /// Suspends an active user.
    Suspend,
    /// Restores a suspended user to active operation.
    Resume,
    /// Begins a deletion cooling-off period.
    RequestDeletion {
        /// UTC time at which the request was accepted.
        requested_at: UtcTimestamp,
        /// Earliest UTC time at which final deletion may occur.
        not_before: DeletionNotBefore,
    },
    /// Recovers a pending deletion using subject-bound authorization evidence.
    RecoverDeletion {
        /// Policy evidence bound to the current pending version.
        authorization: DeletionRecoveryAuthorization,
        /// Trusted UTC time used to validate the authorization interval.
        observed_at: UtcTimestamp,
    },
    /// Completes deletion once the cooling-off boundary has elapsed.
    CompleteDeletion {
        /// Trusted UTC time used to enforce the not-before boundary.
        observed_at: UtcTimestamp,
    },
}

/// A lifecycle action coupled to the caller's expected optimistic version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserTransitionCommand {
    expected_version: UserVersion,
    action: UserTransitionAction,
}

impl UserTransitionCommand {
    /// Creates a version-checked lifecycle command.
    #[must_use]
    pub const fn new(expected_version: UserVersion, action: UserTransitionAction) -> Self {
        Self {
            expected_version,
            action,
        }
    }

    /// Returns the optimistic version required by this command.
    #[must_use]
    pub const fn expected_version(&self) -> UserVersion {
        self.expected_version
    }

    /// Returns the requested lifecycle action.
    #[must_use]
    pub const fn action(&self) -> &UserTransitionAction {
        &self.action
    }
}

/// The domain-specific facts emitted by one accepted transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserLifecycleEventKind {
    /// An invited user became active.
    Activated,
    /// An active user became suspended.
    Suspended,
    /// A suspended user resumed active operation.
    Resumed,
    /// A deletion cooling-off period began.
    DeletionRequested {
        /// UTC time at which deletion was requested.
        requested_at: UtcTimestamp,
        /// Earliest UTC time at which deletion may complete.
        not_before: DeletionNotBefore,
        /// State to restore if the deletion is recovered.
        recovery_state: DeletionRecoveryState,
    },
    /// An authorized recovery restored the pre-deletion state.
    DeletionRecovered {
        /// UTC time at which recovery authorization was observed.
        recovered_at: UtcTimestamp,
        /// State restored by the recovery.
        restored_state: DeletionRecoveryState,
    },
    /// The user entered the terminal deleted state.
    Deleted {
        /// UTC time at which final deletion completed.
        deleted_at: UtcTimestamp,
    },
}

/// An immutable tenant-bound event emitted after a successful transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserLifecycleEvent {
    user_id: UserId,
    tenant_id: TenantId,
    version: UserVersion,
    kind: UserLifecycleEventKind,
}

impl UserLifecycleEvent {
    /// Returns the aggregate identity affected by this event.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the immutable owning tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the new aggregate version produced by this event.
    #[must_use]
    pub const fn version(&self) -> UserVersion {
        self.version
    }

    /// Returns the domain-specific event facts.
    #[must_use]
    pub const fn kind(&self) -> UserLifecycleEventKind {
        self.kind
    }
}

/// The new immutable aggregate and its exactly corresponding lifecycle event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserTransition {
    user: User,
    event: UserLifecycleEvent,
}

impl UserTransition {
    /// Returns the new immutable aggregate.
    #[must_use]
    pub const fn user(&self) -> &User {
        &self.user
    }

    /// Returns the event describing the accepted transition.
    #[must_use]
    pub const fn event(&self) -> &UserLifecycleEvent {
        &self.event
    }

    /// Consumes the result into its aggregate and event parts.
    #[must_use]
    pub fn into_parts(self) -> (User, UserLifecycleEvent) {
        (self.user, self.event)
    }
}

/// Applies a version-checked lifecycle command without mutating the input.
///
/// The result is deterministic for the supplied aggregate and command. The
/// caller supplies trusted UTC instants explicitly; this function reads no
/// clock, persistence, network, or process-global state.
///
/// # Errors
/// Returns a stable [`UserDomainErrorCode`] for optimistic-version conflicts,
/// invalid state transitions, failed recovery evidence, an early deletion, or
/// version exhaustion. Deleted users reject every command.
pub fn transition(
    current: &User,
    command: UserTransitionCommand,
) -> Result<UserTransition, UserDomainError> {
    verify_expected_version(current, command.expected_version)?;
    dispatch(current, command.action)
}

fn verify_expected_version(current: &User, expected: UserVersion) -> Result<(), UserDomainError> {
    if current.version != expected {
        return Err(error(UserDomainErrorCode::VersionConflict));
    }
    Ok(())
}

fn dispatch(
    current: &User,
    action: UserTransitionAction,
) -> Result<UserTransition, UserDomainError> {
    if matches!(current.state, UserState::Deleted) {
        return Err(error(UserDomainErrorCode::DeletedTerminal));
    }
    match action {
        UserTransitionAction::Activate => activate(current),
        UserTransitionAction::Suspend => suspend(current),
        UserTransitionAction::Resume => resume(current),
        UserTransitionAction::RequestDeletion {
            requested_at,
            not_before,
        } => request_deletion(current, requested_at, not_before),
        UserTransitionAction::RecoverDeletion {
            authorization,
            observed_at,
        } => recover_deletion(current, authorization, observed_at),
        UserTransitionAction::CompleteDeletion { observed_at } => {
            complete_deletion(current, observed_at)
        }
    }
}

fn activate(current: &User) -> Result<UserTransition, UserDomainError> {
    if !matches!(current.state, UserState::Invited) {
        return Err(error(UserDomainErrorCode::InvalidTransition));
    }
    evolve(
        current,
        UserState::Active,
        UserLifecycleEventKind::Activated,
    )
}

fn suspend(current: &User) -> Result<UserTransition, UserDomainError> {
    if !matches!(current.state, UserState::Active) {
        return Err(error(UserDomainErrorCode::InvalidTransition));
    }
    evolve(
        current,
        UserState::Suspended,
        UserLifecycleEventKind::Suspended,
    )
}

fn resume(current: &User) -> Result<UserTransition, UserDomainError> {
    if !matches!(current.state, UserState::Suspended) {
        return Err(error(UserDomainErrorCode::InvalidTransition));
    }
    evolve(current, UserState::Active, UserLifecycleEventKind::Resumed)
}

fn request_deletion(
    current: &User,
    requested_at: UtcTimestamp,
    not_before: DeletionNotBefore,
) -> Result<UserTransition, UserDomainError> {
    if not_before.timestamp() <= requested_at {
        return Err(error(UserDomainErrorCode::InvalidArgument));
    }
    let recovery_state = deletion_recovery_state(current)?;
    let pending = PendingDeletion {
        not_before,
        recovery_state,
    };
    let event = UserLifecycleEventKind::DeletionRequested {
        requested_at,
        not_before,
        recovery_state,
    };
    evolve(current, UserState::DeletionPending(pending), event)
}

fn deletion_recovery_state(current: &User) -> Result<DeletionRecoveryState, UserDomainError> {
    match current.state {
        UserState::Active => Ok(DeletionRecoveryState::Active),
        UserState::Suspended => Ok(DeletionRecoveryState::Suspended),
        _ => Err(error(UserDomainErrorCode::InvalidTransition)),
    }
}

fn recover_deletion(
    current: &User,
    authorization: DeletionRecoveryAuthorization,
    observed_at: UtcTimestamp,
) -> Result<UserTransition, UserDomainError> {
    let UserState::DeletionPending(pending) = &current.state else {
        return Err(error(UserDomainErrorCode::InvalidTransition));
    };
    if !authorization.permits(current, observed_at) {
        return Err(error(UserDomainErrorCode::RecoveryUnauthorized));
    }
    let state = restored_user_state(pending.recovery_state);
    let event = UserLifecycleEventKind::DeletionRecovered {
        recovered_at: observed_at,
        restored_state: pending.recovery_state,
    };
    evolve(current, state, event)
}

const fn restored_user_state(recovery: DeletionRecoveryState) -> UserState {
    match recovery {
        DeletionRecoveryState::Active => UserState::Active,
        DeletionRecoveryState::Suspended => UserState::Suspended,
    }
}

fn complete_deletion(
    current: &User,
    observed_at: UtcTimestamp,
) -> Result<UserTransition, UserDomainError> {
    let UserState::DeletionPending(pending) = &current.state else {
        return Err(error(UserDomainErrorCode::InvalidTransition));
    };
    if observed_at < pending.not_before.timestamp() {
        return Err(error(UserDomainErrorCode::DeletionNotReady));
    }
    evolve(
        current,
        UserState::Deleted,
        UserLifecycleEventKind::Deleted {
            deleted_at: observed_at,
        },
    )
}

fn evolve(
    current: &User,
    state: UserState,
    kind: UserLifecycleEventKind,
) -> Result<UserTransition, UserDomainError> {
    let version = current.version.next()?;
    let user = User {
        id: current.id.clone(),
        tenant_id: current.tenant_id.clone(),
        version,
        state,
    };
    let event = UserLifecycleEvent {
        user_id: current.id.clone(),
        tenant_id: current.tenant_id.clone(),
        version,
        kind,
    };
    Ok(UserTransition { user, event })
}

fn valid_user_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USER_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(is_user_id_byte)
}

fn is_user_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

const fn error(code: UserDomainErrorCode) -> UserDomainError {
    UserDomainError::new(code)
}

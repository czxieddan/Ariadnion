//! Stable redacted failures for user application services and repositories.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{CoreError, ErrorCode};
use ariadnion_user_domain::{UserDomainError, UserDomainErrorCode};

const USER_SERVICE_ERROR_CODES: [&str; 18] = [
    "USER_SERVICE_UNAUTHENTICATED",
    "USER_SERVICE_NOT_FOUND",
    "USER_SERVICE_REPOSITORY_CONFLICT",
    "USER_SERVICE_REPOSITORY_UNAVAILABLE",
    "USER_SERVICE_REPOSITORY_INTEGRITY_FAILURE",
    "USER_SERVICE_INVALID_ARGUMENT",
    "USER_SERVICE_VERSION_CONFLICT",
    "USER_SERVICE_VERSION_EXHAUSTED",
    "USER_SERVICE_INVALID_TRANSITION",
    "USER_SERVICE_RECOVERY_UNAUTHORIZED",
    "USER_SERVICE_DELETION_NOT_READY",
    "USER_SERVICE_DELETED_TERMINAL",
    "USER_SERVICE_DOMAIN_FAILURE",
    "USER_SERVICE_CANCELLED",
    "USER_SERVICE_DEADLINE_EXCEEDED",
    "USER_SERVICE_INTERNAL",
    "USER_SERVICE_REPOSITORY_RESOURCE_EXHAUSTED",
    "USER_SERVICE_REPOSITORY_COMMIT_INDETERMINATE",
];

/// Stable machine-readable failures returned by a user repository adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum UserRepositoryErrorCode {
    /// The exact tenant-bound user does not exist.
    NotFound,
    /// The expected previous version or another atomic precondition changed.
    Conflict,
    /// Cancellation was observed before a commit was attempted.
    Cancelled,
    /// The request deadline elapsed before a commit was attempted.
    DeadlineExceeded,
    /// A deterministic repository resource bound prevented the commit.
    ResourceExhausted,
    /// The repository cannot complete an otherwise valid operation.
    Unavailable,
    /// The commit boundary returned without a trustworthy durable outcome.
    CommitIndeterminate,
    /// Stored data, an atomic result, or a repository invariant is inconsistent.
    IntegrityFailure,
}

impl UserRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "USER_REPOSITORY_NOT_FOUND",
            Self::Conflict => "USER_REPOSITORY_CONFLICT",
            Self::Cancelled => "USER_REPOSITORY_CANCELLED",
            Self::DeadlineExceeded => "USER_REPOSITORY_DEADLINE_EXCEEDED",
            Self::ResourceExhausted => "USER_REPOSITORY_RESOURCE_EXHAUSTED",
            Self::Unavailable => "USER_REPOSITORY_UNAVAILABLE",
            Self::CommitIndeterminate => "USER_REPOSITORY_COMMIT_INDETERMINATE",
            Self::IntegrityFailure => "USER_REPOSITORY_INTEGRITY_FAILURE",
        }
    }
}

/// A redacted repository failure that never retains records or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserRepositoryError {
    code: UserRepositoryErrorCode,
}

impl UserRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: UserRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> UserRepositoryErrorCode {
        self.code
    }
}

impl Display for UserRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for UserRepositoryError {}

/// Stable machine-readable failures returned by [`crate::UserService`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum UserServiceErrorCode {
    /// The request has no authenticated principal and tenant.
    Unauthenticated,
    /// The exact tenant-bound user does not exist.
    UserNotFound,
    /// The repository rejected an optimistic or atomic precondition.
    RepositoryConflict,
    /// The repository is temporarily unavailable.
    RepositoryUnavailable,
    /// Repository data or a commit result violated a service invariant.
    RepositoryIntegrityFailure,
    /// A domain input failed bounded or semantic validation.
    InvalidArgument,
    /// The command expected another aggregate version.
    VersionConflict,
    /// The aggregate version cannot advance further.
    VersionExhausted,
    /// The requested lifecycle change is invalid from the current state.
    InvalidTransition,
    /// Pending-deletion recovery evidence did not authorize the transition.
    RecoveryUnauthorized,
    /// Final deletion was requested before its trusted UTC boundary.
    DeletionNotReady,
    /// A terminally deleted aggregate rejected another command.
    DeletedTerminal,
    /// A future domain failure has no more specific projection in this version.
    DomainFailure,
    /// Request cancellation stopped work before another repository operation.
    Cancelled,
    /// The request deadline elapsed before another repository operation.
    DeadlineExceeded,
    /// An unexpected core invariant failed without safe public details.
    Internal,
    /// A deterministic repository resource bound prevented the operation.
    RepositoryResourceExhausted,
    /// A commit may or may not be durable and requires read reconciliation.
    RepositoryCommitIndeterminate,
}

impl UserServiceErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        USER_SERVICE_ERROR_CODES[self as usize]
    }
}

/// A redacted service failure that never retains records or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserServiceError {
    code: UserServiceErrorCode,
}

impl UserServiceError {
    /// Creates a service error from one stable code.
    #[must_use]
    pub const fn new(code: UserServiceErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable service error code.
    #[must_use]
    pub const fn code(self) -> UserServiceErrorCode {
        self.code
    }
}

impl Display for UserServiceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for UserServiceError {}

pub(crate) fn map_context_error(error: CoreError) -> UserServiceError {
    let code = match error.code() {
        ErrorCode::Cancelled => UserServiceErrorCode::Cancelled,
        ErrorCode::DeadlineExceeded => UserServiceErrorCode::DeadlineExceeded,
        _ => UserServiceErrorCode::Internal,
    };
    UserServiceError::new(code)
}

pub(crate) fn map_repository_error(error: UserRepositoryError) -> UserServiceError {
    let code = match error.code() {
        UserRepositoryErrorCode::NotFound => UserServiceErrorCode::UserNotFound,
        UserRepositoryErrorCode::Conflict => UserServiceErrorCode::RepositoryConflict,
        UserRepositoryErrorCode::Cancelled => UserServiceErrorCode::Cancelled,
        UserRepositoryErrorCode::DeadlineExceeded => UserServiceErrorCode::DeadlineExceeded,
        UserRepositoryErrorCode::ResourceExhausted => {
            UserServiceErrorCode::RepositoryResourceExhausted
        }
        UserRepositoryErrorCode::Unavailable => UserServiceErrorCode::RepositoryUnavailable,
        UserRepositoryErrorCode::CommitIndeterminate => {
            UserServiceErrorCode::RepositoryCommitIndeterminate
        }
        UserRepositoryErrorCode::IntegrityFailure => {
            UserServiceErrorCode::RepositoryIntegrityFailure
        }
    };
    UserServiceError::new(code)
}

pub(crate) fn map_domain_error(error: UserDomainError) -> UserServiceError {
    let code = match error.code() {
        UserDomainErrorCode::InvalidArgument => UserServiceErrorCode::InvalidArgument,
        UserDomainErrorCode::VersionConflict => UserServiceErrorCode::VersionConflict,
        UserDomainErrorCode::VersionExhausted => UserServiceErrorCode::VersionExhausted,
        remaining => map_domain_state_error(remaining),
    };
    UserServiceError::new(code)
}

fn map_domain_state_error(code: UserDomainErrorCode) -> UserServiceErrorCode {
    match code {
        UserDomainErrorCode::InvalidTransition => UserServiceErrorCode::InvalidTransition,
        UserDomainErrorCode::RecoveryUnauthorized => UserServiceErrorCode::RecoveryUnauthorized,
        UserDomainErrorCode::DeletionNotReady => UserServiceErrorCode::DeletionNotReady,
        UserDomainErrorCode::DeletedTerminal => UserServiceErrorCode::DeletedTerminal,
        _ => UserServiceErrorCode::DomainFailure,
    }
}

pub(crate) const fn unauthenticated() -> UserServiceError {
    UserServiceError::new(UserServiceErrorCode::Unauthenticated)
}

pub(crate) const fn integrity_failure() -> UserServiceError {
    UserServiceError::new(UserServiceErrorCode::RepositoryIntegrityFailure)
}

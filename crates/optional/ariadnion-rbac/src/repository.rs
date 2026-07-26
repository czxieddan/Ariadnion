//! Stable persistence port and durable receipt types for authorization policies.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_user_domain::UtcTimestamp;

use crate::{AuthorizationPolicy, AuthorizationPolicyTransition, PolicyVersion};

const REPOSITORY_ERROR_CODES: [&str; 8] = [
    "RBAC_POLICY_REPOSITORY_NOT_FOUND",
    "RBAC_POLICY_REPOSITORY_CONFLICT",
    "RBAC_POLICY_REPOSITORY_CANCELLED",
    "RBAC_POLICY_REPOSITORY_DEADLINE_EXCEEDED",
    "RBAC_POLICY_REPOSITORY_RESOURCE_EXHAUSTED",
    "RBAC_POLICY_REPOSITORY_UNAVAILABLE",
    "RBAC_POLICY_REPOSITORY_COMMIT_INDETERMINATE",
    "RBAC_POLICY_REPOSITORY_INTEGRITY_FAILURE",
];

/// Persistence operations required by tenant-bound authorization workflows.
///
/// # Security invariants
///
/// Every method requires an authenticated [`RequestContext`]. Before any
/// storage access, implementations require its principal tenant to equal the
/// explicit `tenant_id`. Writes and reconciliation additionally require that
/// tenant to equal the transition, resulting policy, and event tenants, and
/// require the authenticated principal identity to equal the event actor. An
/// anonymous context or any binding mismatch returns
/// [`AuthorizationPolicyRepositoryErrorCode::IntegrityFailure`]. Repository
/// errors retain no tenant, policy content, event, decision, audit data, or
/// request context.
///
/// Loads authenticate the complete policy snapshot and contiguous event
/// history. Writes bind every role, rule, assignment, event, audit append, and
/// outbox record to the explicit tenant. Authorization decisions are transient
/// results and must never be loaded or persisted through this port.
pub trait AuthorizationPolicyRepositoryPort: Send + Sync {
    /// Loads the exact authorization policy inside its tenant boundary.
    ///
    /// An absent policy and any crossed durable binding return the same
    /// redacted [`AuthorizationPolicyRepositoryErrorCode::NotFound`] result.
    /// Malformed snapshots, non-contiguous events, or divergent tenant facts
    /// fail closed with an integrity error.
    fn load(
        &self,
        tenant_id: &TenantId,
        context: &RequestContext,
    ) -> Result<AuthorizationPolicy, AuthorizationPolicyRepositoryError>;

    /// Atomically compares the previous version and persists one transition.
    ///
    /// The complete policy snapshot, normalized role and assignment rows,
    /// exact policy event, audit-chain append, and outbox message commit
    /// together or not at all. Initial publication requires the durable tenant
    /// key to be absent and uses the initial expected version. Replacement
    /// compares both the version and exact previous snapshot before writing.
    /// The supplied expected version must equal the transition's expected
    /// previous version. All context, tenant, and actor bindings described by
    /// this trait are checked before I/O; a mismatch is an integrity failure.
    /// A changed precondition returns
    /// [`AuthorizationPolicyRepositoryErrorCode::Conflict`] with zero effects.
    ///
    /// Success is returned only after durable commit. An untrusted commit
    /// outcome returns
    /// [`AuthorizationPolicyRepositoryErrorCode::CommitIndeterminate`]; callers
    /// must not retry the write and must reconcile through a fresh repository
    /// session before issuing another transition.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: PolicyVersion,
        transition: &AuthorizationPolicyTransition,
        context: &RequestContext,
    ) -> Result<AuthorizationPolicyCommitReceipt, AuthorizationPolicyRepositoryError>;

    /// Reconciles one indeterminate commit from exact durable evidence.
    ///
    /// Implementations only read and authenticate the target snapshot, exact
    /// policy event, audit-chain membership, and outbox record. Reconciliation
    /// never writes, replays, or synthesizes a transition. A later policy is
    /// accepted only when contiguous authenticated events prove that the
    /// requested transition committed first. Missing, behind, malformed,
    /// duplicate, divergent, or pre-I/O context/transition binding evidence is
    /// an integrity failure.
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: PolicyVersion,
        transition: &AuthorizationPolicyTransition,
        context: &RequestContext,
    ) -> Result<AuthorizationPolicyCommitReceipt, AuthorizationPolicyRepositoryError>;
}

/// Stable machine-readable failures returned by a policy repository.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum AuthorizationPolicyRepositoryErrorCode {
    /// The exact tenant-bound authorization policy does not exist.
    NotFound,
    /// The expected version, snapshot, or another atomic precondition changed.
    Conflict,
    /// Cancellation was observed before a commit was attempted.
    Cancelled,
    /// The request deadline elapsed before a commit was attempted.
    DeadlineExceeded,
    /// A deterministic repository resource bound prevented the operation.
    ResourceExhausted,
    /// The repository cannot complete an otherwise valid operation.
    Unavailable,
    /// The commit boundary returned without a trustworthy durable outcome.
    CommitIndeterminate,
    /// Stored state, evidence, or an atomic result is inconsistent.
    IntegrityFailure,
}

impl AuthorizationPolicyRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        REPOSITORY_ERROR_CODES[self as usize]
    }
}

/// A redacted repository failure that never retains authorization material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicyRepositoryError {
    code: AuthorizationPolicyRepositoryErrorCode,
}

impl AuthorizationPolicyRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: AuthorizationPolicyRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> AuthorizationPolicyRepositoryErrorCode {
        self.code
    }
}

impl Display for AuthorizationPolicyRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AuthorizationPolicyRepositoryError {}

/// Bounded durable commit evidence returned by a trusted policy repository.
///
/// The receipt contains only the authenticated tenant, resulting version, and
/// trusted commit time. It never contains policy material, authorization
/// decisions, events, audit records, or outbox payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicyCommitReceipt {
    tenant_id: TenantId,
    new_version: PolicyVersion,
    committed_at: UtcTimestamp,
}

impl AuthorizationPolicyCommitReceipt {
    /// Records trusted UTC evidence after an atomic durable commit succeeds.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        new_version: PolicyVersion,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            new_version,
            committed_at,
        }
    }

    /// Returns the authenticated tenant committed by the repository.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the newly committed authorization policy version.
    #[must_use]
    pub const fn new_version(&self) -> PolicyVersion {
        self.new_version
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

//! Stable persistence port and durable receipt types for authorization policies.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_user_domain::UtcTimestamp;

use crate::{AuthorizationPolicy, AuthorizationPolicyTransition, PolicyVersion};

/// Persistence operations required by tenant-bound authorization workflows.
///
/// # Security invariants
///
/// Before I/O, every method requires an authenticated [`RequestContext`] whose
/// principal tenant equals the explicit `tenant_id`. Writes and reconciliation
/// also require that tenant to equal the transition, target policy, and event
/// tenants, the context principal to equal the event actor, and the supplied
/// expected version to equal the transition's expected previous version.
/// Anonymous, cross-context, argument, or transition binding mismatches return
/// [`AuthorizationPolicyRepositoryErrorCode::IntegrityFailure`]. A decoded row
/// whose tenant ownership diverges at any point is also an integrity failure.
/// [`AuthorizationPolicyRepositoryErrorCode::NotFound`] is reserved for an
/// authenticated `load` whose exact tenant-scoped policy row is absent.
///
/// Loads authenticate the complete policy snapshot and contiguous event
/// history. Writes bind every role, rule, assignment, event, audit append, and
/// outbox record to the explicit tenant. Authorization decisions are transient
/// results and must never be loaded or persisted through this port.
///
/// # Commit evidence
///
/// An adapter derives one commit-evidence identity from a length-delimited
/// canonical encoding of the original [`RequestContext::request_id`], explicit
/// tenant, expected previous version, event actor, event time, event version,
/// event kind, and target snapshot digest. The snapshot digest is SHA-256 over
/// the domain separator `ariadnion.rbac.policy-snapshot.v1` followed by every
/// field of the complete snapshot. The encoding includes sequence lengths,
/// scalar lengths, enum discriminants, and option-presence markers, and
/// preserves role, rule, and assignment order. Concatenation without lengths
/// or omission of a snapshot field is not canonical evidence.
///
/// The target snapshot and normalized rows, policy event with the original
/// request ID, audit evidence, and outbox identity and payload commit in one
/// transaction. The audit and outbox records carry the same evidence identity
/// and snapshot digest. The request ID remains persistence evidence and is not
/// added to the pure domain event.
pub trait AuthorizationPolicyRepositoryPort: Send + Sync {
    /// Loads the exact authorization policy inside its tenant boundary.
    ///
    /// After the pre-I/O context checks, an absent exact tenant row returns
    /// [`AuthorizationPolicyRepositoryErrorCode::NotFound`]. A decoded tenant
    /// mismatch, malformed snapshot, or divergent event history returns
    /// [`AuthorizationPolicyRepositoryErrorCode::IntegrityFailure`].
    fn load(
        &self,
        tenant_id: &TenantId,
        context: &RequestContext,
    ) -> Result<AuthorizationPolicy, AuthorizationPolicyRepositoryError>;

    /// Atomically compares the previous version and persists one transition.
    ///
    /// Initial publication atomically requires tenant-key absence. Replacement
    /// atomically compares the version and exact previous snapshot. A changed
    /// durable precondition returns
    /// [`AuthorizationPolicyRepositoryErrorCode::Conflict`] with zero effects.
    /// Caller or transition binding mismatches are integrity failures before
    /// I/O, not conflicts. All target, event, audit, outbox, request-ID, and
    /// digest evidence described by this trait commits atomically.
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
    /// Reconciliation is read-only and recomputes the evidence identity from
    /// the original request context, expected version, transition event, and
    /// complete target snapshot. It exactly verifies the policy-event request
    /// ID, audit evidence, outbox identity and payload, and snapshot digest.
    /// Missing, malformed, duplicate, or divergent evidence is an integrity
    /// failure. If indeterminate transition A is followed by different policy
    /// B with identical event actor, time, and kind, reconciling A returns
    /// [`AuthorizationPolicyRepositoryErrorCode::IntegrityFailure`], never a
    /// receipt for B. Adapters must enforce this collision case.
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
        match self {
            Self::NotFound => "RBAC_POLICY_REPOSITORY_NOT_FOUND",
            Self::Conflict => "RBAC_POLICY_REPOSITORY_CONFLICT",
            Self::Cancelled => "RBAC_POLICY_REPOSITORY_CANCELLED",
            Self::DeadlineExceeded => "RBAC_POLICY_REPOSITORY_DEADLINE_EXCEEDED",
            Self::ResourceExhausted
            | Self::Unavailable
            | Self::CommitIndeterminate
            | Self::IntegrityFailure => self.durability_code(),
        }
    }

    const fn durability_code(self) -> &'static str {
        match self {
            Self::ResourceExhausted => "RBAC_POLICY_REPOSITORY_RESOURCE_EXHAUSTED",
            Self::Unavailable => "RBAC_POLICY_REPOSITORY_UNAVAILABLE",
            Self::CommitIndeterminate => "RBAC_POLICY_REPOSITORY_COMMIT_INDETERMINATE",
            Self::IntegrityFailure => "RBAC_POLICY_REPOSITORY_INTEGRITY_FAILURE",
            Self::NotFound | Self::Conflict | Self::Cancelled | Self::DeadlineExceeded => {
                self.as_str()
            }
        }
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

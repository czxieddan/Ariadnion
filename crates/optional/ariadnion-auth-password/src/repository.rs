//! Stable persistence port and durable receipt types for password recovery.

use std::fmt::{self, Display, Formatter};

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::{
    PasswordCredential, PasswordCredentialReplacement, PasswordCredentialVersion, PasswordReset,
    PasswordResetEventKind, PasswordResetId, PasswordResetTokenDigest, PasswordResetTransition,
    PasswordResetVersion,
};

const REPOSITORY_ERROR_CODES: [&str; 8] = [
    "PASSWORD_REPOSITORY_NOT_FOUND",
    "PASSWORD_REPOSITORY_CONFLICT",
    "PASSWORD_REPOSITORY_CANCELLED",
    "PASSWORD_REPOSITORY_DEADLINE_EXCEEDED",
    "PASSWORD_REPOSITORY_RESOURCE_EXHAUSTED",
    "PASSWORD_REPOSITORY_UNAVAILABLE",
    "PASSWORD_REPOSITORY_COMMIT_INDETERMINATE",
    "PASSWORD_REPOSITORY_INTEGRITY_FAILURE",
];

/// Persistence operations required by tenant-bound password recovery.
///
/// # Security invariants
///
/// Every method must reject an anonymous [`RequestContext`] or one whose
/// authenticated principal tenant differs from the explicit `tenant_id` with
/// [`PasswordRepositoryErrorCode::IntegrityFailure`] before accessing
/// storage. Repository failures remain redacted and never retain identifiers,
/// request context, token digests, PHC records, or credential material.
///
/// Reset loads validate the complete snapshot and contiguous event history.
/// Credential loads validate the complete credential snapshot, including the
/// bounded PHC record, without formatting that record into failures. Absent
/// exact keys and cross-tenant keys are indistinguishable.
///
/// Before either write method performs I/O, the explicit tenant and user must
/// equal the transition reset, event, and replacement credential identities.
/// The reset and event reset ID, version, and issuance-bound credential
/// version must also agree. A mismatch is an integrity failure. A matching
/// request whose durable reset or credential version changed is a conflict.
pub trait PasswordRepositoryPort: Send + Sync {
    /// Loads one exact password credential inside its tenant boundary.
    ///
    /// Absent and cross-tenant keys return
    /// [`PasswordRepositoryErrorCode::NotFound`]. Malformed identities,
    /// versions, hash-policy metadata, or PHC records fail closed as
    /// [`PasswordRepositoryErrorCode::IntegrityFailure`].
    fn load_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        context: &RequestContext,
    ) -> Result<PasswordCredential, PasswordRepositoryError>;

    /// Loads one exact password reset inside its tenant and user boundary.
    ///
    /// Absent, cross-tenant, and cross-user keys return the same redacted
    /// [`PasswordRepositoryErrorCode::NotFound`] result. Malformed snapshots,
    /// missing commit evidence, or divergent event history fail closed as
    /// integrity failures.
    fn load_reset(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        reset_id: &PasswordResetId,
        context: &RequestContext,
    ) -> Result<PasswordReset, PasswordRepositoryError>;

    /// Loads one reset from a tenant-bound one-way token digest.
    ///
    /// This lookup never accepts or retains a plaintext reset token. An absent
    /// digest and a digest owned by another tenant or user are indistinguishable
    /// [`PasswordRepositoryErrorCode::NotFound`] results. Duplicate or malformed
    /// digest evidence is an integrity failure.
    fn load_reset_by_token_digest(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        token_digest: PasswordResetTokenDigest,
        context: &RequestContext,
    ) -> Result<PasswordReset, PasswordRepositoryError>;

    /// Atomically compares durable versions and persists one reset commit.
    ///
    /// Issuance starts a transaction and loads the exact tenant/user credential
    /// before any write. The credential must exist and its version must equal
    /// the version bound by the reset transition. Missing, stale, or future
    /// credential versions return [`PasswordRepositoryErrorCode::Conflict`]
    /// with zero writes. The repository then requires the reset identity and
    /// tenant token digest to be absent. It commits the reset snapshot, exact
    /// reset event, commit-evidence row, audit-chain append, and outbox message
    /// together or not at all.
    ///
    /// Revocation and expiry use the same atomic evidence set without a
    /// credential replacement. Every failure while the transaction is active
    /// rolls back the entire transaction; a failed rollback is an integrity
    /// failure. The initial expected reset version represents issuance only.
    ///
    /// Consumption additionally compares the credential version immutably
    /// bound at reset issuance, replaces that credential exactly once with the
    /// PHC record retained only by [`PasswordResetTransition`], advances the
    /// credential version once, and records the domain-produced hash-policy
    /// version in the same transaction. No reset survives an intervening
    /// password change. A changed reset version, credential version, digest,
    /// or other atomic precondition returns
    /// [`PasswordRepositoryErrorCode::Conflict`].
    ///
    /// Success is returned only after durable commit. An untrusted commit
    /// boundary returns [`PasswordRepositoryErrorCode::CommitIndeterminate`]
    /// and requires read-only reconciliation through a fresh repository
    /// session.
    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_reset_version: PasswordResetVersion,
        commit: &PasswordResetCommit<'_>,
        context: &RequestContext,
    ) -> Result<PasswordCommitReceipt, PasswordRepositoryError>;

    /// Reconciles one indeterminate password commit from durable evidence.
    ///
    /// Implementations only read and authenticate the target reset snapshot,
    /// reset event, commit-evidence row, credential replacement when present,
    /// audit-chain membership, and outbox record. Reconciliation never writes,
    /// replays, or synthesizes a transition. A current reset or credential may
    /// be later only when contiguous durable evidence proves the requested
    /// commit first occurred exactly as supplied. Missing, behind, malformed,
    /// duplicate, or divergent evidence is an integrity failure.
    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        expected_previous_reset_version: PasswordResetVersion,
        commit: &PasswordResetCommit<'_>,
        context: &RequestContext,
    ) -> Result<PasswordCommitReceipt, PasswordRepositoryError>;
}

/// Stable machine-readable failures returned by a password repository.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum PasswordRepositoryErrorCode {
    /// The exact tenant-bound password record does not exist.
    NotFound,
    /// A reset, credential, or other atomic precondition changed.
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
    /// Stored data, evidence, or an atomic result is inconsistent.
    IntegrityFailure,
}

impl PasswordRepositoryErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        REPOSITORY_ERROR_CODES[self as usize]
    }
}

/// A redacted repository failure that never retains password material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordRepositoryError {
    code: PasswordRepositoryErrorCode,
}

impl PasswordRepositoryError {
    /// Creates a repository error from one stable code.
    #[must_use]
    pub const fn new(code: PasswordRepositoryErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable repository error code.
    #[must_use]
    pub const fn code(self) -> PasswordRepositoryErrorCode {
        self.code
    }
}

impl Display for PasswordRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for PasswordRepositoryError {}

/// One typed password-reset persistence intent.
///
/// Construction prevents callers from representing consumption without a
/// credential replacement or attaching a replacement to issuance, revocation,
/// or expiry. Both variants borrow the original transition so the PHC record is
/// never copied into repository metadata.
#[derive(Debug)]
pub enum PasswordResetCommit<'a> {
    /// Reset issuance with an exact current-credential precondition.
    Issuance(PasswordResetIssuanceCommit<'a>),
    /// A reset-only revocation or expiry commit.
    ResetOnly(PasswordResetOnlyCommit<'a>),
    /// A consumed reset and its mandatory credential replacement.
    CredentialReplacement(PasswordCredentialReplacementCommit<'a>),
}

impl<'a> PasswordResetCommit<'a> {
    /// Creates an issuance commit bound to the current durable credential.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordRepositoryErrorCode::IntegrityFailure`] when the
    /// transition is not issuance or unexpectedly contains a replacement.
    pub fn issue(transition: &'a PasswordResetTransition) -> Result<Self, PasswordRepositoryError> {
        if !is_issuance(transition) {
            return Err(integrity_failure());
        }
        Ok(Self::Issuance(PasswordResetIssuanceCommit { transition }))
    }

    /// Creates a reset-only commit for revocation or expiry.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordRepositoryErrorCode::IntegrityFailure`] when the
    /// transition is issuance or consumption, or unexpectedly retains a
    /// credential replacement.
    pub fn reset_only(
        transition: &'a PasswordResetTransition,
    ) -> Result<Self, PasswordRepositoryError> {
        if !is_reset_only(transition) {
            return Err(integrity_failure());
        }
        Ok(Self::ResetOnly(PasswordResetOnlyCommit { transition }))
    }

    /// Creates a consumed-reset commit and derives its credential CAS versions.
    ///
    /// The expected credential version, exact successor, hash-policy version,
    /// and PHC record have already been bound by the pure domain transition.
    /// The repository intent cannot replace or reinterpret those values.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordRepositoryErrorCode::IntegrityFailure`] when the
    /// transition is not a consumption or lacks its typed replacement.
    pub fn consume(
        transition: &'a PasswordResetTransition,
    ) -> Result<Self, PasswordRepositoryError> {
        if !is_consumption(transition) {
            return Err(integrity_failure());
        }
        Ok(Self::CredentialReplacement(
            PasswordCredentialReplacementCommit { transition },
        ))
    }

    /// Returns the exact domain transition represented by this commit.
    #[must_use]
    pub const fn transition(&self) -> &PasswordResetTransition {
        match self {
            Self::Issuance(commit) => commit.transition,
            Self::ResetOnly(commit) => commit.transition,
            Self::CredentialReplacement(commit) => commit.transition,
        }
    }

    /// Returns issuance metadata only for a newly issued reset.
    #[must_use]
    pub const fn issuance(&self) -> Option<&PasswordResetIssuanceCommit<'a>> {
        match self {
            Self::Issuance(issuance) => Some(issuance),
            Self::ResetOnly(_) | Self::CredentialReplacement(_) => None,
        }
    }

    /// Returns credential-replacement metadata only for a consumed reset.
    #[must_use]
    pub const fn credential_replacement(&self) -> Option<&PasswordCredentialReplacement> {
        match self {
            Self::Issuance(_) | Self::ResetOnly(_) => None,
            Self::CredentialReplacement(commit) => commit.transition.credential_replacement(),
        }
    }
}

/// Reset issuance bound to one exact current credential version.
#[derive(Debug)]
pub struct PasswordResetIssuanceCommit<'a> {
    transition: &'a PasswordResetTransition,
}

impl<'a> PasswordResetIssuanceCommit<'a> {
    /// Returns the exact issuance transition.
    #[must_use]
    pub const fn transition(&self) -> &'a PasswordResetTransition {
        self.transition
    }

    /// Returns the credential version immutably bound during reset issuance.
    #[must_use]
    pub const fn expected_credential_version(&self) -> PasswordCredentialVersion {
        self.transition.reset().issued_credential_version()
    }

    /// Verifies the credential loaded inside the active issuance transaction.
    ///
    /// The repository must call this after loading by the same explicit tenant
    /// and user passed to `compare_and_commit`, and before inserting any reset,
    /// event, audit, or outbox row. Missing credentials and any lower or higher
    /// version return [`PasswordRepositoryErrorCode::Conflict`]. A tenant or
    /// user mismatch is an integrity failure. The error retains no credential,
    /// identifier, PHC record, or request context.
    ///
    /// # Errors
    ///
    /// Returns a redacted conflict or integrity failure as described above.
    pub fn verify_current_credential(
        &self,
        current: Option<&PasswordCredential>,
    ) -> Result<(), PasswordRepositoryError> {
        let current = current.ok_or_else(conflict)?;
        let reset = self.transition.reset();
        if current.tenant_id() != reset.tenant_id() || current.user_id() != reset.user_id() {
            return Err(integrity_failure());
        }
        if current.version() != self.expected_credential_version() {
            return Err(conflict());
        }
        Ok(())
    }
}

/// A reset-only commit that cannot contain credential replacement metadata.
#[derive(Debug)]
pub struct PasswordResetOnlyCommit<'a> {
    transition: &'a PasswordResetTransition,
}

impl<'a> PasswordResetOnlyCommit<'a> {
    /// Returns the exact issuance, revocation, or expiry transition.
    #[must_use]
    pub const fn transition(&self) -> &'a PasswordResetTransition {
        self.transition
    }
}

/// A consumed-reset commit that borrows its domain-produced replacement.
///
/// This wrapper cannot select a credential version, hash policy, or PHC record.
/// An adapter reads those values only from the associated domain transition
/// while its transaction is active and must not retain secret material in
/// errors, logs, audit details, or receipts.
#[derive(Debug)]
pub struct PasswordCredentialReplacementCommit<'a> {
    transition: &'a PasswordResetTransition,
}

impl<'a> PasswordCredentialReplacementCommit<'a> {
    /// Returns the consumed reset transition that owns the replacement PHC record.
    #[must_use]
    pub const fn transition(&self) -> &'a PasswordResetTransition {
        self.transition
    }
}

/// Bounded durable commit evidence returned by a trusted repository adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordCommitReceipt {
    tenant_id: TenantId,
    user_id: UserId,
    reset_id: PasswordResetId,
    new_reset_version: PasswordResetVersion,
    new_credential_version: Option<PasswordCredentialVersion>,
    committed_at: UtcTimestamp,
}

impl PasswordCommitReceipt {
    /// Records trusted UTC evidence after one atomic durable commit succeeds.
    ///
    /// `new_credential_version` is absent for reset-only commits and present
    /// for consumed-reset credential replacement. Repository adapters must
    /// construct this receipt only from authenticated committed facts.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        user_id: UserId,
        reset_id: PasswordResetId,
        new_reset_version: PasswordResetVersion,
        new_credential_version: Option<PasswordCredentialVersion>,
        committed_at: UtcTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            reset_id,
            new_reset_version,
            new_credential_version,
            committed_at,
        }
    }

    /// Returns the authenticated tenant committed by the repository.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the credential and reset owner committed by the repository.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the committed password-reset identity.
    #[must_use]
    pub const fn reset_id(&self) -> &PasswordResetId {
        &self.reset_id
    }

    /// Returns the newly committed password-reset version.
    #[must_use]
    pub const fn new_reset_version(&self) -> PasswordResetVersion {
        self.new_reset_version
    }

    /// Returns the newly committed credential version for consumption.
    #[must_use]
    pub const fn new_credential_version(&self) -> Option<PasswordCredentialVersion> {
        self.new_credential_version
    }

    /// Returns the trusted UTC durable commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UtcTimestamp {
        self.committed_at
    }
}

fn is_reset_only(transition: &PasswordResetTransition) -> bool {
    matches!(
        transition.event().kind(),
        PasswordResetEventKind::Revoked | PasswordResetEventKind::Expired
    ) && transition.credential_replacement().is_none()
}

fn is_issuance(transition: &PasswordResetTransition) -> bool {
    transition.event().kind() == PasswordResetEventKind::Issued
        && transition.credential_replacement().is_none()
}

fn is_consumption(transition: &PasswordResetTransition) -> bool {
    transition.event().kind() == PasswordResetEventKind::Consumed
        && transition.credential_replacement().is_some()
}

const fn integrity_failure() -> PasswordRepositoryError {
    PasswordRepositoryError::new(PasswordRepositoryErrorCode::IntegrityFailure)
}

const fn conflict() -> PasswordRepositoryError {
    PasswordRepositoryError::new(PasswordRepositoryErrorCode::Conflict)
}

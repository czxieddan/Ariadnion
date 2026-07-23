//! Immutable invitation aggregates and redacted proof digests.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_organization::OrganizationId;
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::error::error;
use crate::{InvitationError, InvitationErrorCode, InvitationId, InvitationVersion};

/// Maximum supported invitation lifetime in seconds.
pub const MAX_INVITATION_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

macro_rules! redacted_digest {
    ($name:ident, $documentation:literal, $label:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Creates a digest from exact SHA-256 bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the exact bytes for persistence and constant-time comparison.
            #[must_use]
            pub const fn bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str($label)
            }
        }
    };
}

redacted_digest!(
    InvitationTokenDigest,
    "A redacted SHA-256 digest of a high-entropy invitation token.",
    "InvitationTokenDigest(<sha256>)"
);
redacted_digest!(
    InvitationSubjectDigest,
    "A redacted SHA-256 digest of the normalized intended recipient.",
    "InvitationSubjectDigest(<sha256>)"
);

/// Stable lifecycle state of a one-time invitation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvitationState {
    /// The invitation may be consumed before its expiry boundary.
    Issued,
    /// The invitation was consumed exactly once.
    Consumed,
    /// An authorized actor revoked the invitation.
    Revoked,
    /// The explicit UTC expiry transition completed.
    Expired,
}

/// Stable identities that bind one invitation issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationIssueBinding {
    id: InvitationId,
    tenant_id: TenantId,
    organization_id: OrganizationId,
    issuer: PrincipalId,
}

impl InvitationIssueBinding {
    /// Creates a tenant- and organization-bound invitation identity.
    #[must_use]
    pub const fn new(
        id: InvitationId,
        tenant_id: TenantId,
        organization_id: OrganizationId,
        issuer: PrincipalId,
    ) -> Self {
        Self {
            id,
            tenant_id,
            organization_id,
            issuer,
        }
    }
}

/// Redacted proof digests retained for one invitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationProofDigests {
    subject_digest: InvitationSubjectDigest,
    token_digest: InvitationTokenDigest,
}

impl InvitationProofDigests {
    /// Creates the recipient and high-entropy token digest pair.
    #[must_use]
    pub const fn new(
        subject_digest: InvitationSubjectDigest,
        token_digest: InvitationTokenDigest,
    ) -> Self {
        Self {
            subject_digest,
            token_digest,
        }
    }
}

/// Trusted issuance and exclusive expiry instants for one invitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationValidityWindow {
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
}

impl InvitationValidityWindow {
    /// Creates a validity window; [`crate::issue`] validates its bounds.
    #[must_use]
    pub const fn new(issued_at: UtcTimestamp, expires_at: UtcTimestamp) -> Self {
        Self {
            issued_at,
            expires_at,
        }
    }
}

/// Complete typed state required to rehydrate one invitation without secrets.
///
/// The tenant and organization identities are retained together in the issue
/// binding, so callers cannot construct a snapshot with duplicated identity
/// fields that disagree. Digests are one-way proofs; plaintext invitation
/// tokens are never accepted by this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationSnapshotState {
    binding: InvitationIssueBinding,
    proofs: InvitationProofDigests,
    validity: InvitationValidityWindow,
    version: InvitationVersion,
    state: InvitationState,
    consumed_by: Option<UserId>,
}

impl InvitationSnapshotState {
    /// Creates a complete candidate snapshot for one invitation aggregate.
    ///
    /// The enclosing [`Invitation::from_snapshot`] constructor validates
    /// lifecycle/version reachability, expiry bounds, and consumer presence.
    #[must_use]
    pub const fn new(
        binding: InvitationIssueBinding,
        proofs: InvitationProofDigests,
        validity: InvitationValidityWindow,
        version: InvitationVersion,
        state: InvitationState,
        consumed_by: Option<UserId>,
    ) -> Self {
        Self {
            binding,
            proofs,
            validity,
            version,
            state,
            consumed_by,
        }
    }

    /// Returns the invitation identity.
    #[must_use]
    pub const fn id(&self) -> &InvitationId {
        &self.binding.id
    }

    /// Returns the tenant identity bound to the invitation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.binding.tenant_id
    }

    /// Returns the organization identity receiving the invitation.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.binding.organization_id
    }

    /// Returns the principal that issued the invitation.
    #[must_use]
    pub const fn issuer(&self) -> &PrincipalId {
        &self.binding.issuer
    }

    /// Returns the one-way intended-recipient digest.
    #[must_use]
    pub const fn subject_digest(&self) -> InvitationSubjectDigest {
        self.proofs.subject_digest
    }

    /// Returns the one-way invitation-token digest.
    #[must_use]
    pub const fn token_digest(&self) -> InvitationTokenDigest {
        self.proofs.token_digest
    }

    /// Returns the trusted issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UtcTimestamp {
        self.validity.issued_at
    }

    /// Returns the exclusive UTC expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> UtcTimestamp {
        self.validity.expires_at
    }

    /// Returns the optimistic aggregate version.
    #[must_use]
    pub const fn version(&self) -> InvitationVersion {
        self.version
    }

    /// Returns the persisted lifecycle state.
    #[must_use]
    pub const fn state(&self) -> InvitationState {
        self.state
    }

    /// Returns the consuming user, which is present only for `Consumed`.
    #[must_use]
    pub const fn consumed_by(&self) -> Option<&UserId> {
        self.consumed_by.as_ref()
    }
}

/// Immutable input required to issue one organization invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationIssueRequest {
    pub(crate) id: InvitationId,
    pub(crate) tenant_id: TenantId,
    pub(crate) organization_id: OrganizationId,
    pub(crate) issuer: PrincipalId,
    pub(crate) subject_digest: InvitationSubjectDigest,
    pub(crate) token_digest: InvitationTokenDigest,
    pub(crate) issued_at: UtcTimestamp,
    pub(crate) expires_at: UtcTimestamp,
}

impl InvitationIssueRequest {
    /// Creates immutable issuance input; [`crate::issue`] validates time bounds.
    #[must_use]
    pub fn new(
        binding: InvitationIssueBinding,
        proofs: InvitationProofDigests,
        validity: InvitationValidityWindow,
    ) -> Self {
        Self {
            id: binding.id,
            tenant_id: binding.tenant_id,
            organization_id: binding.organization_id,
            issuer: binding.issuer,
            subject_digest: proofs.subject_digest,
            token_digest: proofs.token_digest,
            issued_at: validity.issued_at,
            expires_at: validity.expires_at,
        }
    }
}

/// One immutable tenant-bound invitation aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invitation {
    id: InvitationId,
    tenant_id: TenantId,
    organization_id: OrganizationId,
    issuer: PrincipalId,
    subject_digest: InvitationSubjectDigest,
    token_digest: InvitationTokenDigest,
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
    version: InvitationVersion,
    state: InvitationState,
    consumed_by: Option<UserId>,
}

impl Invitation {
    /// Reconstructs an invitation from a complete persisted snapshot.
    ///
    /// The constructor accepts only typed identities and redacted digests. It
    /// revalidates the exclusive expiry window and the reachable lifecycle
    /// version combinations before constructing the aggregate.
    ///
    /// # Errors
    /// Returns [`InvitationErrorCode::InvalidArgument`] when persisted state is
    /// unreachable, has an invalid expiry window, or has an inconsistent
    /// consumer and lifecycle state.
    pub fn from_snapshot(snapshot: InvitationSnapshotState) -> Result<Self, InvitationError> {
        validate_snapshot(&snapshot)?;
        let InvitationSnapshotState {
            binding,
            proofs,
            validity,
            version,
            state,
            consumed_by,
        } = snapshot;
        let InvitationIssueBinding {
            id,
            tenant_id,
            organization_id,
            issuer,
        } = binding;
        let InvitationProofDigests {
            subject_digest,
            token_digest,
        } = proofs;
        Ok(Self {
            id,
            tenant_id,
            organization_id,
            issuer,
            subject_digest,
            token_digest,
            issued_at: validity.issued_at,
            expires_at: validity.expires_at,
            version,
            state,
            consumed_by,
        })
    }

    pub(crate) fn issued(request: InvitationIssueRequest) -> Self {
        Self {
            id: request.id,
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            issuer: request.issuer,
            subject_digest: request.subject_digest,
            token_digest: request.token_digest,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            version: InvitationVersion::initial(),
            state: InvitationState::Issued,
            consumed_by: None,
        }
    }

    pub(crate) fn advance(
        &self,
        version: InvitationVersion,
        state: InvitationState,
        consumed_by: Option<UserId>,
    ) -> Self {
        let mut next = self.clone();
        next.version = version;
        next.state = state;
        next.consumed_by = consumed_by;
        next
    }

    /// Returns the invitation identity.
    #[must_use]
    pub const fn id(&self) -> &InvitationId {
        &self.id
    }

    /// Returns the tenant that owns the invitation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the organization receiving the invited member.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the issuing principal.
    #[must_use]
    pub const fn issuer(&self) -> &PrincipalId {
        &self.issuer
    }

    /// Returns the one-way intended-recipient digest.
    #[must_use]
    pub const fn subject_digest(&self) -> InvitationSubjectDigest {
        self.subject_digest
    }

    /// Returns the one-way high-entropy token digest.
    #[must_use]
    pub const fn token_digest(&self) -> InvitationTokenDigest {
        self.token_digest
    }

    /// Returns the trusted issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UtcTimestamp {
        self.issued_at
    }

    /// Returns the exclusive UTC expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> UtcTimestamp {
        self.expires_at
    }

    /// Returns the current optimistic version.
    #[must_use]
    pub const fn version(&self) -> InvitationVersion {
        self.version
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn state(&self) -> InvitationState {
        self.state
    }

    /// Returns the consuming user only after successful one-time consumption.
    #[must_use]
    pub const fn consumed_by(&self) -> Option<&UserId> {
        self.consumed_by.as_ref()
    }

    /// Returns the complete state required for lossless persistence.
    #[must_use]
    pub fn snapshot_state(&self) -> InvitationSnapshotState {
        InvitationSnapshotState::new(
            InvitationIssueBinding::new(
                self.id.clone(),
                self.tenant_id.clone(),
                self.organization_id.clone(),
                self.issuer.clone(),
            ),
            InvitationProofDigests::new(self.subject_digest, self.token_digest),
            InvitationValidityWindow::new(self.issued_at, self.expires_at),
            self.version,
            self.state,
            self.consumed_by.clone(),
        )
    }
}

fn validate_snapshot(snapshot: &InvitationSnapshotState) -> Result<(), InvitationError> {
    validate_snapshot_lifetime(snapshot.validity)?;
    validate_snapshot_lifecycle(
        snapshot.version,
        snapshot.state,
        snapshot.consumed_by.is_some(),
    )
}

fn validate_snapshot_lifetime(validity: InvitationValidityWindow) -> Result<(), InvitationError> {
    let lifetime = validity
        .expires_at
        .unix_seconds()
        .checked_sub(validity.issued_at.unix_seconds())
        .ok_or_else(|| error(InvitationErrorCode::InvalidArgument))?;
    if !(1..=MAX_INVITATION_LIFETIME_SECONDS).contains(&lifetime) {
        return Err(error(InvitationErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_snapshot_lifecycle(
    version: InvitationVersion,
    state: InvitationState,
    has_consumer: bool,
) -> Result<(), InvitationError> {
    let reachable = matches!(
        (version.get(), state, has_consumer),
        (1, InvitationState::Issued, false)
            | (2, InvitationState::Consumed, true)
            | (
                2,
                InvitationState::Revoked | InvitationState::Expired,
                false
            )
    );
    if reachable {
        Ok(())
    } else {
        Err(error(InvitationErrorCode::InvalidArgument))
    }
}

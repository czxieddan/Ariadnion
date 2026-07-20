//! Immutable invitation aggregates and redacted proof digests.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_organization::OrganizationId;
use ariadnion_user_domain::{UserId, UtcTimestamp};

use crate::{InvitationId, InvitationVersion};

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
}

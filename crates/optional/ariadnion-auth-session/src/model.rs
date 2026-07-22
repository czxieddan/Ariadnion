//! Immutable browser session-family model values.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

use crate::{SessionFamilyId, SessionFamilyVersion, SessionId, SessionVersion};

/// Maximum supported absolute browser session-family lifetime in seconds.
pub const MAX_ABSOLUTE_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
/// Maximum supported idle lifetime in seconds for an active leaf.
pub const MAX_IDLE_LIFETIME_SECONDS: i64 = 12 * 60 * 60;
/// Minimum accepted high-entropy session token length in bytes.
pub const MIN_SESSION_TOKEN_BYTES: usize = 32;
/// Maximum accepted high-entropy session token length in bytes.
pub const MAX_SESSION_TOKEN_BYTES: usize = 256;
/// Maximum rotated leaves retained for family-wide token-reuse detection.
pub const MAX_ROTATED_SESSIONS: usize = 4_096;

const SESSION_TOKEN_DOMAIN: &[u8] = b"ariadnion.browser-session.token.v1\0";

/// Tenant and user identities that bind one browser session family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSubject {
    tenant_id: TenantId,
    user_id: UserId,
}

impl SessionSubject {
    /// Creates a tenant-bound user subject.
    #[must_use]
    pub const fn new(tenant_id: TenantId, user_id: UserId) -> Self {
        Self { tenant_id, user_id }
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the user identity.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

/// A domain-separated SHA-256 digest of a browser session token.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SessionTokenDigest([u8; 32]);

impl SessionTokenDigest {
    /// Derives a digest from a high-entropy token without retaining plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`crate::SessionErrorCode::InvalidArgument`] when the token is
    /// outside the supported byte bounds.
    pub fn from_token(token: &[u8]) -> Result<Self, crate::SessionError> {
        if !(MIN_SESSION_TOKEN_BYTES..=MAX_SESSION_TOKEN_BYTES).contains(&token.len()) {
            return Err(crate::error::error(
                crate::SessionErrorCode::InvalidArgument,
            ));
        }
        Ok(Self(domain_separated_digest(SESSION_TOKEN_DOMAIN, token)))
    }

    /// Creates a digest from exact SHA-256 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes for persistence or constant-time comparison.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn ct_matches(self, presented: Self) -> Choice {
        self.0.ct_eq(&presented.0)
    }
}

impl Debug for SessionTokenDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionTokenDigest(<sha256>)")
    }
}

/// Alias for presentation proof digests retained by adapters.
pub type SessionProofDigest = SessionTokenDigest;

/// Stable lifecycle state of one leaf session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionState {
    /// The leaf is the current active presenter for the family.
    Active,
    /// The leaf was rotated out by a successor leaf.
    Rotated,
    /// The family revoked this leaf.
    Revoked,
    /// The exclusive expiry transition completed for this leaf.
    Expired,
}

/// Stable lifecycle state of one browser session family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionFamilyState {
    /// The family has an active leaf that may rotate.
    Active,
    /// An authorized actor revoked every leaf in the family.
    Revoked,
    /// The exclusive absolute expiry transition completed.
    Expired,
}

/// Stable identities that bind one session-family issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIssueBinding {
    family_id: SessionFamilyId,
    session_id: SessionId,
    subject: SessionSubject,
    actor: PrincipalId,
}

impl SessionIssueBinding {
    /// Creates a tenant- and user-bound session-family identity.
    #[must_use]
    pub const fn new(
        family_id: SessionFamilyId,
        session_id: SessionId,
        subject: SessionSubject,
        actor: PrincipalId,
    ) -> Self {
        Self {
            family_id,
            session_id,
            subject,
            actor,
        }
    }

    /// Returns the family identity.
    #[must_use]
    pub const fn family_id(&self) -> &SessionFamilyId {
        &self.family_id
    }

    /// Returns the first leaf identity.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the subject boundary.
    #[must_use]
    pub const fn subject(&self) -> &SessionSubject {
        &self.subject
    }

    /// Returns the trusted actor that issued the family.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

/// Trusted absolute and idle UTC windows for one browser session family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionValidityWindow {
    issued_at: UtcTimestamp,
    absolute_expires_at: UtcTimestamp,
    idle_expires_at: UtcTimestamp,
}

impl SessionValidityWindow {
    /// Couples trusted absolute and idle expiry boundaries.
    #[must_use]
    pub const fn new(
        issued_at: UtcTimestamp,
        absolute_expires_at: UtcTimestamp,
        idle_expires_at: UtcTimestamp,
    ) -> Self {
        Self {
            issued_at,
            absolute_expires_at,
            idle_expires_at,
        }
    }

    /// Returns the trusted issuance time.
    #[must_use]
    pub const fn issued_at(self) -> UtcTimestamp {
        self.issued_at
    }

    /// Returns the exclusive absolute expiry boundary.
    #[must_use]
    pub const fn absolute_expires_at(self) -> UtcTimestamp {
        self.absolute_expires_at
    }

    /// Returns the exclusive idle expiry boundary for the current leaf.
    #[must_use]
    pub const fn idle_expires_at(self) -> UtcTimestamp {
        self.idle_expires_at
    }
}

/// Immutable inputs required to issue one browser session family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIssueRequest {
    binding: SessionIssueBinding,
    token_digest: SessionTokenDigest,
    validity: SessionValidityWindow,
}

impl SessionIssueRequest {
    /// Creates an issue request for one active family leaf.
    #[must_use]
    pub const fn new(
        binding: SessionIssueBinding,
        token_digest: SessionTokenDigest,
        validity: SessionValidityWindow,
    ) -> Self {
        Self {
            binding,
            token_digest,
            validity,
        }
    }

    /// Returns the issue binding.
    #[must_use]
    pub const fn binding(&self) -> &SessionIssueBinding {
        &self.binding
    }

    /// Returns the leaf token digest.
    #[must_use]
    pub const fn token_digest(&self) -> SessionTokenDigest {
        self.token_digest
    }

    /// Returns the validity windows.
    #[must_use]
    pub const fn validity(&self) -> SessionValidityWindow {
        self.validity
    }
}

/// One immutable leaf session that never retains plaintext tokens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    id: SessionId,
    token_digest: SessionTokenDigest,
    issued_at: UtcTimestamp,
    last_seen_at: UtcTimestamp,
    idle_expires_at: UtcTimestamp,
    version: SessionVersion,
    state: SessionState,
    predecessor_id: Option<SessionId>,
}

impl Session {
    /// Returns the leaf identity.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the stored one-way token digest.
    #[must_use]
    pub const fn token_digest(&self) -> SessionTokenDigest {
        self.token_digest
    }

    /// Returns the trusted leaf issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UtcTimestamp {
        self.issued_at
    }

    /// Returns the trusted last-seen time for idle expiry.
    #[must_use]
    pub const fn last_seen_at(&self) -> UtcTimestamp {
        self.last_seen_at
    }

    /// Returns the exclusive idle expiry boundary for this leaf.
    #[must_use]
    pub const fn idle_expires_at(&self) -> UtcTimestamp {
        self.idle_expires_at
    }

    /// Returns the current optimistic leaf version.
    #[must_use]
    pub const fn version(&self) -> SessionVersion {
        self.version
    }

    /// Returns the current leaf state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the previous leaf identity after a rotation.
    #[must_use]
    pub const fn predecessor_id(&self) -> Option<&SessionId> {
        self.predecessor_id.as_ref()
    }

    pub(crate) fn active_leaf(
        id: SessionId,
        token_digest: SessionTokenDigest,
        issued_at: UtcTimestamp,
        idle_expires_at: UtcTimestamp,
        predecessor_id: Option<SessionId>,
    ) -> Self {
        Self {
            id,
            token_digest,
            issued_at,
            last_seen_at: issued_at,
            idle_expires_at,
            version: SessionVersion::initial(),
            state: SessionState::Active,
            predecessor_id,
        }
    }

    pub(crate) fn with_state(&self, state: SessionState) -> Self {
        Self {
            id: self.id.clone(),
            token_digest: self.token_digest,
            issued_at: self.issued_at,
            last_seen_at: self.last_seen_at,
            idle_expires_at: self.idle_expires_at,
            version: self.version,
            state,
            predecessor_id: self.predecessor_id.clone(),
        }
    }
}

/// An immutable tenant-bound browser session family containing only digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionFamily {
    id: SessionFamilyId,
    subject: SessionSubject,
    absolute_expires_at: UtcTimestamp,
    issued_at: UtcTimestamp,
    version: SessionFamilyVersion,
    state: SessionFamilyState,
    current: Session,
    rotated: Vec<Session>,
}

impl SessionFamily {
    /// Returns the family identity.
    #[must_use]
    pub const fn id(&self) -> &SessionFamilyId {
        &self.id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.subject.tenant_id()
    }

    /// Returns the user identity.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        self.subject.user_id()
    }

    /// Returns the subject binding.
    #[must_use]
    pub const fn subject(&self) -> &SessionSubject {
        &self.subject
    }

    /// Returns the exclusive absolute expiry boundary.
    #[must_use]
    pub const fn absolute_expires_at(&self) -> UtcTimestamp {
        self.absolute_expires_at
    }

    /// Returns the trusted family issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UtcTimestamp {
        self.issued_at
    }

    /// Returns the current optimistic family version.
    #[must_use]
    pub const fn version(&self) -> SessionFamilyVersion {
        self.version
    }

    /// Returns the family lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SessionFamilyState {
        self.state
    }

    /// Returns the current leaf session.
    #[must_use]
    pub const fn current(&self) -> &Session {
        &self.current
    }

    /// Returns the immediately previous leaf when one exists.
    #[must_use]
    pub const fn previous(&self) -> Option<&Session> {
        self.rotated.as_slice().last()
    }

    /// Returns all rotated leaves in issuance order.
    ///
    /// The collection contains at most [`MAX_ROTATED_SESSIONS`] entries and
    /// lets persistence adapters retain every digest needed to detect reuse.
    #[must_use]
    pub fn rotated(&self) -> &[Session] {
        &self.rotated
    }

    pub(crate) fn issued(request: SessionIssueRequest) -> Self {
        let leaf = Session::active_leaf(
            request.binding.session_id,
            request.token_digest,
            request.validity.issued_at,
            request.validity.idle_expires_at,
            None,
        );
        Self {
            id: request.binding.family_id,
            subject: request.binding.subject,
            absolute_expires_at: request.validity.absolute_expires_at,
            issued_at: request.validity.issued_at,
            version: SessionFamilyVersion::initial(),
            state: SessionFamilyState::Active,
            current: leaf,
            rotated: Vec::new(),
        }
    }

    pub(crate) fn advance(
        &self,
        version: SessionFamilyVersion,
        state: SessionFamilyState,
        current: Session,
        rotated: Vec<Session>,
    ) -> Self {
        Self {
            id: self.id.clone(),
            subject: self.subject.clone(),
            absolute_expires_at: self.absolute_expires_at,
            issued_at: self.issued_at,
            version,
            state,
            current,
            rotated,
        }
    }
}

fn domain_separated_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

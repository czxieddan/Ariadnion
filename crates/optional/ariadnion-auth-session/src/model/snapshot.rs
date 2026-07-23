//! Validated durable snapshots for browser session families.

use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};

use crate::error::error;
use crate::{
    MAX_ABSOLUTE_LIFETIME_SECONDS, MAX_IDLE_LIFETIME_SECONDS, MAX_ROTATED_SESSIONS, Session,
    SessionError, SessionErrorCode, SessionFamily, SessionFamilyId, SessionFamilyState,
    SessionFamilyVersion, SessionId, SessionState, SessionSubject, SessionTokenDigest,
    SessionVersion,
};
use ariadnion_user_domain::UtcTimestamp;

/// Complete typed state for one persisted leaf session.
///
/// The repeated family and subject bindings let the aggregate reconstruction
/// boundary reject rows assembled across tenants, users, or families. Token
/// material is represented only by a one-way digest.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionSnapshot {
    /// Family identity stored with this leaf.
    pub family_id: SessionFamilyId,
    /// Tenant and user identities stored with this leaf.
    pub subject: SessionSubject,
    /// Stable leaf-session identity.
    pub id: SessionId,
    /// Domain-separated digest of the leaf token.
    pub token_digest: SessionTokenDigest,
    /// Trusted leaf issuance time.
    pub issued_at: UtcTimestamp,
    /// Trusted most recent presentation time used for idle bounds.
    pub last_seen_at: UtcTimestamp,
    /// Exclusive idle-expiry boundary.
    pub idle_expires_at: UtcTimestamp,
    /// Non-zero optimistic leaf version.
    pub version: SessionVersion,
    /// Persisted leaf lifecycle state.
    pub state: SessionState,
    /// Immediately preceding leaf identity, absent only for the first leaf.
    pub predecessor_id: Option<SessionId>,
}

impl Debug for SessionSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionSnapshot")
            .field("family_id", &self.family_id)
            .field("subject", &self.subject)
            .field("id", &self.id)
            .field("token_digest", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("last_seen_at", &self.last_seen_at)
            .field("idle_expires_at", &self.idle_expires_at)
            .field("version", &self.version)
            .field("state", &self.state)
            .field("predecessor_id", &self.predecessor_id)
            .finish()
    }
}

/// Complete lossless state required to reconstruct one session family.
///
/// Rotated leaves remain in deterministic issuance order so predecessor links
/// and every reuse-detection digest survive a restart.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionFamilySnapshot {
    /// Stable family identity.
    pub id: SessionFamilyId,
    /// Tenant and user identities owning the family.
    pub subject: SessionSubject,
    /// Trusted family issuance time.
    pub issued_at: UtcTimestamp,
    /// Exclusive absolute-expiry boundary.
    pub absolute_expires_at: UtcTimestamp,
    /// Non-zero optimistic family version.
    pub version: SessionFamilyVersion,
    /// Persisted family lifecycle state.
    pub state: SessionFamilyState,
    /// Current leaf, including its digest and predecessor link.
    pub current: SessionSnapshot,
    /// Rotated leaves in deterministic issuance order.
    pub rotated: Vec<SessionSnapshot>,
}

impl Debug for SessionFamilySnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionFamilySnapshot")
            .field("id", &self.id)
            .field("subject", &self.subject)
            .field("issued_at", &self.issued_at)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .field("version", &self.version)
            .field("state", &self.state)
            .field("current", &self.current)
            .field("rotated_leaf_count", &self.rotated.len())
            .finish()
    }
}

impl SessionFamily {
    /// Reconstructs a family from one complete typed persistence snapshot.
    ///
    /// The boundary validates capacity before allocation, then revalidates
    /// family and leaf versions, lifecycle state, tenant/user/family binding,
    /// timestamp bounds, predecessor order, and identity/digest uniqueness.
    /// It accepts only digests and never receives a plaintext token or cookie.
    ///
    /// # Errors
    ///
    /// Returns [`SessionErrorCode::ResourceLimitExceeded`] for oversized
    /// history, the corresponding family/tenant/user mismatch code for crossed
    /// leaf bindings, or [`SessionErrorCode::InvalidArgument`] for any other
    /// state that is not reachable through the public transition API.
    pub fn from_snapshot(snapshot: SessionFamilySnapshot) -> Result<Self, SessionError> {
        validate_snapshot(&snapshot)?;
        Ok(Self {
            id: snapshot.id,
            subject: snapshot.subject,
            absolute_expires_at: snapshot.absolute_expires_at,
            issued_at: snapshot.issued_at,
            version: snapshot.version,
            state: snapshot.state,
            current: snapshot.current.into_session(),
            rotated: snapshot
                .rotated
                .into_iter()
                .map(SessionSnapshot::into_session)
                .collect(),
        })
    }

    /// Returns every durable field needed for lossless reconstruction.
    #[must_use]
    pub fn snapshot_state(&self) -> SessionFamilySnapshot {
        SessionFamilySnapshot {
            id: self.id.clone(),
            subject: self.subject.clone(),
            issued_at: self.issued_at,
            absolute_expires_at: self.absolute_expires_at,
            version: self.version,
            state: self.state,
            current: snapshot_leaf(self, &self.current),
            rotated: self
                .rotated
                .iter()
                .map(|leaf| snapshot_leaf(self, leaf))
                .collect(),
        }
    }
}

impl SessionSnapshot {
    fn into_session(self) -> Session {
        Session {
            id: self.id,
            token_digest: self.token_digest,
            issued_at: self.issued_at,
            last_seen_at: self.last_seen_at,
            idle_expires_at: self.idle_expires_at,
            version: self.version,
            state: self.state,
            predecessor_id: self.predecessor_id,
        }
    }
}

fn snapshot_leaf(family: &SessionFamily, leaf: &Session) -> SessionSnapshot {
    SessionSnapshot {
        family_id: family.id.clone(),
        subject: family.subject.clone(),
        id: leaf.id.clone(),
        token_digest: leaf.token_digest,
        issued_at: leaf.issued_at,
        last_seen_at: leaf.last_seen_at,
        idle_expires_at: leaf.idle_expires_at,
        version: leaf.version,
        state: leaf.state,
        predecessor_id: leaf.predecessor_id.clone(),
    }
}

fn validate_snapshot(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    validate_capacity(snapshot)?;
    validate_family_window(snapshot)?;
    validate_family_version(snapshot)?;
    validate_bindings(snapshot)?;
    validate_lifecycle(snapshot)?;
    validate_history_order(snapshot)?;
    validate_leaf_windows(snapshot)?;
    validate_uniqueness(snapshot)
}

fn validate_capacity(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    if snapshot.rotated.len() > MAX_ROTATED_SESSIONS {
        return Err(error(SessionErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

fn validate_family_window(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    let span = snapshot
        .absolute_expires_at
        .unix_seconds()
        .checked_sub(snapshot.issued_at.unix_seconds())
        .ok_or_else(invalid_snapshot)?;
    if !(1..=MAX_ABSOLUTE_LIFETIME_SECONDS).contains(&span) {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn validate_family_version(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    let history = u64::try_from(snapshot.rotated.len()).map_err(|_| invalid_snapshot())?;
    let transition_count = match snapshot.state {
        SessionFamilyState::Active => 1,
        SessionFamilyState::Revoked | SessionFamilyState::Expired => 2,
    };
    let expected = history
        .checked_add(transition_count)
        .ok_or_else(invalid_snapshot)?;
    if snapshot.version.get() != expected {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn validate_bindings(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    validate_leaf_binding(snapshot, &snapshot.current)?;
    for leaf in &snapshot.rotated {
        validate_leaf_binding(snapshot, leaf)?;
    }
    Ok(())
}

fn validate_leaf_binding(
    snapshot: &SessionFamilySnapshot,
    leaf: &SessionSnapshot,
) -> Result<(), SessionError> {
    if leaf.family_id != snapshot.id {
        return Err(error(SessionErrorCode::FamilyMismatch));
    }
    if leaf.subject.tenant_id() != snapshot.subject.tenant_id() {
        return Err(error(SessionErrorCode::TenantMismatch));
    }
    if leaf.subject.user_id() != snapshot.subject.user_id() {
        return Err(error(SessionErrorCode::UserMismatch));
    }
    Ok(())
}

fn validate_lifecycle(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    let expected = lifecycle_expectation(snapshot.state);
    validate_leaf_lifecycle(
        &snapshot.current,
        expected.current_state,
        expected.current_version,
    )?;
    for leaf in &snapshot.rotated {
        validate_leaf_lifecycle(leaf, expected.rotated_state, expected.rotated_version)?;
    }
    Ok(())
}

struct LifecycleExpectation {
    current_state: SessionState,
    current_version: u64,
    rotated_state: SessionState,
    rotated_version: u64,
}

const fn lifecycle_expectation(state: SessionFamilyState) -> LifecycleExpectation {
    match state {
        SessionFamilyState::Active => LifecycleExpectation {
            current_state: SessionState::Active,
            current_version: 1,
            rotated_state: SessionState::Rotated,
            rotated_version: 2,
        },
        SessionFamilyState::Revoked => LifecycleExpectation {
            current_state: SessionState::Revoked,
            current_version: 2,
            rotated_state: SessionState::Revoked,
            rotated_version: 3,
        },
        SessionFamilyState::Expired => LifecycleExpectation {
            current_state: SessionState::Expired,
            current_version: 2,
            rotated_state: SessionState::Expired,
            rotated_version: 3,
        },
    }
}

fn validate_leaf_lifecycle(
    leaf: &SessionSnapshot,
    expected_state: SessionState,
    expected_version: u64,
) -> Result<(), SessionError> {
    if leaf.state != expected_state {
        return Err(invalid_snapshot());
    }
    if leaf.version.get() != expected_version {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn validate_history_order(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    let mut predecessor = None;
    let mut preceding_issued_at = snapshot.issued_at;
    for leaf in &snapshot.rotated {
        validate_history_leaf(leaf, predecessor, preceding_issued_at)?;
        predecessor = Some(&leaf.id);
        preceding_issued_at = leaf.issued_at;
    }
    validate_current_order(snapshot, predecessor, preceding_issued_at)
}

fn validate_history_leaf<'a>(
    leaf: &'a SessionSnapshot,
    expected_predecessor: Option<&'a SessionId>,
    preceding_issued_at: UtcTimestamp,
) -> Result<(), SessionError> {
    if leaf.predecessor_id.as_ref() != expected_predecessor {
        return Err(invalid_snapshot());
    }
    if leaf.issued_at < preceding_issued_at {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn validate_current_order(
    snapshot: &SessionFamilySnapshot,
    expected_predecessor: Option<&SessionId>,
    preceding_issued_at: UtcTimestamp,
) -> Result<(), SessionError> {
    if snapshot.current.predecessor_id.as_ref() != expected_predecessor {
        return Err(invalid_snapshot());
    }
    if snapshot.current.issued_at < preceding_issued_at {
        return Err(invalid_snapshot());
    }
    let first_issued_at = snapshot
        .rotated
        .first()
        .map_or(snapshot.current.issued_at, |leaf| leaf.issued_at);
    if first_issued_at != snapshot.issued_at {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn validate_leaf_windows(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    validate_leaf_window(snapshot, &snapshot.current)?;
    for leaf in &snapshot.rotated {
        validate_leaf_window(snapshot, leaf)?;
    }
    Ok(())
}

fn validate_leaf_window(
    snapshot: &SessionFamilySnapshot,
    leaf: &SessionSnapshot,
) -> Result<(), SessionError> {
    validate_leaf_time_order(leaf)?;
    validate_leaf_family_bounds(snapshot, leaf)?;
    let idle_span = leaf
        .idle_expires_at
        .unix_seconds()
        .checked_sub(leaf.last_seen_at.unix_seconds())
        .ok_or_else(invalid_snapshot)?;
    if idle_span > MAX_IDLE_LIFETIME_SECONDS {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn validate_leaf_time_order(leaf: &SessionSnapshot) -> Result<(), SessionError> {
    if leaf.last_seen_at < leaf.issued_at {
        return Err(invalid_snapshot());
    }
    if leaf.idle_expires_at <= leaf.last_seen_at {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn validate_leaf_family_bounds(
    snapshot: &SessionFamilySnapshot,
    leaf: &SessionSnapshot,
) -> Result<(), SessionError> {
    if leaf.issued_at < snapshot.issued_at {
        return Err(invalid_snapshot());
    }
    if leaf.issued_at >= snapshot.absolute_expires_at {
        return Err(invalid_snapshot());
    }
    if leaf.idle_expires_at > snapshot.absolute_expires_at {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn validate_uniqueness(snapshot: &SessionFamilySnapshot) -> Result<(), SessionError> {
    let capacity = snapshot
        .rotated
        .len()
        .checked_add(1)
        .ok_or_else(invalid_snapshot)?;
    let mut ids = HashSet::with_capacity(capacity);
    let mut digests = HashSet::with_capacity(capacity);
    validate_unique_leaf(&snapshot.current, &mut ids, &mut digests)?;
    for leaf in &snapshot.rotated {
        validate_unique_leaf(leaf, &mut ids, &mut digests)?;
    }
    Ok(())
}

fn validate_unique_leaf<'a>(
    leaf: &'a SessionSnapshot,
    ids: &mut HashSet<&'a SessionId>,
    digests: &mut HashSet<SessionTokenDigest>,
) -> Result<(), SessionError> {
    if !ids.insert(&leaf.id) {
        return Err(invalid_snapshot());
    }
    if !digests.insert(leaf.token_digest) {
        return Err(invalid_snapshot());
    }
    Ok(())
}

const fn invalid_snapshot() -> SessionError {
    error(SessionErrorCode::InvalidArgument)
}

//! Deterministic browser session-family issuance and lifecycle transitions.

use ariadnion_core::PrincipalId;
use ariadnion_user_domain::UtcTimestamp;
use subtle::Choice;

use crate::error::error;
use crate::{
    MAX_ABSOLUTE_LIFETIME_SECONDS, MAX_IDLE_LIFETIME_SECONDS, MAX_ROTATED_SESSIONS, Session,
    SessionError, SessionErrorCode, SessionFamily, SessionFamilyState, SessionFamilyVersion,
    SessionId, SessionIssueRequest, SessionState, SessionSubject, SessionTokenDigest,
    SessionValidityWindow,
};

/// Evidence required to rotate the active leaf of a session family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRotation {
    family_id: crate::SessionFamilyId,
    session_id: SessionId,
    subject: SessionSubject,
    presented_token: SessionTokenDigest,
    successor_session_id: SessionId,
    successor_token: SessionTokenDigest,
    idle_expires_at: UtcTimestamp,
}

impl SessionRotation {
    /// Creates immutable rotation evidence and successor leaf material.
    #[must_use]
    pub const fn new(
        family_id: crate::SessionFamilyId,
        session_id: SessionId,
        subject: SessionSubject,
        presented_token: SessionTokenDigest,
        successor_session_id: SessionId,
        successor_token: SessionTokenDigest,
        idle_expires_at: UtcTimestamp,
    ) -> Self {
        Self {
            family_id,
            session_id,
            subject,
            presented_token,
            successor_session_id,
            successor_token,
            idle_expires_at,
        }
    }
}

/// One requested browser session-family action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionAction {
    /// Rotate the active leaf when the presented token matches.
    Rotate(SessionRotation),
    /// Revoke every leaf after detecting reuse of a rotated token.
    DetectReuse {
        /// Presented family identity.
        family_id: crate::SessionFamilyId,
        /// Presented leaf identity.
        session_id: SessionId,
        /// Presented subject boundary.
        subject: SessionSubject,
        /// Presented token digest.
        presented_token: SessionTokenDigest,
    },
    /// Revoke the entire family.
    Revoke {
        /// Presented subject boundary.
        subject: SessionSubject,
    },
    /// Mark the family expired at or after its absolute boundary.
    Expire {
        /// Presented subject boundary.
        subject: SessionSubject,
    },
}

/// Version-bound session-family command with trusted actor and UTC time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCommand {
    expected_version: SessionFamilyVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    action: SessionAction,
}

impl SessionCommand {
    /// Creates a deterministic command without consulting a clock.
    #[must_use]
    pub const fn new(
        expected_version: SessionFamilyVersion,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
        action: SessionAction,
    ) -> Self {
        Self {
            expected_version,
            actor,
            occurred_at,
            action,
        }
    }
}

/// Stable audit-ready session-family event kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionEventKind {
    /// A browser session family was issued.
    Issued,
    /// The active leaf was rotated to a successor.
    Rotated,
    /// The family was revoked after token reuse detection.
    ReuseRevoked,
    /// An authorized actor revoked the family.
    Revoked,
    /// The exclusive absolute expiry transition completed.
    Expired,
}

/// Immutable audit-ready event produced with every accepted transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionEvent {
    family_id: crate::SessionFamilyId,
    session_id: SessionId,
    tenant_id: ariadnion_core::TenantId,
    user_id: ariadnion_user_domain::UserId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    version: SessionFamilyVersion,
    kind: SessionEventKind,
}

impl SessionEvent {
    /// Returns the family identity.
    #[must_use]
    pub const fn family_id(&self) -> &crate::SessionFamilyId {
        &self.family_id
    }

    /// Returns the leaf identity associated with the event.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &ariadnion_core::TenantId {
        &self.tenant_id
    }

    /// Returns the user identity.
    #[must_use]
    pub const fn user_id(&self) -> &ariadnion_user_domain::UserId {
        &self.user_id
    }

    /// Returns the trusted actor.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the trusted UTC event time.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the resulting family version.
    #[must_use]
    pub const fn version(&self) -> SessionFamilyVersion {
        self.version
    }

    /// Returns the event kind.
    #[must_use]
    pub const fn kind(&self) -> SessionEventKind {
        self.kind
    }
}

/// One accepted session-family aggregate coupled to its immutable event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTransition {
    family: SessionFamily,
    event: SessionEvent,
}

impl SessionTransition {
    /// Returns the resulting aggregate.
    #[must_use]
    pub const fn family(&self) -> &SessionFamily {
        &self.family
    }

    /// Returns the exactly corresponding audit event.
    #[must_use]
    pub const fn event(&self) -> &SessionEvent {
        &self.event
    }

    /// Consumes the result into aggregate and event.
    #[must_use]
    pub fn into_parts(self) -> (SessionFamily, SessionEvent) {
        (self.family, self.event)
    }
}

/// Issues one active browser session family with a single leaf.
///
/// # Errors
///
/// Returns stable redacted failures for invalid absolute or idle windows.
pub fn issue_session(request: SessionIssueRequest) -> Result<SessionTransition, SessionError> {
    validate_validity_window(request.validity())?;
    let actor = request.binding().actor().clone();
    let occurred_at = request.validity().issued_at();
    let family = SessionFamily::issued(request);
    let event = event_from(&family, actor, occurred_at, SessionEventKind::Issued);
    Ok(SessionTransition { family, event })
}

/// Applies one deterministic optimistic session-family transition.
///
/// Token comparison is constant time. Presenting any rotated token revokes the
/// family through reuse detection. This pure transition does not
/// itself prove durable single use. The persistence adapter must atomically
/// compare-and-swap the expected family version, replace leaf digests, and
/// append the event.
///
/// # Errors
///
/// Returns stable redacted failures for invalid evidence, optimistic-version
/// conflicts, pre-issuance commands, expiry boundaries, terminal states,
/// inactive leaves, token reuse, exhausted history capacity, or version
/// exhaustion.
pub fn transition_session_family(
    current: &SessionFamily,
    command: SessionCommand,
) -> Result<SessionTransition, SessionError> {
    validate_expected_version(current, command.expected_version)?;
    validate_command_time(current, command.occurred_at)?;

    let SessionCommand {
        expected_version: _,
        actor,
        occurred_at,
        action,
    } = command;

    match action {
        SessionAction::Rotate(rotation) => apply_rotation(current, actor, occurred_at, rotation),
        SessionAction::DetectReuse {
            family_id,
            session_id,
            subject,
            presented_token,
        } => apply_reuse_detection(
            current,
            actor,
            occurred_at,
            family_id,
            session_id,
            subject,
            presented_token,
        ),
        SessionAction::Revoke { subject } => apply_revoke(current, actor, occurred_at, subject),
        SessionAction::Expire { subject } => apply_expire(current, actor, occurred_at, subject),
    }
}

fn apply_rotation(
    current: &SessionFamily,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    rotation: SessionRotation,
) -> Result<SessionTransition, SessionError> {
    validate_rotation_preconditions(current, occurred_at, &rotation)?;
    match evaluate_presented_token(current, rotation.presented_token) {
        PresentedTokenOutcome::ActiveMatch => {
            validate_idle_window(current, occurred_at, rotation.idle_expires_at)?;
            validate_successor(current, &rotation)?;
            rotate_active_leaf(current, actor, occurred_at, rotation)
        }
        PresentedTokenOutcome::PreviousMatch => revoke_for_reuse(current, actor, occurred_at),
        PresentedTokenOutcome::Mismatch => Err(error(SessionErrorCode::TokenMismatch)),
    }
}

enum PresentedTokenOutcome {
    ActiveMatch,
    PreviousMatch,
    Mismatch,
}

fn evaluate_presented_token(
    current: &SessionFamily,
    presented: SessionTokenDigest,
) -> PresentedTokenOutcome {
    let current_matches = current.current().token_digest().ct_matches(presented);
    let rotated_matches = rotated_token_match_choice(current, presented);
    if bool::from(current_matches) {
        return PresentedTokenOutcome::ActiveMatch;
    }
    if bool::from(rotated_matches) {
        return PresentedTokenOutcome::PreviousMatch;
    }
    PresentedTokenOutcome::Mismatch
}

fn validate_rotation_preconditions(
    current: &SessionFamily,
    occurred_at: UtcTimestamp,
    rotation: &SessionRotation,
) -> Result<(), SessionError> {
    validate_active_family(current)?;
    validate_subject(current, &rotation.subject)?;
    validate_family_id(current, &rotation.family_id)?;
    validate_current_leaf(current, &rotation.session_id)?;
    validate_not_expired(current, occurred_at)
}

fn rotate_active_leaf(
    current: &SessionFamily,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    rotation: SessionRotation,
) -> Result<SessionTransition, SessionError> {
    let version = current.version().next()?;
    let predecessor = current.current().with_state(SessionState::Rotated);
    let successor = Session::active_leaf(
        rotation.successor_session_id,
        rotation.successor_token,
        occurred_at,
        rotation.idle_expires_at,
        Some(predecessor.id().clone()),
    );
    let mut rotated = current.rotated().to_vec();
    rotated.push(predecessor);
    let family = current.advance(version, SessionFamilyState::Active, successor, rotated);
    let event = event_from(&family, actor, occurred_at, SessionEventKind::Rotated);
    Ok(SessionTransition { family, event })
}

fn apply_reuse_detection(
    current: &SessionFamily,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    family_id: crate::SessionFamilyId,
    session_id: SessionId,
    subject: SessionSubject,
    presented_token: SessionTokenDigest,
) -> Result<SessionTransition, SessionError> {
    validate_subject(current, &subject)?;
    validate_family_id(current, &family_id)?;
    if current.state() != SessionFamilyState::Active {
        return Err(error(SessionErrorCode::FamilyTerminal));
    }
    if !rotated_session_matches(current, &session_id, presented_token) {
        return Err(error(SessionErrorCode::TokenMismatch));
    }
    revoke_for_reuse(current, actor, occurred_at)
}

fn apply_revoke(
    current: &SessionFamily,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    subject: SessionSubject,
) -> Result<SessionTransition, SessionError> {
    validate_subject(current, &subject)?;
    validate_active_family(current)?;
    let version = current.version().next()?;
    let current_leaf = current.current().with_state(SessionState::Revoked);
    let rotated = rotated_with_state(current, SessionState::Revoked);
    let family = current.advance(version, SessionFamilyState::Revoked, current_leaf, rotated);
    let event = event_from(&family, actor, occurred_at, SessionEventKind::Revoked);
    Ok(SessionTransition { family, event })
}

fn apply_expire(
    current: &SessionFamily,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    subject: SessionSubject,
) -> Result<SessionTransition, SessionError> {
    validate_subject(current, &subject)?;
    validate_active_family(current)?;
    if occurred_at.unix_seconds() < current.absolute_expires_at().unix_seconds()
        && occurred_at.unix_seconds() < current.current().idle_expires_at().unix_seconds()
    {
        return Err(error(SessionErrorCode::NotYetExpired));
    }
    let version = current.version().next()?;
    let current_leaf = current.current().with_state(SessionState::Expired);
    let rotated = rotated_with_state(current, SessionState::Expired);
    let family = current.advance(version, SessionFamilyState::Expired, current_leaf, rotated);
    let event = event_from(&family, actor, occurred_at, SessionEventKind::Expired);
    Ok(SessionTransition { family, event })
}

fn revoke_for_reuse(
    current: &SessionFamily,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
) -> Result<SessionTransition, SessionError> {
    let version = current.version().next()?;
    let current_leaf = current.current().with_state(SessionState::Revoked);
    let rotated = rotated_with_state(current, SessionState::Revoked);
    let family = current.advance(version, SessionFamilyState::Revoked, current_leaf, rotated);
    let event = event_from(&family, actor, occurred_at, SessionEventKind::ReuseRevoked);
    Ok(SessionTransition { family, event })
}

fn event_from(
    family: &SessionFamily,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    kind: SessionEventKind,
) -> SessionEvent {
    SessionEvent {
        family_id: family.id().clone(),
        session_id: family.current().id().clone(),
        tenant_id: family.tenant_id().clone(),
        user_id: family.user_id().clone(),
        actor,
        occurred_at,
        version: family.version(),
        kind,
    }
}

fn validate_validity_window(window: SessionValidityWindow) -> Result<(), SessionError> {
    let issued = window.issued_at().unix_seconds();
    let absolute = window.absolute_expires_at().unix_seconds();
    let idle = window.idle_expires_at().unix_seconds();
    validate_positive_window_order(issued, absolute, idle)?;
    validate_window_spans(issued, absolute, idle)?;
    if idle > absolute {
        return Err(error(SessionErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_positive_window_order(
    issued: i64,
    absolute: i64,
    idle: i64,
) -> Result<(), SessionError> {
    if absolute <= issued || idle <= issued {
        return Err(error(SessionErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_window_spans(issued: i64, absolute: i64, idle: i64) -> Result<(), SessionError> {
    let absolute_span = absolute
        .checked_sub(issued)
        .ok_or_else(|| error(SessionErrorCode::InvalidArgument))?;
    let idle_span = idle
        .checked_sub(issued)
        .ok_or_else(|| error(SessionErrorCode::InvalidArgument))?;
    if absolute_span > MAX_ABSOLUTE_LIFETIME_SECONDS || idle_span > MAX_IDLE_LIFETIME_SECONDS {
        return Err(error(SessionErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_expected_version(
    current: &SessionFamily,
    expected: SessionFamilyVersion,
) -> Result<(), SessionError> {
    if current.version() != expected {
        return Err(error(SessionErrorCode::VersionConflict));
    }
    Ok(())
}

fn validate_command_time(
    current: &SessionFamily,
    occurred_at: UtcTimestamp,
) -> Result<(), SessionError> {
    if occurred_at.unix_seconds() < current.issued_at().unix_seconds() {
        return Err(error(SessionErrorCode::NotYetValid));
    }
    Ok(())
}

fn validate_active_family(current: &SessionFamily) -> Result<(), SessionError> {
    if current.state() != SessionFamilyState::Active {
        return Err(error(SessionErrorCode::FamilyTerminal));
    }
    if current.current().state() != SessionState::Active {
        return Err(error(SessionErrorCode::InactiveLeaf));
    }
    Ok(())
}

fn validate_subject(current: &SessionFamily, subject: &SessionSubject) -> Result<(), SessionError> {
    if current.tenant_id() != subject.tenant_id() {
        return Err(error(SessionErrorCode::TenantMismatch));
    }
    if current.user_id() != subject.user_id() {
        return Err(error(SessionErrorCode::UserMismatch));
    }
    Ok(())
}

fn validate_family_id(
    current: &SessionFamily,
    family_id: &crate::SessionFamilyId,
) -> Result<(), SessionError> {
    if current.id() != family_id {
        return Err(error(SessionErrorCode::FamilyMismatch));
    }
    Ok(())
}

fn validate_current_leaf(
    current: &SessionFamily,
    session_id: &SessionId,
) -> Result<(), SessionError> {
    if current.current().id() != session_id {
        return Err(error(SessionErrorCode::SessionMismatch));
    }
    Ok(())
}

fn validate_not_expired(
    current: &SessionFamily,
    occurred_at: UtcTimestamp,
) -> Result<(), SessionError> {
    if occurred_at.unix_seconds() >= current.absolute_expires_at().unix_seconds()
        || occurred_at.unix_seconds() >= current.current().idle_expires_at().unix_seconds()
    {
        return Err(error(SessionErrorCode::Expired));
    }
    Ok(())
}

fn validate_idle_window(
    current: &SessionFamily,
    occurred_at: UtcTimestamp,
    idle_expires_at: UtcTimestamp,
) -> Result<(), SessionError> {
    if idle_expires_at.unix_seconds() <= occurred_at.unix_seconds() {
        return Err(error(SessionErrorCode::InvalidArgument));
    }
    let idle_span = idle_expires_at
        .unix_seconds()
        .checked_sub(occurred_at.unix_seconds())
        .ok_or_else(|| error(SessionErrorCode::InvalidArgument))?;
    if idle_span > MAX_IDLE_LIFETIME_SECONDS {
        return Err(error(SessionErrorCode::InvalidArgument));
    }
    if idle_expires_at.unix_seconds() > current.absolute_expires_at().unix_seconds() {
        return Err(error(SessionErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_successor(
    current: &SessionFamily,
    rotation: &SessionRotation,
) -> Result<(), SessionError> {
    if current.rotated().len() >= MAX_ROTATED_SESSIONS {
        return Err(error(SessionErrorCode::ResourceLimitExceeded));
    }
    let id_was_used = session_id_was_used(current, &rotation.successor_session_id);
    let token_was_used = token_was_used(current, rotation.successor_token);
    if id_was_used | token_was_used {
        return Err(error(SessionErrorCode::InvalidArgument));
    }
    Ok(())
}

fn session_id_was_used(current: &SessionFamily, candidate: &SessionId) -> bool {
    let mut found = current.current().id() == candidate;
    for leaf in current.rotated() {
        found |= leaf.id() == candidate;
    }
    found
}

fn token_was_used(current: &SessionFamily, candidate: SessionTokenDigest) -> bool {
    let mut found = current.current().token_digest().ct_matches(candidate);
    for leaf in current.rotated() {
        found |= leaf.token_digest().ct_matches(candidate);
    }
    bool::from(found)
}

fn rotated_token_match_choice(current: &SessionFamily, presented: SessionTokenDigest) -> Choice {
    let mut found = Choice::from(0);
    for leaf in current.rotated() {
        found |= leaf.token_digest().ct_matches(presented);
    }
    found
}

fn rotated_session_matches(
    current: &SessionFamily,
    session_id: &SessionId,
    presented: SessionTokenDigest,
) -> bool {
    let mut found = Choice::from(0);
    for leaf in current.rotated() {
        let id_matches = Choice::from(u8::from(leaf.id() == session_id));
        found |= id_matches & leaf.token_digest().ct_matches(presented);
    }
    bool::from(found)
}

fn rotated_with_state(current: &SessionFamily, state: SessionState) -> Vec<Session> {
    current
        .rotated()
        .iter()
        .map(|leaf| leaf.with_state(state))
        .collect()
}

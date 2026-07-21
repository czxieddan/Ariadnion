//! Deterministic scoped API-key issuance and lifecycle transitions.

use ariadnion_core::PrincipalId;
use ariadnion_user_domain::UtcTimestamp;

use crate::error::error;
use crate::{
    ApiKey, ApiKeyError, ApiKeyErrorCode, ApiKeyId, ApiKeyIssueRequest, ApiKeyOwner, ApiKeyPrefix,
    ApiKeyScope, ApiKeySecretDigest, ApiKeyState, ApiKeyValidityWindow, ApiKeyVersion,
    MAX_API_KEY_LIFETIME_SECONDS, MAX_OVERLAP_SECONDS,
};

/// Evidence required to rotate an API-key secret with a short overlap window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyRotation {
    key_id: ApiKeyId,
    owner: ApiKeyOwner,
    new_secret: ApiKeySecretDigest,
    previous_secret_expires_at: UtcTimestamp,
}

impl ApiKeyRotation {
    /// Creates immutable rotation evidence.
    #[must_use]
    pub const fn new(
        key_id: ApiKeyId,
        owner: ApiKeyOwner,
        new_secret: ApiKeySecretDigest,
        previous_secret_expires_at: UtcTimestamp,
    ) -> Self {
        Self {
            key_id,
            owner,
            new_secret,
            previous_secret_expires_at,
        }
    }
}

/// Presentation evidence used to verify an API key without retaining plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyPresentation {
    key_id: ApiKeyId,
    owner: ApiKeyOwner,
    prefix: ApiKeyPrefix,
    secret_digest: ApiKeySecretDigest,
    required_scope: ApiKeyScope,
    presented_at: UtcTimestamp,
}

impl ApiKeyPresentation {
    /// Creates immutable presentation evidence from adapter-derived digests.
    #[must_use]
    pub const fn new(
        key_id: ApiKeyId,
        owner: ApiKeyOwner,
        prefix: ApiKeyPrefix,
        secret_digest: ApiKeySecretDigest,
        required_scope: ApiKeyScope,
        presented_at: UtcTimestamp,
    ) -> Self {
        Self {
            key_id,
            owner,
            prefix,
            secret_digest,
            required_scope,
            presented_at,
        }
    }
}

/// Successful verification result without secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyVerification {
    key_id: ApiKeyId,
    tenant_id: ariadnion_core::TenantId,
    user_id: ariadnion_user_domain::UserId,
    matched_scope: ApiKeyScope,
}

impl ApiKeyVerification {
    /// Returns the verified key identity.
    #[must_use]
    pub const fn key_id(&self) -> &ApiKeyId {
        &self.key_id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &ariadnion_core::TenantId {
        &self.tenant_id
    }

    /// Returns the owner identity.
    #[must_use]
    pub const fn user_id(&self) -> &ariadnion_user_domain::UserId {
        &self.user_id
    }

    /// Returns the matched required scope.
    #[must_use]
    pub const fn matched_scope(&self) -> &ApiKeyScope {
        &self.matched_scope
    }
}

/// One requested API-key lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiKeyAction {
    /// Rotate the secret and keep a short previous-secret overlap.
    Rotate(ApiKeyRotation),
    /// End the previous-secret overlap after its exclusive boundary.
    CompleteRotation,
    /// Revoke the key immediately.
    Revoke {
        /// Presented owner boundary.
        owner: ApiKeyOwner,
    },
    /// Mark the key expired at or after its absolute boundary.
    Expire {
        /// Presented owner boundary.
        owner: ApiKeyOwner,
    },
}

/// Version-bound API-key command with trusted actor and UTC time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyCommand {
    expected_version: ApiKeyVersion,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    action: ApiKeyAction,
}

impl ApiKeyCommand {
    /// Creates a deterministic command without consulting a clock.
    #[must_use]
    pub const fn new(
        expected_version: ApiKeyVersion,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
        action: ApiKeyAction,
    ) -> Self {
        Self {
            expected_version,
            actor,
            occurred_at,
            action,
        }
    }
}

/// Stable audit-ready API-key event kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApiKeyEventKind {
    /// An API key was issued.
    Issued,
    /// An API key entered a rotation overlap window.
    Rotated,
    /// The previous secret overlap ended.
    RotationCompleted,
    /// An authorized actor revoked the key.
    Revoked,
    /// The exclusive expiry transition completed.
    Expired,
}

/// Immutable audit-ready event produced with every accepted transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyEvent {
    key_id: ApiKeyId,
    tenant_id: ariadnion_core::TenantId,
    user_id: ariadnion_user_domain::UserId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    version: ApiKeyVersion,
    kind: ApiKeyEventKind,
}

impl ApiKeyEvent {
    /// Returns the key identity.
    #[must_use]
    pub const fn key_id(&self) -> &ApiKeyId {
        &self.key_id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &ariadnion_core::TenantId {
        &self.tenant_id
    }

    /// Returns the owner identity.
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

    /// Returns the resulting version.
    #[must_use]
    pub const fn version(&self) -> ApiKeyVersion {
        self.version
    }

    /// Returns the event kind.
    #[must_use]
    pub const fn kind(&self) -> ApiKeyEventKind {
        self.kind
    }
}

/// One accepted API-key aggregate coupled to its immutable event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyTransition {
    key: ApiKey,
    event: ApiKeyEvent,
}

impl ApiKeyTransition {
    /// Returns the resulting aggregate.
    #[must_use]
    pub const fn key(&self) -> &ApiKey {
        &self.key
    }

    /// Returns the corresponding audit event.
    #[must_use]
    pub const fn event(&self) -> &ApiKeyEvent {
        &self.event
    }
}

/// Issues one active scoped API key that retains only digests.
///
/// # Errors
///
/// Returns stable redacted failures for invalid lifetime windows or scopes.
pub fn issue_api_key(request: ApiKeyIssueRequest) -> Result<ApiKeyTransition, ApiKeyError> {
    validate_validity_window(request.validity())?;
    let actor = request.actor().clone();
    let occurred_at = request.validity().issued_at();
    let key = ApiKey::issued(request);
    let event = event_from(&key, actor, occurred_at, ApiKeyEventKind::Issued);
    Ok(ApiKeyTransition { key, event })
}

/// Verifies presentation evidence against an API-key aggregate.
///
/// Secret comparison is constant time. Failures do not retain secrets.
///
/// # Errors
///
/// Returns stable redacted failures for mismatched evidence, terminal keys,
/// expiry, or missing scopes.
pub fn verify_api_key_presentation(
    current: &ApiKey,
    presentation: ApiKeyPresentation,
) -> Result<ApiKeyVerification, ApiKeyError> {
    validate_owner(current, &presentation.owner)?;
    if current.id() != &presentation.key_id {
        return Err(error(ApiKeyErrorCode::KeyMismatch));
    }
    if current.prefix() != &presentation.prefix {
        return Err(error(ApiKeyErrorCode::PrefixMismatch));
    }
    validate_usable_state(current)?;
    validate_not_expired(current, presentation.presented_at)?;
    if !secret_is_acceptable(
        current,
        presentation.secret_digest,
        presentation.presented_at,
    ) {
        return Err(error(ApiKeyErrorCode::SecretMismatch));
    }
    if !current
        .scopes()
        .iter()
        .any(|scope| scope == &presentation.required_scope)
    {
        return Err(error(ApiKeyErrorCode::ScopeDenied));
    }
    Ok(ApiKeyVerification {
        key_id: current.id().clone(),
        tenant_id: current.tenant_id().clone(),
        user_id: current.user_id().clone(),
        matched_scope: presentation.required_scope,
    })
}

/// Applies one deterministic optimistic API-key transition.
///
/// # Errors
///
/// Returns stable redacted failures for invalid evidence, version conflicts,
/// terminal states, or expiry boundaries.
pub fn transition_api_key(
    current: &ApiKey,
    command: ApiKeyCommand,
) -> Result<ApiKeyTransition, ApiKeyError> {
    validate_expected_version(current, command.expected_version)?;
    validate_command_time(current, command.occurred_at)?;

    let ApiKeyCommand {
        expected_version: _,
        actor,
        occurred_at,
        action,
    } = command;

    match action {
        ApiKeyAction::Rotate(rotation) => apply_rotation(current, actor, occurred_at, rotation),
        ApiKeyAction::CompleteRotation => apply_complete_rotation(current, actor, occurred_at),
        ApiKeyAction::Revoke { owner } => apply_revoke(current, actor, occurred_at, owner),
        ApiKeyAction::Expire { owner } => apply_expire(current, actor, occurred_at, owner),
    }
}

fn apply_rotation(
    current: &ApiKey,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    rotation: ApiKeyRotation,
) -> Result<ApiKeyTransition, ApiKeyError> {
    validate_usable_state(current)?;
    validate_owner(current, &rotation.owner)?;
    if current.id() != &rotation.key_id {
        return Err(error(ApiKeyErrorCode::KeyMismatch));
    }
    validate_not_expired(current, occurred_at)?;
    validate_overlap_window(current, occurred_at, rotation.previous_secret_expires_at)?;
    if current.current_secret().matches(rotation.new_secret) {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    let version = current.version().next()?;
    let key = current.advance(
        version,
        ApiKeyState::Rotating,
        rotation.new_secret,
        Some(current.current_secret()),
        Some(rotation.previous_secret_expires_at),
    );
    let event = event_from(&key, actor, occurred_at, ApiKeyEventKind::Rotated);
    Ok(ApiKeyTransition { key, event })
}

fn apply_complete_rotation(
    current: &ApiKey,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
) -> Result<ApiKeyTransition, ApiKeyError> {
    if current.state() != ApiKeyState::Rotating {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    let previous_expires = current
        .previous_secret_expires_at()
        .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))?;
    if occurred_at.unix_seconds() < previous_expires.unix_seconds() {
        return Err(error(ApiKeyErrorCode::NotYetExpired));
    }
    let version = current.version().next()?;
    let key = current.advance(
        version,
        ApiKeyState::Active,
        current.current_secret(),
        None,
        None,
    );
    let event = event_from(&key, actor, occurred_at, ApiKeyEventKind::RotationCompleted);
    Ok(ApiKeyTransition { key, event })
}

fn apply_revoke(
    current: &ApiKey,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    owner: ApiKeyOwner,
) -> Result<ApiKeyTransition, ApiKeyError> {
    validate_owner(current, &owner)?;
    validate_usable_state(current)?;
    let version = current.version().next()?;
    let key = current.advance(
        version,
        ApiKeyState::Revoked,
        current.current_secret(),
        None,
        None,
    );
    let event = event_from(&key, actor, occurred_at, ApiKeyEventKind::Revoked);
    Ok(ApiKeyTransition { key, event })
}

fn apply_expire(
    current: &ApiKey,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    owner: ApiKeyOwner,
) -> Result<ApiKeyTransition, ApiKeyError> {
    validate_owner(current, &owner)?;
    validate_usable_state(current)?;
    let expires_at = current
        .expires_at()
        .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))?;
    if occurred_at.unix_seconds() < expires_at.unix_seconds() {
        return Err(error(ApiKeyErrorCode::NotYetExpired));
    }
    let version = current.version().next()?;
    let key = current.advance(
        version,
        ApiKeyState::Expired,
        current.current_secret(),
        None,
        None,
    );
    let event = event_from(&key, actor, occurred_at, ApiKeyEventKind::Expired);
    Ok(ApiKeyTransition { key, event })
}

fn event_from(
    key: &ApiKey,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    kind: ApiKeyEventKind,
) -> ApiKeyEvent {
    ApiKeyEvent {
        key_id: key.id().clone(),
        tenant_id: key.tenant_id().clone(),
        user_id: key.user_id().clone(),
        actor,
        occurred_at,
        version: key.version(),
        kind,
    }
}

fn validate_validity_window(window: ApiKeyValidityWindow) -> Result<(), ApiKeyError> {
    let Some(expires_at) = window.expires_at() else {
        return Ok(());
    };
    let issued = window.issued_at().unix_seconds();
    let expires = expires_at.unix_seconds();
    if expires <= issued {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    let span = expires
        .checked_sub(issued)
        .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))?;
    if span > MAX_API_KEY_LIFETIME_SECONDS {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_expected_version(current: &ApiKey, expected: ApiKeyVersion) -> Result<(), ApiKeyError> {
    if current.version() != expected {
        return Err(error(ApiKeyErrorCode::VersionConflict));
    }
    Ok(())
}

fn validate_command_time(current: &ApiKey, occurred_at: UtcTimestamp) -> Result<(), ApiKeyError> {
    if occurred_at.unix_seconds() < current.issued_at().unix_seconds() {
        return Err(error(ApiKeyErrorCode::NotYetValid));
    }
    Ok(())
}

fn validate_owner(current: &ApiKey, owner: &ApiKeyOwner) -> Result<(), ApiKeyError> {
    if current.tenant_id() != owner.tenant_id() {
        return Err(error(ApiKeyErrorCode::TenantMismatch));
    }
    if current.user_id() != owner.user_id() {
        return Err(error(ApiKeyErrorCode::OwnerMismatch));
    }
    Ok(())
}

fn validate_usable_state(current: &ApiKey) -> Result<(), ApiKeyError> {
    match current.state() {
        ApiKeyState::Active | ApiKeyState::Rotating => Ok(()),
        ApiKeyState::Revoked | ApiKeyState::Expired => Err(error(ApiKeyErrorCode::Terminal)),
    }
}

fn validate_not_expired(current: &ApiKey, occurred_at: UtcTimestamp) -> Result<(), ApiKeyError> {
    if let Some(expires_at) = current.expires_at()
        && occurred_at.unix_seconds() >= expires_at.unix_seconds()
    {
        return Err(error(ApiKeyErrorCode::Expired));
    }
    Ok(())
}

fn validate_overlap_window(
    current: &ApiKey,
    occurred_at: UtcTimestamp,
    previous_secret_expires_at: UtcTimestamp,
) -> Result<(), ApiKeyError> {
    if previous_secret_expires_at.unix_seconds() <= occurred_at.unix_seconds() {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    let span = previous_secret_expires_at
        .unix_seconds()
        .checked_sub(occurred_at.unix_seconds())
        .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))?;
    if span > MAX_OVERLAP_SECONDS {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    if let Some(absolute) = current.expires_at()
        && previous_secret_expires_at.unix_seconds() > absolute.unix_seconds()
    {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn secret_is_acceptable(
    current: &ApiKey,
    presented: ApiKeySecretDigest,
    presented_at: UtcTimestamp,
) -> bool {
    if current.current_secret().matches(presented) {
        return true;
    }
    previous_secret_is_acceptable(current, presented, presented_at)
}

fn previous_secret_is_acceptable(
    current: &ApiKey,
    presented: ApiKeySecretDigest,
    presented_at: UtcTimestamp,
) -> bool {
    let Some(previous) = current.previous_secret() else {
        return false;
    };
    let Some(previous_expires) = current.previous_secret_expires_at() else {
        return false;
    };
    if presented_at.unix_seconds() >= previous_expires.unix_seconds() {
        return false;
    }
    previous.matches(presented)
}

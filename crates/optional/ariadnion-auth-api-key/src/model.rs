//! Immutable scoped API-key model values.

use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

use crate::error::error;
use crate::{ApiKeyError, ApiKeyErrorCode, ApiKeyId, ApiKeyVersion};

/// Maximum supported API-key lifetime in seconds.
pub const MAX_API_KEY_LIFETIME_SECONDS: i64 = 365 * 24 * 60 * 60;
/// Maximum secret overlap window after rotation in seconds.
pub const MAX_OVERLAP_SECONDS: i64 = 24 * 60 * 60;
/// Minimum accepted secret length in bytes.
pub const MIN_SECRET_BYTES: usize = 32;
/// Maximum accepted secret length in bytes.
pub const MAX_SECRET_BYTES: usize = 256;
/// Minimum accepted recognizable prefix length in bytes.
pub const MIN_PREFIX_BYTES: usize = 4;
/// Maximum accepted recognizable prefix length in bytes.
pub const MAX_PREFIX_BYTES: usize = 32;
/// Maximum scopes retained on one key.
pub const MAX_API_KEY_SCOPES: usize = 32;
/// Maximum length of one scope identifier in bytes.
pub const MAX_SCOPE_BYTES: usize = 64;
/// Maximum retired secret digests retained for reuse detection.
pub const MAX_RETIRED_SECRETS: usize = 4_096;

const API_KEY_SECRET_DOMAIN: &[u8] = b"ariadnion.api-key.secret.v1\0";

/// Tenant and owner identities that bind one API key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyOwner {
    tenant_id: TenantId,
    user_id: UserId,
}

impl ApiKeyOwner {
    /// Creates a tenant-bound owner identity.
    #[must_use]
    pub const fn new(tenant_id: TenantId, user_id: UserId) -> Self {
        Self { tenant_id, user_id }
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the owner user identity.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

/// A recognizable non-secret prefix used for indexed lookup only.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApiKeyPrefix(Box<str>);

impl ApiKeyPrefix {
    /// Parses a non-secret ASCII prefix used only for lookup.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyErrorCode::InvalidArgument`] without retaining rejected input.
    pub fn parse(value: &str) -> Result<Self, ApiKeyError> {
        if !(MIN_PREFIX_BYTES..=MAX_PREFIX_BYTES).contains(&value.len())
            || !value.is_ascii()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(error(ApiKeyErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ApiKeyPrefix {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyPrefix(<lookup>)")
    }
}

/// A single bounded scope identifier granted to an API key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApiKeyScope(Box<str>);

impl ApiKeyScope {
    /// Parses a non-empty ASCII scope of at most 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyErrorCode::InvalidArgument`] without retaining rejected input.
    pub fn parse(value: &str) -> Result<Self, ApiKeyError> {
        if value.is_empty()
            || value.len() > MAX_SCOPE_BYTES
            || !value.is_ascii()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
            })
        {
            return Err(error(ApiKeyErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated scope.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ApiKeyScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ApiKeyScope")
            .field(&self.as_str())
            .finish()
    }
}

/// A domain-separated SHA-256 digest of an API-key secret.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ApiKeySecretDigest([u8; 32]);

impl ApiKeySecretDigest {
    /// Derives a digest from a high-entropy secret without retaining plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyErrorCode::InvalidArgument`] when the secret is outside bounds.
    pub fn from_secret(secret: &[u8]) -> Result<Self, ApiKeyError> {
        if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&secret.len()) {
            return Err(error(ApiKeyErrorCode::InvalidArgument));
        }
        Ok(Self(domain_separated_digest(API_KEY_SECRET_DOMAIN, secret)))
    }

    /// Creates a digest from exact SHA-256 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn ct_matches(self, presented: Self) -> Choice {
        self.0.ct_eq(&presented.0)
    }
}

impl Debug for ApiKeySecretDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeySecretDigest(<sha256>)")
    }
}

/// Stable lifecycle state of one API key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApiKeyState {
    /// The key may authenticate until expiry or revocation.
    Active,
    /// The key is rotating and may accept previous and current secrets.
    Rotating,
    /// An authorized actor revoked the key.
    Revoked,
    /// The exclusive expiry transition completed.
    Expired,
}

/// Trusted issuance and exclusive expiry boundaries for one API key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyValidityWindow {
    issued_at: UtcTimestamp,
    expires_at: Option<UtcTimestamp>,
}

impl ApiKeyValidityWindow {
    /// Couples trusted issuance and optional exclusive expiry.
    #[must_use]
    pub const fn new(issued_at: UtcTimestamp, expires_at: Option<UtcTimestamp>) -> Self {
        Self {
            issued_at,
            expires_at,
        }
    }

    /// Returns the trusted issuance time.
    #[must_use]
    pub const fn issued_at(self) -> UtcTimestamp {
        self.issued_at
    }

    /// Returns the exclusive expiry boundary when one exists.
    #[must_use]
    pub const fn expires_at(self) -> Option<UtcTimestamp> {
        self.expires_at
    }
}

/// Tenant-bound identity and lookup metadata for one API-key issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyIssueBinding {
    id: ApiKeyId,
    owner: ApiKeyOwner,
    actor: PrincipalId,
    prefix: ApiKeyPrefix,
}

impl ApiKeyIssueBinding {
    /// Creates trusted identity and lookup metadata for API-key issuance.
    #[must_use]
    pub const fn new(
        id: ApiKeyId,
        owner: ApiKeyOwner,
        actor: PrincipalId,
        prefix: ApiKeyPrefix,
    ) -> Self {
        Self {
            id,
            owner,
            actor,
            prefix,
        }
    }

    /// Returns the API-key identity.
    #[must_use]
    pub const fn id(&self) -> &ApiKeyId {
        &self.id
    }

    /// Returns the tenant-bound owner.
    #[must_use]
    pub const fn owner(&self) -> &ApiKeyOwner {
        &self.owner
    }

    /// Returns the trusted issuance actor.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the non-secret lookup prefix.
    #[must_use]
    pub const fn prefix(&self) -> &ApiKeyPrefix {
        &self.prefix
    }
}

/// Immutable inputs required to issue one scoped API key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyIssueRequest {
    binding: ApiKeyIssueBinding,
    secret_digest: ApiKeySecretDigest,
    scopes: Box<[ApiKeyScope]>,
    validity: ApiKeyValidityWindow,
}

impl ApiKeyIssueRequest {
    /// Creates an issue request retaining only digests and bounded scopes.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyErrorCode::InvalidArgument`] when the scope set is empty
    /// or exceeds the documented bound.
    pub fn new(
        binding: ApiKeyIssueBinding,
        secret_digest: ApiKeySecretDigest,
        scopes: Vec<ApiKeyScope>,
        validity: ApiKeyValidityWindow,
    ) -> Result<Self, ApiKeyError> {
        let scopes = normalize_scopes(scopes)?;
        Ok(Self {
            binding,
            secret_digest,
            scopes,
            validity,
        })
    }

    /// Returns the trusted issuance binding.
    #[must_use]
    pub const fn binding(&self) -> &ApiKeyIssueBinding {
        &self.binding
    }

    /// Returns the trusted actor for issuance.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        self.binding.actor()
    }

    /// Returns the validity window.
    #[must_use]
    pub const fn validity(&self) -> ApiKeyValidityWindow {
        self.validity
    }
}

/// An immutable tenant-bound API-key aggregate containing only digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKey {
    id: ApiKeyId,
    owner: ApiKeyOwner,
    prefix: ApiKeyPrefix,
    current_secret: ApiKeySecretDigest,
    previous_secret: Option<ApiKeySecretDigest>,
    rotation_started_at: Option<UtcTimestamp>,
    previous_secret_expires_at: Option<UtcTimestamp>,
    retired_secrets: Vec<ApiKeySecretDigest>,
    scopes: Box<[ApiKeyScope]>,
    issued_at: UtcTimestamp,
    expires_at: Option<UtcTimestamp>,
    version: ApiKeyVersion,
    state: ApiKeyState,
}

/// Complete typed state required to reconstruct one API key from persistence.
///
/// Fields are public so a storage adapter can decode one candidate without a
/// permissive constructor. [`ApiKey::from_snapshot`] remains the validation
/// boundary and rejects combinations that public transitions cannot produce.
#[derive(Clone, Eq, PartialEq)]
pub struct ApiKeySnapshot {
    /// Stable API-key aggregate identity.
    pub id: ApiKeyId,
    /// Tenant and user identities that own the key.
    pub owner: ApiKeyOwner,
    /// Recognizable non-secret lookup prefix.
    pub prefix: ApiKeyPrefix,
    /// Current domain-separated secret digest.
    pub current_secret: ApiKeySecretDigest,
    /// Previous digest accepted only during rotation overlap.
    pub previous_secret: Option<ApiKeySecretDigest>,
    /// Trusted instant at which the current rotation overlap began.
    pub rotation_started_at: Option<UtcTimestamp>,
    /// Exclusive boundary for accepting the previous digest.
    pub previous_secret_expires_at: Option<UtcTimestamp>,
    /// Retired digests retained in retirement order for reuse detection.
    pub retired_secrets: Vec<ApiKeySecretDigest>,
    /// Granted scopes, normalized during reconstruction.
    pub scopes: Vec<ApiKeyScope>,
    /// Trusted issuance timestamp.
    pub issued_at: UtcTimestamp,
    /// Optional exclusive absolute expiry boundary.
    pub expires_at: Option<UtcTimestamp>,
    /// Non-zero optimistic aggregate version.
    pub version: ApiKeyVersion,
    /// Persisted lifecycle state.
    pub state: ApiKeyState,
}

/// Compatibility alias for callers that name aggregate state snapshots.
pub type ApiKeySnapshotState = ApiKeySnapshot;

impl Debug for ApiKeySnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeySnapshot")
            .field("id", &self.id)
            .field("owner", &self.owner)
            .field("prefix", &self.prefix)
            .field("current_secret", &"<redacted>")
            .field("has_previous_secret", &self.previous_secret.is_some())
            .field("rotation_started_at", &self.rotation_started_at)
            .field(
                "previous_secret_expires_at",
                &self.previous_secret_expires_at,
            )
            .field("retired_secret_count", &self.retired_secrets.len())
            .field("scopes", &self.scopes)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("version", &self.version)
            .field("state", &self.state)
            .finish()
    }
}

impl ApiKey {
    /// Reconstructs an API key from one complete typed persistence snapshot.
    ///
    /// The reconstruction boundary validates identity and version floors,
    /// normalizes bounded scopes, verifies validity and overlap ordering, and
    /// rejects incomplete lifecycle state or duplicate/reused secret digests.
    /// It accepts only one-way digests and never receives plaintext key data.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyErrorCode::InvalidArgument`] when the persisted fields
    /// cannot represent a state reachable through the public transition API.
    pub fn from_snapshot(snapshot: ApiKeySnapshot) -> Result<Self, ApiKeyError> {
        let scopes = validate_snapshot(&snapshot)?;
        Ok(Self {
            id: snapshot.id,
            owner: snapshot.owner,
            prefix: snapshot.prefix,
            current_secret: snapshot.current_secret,
            previous_secret: snapshot.previous_secret,
            rotation_started_at: snapshot.rotation_started_at,
            previous_secret_expires_at: snapshot.previous_secret_expires_at,
            retired_secrets: snapshot.retired_secrets,
            scopes,
            issued_at: snapshot.issued_at,
            expires_at: snapshot.expires_at,
            version: snapshot.version,
            state: snapshot.state,
        })
    }

    /// Returns the key identity.
    #[must_use]
    pub const fn id(&self) -> &ApiKeyId {
        &self.id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.owner.tenant_id()
    }

    /// Returns the owner user identity.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        self.owner.user_id()
    }

    /// Returns the owner binding.
    #[must_use]
    pub const fn owner(&self) -> &ApiKeyOwner {
        &self.owner
    }

    /// Returns the non-secret lookup prefix.
    #[must_use]
    pub const fn prefix(&self) -> &ApiKeyPrefix {
        &self.prefix
    }

    /// Returns the current secret digest.
    #[must_use]
    pub const fn current_secret(&self) -> ApiKeySecretDigest {
        self.current_secret
    }

    /// Returns the previous secret digest during an overlap window.
    #[must_use]
    pub const fn previous_secret(&self) -> Option<ApiKeySecretDigest> {
        self.previous_secret
    }

    /// Returns the trusted instant at which the current rotation began.
    #[must_use]
    pub const fn rotation_started_at(&self) -> Option<UtcTimestamp> {
        self.rotation_started_at
    }

    /// Returns when the previous secret stops being accepted.
    #[must_use]
    pub const fn previous_secret_expires_at(&self) -> Option<UtcTimestamp> {
        self.previous_secret_expires_at
    }

    /// Returns all retired secret digests in retirement order.
    ///
    /// The collection contains at most [`MAX_RETIRED_SECRETS`] entries and
    /// must be persisted with the aggregate for complete reuse detection.
    #[must_use]
    pub fn retired_secrets(&self) -> &[ApiKeySecretDigest] {
        &self.retired_secrets
    }

    /// Returns the granted scopes.
    #[must_use]
    pub fn scopes(&self) -> &[ApiKeyScope] {
        &self.scopes
    }

    /// Returns the trusted issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UtcTimestamp {
        self.issued_at
    }

    /// Returns the exclusive absolute expiry boundary when configured.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UtcTimestamp> {
        self.expires_at
    }

    /// Returns the current optimistic version.
    #[must_use]
    pub const fn version(&self) -> ApiKeyVersion {
        self.version
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ApiKeyState {
        self.state
    }

    /// Returns every durable field needed for lossless reconstruction.
    #[must_use]
    pub fn snapshot_state(&self) -> ApiKeySnapshot {
        ApiKeySnapshot {
            id: self.id.clone(),
            owner: self.owner.clone(),
            prefix: self.prefix.clone(),
            current_secret: self.current_secret,
            previous_secret: self.previous_secret,
            rotation_started_at: self.rotation_started_at,
            previous_secret_expires_at: self.previous_secret_expires_at,
            retired_secrets: self.retired_secrets.clone(),
            scopes: self.scopes.to_vec(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            version: self.version,
            state: self.state,
        }
    }

    pub(crate) fn issued(request: ApiKeyIssueRequest) -> Self {
        Self {
            id: request.binding.id,
            owner: request.binding.owner,
            prefix: request.binding.prefix,
            current_secret: request.secret_digest,
            previous_secret: None,
            rotation_started_at: None,
            previous_secret_expires_at: None,
            retired_secrets: Vec::new(),
            scopes: request.scopes,
            issued_at: request.validity.issued_at,
            expires_at: request.validity.expires_at,
            version: ApiKeyVersion::initial(),
            state: ApiKeyState::Active,
        }
    }

    pub(crate) fn advance(&self, next: ApiKeyAdvance) -> Self {
        Self {
            id: self.id.clone(),
            owner: self.owner.clone(),
            prefix: self.prefix.clone(),
            current_secret: next.current_secret,
            previous_secret: next.previous_secret,
            rotation_started_at: next.rotation_started_at,
            previous_secret_expires_at: next.previous_secret_expires_at,
            retired_secrets: next.retired_secrets,
            scopes: self.scopes.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            version: next.version,
            state: next.state,
        }
    }
}

pub(crate) struct ApiKeyAdvance {
    pub(crate) version: ApiKeyVersion,
    pub(crate) state: ApiKeyState,
    pub(crate) current_secret: ApiKeySecretDigest,
    pub(crate) previous_secret: Option<ApiKeySecretDigest>,
    pub(crate) rotation_started_at: Option<UtcTimestamp>,
    pub(crate) previous_secret_expires_at: Option<UtcTimestamp>,
    pub(crate) retired_secrets: Vec<ApiKeySecretDigest>,
}

pub(crate) fn normalize_scopes(
    scopes: Vec<ApiKeyScope>,
) -> Result<Box<[ApiKeyScope]>, ApiKeyError> {
    if scopes.is_empty() || scopes.len() > MAX_API_KEY_SCOPES {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    let mut normalized = scopes;
    normalized.sort();
    normalized.dedup();
    if normalized.is_empty() || normalized.len() > MAX_API_KEY_SCOPES {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(normalized.into_boxed_slice())
}

fn validate_snapshot(snapshot: &ApiKeySnapshot) -> Result<Box<[ApiKeyScope]>, ApiKeyError> {
    validate_snapshot_identity(snapshot)?;
    validate_snapshot_version(snapshot)?;
    validate_snapshot_validity(snapshot)?;
    validate_snapshot_secret_state(snapshot)?;
    validate_retired_secrets(snapshot)?;
    normalize_scopes(snapshot.scopes.clone())
}

fn validate_snapshot_identity(snapshot: &ApiKeySnapshot) -> Result<(), ApiKeyError> {
    let valid = !snapshot.id.as_str().is_empty()
        && !snapshot.owner.tenant_id().as_str().is_empty()
        && !snapshot.owner.user_id().as_str().is_empty()
        && !snapshot.prefix.as_str().is_empty()
        && snapshot.version.get() != 0;
    if !valid {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_snapshot_version(snapshot: &ApiKeySnapshot) -> Result<(), ApiKeyError> {
    let retired = u64::try_from(snapshot.retired_secrets.len())
        .map_err(|_| error(ApiKeyErrorCode::InvalidArgument))?;
    let rotation_cost = retired
        .checked_mul(2)
        .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))?;
    let active = version_with_cost(1, rotation_cost)?;
    let rotating = version_with_cost(2, rotation_cost)?;
    let valid = match snapshot.state {
        ApiKeyState::Active => snapshot.version.get() == active,
        ApiKeyState::Rotating => snapshot.version.get() == rotating,
        ApiKeyState::Revoked | ApiKeyState::Expired => {
            valid_terminal_version(snapshot.version.get(), retired, active, rotating)
        }
    };
    if !valid {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn version_with_cost(base: u64, cost: u64) -> Result<u64, ApiKeyError> {
    base.checked_add(cost)
        .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))
}

fn valid_terminal_version(version: u64, retired: u64, active: u64, rotating: u64) -> bool {
    version == rotating || (retired > 0 && version == active)
}

fn validate_snapshot_validity(snapshot: &ApiKeySnapshot) -> Result<(), ApiKeyError> {
    let Some(expires_at) = snapshot.expires_at else {
        return validate_expired_state(snapshot);
    };
    let span = expires_at
        .unix_seconds()
        .checked_sub(snapshot.issued_at.unix_seconds())
        .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))?;
    if span <= 0 || span > MAX_API_KEY_LIFETIME_SECONDS {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_expired_state(snapshot: &ApiKeySnapshot) -> Result<(), ApiKeyError> {
    if snapshot.state == ApiKeyState::Expired {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_snapshot_secret_state(snapshot: &ApiKeySnapshot) -> Result<(), ApiKeyError> {
    let has_previous = snapshot.previous_secret.is_some();
    let complete_pairing = has_previous == snapshot.rotation_started_at.is_some()
        && has_previous == snapshot.previous_secret_expires_at.is_some();
    if !complete_pairing {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    validate_previous_state(snapshot, has_previous)?;
    validate_previous_digest(snapshot)?;
    validate_snapshot_overlap(snapshot)
}

fn validate_previous_state(
    snapshot: &ApiKeySnapshot,
    has_previous: bool,
) -> Result<(), ApiKeyError> {
    let valid = match snapshot.state {
        ApiKeyState::Rotating => has_previous,
        ApiKeyState::Active | ApiKeyState::Revoked | ApiKeyState::Expired => !has_previous,
    };
    if !valid {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_previous_digest(snapshot: &ApiKeySnapshot) -> Result<(), ApiKeyError> {
    if snapshot.previous_secret == Some(snapshot.current_secret) {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_snapshot_overlap(snapshot: &ApiKeySnapshot) -> Result<(), ApiKeyError> {
    let Some((rotation_started, overlap_expiry)) = snapshot
        .rotation_started_at
        .zip(snapshot.previous_secret_expires_at)
    else {
        return Ok(());
    };
    let span = overlap_expiry
        .unix_seconds()
        .checked_sub(rotation_started.unix_seconds())
        .ok_or_else(|| error(ApiKeyErrorCode::InvalidArgument))?;
    if span <= 0 || span > MAX_OVERLAP_SECONDS {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    validate_rotation_start(snapshot, rotation_started)?;
    validate_overlap_before_expiry(snapshot, overlap_expiry)
}

fn validate_rotation_start(
    snapshot: &ApiKeySnapshot,
    rotation_started: UtcTimestamp,
) -> Result<(), ApiKeyError> {
    let after_issue = rotation_started.unix_seconds() >= snapshot.issued_at.unix_seconds();
    let before_expiry = snapshot
        .expires_at
        .is_none_or(|absolute| rotation_started.unix_seconds() < absolute.unix_seconds());
    if !after_issue || !before_expiry {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_overlap_before_expiry(
    snapshot: &ApiKeySnapshot,
    overlap_expiry: UtcTimestamp,
) -> Result<(), ApiKeyError> {
    let within_absolute = snapshot
        .expires_at
        .is_none_or(|absolute| overlap_expiry.unix_seconds() <= absolute.unix_seconds());
    if !within_absolute {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_retired_secrets(snapshot: &ApiKeySnapshot) -> Result<(), ApiKeyError> {
    if snapshot.retired_secrets.len() > MAX_RETIRED_SECRETS {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    let mut seen = HashSet::with_capacity(snapshot.retired_secrets.len());
    for digest in &snapshot.retired_secrets {
        validate_retired_digest(snapshot, *digest, &mut seen)?;
    }
    Ok(())
}

fn validate_retired_digest(
    snapshot: &ApiKeySnapshot,
    digest: ApiKeySecretDigest,
    seen: &mut HashSet<ApiKeySecretDigest>,
) -> Result<(), ApiKeyError> {
    let duplicates_live =
        digest == snapshot.current_secret || Some(digest) == snapshot.previous_secret;
    if duplicates_live || !seen.insert(digest) {
        return Err(error(ApiKeyErrorCode::InvalidArgument));
    }
    Ok(())
}

fn domain_separated_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

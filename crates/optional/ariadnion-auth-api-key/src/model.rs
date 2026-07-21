//! Immutable scoped API-key model values.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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

    pub(crate) fn matches(self, presented: Self) -> bool {
        bool::from(self.0.ct_eq(&presented.0))
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

/// Immutable inputs required to issue one scoped API key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyIssueRequest {
    id: ApiKeyId,
    owner: ApiKeyOwner,
    actor: PrincipalId,
    prefix: ApiKeyPrefix,
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
        id: ApiKeyId,
        owner: ApiKeyOwner,
        actor: PrincipalId,
        prefix: ApiKeyPrefix,
        secret_digest: ApiKeySecretDigest,
        scopes: Vec<ApiKeyScope>,
        validity: ApiKeyValidityWindow,
    ) -> Result<Self, ApiKeyError> {
        let scopes = normalize_scopes(scopes)?;
        Ok(Self {
            id,
            owner,
            actor,
            prefix,
            secret_digest,
            scopes,
            validity,
        })
    }

    /// Returns the trusted actor for issuance.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
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
    previous_secret_expires_at: Option<UtcTimestamp>,
    scopes: Box<[ApiKeyScope]>,
    issued_at: UtcTimestamp,
    expires_at: Option<UtcTimestamp>,
    version: ApiKeyVersion,
    state: ApiKeyState,
}

impl ApiKey {
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

    /// Returns when the previous secret stops being accepted.
    #[must_use]
    pub const fn previous_secret_expires_at(&self) -> Option<UtcTimestamp> {
        self.previous_secret_expires_at
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

    pub(crate) fn issued(request: ApiKeyIssueRequest) -> Self {
        Self {
            id: request.id,
            owner: request.owner,
            prefix: request.prefix,
            current_secret: request.secret_digest,
            previous_secret: None,
            previous_secret_expires_at: None,
            scopes: request.scopes,
            issued_at: request.validity.issued_at,
            expires_at: request.validity.expires_at,
            version: ApiKeyVersion::initial(),
            state: ApiKeyState::Active,
        }
    }

    pub(crate) fn advance(
        &self,
        version: ApiKeyVersion,
        state: ApiKeyState,
        current_secret: ApiKeySecretDigest,
        previous_secret: Option<ApiKeySecretDigest>,
        previous_secret_expires_at: Option<UtcTimestamp>,
    ) -> Self {
        Self {
            id: self.id.clone(),
            owner: self.owner.clone(),
            prefix: self.prefix.clone(),
            current_secret,
            previous_secret,
            previous_secret_expires_at,
            scopes: self.scopes.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            version,
            state,
        }
    }
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

fn domain_separated_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

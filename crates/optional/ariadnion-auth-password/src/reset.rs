//! Tenant-bound one-time password-recovery contracts.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU64;

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{PasswordError, PasswordErrorCode, PasswordHashRecord};

const MAX_RESET_ID_BYTES: usize = 128;
const MIN_RESET_TOKEN_BYTES: usize = 32;
const MAX_RESET_TOKEN_BYTES: usize = 256;
const MAX_RESET_LIFETIME_SECONDS: i64 = 1_800;
const RESET_TOKEN_DOMAIN: &[u8] = b"ariadnion.password-recovery.token.v1\0";
const PASSWORD_HASH_RECORD_DOMAIN: &[u8] = b"ariadnion.password-recovery.password-hash-record.v1\0";

/// A bounded path-free password-reset aggregate identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PasswordResetId(Box<str>);

impl PasswordResetId {
    /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
    ///
    /// The accepted alphabet contains ASCII letters, digits, dots, hyphens,
    /// and underscores.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidResetArgument`] without retaining
    /// the rejected value when its length or alphabet is invalid.
    pub fn parse(value: &str) -> Result<Self, PasswordError> {
        if !valid_reset_id(value) {
            return Err(reset_error(PasswordErrorCode::InvalidResetArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity for persistence or protocol encoding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for PasswordResetId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordResetId(<opaque>)")
    }
}

/// A non-zero optimistic version for one password-reset aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PasswordResetVersion(NonZeroU64);

impl PasswordResetVersion {
    /// Returns the version assigned during password-reset issuance.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero optimistic password-reset version.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidResetArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, PasswordError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| reset_error(PasswordErrorCode::InvalidResetArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic password-reset version.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::ResetVersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, PasswordError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| reset_error(PasswordErrorCode::ResetVersionExhausted))
    }
}

/// A domain-separated SHA-256 digest of a password-recovery token.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PasswordResetTokenDigest([u8; 32]);

impl PasswordResetTokenDigest {
    /// Derives a digest from a high-entropy token without retaining plaintext.
    ///
    /// The token must contain between 32 and 256 bytes inclusive. The digest
    /// includes a fixed versioned password-recovery domain prefix.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidResetArgument`] when the token is
    /// outside the supported byte bounds.
    pub fn from_token(token: &[u8]) -> Result<Self, PasswordError> {
        if !(MIN_RESET_TOKEN_BYTES..=MAX_RESET_TOKEN_BYTES).contains(&token.len()) {
            return Err(reset_error(PasswordErrorCode::InvalidResetArgument));
        }
        Ok(Self(domain_separated_digest(RESET_TOKEN_DOMAIN, token)))
    }

    /// Returns the exact digest bytes for persistence or constant-time comparison.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }

    fn matches(self, presented: Self) -> bool {
        bool::from(self.0.ct_eq(&presented.0))
    }
}

impl Debug for PasswordResetTokenDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordResetTokenDigest(<sha256>)")
    }
}

/// A domain-separated SHA-256 commitment to a validated PHC record.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PasswordHashRecordDigest([u8; 32]);

impl PasswordHashRecordDigest {
    /// Derives a commitment without retaining another copy of the PHC text.
    #[must_use]
    pub fn from_record(record: &PasswordHashRecord) -> Self {
        Self(domain_separated_digest(
            PASSWORD_HASH_RECORD_DOMAIN,
            record.as_str().as_bytes(),
        ))
    }

    /// Returns the exact digest bytes for persistence or constant-time comparison.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Debug for PasswordHashRecordDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHashRecordDigest(<sha256>)")
    }
}

/// The fixed purpose of every password reset issued by this module.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PasswordResetPurpose {
    /// Recovery of a user's password credential.
    PasswordRecovery,
}

/// The complete lifecycle state set for a password-reset aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PasswordResetState {
    /// The reset may be consumed or revoked before its expiry boundary.
    Issued,
    /// The reset produced a replacement password-hash commit intent.
    Consumed,
    /// The reset was explicitly revoked before consumption.
    Revoked,
    /// The reset reached an explicit expiry transition.
    Expired,
}

/// Tenant and user identity bound to one password-recovery flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordResetSubject {
    tenant_id: TenantId,
    user_id: UserId,
}

impl PasswordResetSubject {
    /// Creates a subject without allowing callers to select a reset purpose.
    #[must_use]
    pub const fn new(tenant_id: TenantId, user_id: UserId) -> Self {
        Self { tenant_id, user_id }
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the user identity within the tenant boundary.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

/// Trusted UTC issuance and exclusive expiry boundaries for a password reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordResetValidityWindow {
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
}

impl PasswordResetValidityWindow {
    /// Couples trusted UTC boundaries for validation during issuance.
    ///
    /// [`issue_password_reset`] rejects empty, reversed, overflowing, or
    /// longer-than-30-minute windows.
    #[must_use]
    pub const fn new(issued_at: UtcTimestamp, expires_at: UtcTimestamp) -> Self {
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

    /// Returns the exclusive UTC expiry boundary.
    #[must_use]
    pub const fn expires_at(self) -> UtcTimestamp {
        self.expires_at
    }
}

/// Immutable inputs required to issue one password-recovery reset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordResetIssueRequest {
    reset_id: PasswordResetId,
    subject: PasswordResetSubject,
    actor: PrincipalId,
    token_digest: PasswordResetTokenDigest,
    validity: PasswordResetValidityWindow,
}

impl PasswordResetIssueRequest {
    /// Creates an issue request whose purpose is stamped internally as password recovery.
    #[must_use]
    pub const fn new(
        reset_id: PasswordResetId,
        subject: PasswordResetSubject,
        actor: PrincipalId,
        token_digest: PasswordResetTokenDigest,
        validity: PasswordResetValidityWindow,
    ) -> Self {
        Self {
            reset_id,
            subject,
            actor,
            token_digest,
            validity,
        }
    }
}

/// An immutable tenant-bound password-reset aggregate containing only digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordReset {
    id: PasswordResetId,
    subject: PasswordResetSubject,
    token_digest: PasswordResetTokenDigest,
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
    version: PasswordResetVersion,
    purpose: PasswordResetPurpose,
    state: PasswordResetState,
    password_hash_digest: Option<PasswordHashRecordDigest>,
}

impl PasswordReset {
    /// Returns the immutable reset identity.
    #[must_use]
    pub const fn id(&self) -> &PasswordResetId {
        &self.id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.subject.tenant_id()
    }

    /// Returns the user identity within the tenant boundary.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        self.subject.user_id()
    }

    /// Returns the stored one-way token digest.
    #[must_use]
    pub const fn token_digest(&self) -> PasswordResetTokenDigest {
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
    pub const fn version(&self) -> PasswordResetVersion {
        self.version
    }

    /// Returns the fixed password-recovery purpose.
    #[must_use]
    pub const fn purpose(&self) -> PasswordResetPurpose {
        self.purpose
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> PasswordResetState {
        self.state
    }

    /// Returns the replacement PHC commitment only after consumption.
    #[must_use]
    pub const fn password_hash_digest(&self) -> Option<PasswordHashRecordDigest> {
        self.password_hash_digest
    }

    fn issued(request: PasswordResetIssueRequest) -> Self {
        Self {
            id: request.reset_id,
            subject: request.subject,
            token_digest: request.token_digest,
            issued_at: request.validity.issued_at,
            expires_at: request.validity.expires_at,
            version: PasswordResetVersion::initial(),
            purpose: PasswordResetPurpose::PasswordRecovery,
            state: PasswordResetState::Issued,
            password_hash_digest: None,
        }
    }

    fn advance(
        &self,
        version: PasswordResetVersion,
        state: PasswordResetState,
        password_hash_digest: Option<PasswordHashRecordDigest>,
    ) -> Self {
        Self {
            id: self.id.clone(),
            subject: self.subject.clone(),
            token_digest: self.token_digest,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            version,
            purpose: self.purpose,
            state,
            password_hash_digest,
        }
    }
}

/// Token evidence and the actual replacement PHC record for consumption.
#[derive(Debug)]
pub struct PasswordResetConsumption {
    token_digest: PasswordResetTokenDigest,
    password_hash_record: PasswordHashRecord,
}

impl PasswordResetConsumption {
    /// Owns consumption evidence without deriving the PHC commitment early.
    ///
    /// The replacement digest is derived only after subject and token evidence
    /// passes inside [`transition_password_reset`].
    #[must_use]
    pub const fn new(
        token_digest: PasswordResetTokenDigest,
        password_hash_record: PasswordHashRecord,
    ) -> Self {
        Self {
            token_digest,
            password_hash_record,
        }
    }
}

/// One requested password-reset lifecycle action.
#[derive(Debug)]
pub enum PasswordResetAction {
    /// Consume the reset once and produce a credential-replacement commit intent.
    Consume(PasswordResetConsumption),
    /// Revoke an issued reset before its expiry boundary.
    Revoke,
    /// Mark an issued reset expired at or after its boundary.
    Expire,
}

/// Subject-, actor-, time-, version-, and action-bound password-reset command.
#[derive(Debug)]
pub struct PasswordResetCommand {
    expected_version: PasswordResetVersion,
    subject: PasswordResetSubject,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    action: PasswordResetAction,
}

impl PasswordResetCommand {
    /// Creates a deterministic command without consulting a clock or storage.
    #[must_use]
    pub const fn new(
        expected_version: PasswordResetVersion,
        subject: PasswordResetSubject,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
        action: PasswordResetAction,
    ) -> Self {
        Self {
            expected_version,
            subject,
            actor,
            occurred_at,
            action,
        }
    }
}

/// Stable audit-ready password-reset event kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PasswordResetEventKind {
    /// A password reset was issued.
    Issued,
    /// A password reset was consumed.
    Consumed,
    /// A password reset was revoked.
    Revoked,
    /// A password reset reached its explicit expiry transition.
    Expired,
}

impl PasswordResetEventKind {
    /// Returns the stable English machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "PASSWORD_RESET_ISSUED",
            Self::Consumed => "PASSWORD_RESET_CONSUMED",
            Self::Revoked => "PASSWORD_RESET_REVOKED",
            Self::Expired => "PASSWORD_RESET_EXPIRED",
        }
    }
}

/// Immutable audit-ready event produced with every accepted reset transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordResetEvent {
    reset_id: PasswordResetId,
    subject: PasswordResetSubject,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    version: PasswordResetVersion,
    purpose: PasswordResetPurpose,
    kind: PasswordResetEventKind,
    password_hash_digest: Option<PasswordHashRecordDigest>,
}

impl PasswordResetEvent {
    /// Returns the password-reset identity.
    #[must_use]
    pub const fn reset_id(&self) -> &PasswordResetId {
        &self.reset_id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.subject.tenant_id()
    }

    /// Returns the user identity within the tenant boundary.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        self.subject.user_id()
    }

    /// Returns the trusted actor attributed to this event.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the trusted UTC event time.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the resulting aggregate version.
    #[must_use]
    pub const fn version(&self) -> PasswordResetVersion {
        self.version
    }

    /// Returns the fixed password-recovery purpose.
    #[must_use]
    pub const fn purpose(&self) -> PasswordResetPurpose {
        self.purpose
    }

    /// Returns the stable lifecycle event kind.
    #[must_use]
    pub const fn kind(&self) -> PasswordResetEventKind {
        self.kind
    }

    /// Returns the replacement PHC commitment only for consumption events.
    #[must_use]
    pub const fn password_hash_digest(&self) -> Option<PasswordHashRecordDigest> {
        self.password_hash_digest
    }
}

/// A resulting reset snapshot, audit event, and optional credential commit intent.
#[derive(Debug)]
pub struct PasswordResetTransition {
    reset: PasswordReset,
    event: PasswordResetEvent,
    password_hash_record: Option<PasswordHashRecord>,
}

impl PasswordResetTransition {
    /// Returns the resulting immutable reset snapshot.
    #[must_use]
    pub const fn reset(&self) -> &PasswordReset {
        &self.reset
    }

    /// Returns the exactly corresponding audit event.
    #[must_use]
    pub const fn event(&self) -> &PasswordResetEvent {
        &self.event
    }

    /// Returns the actual replacement PHC record only after successful consumption.
    ///
    /// A persistence adapter must use this record in the same atomic operation
    /// that commits the returned reset snapshot and event.
    #[must_use]
    pub const fn password_hash_record(&self) -> Option<&PasswordHashRecord> {
        self.password_hash_record.as_ref()
    }

    /// Consumes the transition into its snapshot, event, and optional PHC record.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PasswordReset,
        PasswordResetEvent,
        Option<PasswordHashRecord>,
    ) {
        (self.reset, self.event, self.password_hash_record)
    }
}

/// Issues a password-recovery reset with a version-one audit event.
///
/// The purpose is always [`PasswordResetPurpose::PasswordRecovery`]; callers
/// cannot substitute another purpose.
///
/// # Errors
///
/// Returns [`PasswordErrorCode::InvalidResetLifetime`] unless expiry is one
/// through 1,800 checked UTC seconds after issuance.
pub fn issue_password_reset(
    request: PasswordResetIssueRequest,
) -> Result<PasswordResetTransition, PasswordError> {
    validate_reset_lifetime(request.validity)?;
    let actor = request.actor.clone();
    let occurred_at = request.validity.issued_at;
    let reset = PasswordReset::issued(request);
    let event = event_from(&reset, actor, occurred_at, PasswordResetEventKind::Issued);
    Ok(PasswordResetTransition {
        reset,
        event,
        password_hash_record: None,
    })
}

/// Applies one deterministic optimistic password-reset transition.
///
/// Subject and token evidence are checked before version, time, and lifecycle
/// state so invalid evidence cannot be used as a state oracle. The token digest
/// comparison is constant time. This pure transition does not itself prove
/// durable single use and has no storage dependency. The persistence adapter
/// must atomically compare-and-swap the expected stored reset version, replace
/// the credential with the returned PHC record, persist the consumed snapshot,
/// and append the event. A failure must commit none of those effects.
///
/// # Errors
///
/// Returns stable redacted failures for invalid evidence, optimistic-version
/// conflicts, pre-issuance commands, expiry boundaries, terminal states, or
/// version exhaustion.
pub fn transition_password_reset(
    current: &PasswordReset,
    command: PasswordResetCommand,
) -> Result<PasswordResetTransition, PasswordError> {
    validate_reset_evidence(current, &command)?;
    validate_expected_version(current, command.expected_version)?;
    validate_command_time(current, command.occurred_at)?;
    validate_current_state(current.state)?;

    let PasswordResetCommand {
        expected_version: _,
        subject: _,
        actor,
        occurred_at,
        action,
    } = command;
    let outcome = apply_action(current, occurred_at, action)?;
    let version = current.version.next()?;
    let reset = current.advance(version, outcome.state, outcome.password_hash_digest);
    let event = event_from(&reset, actor, occurred_at, outcome.kind);
    Ok(PasswordResetTransition {
        reset,
        event,
        password_hash_record: outcome.password_hash_record,
    })
}

struct TransitionOutcome {
    state: PasswordResetState,
    kind: PasswordResetEventKind,
    password_hash_digest: Option<PasswordHashRecordDigest>,
    password_hash_record: Option<PasswordHashRecord>,
}

fn valid_reset_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RESET_ID_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn domain_separated_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    <[u8; 32]>::from(digest.finalize())
}

fn validate_reset_lifetime(validity: PasswordResetValidityWindow) -> Result<(), PasswordError> {
    let lifetime = validity
        .expires_at
        .unix_seconds()
        .checked_sub(validity.issued_at.unix_seconds())
        .ok_or_else(|| reset_error(PasswordErrorCode::InvalidResetLifetime))?;
    if !(1..=MAX_RESET_LIFETIME_SECONDS).contains(&lifetime) {
        return Err(reset_error(PasswordErrorCode::InvalidResetLifetime));
    }
    Ok(())
}

fn validate_reset_evidence(
    reset: &PasswordReset,
    command: &PasswordResetCommand,
) -> Result<(), PasswordError> {
    let subject_matches = command.subject == reset.subject;
    let token_matches = match &command.action {
        PasswordResetAction::Consume(consumption) => {
            reset.token_digest.matches(consumption.token_digest)
        }
        PasswordResetAction::Revoke | PasswordResetAction::Expire => true,
    };
    if !subject_matches || !token_matches {
        return Err(reset_error(PasswordErrorCode::InvalidResetEvidence));
    }
    Ok(())
}

fn validate_expected_version(
    reset: &PasswordReset,
    expected: PasswordResetVersion,
) -> Result<(), PasswordError> {
    if reset.version != expected {
        return Err(reset_error(PasswordErrorCode::ResetVersionConflict));
    }
    Ok(())
}

fn validate_command_time(
    reset: &PasswordReset,
    occurred_at: UtcTimestamp,
) -> Result<(), PasswordError> {
    if occurred_at < reset.issued_at {
        return Err(reset_error(PasswordErrorCode::InvalidResetTime));
    }
    Ok(())
}

fn validate_current_state(state: PasswordResetState) -> Result<(), PasswordError> {
    match state {
        PasswordResetState::Issued => Ok(()),
        PasswordResetState::Consumed => Err(reset_error(PasswordErrorCode::ResetAlreadyConsumed)),
        PasswordResetState::Revoked => Err(reset_error(PasswordErrorCode::ResetRevoked)),
        PasswordResetState::Expired => Err(reset_error(PasswordErrorCode::ResetExpired)),
    }
}

fn apply_action(
    reset: &PasswordReset,
    occurred_at: UtcTimestamp,
    action: PasswordResetAction,
) -> Result<TransitionOutcome, PasswordError> {
    match action {
        PasswordResetAction::Consume(consumption) => {
            apply_consumption(reset, occurred_at, consumption)
        }
        PasswordResetAction::Revoke => apply_revocation(reset, occurred_at),
        PasswordResetAction::Expire => apply_expiry(reset, occurred_at),
    }
}

fn apply_consumption(
    reset: &PasswordReset,
    occurred_at: UtcTimestamp,
    consumption: PasswordResetConsumption,
) -> Result<TransitionOutcome, PasswordError> {
    require_not_expired(reset, occurred_at)?;
    let PasswordResetConsumption {
        token_digest: _,
        password_hash_record,
    } = consumption;
    let digest = PasswordHashRecordDigest::from_record(&password_hash_record);
    Ok(TransitionOutcome {
        state: PasswordResetState::Consumed,
        kind: PasswordResetEventKind::Consumed,
        password_hash_digest: Some(digest),
        password_hash_record: Some(password_hash_record),
    })
}

fn apply_revocation(
    reset: &PasswordReset,
    occurred_at: UtcTimestamp,
) -> Result<TransitionOutcome, PasswordError> {
    require_not_expired(reset, occurred_at)?;
    Ok(TransitionOutcome {
        state: PasswordResetState::Revoked,
        kind: PasswordResetEventKind::Revoked,
        password_hash_digest: None,
        password_hash_record: None,
    })
}

fn apply_expiry(
    reset: &PasswordReset,
    occurred_at: UtcTimestamp,
) -> Result<TransitionOutcome, PasswordError> {
    if occurred_at < reset.expires_at {
        return Err(reset_error(PasswordErrorCode::ResetNotYetExpired));
    }
    Ok(TransitionOutcome {
        state: PasswordResetState::Expired,
        kind: PasswordResetEventKind::Expired,
        password_hash_digest: None,
        password_hash_record: None,
    })
}

fn require_not_expired(
    reset: &PasswordReset,
    occurred_at: UtcTimestamp,
) -> Result<(), PasswordError> {
    if occurred_at >= reset.expires_at {
        return Err(reset_error(PasswordErrorCode::ResetExpired));
    }
    Ok(())
}

fn event_from(
    reset: &PasswordReset,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    kind: PasswordResetEventKind,
) -> PasswordResetEvent {
    PasswordResetEvent {
        reset_id: reset.id.clone(),
        subject: reset.subject.clone(),
        actor,
        occurred_at,
        version: reset.version,
        purpose: reset.purpose,
        kind,
        password_hash_digest: reset.password_hash_digest,
    }
}

const fn reset_error(code: PasswordErrorCode) -> PasswordError {
    PasswordError::new(code)
}

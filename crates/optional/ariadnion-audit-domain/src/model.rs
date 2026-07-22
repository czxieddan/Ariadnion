//! Immutable auditable security-event model.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_user_domain::UtcTimestamp;
use sha2::{Digest, Sha256};

use crate::error::error;
use crate::{AuditError, AuditErrorCode, AuditEventId, AuditSequence};

/// Maximum accepted reason code length in bytes.
pub const MAX_REASON_BYTES: usize = 64;
/// Maximum payload material accepted by the in-memory digest helper.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.audit.payload.v1\0";
/// Chain digest schema version. Changing canonical fields requires a new value.
pub const AUDIT_CHAIN_DIGEST_VERSION: u16 = 2;

const CHAIN_DOMAIN: &[u8] = b"ariadnion.audit.chain.v2\0";

/// Stable audited subject category without embedding secrets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditSubjectKind {
    /// A user aggregate was affected.
    User,
    /// An organization aggregate was affected.
    Organization,
    /// An invitation aggregate was affected.
    Invitation,
    /// A browser session family was affected.
    SessionFamily,
    /// An API key was affected.
    ApiKey,
    /// A password-reset aggregate was affected.
    PasswordReset,
    /// An administrative decision or policy change was affected.
    Administration,
}

/// Stable audited security event kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditEventKind {
    /// A security-relevant resource was created or issued.
    Issued,
    /// A security-relevant resource was consumed or accepted.
    Consumed,
    /// A security-relevant resource was rotated.
    Rotated,
    /// A security-relevant resource was revoked.
    Revoked,
    /// A security-relevant resource expired.
    Expired,
    /// Token or secret reuse was detected.
    ReuseDetected,
    /// An administrative action was accepted.
    Administered,
}

/// Irreversible pseudonym retained for subject correlation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AuditSubjectDigest([u8; 32]);

impl AuditSubjectDigest {
    /// Rehydrates an adapter-produced, already pseudonymized subject digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes for authenticated persistence.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Debug for AuditSubjectDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditSubjectDigest(<sha256>)")
    }
}

/// Pseudonymous subject identity retained for audit correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditSubject {
    kind: AuditSubjectKind,
    digest: AuditSubjectDigest,
}

impl AuditSubject {
    /// Rehydrates an already pseudonymized subject identity.
    ///
    /// Adapters must derive this digest with a tenant-scoped keyed mechanism or
    /// use a revocable mapping before constructing the audit subject. This
    /// contract intentionally accepts only fixed-size digest material and never
    /// receives a raw identifier.
    #[must_use]
    pub const fn from_digest(kind: AuditSubjectKind, digest: AuditSubjectDigest) -> Self {
        Self { kind, digest }
    }

    /// Returns the subject category.
    #[must_use]
    pub const fn kind(&self) -> AuditSubjectKind {
        self.kind
    }

    /// Returns the irreversible subject pseudonym.
    #[must_use]
    pub const fn digest(&self) -> AuditSubjectDigest {
        self.digest
    }
}

/// Domain-separated SHA-256 digest of a canonical audit payload.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AuditPayloadDigest([u8; 32]);

impl AuditPayloadDigest {
    /// Creates a digest from exact SHA-256 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Digests bounded adapter-canonical payload bytes without retaining them.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::InvalidArgument`] when `payload` exceeds
    /// [`MAX_PAYLOAD_BYTES`]. Streaming or durable adapters should hash larger
    /// inputs outside this helper and pass the resulting fixed-size digest.
    pub fn from_payload(payload: &[u8]) -> Result<Self, AuditError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(error(AuditErrorCode::InvalidArgument));
        }
        Ok(Self(domain_separated_digest(PAYLOAD_DOMAIN, payload)))
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Debug for AuditPayloadDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditPayloadDigest(<sha256>)")
    }
}

/// Domain-separated chain digest linking one audit event to its predecessor.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AuditChainDigest([u8; 32]);

impl AuditChainDigest {
    /// Creates a digest from exact SHA-256 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Digests the predecessor chain material without retaining it.
    #[must_use]
    pub(crate) fn from_material(material: &[u8]) -> Self {
        Self(domain_separated_digest(CHAIN_DOMAIN, material))
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Debug for AuditChainDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditChainDigest(<sha256>)")
    }
}

/// Immutable append-only security audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    id: AuditEventId,
    tenant_id: TenantId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    sequence: AuditSequence,
    kind: AuditEventKind,
    subject: AuditSubject,
    reason_code: Box<str>,
    payload_digest: AuditPayloadDigest,
    previous_chain_digest: Option<AuditChainDigest>,
    chain_digest_version: u16,
    chain_digest: AuditChainDigest,
}

impl AuditEvent {
    /// Returns the event identity.
    #[must_use]
    pub const fn id(&self) -> &AuditEventId {
        &self.id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
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

    /// Returns the append-only sequence number.
    #[must_use]
    pub const fn sequence(&self) -> AuditSequence {
        self.sequence
    }

    /// Returns the event kind.
    #[must_use]
    pub const fn kind(&self) -> AuditEventKind {
        self.kind
    }

    /// Returns the affected subject.
    #[must_use]
    pub const fn subject(&self) -> &AuditSubject {
        &self.subject
    }

    /// Returns the stable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }

    /// Returns the payload digest.
    #[must_use]
    pub const fn payload_digest(&self) -> AuditPayloadDigest {
        self.payload_digest
    }

    /// Returns the previous chain digest when one exists.
    #[must_use]
    pub const fn previous_chain_digest(&self) -> Option<AuditChainDigest> {
        self.previous_chain_digest
    }

    /// Returns the canonical chain digest schema version.
    #[must_use]
    pub const fn chain_digest_version(&self) -> u16 {
        self.chain_digest_version
    }

    /// Returns the current chain digest.
    #[must_use]
    pub const fn chain_digest(&self) -> AuditChainDigest {
        self.chain_digest
    }

    /// Recomputes the digest from this event's canonical versioned material.
    ///
    /// Persistence and verification adapters must compare this value with
    /// [`Self::chain_digest`] before trusting the event as a chain anchor.
    #[must_use]
    pub fn recompute_chain_digest(&self) -> AuditChainDigest {
        compute_chain_digest(ChainDigestMaterial::from_event(self))
    }
}

/// Tenant-bound identity and ordering for one audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEventBinding {
    id: AuditEventId,
    tenant_id: TenantId,
    actor: PrincipalId,
    occurred_at: UtcTimestamp,
    sequence: AuditSequence,
}

impl AuditEventBinding {
    /// Creates identity and ordering metadata for one audit event.
    #[must_use]
    pub const fn new(
        id: AuditEventId,
        tenant_id: TenantId,
        actor: PrincipalId,
        occurred_at: UtcTimestamp,
        sequence: AuditSequence,
    ) -> Self {
        Self {
            id,
            tenant_id,
            actor,
            occurred_at,
            sequence,
        }
    }
}

/// Content and chain material for one audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEventContent {
    kind: AuditEventKind,
    subject: AuditSubject,
    reason_code: Box<str>,
    payload_digest: AuditPayloadDigest,
    previous_chain_digest: Option<AuditChainDigest>,
}

impl AuditEventContent {
    /// Creates content material after validating the reason code.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::InvalidArgument`] for invalid reason codes.
    pub fn new(
        kind: AuditEventKind,
        subject: AuditSubject,
        reason_code: &str,
        payload_digest: AuditPayloadDigest,
        previous_chain_digest: Option<AuditChainDigest>,
    ) -> Result<Self, AuditError> {
        Ok(Self {
            kind,
            subject,
            reason_code: parse_reason_code(reason_code)?,
            payload_digest,
            previous_chain_digest,
        })
    }
}

/// Trusted inputs required to construct one append-only audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEventRequest {
    binding: AuditEventBinding,
    content: AuditEventContent,
}

impl AuditEventRequest {
    /// Creates an audit-event request from binding and content.
    #[must_use]
    pub const fn new(binding: AuditEventBinding, content: AuditEventContent) -> Self {
        Self { binding, content }
    }
}

/// Builds one append-only audit event with a chain digest.
///
/// The chain digest covers event id, tenant, actor, occurred-at UTC seconds,
/// sequence, kind, subject, reason code, payload digest, and optional previous
/// chain digest. Adapters must append events in sequence order and reject broken
/// chains. The canonical material is versioned by [`AUDIT_CHAIN_DIGEST_VERSION`].
///
/// # Errors
///
/// Returns stable redacted failures only through request construction.
pub fn build_audit_event(request: AuditEventRequest) -> Result<AuditEvent, AuditError> {
    let chain_digest = compute_chain_digest(ChainDigestMaterial::from_request(&request));
    Ok(AuditEvent {
        id: request.binding.id,
        tenant_id: request.binding.tenant_id,
        actor: request.binding.actor,
        occurred_at: request.binding.occurred_at,
        sequence: request.binding.sequence,
        kind: request.content.kind,
        subject: request.content.subject,
        reason_code: request.content.reason_code,
        payload_digest: request.content.payload_digest,
        previous_chain_digest: request.content.previous_chain_digest,
        chain_digest_version: AUDIT_CHAIN_DIGEST_VERSION,
        chain_digest,
    })
}

/// Rehydrates one persisted audit event after authenticating its declared digest.
///
/// # Errors
///
/// Returns [`AuditErrorCode::UnsupportedVersion`] for an unknown schema or
/// [`AuditErrorCode::DigestMismatch`] when the declared digest differs from the
/// canonical versioned event material.
pub fn rehydrate_audit_event(
    request: AuditEventRequest,
    declared_chain_digest_version: u16,
    declared_chain_digest: AuditChainDigest,
) -> Result<AuditEvent, AuditError> {
    if declared_chain_digest_version != AUDIT_CHAIN_DIGEST_VERSION {
        return Err(error(AuditErrorCode::UnsupportedVersion));
    }
    let event = build_audit_event(request)?;
    if event.chain_digest() != declared_chain_digest {
        return Err(error(AuditErrorCode::DigestMismatch));
    }
    Ok(event)
}

struct ChainDigestMaterial<'a> {
    id: &'a AuditEventId,
    tenant_id: &'a TenantId,
    actor: &'a PrincipalId,
    occurred_at: UtcTimestamp,
    sequence: AuditSequence,
    kind: AuditEventKind,
    subject: &'a AuditSubject,
    reason_code: &'a str,
    payload_digest: AuditPayloadDigest,
    previous_chain_digest: Option<AuditChainDigest>,
}

impl<'a> ChainDigestMaterial<'a> {
    fn from_request(request: &'a AuditEventRequest) -> Self {
        Self {
            id: &request.binding.id,
            tenant_id: &request.binding.tenant_id,
            actor: &request.binding.actor,
            occurred_at: request.binding.occurred_at,
            sequence: request.binding.sequence,
            kind: request.content.kind,
            subject: &request.content.subject,
            reason_code: &request.content.reason_code,
            payload_digest: request.content.payload_digest,
            previous_chain_digest: request.content.previous_chain_digest,
        }
    }

    fn from_event(event: &'a AuditEvent) -> Self {
        Self {
            id: &event.id,
            tenant_id: &event.tenant_id,
            actor: &event.actor,
            occurred_at: event.occurred_at,
            sequence: event.sequence,
            kind: event.kind,
            subject: &event.subject,
            reason_code: &event.reason_code,
            payload_digest: event.payload_digest,
            previous_chain_digest: event.previous_chain_digest,
        }
    }
}

fn compute_chain_digest(input: ChainDigestMaterial<'_>) -> AuditChainDigest {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(input.id.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(input.tenant_id.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(input.actor.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&input.occurred_at.unix_seconds().to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&input.sequence.get().to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(kind_label(input.kind).as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(subject_kind_label(input.subject.kind()).as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&input.subject.digest().bytes());
    bytes.push(0);
    bytes.extend_from_slice(input.reason_code.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&input.payload_digest.bytes());
    bytes.push(0);
    match input.previous_chain_digest {
        Some(previous) => bytes.extend_from_slice(&previous.bytes()),
        None => bytes.extend_from_slice(&[0_u8; 32]),
    }
    AuditChainDigest::from_material(&bytes)
}

fn parse_reason_code(value: &str) -> Result<Box<str>, AuditError> {
    if !valid_reason_code(value) {
        return Err(error(AuditErrorCode::InvalidArgument));
    }
    Ok(value.into())
}

fn valid_reason_code(value: &str) -> bool {
    valid_reason_bounds(value) && value.bytes().all(valid_reason_byte)
}

fn valid_reason_bounds(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REASON_BYTES && value.is_ascii()
}

fn valid_reason_byte(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
}

fn kind_label(kind: AuditEventKind) -> &'static str {
    match kind {
        AuditEventKind::Issued => "issued",
        AuditEventKind::Consumed => "consumed",
        AuditEventKind::Rotated => "rotated",
        AuditEventKind::Revoked => "revoked",
        AuditEventKind::Expired => "expired",
        AuditEventKind::ReuseDetected => "reuse_detected",
        AuditEventKind::Administered => "administered",
    }
}

fn subject_kind_label(kind: AuditSubjectKind) -> &'static str {
    match kind {
        AuditSubjectKind::User => "user",
        AuditSubjectKind::Organization => "organization",
        AuditSubjectKind::Invitation => "invitation",
        AuditSubjectKind::SessionFamily => "session_family",
        AuditSubjectKind::ApiKey => "api_key",
        AuditSubjectKind::PasswordReset => "password_reset",
        AuditSubjectKind::Administration => "administration",
    }
}

fn domain_separated_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

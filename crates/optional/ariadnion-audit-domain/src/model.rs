//! Immutable auditable security-event model.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, TenantId};
use ariadnion_user_domain::UtcTimestamp;
use sha2::{Digest, Sha256};

use crate::error::error;
use crate::{AuditError, AuditErrorCode, AuditEventId, AuditSequence};

/// Maximum accepted reason code length in bytes.
pub const MAX_REASON_BYTES: usize = 64;

const PAYLOAD_DOMAIN: &[u8] = b"ariadnion.audit.payload.v1\0";
const CHAIN_DOMAIN: &[u8] = b"ariadnion.audit.chain.v1\0";

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

/// Redacted subject identity retained for audit correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditSubject {
    kind: AuditSubjectKind,
    id: Box<str>,
}

impl AuditSubject {
    /// Creates a redacted subject identity.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorCode::InvalidArgument`] without retaining rejected input.
    pub fn new(kind: AuditSubjectKind, id: &str) -> Result<Self, AuditError> {
        if !valid_subject_id(id) {
            return Err(error(AuditErrorCode::InvalidArgument));
        }
        Ok(Self {
            kind,
            id: id.into(),
        })
    }

    /// Returns the subject category.
    #[must_use]
    pub const fn kind(&self) -> AuditSubjectKind {
        self.kind
    }

    /// Returns the redacted subject identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
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

    /// Digests adapter-canonical payload bytes without retaining them.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Self {
        Self(domain_separated_digest(PAYLOAD_DOMAIN, payload))
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
    pub fn from_material(material: &[u8]) -> Self {
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

    /// Returns the current chain digest.
    #[must_use]
    pub const fn chain_digest(&self) -> AuditChainDigest {
        self.chain_digest
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
/// The chain digest covers event id, tenant, actor, sequence, kind, subject,
/// reason code, payload digest, and optional previous chain digest. Adapters
/// must append events in sequence order and reject broken chains.
///
/// # Errors
///
/// Returns stable redacted failures only through request construction.
pub fn build_audit_event(request: AuditEventRequest) -> Result<AuditEvent, AuditError> {
    let chain_digest = compute_chain_digest(&request);
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
        chain_digest,
    })
}

fn compute_chain_digest(request: &AuditEventRequest) -> AuditChainDigest {
    let mut material = Vec::with_capacity(256);
    material.extend_from_slice(request.binding.id.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(request.binding.tenant_id.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(request.binding.actor.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(&request.binding.sequence.get().to_be_bytes());
    material.push(0);
    material.extend_from_slice(kind_label(request.content.kind).as_bytes());
    material.push(0);
    material.extend_from_slice(subject_kind_label(request.content.subject.kind()).as_bytes());
    material.push(0);
    material.extend_from_slice(request.content.subject.id().as_bytes());
    material.push(0);
    material.extend_from_slice(request.content.reason_code.as_bytes());
    material.push(0);
    material.extend_from_slice(&request.content.payload_digest.bytes());
    material.push(0);
    match request.content.previous_chain_digest {
        Some(previous) => material.extend_from_slice(&previous.bytes()),
        None => material.extend_from_slice(&[0_u8; 32]),
    }
    AuditChainDigest::from_material(&material)
}

fn parse_reason_code(value: &str) -> Result<Box<str>, AuditError> {
    if value.is_empty()
        || value.len() > MAX_REASON_BYTES
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(error(AuditErrorCode::InvalidArgument));
    }
    Ok(value.into())
}

fn valid_subject_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
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

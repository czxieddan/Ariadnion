// crates/optional/ariadnion-principal-binding/src/model.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Durable principal-binding state, snapshots, commitments, and events.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalContext, PrincipalId, RequestId, TenantId};
use ariadnion_organization::{MembershipId, OrganizationId};
use ariadnion_user_domain::{UserId, UtcTimestamp};
use sha2::{Digest, Sha256};

use crate::error::{PrincipalBindingError, PrincipalBindingErrorCode, error};
use crate::ids::PrincipalBindingVersion;

const SUBJECT_COMMITMENT_DOMAIN: &[u8] = b"ariadnion.principal-binding.subject.v1";

/// Direct subject identities bound to one authenticated principal.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalBindingIdentity {
    principal: PrincipalContext,
    user_id: UserId,
    organization_id: OrganizationId,
    membership_id: MembershipId,
}

impl PrincipalBindingIdentity {
    /// Creates a direct identity tuple after checking its exact durable key.
    ///
    /// A principal is an independently issued authentication identity. This
    /// constructor never derives it from the user, membership, session, or API
    /// key identities supplied by other boundaries.
    ///
    /// # Errors
    /// Returns a stable mismatch code when the authenticated tenant or principal
    /// differs from the exact durable key supplied by the caller.
    pub fn new(
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        principal: PrincipalContext,
        user_id: UserId,
        organization_id: OrganizationId,
        membership_id: MembershipId,
    ) -> Result<Self, PrincipalBindingError> {
        validate_principal_boundary(tenant_id, principal_id, &principal)?;
        Ok(Self {
            principal,
            user_id,
            organization_id,
            membership_id,
        })
    }

    /// Returns the independently authenticated principal context.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalContext {
        &self.principal
    }

    /// Returns the durable user aggregate identity.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the selected organization identity.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the selected membership identity.
    #[must_use]
    pub const fn membership_id(&self) -> &MembershipId {
        &self.membership_id
    }

    pub(crate) fn validate_key(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
    ) -> Result<(), PrincipalBindingError> {
        validate_principal_boundary(tenant_id, principal_id, &self.principal)
    }
}

impl Debug for PrincipalBindingIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalBindingIdentity(<redacted>)")
    }
}

fn validate_principal_boundary(
    tenant_id: &TenantId,
    principal_id: &PrincipalId,
    principal: &PrincipalContext,
) -> Result<(), PrincipalBindingError> {
    if principal.tenant_id() != tenant_id {
        return Err(error(PrincipalBindingErrorCode::TenantMismatch));
    }
    if principal.principal_id() != principal_id {
        return Err(error(PrincipalBindingErrorCode::PrincipalMismatch));
    }
    Ok(())
}

/// A fixed SHA-256 commitment to the direct subject tuple.
///
/// This unkeyed digest is sensitive pseudonymous correlation evidence, not an
/// anonymization mechanism. Anyone who knows or guesses a candidate tuple can
/// derive it offline and compare the result. Callers must apply the same access,
/// logging, export, and retention controls used for other linkable identity data.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SubjectCommitment([u8; 32]);

impl SubjectCommitment {
    /// Derives the commitment using a domain tag and length-prefixed UTF-8 fields.
    ///
    /// Fields are committed in tenant, principal, user, organization, and
    /// membership order. The explicit tag and big-endian `u64` lengths prevent
    /// ambiguity and cross-protocol reuse.
    #[must_use]
    pub fn derive(identity: &PrincipalBindingIdentity) -> Self {
        let mut digest = Sha256::new();
        append_field(&mut digest, SUBJECT_COMMITMENT_DOMAIN);
        append_field(
            &mut digest,
            identity.principal().tenant_id().as_str().as_bytes(),
        );
        append_field(
            &mut digest,
            identity.principal().principal_id().as_str().as_bytes(),
        );
        append_field(&mut digest, identity.user_id().as_str().as_bytes());
        append_field(&mut digest, identity.organization_id().as_str().as_bytes());
        append_field(&mut digest, identity.membership_id().as_str().as_bytes());
        Self(digest.finalize().into())
    }

    /// Restores a fixed commitment from trusted-width durable bytes.
    ///
    /// Active and revoked snapshot rehydration recomputes and checks these bytes.
    /// Erased snapshots retain them as sensitive pseudonymous correlation
    /// evidence. Removing direct identifiers does not make retained records
    /// anonymous, and known candidate tuples remain testable offline.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed bytes for durable hexadecimal encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Debug for SubjectCommitment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubjectCommitment(<redacted>)")
    }
}

fn append_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// Durable lifecycle of one principal binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalBindingState {
    /// Direct subject identities may be used by authorized identity workflows.
    Active,
    /// Authentication reuse is forbidden while direct identifiers await erasure.
    Revoked,
    /// Direct identifiers have been destroyed and the principal key is terminal.
    Erased,
}

/// Persisted snapshot fields supplied to snapshot rehydration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalBindingSnapshotData {
    /// Exact tenant key.
    pub tenant_id: TenantId,
    /// Exact independently issued principal key.
    pub principal_id: PrincipalId,
    /// Commitment retained across every lifecycle state.
    pub subject_commitment: SubjectCommitment,
    /// Exact optimistic version.
    pub version: PrincipalBindingVersion,
    /// Persisted lifecycle state.
    pub state: PrincipalBindingState,
    /// Direct tuple retained only while active or revoked.
    pub identity: Option<PrincipalBindingIdentity>,
    /// Trusted initial provisioning time.
    pub provisioned_at: UtcTimestamp,
    /// Trusted revocation time, when revocation occurred.
    pub revoked_at: Option<UtcTimestamp>,
    /// Trusted erasure time, when direct identifiers were destroyed.
    pub erased_at: Option<UtcTimestamp>,
}

/// An untrusted durable representation validated during aggregate rehydration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalBindingSnapshot(PrincipalBindingSnapshotData);

impl PrincipalBindingSnapshot {
    /// Wraps durable fields without treating them as validated aggregate state.
    #[must_use]
    pub const fn new(data: PrincipalBindingSnapshotData) -> Self {
        Self(data)
    }

    /// Returns the exact tenant key.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.0.tenant_id
    }

    /// Returns the exact independently issued principal key.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.0.principal_id
    }

    /// Returns the retained subject commitment.
    #[must_use]
    pub const fn subject_commitment(&self) -> &SubjectCommitment {
        &self.0.subject_commitment
    }

    /// Returns the optimistic aggregate version.
    #[must_use]
    pub const fn version(&self) -> PrincipalBindingVersion {
        self.0.version
    }

    /// Returns the persisted lifecycle state.
    #[must_use]
    pub const fn state(&self) -> PrincipalBindingState {
        self.0.state
    }

    /// Returns the complete direct subject tuple, when retained.
    #[must_use]
    pub const fn identity(&self) -> Option<&PrincipalBindingIdentity> {
        self.0.identity.as_ref()
    }

    /// Returns the trusted provisioning time.
    #[must_use]
    pub const fn provisioned_at(&self) -> UtcTimestamp {
        self.0.provisioned_at
    }

    /// Returns the trusted revocation time, when present.
    #[must_use]
    pub const fn revoked_at(&self) -> Option<UtcTimestamp> {
        self.0.revoked_at
    }

    /// Returns the trusted erasure time, when present.
    #[must_use]
    pub const fn erased_at(&self) -> Option<UtcTimestamp> {
        self.0.erased_at
    }
}

/// A validated tenant-bound durable principal binding.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalBinding {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    subject_commitment: SubjectCommitment,
    version: PrincipalBindingVersion,
    state: PrincipalBindingState,
    identity: Option<PrincipalBindingIdentity>,
    provisioned_at: UtcTimestamp,
    revoked_at: Option<UtcTimestamp>,
    erased_at: Option<UtcTimestamp>,
}

impl PrincipalBinding {
    /// Rehydrates a snapshot only when its lifecycle, key, and commitment agree.
    ///
    /// # Errors
    /// Returns a stable mismatch or malformed-snapshot code. Active and revoked
    /// snapshots recompute the direct subject commitment. Erased snapshots must
    /// contain no direct subject tuple and retain only the commitment.
    pub fn rehydrate(snapshot: PrincipalBindingSnapshot) -> Result<Self, PrincipalBindingError> {
        validate_snapshot(&snapshot.0)?;
        let data = snapshot.0;
        Ok(Self {
            tenant_id: data.tenant_id,
            principal_id: data.principal_id,
            subject_commitment: data.subject_commitment,
            version: data.version,
            state: data.state,
            identity: data.identity,
            provisioned_at: data.provisioned_at,
            revoked_at: data.revoked_at,
            erased_at: data.erased_at,
        })
    }

    /// Returns an exact durable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PrincipalBindingSnapshot {
        PrincipalBindingSnapshot::new(PrincipalBindingSnapshotData {
            tenant_id: self.tenant_id.clone(),
            principal_id: self.principal_id.clone(),
            subject_commitment: self.subject_commitment,
            version: self.version,
            state: self.state,
            identity: self.identity.clone(),
            provisioned_at: self.provisioned_at,
            revoked_at: self.revoked_at,
            erased_at: self.erased_at,
        })
    }

    /// Returns the tenant key retained in every state.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the independently issued principal key retained in every state.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the subject commitment retained in every state.
    #[must_use]
    pub const fn subject_commitment(&self) -> &SubjectCommitment {
        &self.subject_commitment
    }

    /// Returns the optimistic aggregate version.
    #[must_use]
    pub const fn version(&self) -> PrincipalBindingVersion {
        self.version
    }

    /// Returns the durable lifecycle state.
    #[must_use]
    pub const fn state(&self) -> PrincipalBindingState {
        self.state
    }

    /// Returns direct subject fields only while active or revoked.
    #[must_use]
    pub const fn identity(&self) -> Option<&PrincipalBindingIdentity> {
        self.identity.as_ref()
    }

    /// Returns the trusted provisioning time.
    #[must_use]
    pub const fn provisioned_at(&self) -> UtcTimestamp {
        self.provisioned_at
    }

    /// Returns the trusted revocation time, when present.
    #[must_use]
    pub const fn revoked_at(&self) -> Option<UtcTimestamp> {
        self.revoked_at
    }

    /// Returns the trusted erasure time, when present.
    #[must_use]
    pub const fn erased_at(&self) -> Option<UtcTimestamp> {
        self.erased_at
    }

    pub(crate) fn from_validated_parts(data: PrincipalBindingSnapshotData) -> Self {
        Self {
            tenant_id: data.tenant_id,
            principal_id: data.principal_id,
            subject_commitment: data.subject_commitment,
            version: data.version,
            state: data.state,
            identity: data.identity,
            provisioned_at: data.provisioned_at,
            revoked_at: data.revoked_at,
            erased_at: data.erased_at,
        }
    }
}

impl Debug for PrincipalBinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalBinding")
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("subject_commitment", &self.subject_commitment)
            .field("version", &self.version)
            .field("state", &self.state)
            .field("identity", &self.identity.as_ref().map(|_| "<redacted>"))
            .field("provisioned_at", &self.provisioned_at)
            .field("revoked_at", &self.revoked_at)
            .field("erased_at", &self.erased_at)
            .finish()
    }
}

fn validate_snapshot(data: &PrincipalBindingSnapshotData) -> Result<(), PrincipalBindingError> {
    validate_state_shape(data)?;
    validate_snapshot_times(data)?;
    if let Some(identity) = data.identity.as_ref() {
        identity.validate_key(&data.tenant_id, &data.principal_id)?;
        validate_commitment(identity, data.subject_commitment)?;
    }
    Ok(())
}

fn validate_state_shape(data: &PrincipalBindingSnapshotData) -> Result<(), PrincipalBindingError> {
    let valid = match data.state {
        PrincipalBindingState::Active => active_shape(data),
        PrincipalBindingState::Revoked => revoked_shape(data),
        PrincipalBindingState::Erased => erased_shape(data),
    };
    if !valid {
        return Err(error(PrincipalBindingErrorCode::InvalidSnapshot));
    }
    Ok(())
}

fn active_shape(data: &PrincipalBindingSnapshotData) -> bool {
    data.version == PrincipalBindingVersion::initial()
        && data.identity.is_some()
        && data.revoked_at.is_none()
        && data.erased_at.is_none()
}

fn revoked_shape(data: &PrincipalBindingSnapshotData) -> bool {
    data.version.get() == 2
        && data.identity.is_some()
        && data.revoked_at.is_some()
        && data.erased_at.is_none()
}

fn erased_shape(data: &PrincipalBindingSnapshotData) -> bool {
    data.version.get() == 3
        && data.identity.is_none()
        && data.revoked_at.is_some()
        && data.erased_at.is_some()
}

fn validate_snapshot_times(
    data: &PrincipalBindingSnapshotData,
) -> Result<(), PrincipalBindingError> {
    if data
        .revoked_at
        .is_some_and(|value| value < data.provisioned_at)
    {
        return Err(error(PrincipalBindingErrorCode::TimestampRegression));
    }
    if data
        .erased_at
        .is_some_and(|value| data.revoked_at.is_none_or(|revoked_at| value < revoked_at))
    {
        return Err(error(PrincipalBindingErrorCode::TimestampRegression));
    }
    Ok(())
}

fn validate_commitment(
    identity: &PrincipalBindingIdentity,
    commitment: SubjectCommitment,
) -> Result<(), PrincipalBindingError> {
    if SubjectCommitment::derive(identity) != commitment {
        return Err(error(PrincipalBindingErrorCode::CommitmentMismatch));
    }
    Ok(())
}

/// Immutable event kinds for the only legal principal-binding lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalBindingEventKind {
    /// A new independently issued principal was durably bound.
    Provisioned,
    /// Authentication reuse was terminally revoked.
    Revoked,
    /// Direct user, organization, and membership identifiers were destroyed.
    Erased,
}

/// Persisted event facts that intentionally omit direct subject identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalBindingEventData {
    /// Exact tenant key.
    pub tenant_id: TenantId,
    /// Exact independently issued principal key.
    pub principal_id: PrincipalId,
    /// Exact lifecycle version.
    pub version: PrincipalBindingVersion,
    /// Persisted event kind.
    pub kind: PrincipalBindingEventKind,
    /// Trusted event occurrence time.
    pub occurred_at: UtcTimestamp,
    /// Authenticated actor attributed to the change.
    pub actor: PrincipalId,
    /// Request correlation identity.
    pub request_id: RequestId,
    /// Sensitive pseudonymous subject commitment.
    pub subject_commitment: SubjectCommitment,
}

/// Audit event that deliberately excludes all direct subject identifiers.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalBindingEvent {
    pub(crate) tenant_id: TenantId,
    pub(crate) principal_id: PrincipalId,
    pub(crate) version: PrincipalBindingVersion,
    pub(crate) kind: PrincipalBindingEventKind,
    pub(crate) occurred_at: UtcTimestamp,
    pub(crate) actor: PrincipalId,
    pub(crate) request_id: RequestId,
    pub(crate) subject_commitment: SubjectCommitment,
}

impl PrincipalBindingEvent {
    /// Rehydrates immutable event facts after validating lifecycle continuity.
    ///
    /// # Errors
    /// Returns [`PrincipalBindingErrorCode::InvalidEvent`] when the persisted
    /// kind does not carry its exact legal lifecycle version.
    pub fn rehydrate(data: PrincipalBindingEventData) -> Result<Self, PrincipalBindingError> {
        validate_event_version(data.kind, data.version)?;
        Ok(Self {
            tenant_id: data.tenant_id,
            principal_id: data.principal_id,
            version: data.version,
            kind: data.kind,
            occurred_at: data.occurred_at,
            actor: data.actor,
            request_id: data.request_id,
            subject_commitment: data.subject_commitment,
        })
    }

    /// Returns the exact tenant key.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the exact independently issued principal key.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the event version.
    #[must_use]
    pub const fn version(&self) -> PrincipalBindingVersion {
        self.version
    }

    /// Returns the lifecycle event kind.
    #[must_use]
    pub const fn kind(&self) -> PrincipalBindingEventKind {
        self.kind
    }

    /// Returns the trusted occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the authenticated actor attributed to the transition.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the request correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the sensitive pseudonymous subject commitment.
    #[must_use]
    pub const fn subject_commitment(&self) -> &SubjectCommitment {
        &self.subject_commitment
    }
}

fn validate_event_version(
    kind: PrincipalBindingEventKind,
    version: PrincipalBindingVersion,
) -> Result<(), PrincipalBindingError> {
    let expected = match kind {
        PrincipalBindingEventKind::Provisioned => 1,
        PrincipalBindingEventKind::Revoked => 2,
        PrincipalBindingEventKind::Erased => 3,
    };
    if version.get() != expected {
        return Err(error(PrincipalBindingErrorCode::InvalidEvent));
    }
    Ok(())
}

impl Debug for PrincipalBindingEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalBindingEvent")
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("occurred_at", &self.occurred_at)
            .field("actor", &self.actor)
            .field("request_id", &self.request_id)
            .field("subject_commitment", &self.subject_commitment)
            .finish()
    }
}

/// One validated aggregate and its exact immutable event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalBindingTransition {
    pub(crate) previous_version: Option<PrincipalBindingVersion>,
    pub(crate) previous_snapshot: Option<PrincipalBindingSnapshot>,
    pub(crate) binding: PrincipalBinding,
    pub(crate) event: PrincipalBindingEvent,
}

impl PrincipalBindingTransition {
    /// Returns the expected previous version used by compare-and-commit.
    #[must_use]
    pub const fn expected_previous_version(&self) -> Option<PrincipalBindingVersion> {
        self.previous_version
    }

    /// Returns the exact tenant key for persistence routing.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.binding.tenant_id()
    }

    /// Returns the exact principal key for persistence routing.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        self.binding.principal_id()
    }

    /// Returns the validated previous snapshot, or `None` for provisioning.
    #[must_use]
    pub const fn previous_snapshot(&self) -> Option<&PrincipalBindingSnapshot> {
        self.previous_snapshot.as_ref()
    }

    /// Returns an exact new snapshot for atomic persistence.
    #[must_use]
    pub fn new_snapshot(&self) -> PrincipalBindingSnapshot {
        self.binding.snapshot()
    }

    /// Returns the new aggregate state.
    #[must_use]
    pub const fn binding(&self) -> &PrincipalBinding {
        &self.binding
    }

    /// Consumes the transition and returns the new aggregate.
    #[must_use]
    pub fn into_binding(self) -> PrincipalBinding {
        self.binding
    }

    /// Returns the exact immutable event.
    #[must_use]
    pub const fn event(&self) -> &PrincipalBindingEvent {
        &self.event
    }
}

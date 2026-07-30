// crates/optional/ariadnion-principal-binding/src/authenticator_model.rs - Rust source for Ariadnion.
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
//! Immutable snapshots, events, and transitions for authenticator links.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, RequestId, TenantId};
use ariadnion_user_domain::UtcTimestamp;

use crate::PrincipalBindingVersion;
use crate::authenticator_error::{
    PrincipalAuthenticatorError, PrincipalAuthenticatorErrorCode, authenticator_error,
};
use crate::authenticator_ids::{
    PrincipalAuthenticatorId, PrincipalAuthenticatorKind, PrincipalAuthenticatorSourceCommitment,
    PrincipalAuthenticatorSourceId, PrincipalAuthenticatorVersion,
};

/// The terminal lifecycle state of an immutable authenticator link.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalAuthenticatorState {
    /// The exact authenticator may produce authentication evidence.
    Active,
    /// The source key remains occupied but cannot authenticate again.
    Revoked,
}

/// Untrusted durable fields used to rehydrate one authenticator snapshot.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalAuthenticatorSnapshotData {
    /// Tenant that permanently owns this source key.
    pub tenant_id: TenantId,
    /// Deterministic tenant/kind/source identifier.
    pub authenticator_id: PrincipalAuthenticatorId,
    /// Exhaustive authenticator kind.
    pub authenticator_kind: PrincipalAuthenticatorKind,
    /// Immutable opaque source identifier.
    pub source_id: PrincipalAuthenticatorSourceId,
    /// Immutable linked principal.
    pub principal_id: PrincipalId,
    /// Active principal-binding version present when the link was created.
    pub principal_binding_version: PrincipalBindingVersion,
    /// Non-zero optimistic authenticator-link version.
    pub version: PrincipalAuthenticatorVersion,
    /// Active or terminal revoked state.
    pub state: PrincipalAuthenticatorState,
    /// UTC time at which the immutable link was created.
    pub linked_at: UtcTimestamp,
    /// UTC revocation time, present only for the terminal state.
    pub revoked_at: Option<UtcTimestamp>,
}

impl Debug for PrincipalAuthenticatorSnapshotData {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorSnapshotData(<redacted>)")
    }
}

/// An immutable untrusted snapshot envelope for repository decoding.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalAuthenticatorSnapshot(PrincipalAuthenticatorSnapshotData);

impl PrincipalAuthenticatorSnapshot {
    /// Wraps untrusted durable fields without asserting that they are valid.
    ///
    /// Pass the result to [`PrincipalAuthenticatorLink::rehydrate`] before use.
    #[must_use]
    pub const fn new(data: PrincipalAuthenticatorSnapshotData) -> Self {
        Self(data)
    }

    /// Returns the tenant key.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.0.tenant_id
    }

    /// Returns the deterministic authenticator key.
    #[must_use]
    pub const fn authenticator_id(&self) -> &PrincipalAuthenticatorId {
        &self.0.authenticator_id
    }

    /// Returns the exhaustive authenticator kind.
    #[must_use]
    pub const fn authenticator_kind(&self) -> PrincipalAuthenticatorKind {
        self.0.authenticator_kind
    }

    /// Returns the opaque source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &PrincipalAuthenticatorSourceId {
        &self.0.source_id
    }

    /// Returns the immutable principal key.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.0.principal_id
    }

    /// Returns the principal-binding version fixed when this link was created.
    #[must_use]
    pub const fn principal_binding_version(&self) -> PrincipalBindingVersion {
        self.0.principal_binding_version
    }

    /// Returns the current link version.
    #[must_use]
    pub const fn version(&self) -> PrincipalAuthenticatorVersion {
        self.0.version
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> PrincipalAuthenticatorState {
        self.0.state
    }

    /// Returns the immutable link time.
    #[must_use]
    pub const fn linked_at(&self) -> UtcTimestamp {
        self.0.linked_at
    }

    /// Returns the terminal revocation time when present.
    #[must_use]
    pub const fn revoked_at(&self) -> Option<UtcTimestamp> {
        self.0.revoked_at
    }
}

impl Debug for PrincipalAuthenticatorSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorSnapshot(<redacted>)")
    }
}

/// A validated immutable source-to-principal link aggregate.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalAuthenticatorLink {
    tenant_id: TenantId,
    authenticator_id: PrincipalAuthenticatorId,
    authenticator_kind: PrincipalAuthenticatorKind,
    source_id: PrincipalAuthenticatorSourceId,
    principal_id: PrincipalId,
    principal_binding_version: PrincipalBindingVersion,
    version: PrincipalAuthenticatorVersion,
    state: PrincipalAuthenticatorState,
    linked_at: UtcTimestamp,
    revoked_at: Option<UtcTimestamp>,
}

impl PrincipalAuthenticatorLink {
    /// Rehydrates a snapshot after checking derived identity and lifecycle invariants.
    ///
    /// # Errors
    /// Returns a stable redacted error if the derived ID, state/version pairing,
    /// or timestamp shape is inconsistent. Stored identifiers are never included.
    pub fn rehydrate(
        snapshot: PrincipalAuthenticatorSnapshot,
    ) -> Result<Self, PrincipalAuthenticatorError> {
        validate_snapshot(&snapshot.0)?;
        Ok(Self::from_validated_parts(snapshot.0))
    }

    pub(crate) fn from_validated_parts(data: PrincipalAuthenticatorSnapshotData) -> Self {
        Self {
            tenant_id: data.tenant_id,
            authenticator_id: data.authenticator_id,
            authenticator_kind: data.authenticator_kind,
            source_id: data.source_id,
            principal_id: data.principal_id,
            principal_binding_version: data.principal_binding_version,
            version: data.version,
            state: data.state,
            linked_at: data.linked_at,
            revoked_at: data.revoked_at,
        }
    }

    /// Returns a complete immutable snapshot of the aggregate.
    #[must_use]
    pub fn snapshot(&self) -> PrincipalAuthenticatorSnapshot {
        PrincipalAuthenticatorSnapshot(PrincipalAuthenticatorSnapshotData {
            tenant_id: self.tenant_id.clone(),
            authenticator_id: self.authenticator_id.clone(),
            authenticator_kind: self.authenticator_kind,
            source_id: self.source_id.clone(),
            principal_id: self.principal_id.clone(),
            principal_binding_version: self.principal_binding_version,
            version: self.version,
            state: self.state,
            linked_at: self.linked_at,
            revoked_at: self.revoked_at,
        })
    }

    /// Returns the immutable tenant key.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the deterministic authenticator key.
    #[must_use]
    pub const fn authenticator_id(&self) -> &PrincipalAuthenticatorId {
        &self.authenticator_id
    }

    /// Returns the exhaustive authenticator kind.
    #[must_use]
    pub const fn kind(&self) -> PrincipalAuthenticatorKind {
        self.authenticator_kind
    }

    /// Returns the immutable opaque source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &PrincipalAuthenticatorSourceId {
        &self.source_id
    }

    /// Returns the immutable linked principal.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the immutable principal-binding version.
    #[must_use]
    pub const fn principal_binding_version(&self) -> PrincipalBindingVersion {
        self.principal_binding_version
    }

    /// Returns the current non-zero link version.
    #[must_use]
    pub const fn version(&self) -> PrincipalAuthenticatorVersion {
        self.version
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> PrincipalAuthenticatorState {
        self.state
    }

    /// Returns the immutable link time.
    #[must_use]
    pub const fn linked_at(&self) -> UtcTimestamp {
        self.linked_at
    }

    /// Returns the terminal revocation time when present.
    #[must_use]
    pub const fn revoked_at(&self) -> Option<UtcTimestamp> {
        self.revoked_at
    }
}

impl Debug for PrincipalAuthenticatorLink {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorLink(<redacted>)")
    }
}

fn validate_snapshot(
    data: &PrincipalAuthenticatorSnapshotData,
) -> Result<(), PrincipalAuthenticatorError> {
    let expected_id =
        PrincipalAuthenticatorId::derive(&data.tenant_id, data.authenticator_kind, &data.source_id);
    if data.authenticator_id != expected_id {
        return Err(authenticator_error(
            PrincipalAuthenticatorErrorCode::InvalidSnapshot,
        ));
    }
    validate_snapshot_lifecycle(data)
}

fn validate_snapshot_lifecycle(
    data: &PrincipalAuthenticatorSnapshotData,
) -> Result<(), PrincipalAuthenticatorError> {
    let valid = match data.state {
        PrincipalAuthenticatorState::Active => {
            data.version == PrincipalAuthenticatorVersion::initial() && data.revoked_at.is_none()
        }
        PrincipalAuthenticatorState::Revoked => {
            data.version.get() == 2 && data.revoked_at.is_some_and(|time| time >= data.linked_at)
        }
    };
    if valid {
        return Ok(());
    }
    Err(authenticator_error(
        PrincipalAuthenticatorErrorCode::InvalidSnapshot,
    ))
}

/// The exhaustive kind of immutable authenticator-link event.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalAuthenticatorEventKind {
    /// The source was linked to its immutable principal.
    Linked,
    /// The exact source was terminally revoked.
    Revoked,
}

/// Untrusted durable fields used to rehydrate one immutable event.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalAuthenticatorEventData {
    /// Tenant that owns the event.
    pub tenant_id: TenantId,
    /// Deterministic aggregate identifier.
    pub authenticator_id: PrincipalAuthenticatorId,
    /// Exhaustive authenticator kind.
    pub authenticator_kind: PrincipalAuthenticatorKind,
    /// Domain-separated source commitment; raw source identifiers are excluded.
    pub source_commitment: PrincipalAuthenticatorSourceCommitment,
    /// Immutable linked principal.
    pub principal_id: PrincipalId,
    /// Immutable principal-binding version.
    pub principal_binding_version: PrincipalBindingVersion,
    /// Aggregate version produced by this event.
    pub version: PrincipalAuthenticatorVersion,
    /// Immutable event kind.
    pub kind: PrincipalAuthenticatorEventKind,
    /// UTC event time.
    pub occurred_at: UtcTimestamp,
    /// Principal that authorized the transition.
    pub actor: PrincipalId,
    /// Request that caused the transition.
    pub request_id: RequestId,
}

impl Debug for PrincipalAuthenticatorEventData {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorEventData(<redacted>)")
    }
}

/// A validated immutable authenticator-link event.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalAuthenticatorEvent {
    tenant_id: TenantId,
    authenticator_id: PrincipalAuthenticatorId,
    authenticator_kind: PrincipalAuthenticatorKind,
    source_commitment: PrincipalAuthenticatorSourceCommitment,
    principal_id: PrincipalId,
    principal_binding_version: PrincipalBindingVersion,
    version: PrincipalAuthenticatorVersion,
    kind: PrincipalAuthenticatorEventKind,
    occurred_at: UtcTimestamp,
    actor: PrincipalId,
    request_id: RequestId,
}

impl PrincipalAuthenticatorEvent {
    /// Rehydrates an immutable event after validating its kind/version pairing.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::InvalidEvent`] for a malformed
    /// event. Use [`Self::validate_against`] to check exact aggregate binding.
    pub fn rehydrate(
        data: PrincipalAuthenticatorEventData,
    ) -> Result<Self, PrincipalAuthenticatorError> {
        validate_event_version(data.kind, data.version)?;
        Ok(Self::from_validated_parts(data))
    }

    pub(crate) fn from_validated_parts(data: PrincipalAuthenticatorEventData) -> Self {
        Self {
            tenant_id: data.tenant_id,
            authenticator_id: data.authenticator_id,
            authenticator_kind: data.authenticator_kind,
            source_commitment: data.source_commitment,
            principal_id: data.principal_id,
            principal_binding_version: data.principal_binding_version,
            version: data.version,
            kind: data.kind,
            occurred_at: data.occurred_at,
            actor: data.actor,
            request_id: data.request_id,
        }
    }

    /// Validates that this event describes the exact target snapshot.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::InvalidEvent`] on any key,
    /// source commitment, principal, version, state, or timestamp divergence.
    pub fn validate_against(
        &self,
        snapshot: &PrincipalAuthenticatorSnapshot,
    ) -> Result<(), PrincipalAuthenticatorError> {
        validate_snapshot(&snapshot.0)
            .map_err(|_| authenticator_error(PrincipalAuthenticatorErrorCode::InvalidEvent))?;
        if !self.matches_snapshot_identity(snapshot) || !self.matches_snapshot_lifecycle(snapshot) {
            return Err(authenticator_error(
                PrincipalAuthenticatorErrorCode::InvalidEvent,
            ));
        }
        Ok(())
    }

    fn matches_snapshot_identity(&self, snapshot: &PrincipalAuthenticatorSnapshot) -> bool {
        self.tenant_id == *snapshot.tenant_id()
            && self.authenticator_id == *snapshot.authenticator_id()
            && self.authenticator_kind == snapshot.authenticator_kind()
            && self.principal_id == *snapshot.principal_id()
            && self.principal_binding_version == snapshot.principal_binding_version()
            && self.source_commitment
                == PrincipalAuthenticatorSourceCommitment::derive(
                    snapshot.tenant_id(),
                    snapshot.authenticator_kind(),
                    snapshot.source_id(),
                )
    }

    fn matches_snapshot_lifecycle(&self, snapshot: &PrincipalAuthenticatorSnapshot) -> bool {
        if self.version != snapshot.version() {
            return false;
        }
        match self.kind {
            PrincipalAuthenticatorEventKind::Linked => {
                snapshot.state() == PrincipalAuthenticatorState::Active
                    && self.occurred_at == snapshot.linked_at()
            }
            PrincipalAuthenticatorEventKind::Revoked => {
                snapshot.state() == PrincipalAuthenticatorState::Revoked
                    && snapshot.revoked_at() == Some(self.occurred_at)
            }
        }
    }

    /// Returns the tenant key.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the deterministic aggregate identifier.
    #[must_use]
    pub const fn authenticator_id(&self) -> &PrincipalAuthenticatorId {
        &self.authenticator_id
    }

    /// Returns the exhaustive authenticator kind.
    #[must_use]
    pub const fn authenticator_kind(&self) -> PrincipalAuthenticatorKind {
        self.authenticator_kind
    }

    /// Returns the domain-separated source commitment.
    #[must_use]
    pub const fn source_commitment(&self) -> &PrincipalAuthenticatorSourceCommitment {
        &self.source_commitment
    }

    /// Returns the immutable linked principal.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the immutable principal-binding version.
    #[must_use]
    pub const fn principal_binding_version(&self) -> PrincipalBindingVersion {
        self.principal_binding_version
    }

    /// Returns the aggregate version produced by this event.
    #[must_use]
    pub const fn version(&self) -> PrincipalAuthenticatorVersion {
        self.version
    }

    /// Returns the immutable event kind.
    #[must_use]
    pub const fn kind(&self) -> PrincipalAuthenticatorEventKind {
        self.kind
    }

    /// Returns the UTC event time.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }

    /// Returns the principal that authorized the transition.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the request that caused the transition.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
}

impl Debug for PrincipalAuthenticatorEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorEvent(<redacted>)")
    }
}

fn validate_event_version(
    kind: PrincipalAuthenticatorEventKind,
    version: PrincipalAuthenticatorVersion,
) -> Result<(), PrincipalAuthenticatorError> {
    let valid = match kind {
        PrincipalAuthenticatorEventKind::Linked => {
            version == PrincipalAuthenticatorVersion::initial()
        }
        PrincipalAuthenticatorEventKind::Revoked => version.get() == 2,
    };
    if valid {
        return Ok(());
    }
    Err(authenticator_error(
        PrincipalAuthenticatorErrorCode::InvalidEvent,
    ))
}

/// One exact compare-and-commit transition with immutable audit evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalAuthenticatorTransition {
    pub(crate) previous_version: Option<PrincipalAuthenticatorVersion>,
    pub(crate) previous_snapshot: Option<PrincipalAuthenticatorSnapshot>,
    pub(crate) link: PrincipalAuthenticatorLink,
    pub(crate) event: PrincipalAuthenticatorEvent,
}

impl PrincipalAuthenticatorTransition {
    /// Returns the required durable previous version, or `None` for first link.
    #[must_use]
    pub const fn expected_previous_version(&self) -> Option<PrincipalAuthenticatorVersion> {
        self.previous_version
    }

    /// Returns the exact immutable previous snapshot when one must exist.
    #[must_use]
    pub const fn previous_snapshot(&self) -> Option<&PrincipalAuthenticatorSnapshot> {
        self.previous_snapshot.as_ref()
    }

    /// Returns the target snapshot.
    #[must_use]
    pub fn new_snapshot(&self) -> PrincipalAuthenticatorSnapshot {
        self.link.snapshot()
    }

    /// Returns the target validated link.
    #[must_use]
    pub const fn link(&self) -> &PrincipalAuthenticatorLink {
        &self.link
    }

    /// Consumes the transition and returns its target link.
    #[must_use]
    pub fn into_link(self) -> PrincipalAuthenticatorLink {
        self.link
    }

    /// Returns the immutable event that must commit with the target snapshot.
    #[must_use]
    pub const fn event(&self) -> &PrincipalAuthenticatorEvent {
        &self.event
    }

    /// Returns the tenant key shared by all transition evidence.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.link.tenant_id()
    }

    /// Returns the deterministic aggregate identifier shared by all evidence.
    #[must_use]
    pub const fn authenticator_id(&self) -> &PrincipalAuthenticatorId {
        self.link.authenticator_id()
    }
}

impl Debug for PrincipalAuthenticatorTransition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthenticatorTransition(<redacted>)")
    }
}

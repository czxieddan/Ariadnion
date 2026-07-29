// crates/optional/ariadnion-principal-binding/src/transition.rs - Rust source for Ariadnion.
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
//! Deterministic provisioning, revocation, and direct-identifier erasure.

use ariadnion_core::{PrincipalId, RequestId};
use ariadnion_user_domain::UtcTimestamp;

use crate::error::{PrincipalBindingError, PrincipalBindingErrorCode, error};
use crate::ids::PrincipalBindingVersion;
use crate::model::{
    PrincipalBinding, PrincipalBindingEvent, PrincipalBindingEventKind, PrincipalBindingIdentity,
    PrincipalBindingSnapshotData, PrincipalBindingState, PrincipalBindingTransition,
    SubjectCommitment,
};

/// Version and trusted audit evidence for one existing-binding transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalBindingCommand {
    expected_version: PrincipalBindingVersion,
    actor: PrincipalId,
    request_id: RequestId,
    occurred_at: UtcTimestamp,
}

impl PrincipalBindingCommand {
    /// Creates a deterministic lifecycle command.
    #[must_use]
    pub const fn new(
        expected_version: PrincipalBindingVersion,
        actor: PrincipalId,
        request_id: RequestId,
        occurred_at: UtcTimestamp,
    ) -> Self {
        Self {
            expected_version,
            actor,
            request_id,
            occurred_at,
        }
    }

    /// Returns the optimistic version required by this command.
    #[must_use]
    pub const fn expected_version(&self) -> PrincipalBindingVersion {
        self.expected_version
    }

    /// Returns the authenticated actor.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the request correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the trusted transition time.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }
}

/// Provisions an initial active binding and derives its subject commitment.
///
/// This API deliberately accepts no commitment and no existing aggregate. The
/// repository must atomically require the tenant/principal key to be absent,
/// making erased and previously used principals unavailable for reuse.
///
/// # Errors
/// This currently has no data-dependent failure after identity construction;
/// the result remains fallible so callers use the same stable domain-error path
/// as persisted transitions and future compatible validation.
pub fn provision(
    identity: PrincipalBindingIdentity,
    actor: PrincipalId,
    request_id: RequestId,
    occurred_at: UtcTimestamp,
) -> Result<PrincipalBindingTransition, PrincipalBindingError> {
    let tenant_id = identity.principal().tenant_id().clone();
    let principal_id = identity.principal().principal_id().clone();
    let subject_commitment = SubjectCommitment::derive(&identity);
    let binding = PrincipalBinding::from_validated_parts(PrincipalBindingSnapshotData {
        tenant_id: tenant_id.clone(),
        principal_id: principal_id.clone(),
        subject_commitment,
        version: PrincipalBindingVersion::initial(),
        state: PrincipalBindingState::Active,
        identity: Some(identity),
        provisioned_at: occurred_at,
        revoked_at: None,
        erased_at: None,
    });
    let event = event(
        &binding,
        PrincipalBindingEventKind::Provisioned,
        actor,
        request_id,
        occurred_at,
    );
    Ok(PrincipalBindingTransition {
        previous_version: None,
        previous_snapshot: None,
        binding,
        event,
    })
}

/// Revokes an active binding while retaining direct identifiers for erasure.
///
/// # Errors
/// Returns stable codes for a stale version, non-active state, version
/// exhaustion, or a timestamp preceding provisioning.
pub fn revoke(
    current: &PrincipalBinding,
    command: PrincipalBindingCommand,
) -> Result<PrincipalBindingTransition, PrincipalBindingError> {
    validate_command(current, &command, PrincipalBindingState::Active)?;
    let new_version = current.version().next()?;
    let binding = PrincipalBinding::from_validated_parts(PrincipalBindingSnapshotData {
        tenant_id: current.tenant_id().clone(),
        principal_id: current.principal_id().clone(),
        subject_commitment: *current.subject_commitment(),
        version: new_version,
        state: PrincipalBindingState::Revoked,
        identity: current.identity().cloned(),
        provisioned_at: current.provisioned_at(),
        revoked_at: Some(command.occurred_at),
        erased_at: None,
    });
    Ok(transition(
        current,
        binding,
        PrincipalBindingEventKind::Revoked,
        command,
    ))
}

/// Erases direct identifiers while retaining linkable pseudonymous evidence.
///
/// No reactivation or rebinding transition exists. Once this succeeds, the
/// aggregate is terminal and its principal key remains durably occupied. The
/// retained unkeyed commitment is sensitive: a known candidate subject tuple
/// can be tested offline, so erasure does not make the record anonymous.
///
/// # Errors
/// Returns stable codes for a stale version, non-revoked state, version
/// exhaustion, or a timestamp preceding revocation.
pub fn erase(
    current: &PrincipalBinding,
    command: PrincipalBindingCommand,
) -> Result<PrincipalBindingTransition, PrincipalBindingError> {
    validate_command(current, &command, PrincipalBindingState::Revoked)?;
    let new_version = current.version().next()?;
    let binding = PrincipalBinding::from_validated_parts(PrincipalBindingSnapshotData {
        tenant_id: current.tenant_id().clone(),
        principal_id: current.principal_id().clone(),
        subject_commitment: *current.subject_commitment(),
        version: new_version,
        state: PrincipalBindingState::Erased,
        identity: None,
        provisioned_at: current.provisioned_at(),
        revoked_at: current.revoked_at(),
        erased_at: Some(command.occurred_at),
    });
    Ok(transition(
        current,
        binding,
        PrincipalBindingEventKind::Erased,
        command,
    ))
}

fn validate_command(
    current: &PrincipalBinding,
    command: &PrincipalBindingCommand,
    required_state: PrincipalBindingState,
) -> Result<(), PrincipalBindingError> {
    if command.expected_version != current.version() {
        return Err(error(PrincipalBindingErrorCode::VersionConflict));
    }
    if current.state() != required_state {
        return Err(error(PrincipalBindingErrorCode::InvalidTransition));
    }
    validate_time(current, command.occurred_at)
}

fn validate_time(
    current: &PrincipalBinding,
    occurred_at: UtcTimestamp,
) -> Result<(), PrincipalBindingError> {
    let last = current.revoked_at().unwrap_or(current.provisioned_at());
    if occurred_at < last {
        return Err(error(PrincipalBindingErrorCode::TimestampRegression));
    }
    Ok(())
}

fn transition(
    current: &PrincipalBinding,
    binding: PrincipalBinding,
    kind: PrincipalBindingEventKind,
    command: PrincipalBindingCommand,
) -> PrincipalBindingTransition {
    let event = event(
        &binding,
        kind,
        command.actor,
        command.request_id,
        command.occurred_at,
    );
    PrincipalBindingTransition {
        previous_version: Some(current.version()),
        previous_snapshot: Some(current.snapshot()),
        binding,
        event,
    }
}

fn event(
    binding: &PrincipalBinding,
    kind: PrincipalBindingEventKind,
    actor: PrincipalId,
    request_id: RequestId,
    occurred_at: UtcTimestamp,
) -> PrincipalBindingEvent {
    PrincipalBindingEvent {
        tenant_id: binding.tenant_id().clone(),
        principal_id: binding.principal_id().clone(),
        version: binding.version(),
        kind,
        occurred_at,
        actor,
        request_id,
        subject_commitment: *binding.subject_commitment(),
    }
}

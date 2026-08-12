// crates/optional/ariadnion-principal-binding/src/authenticator_transition.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Legal creation and terminal revocation of authenticator links.

use ariadnion_core::{PrincipalId, RequestId};
use ariadnion_user_domain::UtcTimestamp;

use crate::authenticator_error::{
    PrincipalAuthenticatorError, PrincipalAuthenticatorErrorCode, authenticator_error,
};
use crate::authenticator_ids::{
    PrincipalAuthenticatorId, PrincipalAuthenticatorKind, PrincipalAuthenticatorSourceCommitment,
    PrincipalAuthenticatorSourceId, PrincipalAuthenticatorVersion,
};
use crate::authenticator_model::{
    PrincipalAuthenticatorEvent, PrincipalAuthenticatorEventData, PrincipalAuthenticatorEventKind,
    PrincipalAuthenticatorLink, PrincipalAuthenticatorSnapshotData, PrincipalAuthenticatorState,
    PrincipalAuthenticatorTransition,
};
use crate::{PrincipalBinding, PrincipalBindingState};

/// Actor, request, expected-version, and UTC evidence for one revocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalAuthenticatorCommand {
    expected_version: PrincipalAuthenticatorVersion,
    actor: PrincipalId,
    request_id: RequestId,
    occurred_at: UtcTimestamp,
}

impl PrincipalAuthenticatorCommand {
    /// Creates one bounded revocation command.
    #[must_use]
    pub const fn new(
        expected_version: PrincipalAuthenticatorVersion,
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

    /// Returns the optimistic expected version.
    #[must_use]
    pub const fn expected_version(&self) -> PrincipalAuthenticatorVersion {
        self.expected_version
    }

    /// Returns the authorizing principal.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    /// Returns the causative request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the command UTC timestamp.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcTimestamp {
        self.occurred_at
    }
}

/// Creates the only link for one immutable tenant/kind/source key.
///
/// The tenant, principal, and principal-binding version are derived from the
/// supplied active principal binding. The authenticator ID is derived internally;
/// callers cannot inject it. Durable compare-and-commit must require exact-key
/// absence, so a revoked source can never be rebound or reused.
///
/// # Errors
/// Returns a stable redacted code when the principal binding is not active or
/// when `linked_at` predates that binding's provisioning time.
pub fn link_authenticator(
    binding: &PrincipalBinding,
    kind: PrincipalAuthenticatorKind,
    source_id: PrincipalAuthenticatorSourceId,
    actor: PrincipalId,
    request_id: RequestId,
    linked_at: UtcTimestamp,
) -> Result<PrincipalAuthenticatorTransition, PrincipalAuthenticatorError> {
    validate_principal_binding(binding, linked_at)?;
    let authenticator_id = PrincipalAuthenticatorId::derive(binding.tenant_id(), kind, &source_id);
    let link =
        PrincipalAuthenticatorLink::from_validated_parts(PrincipalAuthenticatorSnapshotData {
            tenant_id: binding.tenant_id().clone(),
            authenticator_id,
            authenticator_kind: kind,
            source_id,
            principal_id: binding.principal_id().clone(),
            principal_binding_version: binding.version(),
            version: PrincipalAuthenticatorVersion::initial(),
            state: PrincipalAuthenticatorState::Active,
            linked_at,
            revoked_at: None,
        });
    Ok(initial_transition(link, actor, request_id))
}

fn validate_principal_binding(
    binding: &PrincipalBinding,
    linked_at: UtcTimestamp,
) -> Result<(), PrincipalAuthenticatorError> {
    if binding.state() != PrincipalBindingState::Active {
        return Err(authenticator_error(
            PrincipalAuthenticatorErrorCode::PrincipalBindingInactive,
        ));
    }
    if linked_at < binding.provisioned_at() {
        return Err(authenticator_error(
            PrincipalAuthenticatorErrorCode::TimestampRegression,
        ));
    }
    Ok(())
}

fn initial_transition(
    link: PrincipalAuthenticatorLink,
    actor: PrincipalId,
    request_id: RequestId,
) -> PrincipalAuthenticatorTransition {
    let occurred_at = link.linked_at();
    let event = event(
        &link,
        PrincipalAuthenticatorEventKind::Linked,
        actor,
        request_id,
        occurred_at,
    );
    PrincipalAuthenticatorTransition {
        previous_version: None,
        previous_snapshot: None,
        link,
        event,
    }
}

/// Terminally revokes one exact active authenticator link.
///
/// No delete, reactivation, source replacement, principal replacement, or kind
/// replacement transition exists. The immutable source key remains occupied.
///
/// # Errors
/// Returns stable redacted codes for a stale version, non-active state, version
/// exhaustion, or timestamp regression.
pub fn revoke_authenticator(
    current: &PrincipalAuthenticatorLink,
    command: PrincipalAuthenticatorCommand,
) -> Result<PrincipalAuthenticatorTransition, PrincipalAuthenticatorError> {
    validate_revoke(current, &command)?;
    let version = current.version().next()?;
    let link =
        PrincipalAuthenticatorLink::from_validated_parts(PrincipalAuthenticatorSnapshotData {
            tenant_id: current.tenant_id().clone(),
            authenticator_id: current.authenticator_id().clone(),
            authenticator_kind: current.kind(),
            source_id: current.source_id().clone(),
            principal_id: current.principal_id().clone(),
            principal_binding_version: current.principal_binding_version(),
            version,
            state: PrincipalAuthenticatorState::Revoked,
            linked_at: current.linked_at(),
            revoked_at: Some(command.occurred_at),
        });
    Ok(existing_transition(current, link, command))
}

fn validate_revoke(
    current: &PrincipalAuthenticatorLink,
    command: &PrincipalAuthenticatorCommand,
) -> Result<(), PrincipalAuthenticatorError> {
    if command.expected_version != current.version() {
        return Err(authenticator_error(
            PrincipalAuthenticatorErrorCode::VersionConflict,
        ));
    }
    if current.state() != PrincipalAuthenticatorState::Active {
        return Err(authenticator_error(
            PrincipalAuthenticatorErrorCode::InvalidTransition,
        ));
    }
    if command.occurred_at < current.linked_at() {
        return Err(authenticator_error(
            PrincipalAuthenticatorErrorCode::TimestampRegression,
        ));
    }
    Ok(())
}

fn existing_transition(
    current: &PrincipalAuthenticatorLink,
    link: PrincipalAuthenticatorLink,
    command: PrincipalAuthenticatorCommand,
) -> PrincipalAuthenticatorTransition {
    let event = event(
        &link,
        PrincipalAuthenticatorEventKind::Revoked,
        command.actor,
        command.request_id,
        command.occurred_at,
    );
    PrincipalAuthenticatorTransition {
        previous_version: Some(current.version()),
        previous_snapshot: Some(current.snapshot()),
        link,
        event,
    }
}

fn event(
    link: &PrincipalAuthenticatorLink,
    kind: PrincipalAuthenticatorEventKind,
    actor: PrincipalId,
    request_id: RequestId,
    occurred_at: UtcTimestamp,
) -> PrincipalAuthenticatorEvent {
    PrincipalAuthenticatorEvent::from_validated_parts(PrincipalAuthenticatorEventData {
        tenant_id: link.tenant_id().clone(),
        authenticator_id: link.authenticator_id().clone(),
        authenticator_kind: link.kind(),
        source_commitment: PrincipalAuthenticatorSourceCommitment::derive(
            link.tenant_id(),
            link.kind(),
            link.source_id(),
        ),
        principal_id: link.principal_id().clone(),
        principal_binding_version: link.principal_binding_version(),
        version: link.version(),
        kind,
        occurred_at,
        actor,
        request_id,
    })
}

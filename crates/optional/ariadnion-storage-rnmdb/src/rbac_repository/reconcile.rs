// crates/optional/ariadnion-storage-rnmdb/src/rbac_repository/reconcile.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Read-only reconciliation of one exact authorization-policy commit.

use ariadnion_rbac::{
    AuthorizationPolicyCommitReceipt, AuthorizationPolicyEventKind, PolicyVersion,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::LocalSession;

#[cfg(feature = "test-hooks")]
use super::HistoryTestHooks;
use super::decode::PersistedPolicyEvent;
use super::{
    AuditSubjectKeyMaterial, CommitRequest, evidence, integrity_failure, load_authenticated_policy,
    validate_commit_request,
};

pub(super) fn reconcile_commit(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<AuthorizationPolicyCommitReceipt, StorageError> {
    validate_commit_request(request)?;
    let loaded = load_authenticated_policy(
        session,
        request.tenant_id,
        request.context,
        key,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )
    .map_err(map_reconciliation_load_error)?;
    let target = request.transition.policy();
    validate_current_snapshot(target, &loaded.policy)?;
    let event = target_event(&loaded.events, target.version())?;
    validate_target_event(event, request)?;
    let committed_at = evidence::verify_snapshot_evidence(
        session,
        event,
        target,
        key,
        request.context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    Ok(AuthorizationPolicyCommitReceipt::new(
        request.tenant_id.clone(),
        target.version(),
        committed_at,
    ))
}

fn validate_current_snapshot(
    target: &ariadnion_rbac::AuthorizationPolicy,
    current: &ariadnion_rbac::AuthorizationPolicy,
) -> Result<(), StorageError> {
    if current.version() < target.version() {
        return Err(integrity_failure());
    }
    if current.version() == target.version() && current != target {
        return Err(integrity_failure());
    }
    Ok(())
}

fn target_event(
    events: &[PersistedPolicyEvent],
    version: PolicyVersion,
) -> Result<&PersistedPolicyEvent, StorageError> {
    let index = version
        .get()
        .checked_sub(1)
        .ok_or_else(integrity_failure)
        .and_then(|value| usize::try_from(value).map_err(|_| integrity_failure()))?;
    events.get(index).ok_or_else(integrity_failure)
}

fn validate_target_event(
    persisted: &PersistedPolicyEvent,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let event = request.transition.event();
    let valid = persisted.tenant_id() == event.tenant_id()
        && persisted.version() == event.version()
        && persisted.kind() == event.kind()
        && persisted.occurred_at() == event.occurred_at()
        && persisted.actor() == event.actor()
        && persisted.request_id() == request.context.request_id();
    if !valid {
        return Err(integrity_failure());
    }
    validate_event_kind(event.version(), event.kind())
}

fn validate_event_kind(
    version: PolicyVersion,
    kind: AuthorizationPolicyEventKind,
) -> Result<(), StorageError> {
    let valid = match kind {
        AuthorizationPolicyEventKind::Published => version == PolicyVersion::initial(),
        AuthorizationPolicyEventKind::Replaced => version.get() > 1,
    };
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn map_reconciliation_load_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::Unavailable
        | StorageErrorCode::ResourceExhausted => error,
        _ => integrity_failure(),
    }
}

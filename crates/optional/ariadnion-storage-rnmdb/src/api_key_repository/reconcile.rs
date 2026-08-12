// crates/optional/ariadnion-storage-rnmdb/src/api_key_repository/reconcile.rs - Rust source for Ariadnion.
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
//! Read-only reconciliation for complete durable API-key lifecycle evidence.

use ariadnion_audit_domain::AuditSequence;
use ariadnion_auth_api_key::{
    ApiKey, ApiKeyCommitReceipt, ApiKeyEvent, ApiKeyEventKind, ApiKeyState,
};
use ariadnion_core::{RequestContext, RequestId};
use ariadnion_principal_binding::{
    PrincipalAuthenticatorEventKind, PrincipalAuthenticatorLink, PrincipalAuthenticatorState,
};
use ariadnion_storage_domain::StorageError;
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::LocalSession;

use super::{
    CommitRequest, commit_receipt, decode, evidence, immutable_fields_match, integrity_failure,
    map_reconcile_error, reconcile_api_key_authenticator_history, validate_active_link_history,
};
use crate::AuditSubjectKeyMaterial;
use crate::principal_authenticator_repository::{
    ReconciledPrincipalAuthenticatorFact, ReconciledPrincipalAuthenticatorHistory,
};

pub(super) fn reconcile_exact(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ApiKeyCommitReceipt, StorageError> {
    let material = load_reconciliation_material(session, request, subject_key)?;
    validate_reconciled_material(&material)?;
    Ok(commit_receipt(
        request,
        material.history.target_committed_at(),
    ))
}

struct ApiKeyReconciliationMaterial {
    durable: ApiKey,
    history: ReconciledApiKeyHistory,
    authenticator: ReconciledPrincipalAuthenticatorHistory,
}

struct ReconciledApiKeyHistory {
    issuance: ReconciledTransitionSummary,
    terminal: ReconciledTransitionSummary,
    target_committed_at: UtcTimestamp,
}

impl ReconciledApiKeyHistory {
    const fn target_committed_at(&self) -> UtcTimestamp {
        self.target_committed_at
    }
}

#[derive(Clone)]
struct ReconciledTransitionSummary {
    event: ApiKeyEvent,
    request_id: RequestId,
    committed_at: UtcTimestamp,
    audit_sequence: AuditSequence,
    durable_head_sequence: AuditSequence,
}

fn load_reconciliation_material(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ApiKeyReconciliationMaterial, StorageError> {
    let target = request.transition.key();
    let durable = decode::load_key(session, request.tenant_id, request.user_id, target.id())
        .map_err(map_reconcile_error)?;
    validate_reconciliation_snapshot(&durable, target)?;
    let authenticator = reconcile_api_key_authenticator_history(session, request, subject_key)?;
    let history = reconcile_transition_history(
        session,
        request,
        &durable,
        authenticator.link(),
        subject_key,
    )?;
    Ok(ApiKeyReconciliationMaterial {
        durable,
        history,
        authenticator,
    })
}

fn validate_target_transition(
    request: &CommitRequest<'_>,
    persisted: &decode::PersistedApiKeyTransition,
) -> Result<(), StorageError> {
    let valid = persisted.expected_previous_version() == request.expected_previous_version
        && persisted.transition() == request.transition
        && persisted.request_id() == request.context.request_id();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn reconcile_transition_history(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    durable: &ApiKey,
    link: &PrincipalAuthenticatorLink,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<ReconciledApiKeyHistory, StorageError> {
    let mut reconciled = ApiKeyHistoryAccumulator::new();
    decode::visit_transition_history(session, durable, |session, persisted| {
        let next = reconcile_persisted_transition(session, request, persisted, subject_key)?;
        reconciled.push(request, link, persisted, next)
    })
    .map_err(map_reconcile_error)?;
    reconciled.finish()
}

fn validate_next_evidence(
    previous: Option<&evidence::ReconciledTransitionEvidence>,
    next: &evidence::ReconciledTransitionEvidence,
) -> Result<(), StorageError> {
    match previous {
        Some(previous) => evidence::validate_later_transition_evidence(previous, next),
        None => Ok(()),
    }
}

fn reconcile_persisted_transition(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    persisted: &decode::PersistedApiKeyTransition,
    subject_key: &AuditSubjectKeyMaterial,
) -> Result<evidence::ReconciledTransitionEvidence, StorageError> {
    let context = request_context(request.context, persisted.request_id());
    let stored = CommitRequest {
        tenant_id: request.tenant_id,
        user_id: request.user_id,
        expected_previous_version: persisted.expected_previous_version(),
        transition: persisted.transition(),
        context: &context,
    };
    evidence::reconcile_transition_evidence(session, &stored, subject_key)
        .map_err(map_reconcile_error)
}

fn request_context(context: &RequestContext, request_id: &RequestId) -> RequestContext {
    RequestContext::new(
        request_id.clone(),
        context.trace_id().clone(),
        context.principal().cloned(),
        context.deadline(),
        context.cancellation(),
    )
}

struct ApiKeyHistoryAccumulator {
    issuance: Option<ReconciledTransitionSummary>,
    terminal: Option<ReconciledTransitionSummary>,
    previous_evidence: Option<evidence::ReconciledTransitionEvidence>,
    target_committed_at: Option<UtcTimestamp>,
}

impl ApiKeyHistoryAccumulator {
    const fn new() -> Self {
        Self {
            issuance: None,
            terminal: None,
            previous_evidence: None,
            target_committed_at: None,
        }
    }

    fn push(
        &mut self,
        request: &CommitRequest<'_>,
        link: &PrincipalAuthenticatorLink,
        persisted: &decode::PersistedApiKeyTransition,
        next: evidence::ReconciledTransitionEvidence,
    ) -> Result<(), StorageError> {
        validate_next_evidence(self.previous_evidence.as_ref(), &next)?;
        validate_reconciled_rotation_actor(link, persisted.transition().event())?;
        self.capture_target(request, persisted, &next)?;
        let summary = transition_summary(persisted, &next);
        if self.issuance.is_none() {
            self.issuance = Some(summary.clone());
        }
        self.terminal = Some(summary);
        self.previous_evidence = Some(next);
        Ok(())
    }

    fn capture_target(
        &mut self,
        request: &CommitRequest<'_>,
        persisted: &decode::PersistedApiKeyTransition,
        next: &evidence::ReconciledTransitionEvidence,
    ) -> Result<(), StorageError> {
        if persisted.transition().key().version() != request.transition.key().version() {
            return Ok(());
        }
        if self.target_committed_at.is_some() {
            return Err(integrity_failure());
        }
        validate_target_transition(request, persisted)?;
        self.target_committed_at = Some(next.committed_at());
        Ok(())
    }

    fn finish(self) -> Result<ReconciledApiKeyHistory, StorageError> {
        Ok(ReconciledApiKeyHistory {
            issuance: self.issuance.ok_or_else(integrity_failure)?,
            terminal: self.terminal.ok_or_else(integrity_failure)?,
            target_committed_at: self.target_committed_at.ok_or_else(integrity_failure)?,
        })
    }
}

fn transition_summary(
    persisted: &decode::PersistedApiKeyTransition,
    evidence: &evidence::ReconciledTransitionEvidence,
) -> ReconciledTransitionSummary {
    ReconciledTransitionSummary {
        event: persisted.transition().event().clone(),
        request_id: persisted.request_id().clone(),
        committed_at: evidence.committed_at(),
        audit_sequence: evidence.audit_sequence(),
        durable_head_sequence: evidence.durable_head_sequence(),
    }
}

fn validate_reconciled_rotation_actor(
    link: &PrincipalAuthenticatorLink,
    event: &ApiKeyEvent,
) -> Result<(), StorageError> {
    let is_rotation = matches!(
        event.kind(),
        ApiKeyEventKind::Rotated | ApiKeyEventKind::RotationCompleted
    );
    let valid = !is_rotation || event.actor() == link.principal_id();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_reconciled_material(
    material: &ApiKeyReconciliationMaterial,
) -> Result<(), StorageError> {
    validate_reconciled_link_identity(
        material.authenticator.link(),
        material.authenticator.facts(),
        &material.history.issuance,
    )?;
    validate_reconciled_link_lifecycle(material)
}

fn validate_reconciled_link_identity(
    link: &PrincipalAuthenticatorLink,
    facts: &[ReconciledPrincipalAuthenticatorFact],
    issuance: &ReconciledTransitionSummary,
) -> Result<(), StorageError> {
    let event = &issuance.event;
    let linked = facts.first().ok_or_else(integrity_failure)?;
    let valid = api_link_identity_matches(link, event)
        && linked_fact_matches_api(linked, issuance, event)
        && linked.committed_at() == issuance.committed_at;
    valid.then_some(()).ok_or_else(integrity_failure)?;
    validate_paired_audit_order(linked.audit_sequence(), issuance)
}

fn api_link_identity_matches(link: &PrincipalAuthenticatorLink, issuance: &ApiKeyEvent) -> bool {
    issuance.kind() == ApiKeyEventKind::Issued && link.principal_id() == issuance.actor()
}

fn linked_fact_matches_api(
    linked: &ReconciledPrincipalAuthenticatorFact,
    issuance: &ReconciledTransitionSummary,
    event: &ApiKeyEvent,
) -> bool {
    linked.kind() == PrincipalAuthenticatorEventKind::Linked
        && linked.actor() == event.actor()
        && linked.request_id() == &issuance.request_id
        && linked.occurred_at() == event.occurred_at()
}

fn validate_paired_audit_order(
    authenticator_sequence: AuditSequence,
    api_evidence: &ReconciledTransitionSummary,
) -> Result<(), StorageError> {
    let expected = api_evidence
        .audit_sequence
        .next()
        .map_err(|_| integrity_failure())?;
    let valid = authenticator_sequence == expected
        && authenticator_sequence <= api_evidence.durable_head_sequence;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_reconciled_link_lifecycle(
    material: &ApiKeyReconciliationMaterial,
) -> Result<(), StorageError> {
    match material.durable.state() {
        ApiKeyState::Revoked | ApiKeyState::Expired => validate_reconciled_terminal_link(material),
        ApiKeyState::Active | ApiKeyState::Rotating => {
            validate_active_link_history(&material.authenticator)
        }
    }
}

fn validate_reconciled_terminal_link(
    material: &ApiKeyReconciliationMaterial,
) -> Result<(), StorageError> {
    let terminal = &material.history.terminal;
    let event = &terminal.event;
    let revoked = material
        .authenticator
        .facts()
        .get(1)
        .ok_or_else(integrity_failure)?;
    let link = material.authenticator.link();
    let valid = terminal_link_state_matches(link, &material.authenticator, event)
        && revoked_fact_matches_api(revoked, terminal, event)
        && revoked.committed_at() == terminal.committed_at;
    valid.then_some(()).ok_or_else(integrity_failure)?;
    validate_paired_audit_order(revoked.audit_sequence(), terminal)
}

fn terminal_link_state_matches(
    link: &PrincipalAuthenticatorLink,
    history: &ReconciledPrincipalAuthenticatorHistory,
    terminal: &ApiKeyEvent,
) -> bool {
    let terminal_kind = matches!(
        terminal.kind(),
        ApiKeyEventKind::Revoked | ApiKeyEventKind::Expired
    );
    terminal_kind
        && link.version().get() == 2
        && link.state() == PrincipalAuthenticatorState::Revoked
        && link.revoked_at() == Some(terminal.occurred_at())
        && history.facts().len() == 2
}

fn revoked_fact_matches_api(
    revoked: &ReconciledPrincipalAuthenticatorFact,
    terminal: &ReconciledTransitionSummary,
    event: &ApiKeyEvent,
) -> bool {
    revoked.kind() == PrincipalAuthenticatorEventKind::Revoked
        && revoked.actor() == event.actor()
        && revoked.request_id() == &terminal.request_id
        && revoked.occurred_at() == event.occurred_at()
}

fn validate_reconciliation_snapshot(durable: &ApiKey, target: &ApiKey) -> Result<(), StorageError> {
    let valid = durable.version() >= target.version() && immutable_fields_match(durable, target);
    valid.then_some(()).ok_or_else(integrity_failure)
}

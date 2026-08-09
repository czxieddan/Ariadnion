// crates/optional/ariadnion-provider-http/src/transmission.rs - Provider transmission evidence for Ariadnion.
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

//! Attempt evidence synchronized with the first physical request write.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;

use ariadnion_provider_sdk::{
    ProviderAttemptEvidence, ProviderAttemptProgress, ProviderTransmission,
};

#[derive(Clone)]
pub(crate) struct ProviderTransmissionMarker {
    state: Arc<Mutex<ProviderTransmissionState>>,
}

struct ProviderTransmissionState {
    evidence: ProviderAttemptEvidence,
    lifecycle: ProviderTransmissionLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderTransmissionLifecycle {
    Unarmed,
    Idle,
    Claimed,
    Closed,
}

pub(crate) struct ProviderWriteGuard<'a> {
    _state: MutexGuard<'a, ProviderTransmissionState>,
}

impl ProviderTransmissionMarker {
    pub(crate) fn new(evidence: ProviderAttemptEvidence) -> Self {
        Self {
            state: Arc::new(Mutex::new(ProviderTransmissionState {
                evidence,
                lifecycle: ProviderTransmissionLifecycle::Unarmed,
            })),
        }
    }

    pub(crate) fn evidence(&self) -> ProviderAttemptEvidence {
        lock_transmission_state(&self.state).evidence.clone()
    }

    pub(crate) fn arm(&self) {
        let mut state = lock_transmission_state(&self.state);
        if state.lifecycle == ProviderTransmissionLifecycle::Unarmed {
            state.lifecycle = ProviderTransmissionLifecycle::Idle;
        }
    }

    pub(crate) fn rebind(&self, evidence: ProviderAttemptEvidence) -> io::Result<()> {
        if !pristine_progress(evidence.progress()) {
            return Err(evidence_error());
        }
        let mut state = lock_transmission_state(&self.state);
        if state.lifecycle != ProviderTransmissionLifecycle::Claimed
            || !completed_progress(state.evidence.progress())
        {
            return Err(evidence_error());
        }
        state.evidence = evidence;
        state.lifecycle = ProviderTransmissionLifecycle::Idle;
        Ok(())
    }

    /// Acquires the lifecycle before the evidence mutex and retains it through
    /// one synchronous transport poll. No code acquires these locks in reverse
    /// order, and the guard never crosses an await boundary.
    pub(crate) fn write_guard(&self) -> io::Result<ProviderWriteGuard<'_>> {
        let mut state = lock_transmission_state(&self.state);
        match state.lifecycle {
            ProviderTransmissionLifecycle::Idle => self.claim(&mut state)?,
            ProviderTransmissionLifecycle::Claimed => {}
            ProviderTransmissionLifecycle::Unarmed | ProviderTransmissionLifecycle::Closed => {
                return Err(evidence_error());
            }
        }
        Ok(ProviderWriteGuard { _state: state })
    }

    fn claim(&self, state: &mut ProviderTransmissionState) -> io::Result<()> {
        if !pristine_progress(state.evidence.progress()) {
            state.lifecycle = ProviderTransmissionLifecycle::Closed;
            return Err(evidence_error());
        }
        if state.evidence.mark_transmission_started().is_err() {
            state.lifecycle = ProviderTransmissionLifecycle::Closed;
            return Err(evidence_error());
        }
        if !claimed_progress(state.evidence.progress()) {
            self.close_failed_claim(state);
            return Err(evidence_error());
        }
        state.lifecycle = ProviderTransmissionLifecycle::Claimed;
        Ok(())
    }

    fn close_failed_claim(&self, state: &mut ProviderTransmissionState) {
        if state.evidence.progress().transmission() == ProviderTransmission::Started {
            let _result = state.evidence.mark_transmission_unknown();
        }
        state.lifecycle = ProviderTransmissionLifecycle::Closed;
    }

    pub(crate) fn close(&self) {
        let mut state = lock_transmission_state(&self.state);
        if state.lifecycle == ProviderTransmissionLifecycle::Claimed
            && state.evidence.progress().transmission() == ProviderTransmission::Started
        {
            let _result = state.evidence.mark_transmission_unknown();
        }
        state.lifecycle = ProviderTransmissionLifecycle::Closed;
    }

    pub(crate) fn observe_response_bytes(&self) -> io::Result<()> {
        let state = lock_transmission_state(&self.state);
        if state.lifecycle != ProviderTransmissionLifecycle::Claimed {
            return Err(evidence_error());
        }
        Self::commit_response(&state.evidence)?;
        Self::mark_upstream_response(&state.evidence)
    }

    pub(crate) fn finish_write(&self, result: &Poll<io::Result<usize>>) {
        if matches!(result, Poll::Ready(Err(_)) | Poll::Ready(Ok(0))) {
            self.close();
        }
    }

    fn commit_response(evidence: &ProviderAttemptEvidence) -> io::Result<()> {
        match evidence.progress().transmission() {
            ProviderTransmission::Started => evidence
                .mark_request_committed()
                .map_err(|_| evidence_error()),
            ProviderTransmission::Committed => Ok(()),
            ProviderTransmission::NotStarted | ProviderTransmission::Unknown => {
                Err(evidence_error())
            }
            _ => Err(evidence_error()),
        }
    }

    fn mark_upstream_response(evidence: &ProviderAttemptEvidence) -> io::Result<()> {
        if evidence.progress().upstream_response_started() {
            return Ok(());
        }
        evidence
            .mark_upstream_response_started()
            .map_err(|_| evidence_error())
    }
}

fn pristine_progress(progress: ProviderAttemptProgress) -> bool {
    progress.transmission() == ProviderTransmission::NotStarted
        && !progress.upstream_response_started()
        && !progress.downstream_delivery_started()
}

fn claimed_progress(progress: ProviderAttemptProgress) -> bool {
    progress.transmission() == ProviderTransmission::Started
        && !progress.upstream_response_started()
        && !progress.downstream_delivery_started()
}

fn completed_progress(progress: ProviderAttemptProgress) -> bool {
    progress.transmission() == ProviderTransmission::Committed
        && progress.upstream_response_started()
        && progress.downstream_delivery_started()
}

fn lock_transmission_state(
    state: &Mutex<ProviderTransmissionState>,
) -> MutexGuard<'_, ProviderTransmissionState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn evidence_error() -> io::Error {
    io::Error::other("provider transmission evidence rejected")
}

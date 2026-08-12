// crates/optional/ariadnion-provider-sdk/src/attempt.rs - Provider attempt lifecycle for Ariadnion.
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
//! Immutable provider-attempt identity and monotonic transmission evidence.

use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard};

use ariadnion_api_domain::{ResponseMode, ServiceRequest};
use ariadnion_core::{AttemptId, RequestContext};

use crate::contract::ProviderModelId;

/// The observed state of upstream request transmission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderTransmission {
    /// No upstream bytes were observed.
    NotStarted,
    /// Headers or body transmission began.
    Started,
    /// The provider may have acted on the request.
    Committed,
    /// The adapter cannot prove whether transmission completed.
    Unknown,
}

/// Monotonic evidence used by retry and failover policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAttemptProgress {
    transmission: ProviderTransmission,
    upstream_response_started: bool,
    downstream_delivery_started: bool,
}

impl ProviderAttemptProgress {
    /// Creates an untouched evidence record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            transmission: ProviderTransmission::NotStarted,
            upstream_response_started: false,
            downstream_delivery_started: false,
        }
    }

    /// Returns the upstream transmission state.
    #[must_use]
    pub const fn transmission(self) -> ProviderTransmission {
        self.transmission
    }

    /// Returns whether an upstream response/event was observed.
    #[must_use]
    pub const fn upstream_response_started(self) -> bool {
        self.upstream_response_started
    }

    /// Returns whether a client-visible event was delivered.
    #[must_use]
    pub const fn downstream_delivery_started(self) -> bool {
        self.downstream_delivery_started
    }
}

impl Default for ProviderAttemptProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable failures from an invalid evidence transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AttemptProgressErrorCode {
    /// A transition would move evidence backwards or repeat a boundary.
    InvalidTransition,
}

/// A redacted attempt-evidence transition error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptProgressError {
    code: AttemptProgressErrorCode,
}

impl AttemptProgressError {
    const fn invalid_transition() -> Self {
        Self {
            code: AttemptProgressErrorCode::InvalidTransition,
        }
    }

    /// Returns the stable error code.
    #[must_use]
    pub const fn code(self) -> AttemptProgressErrorCode {
        self.code
    }
}

impl Display for AttemptProgressError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("provider_attempt_invalid_transition")
    }
}

impl std::error::Error for AttemptProgressError {}

/// A cloneable handle for recording one attempt's irreversible evidence.
#[derive(Clone, Debug)]
pub struct ProviderAttemptEvidence {
    progress: Arc<Mutex<ProviderAttemptProgress>>,
}

impl ProviderAttemptEvidence {
    /// Creates an untouched evidence handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            progress: Arc::new(Mutex::new(ProviderAttemptProgress::new())),
        }
    }

    /// Returns a snapshot of current evidence.
    #[must_use]
    pub fn progress(&self) -> ProviderAttemptProgress {
        *lock_progress(&self.progress)
    }

    /// Records that upstream transmission started.
    pub fn mark_transmission_started(&self) -> Result<(), AttemptProgressError> {
        let mut progress = lock_progress(&self.progress);
        if progress.transmission != ProviderTransmission::NotStarted {
            return Err(AttemptProgressError::invalid_transition());
        }
        progress.transmission = ProviderTransmission::Started;
        Ok(())
    }

    /// Records that the provider may have acted on the request.
    pub fn mark_request_committed(&self) -> Result<(), AttemptProgressError> {
        let mut progress = lock_progress(&self.progress);
        if progress.transmission != ProviderTransmission::Started {
            return Err(AttemptProgressError::invalid_transition());
        }
        progress.transmission = ProviderTransmission::Committed;
        Ok(())
    }

    /// Records that the adapter lost certainty about request transmission.
    pub fn mark_transmission_unknown(&self) -> Result<(), AttemptProgressError> {
        let mut progress = lock_progress(&self.progress);
        if progress.transmission == ProviderTransmission::Unknown {
            return Err(AttemptProgressError::invalid_transition());
        }
        progress.transmission = ProviderTransmission::Unknown;
        Ok(())
    }

    /// Records the first provider response/event observation.
    pub fn mark_upstream_response_started(&self) -> Result<(), AttemptProgressError> {
        let mut progress = lock_progress(&self.progress);
        if progress.upstream_response_started {
            return Err(AttemptProgressError::invalid_transition());
        }
        progress.upstream_response_started = true;
        Ok(())
    }

    /// Records the first client-visible response/event delivery.
    pub fn mark_downstream_delivery_started(&self) -> Result<(), AttemptProgressError> {
        let mut progress = lock_progress(&self.progress);
        if progress.downstream_delivery_started {
            return Err(AttemptProgressError::invalid_transition());
        }
        progress.downstream_delivery_started = true;
        Ok(())
    }
}

impl Default for ProviderAttemptEvidence {
    fn default() -> Self {
        Self::new()
    }
}

/// One immutable physical provider attempt.
pub struct ProviderAttempt {
    attempt_id: AttemptId,
    model: ProviderModelId,
    request: ServiceRequest,
    context: RequestContext,
    evidence: ProviderAttemptEvidence,
}

impl fmt::Debug for ProviderAttempt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAttempt")
            .field("attempt_id", &self.attempt_id)
            .field("model", &self.model)
            .field("progress", &self.evidence.progress())
            .finish_non_exhaustive()
    }
}

impl ProviderAttempt {
    /// Binds one attempt ID to a request and an independently cancellable child
    /// context. The parent context is never cancelled by this attempt.
    #[must_use]
    pub fn new(
        attempt_id: AttemptId,
        model: ProviderModelId,
        request: ServiceRequest,
        parent: &RequestContext,
    ) -> Self {
        let context = RequestContext::new(
            parent.request_id().clone(),
            parent.trace_id().clone(),
            parent.principal().cloned(),
            parent.deadline(),
            parent.cancellation().child(),
        );
        Self {
            attempt_id,
            model,
            request,
            context,
            evidence: ProviderAttemptEvidence::new(),
        }
    }

    /// Returns the immutable physical attempt ID.
    #[must_use]
    pub const fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }

    /// Returns the provider model mapping.
    #[must_use]
    pub const fn model(&self) -> &ProviderModelId {
        &self.model
    }

    /// Returns the transport-neutral service request.
    #[must_use]
    pub const fn request(&self) -> &ServiceRequest {
        &self.request
    }

    /// Returns the child request context.
    #[must_use]
    pub const fn context(&self) -> &RequestContext {
        &self.context
    }

    /// Returns the caller-requested response mode when known to this SDK.
    #[must_use]
    pub fn response_mode(&self) -> Option<ResponseMode> {
        match &self.request {
            ServiceRequest::Text(request) => Some(request.response_mode()),
            ServiceRequest::Chat(request) => Some(request.response_mode()),
            ServiceRequest::Embedding(_) => Some(ResponseMode::Complete),
            ServiceRequest::Image(_) => Some(ResponseMode::Complete),
            _ => None,
        }
    }

    /// Returns a cloneable evidence handle for the adapter and stream bridge.
    #[must_use]
    pub fn evidence(&self) -> ProviderAttemptEvidence {
        self.evidence.clone()
    }

    /// Cancels only this physical attempt.
    pub fn cancel(&self) -> bool {
        self.context.cancellation().cancel()
    }
}

fn lock_progress(
    progress: &Mutex<ProviderAttemptProgress>,
) -> MutexGuard<'_, ProviderAttemptProgress> {
    match progress.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

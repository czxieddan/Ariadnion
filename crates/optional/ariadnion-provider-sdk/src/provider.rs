// crates/optional/ariadnion-provider-sdk/src/provider.rs - Provider call contracts for Ariadnion.
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
//! Runtime-neutral provider calls with attempt-correlated outcomes.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use ariadnion_api_domain::{ResponseMode, ServiceResponse};
use ariadnion_core::{AttemptId, ErrorCode, RequestContext};

use crate::{
    ProviderAttempt, ProviderAttemptEvidence, ProviderDescriptor, ProviderFailure,
    ProviderFailureClass, ProviderStreamSubscriber,
};

/// A boxed runtime-neutral provider call returned by a trusted adapter.
///
/// Returned failures contain provider classification facts only. The checked
/// call wrapper binds current attempt evidence before exposing an outcome.
pub type BoxProviderCall<'a> =
    Pin<Box<dyn Future<Output = Result<ProviderRawOutcome, ProviderFailure>> + Send + 'a>>;

/// A raw provider result before response-mode and attempt correlation checks.
///
/// Implementations may construct this value only after bounded domain parsing.
/// They must not retain raw response bodies, headers, URLs, or credentials in
/// either variant or in returned failures.
#[non_exhaustive]
pub enum ProviderRawOutcome {
    /// One complete bounded service response.
    Complete(ServiceResponse),
    /// One bounded provider-native event subscriber.
    Stream(ProviderStreamSubscriber),
}

/// A provider result correlated to the immutable physical attempt identity.
#[non_exhaustive]
pub enum ProviderAttemptOutcome {
    /// A complete response matching the request mode.
    Complete {
        /// Immutable physical attempt identity.
        attempt_id: AttemptId,
        /// Bounded transport-neutral response.
        response: ServiceResponse,
    },
    /// A stream matching the request mode.
    Stream {
        /// Immutable physical attempt identity.
        attempt_id: AttemptId,
        /// Single-consumer provider-native stream.
        stream: ProviderStreamSubscriber,
    },
    /// A classified terminal failure.
    Failed {
        /// Immutable physical attempt identity.
        attempt_id: AttemptId,
        /// Redacted provider failure.
        failure: ProviderFailure,
    },
}

impl ProviderAttemptOutcome {
    /// Returns the immutable identity shared by every terminal outcome.
    #[must_use]
    pub const fn attempt_id(&self) -> &AttemptId {
        match self {
            Self::Complete { attempt_id, .. }
            | Self::Stream { attempt_id, .. }
            | Self::Failed { attempt_id, .. } => attempt_id,
        }
    }
}

/// An object-safe provider adapter boundary.
pub trait ProviderPort: Send + Sync {
    /// Returns immutable provider metadata used before adapter work starts.
    fn descriptor(&self) -> &ProviderDescriptor;

    /// Starts the trusted adapter future for one owned physical attempt.
    ///
    /// This method must only construct a lazy future. The future must check the
    /// supplied attempt context before each external side effect and must return
    /// only bounded domain values or unbound classified failure facts.
    fn start_raw<'a>(&'a self, attempt: ProviderAttempt) -> BoxProviderCall<'a>;

    /// Starts a checked provider call with cancellation and mode enforcement.
    #[must_use]
    fn call<'a>(&'a self, attempt: ProviderAttempt) -> ProviderCallFuture<'a> {
        let attempt_id = attempt.attempt_id().clone();
        let expected_mode = attempt.response_mode();
        let evidence = attempt.evidence();
        let context = attempt.context().clone();
        let initial_failure = inactive_failure(&context);
        let inner = initial_failure.is_none().then(|| self.start_raw(attempt));
        ProviderCallFuture {
            inner,
            attempt_id,
            expected_mode,
            evidence,
            context,
            initial_failure,
            completed: false,
        }
    }
}

/// A cancellation-aware wrapper around one raw provider call.
pub struct ProviderCallFuture<'a> {
    inner: Option<BoxProviderCall<'a>>,
    attempt_id: AttemptId,
    expected_mode: Option<ResponseMode>,
    evidence: ProviderAttemptEvidence,
    context: RequestContext,
    initial_failure: Option<ProviderFailure>,
    completed: bool,
}

impl Future for ProviderCallFuture<'_> {
    type Output = ProviderAttemptOutcome;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(outcome) = this.preflight_outcome() {
            return Poll::Ready(outcome);
        }
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(this.complete_failure(internal_failure()));
        };
        match inner.as_mut().poll(task) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(outcome) => {
                this.inner = None;
                this.completed = true;
                Poll::Ready(correlate_outcome(
                    &this.attempt_id,
                    this.expected_mode,
                    &this.evidence,
                    outcome,
                ))
            }
        }
    }
}

impl ProviderCallFuture<'_> {
    fn preflight_outcome(&mut self) -> Option<ProviderAttemptOutcome> {
        let failure = self
            .initial_failure
            .take()
            .or_else(|| inactive_failure(&self.context))?;
        Some(self.complete_failure(failure))
    }

    fn complete_failure(&mut self, failure: ProviderFailure) -> ProviderAttemptOutcome {
        self.context.cancellation().cancel();
        self.inner = None;
        self.completed = true;
        ProviderAttemptOutcome::Failed {
            attempt_id: self.attempt_id.clone(),
            failure: failure.bind_progress(self.evidence.progress()),
        }
    }
}

impl Drop for ProviderCallFuture<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.context.cancellation().cancel();
        }
    }
}

fn correlate_outcome(
    attempt_id: &AttemptId,
    expected_mode: Option<ResponseMode>,
    evidence: &ProviderAttemptEvidence,
    outcome: Result<ProviderRawOutcome, ProviderFailure>,
) -> ProviderAttemptOutcome {
    match (expected_mode, outcome) {
        (_, Err(failure)) => failed(attempt_id, evidence, failure),
        (Some(ResponseMode::Complete), Ok(ProviderRawOutcome::Complete(response))) => {
            ProviderAttemptOutcome::Complete {
                attempt_id: attempt_id.clone(),
                response,
            }
        }
        (Some(ResponseMode::Stream), Ok(ProviderRawOutcome::Stream(stream))) => {
            ProviderAttemptOutcome::Stream {
                attempt_id: attempt_id.clone(),
                stream,
            }
        }
        (_, Ok(_)) => failed(attempt_id, evidence, protocol_failure()),
    }
}

fn failed(
    attempt_id: &AttemptId,
    evidence: &ProviderAttemptEvidence,
    failure: ProviderFailure,
) -> ProviderAttemptOutcome {
    ProviderAttemptOutcome::Failed {
        attempt_id: attempt_id.clone(),
        failure: failure.bind_progress(evidence.progress()),
    }
}

fn inactive_failure(context: &RequestContext) -> Option<ProviderFailure> {
    context
        .check_active()
        .err()
        .map(|error| ProviderFailure::new(failure_class(error.code())))
}

const fn failure_class(code: ErrorCode) -> ProviderFailureClass {
    match code {
        ErrorCode::Cancelled => ProviderFailureClass::Cancelled,
        ErrorCode::DeadlineExceeded => ProviderFailureClass::DeadlineExceeded,
        _ => ProviderFailureClass::Internal,
    }
}

const fn protocol_failure() -> ProviderFailure {
    ProviderFailure::new(ProviderFailureClass::ProtocolViolation)
}

const fn internal_failure() -> ProviderFailure {
    ProviderFailure::new(ProviderFailureClass::Internal)
}

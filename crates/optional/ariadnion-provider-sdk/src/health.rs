// crates/optional/ariadnion-provider-sdk/src/health.rs - Provider health contracts for Ariadnion.
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
//! Bounded provider health observations and cancellable probe futures.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use ariadnion_core::{ErrorCode, RequestContext};

const PROVIDER_HEALTH_REASON_CODES: [&str; 9] = [
    "provider_health_ready",
    "provider_health_elevated_latency",
    "provider_health_rate_limited",
    "provider_health_authentication_rejected",
    "provider_health_upstream_unavailable",
    "provider_health_protocol_violation",
    "provider_health_cancelled",
    "provider_health_deadline_exceeded",
    "provider_health_internal",
];

/// A factual provider-level health status without routing policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderHealthStatus {
    /// The provider probe observed normal service.
    Healthy,
    /// The provider remains usable with a bounded impairment.
    Degraded,
    /// The provider cannot currently accept work.
    Unavailable,
}

/// A stable redacted reason for one provider health observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum ProviderHealthReason {
    /// The provider accepted the bounded probe normally.
    Ready = 0,
    /// The probe observed elevated latency without retaining timings.
    ElevatedLatency = 1,
    /// The provider applied a rate limit.
    RateLimited = 2,
    /// The provider rejected authentication evidence.
    AuthenticationRejected = 3,
    /// The provider or its transport was unavailable.
    UpstreamUnavailable = 4,
    /// The provider response violated its protocol contract.
    ProtocolViolation = 5,
    /// The probe was cancelled.
    Cancelled = 6,
    /// The caller deadline expired.
    DeadlineExceeded = 7,
    /// The adapter could not classify the observation safely.
    Internal = 8,
}

impl ProviderHealthReason {
    /// Returns the stable machine code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        PROVIDER_HEALTH_REASON_CODES
            .get(self as usize)
            .copied()
            .unwrap_or("provider_health_internal")
    }
}

/// One provider health observation containing no raw diagnostic text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderHealthSnapshot {
    status: ProviderHealthStatus,
    reason: ProviderHealthReason,
}

impl ProviderHealthSnapshot {
    /// Creates one factual provider-level health observation.
    #[must_use]
    pub const fn new(status: ProviderHealthStatus, reason: ProviderHealthReason) -> Self {
        Self { status, reason }
    }

    /// Returns the factual provider status.
    #[must_use]
    pub const fn status(self) -> ProviderHealthStatus {
        self.status
    }

    /// Returns the stable redacted reason.
    #[must_use]
    pub const fn reason(self) -> ProviderHealthReason {
        self.reason
    }
}

/// A boxed runtime-neutral provider health probe.
pub type BoxProviderHealthProbe<'a> =
    Pin<Box<dyn Future<Output = ProviderHealthSnapshot> + Send + 'a>>;

/// An object-safe provider health boundary that does not aggregate policy.
pub trait ProviderHealthPort: Send + Sync {
    /// Starts a lazy adapter probe with an independently cancellable context.
    ///
    /// Implementations must check the context before external work and return
    /// no URLs, raw provider responses, credential material, or user content.
    fn start_probe<'a>(&'a self, context: RequestContext) -> BoxProviderHealthProbe<'a>;

    /// Starts a bounded health probe derived from the caller context.
    #[must_use]
    fn probe<'a>(&'a self, parent: &RequestContext) -> ProviderHealthFuture<'a> {
        let context = child_context(parent);
        let initially_inactive = inactive_snapshot(&context);
        let inner = initially_inactive
            .is_none()
            .then(|| self.start_probe(context.clone()));
        ProviderHealthFuture {
            inner,
            context,
            initially_inactive,
            completed: false,
        }
    }
}

/// A cancellation- and deadline-aware provider health future.
pub struct ProviderHealthFuture<'a> {
    inner: Option<BoxProviderHealthProbe<'a>>,
    context: RequestContext,
    initially_inactive: Option<ProviderHealthSnapshot>,
    completed: bool,
}

impl Future for ProviderHealthFuture<'_> {
    type Output = ProviderHealthSnapshot;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(snapshot) = this.preflight_snapshot() {
            return Poll::Ready(this.cancel_and_complete(snapshot));
        }
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(this.cancel_and_complete(internal_snapshot()));
        };
        match inner.as_mut().poll(task) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(snapshot) => Poll::Ready(this.complete(snapshot)),
        }
    }
}

impl ProviderHealthFuture<'_> {
    fn preflight_snapshot(&mut self) -> Option<ProviderHealthSnapshot> {
        self.initially_inactive
            .take()
            .or_else(|| inactive_snapshot(&self.context))
    }

    fn complete(&mut self, snapshot: ProviderHealthSnapshot) -> ProviderHealthSnapshot {
        self.inner = None;
        self.completed = true;
        snapshot
    }

    fn cancel_and_complete(&mut self, snapshot: ProviderHealthSnapshot) -> ProviderHealthSnapshot {
        self.context.cancellation().cancel();
        self.complete(snapshot)
    }
}

impl Drop for ProviderHealthFuture<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.context.cancellation().cancel();
        }
    }
}

fn child_context(parent: &RequestContext) -> RequestContext {
    RequestContext::new(
        parent.request_id().clone(),
        parent.trace_id().clone(),
        parent.principal().cloned(),
        parent.deadline(),
        parent.cancellation().child(),
    )
}

fn inactive_snapshot(context: &RequestContext) -> Option<ProviderHealthSnapshot> {
    context
        .check_active()
        .err()
        .map(|error| unavailable_snapshot(health_reason(error.code())))
}

const fn health_reason(code: ErrorCode) -> ProviderHealthReason {
    match code {
        ErrorCode::Cancelled => ProviderHealthReason::Cancelled,
        ErrorCode::DeadlineExceeded => ProviderHealthReason::DeadlineExceeded,
        _ => ProviderHealthReason::Internal,
    }
}

const fn unavailable_snapshot(reason: ProviderHealthReason) -> ProviderHealthSnapshot {
    ProviderHealthSnapshot::new(ProviderHealthStatus::Unavailable, reason)
}

const fn internal_snapshot() -> ProviderHealthSnapshot {
    unavailable_snapshot(ProviderHealthReason::Internal)
}

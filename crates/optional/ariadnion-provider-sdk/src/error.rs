// crates/optional/ariadnion-provider-sdk/src/error.rs - Provider failure classification for Ariadnion.
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
//! Stable redacted provider failures and factual retry advice.

use std::fmt::{self, Display, Formatter};
use std::time::Duration;

use crate::attempt::{ProviderAttemptProgress, ProviderTransmission};
use crate::contract::{ProviderContractError, ProviderContractErrorCode};

/// The maximum accepted provider retry delay.
pub const MAX_PROVIDER_RETRY_AFTER: Duration = Duration::from_secs(86_400);

const PROVIDER_FAILURE_CODES: [&str; 14] = [
    "provider_cancelled",
    "provider_deadline_exceeded",
    "provider_attempt_timeout",
    "provider_invalid_request",
    "provider_authentication_failed",
    "provider_permission_denied",
    "provider_not_found",
    "provider_rate_limited",
    "provider_quota_exhausted",
    "provider_content_rejected",
    "provider_upstream_unavailable",
    "provider_protocol_violation",
    "provider_response_limit",
    "provider_internal",
];

/// A stable provider failure classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum ProviderFailureClass {
    /// The caller or consumer cancelled work.
    Cancelled = 0,
    /// The overall request deadline expired.
    DeadlineExceeded = 1,
    /// A bounded per-attempt timeout expired while the overall request may continue.
    AttemptTimeout = 2,
    /// The provider rejected the request shape or semantics.
    InvalidRequest = 3,
    /// The provider rejected authentication evidence.
    Authentication = 4,
    /// The provider denied the authenticated action.
    PermissionDenied = 5,
    /// The selected provider resource does not exist.
    NotFound = 6,
    /// The provider applied a rate limit.
    RateLimited = 7,
    /// The selected provider account exhausted quota.
    QuotaExhausted = 8,
    /// The provider rejected content under its policy.
    ContentRejected = 9,
    /// The upstream provider or transport is unavailable.
    UpstreamUnavailable = 10,
    /// The upstream response violated the selected protocol contract.
    ProtocolViolation = 11,
    /// A response exceeded a configured byte, event, or token limit.
    ResponseLimit = 12,
    /// The adapter encountered an unclassified internal failure.
    Internal = 13,
}

impl ProviderFailureClass {
    /// Returns the stable machine code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        PROVIDER_FAILURE_CODES
            .get(self as usize)
            .copied()
            .unwrap_or("provider_internal")
    }
}

/// A provider hint that never grants retry authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderRetryAdvice {
    /// No transparent retry is safe from the recorded facts.
    Never,
    /// The same provider may be considered by later routing policy.
    SameProvider,
    /// Another provider may be considered by later routing policy.
    AlternateProvider,
    /// The same provider may be considered after a bounded delay.
    After(Duration),
}

/// A redacted provider failure with immutable attempt evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderFailure {
    class: ProviderFailureClass,
    progress: ProviderAttemptProgress,
    retry_after: Option<Duration>,
}

impl ProviderFailure {
    /// Creates a classified failure without raw provider diagnostics.
    #[must_use]
    pub const fn new(class: ProviderFailureClass, progress: ProviderAttemptProgress) -> Self {
        Self {
            class,
            progress,
            retry_after: None,
        }
    }

    /// Attaches a provider retry delay within the 24-hour hard bound.
    pub fn with_retry_after(
        mut self,
        retry_after: Duration,
    ) -> Result<Self, ProviderContractError> {
        if retry_after > MAX_PROVIDER_RETRY_AFTER {
            return Err(ProviderContractError::new(
                ProviderContractErrorCode::LimitExceeded,
            ));
        }
        self.retry_after = Some(retry_after);
        Ok(self)
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn class(self) -> ProviderFailureClass {
        self.class
    }

    /// Returns the stable machine code.
    #[must_use]
    pub fn code(self) -> &'static str {
        self.class.as_str()
    }

    /// Returns immutable attempt evidence captured for this failure.
    #[must_use]
    pub const fn progress(self) -> ProviderAttemptProgress {
        self.progress
    }

    /// Returns the bounded retry delay supplied by the provider.
    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        self.retry_after
    }

    /// Derives factual retry advice from the failure and replayability evidence.
    ///
    /// Routing remains responsible for deadline checks, account selection,
    /// attempt budgets, billing, and the final retry decision.
    #[must_use]
    pub const fn retry_advice(self, replayable: bool) -> ProviderRetryAdvice {
        if response_started(self.progress) {
            return ProviderRetryAdvice::Never;
        }
        if !transmission_allows_retry(self.progress.transmission(), replayable) {
            return ProviderRetryAdvice::Never;
        }
        class_advice(self.class, self.retry_after)
    }
}

impl Display for ProviderFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.class.as_str())
    }
}

impl std::error::Error for ProviderFailure {}

const fn response_started(progress: ProviderAttemptProgress) -> bool {
    progress.upstream_response_started() || progress.downstream_delivery_started()
}

const fn transmission_allows_retry(transmission: ProviderTransmission, replayable: bool) -> bool {
    match transmission {
        ProviderTransmission::NotStarted => true,
        ProviderTransmission::Started | ProviderTransmission::Committed => replayable,
        ProviderTransmission::Unknown => false,
    }
}

const fn class_advice(
    class: ProviderFailureClass,
    retry_after: Option<Duration>,
) -> ProviderRetryAdvice {
    match (class, retry_after) {
        (ProviderFailureClass::RateLimited, Some(delay)) => ProviderRetryAdvice::After(delay),
        (ProviderFailureClass::RateLimited, None)
        | (ProviderFailureClass::QuotaExhausted, _)
        | (ProviderFailureClass::AttemptTimeout, _)
        | (ProviderFailureClass::UpstreamUnavailable, _) => ProviderRetryAdvice::AlternateProvider,
        _ => ProviderRetryAdvice::Never,
    }
}

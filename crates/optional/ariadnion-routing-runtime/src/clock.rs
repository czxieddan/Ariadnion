// crates/optional/ariadnion-routing-runtime/src/clock.rs - Runtime monotonic clocks for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Runtime monotonic clock interfaces and process-local implementation.

use std::fmt::{self, Display, Formatter};
use std::time::Instant;

use ariadnion_rate_limit::MonotonicTime;

/// Redacted failure returned by a monotonic clock implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeMonotonicClockError;

impl Display for RuntimeMonotonicClockError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ROUTING_RUNTIME_MONOTONIC_CLOCK_UNAVAILABLE")
    }
}

impl std::error::Error for RuntimeMonotonicClockError {}

/// Adapter-owned monotonic clock sharing the origin used by admission requests.
pub trait RuntimeMonotonicClock: Send + Sync {
    /// Samples nanoseconds from the clock's stable origin.
    ///
    /// # Errors
    /// Returns a redacted error when a monotonic observation is unavailable.
    fn now(&self) -> Result<MonotonicTime, RuntimeMonotonicClockError>;
}

/// Process-local monotonic clock backed by one stable [`Instant`] origin.
///
/// Callers must use observations from this same instance when constructing
/// admission requests passed to a runtime that owns it.
#[derive(Clone, Debug)]
pub struct ProcessMonotonicClock {
    origin: Instant,
}

impl ProcessMonotonicClock {
    /// Creates a clock whose zero point is the current process-local instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for ProcessMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeMonotonicClock for ProcessMonotonicClock {
    fn now(&self) -> Result<MonotonicTime, RuntimeMonotonicClockError> {
        u64::try_from(self.origin.elapsed().as_nanos())
            .map(MonotonicTime::from_nanos)
            .map_err(|_| RuntimeMonotonicClockError)
    }
}

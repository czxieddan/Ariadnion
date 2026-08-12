// crates/optional/ariadnion-provider-http/src/shutdown.rs - Provider HTTP pool shutdown for Ariadnion.
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

//! Admission stop, bounded drain, forced abort, and owned driver joins.

use std::time::Duration;

use crate::error::{ProviderHttpError, ProviderHttpErrorCode};
use crate::pool::{
    PoolInner, begin_shutdown, collect_shutdown_drivers, complete_shutdown, drain_complete,
    force_shutdown, forced_cleanup_complete,
};

const MAX_SHUTDOWN_MILLIS: u128 = 60_000;

/// Immutable outcome of one bounded pool shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderHttpShutdownReport {
    idle_closed: usize,
    active_aborted: usize,
    drivers_joined: usize,
    deadline_reached: bool,
}

impl ProviderHttpShutdownReport {
    /// Returns the number of idle connections closed when draining began.
    #[must_use]
    pub const fn idle_closed(self) -> usize {
        self.idle_closed
    }

    /// Returns the number of live connections force-aborted at the deadline.
    #[must_use]
    pub const fn active_aborted(self) -> usize {
        self.active_aborted
    }

    /// Returns the number of owned HTTP/1 driver tasks joined before return.
    #[must_use]
    pub const fn drivers_joined(self) -> usize {
        self.drivers_joined
    }

    /// Returns whether the drain budget elapsed before all admitted operations
    /// and live or reserved connection slots exited.
    #[must_use]
    pub const fn deadline_reached(self) -> bool {
        self.deadline_reached
    }
}

pub(crate) async fn shutdown_pool(
    inner: &PoolInner,
    budget: Duration,
) -> Result<ProviderHttpShutdownReport, ProviderHttpError> {
    validate_budget(budget)?;
    let idle_closed = begin_shutdown(inner);
    let deadline_reached = tokio::time::timeout(budget, wait_for_drain(inner))
        .await
        .is_err();
    let active_aborted = finish_drain(inner, deadline_reached).await;
    let drivers = collect_shutdown_drivers(inner);
    let drivers_joined = join_drivers(drivers).await;
    Ok(ProviderHttpShutdownReport {
        idle_closed,
        active_aborted,
        drivers_joined,
        deadline_reached,
    })
}

fn validate_budget(budget: Duration) -> Result<(), ProviderHttpError> {
    if budget.is_zero() || budget.as_millis() > MAX_SHUTDOWN_MILLIS {
        return Err(ProviderHttpError::new(
            ProviderHttpErrorCode::InvalidTimeout,
        ));
    }
    Ok(())
}

async fn wait_for_drain(inner: &PoolInner) {
    wait_for_state(inner, drain_complete).await;
}

async fn finish_drain(inner: &PoolInner, deadline_reached: bool) -> usize {
    if !deadline_reached {
        complete_shutdown(inner);
        return 0;
    }
    let active_aborted = force_shutdown(inner);
    wait_for_state(inner, forced_cleanup_complete).await;
    active_aborted
}

async fn wait_for_state(inner: &PoolInner, complete: fn(&PoolInner) -> bool) {
    loop {
        let notified = inner.changed.notified();
        let mut notified = std::pin::pin!(notified);
        let _enabled = notified.as_mut().enable();
        if complete(inner) {
            return;
        }
        notified.await;
    }
}

async fn join_drivers(drivers: Vec<tokio::task::JoinHandle<()>>) -> usize {
    let count = drivers.len();
    for driver in drivers {
        let _result = driver.await;
    }
    count
}

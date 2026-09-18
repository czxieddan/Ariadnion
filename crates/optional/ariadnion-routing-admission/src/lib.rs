// crates/optional/ariadnion-routing-admission/src/lib.rs - Composed routing admission for Ariadnion.
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
//! Fail-closed composition of routing rate, concurrency, and account budgets.
//!
//! Admission first acquires a pending rate/concurrency lease and then reserves
//! the typed budget request. A budget rejection cancels the pending rate lease
//! before the error is returned. This crate is an in-process coordinator; it does
//! not claim durable publication or cross-process transaction semantics.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use ariadnion_account_budget::{
    BudgetBook, BudgetError, BudgetErrorCode, ReservationId, ReservationReceipt,
    ReservationRequest, UnixTimeSeconds,
};
use ariadnion_rate_limit::{
    AdmissionController, AdmissionError, AdmissionErrorCode, AdmissionLease, AdmissionRequest,
    MonotonicTime,
};

/// Stable machine-readable failures for composed routing admission.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RoutingAdmissionErrorCode {
    /// An input was malformed or outside a component's bound.
    InvalidArgument,
    /// The rate window has no remaining capacity.
    RateLimited,
    /// The concurrency limit has no remaining permit.
    ConcurrencyLimited,
    /// The account budget rejected the reservation.
    BudgetRejected,
    /// A tenant-scoped rate key disagreed with the budget tenant.
    TenantMismatch,
    /// A component's state could not be accessed safely.
    StateUnavailable,
    /// The supplied monotonic observation moved backward.
    ClockRegressed,
    /// A lease expired before its lifecycle transition.
    LeaseExpired,
    /// A lease was already finalized.
    LeaseClosed,
    /// A cross-component commit did not complete atomically.
    CommitIncomplete,
    /// Rate rollback failed after budget reservation failed.
    RollbackFailed,
}

impl RoutingAdmissionErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ROUTING_ADMISSION_INVALID_ARGUMENT",
            Self::RateLimited => "ROUTING_ADMISSION_RATE_LIMITED",
            Self::ConcurrencyLimited => "ROUTING_ADMISSION_CONCURRENCY_LIMITED",
            Self::BudgetRejected => "ROUTING_ADMISSION_BUDGET_REJECTED",
            Self::TenantMismatch => "ROUTING_ADMISSION_TENANT_MISMATCH",
            Self::StateUnavailable => "ROUTING_ADMISSION_STATE_UNAVAILABLE",
            other => other.as_tail_str(),
        }
    }

    const fn as_tail_str(self) -> &'static str {
        match self {
            Self::ClockRegressed => "ROUTING_ADMISSION_CLOCK_REGRESSED",
            Self::LeaseExpired => "ROUTING_ADMISSION_LEASE_EXPIRED",
            Self::LeaseClosed => "ROUTING_ADMISSION_LEASE_CLOSED",
            Self::CommitIncomplete => "ROUTING_ADMISSION_COMMIT_INCOMPLETE",
            Self::RollbackFailed => "ROUTING_ADMISSION_ROLLBACK_FAILED",
            _ => "ROUTING_ADMISSION_INVALID_ARGUMENT",
        }
    }
}

/// Redacted composed-admission failure with bounded retry guidance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingAdmissionError {
    code: RoutingAdmissionErrorCode,
    retry_after: Option<Duration>,
}

impl RoutingAdmissionError {
    const fn new(code: RoutingAdmissionErrorCode, retry_after: Option<Duration>) -> Self {
        Self { code, retry_after }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> RoutingAdmissionErrorCode {
        self.code
    }

    /// Returns the minimum known wait before retrying, when available.
    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        self.retry_after
    }
}

impl Display for RoutingAdmissionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for RoutingAdmissionError {}

/// Immutable input to one composed admission attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingAdmissionRequest {
    rate: AdmissionRequest,
    budget: ReservationRequest,
    monotonic_now: MonotonicTime,
    budget_now: UnixTimeSeconds,
}

impl Debug for RoutingAdmissionRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingAdmissionRequest")
            .field("rate_dimension_count", &self.rate.keys().len())
            .field("rate_units", &self.rate.units().get())
            .field("budget_amount_present", &true)
            .field("budget_expires_at", &self.budget.expires_at())
            .field("monotonic_now", &self.monotonic_now)
            .field("budget_now", &self.budget_now)
            .finish()
    }
}

impl RoutingAdmissionRequest {
    /// Creates a request using explicit monotonic and UTC observations.
    #[must_use]
    pub const fn new(
        rate: AdmissionRequest,
        budget: ReservationRequest,
        monotonic_now: MonotonicTime,
        budget_now: UnixTimeSeconds,
    ) -> Self {
        Self {
            rate,
            budget,
            monotonic_now,
            budget_now,
        }
    }

    /// Returns the rate and concurrency request.
    #[must_use]
    pub const fn rate(&self) -> &AdmissionRequest {
        &self.rate
    }

    /// Returns the typed budget reservation request.
    #[must_use]
    pub const fn budget(&self) -> &ReservationRequest {
        &self.budget
    }

    /// Returns the caller-observed monotonic time.
    #[must_use]
    pub const fn monotonic_now(&self) -> MonotonicTime {
        self.monotonic_now
    }

    /// Returns the caller-observed UTC budget time.
    #[must_use]
    pub const fn budget_now(&self) -> UnixTimeSeconds {
        self.budget_now
    }
}

/// Coordinator for rate/concurrency and account-budget admission.
#[derive(Clone, Debug)]
pub struct RoutingAdmissionCoordinator {
    rate: AdmissionController,
    budget: Arc<BudgetBook>,
}

/// Observable lifecycle state of a coupled admission lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RoutingAdmissionLeaseState {
    /// Budget and rate/concurrency capacity are reserved but not finalized.
    Pending,
    /// Budget usage is committed and rate usage is charged; concurrency is released.
    Committed,
    /// Budget usage is committed but the rate transition did not complete.
    ReconciliationRequired,
}

impl RoutingAdmissionCoordinator {
    /// Creates a coordinator from independent in-process component stores.
    #[must_use]
    pub fn new(rate: AdmissionController, budget: BudgetBook) -> Self {
        Self {
            rate,
            budget: Arc::new(budget),
        }
    }

    /// Reserves both dimensions and returns their coupled lifecycle lease.
    ///
    /// The rate lease remains pending until [`RoutingAdmissionLease::commit`].
    /// If the budget reservation fails, the pending rate lease is cancelled and
    /// all capacity is restored before the rejection is returned. A failed
    /// rollback is reported as [`RoutingAdmissionErrorCode::RollbackFailed`].
    ///
    /// This method is intentionally local and in-memory; it does not publish a
    /// durable intent or provide a cross-process transaction guarantee.
    pub fn admit(
        &self,
        request: RoutingAdmissionRequest,
    ) -> Result<RoutingAdmissionLease, RoutingAdmissionError> {
        validate_tenant_binding(&request)?;
        let rate_lease = self
            .rate
            .try_admit(request.rate(), request.monotonic_now())
            .map_err(map_rate_error)?;
        let receipt = match self
            .budget
            .reserve(request.budget().clone(), request.budget_now())
        {
            Ok(receipt) => receipt,
            Err(budget_error) => {
                let rollback = rate_lease.cancel(request.monotonic_now());
                if rollback.is_err() {
                    return Err(error(RoutingAdmissionErrorCode::RollbackFailed));
                }
                return Err(map_budget_error(budget_error));
            }
        };
        Ok(RoutingAdmissionLease {
            rate: Some(rate_lease),
            budget: Arc::clone(&self.budget),
            reservation_id: receipt.id().clone(),
            budget_receipt: receipt,
            budget_finalized: false,
            closed: false,
            state: RoutingAdmissionLeaseState::Pending,
        })
    }
}

fn validate_tenant_binding(request: &RoutingAdmissionRequest) -> Result<(), RoutingAdmissionError> {
    let budget_tenant = request.budget().context().tenant_id().as_str();
    for key in request.rate().keys() {
        let key_tenant = match key {
            ariadnion_rate_limit::LimitKey::Tenant(tenant) => Some(tenant.as_str()),
            ariadnion_rate_limit::LimitKey::Account(account) => Some(account.tenant().as_str()),
            _ => None,
        };
        if key_tenant.is_some_and(|tenant| tenant != budget_tenant) {
            return Err(error(RoutingAdmissionErrorCode::TenantMismatch));
        }
    }
    Ok(())
}

/// Coupled lifecycle handle for one successful composed admission.
pub struct RoutingAdmissionLease {
    rate: Option<AdmissionLease>,
    budget: Arc<BudgetBook>,
    reservation_id: ReservationId,
    budget_receipt: ReservationReceipt,
    budget_finalized: bool,
    closed: bool,
    state: RoutingAdmissionLeaseState,
}

impl RoutingAdmissionLease {
    /// Returns the current budget reservation receipt.
    #[must_use]
    pub const fn budget_receipt(&self) -> &ReservationReceipt {
        &self.budget_receipt
    }

    /// Returns the coupled lease lifecycle state.
    #[must_use]
    pub const fn state(&self) -> RoutingAdmissionLeaseState {
        self.state
    }

    /// Commits budget usage and then permanently charges the rate window.
    ///
    /// A rate-side failure after the budget commit returns
    /// [`RoutingAdmissionErrorCode::CommitIncomplete`] and never reports
    /// success, because the two component stores cannot provide a shared
    /// transaction in this local coordinator.
    pub fn commit(&mut self, now: MonotonicTime) -> Result<(), RoutingAdmissionError> {
        self.ensure_open()?;
        self.commit_budget()?;
        self.commit_rate_and_release(now)?;
        self.state = RoutingAdmissionLeaseState::Committed;
        self.closed = true;
        Ok(())
    }

    fn commit_budget(&mut self) -> Result<(), RoutingAdmissionError> {
        let receipt = self
            .budget
            .commit(self.reservation_id.clone())
            .map_err(map_budget_lifecycle_error)?;
        self.budget_receipt = receipt;
        self.budget_finalized = true;
        Ok(())
    }

    fn commit_rate_and_release(&mut self, now: MonotonicTime) -> Result<(), RoutingAdmissionError> {
        let Some(mut rate) = self.rate.take() else {
            return self.commit_incomplete();
        };
        if rate.commit_rate(now).is_err() {
            drop(rate);
            return self.commit_incomplete();
        }
        if rate.release(now).is_err() {
            return self.commit_incomplete();
        }
        Ok(())
    }

    fn commit_incomplete(&mut self) -> Result<(), RoutingAdmissionError> {
        self.mark_reconciliation_required();
        Err(error(RoutingAdmissionErrorCode::CommitIncomplete))
    }

    /// Releases budget capacity and the rate/concurrency lease.
    pub fn release(mut self, now: MonotonicTime) -> Result<(), RoutingAdmissionError> {
        self.ensure_open()?;
        let receipt = self
            .budget
            .release(self.reservation_id.clone())
            .map_err(map_budget_lifecycle_error)?;
        self.budget_receipt = receipt;
        self.budget_finalized = true;
        let Some(rate) = self.rate.take() else {
            return Err(error(RoutingAdmissionErrorCode::LeaseClosed));
        };
        rate.release(now).map_err(map_rate_error)?;
        self.closed = true;
        Ok(())
    }

    /// Cancels the lease, releasing both dimensions.
    pub fn cancel(self, now: MonotonicTime) -> Result<(), RoutingAdmissionError> {
        self.release(now)
    }

    fn ensure_open(&self) -> Result<(), RoutingAdmissionError> {
        if self.closed {
            Err(error(RoutingAdmissionErrorCode::LeaseClosed))
        } else {
            Ok(())
        }
    }

    fn mark_reconciliation_required(&mut self) {
        self.state = RoutingAdmissionLeaseState::ReconciliationRequired;
        self.closed = true;
    }
}

impl Debug for RoutingAdmissionLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingAdmissionLease")
            .field("budget_state", &self.budget_receipt.state())
            .field("budget_finalized", &self.budget_finalized)
            .field("state", &self.state)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Drop for RoutingAdmissionLease {
    fn drop(&mut self) {
        if !self.budget_finalized {
            let _ = self.budget.release(self.reservation_id.clone());
        }
    }
}

fn error(code: RoutingAdmissionErrorCode) -> RoutingAdmissionError {
    RoutingAdmissionError::new(code, None)
}

fn map_rate_error(value: AdmissionError) -> RoutingAdmissionError {
    let code = match value.code() {
        AdmissionErrorCode::RateLimited => RoutingAdmissionErrorCode::RateLimited,
        AdmissionErrorCode::ConcurrencyLimited => RoutingAdmissionErrorCode::ConcurrencyLimited,
        AdmissionErrorCode::ClockRegressed => RoutingAdmissionErrorCode::ClockRegressed,
        AdmissionErrorCode::LeaseExpired => RoutingAdmissionErrorCode::LeaseExpired,
        AdmissionErrorCode::LeaseClosed => RoutingAdmissionErrorCode::LeaseClosed,
        AdmissionErrorCode::StateUnavailable => RoutingAdmissionErrorCode::StateUnavailable,
        _ => RoutingAdmissionErrorCode::InvalidArgument,
    };
    RoutingAdmissionError::new(code, value.retry_after())
}

fn map_budget_error(value: BudgetError) -> RoutingAdmissionError {
    if value.code() == BudgetErrorCode::StateUnavailable {
        error(RoutingAdmissionErrorCode::StateUnavailable)
    } else {
        error(RoutingAdmissionErrorCode::BudgetRejected)
    }
}

fn map_budget_lifecycle_error(value: BudgetError) -> RoutingAdmissionError {
    match value.code() {
        BudgetErrorCode::StateUnavailable => error(RoutingAdmissionErrorCode::StateUnavailable),
        BudgetErrorCode::ReservationFinalized | BudgetErrorCode::ReservationNotFound => {
            error(RoutingAdmissionErrorCode::LeaseClosed)
        }
        _ => error(RoutingAdmissionErrorCode::CommitIncomplete),
    }
}

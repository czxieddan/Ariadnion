// crates/optional/ariadnion-rate-limit/src/controller.rs - Rate and concurrency lifecycle for Ariadnion.
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

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard};

use super::{
    AdmissionError, AdmissionErrorCode, AdmissionLeaseId, AdmissionPolicySet, AdmissionRequest,
    ConcurrencyPermit, LimitKey, LimitPolicy, LimitSnapshot, MonotonicTime, RateReservation,
    RateReservationId, RateRule, error, exhausted, invalid, refusal_scope,
};

/// Thread-safe atomic admission controller over an immutable policy set.
#[derive(Clone)]
pub struct AdmissionController {
    inner: Arc<ControllerInner>,
}

/// Terminal disposition of one physically accepted admission lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AcceptedFinalization {
    /// Rate usage was charged and concurrency was released.
    Completed,
    /// Rate usage was charged while concurrency remains until the original expiry.
    ReconciliationRequired,
}

impl AdmissionController {
    /// Creates an empty controller at a caller-observed monotonic time.
    #[must_use]
    pub fn new(policies: AdmissionPolicySet, initial_now: MonotonicTime) -> Self {
        Self {
            inner: Arc::new(ControllerInner {
                policies,
                state: Mutex::new(ControllerState::new(initial_now)),
            }),
        }
    }

    /// Atomically reserves all requested rate and concurrency dimensions.
    ///
    /// Rate use remains pending until [`AdmissionLease::commit_rate`] succeeds.
    /// Dropping or cancelling an uncommitted lease refunds its pending rate use;
    /// committed use remains charged until its fixed window ends.
    ///
    /// # Errors
    /// Returns a stable redacted error without partially consuming capacity.
    pub fn try_admit(
        &self,
        request: &AdmissionRequest,
        now: MonotonicTime,
    ) -> Result<AdmissionLease, AdmissionError> {
        let prepared = self.inner.prepare_admission(request, now)?;
        Ok(AdmissionLease {
            inner: Arc::clone(&self.inner),
            id: prepared.lease_id,
            expires_at: prepared.expires_at,
            reservation: prepared.reservation,
            permits: prepared.permits,
            closed: false,
        })
    }

    /// Reads remaining capacity after applying expiry and window rollover.
    ///
    /// # Errors
    /// Returns a stable error for missing policy, clock regression, or state loss.
    pub fn snapshot(
        &self,
        key: &LimitKey,
        now: MonotonicTime,
    ) -> Result<LimitSnapshot, AdmissionError> {
        let policy = self
            .inner
            .policies
            .policy(key)
            .ok_or_else(|| error(AdmissionErrorCode::PolicyNotFound))?;
        let mut state = self.inner.lock_state()?;
        state.observe_and_expire(now)?;
        state.prepare_window(policy, now)?;
        Ok(state.snapshot(policy, now))
    }
}

impl Debug for AdmissionController {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionController(<shared-state>)")
    }
}

/// Owning admission lease for pending rate use and concurrency permits.
pub struct AdmissionLease {
    inner: Arc<ControllerInner>,
    id: AdmissionLeaseId,
    expires_at: MonotonicTime,
    reservation: Option<RateReservation>,
    permits: Vec<ConcurrencyPermit>,
    closed: bool,
}

impl AdmissionLease {
    /// Returns the process-local lease identity.
    #[must_use]
    pub const fn id(&self) -> AdmissionLeaseId {
        self.id
    }

    /// Returns the pending reservation, when any requested policy has a rate rule.
    #[must_use]
    pub const fn reservation(&self) -> Option<&RateReservation> {
        self.reservation.as_ref()
    }

    /// Returns typed concurrency permits in request order.
    #[must_use]
    pub fn permits(&self) -> &[ConcurrencyPermit] {
        &self.permits
    }

    /// Returns the exclusive monotonic lease expiry.
    #[must_use]
    pub const fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }

    /// Permanently charges pending rate units while retaining concurrency permits.
    ///
    /// Repeating a successful commit is idempotent. Cancellation or release after
    /// commit does not refund charged rate units.
    ///
    /// # Errors
    /// Returns a stable error for expiry, closure, clock regression, or state loss.
    pub fn commit_rate(&mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        self.ensure_open()?;
        let mut state = self.inner.lock_state()?;
        state.observe_and_expire(now)?;
        state.commit_rate(self.id)?;
        Ok(())
    }

    /// Finalizes capacity for a provider execution known to be accepted.
    ///
    /// A reliable observation commits rate usage and releases concurrency in one
    /// controller critical section. Without a reliable observation, or when the
    /// observation regresses, rate usage is committed without releasing the
    /// concurrency permit. The retained permit expires at its original bound.
    /// This method consumes the lease and detaches it from ordinary drop cleanup
    /// before returning any error.
    ///
    /// # Errors
    /// Returns a stable expiry, closure, counter, or state error. An error never
    /// triggers ordinary drop compensation for this accepted execution.
    pub fn finalize_accepted(
        mut self,
        now: Option<MonotonicTime>,
    ) -> Result<AcceptedFinalization, AdmissionError> {
        self.ensure_open()?;
        let result = self.inner.finalize_accepted(self.id, now);
        self.closed = true;
        result
    }

    /// Charges pending rate usage while retaining concurrency until lease expiry.
    ///
    /// This cancellation-safe terminal path is for a physical dispatch whose
    /// acceptance became unknowable. The lease is detached from ordinary drop
    /// cleanup even when the rate transition fails, so concurrency cannot be
    /// reused before the original exclusive expiry. A later controller
    /// observation expires the retained lease and releases its permits. If the
    /// caller's dispatch-time fallback predates another accepted controller
    /// observation, the existing active lease authorizes a no-time rate commit;
    /// an already expired lease is never recreated.
    ///
    /// # Errors
    /// Returns a stable rate, clock, expiry, closure, or state error. On error,
    /// the lease still remains retained until its original expiry whenever its
    /// authoritative state record exists.
    pub fn commit_rate_and_retain_concurrency(
        mut self,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        self.ensure_open()?;
        let result = self.inner.retain_dispatched(self.id, now);
        self.closed = true;
        result
    }

    /// Releases concurrency and refunds rate units only when not yet committed.
    ///
    /// # Errors
    /// Returns a stable error for expiry, closure, clock regression, or state loss.
    pub fn release(mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        self.close(now)
    }

    /// Cancels the lease with the same capacity behavior as release.
    ///
    /// Cancellation is explicit for request-lifetime propagation. Pending rate
    /// units are refunded; committed units remain charged.
    ///
    /// # Errors
    /// Returns a stable error for expiry, closure, clock regression, or state loss.
    pub fn cancel(mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        self.close(now)
    }

    fn close(&mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        self.ensure_open()?;
        let result = self.inner.close_lease(self.id, now);
        if result.is_ok()
            || matches!(result, Err(value) if value.code() == AdmissionErrorCode::LeaseExpired)
        {
            self.closed = true;
        }
        result
    }

    fn ensure_open(&self) -> Result<(), AdmissionError> {
        if self.closed {
            Err(error(AdmissionErrorCode::LeaseClosed))
        } else {
            Ok(())
        }
    }
}

impl Debug for AdmissionLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmissionLease")
            .field("id", &self.id)
            .field("expires_at", &self.expires_at)
            .field("reservation", &self.reservation)
            .field("permit_count", &self.permits.len())
            .field("closed", &self.closed)
            .finish()
    }
}

impl Drop for AdmissionLease {
    fn drop(&mut self) {
        if !self.closed {
            self.inner.close_lease_without_time(self.id);
            self.closed = true;
        }
    }
}

// The single controller lock protects all counters and leases. It is never held
// across external calls; poison fails closed without compensating accepted work.
struct ControllerInner {
    policies: AdmissionPolicySet,
    state: Mutex<ControllerState>,
}

impl ControllerInner {
    fn lock_state(&self) -> Result<MutexGuard<'_, ControllerState>, AdmissionError> {
        self.state
            .lock()
            .map_err(|_| error(AdmissionErrorCode::StateUnavailable))
    }

    fn resolve_policies<'a>(
        &'a self,
        request: &AdmissionRequest,
    ) -> Result<Vec<&'a LimitPolicy>, AdmissionError> {
        request
            .keys()
            .iter()
            .map(|key| {
                self.policies
                    .policy(key)
                    .ok_or_else(|| error(AdmissionErrorCode::PolicyNotFound))
            })
            .collect()
    }

    fn prepare_admission(
        &self,
        request: &AdmissionRequest,
        now: MonotonicTime,
    ) -> Result<PreparedAdmission, AdmissionError> {
        let policies = self.resolve_policies(request)?;
        let mut state = self.lock_state()?;
        state.prepare_admission(&policies, request, now)
    }

    fn close_lease(&self, id: AdmissionLeaseId, now: MonotonicTime) -> Result<(), AdmissionError> {
        let mut state = self.lock_state()?;
        state.observe_and_expire(now)?;
        if state.remove_lease(id) {
            Ok(())
        } else {
            Err(error(AdmissionErrorCode::LeaseExpired))
        }
    }

    fn close_lease_without_time(&self, id: AdmissionLeaseId) {
        if let Ok(mut state) = self.state.lock() {
            state.remove_lease(id);
        }
    }

    fn retain_dispatched(
        &self,
        id: AdmissionLeaseId,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        let mut state = self.lock_state()?;
        state.retain_dispatched(id, now)
    }

    fn finalize_accepted(
        &self,
        id: AdmissionLeaseId,
        now: Option<MonotonicTime>,
    ) -> Result<AcceptedFinalization, AdmissionError> {
        let mut state = self.lock_state()?;
        state.finalize_accepted(id, now)
    }
}

struct ControllerState {
    last_now: MonotonicTime,
    next_identity: u64,
    windows: BTreeMap<LimitKey, RateWindowState>,
    concurrency: BTreeMap<LimitKey, u32>,
    leases: BTreeMap<AdmissionLeaseId, ActiveLease>,
}

impl ControllerState {
    fn new(initial_now: MonotonicTime) -> Self {
        Self {
            last_now: initial_now,
            next_identity: 0,
            windows: BTreeMap::new(),
            concurrency: BTreeMap::new(),
            leases: BTreeMap::new(),
        }
    }

    fn prepare_admission(
        &mut self,
        policies: &[&LimitPolicy],
        request: &AdmissionRequest,
        now: MonotonicTime,
    ) -> Result<PreparedAdmission, AdmissionError> {
        self.observe_and_expire(now)?;
        self.prepare_windows(policies, now)?;
        self.check_capacity(policies, request, now)?;
        let (reservation_id, lease_id) = self.allocate_identities()?;
        let expires_at = self.lease_expiry(policies, now)?;
        let parts = self.reserve(policies, request, reservation_id, lease_id, expires_at)?;
        Ok(PreparedAdmission {
            lease_id,
            expires_at,
            reservation: parts.reservation,
            permits: parts.permits,
        })
    }

    fn observe_and_expire(&mut self, now: MonotonicTime) -> Result<(), AdmissionError> {
        if now < self.last_now {
            return Err(error(AdmissionErrorCode::ClockRegressed));
        }
        self.last_now = now;
        let expired: Vec<_> = self
            .leases
            .iter()
            .filter_map(|(id, lease)| (lease.expires_at <= now).then_some(*id))
            .collect();
        for id in expired {
            self.remove_lease(id);
        }
        Ok(())
    }

    fn prepare_windows(
        &mut self,
        policies: &[&LimitPolicy],
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        for policy in policies {
            if let Some(rule) = policy.rate {
                now.checked_add(rule.window)?;
            }
        }
        for policy in policies {
            self.prepare_window(policy, now)?;
        }
        Ok(())
    }

    fn prepare_window(
        &mut self,
        policy: &LimitPolicy,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        let Some(rule) = policy.rate else {
            return Ok(());
        };
        let window = self
            .windows
            .entry(policy.key.clone())
            .or_insert(RateWindowState::new(now, rule)?);
        if window.ends_at <= now {
            *window = RateWindowState::new(now, rule)?;
        }
        Ok(())
    }

    fn check_capacity(
        &self,
        policies: &[&LimitPolicy],
        request: &AdmissionRequest,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        for policy in policies {
            self.check_rate(policy, request.units(), now)?;
            self.check_concurrency(policy, now)?;
        }
        Ok(())
    }

    fn check_rate(
        &self,
        policy: &LimitPolicy,
        units: NonZeroU32,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        let Some(rule) = policy.rate else {
            return Ok(());
        };
        let Some(window) = self.windows.get(&policy.key) else {
            return Err(error(AdmissionErrorCode::StateUnavailable));
        };
        let used = window.committed.saturating_add(window.pending);
        let remaining = rule.capacity.get().saturating_sub(used);
        if units.get() > remaining {
            return Err(AdmissionError::with_scope(
                AdmissionErrorCode::RateLimited,
                Some(now.duration_until(window.ends_at)),
                refusal_scope(policy.key.dimension()),
            ));
        }
        Ok(())
    }

    fn check_concurrency(
        &self,
        policy: &LimitPolicy,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        let Some(rule) = policy.concurrency else {
            return Ok(());
        };
        let active = self.concurrency.get(&policy.key).copied().unwrap_or(0);
        if active < rule.limit.get() {
            return Ok(());
        }
        let retry_after = self
            .earliest_expiry(&policy.key)
            .map(|at| now.duration_until(at));
        Err(AdmissionError::with_scope(
            AdmissionErrorCode::ConcurrencyLimited,
            retry_after,
            refusal_scope(policy.key.dimension()),
        ))
    }

    fn earliest_expiry(&self, key: &LimitKey) -> Option<MonotonicTime> {
        self.leases
            .values()
            .filter(|lease| lease.concurrency_keys.contains(key))
            .map(|lease| lease.expires_at)
            .min()
    }

    fn allocate_identities(
        &mut self,
    ) -> Result<(RateReservationId, AdmissionLeaseId), AdmissionError> {
        let reservation = self.next_identity.checked_add(1).ok_or_else(exhausted)?;
        let lease = reservation.checked_add(1).ok_or_else(exhausted)?;
        self.next_identity = lease;
        Ok((RateReservationId(reservation), AdmissionLeaseId(lease)))
    }

    fn reserve(
        &mut self,
        policies: &[&LimitPolicy],
        request: &AdmissionRequest,
        reservation_id: RateReservationId,
        lease_id: AdmissionLeaseId,
        expires_at: MonotonicTime,
    ) -> Result<ReservedParts, AdmissionError> {
        let rate_keys = rate_keys(policies);
        let concurrency_keys = concurrency_keys(policies);
        self.add_pending(&rate_keys, request.units())?;
        self.add_concurrency(&concurrency_keys)?;
        self.leases.insert(
            lease_id,
            ActiveLease {
                rate_keys: rate_keys.clone(),
                concurrency_keys: concurrency_keys.clone(),
                units: request.units(),
                expires_at,
                rate_committed: false,
            },
        );
        Ok(ReservedParts {
            reservation: (!rate_keys.is_empty()).then_some(RateReservation {
                id: reservation_id,
                keys: rate_keys,
                units: request.units(),
                expires_at,
            }),
            permits: concurrency_keys
                .into_iter()
                .map(|key| ConcurrencyPermit {
                    lease_id,
                    key,
                    expires_at,
                })
                .collect(),
        })
    }

    fn add_pending(&mut self, keys: &[LimitKey], units: NonZeroU32) -> Result<(), AdmissionError> {
        self.validate_pending_addition(keys, units)?;
        self.apply_pending_addition(keys, units)
    }

    fn validate_pending_addition(
        &self,
        keys: &[LimitKey],
        units: NonZeroU32,
    ) -> Result<(), AdmissionError> {
        for key in keys {
            let Some(window) = self.windows.get(key) else {
                return Err(error(AdmissionErrorCode::StateUnavailable));
            };
            window
                .pending
                .checked_add(units.get())
                .ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn apply_pending_addition(
        &mut self,
        keys: &[LimitKey],
        units: NonZeroU32,
    ) -> Result<(), AdmissionError> {
        for key in keys {
            let Some(window) = self.windows.get_mut(key) else {
                return Err(error(AdmissionErrorCode::StateUnavailable));
            };
            window.pending = window
                .pending
                .checked_add(units.get())
                .ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn add_concurrency(&mut self, keys: &[LimitKey]) -> Result<(), AdmissionError> {
        for key in keys {
            let active = self.concurrency.get(key).copied().unwrap_or(0);
            active.checked_add(1).ok_or_else(exhausted)?;
        }
        for key in keys {
            let active = self.concurrency.entry(key.clone()).or_default();
            *active = active.checked_add(1).ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn commit_rate(&mut self, id: AdmissionLeaseId) -> Result<(), AdmissionError> {
        let Some((keys, units)) = self.pending_rate_commitment(id)? else {
            return Ok(());
        };
        self.validate_rate_commitment(&keys, units)?;
        self.apply_rate_commitment(&keys, units)?;
        self.mark_rate_committed(id)
    }

    fn finalize_accepted(
        &mut self,
        id: AdmissionLeaseId,
        now: Option<MonotonicTime>,
    ) -> Result<AcceptedFinalization, AdmissionError> {
        match now {
            Some(now) => self.finalize_accepted_at(id, now),
            None => self.retain_accepted(id),
        }
    }

    fn retain_accepted(
        &mut self,
        id: AdmissionLeaseId,
    ) -> Result<AcceptedFinalization, AdmissionError> {
        self.commit_rate(id)?;
        Ok(AcceptedFinalization::ReconciliationRequired)
    }

    fn finalize_accepted_at(
        &mut self,
        id: AdmissionLeaseId,
        now: MonotonicTime,
    ) -> Result<AcceptedFinalization, AdmissionError> {
        // Charge the surviving record before expiry can refund pending units.
        // Records expired by a previous observation are never reconstructed.
        self.commit_rate(id)?;
        match self.observe_and_expire(now) {
            Ok(()) => self.complete_accepted(id),
            Err(value) if value.code() == AdmissionErrorCode::ClockRegressed => {
                self.retain_accepted(id)
            }
            Err(value) => Err(value),
        }
    }

    fn retain_dispatched(
        &mut self,
        id: AdmissionLeaseId,
        now: MonotonicTime,
    ) -> Result<(), AdmissionError> {
        self.commit_rate(id)?;
        match self.observe_and_expire(now) {
            Err(value) if value.code() == AdmissionErrorCode::ClockRegressed => Ok(()),
            result => {
                result?;
                self.pending_rate_commitment(id).map(|_| ())
            }
        }
    }

    fn complete_accepted(
        &mut self,
        id: AdmissionLeaseId,
    ) -> Result<AcceptedFinalization, AdmissionError> {
        self.commit_rate(id)?;
        if !self.remove_lease(id) {
            return Err(error(AdmissionErrorCode::LeaseExpired));
        }
        Ok(AcceptedFinalization::Completed)
    }

    fn pending_rate_commitment(
        &self,
        id: AdmissionLeaseId,
    ) -> Result<Option<(Vec<LimitKey>, NonZeroU32)>, AdmissionError> {
        let Some(lease) = self.leases.get(&id) else {
            return Err(error(AdmissionErrorCode::LeaseExpired));
        };
        Ok((!lease.rate_committed).then(|| (lease.rate_keys.clone(), lease.units)))
    }

    fn validate_rate_commitment(
        &self,
        keys: &[LimitKey],
        units: NonZeroU32,
    ) -> Result<(), AdmissionError> {
        for key in keys {
            let Some(window) = self.windows.get(key) else {
                return Err(error(AdmissionErrorCode::StateUnavailable));
            };
            window
                .committed
                .checked_add(units.get())
                .ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn apply_rate_commitment(
        &mut self,
        keys: &[LimitKey],
        units: NonZeroU32,
    ) -> Result<(), AdmissionError> {
        for key in keys {
            let Some(window) = self.windows.get_mut(key) else {
                return Err(error(AdmissionErrorCode::StateUnavailable));
            };
            window.pending = window.pending.saturating_sub(units.get());
            window.committed = window
                .committed
                .checked_add(units.get())
                .ok_or_else(exhausted)?;
        }
        Ok(())
    }

    fn mark_rate_committed(&mut self, id: AdmissionLeaseId) -> Result<(), AdmissionError> {
        let Some(lease) = self.leases.get_mut(&id) else {
            return Err(error(AdmissionErrorCode::LeaseExpired));
        };
        lease.rate_committed = true;
        Ok(())
    }

    fn remove_lease(&mut self, id: AdmissionLeaseId) -> bool {
        let Some(lease) = self.leases.remove(&id) else {
            return false;
        };
        self.release_concurrency(&lease.concurrency_keys);
        if !lease.rate_committed {
            self.release_pending(&lease.rate_keys, lease.units);
        }
        true
    }

    fn release_concurrency(&mut self, keys: &[LimitKey]) {
        for key in keys {
            if let Some(active) = self.concurrency.get_mut(key) {
                *active = active.saturating_sub(1);
            }
        }
    }

    fn release_pending(&mut self, keys: &[LimitKey], units: NonZeroU32) {
        for key in keys {
            if let Some(window) = self.windows.get_mut(key) {
                window.pending = window.pending.saturating_sub(units.get());
            }
        }
    }

    fn snapshot(&self, policy: &LimitPolicy, now: MonotonicTime) -> LimitSnapshot {
        let (rate_remaining, rate_resets_at) = self.rate_snapshot(policy, now);
        let concurrency_remaining = policy.concurrency.map(|rule| {
            let active = self.concurrency.get(&policy.key).copied().unwrap_or(0);
            rule.limit.get().saturating_sub(active)
        });
        LimitSnapshot {
            rate_remaining,
            rate_resets_at,
            concurrency_remaining,
        }
    }

    fn rate_snapshot(
        &self,
        policy: &LimitPolicy,
        now: MonotonicTime,
    ) -> (Option<u32>, Option<MonotonicTime>) {
        let Some(rule) = policy.rate else {
            return (None, None);
        };
        let Some(window) = self.windows.get(&policy.key) else {
            return (Some(rule.capacity.get()), None);
        };
        let used = window.committed.saturating_add(window.pending);
        let remaining = rule.capacity.get().saturating_sub(used);
        let reset = (window.ends_at > now).then_some(window.ends_at);
        (Some(remaining), reset)
    }

    fn lease_expiry(
        &self,
        policies: &[&LimitPolicy],
        now: MonotonicTime,
    ) -> Result<MonotonicTime, AdmissionError> {
        let mut earliest = None;
        for policy in policies {
            let deadline = self.policy_expiry(policy, now)?;
            earliest =
                Some(earliest.map_or(deadline, |current: MonotonicTime| current.min(deadline)));
        }
        earliest.ok_or_else(invalid)
    }

    fn policy_expiry(
        &self,
        policy: &LimitPolicy,
        now: MonotonicTime,
    ) -> Result<MonotonicTime, AdmissionError> {
        // A reservation may not cross the window that owns its pending units.
        let rate_expiry = self.windows.get(&policy.key).map(|window| window.ends_at);
        let concurrency_expiry = policy
            .concurrency
            .map(|rule| now.checked_add(rule.lease_duration))
            .transpose()?;
        rate_expiry
            .into_iter()
            .chain(concurrency_expiry)
            .min()
            .ok_or_else(invalid)
    }
}

struct RateWindowState {
    ends_at: MonotonicTime,
    committed: u32,
    pending: u32,
}

impl RateWindowState {
    fn new(now: MonotonicTime, rule: RateRule) -> Result<Self, AdmissionError> {
        Ok(Self {
            ends_at: now.checked_add(rule.window)?,
            committed: 0,
            pending: 0,
        })
    }
}

struct ActiveLease {
    rate_keys: Vec<LimitKey>,
    concurrency_keys: Vec<LimitKey>,
    units: NonZeroU32,
    expires_at: MonotonicTime,
    rate_committed: bool,
}

struct ReservedParts {
    reservation: Option<RateReservation>,
    permits: Vec<ConcurrencyPermit>,
}

struct PreparedAdmission {
    lease_id: AdmissionLeaseId,
    expires_at: MonotonicTime,
    reservation: Option<RateReservation>,
    permits: Vec<ConcurrencyPermit>,
}

fn rate_keys(policies: &[&LimitPolicy]) -> Vec<LimitKey> {
    policies
        .iter()
        .filter(|policy| policy.rate.is_some())
        .map(|policy| policy.key.clone())
        .collect()
}

fn concurrency_keys(policies: &[&LimitPolicy]) -> Vec<LimitKey> {
    policies
        .iter()
        .filter(|policy| policy.concurrency.is_some())
        .map(|policy| policy.key.clone())
        .collect()
}

// crates/ariadnion-core/src/context.rs - Rust source for Ariadnion.
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
//! Bounded request identity, deadline, and cancellation context.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::Waker;
use std::time::{Duration, SystemTime};

use crate::error::{CoreError, ErrorCode};
use crate::ids::{PrincipalId, RequestId, TenantId, TraceId};

const MAX_CANCELLATION_WAITERS: usize = 1 << 8;

/// A cloneable cancellation handle shared across request boundaries.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
}

#[derive(Debug)]
struct CancellationState {
    cancelled: AtomicBool,
    parent: Option<Arc<CancellationState>>,
    waiters: Mutex<Vec<CancellationWaiter>>,
}

#[derive(Debug)]
struct CancellationWaiter {
    owner: Weak<CancellationState>,
    waker: Waker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WakerRegistration {
    Registered,
    Cancelled,
    Exhausted,
}

impl CancellationState {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.is_cancelled())
    }

    fn register_local_waker(
        &self,
        owner: &Arc<CancellationState>,
        waker: &Waker,
    ) -> WakerRegistration {
        if self.cancelled.load(Ordering::Acquire) {
            return WakerRegistration::Cancelled;
        }
        self.remove_inactive_waiters();
        let replacement = waker.clone();
        let mut waiters = lock_waiters(&self.waiters);
        if self.cancelled.load(Ordering::Acquire) {
            return WakerRegistration::Cancelled;
        }
        let owner = Arc::downgrade(owner);
        if let Some(index) = find_waiter_index(&waiters, &owner, waker) {
            let previous = std::mem::replace(&mut waiters[index].waker, replacement);
            drop(waiters);
            drop(previous);
            return WakerRegistration::Registered;
        }
        if waiters.len() >= MAX_CANCELLATION_WAITERS {
            return WakerRegistration::Exhausted;
        }
        waiters.push(CancellationWaiter {
            owner,
            waker: replacement,
        });
        WakerRegistration::Registered
    }

    fn remove_owner_waiters(&self, owner: &Arc<CancellationState>) {
        let owner = Arc::downgrade(owner);
        remove_waiters_if(&self.waiters, |waiter| Weak::ptr_eq(&waiter.owner, &owner));
    }

    fn take_waiters(&self) -> Vec<CancellationWaiter> {
        std::mem::take(&mut *lock_waiters(&self.waiters))
    }

    fn remove_inactive_waiters(&self) {
        remove_waiters_if(&self.waiters, |waiter| !waiter.is_active());
    }
}

impl CancellationWaiter {
    fn is_active(&self) -> bool {
        self.owner
            .upgrade()
            .is_some_and(|owner| !owner.is_cancelled())
    }
}

impl CancellationToken {
    /// Creates a token in the active state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                parent: None,
                waiters: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Creates an independently cancellable child linked to this token.
    ///
    /// Cancelling the child does not affect its parent. Cancelling the parent
    /// makes the child observe cancellation without a registration callback or
    /// mutable global state.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            state: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                parent: Some(self.state.clone()),
                waiters: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Requests cancellation and returns `true` only for the first request.
    pub fn cancel(&self) -> bool {
        if self.state.cancelled.swap(true, Ordering::AcqRel) {
            return false;
        }
        let waiters = self.state.take_waiters();
        self.remove_waker_chain();
        wake_waiters(waiters);
        true
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.is_cancelled()
    }

    /// Registers a task to be notified when this token becomes cancelled.
    ///
    /// This method returns `true` when cancellation is already observable. A
    /// caller polling a future may then return `Poll::Ready`; otherwise it may
    /// return `Poll::Pending` after this method returns `false`. Registration
    /// covers this token and every ancestor, and a final cancellation check
    /// prevents cancellation racing with registration from being missed.
    ///
    /// Each token node retains at most 256 distinct waker identities. Repeated
    /// registration by the same task replaces its equivalent entry. If any
    /// node in the parent chain is full, this token cancels itself rather than
    /// silently dropping the notification. Cancelling a node wakes its local
    /// registered tasks after releasing the internal lock.
    #[must_use]
    pub fn register_waker(&self, waker: &Waker) -> bool {
        let cancelled = match self.register_waker_chain(waker) {
            WakerRegistration::Registered => self.is_cancelled(),
            WakerRegistration::Cancelled => true,
            WakerRegistration::Exhausted => {
                self.cancel();
                true
            }
        };
        if cancelled {
            self.remove_waker_chain();
        }
        cancelled
    }

    /// Returns a stable cancellation error when cancellation was requested.
    pub fn check_active(&self) -> Result<(), CoreError> {
        if self.is_cancelled() {
            return Err(CoreError::from_code(ErrorCode::Cancelled));
        }
        Ok(())
    }

    fn register_waker_chain(&self, waker: &Waker) -> WakerRegistration {
        let mut current = Some(self.state.clone());
        while let Some(state) = current {
            match state.register_local_waker(&self.state, waker) {
                WakerRegistration::Registered => current = state.parent.clone(),
                outcome => return outcome,
            }
        }
        WakerRegistration::Registered
    }

    fn remove_waker_chain(&self) {
        let mut current = Some(self.state.clone());
        while let Some(state) = current {
            state.remove_owner_waiters(&self.state);
            current = state.parent.clone();
        }
    }
}

fn find_waiter_index(
    waiters: &[CancellationWaiter],
    owner: &Weak<CancellationState>,
    waker: &Waker,
) -> Option<usize> {
    waiters
        .iter()
        .enumerate()
        .find(|(_, entry)| Weak::ptr_eq(&entry.owner, owner) && entry.waker.will_wake(waker))
        .map(|(index, _)| index)
}

fn remove_waiters_if(
    waiters: &Mutex<Vec<CancellationWaiter>>,
    mut should_remove: impl FnMut(&CancellationWaiter) -> bool,
) {
    let mut guard = lock_waiters(waiters);
    let entries = std::mem::take(&mut *guard);
    let (removed, retained): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .partition(|waiter| should_remove(waiter));
    *guard = retained;
    drop(guard);
    drop(removed);
}

fn lock_waiters(
    waiters: &Mutex<Vec<CancellationWaiter>>,
) -> MutexGuard<'_, Vec<CancellationWaiter>> {
    match waiters.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn wake_waiters(waiters: Vec<CancellationWaiter>) {
    for waiter in waiters {
        // Executor wakers are outside the core trust boundary. One malformed
        // waker must not prevent cancellation from reaching remaining tasks.
        let _wake = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            waiter.waker.wake();
        }));
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// A safe identity summary produced by an authentication adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalContext {
    tenant_id: TenantId,
    principal_id: PrincipalId,
}

impl PrincipalContext {
    /// Creates an authenticated principal context for one tenant.
    #[must_use]
    pub const fn new(tenant_id: TenantId, principal_id: PrincipalId) -> Self {
        Self {
            tenant_id,
            principal_id,
        }
    }

    /// Returns the tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the authenticated principal identity.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }
}

/// Immutable request metadata propagated through core ports.
#[derive(Clone, Debug)]
pub struct RequestContext {
    request_id: RequestId,
    trace_id: TraceId,
    principal: Option<PrincipalContext>,
    deadline: Option<SystemTime>,
    cancellation: CancellationToken,
}

impl RequestContext {
    /// Creates a request context with an optional identity and UTC deadline.
    #[must_use]
    pub const fn new(
        request_id: RequestId,
        trace_id: TraceId,
        principal: Option<PrincipalContext>,
        deadline: Option<SystemTime>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            request_id,
            trace_id,
            principal,
            deadline,
            cancellation,
        }
    }

    /// Creates an unauthenticated request context.
    #[must_use]
    pub fn anonymous(
        request_id: RequestId,
        trace_id: TraceId,
        deadline: Option<SystemTime>,
    ) -> Self {
        Self::new(
            request_id,
            trace_id,
            None,
            deadline,
            CancellationToken::new(),
        )
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the trace identifier.
    #[must_use]
    pub const fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// Returns the authenticated principal summary, when available.
    #[must_use]
    pub const fn principal(&self) -> Option<&PrincipalContext> {
        self.principal.as_ref()
    }

    /// Returns the UTC deadline, when one was supplied.
    #[must_use]
    pub const fn deadline(&self) -> Option<SystemTime> {
        self.deadline
    }

    /// Returns a clone of the cancellation handle.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Returns whether cancellation or deadline expiry currently stops work.
    #[must_use]
    pub fn is_inactive(&self) -> bool {
        self.cancellation.is_cancelled() || self.is_expired_at(SystemTime::now())
    }

    /// Checks cancellation and deadline state at the current time.
    ///
    /// Cancellation has precedence and returns [`ErrorCode::Cancelled`]. If the
    /// request is not cancelled and its deadline is equal to or before the
    /// current UTC time, this returns [`ErrorCode::DeadlineExceeded`].
    pub fn check_active(&self) -> Result<(), CoreError> {
        self.check_active_at(SystemTime::now())
    }

    /// Checks cancellation and deadline state at a supplied UTC time.
    ///
    /// Cancellation is evaluated first. A deadline equal to `now` is expired;
    /// no work may begin at that boundary.
    pub fn check_active_at(&self, now: SystemTime) -> Result<(), CoreError> {
        self.cancellation.check_active()?;
        if self.is_expired_at(now) {
            return Err(CoreError::from_code(ErrorCode::DeadlineExceeded));
        }
        Ok(())
    }

    /// Returns remaining time at the current UTC time.
    ///
    /// This returns `Ok(None)` only when no deadline exists. Cancellation and an
    /// expired deadline return the same stable codes as [`Self::check_active`].
    pub fn remaining(&self) -> Result<Option<Duration>, CoreError> {
        self.remaining_at(SystemTime::now())
    }

    /// Returns remaining time at a supplied UTC time.
    ///
    /// Cancellation is checked before the deadline. A deadline equal to `now`
    /// returns [`ErrorCode::DeadlineExceeded`], never a zero duration.
    pub fn remaining_at(&self, now: SystemTime) -> Result<Option<Duration>, CoreError> {
        self.cancellation.check_active()?;
        let Some(deadline) = self.deadline else {
            return Ok(None);
        };
        if deadline <= now {
            return Err(CoreError::from_code(ErrorCode::DeadlineExceeded));
        }
        deadline
            .duration_since(now)
            .map(Some)
            .map_err(|_| CoreError::from_code(ErrorCode::DeadlineExceeded))
    }

    /// Produces a safe immutable summary for diagnostics and policy input.
    #[must_use]
    pub fn summary(&self) -> RequestContextSummary {
        RequestContextSummary {
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            tenant_id: self.principal.as_ref().map(|value| value.tenant_id.clone()),
            principal_id: self
                .principal
                .as_ref()
                .map(|value| value.principal_id.clone()),
            deadline: self.deadline,
            cancelled: self.cancellation.is_cancelled(),
        }
    }

    fn is_expired_at(&self, now: SystemTime) -> bool {
        self.deadline.is_some_and(|deadline| deadline <= now)
    }
}

/// A safe request summary that excludes credentials and request bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestContextSummary {
    request_id: RequestId,
    trace_id: TraceId,
    tenant_id: Option<TenantId>,
    principal_id: Option<PrincipalId>,
    deadline: Option<SystemTime>,
    cancelled: bool,
}

impl RequestContextSummary {
    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the trace identifier.
    #[must_use]
    pub const fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// Returns the tenant identity, when authenticated.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// Returns the principal identity, when authenticated.
    #[must_use]
    pub const fn principal_id(&self) -> Option<&PrincipalId> {
        self.principal_id.as_ref()
    }

    /// Returns the UTC deadline, when supplied.
    #[must_use]
    pub const fn deadline(&self) -> Option<SystemTime> {
        self.deadline
    }

    /// Returns whether cancellation had been requested when summarized.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

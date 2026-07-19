//! Bounded, synchronous shutdown coordination for the core process.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::error::{CoreError, ErrorCode};

/// The reason that initiated a shutdown request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownReason {
    /// A POSIX termination signal or equivalent console request was received.
    Signal,
    /// An operator requested an orderly stop through an internal control path.
    Operator,
    /// A fatal core precondition requires a safe stop.
    FatalPrecondition,
}

impl ShutdownReason {
    /// Returns the stable display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signal => "signal",
            Self::Operator => "operator",
            Self::FatalPrecondition => "fatal_precondition",
        }
    }
}

/// Result of requesting shutdown, including whether this caller won the race.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownRequestOutcome {
    /// This caller transitioned the coordinator into the requested state.
    Initiated,
    /// Another caller had already initiated shutdown.
    AlreadyRequested,
}

/// A report returned after the shutdown deadline has been observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    reason: ShutdownReason,
    elapsed: Duration,
    deadline_reached: bool,
}

impl ShutdownReport {
    /// Returns the initiating reason.
    #[must_use]
    pub const fn reason(self) -> ShutdownReason {
        self.reason
    }

    /// Returns the time spent waiting for the process to drain.
    #[must_use]
    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }

    /// Returns whether the configured deadline was reached before completion.
    #[must_use]
    pub const fn deadline_reached(self) -> bool {
        self.deadline_reached
    }
}

#[derive(Clone, Copy, Debug)]
struct ShutdownState {
    reason: Option<ShutdownReason>,
    draining: bool,
    drained: bool,
}

impl ShutdownState {
    const fn new() -> Self {
        Self {
            reason: None,
            draining: false,
            drained: false,
        }
    }
}

/// Coordinates one process-wide shutdown without exposing mutable global state.
#[derive(Clone)]
pub struct ShutdownCoordinator {
    state: Arc<(Mutex<ShutdownState>, Condvar)>,
}

fn lock_state<'a>(lock: &'a Mutex<ShutdownState>) -> std::sync::MutexGuard<'a, ShutdownState> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl ShutdownCoordinator {
    /// Creates an active coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(ShutdownState::new()), Condvar::new())),
        }
    }

    /// Requests a transition into draining state.
    pub fn request(&self, reason: ShutdownReason) -> ShutdownRequestOutcome {
        let (lock, condition) = &*self.state;
        let mut state = lock_state(lock);
        if state.reason.is_some() {
            return ShutdownRequestOutcome::AlreadyRequested;
        }
        state.reason = Some(reason);
        state.draining = true;
        condition.notify_all();
        ShutdownRequestOutcome::Initiated
    }

    /// Returns whether new work must be rejected.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        let (lock, _) = &*self.state;
        let state = lock_state(lock);
        state.draining
    }

    /// Returns the initiating reason, if shutdown was requested.
    #[must_use]
    pub fn reason(&self) -> Option<ShutdownReason> {
        let (lock, _) = &*self.state;
        let state = lock_state(lock);
        state.reason
    }

    /// Waits for a request or returns `None` when the timeout expires first.
    ///
    /// A timeout whose addition overflows the monotonic clock returns
    /// [`ErrorCode::ResourceExhausted`]. Lock poisoning is recovered by taking
    /// the protected state because the state transition is idempotent.
    pub fn wait_for_request_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<ShutdownReason>, CoreError> {
        let deadline = shutdown_deadline(Instant::now(), timeout)?;
        let (lock, condition) = &*self.state;
        let mut state = lock_state(lock);
        while state.reason.is_none() {
            let Some(remaining) = remaining_until(deadline) else {
                return Ok(None);
            };
            let (next_state, timed_out) = wait_once(condition, state, remaining);
            state = next_state;
            if timed_out && state.reason.is_none() {
                return Ok(None);
            }
        }
        Ok(state.reason)
    }

    /// Blocks until a shutdown request is observed.
    ///
    /// This method has no timeout and must only run on a process coordination
    /// thread. Lock poisoning is recovered by preserving the protected state.
    pub fn wait_for_request(&self) -> ShutdownReason {
        let (lock, condition) = &*self.state;
        let mut state = lock_state(lock);
        loop {
            if let Some(reason) = state.reason {
                return reason;
            }
            state = match condition.wait(state) {
                Ok(next_state) => next_state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    /// Marks all accepted work as drained and wakes shutdown waiters.
    ///
    /// Calling this before a shutdown request returns [`ErrorCode::Conflict`].
    /// Repeated calls after draining are idempotent.
    pub fn mark_drained(&self) -> Result<(), CoreError> {
        let (lock, condition) = &*self.state;
        let mut state = lock_state(lock);
        if !state.draining {
            return Err(CoreError::from_code(ErrorCode::Conflict)
                .with_internal_context("cannot mark an active coordinator drained"));
        }
        state.drained = true;
        condition.notify_all();
        Ok(())
    }

    /// Waits until draining completes or the supplied timeout expires.
    ///
    /// Calling this before a request returns [`ErrorCode::Conflict`]. Timeout
    /// overflow returns [`ErrorCode::ResourceExhausted`]. A normal timeout is
    /// represented by [`ShutdownReport::deadline_reached`] rather than an error.
    pub fn wait_for_drain(&self, timeout: Duration) -> Result<ShutdownReport, CoreError> {
        let reason = self.shutdown_reason()?;
        let started = Instant::now();
        let deadline = shutdown_deadline(started, timeout)?;
        let deadline_reached = self.wait_until_drained(deadline);
        Ok(ShutdownReport {
            reason,
            elapsed: started.elapsed(),
            deadline_reached,
        })
    }

    fn shutdown_reason(&self) -> Result<ShutdownReason, CoreError> {
        self.reason()
            .ok_or_else(|| CoreError::from_code(ErrorCode::Conflict))
    }

    fn wait_until_drained(&self, deadline: Instant) -> bool {
        let (lock, condition) = &*self.state;
        let mut state = lock_state(lock);
        while !state.drained {
            let Some(remaining) = remaining_until(deadline) else {
                return true;
            };
            let (next_state, timed_out) = wait_once(condition, state, remaining);
            state = next_state;
            if timed_out && !state.drained {
                return true;
            }
        }
        false
    }
}

fn shutdown_deadline(started: Instant, timeout: Duration) -> Result<Instant, CoreError> {
    started.checked_add(timeout).ok_or_else(|| {
        CoreError::from_code(ErrorCode::ResourceExhausted)
            .with_internal_context("shutdown timeout overflow")
    })
}

fn remaining_until(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    (now < deadline).then(|| deadline.saturating_duration_since(now))
}

fn wait_once<'a>(
    condition: &Condvar,
    state: std::sync::MutexGuard<'a, ShutdownState>,
    remaining: Duration,
) -> (std::sync::MutexGuard<'a, ShutdownState>, bool) {
    match condition.wait_timeout(state, remaining) {
        Ok((next_state, result)) => (next_state, result.timed_out()),
        Err(poisoned) => {
            let (next_state, result) = poisoned.into_inner();
            (next_state, result.timed_out())
        }
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

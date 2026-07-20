//! Bounded request identity, deadline, and cancellation context.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use crate::error::{CoreError, ErrorCode};
use crate::ids::{PrincipalId, RequestId, TenantId, TraceId};

/// A cloneable cancellation handle shared across request boundaries.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
}

#[derive(Debug)]
struct CancellationState {
    cancelled: AtomicBool,
    parent: Option<Arc<CancellationState>>,
}

impl CancellationState {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.is_cancelled())
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
            }),
        }
    }

    /// Requests cancellation and returns `true` only for the first request.
    pub fn cancel(&self) -> bool {
        !self.state.cancelled.swap(true, Ordering::AcqRel)
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.is_cancelled()
    }

    /// Returns a stable cancellation error when cancellation was requested.
    pub fn check_active(&self) -> Result<(), CoreError> {
        if self.is_cancelled() {
            return Err(CoreError::from_code(ErrorCode::Cancelled));
        }
        Ok(())
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

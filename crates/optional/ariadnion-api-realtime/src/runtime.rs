// crates/optional/ariadnion-api-realtime/src/runtime.rs - Bounded Realtime session state machine.
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

//! Runtime-owned Realtime session state without protocol grammar or transport I/O.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, SystemTime};

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, BoxRealtimeFuture, MAX_REALTIME_OUTBOUND_QUEUE_EVENTS,
    RealtimeClientEvent, RealtimeInboundEvent, RealtimeOutboundEvent, RealtimeResponseCancel,
    RealtimeResponseFinishReason, RealtimeResponseId, RealtimeServerEvent,
    RealtimeSessionCloseReason, RealtimeSessionDescriptor, RealtimeSessionId,
    RealtimeSessionOpenRequest, RealtimeSessionPort, RealtimeSessionState, RealtimeTextFrame,
};
use ariadnion_core::{RequestContext, TenantId};

/// Maximum live sessions retained by one runtime instance.
pub const MAX_LIVE_REALTIME_SESSIONS: usize = 256;
const RESPONSE_EVENT_COUNT: usize = 7;
const TIMER_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Projects one semantic runtime event into an already bounded protocol frame.
///
/// The runtime owns queue capacity and lifecycle order, while the injected
/// projector owns the public protocol grammar. A projector must be pure for a
/// given event and must not perform transport I/O, authentication, or provider
/// selection while the runtime holds its short state lock.
pub trait RealtimeFrameProjectorPort: Send + Sync {
    /// Creates the exact bounded protocol frame for one semantic event.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the selected protocol cannot safely
    /// represent the supplied event. The runtime closes that session rather than
    /// fabricating a replacement frame.
    fn project(&self, event: &RealtimeServerEvent) -> Result<RealtimeTextFrame, ApiDomainError>;
}

/// Runtime-neutral, bounded implementation of [`RealtimeSessionPort`].
///
/// Each instance retains at most 256 tenant-scoped sessions and 16 projected
/// outbound events per session. The runtime does not own a socket, protocol DTO,
/// file alias, provider account, or provider attempt. It produces the initial
/// empty text-response lifecycle deterministically; a later provider-capable
/// runtime can replace that execution policy behind the same domain port.
pub struct RealtimeRuntime {
    projector: Arc<dyn RealtimeFrameProjectorPort>,
    state: Arc<Mutex<RuntimeState>>,
    next_session: AtomicU64,
    next_response: AtomicU64,
    next_receiver: AtomicU64,
    timer_started: Mutex<bool>,
}

struct RuntimeState {
    sessions: HashMap<RealtimeSessionId, Session>,
}

struct Session {
    tenant_id: TenantId,
    expires_at: SystemTime,
    state: RealtimeSessionState,
    outbound: VecDeque<RealtimeOutboundEvent>,
    waiting_receiver: Option<WaitingReceiver>,
}

struct WaitingReceiver {
    lease: ReceiverLease,
    waker: Waker,
}

#[derive(Clone)]
struct ReceiverLease {
    token: u64,
    signal: Arc<ReceiverSignal>,
}

#[derive(Default)]
struct ReceiverSignal {
    terminal: Mutex<Option<ApiDomainError>>,
}

struct NextEventFuture<'a> {
    runtime: &'a RealtimeRuntime,
    session_id: &'a RealtimeSessionId,
    context: &'a RequestContext,
    lease: Option<ReceiverLease>,
    complete: bool,
}

enum OwnedSessionStatus {
    Active,
    Expired(Option<Waker>),
}

enum ApplyFailure {
    Rejected(ApiDomainError),
    Projector(ApiDomainError),
}

impl RealtimeRuntime {
    /// Creates an empty runtime with deterministic monotonic opaque identifiers.
    #[must_use]
    pub fn new(projector: Arc<dyn RealtimeFrameProjectorPort>) -> Self {
        Self {
            projector,
            state: Arc::new(Mutex::new(RuntimeState {
                sessions: HashMap::new(),
            })),
            next_session: AtomicU64::new(1),
            next_response: AtomicU64::new(1),
            next_receiver: AtomicU64::new(1),
            timer_started: Mutex::new(false),
        }
    }

    fn open_now(
        &self,
        request: RealtimeSessionOpenRequest,
        context: &RequestContext,
    ) -> Result<RealtimeSessionDescriptor, ApiDomainError> {
        let tenant_id = authenticated_active_tenant(context)?.clone();
        let now = SystemTime::now();
        let expires_at = session_expiry(now, request.lifetime().seconds())?;
        let mut state = self.lock_state()?;
        let expired_wakers = reclaim_expired_sessions(&mut state, now);
        let result = self.admit_session(&mut state, request, tenant_id, expires_at);
        drop(state);
        wake_all(expired_wakers);
        result
    }

    fn submit_now(
        &self,
        session_id: &RealtimeSessionId,
        event: RealtimeInboundEvent,
        context: &RequestContext,
    ) -> Result<(), ApiDomainError> {
        let tenant_id = authenticated_active_tenant(context)?;
        let mut state = self.lock_state()?;
        let expiry = reclaim_owned_expiry(&mut state, session_id, tenant_id, SystemTime::now())?;
        if let OwnedSessionStatus::Expired(waker) = expiry {
            drop(state);
            wake_optional(waker);
            return Err(deadline_exceeded());
        }
        let outcome = apply_submission(
            &mut state,
            session_id,
            tenant_id,
            event,
            self.projector.as_ref(),
            &self.next_response,
        );
        let (result, waker) = finish_submission(&mut state, session_id, outcome);
        drop(state);
        wake_optional(waker);
        result
    }

    fn poll_next(
        &self,
        session_id: &RealtimeSessionId,
        context: &RequestContext,
        lease: &ReceiverLease,
        task: &mut Context<'_>,
    ) -> Poll<Result<RealtimeOutboundEvent, ApiDomainError>> {
        let tenant_id = match authenticated_active_tenant(context) {
            Ok(value) => value,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Some(error) = lease.terminal_error() {
            return Poll::Ready(Err(error));
        }
        let mut state = match self.lock_state() {
            Ok(value) => value,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let expiry =
            match reclaim_owned_expiry(&mut state, session_id, tenant_id, SystemTime::now()) {
                Ok(value) => value,
                Err(error) => return Poll::Ready(Err(error)),
            };
        if let OwnedSessionStatus::Expired(waker) = expiry {
            drop(state);
            wake_optional(waker);
            return Poll::Ready(Err(deadline_exceeded()));
        }
        poll_session_event(&mut state, session_id, tenant_id, lease, task)
    }

    fn close_now(
        &self,
        session_id: &RealtimeSessionId,
        _reason: RealtimeSessionCloseReason,
        context: &RequestContext,
    ) -> Result<(), ApiDomainError> {
        let tenant_id = authenticated_tenant_identity(context)?;
        let mut state = self.lock_state()?;
        let waker = remove_session(&mut state, session_id, tenant_id)?;
        drop(state);
        wake_optional(waker);
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, RuntimeState>, ApiDomainError> {
        self.state.lock().map_err(|_| internal())
    }

    fn issue_session_id(&self) -> Result<RealtimeSessionId, ApiDomainError> {
        let value = issue_id(&self.next_session, "rt-session-")?;
        RealtimeSessionId::new(&value).map_err(|_| internal())
    }

    fn issue_receiver_lease(&self) -> Result<ReceiverLease, ApiDomainError> {
        let token = issue_counter(&self.next_receiver)?;
        Ok(ReceiverLease {
            token,
            signal: Arc::new(ReceiverSignal::default()),
        })
    }

    fn admit_session(
        &self,
        state: &mut RuntimeState,
        request: RealtimeSessionOpenRequest,
        tenant_id: TenantId,
        expires_at: SystemTime,
    ) -> Result<RealtimeSessionDescriptor, ApiDomainError> {
        if state.sessions.len() >= MAX_LIVE_REALTIME_SESSIONS {
            return Err(resource_exhausted());
        }
        let id = self.issue_session_id()?;
        let descriptor = RealtimeSessionDescriptor::new(id.clone(), request);
        state
            .sessions
            .insert(id, Session::new(tenant_id, expires_at));
        Ok(descriptor)
    }

    fn ensure_timer_started(&self) -> Result<(), ApiDomainError> {
        let mut started = self.timer_started.lock().map_err(|_| internal())?;
        if *started {
            return Ok(());
        }
        let state = Arc::downgrade(&self.state);
        thread::Builder::new()
            .name("ariadnion-realtime-timer".into())
            .spawn(move || timer_loop(state))
            .map(drop)
            .map_err(|_| unavailable())?;
        *started = true;
        Ok(())
    }

    fn release_waiter(&self, session_id: &RealtimeSessionId, token: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(session) = state.sessions.get_mut(session_id) {
            session.release_receiver(token);
        }
    }
}

impl RealtimeSessionPort for RealtimeRuntime {
    fn open<'a>(
        &'a self,
        request: RealtimeSessionOpenRequest,
        context: &'a RequestContext,
    ) -> BoxRealtimeFuture<'a, Result<RealtimeSessionDescriptor, ApiDomainError>> {
        Box::pin(async move { self.open_now(request, context) })
    }

    fn submit<'a>(
        &'a self,
        session_id: &'a RealtimeSessionId,
        event: RealtimeInboundEvent,
        context: &'a RequestContext,
    ) -> BoxRealtimeFuture<'a, Result<(), ApiDomainError>> {
        Box::pin(async move { self.submit_now(session_id, event, context) })
    }

    fn next_event<'a>(
        &'a self,
        session_id: &'a RealtimeSessionId,
        context: &'a RequestContext,
    ) -> BoxRealtimeFuture<'a, Result<RealtimeOutboundEvent, ApiDomainError>> {
        Box::pin(NextEventFuture::new(self, session_id, context))
    }

    fn close<'a>(
        &'a self,
        session_id: &'a RealtimeSessionId,
        reason: RealtimeSessionCloseReason,
        context: &'a RequestContext,
    ) -> BoxRealtimeFuture<'a, Result<(), ApiDomainError>> {
        Box::pin(async move { self.close_now(session_id, reason, context) })
    }
}

impl<'a> NextEventFuture<'a> {
    fn new(
        runtime: &'a RealtimeRuntime,
        session_id: &'a RealtimeSessionId,
        context: &'a RequestContext,
    ) -> Self {
        Self {
            runtime,
            session_id,
            context,
            lease: None,
            complete: false,
        }
    }
}

impl Future for NextEventFuture<'_> {
    type Output = Result<RealtimeOutboundEvent, ApiDomainError>;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.complete {
            return Poll::Ready(Err(internal()));
        }
        if this.lease.is_none() {
            match this.runtime.issue_receiver_lease() {
                Ok(lease) => this.lease = Some(lease),
                Err(error) => {
                    this.complete = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
        let Some(lease) = this.lease.as_ref() else {
            this.complete = true;
            return Poll::Ready(Err(internal()));
        };
        match this
            .runtime
            .poll_next(this.session_id, this.context, lease, task)
        {
            Poll::Ready(result) => {
                this.runtime.release_waiter(this.session_id, lease.token);
                this.complete = true;
                Poll::Ready(result)
            }
            Poll::Pending => match this.runtime.ensure_timer_started() {
                Ok(()) => Poll::Pending,
                Err(error) => {
                    this.runtime.release_waiter(this.session_id, lease.token);
                    this.complete = true;
                    Poll::Ready(Err(error))
                }
            },
        }
    }
}

impl Drop for NextEventFuture<'_> {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        if let Some(lease) = self.lease.as_ref() {
            self.runtime.release_waiter(self.session_id, lease.token);
        }
    }
}

impl ReceiverSignal {
    fn set_terminal(&self, error: ApiDomainError) {
        let mut terminal = match self.terminal.lock() {
            Ok(value) => value,
            Err(poisoned) => poisoned.into_inner(),
        };
        if terminal.is_none() {
            *terminal = Some(error);
        }
    }

    fn terminal_error(&self) -> Option<ApiDomainError> {
        match self.terminal.lock() {
            Ok(value) => *value,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }
}

impl ReceiverLease {
    fn terminal_error(&self) -> Option<ApiDomainError> {
        self.signal.terminal_error()
    }
}

impl Session {
    fn new(tenant_id: TenantId, expires_at: SystemTime) -> Self {
        Self {
            tenant_id,
            expires_at,
            state: RealtimeSessionState::new(),
            outbound: VecDeque::new(),
            waiting_receiver: None,
        }
    }

    fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }

    fn apply(
        &mut self,
        event: RealtimeInboundEvent,
        projector: &dyn RealtimeFrameProjectorPort,
        next_response: &AtomicU64,
    ) -> Result<Option<Waker>, ApplyFailure> {
        match event.event() {
            RealtimeClientEvent::SessionUpdate(_) => self.queue_session_updated(projector)?,
            RealtimeClientEvent::ConversationItemCreate(item) => self
                .state
                .accept_conversation_item(item)
                .map_err(ApplyFailure::Rejected)?,
            RealtimeClientEvent::ResponseCreate(_) => {
                self.queue_response(projector, next_response)?
            }
            RealtimeClientEvent::ResponseCancel(cancel) => {
                self.cancel_response(projector, cancel)?
            }
        }
        Ok(self.waiting_waker())
    }

    fn ensure_capacity(&self, additional: usize) -> Result<(), ApplyFailure> {
        if self.outbound.len().saturating_add(additional) > MAX_REALTIME_OUTBOUND_QUEUE_EVENTS {
            return Err(ApplyFailure::Rejected(resource_exhausted()));
        }
        Ok(())
    }

    fn queue_session_updated(
        &mut self,
        projector: &dyn RealtimeFrameProjectorPort,
    ) -> Result<(), ApplyFailure> {
        self.ensure_capacity(1)?;
        let event = project_event(projector, RealtimeServerEvent::SessionUpdated)?;
        self.outbound.push_back(event);
        Ok(())
    }

    fn queue_response(
        &mut self,
        projector: &dyn RealtimeFrameProjectorPort,
        next_response: &AtomicU64,
    ) -> Result<(), ApplyFailure> {
        self.ensure_capacity(RESPONSE_EVENT_COUNT)?;
        let response_id = issue_response_id(next_response)?;
        let projected = project_events(projector, initial_response_events(response_id.clone()))?;
        self.state
            .start_response(response_id)
            .map_err(ApplyFailure::Rejected)?;
        self.outbound.extend(projected);
        Ok(())
    }

    fn cancel_response(
        &mut self,
        projector: &dyn RealtimeFrameProjectorPort,
        cancel: &RealtimeResponseCancel,
    ) -> Result<(), ApplyFailure> {
        let response_id = self
            .state
            .cancel_response(cancel.response_id())
            .map_err(ApplyFailure::Rejected)?;
        let event = project_event(
            projector,
            RealtimeServerEvent::ResponseDone {
                response_id: response_id.clone(),
                finish_reason: RealtimeResponseFinishReason::Cancelled,
            },
        )?;
        self.outbound
            .retain(|queued| !matches_response(queued.event(), &response_id));
        self.outbound.push_back(event);
        Ok(())
    }

    fn register_receiver(
        &mut self,
        lease: &ReceiverLease,
        task: &Context<'_>,
    ) -> Result<(), ApiDomainError> {
        match self.waiting_receiver.as_mut() {
            Some(waiting) if waiting.lease.token != lease.token => Err(conflict()),
            Some(waiting) => update_waiting_waker(waiting, task.waker()),
            None => {
                let Some(waker) = clone_waker(task.waker()) else {
                    return Err(internal());
                };
                self.waiting_receiver = Some(WaitingReceiver {
                    lease: lease.clone(),
                    waker,
                });
                Ok(())
            }
        }
    }

    fn has_other_receiver(&self, token: u64) -> bool {
        self.waiting_receiver
            .as_ref()
            .is_some_and(|waiting| waiting.lease.token != token)
    }

    fn release_receiver(&mut self, token: u64) {
        if self
            .waiting_receiver
            .as_ref()
            .is_some_and(|waiting| waiting.lease.token == token)
        {
            self.waiting_receiver = None;
        }
    }

    fn waiting_waker(&self) -> Option<Waker> {
        self.waiting_receiver
            .as_ref()
            .and_then(|waiting| clone_waker(&waiting.waker))
    }

    fn retire(&mut self, error: ApiDomainError) -> Option<Waker> {
        self.state.close();
        self.outbound.clear();
        let waiting = self.waiting_receiver.take()?;
        waiting.lease.signal.set_terminal(error);
        Some(waiting.waker)
    }
}

fn authenticated_tenant_identity(context: &RequestContext) -> Result<&TenantId, ApiDomainError> {
    context
        .principal()
        .map(|principal| principal.tenant_id())
        .ok_or_else(unavailable)
}

fn authenticated_active_tenant(context: &RequestContext) -> Result<&TenantId, ApiDomainError> {
    let tenant_id = authenticated_tenant_identity(context)?;
    context.check_active().map_err(ApiDomainError::from)?;
    Ok(tenant_id)
}

fn session_expiry(now: SystemTime, lifetime_seconds: u64) -> Result<SystemTime, ApiDomainError> {
    now.checked_add(Duration::from_secs(lifetime_seconds))
        .ok_or_else(internal)
}

fn issue_id(counter: &AtomicU64, prefix: &str) -> Result<String, ApiDomainError> {
    issue_counter(counter).map(|value| format!("{prefix}{value}"))
}

fn issue_counter(counter: &AtomicU64) -> Result<u64, ApiDomainError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .map_err(|_| resource_exhausted())
}

fn reclaim_expired_sessions(state: &mut RuntimeState, now: SystemTime) -> Vec<Waker> {
    let expired: Vec<_> = state
        .sessions
        .iter()
        .filter(|(_, session)| session.is_expired_at(now))
        .map(|(session_id, _)| session_id.clone())
        .collect();
    expired
        .into_iter()
        .filter_map(|session_id| remove_expired_session(state, &session_id))
        .collect()
}

fn reclaim_owned_expiry(
    state: &mut RuntimeState,
    session_id: &RealtimeSessionId,
    tenant_id: &TenantId,
    now: SystemTime,
) -> Result<OwnedSessionStatus, ApiDomainError> {
    let session = state.sessions.get(session_id).ok_or_else(unavailable)?;
    if &session.tenant_id != tenant_id {
        return Err(unavailable());
    }
    if !session.is_expired_at(now) {
        return Ok(OwnedSessionStatus::Active);
    }
    Ok(OwnedSessionStatus::Expired(remove_expired_session(
        state, session_id,
    )))
}

fn remove_expired_session(
    state: &mut RuntimeState,
    session_id: &RealtimeSessionId,
) -> Option<Waker> {
    state
        .sessions
        .remove(session_id)
        .and_then(|mut session| session.retire(deadline_exceeded()))
}

fn apply_submission(
    state: &mut RuntimeState,
    session_id: &RealtimeSessionId,
    tenant_id: &TenantId,
    event: RealtimeInboundEvent,
    projector: &dyn RealtimeFrameProjectorPort,
    next_response: &AtomicU64,
) -> Result<Option<Waker>, ApplyFailure> {
    let session =
        session_for_tenant(state, session_id, tenant_id).map_err(ApplyFailure::Rejected)?;
    session.apply(event, projector, next_response)
}

fn finish_submission(
    state: &mut RuntimeState,
    session_id: &RealtimeSessionId,
    outcome: Result<Option<Waker>, ApplyFailure>,
) -> (Result<(), ApiDomainError>, Option<Waker>) {
    match outcome {
        Ok(waker) => (Ok(()), waker),
        Err(ApplyFailure::Rejected(error)) => (Err(error), None),
        Err(ApplyFailure::Projector(error)) => {
            let waker = state
                .sessions
                .remove(session_id)
                .and_then(|mut session| session.retire(error));
            (Err(error), waker)
        }
    }
}

fn initial_response_events(response_id: RealtimeResponseId) -> Vec<RealtimeServerEvent> {
    vec![
        RealtimeServerEvent::ResponseCreated(response_id.clone()),
        RealtimeServerEvent::ResponseOutputItemAdded(response_id.clone()),
        RealtimeServerEvent::ResponseContentPartAdded(response_id.clone()),
        RealtimeServerEvent::ResponseOutputTextDone(response_id.clone()),
        RealtimeServerEvent::ResponseContentPartDone(response_id.clone()),
        RealtimeServerEvent::ResponseOutputItemDone(response_id.clone()),
        RealtimeServerEvent::ResponseDone {
            response_id,
            finish_reason: RealtimeResponseFinishReason::Completed,
        },
    ]
}

fn issue_response_id(next_response: &AtomicU64) -> Result<RealtimeResponseId, ApplyFailure> {
    let value = issue_id(next_response, "rt-response-").map_err(ApplyFailure::Rejected)?;
    RealtimeResponseId::new(&value).map_err(|_| ApplyFailure::Projector(internal()))
}

fn project_events(
    projector: &dyn RealtimeFrameProjectorPort,
    events: Vec<RealtimeServerEvent>,
) -> Result<Vec<RealtimeOutboundEvent>, ApplyFailure> {
    events
        .into_iter()
        .map(|event| project_event(projector, event))
        .collect()
}

fn project_event(
    projector: &dyn RealtimeFrameProjectorPort,
    event: RealtimeServerEvent,
) -> Result<RealtimeOutboundEvent, ApplyFailure> {
    let projected = catch_unwind(AssertUnwindSafe(|| projector.project(&event)))
        .map_err(|_| ApplyFailure::Projector(internal()))?;
    let frame = projected.map_err(ApplyFailure::Projector)?;
    Ok(RealtimeOutboundEvent::new(event, frame))
}

fn poll_session_event(
    state: &mut RuntimeState,
    session_id: &RealtimeSessionId,
    tenant_id: &TenantId,
    lease: &ReceiverLease,
    task: &mut Context<'_>,
) -> Poll<Result<RealtimeOutboundEvent, ApiDomainError>> {
    let session = match session_for_tenant(state, session_id, tenant_id) {
        Ok(value) => value,
        Err(error) => return Poll::Ready(Err(error)),
    };
    if session.has_other_receiver(lease.token) {
        return Poll::Ready(Err(conflict()));
    }
    match session.outbound.pop_front() {
        Some(event) => {
            session.release_receiver(lease.token);
            Poll::Ready(finish_delivered_event(session, event))
        }
        None => match session.register_receiver(lease, task) {
            Ok(()) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        },
    }
}

fn matches_response(event: &RealtimeServerEvent, response_id: &RealtimeResponseId) -> bool {
    match event {
        RealtimeServerEvent::ResponseCreated(value)
        | RealtimeServerEvent::ResponseOutputItemAdded(value)
        | RealtimeServerEvent::ResponseContentPartAdded(value)
        | RealtimeServerEvent::ResponseOutputTextDone(value)
        | RealtimeServerEvent::ResponseContentPartDone(value)
        | RealtimeServerEvent::ResponseOutputItemDone(value) => value == response_id,
        RealtimeServerEvent::ResponseOutputTextDelta {
            response_id: value, ..
        }
        | RealtimeServerEvent::ResponseDone {
            response_id: value, ..
        } => value == response_id,
        _ => false,
    }
}

fn finish_delivered_event(
    session: &mut Session,
    event: RealtimeOutboundEvent,
) -> Result<RealtimeOutboundEvent, ApiDomainError> {
    if let RealtimeServerEvent::ResponseDone { response_id, .. } = event.event() {
        session.state.finish_response(response_id)?;
    }
    Ok(event)
}

fn session_for_tenant<'a>(
    state: &'a mut RuntimeState,
    session_id: &RealtimeSessionId,
    tenant_id: &TenantId,
) -> Result<&'a mut Session, ApiDomainError> {
    let session = state.sessions.get_mut(session_id).ok_or_else(unavailable)?;
    if &session.tenant_id != tenant_id {
        return Err(unavailable());
    }
    Ok(session)
}

fn remove_session(
    state: &mut RuntimeState,
    session_id: &RealtimeSessionId,
    tenant_id: &TenantId,
) -> Result<Option<Waker>, ApiDomainError> {
    let owned = state
        .sessions
        .get(session_id)
        .is_some_and(|session| &session.tenant_id == tenant_id);
    if !owned {
        return Err(unavailable());
    }
    Ok(state
        .sessions
        .remove(session_id)
        .and_then(|mut session| session.retire(unavailable())))
}

fn update_waiting_waker(
    waiting: &mut WaitingReceiver,
    candidate: &Waker,
) -> Result<(), ApiDomainError> {
    if waiting.waker.will_wake(candidate) {
        return Ok(());
    }
    waiting.waker = clone_waker(candidate).ok_or_else(internal)?;
    Ok(())
}

fn clone_waker(waker: &Waker) -> Option<Waker> {
    catch_unwind(AssertUnwindSafe(|| waker.clone())).ok()
}

fn wake_optional(waker: Option<Waker>) {
    if let Some(waker) = waker {
        wake(waker);
    }
}

fn wake_all(wakers: Vec<Waker>) {
    for waker in wakers {
        wake(waker);
    }
}

fn wake(waker: Waker) {
    let _ = catch_unwind(AssertUnwindSafe(|| waker.wake()));
}

fn timer_loop(state: Weak<Mutex<RuntimeState>>) {
    loop {
        thread::sleep(TIMER_POLL_INTERVAL);
        let Some(state) = state.upgrade() else {
            return;
        };
        wake_all(waiting_wakers(&state));
    }
}

fn waiting_wakers(state: &Mutex<RuntimeState>) -> Vec<Waker> {
    let state = match state.lock() {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    };
    state
        .sessions
        .values()
        .filter_map(Session::waiting_waker)
        .collect()
}

const fn unavailable() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::Unavailable)
}

const fn resource_exhausted() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::ResourceExhausted)
}

const fn conflict() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::Conflict)
}

const fn deadline_exceeded() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::DeadlineExceeded)
}

const fn internal() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::Internal)
}

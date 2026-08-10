// crates/optional/ariadnion-provider-dispatch/src/stream.rs - Bounded provider stream relay for Ariadnion.
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
//! Cancellation-aware blocking relay for provider-native events.

use std::mem;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ariadnion_api_domain::{ApiDomainError, ChatStreamEvent, ServiceStreamEvent, TextStreamEvent};
use ariadnion_core::{
    CancellationToken, EventEnvelope, EventPublisher, EventSubscriber, PublishError,
    ReceiveOutcome, RequestContext, bounded_event_channel,
};
use ariadnion_provider_sdk::{ProviderStreamEvent, ProviderStreamSubscriber};

use crate::dispatch::ServiceKind;
use crate::error::{
    internal_error, project_provider_failure, resource_exhausted_error, unavailable_error,
};

const SERVICE_STREAM_CAPACITY: usize = 8;
const MAX_ACTIVE_RELAYS: usize = 64;
const PROVIDER_RECEIVE_WAIT: Duration = Duration::from_millis(10);
const OUTPUT_RETRY_WAIT: Duration = Duration::from_millis(2);
const RELAY_THREAD_NAME: &str = "ariadnion-provider-relay";

struct RelayAdmissionHealth {
    unhealthy: AtomicBool,
}

impl RelayAdmissionHealth {
    const fn new() -> Self {
        Self {
            unhealthy: AtomicBool::new(false),
        }
    }

    fn is_healthy(&self) -> bool {
        !self.unhealthy.load(Ordering::Acquire)
    }

    fn mark_unhealthy(&self) {
        // Release publishes failure before cancellation wakes another admission.
        self.unhealthy.store(true, Ordering::Release);
    }
}

struct RelayAdmission {
    active: AtomicUsize,
}

impl RelayAdmission {
    const fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Result<RelayPermit, ApiDomainError> {
        // AcqRel pairs the prior task's permit release with the next admission.
        let acquired =
            self.active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, next_active_relay_count);
        match acquired {
            Ok(_) => Ok(RelayPermit {
                admission: self.clone(),
            }),
            Err(_) => Err(resource_exhausted_error()),
        }
    }
}

fn next_active_relay_count(active: usize) -> Option<usize> {
    if active >= MAX_ACTIVE_RELAYS {
        return None;
    }
    active.checked_add(1)
}

/// Lifetime-bound ownership of one admitted relay slot.
pub(crate) struct RelayPermit {
    admission: Arc<RelayAdmission>,
}

impl Drop for RelayPermit {
    fn drop(&mut self) {
        // Permit ownership is the only path that decrements active admission.
        self.admission.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RelayExit {
    Healthy,
    Unhealthy,
}

impl RelayExit {
    fn merge(self, other: Self) -> Self {
        if self == Self::Unhealthy || other == Self::Unhealthy {
            return Self::Unhealthy;
        }
        Self::Healthy
    }
}

struct RelayTask {
    handle: JoinHandle<RelayExit>,
    _permit: RelayPermit,
}

impl RelayTask {
    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    fn join(self) -> bool {
        matches!(self.handle.join(), Ok(RelayExit::Healthy))
    }
}

/// Owns one dispatcher's bounded relay admission, shutdown, and thread handles.
///
/// The handle lock is never acquired by a relay thread. Relays publish protocol
/// failure through a separate admission latch before cancellation, while
/// finished handles latch shutdown only after terminal publication can finish.
/// Each registered handle owns its admission permit, so the registry cannot
/// exceed the fixed relay limit even when a new thread exits before registration.
pub(crate) struct RelayManager {
    admission: Arc<RelayAdmission>,
    admission_health: Arc<RelayAdmissionHealth>,
    shutdown: CancellationToken,
    handles: Mutex<Vec<RelayTask>>,
}

impl RelayManager {
    pub(crate) fn new() -> Self {
        Self {
            admission: Arc::new(RelayAdmission::new()),
            admission_health: Arc::new(RelayAdmissionHealth::new()),
            shutdown: CancellationToken::new(),
            handles: Mutex::new(Vec::with_capacity(MAX_ACTIVE_RELAYS)),
        }
    }

    pub(crate) fn try_acquire(&self) -> Result<RelayPermit, ApiDomainError> {
        self.check_healthy()?;
        self.admission.try_acquire()
    }

    pub(crate) fn check_healthy(&self) -> Result<(), ApiDomainError> {
        if self.reap_finished()
            && self.admission_health.is_healthy()
            && !self.shutdown.is_cancelled()
        {
            return Ok(());
        }
        Err(unavailable_error())
    }

    pub(crate) fn start(
        &self,
        source: ProviderStreamSubscriber,
        kind: ServiceKind,
        attempt_context: RequestContext,
        permit: RelayPermit,
    ) -> Result<EventSubscriber<ServiceStreamEvent>, ApiDomainError> {
        if self.check_healthy().is_err() {
            source.cancellation().cancel();
            return Err(unavailable_error());
        }
        self.spawn(source, kind, attempt_context, permit)
    }

    fn spawn(
        &self,
        source: ProviderStreamSubscriber,
        kind: ServiceKind,
        attempt_context: RequestContext,
        permit: RelayPermit,
    ) -> Result<EventSubscriber<ServiceStreamEvent>, ApiDomainError> {
        let provider_cancellation = source.cancellation();
        let output_cancellation = CancellationToken::new();
        let (target, subscriber) =
            bounded_event_channel(SERVICE_STREAM_CAPACITY, output_cancellation.clone())
                .map_err(ApiDomainError::from)?;
        let relay = StreamRelay {
            source,
            target,
            output_cancellation: output_cancellation.clone(),
            admission_health: self.admission_health.clone(),
            manager_cancellation: self.shutdown.clone(),
            attempt_context,
            kind,
        };
        // Health checks use the same lock, so no admission can observe a
        // started relay before its handle and permit become registered.
        let mut handles = lock_handles(&self.handles);
        let spawned = thread::Builder::new()
            .name(RELAY_THREAD_NAME.to_owned())
            .spawn(move || relay.run());
        match spawned {
            Ok(handle) => {
                handles.push(RelayTask {
                    handle,
                    _permit: permit,
                });
                Ok(subscriber)
            }
            Err(_) => {
                provider_cancellation.cancel();
                output_cancellation.cancel();
                Err(internal_error())
            }
        }
    }

    fn reap_finished(&self) -> bool {
        let mut handles = lock_handles(&self.handles);
        let healthy = reap_finished_tasks(&mut handles);
        if !healthy {
            self.admission_health.mark_unhealthy();
            self.shutdown.cancel();
        }
        healthy
    }
}

impl Drop for RelayManager {
    fn drop(&mut self) {
        self.shutdown.cancel();
        let tasks = take_all_tasks(&self.handles);
        let _healthy = join_tasks(tasks);
    }
}

fn reap_finished_tasks(handles: &mut Vec<RelayTask>) -> bool {
    let current = mem::take(handles);
    let mut healthy = true;
    for task in current {
        if task.is_finished() {
            if !task.join() {
                healthy = false;
            }
        } else {
            handles.push(task);
        }
    }
    healthy
}

fn take_all_tasks(handles: &Mutex<Vec<RelayTask>>) -> Vec<RelayTask> {
    mem::take(&mut *lock_handles(handles))
}

fn join_tasks(tasks: Vec<RelayTask>) -> bool {
    let mut healthy = true;
    for task in tasks {
        if !task.join() {
            healthy = false;
        }
    }
    healthy
}

fn lock_handles(handles: &Mutex<Vec<RelayTask>>) -> MutexGuard<'_, Vec<RelayTask>> {
    match handles.lock() {
        Ok(guard) => guard,
        // The vector still owns every task after poisoning; JoinHandle results
        // independently detect relay failure and close future admission.
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct StreamRelay {
    source: ProviderStreamSubscriber,
    target: EventPublisher<ServiceStreamEvent>,
    output_cancellation: CancellationToken,
    admission_health: Arc<RelayAdmissionHealth>,
    manager_cancellation: CancellationToken,
    attempt_context: RequestContext,
    kind: ServiceKind,
}

impl StreamRelay {
    fn run(self) -> RelayExit {
        while self.is_active() {
            let outcome = self.source.receive_timeout(PROVIDER_RECEIVE_WAIT);
            if let RelayStep::Stop(exit) = self.process_receive(outcome) {
                return exit;
            }
        }
        RelayExit::Healthy
    }

    fn is_active(&self) -> bool {
        if self.manager_cancellation.is_cancelled() {
            self.cancel_both();
            return false;
        }
        if self.output_cancellation.is_cancelled() {
            self.cancel_provider();
            return false;
        }
        if self.attempt_context.check_active().is_err() {
            self.cancel_both();
            return false;
        }
        true
    }

    fn process_receive(&self, outcome: ReceiveOutcome<ProviderStreamEvent>) -> RelayStep {
        match outcome {
            ReceiveOutcome::Event(event) => self.forward(event),
            ReceiveOutcome::TimedOut => RelayStep::Continue,
            ReceiveOutcome::Closed => {
                self.cancel_output();
                RelayStep::Stop(RelayExit::Healthy)
            }
            ReceiveOutcome::Cancelled => {
                self.cancel_output();
                RelayStep::Stop(RelayExit::Healthy)
            }
        }
    }

    fn forward(&self, event: EventEnvelope<ProviderStreamEvent>) -> RelayStep {
        let projected = project_event(self.kind, event);
        let projected_exit = projected.exit;
        if projected_exit == RelayExit::Unhealthy {
            self.admission_health.mark_unhealthy();
        }
        match self.publish_retained(projected.event) {
            RelayPublication::Published => {}
            RelayPublication::Stopped(publication_exit) => {
                return RelayStep::Stop(projected_exit.merge(publication_exit));
            }
        }
        if projected.cancel_provider {
            self.cancel_provider();
        }
        if projected.terminal {
            RelayStep::Stop(projected_exit)
        } else {
            RelayStep::Continue
        }
    }

    fn publish_retained(&self, mut event: EventEnvelope<ServiceStreamEvent>) -> RelayPublication {
        loop {
            match self.publish_once(event) {
                PublishAttempt::Published => return RelayPublication::Published,
                PublishAttempt::Retry(retained) => {
                    event = retained;
                    thread::park_timeout(OUTPUT_RETRY_WAIT);
                }
                PublishAttempt::Stopped(exit) => return RelayPublication::Stopped(exit),
            }
        }
    }

    fn publish_once(&self, event: EventEnvelope<ServiceStreamEvent>) -> PublishAttempt {
        if !self.is_active() {
            return PublishAttempt::Stopped(RelayExit::Healthy);
        }
        match self.target.try_publish(event) {
            Ok(()) => PublishAttempt::Published,
            Err(PublishError::Full(retained)) => PublishAttempt::Retry(retained),
            Err(PublishError::Closed(_)) | Err(PublishError::Cancelled(_)) => {
                self.cancel_provider();
                PublishAttempt::Stopped(RelayExit::Healthy)
            }
            Err(PublishError::OutOfOrder(_)) => {
                self.admission_health.mark_unhealthy();
                self.cancel_both();
                PublishAttempt::Stopped(RelayExit::Unhealthy)
            }
        }
    }

    fn cancel_provider(&self) {
        self.source.cancellation().cancel();
    }

    fn cancel_both(&self) {
        self.cancel_provider();
        self.cancel_output();
    }

    fn cancel_output(&self) {
        self.output_cancellation.cancel();
    }
}

#[derive(Clone, Copy)]
enum RelayStep {
    Continue,
    Stop(RelayExit),
}

#[derive(Clone, Copy)]
enum RelayPublication {
    Published,
    Stopped(RelayExit),
}

enum PublishAttempt {
    Published,
    Retry(EventEnvelope<ServiceStreamEvent>),
    Stopped(RelayExit),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProjectionState {
    Continue,
    Terminal,
    Reject,
}

struct ProjectedEvent {
    event: EventEnvelope<ServiceStreamEvent>,
    terminal: bool,
    cancel_provider: bool,
    exit: RelayExit,
}

fn project_event(kind: ServiceKind, event: EventEnvelope<ProviderStreamEvent>) -> ProjectedEvent {
    match kind {
        ServiceKind::Text => project_text_event(event),
        ServiceKind::Chat => project_chat_event(event),
    }
}

fn project_text_event(event: EventEnvelope<ProviderStreamEvent>) -> ProjectedEvent {
    let state = text_projection_state(event.payload());
    ProjectedEvent {
        event: event.map_payload(map_text_payload),
        terminal: state != ProjectionState::Continue,
        cancel_provider: state == ProjectionState::Reject,
        exit: projection_exit(state),
    }
}

fn text_projection_state(event: &ProviderStreamEvent) -> ProjectionState {
    match event {
        ProviderStreamEvent::Started { .. } | ProviderStreamEvent::TextDelta(_) => {
            ProjectionState::Continue
        }
        ProviderStreamEvent::Completed { .. } | ProviderStreamEvent::Failed(_) => {
            ProjectionState::Terminal
        }
        _ => ProjectionState::Reject,
    }
}

fn map_text_payload(event: ProviderStreamEvent) -> ServiceStreamEvent {
    let mapped = match event {
        ProviderStreamEvent::Started { version } => TextStreamEvent::Started { version },
        ProviderStreamEvent::TextDelta(delta) => TextStreamEvent::Delta(delta),
        ProviderStreamEvent::Completed { finish_reason } => {
            TextStreamEvent::Completed { finish_reason }
        }
        ProviderStreamEvent::Failed(failure) => {
            TextStreamEvent::Failed(project_provider_failure(failure))
        }
        _ => TextStreamEvent::Failed(internal_error()),
    };
    ServiceStreamEvent::Text(mapped)
}

fn project_chat_event(event: EventEnvelope<ProviderStreamEvent>) -> ProjectedEvent {
    let state = chat_projection_state(event.payload());
    ProjectedEvent {
        event: event.map_payload(map_chat_payload),
        terminal: state != ProjectionState::Continue,
        cancel_provider: state == ProjectionState::Reject,
        exit: projection_exit(state),
    }
}

fn chat_projection_state(event: &ProviderStreamEvent) -> ProjectionState {
    match event {
        ProviderStreamEvent::ChatStarted { .. } | ProviderStreamEvent::ChatDelta(_) => {
            ProjectionState::Continue
        }
        ProviderStreamEvent::ChatCompleted { .. } | ProviderStreamEvent::Failed(_) => {
            ProjectionState::Terminal
        }
        _ => ProjectionState::Reject,
    }
}

fn projection_exit(state: ProjectionState) -> RelayExit {
    if state == ProjectionState::Reject {
        return RelayExit::Unhealthy;
    }
    RelayExit::Healthy
}

fn map_chat_payload(event: ProviderStreamEvent) -> ServiceStreamEvent {
    let mapped = match event {
        ProviderStreamEvent::ChatStarted { version } => ChatStreamEvent::Started { version },
        ProviderStreamEvent::ChatDelta(delta) => ChatStreamEvent::Delta(delta),
        ProviderStreamEvent::ChatCompleted {
            finish_reason,
            usage,
        } => ChatStreamEvent::Completed {
            finish_reason,
            usage,
        },
        ProviderStreamEvent::Failed(failure) => {
            ChatStreamEvent::Failed(project_provider_failure(failure))
        }
        _ => ChatStreamEvent::Failed(internal_error()),
    };
    ServiceStreamEvent::Chat(mapped)
}

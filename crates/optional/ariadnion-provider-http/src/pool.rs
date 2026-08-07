// crates/optional/ariadnion-provider-http/src/pool.rs - Bounded provider HTTP pooling for Ariadnion.
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

//! Profile-isolated exclusive HTTP/1 leases and bounded admission.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ariadnion_core::{CancellationToken, ErrorCode, RequestContext};
use ariadnion_provider_sdk::{ProviderAttemptEvidence, ProviderTransmission};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::config::ProviderHttpProfile;
use crate::connector::{ProviderHttpDirectConnection, ProviderHttpDirectConnector};
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};
use crate::exchange::ProviderHttpExchange;
use crate::request::ProviderHttpRequest;
use crate::response::ProviderHttpResponse;
use crate::shutdown::{ProviderHttpShutdownReport, shutdown_pool};

const MAX_PARTITION_BYTES: usize = 128;

/// A checked opaque boundary that prevents connection reuse across callers.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProviderHttpPartition(Box<str>);

impl ProviderHttpPartition {
    /// Creates a nonempty bounded ASCII partition identifier.
    ///
    /// # Errors
    ///
    /// Returns `provider_http_invalid_pool` when the identifier is empty, too
    /// large, or contains control or non-ASCII bytes.
    pub fn new(value: &str) -> Result<Self, ProviderHttpError> {
        if value.is_empty() || value.len() > MAX_PARTITION_BYTES || !partition_is_safe(value) {
            return Err(ProviderHttpError::new(ProviderHttpErrorCode::InvalidPool));
        }
        Ok(Self(value.into()))
    }
}

impl Debug for ProviderHttpPartition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpPartition { redacted }")
    }
}

fn partition_is_safe(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// An immutable snapshot of bounded pool occupancy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderHttpPoolMetrics {
    live_connections: usize,
    idle_connections: usize,
    waiters: usize,
    shutdown: bool,
}

impl ProviderHttpPoolMetrics {
    /// Returns the number of live or reserved connection slots owned by the pool.
    #[must_use]
    pub const fn live_connections(self) -> usize {
        self.live_connections
    }

    /// Returns the number of clean reusable idle connections.
    #[must_use]
    pub const fn idle_connections(self) -> usize {
        self.idle_connections
    }

    /// Returns the number of callers waiting for an exclusive lease.
    #[must_use]
    pub const fn waiters(self) -> usize {
        self.waiters
    }

    /// Returns whether admission has permanently stopped.
    #[must_use]
    pub const fn is_shutdown(self) -> bool {
        self.shutdown
    }
}

/// A bounded connection pool dedicated to one immutable profile and partition.
pub struct ProviderHttpConnectionPool {
    pub(crate) inner: Arc<PoolInner>,
}

impl ProviderHttpConnectionPool {
    /// Creates an empty profile-isolated connection pool.
    ///
    /// Construction has no network side effects. The connector, profile, and
    /// partition remain immutable for the lifetime of the pool.
    ///
    /// # Errors
    ///
    /// Returns a stable pool error if the supplied profile has inconsistent
    /// bounds. Checked profiles normally make this branch unreachable.
    pub fn new(
        profile: ProviderHttpProfile,
        connector: Arc<ProviderHttpDirectConnector>,
        partition: ProviderHttpPartition,
    ) -> Result<Self, ProviderHttpError> {
        let limits = profile.pool();
        if limits.max_idle() > limits.max_connections() {
            return Err(ProviderHttpError::new(ProviderHttpErrorCode::InvalidPool));
        }
        Ok(Self {
            inner: Arc::new(PoolInner::new(profile, connector, partition)),
        })
    }

    /// Executes one request on an exclusive pooled HTTP/1 lease.
    ///
    /// A clean response EOF returns the physical connection to this exact pool.
    /// Every other exit discards it. Capacity waiting is bounded by the profile
    /// waiter count, connect budget, request cancellation, and request deadline.
    ///
    /// `evidence` must be pristine and exclusive to this attempt.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error for admission, waiting, connection,
    /// dispatch, cancellation, deadline, or response-head failure.
    pub async fn execute(
        &self,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
        request: ProviderHttpRequest,
    ) -> Result<ProviderHttpPooledResponse, ProviderHttpError> {
        check_wait_context(context)?;
        validate_attempt_evidence(evidence)?;
        let (operation_context, operation) = self.inner.register_operation(context)?;
        let result = self
            .inner
            .execute_operation(&operation_context, evidence, request)
            .await;
        project_operation_result(result, context, &operation)
    }

    /// Stops admission, drains until the supplied budget, then aborts survivors.
    ///
    /// # Errors
    ///
    /// Returns `provider_http_invalid_timeout` when the budget is zero or above
    /// the hard one-minute shutdown ceiling.
    pub async fn shutdown(
        &self,
        budget: Duration,
    ) -> Result<ProviderHttpShutdownReport, ProviderHttpError> {
        shutdown_pool(&self.inner, budget).await
    }

    /// Returns an immutable occupancy snapshot without exposing connection keys.
    #[must_use]
    pub fn metrics(&self) -> ProviderHttpPoolMetrics {
        self.inner.metrics()
    }
}

impl Debug for ProviderHttpConnectionPool {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpConnectionPool { redacted }")
    }
}

/// A pull-driven response whose physical lease is returned only after clean EOF.
pub struct ProviderHttpPooledResponse {
    response: Option<ProviderHttpResponse>,
    pool: Arc<PoolInner>,
    connection_id: u64,
    released: bool,
}

impl ProviderHttpPooledResponse {
    /// Returns the numeric HTTP response status.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.response
            .as_ref()
            .map_or(0, ProviderHttpResponse::status)
    }

    /// Returns the first matching checked response header.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.response
            .as_ref()
            .and_then(|response| response.header(name))
    }

    /// Pulls at most one body chunk and releases the lease on clean EOF.
    ///
    /// # Errors
    ///
    /// Returns the underlying stable response-body error. The connection is
    /// discarded before the error is returned.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProviderHttpError> {
        if self.released {
            return Ok(None);
        }
        let result = self.pull_chunk().await;
        self.finish_chunk(result)
    }

    async fn pull_chunk(&mut self) -> Result<Option<Vec<u8>>, ProviderHttpError> {
        match self.response.as_mut() {
            Some(response) => response.next_chunk().await,
            None => Ok(None),
        }
    }

    fn finish_chunk(
        &mut self,
        result: Result<Option<Vec<u8>>, ProviderHttpError>,
    ) -> Result<Option<Vec<u8>>, ProviderHttpError> {
        match result {
            Ok(None) => {
                self.release_clean();
                Ok(None)
            }
            Err(error) => {
                self.release_unclean();
                Err(error)
            }
            Ok(chunk) => Ok(chunk),
        }
    }

    fn release_clean(&mut self) {
        let reusable = self
            .response
            .as_mut()
            .and_then(ProviderHttpResponse::take_reusable_connection);
        match reusable {
            Some(connection) => self
                .pool
                .checkin(self.connection_id, connection.into_connection()),
            None => self.pool.discard(self.connection_id),
        }
        self.released = true;
    }

    fn release_unclean(&mut self) {
        let _response = self.response.take();
        self.pool.discard(self.connection_id);
        self.released = true;
    }
}

impl Drop for ProviderHttpPooledResponse {
    fn drop(&mut self) {
        if !self.released {
            self.release_unclean();
        }
    }
}

impl Debug for ProviderHttpPooledResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpPooledResponse { redacted }")
    }
}

pub(crate) struct PoolInner {
    profile: ProviderHttpProfile,
    connector: Arc<ProviderHttpDirectConnector>,
    _partition: ProviderHttpPartition,
    state: Mutex<PoolState>,
    pub(crate) changed: Notify,
}

struct PoolState {
    mode: PoolMode,
    live: usize,
    waiters: usize,
    next_connection_id: u64,
    next_operation_id: u64,
    reservations: BTreeSet<u64>,
    idle: VecDeque<Box<IdleConnection>>,
    drivers: BTreeMap<u64, JoinHandle<()>>,
    retired_drivers: Vec<JoinHandle<()>>,
    operations: BTreeMap<u64, OperationControl>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PoolMode {
    Accepting,
    Draining,
    Stopped,
}

struct IdleConnection {
    id: u64,
    idle_since: Instant,
    connection: ProviderHttpDirectConnection,
}

struct CheckedOutConnection {
    id: u64,
    connection: ProviderHttpDirectConnection,
}

enum CheckoutAction {
    Reuse(Box<IdleConnection>),
    Connect(u64),
    Wait,
}

struct WaiterGuard {
    pool: Arc<PoolInner>,
    registered: bool,
}

struct ReservationGuard {
    pool: Arc<PoolInner>,
    connection_id: u64,
    armed: bool,
}

struct LeaseGuard {
    pool: Arc<PoolInner>,
    connection_id: u64,
    armed: bool,
}

struct OperationGuard {
    pool: Arc<PoolInner>,
    operation_id: u64,
    forced_shutdown: Arc<AtomicBool>,
}

struct OperationControl {
    cancellation: CancellationToken,
    forced_shutdown: Arc<AtomicBool>,
}

impl PoolInner {
    fn new(
        profile: ProviderHttpProfile,
        connector: Arc<ProviderHttpDirectConnector>,
        partition: ProviderHttpPartition,
    ) -> Self {
        Self {
            profile,
            connector,
            _partition: partition,
            state: Mutex::new(PoolState {
                mode: PoolMode::Accepting,
                live: 0,
                waiters: 0,
                next_connection_id: 1,
                next_operation_id: 1,
                reservations: BTreeSet::new(),
                idle: VecDeque::new(),
                drivers: BTreeMap::new(),
                retired_drivers: Vec::new(),
                operations: BTreeMap::new(),
            }),
            changed: Notify::new(),
        }
    }

    fn register_operation(
        self: &Arc<Self>,
        context: &RequestContext,
    ) -> Result<(RequestContext, OperationGuard), ProviderHttpError> {
        let cancellation = context.cancellation().child();
        let mut state = lock_state(&self.state);
        if state.mode != PoolMode::Accepting {
            return Err(pool_shutdown_error());
        }
        let maximum = self
            .profile
            .pool()
            .max_connections()
            .saturating_add(self.profile.pool().max_waiters());
        if state.operations.len() >= maximum {
            return Err(ProviderHttpError::new(ProviderHttpErrorCode::PoolExhausted));
        }
        let operation_id = state.next_operation_id;
        state.next_operation_id = state.next_operation_id.saturating_add(1);
        let forced_shutdown = Arc::new(AtomicBool::new(false));
        state.operations.insert(
            operation_id,
            OperationControl {
                cancellation: cancellation.clone(),
                forced_shutdown: forced_shutdown.clone(),
            },
        );
        drop(state);
        let operation_context = RequestContext::new(
            context.request_id().clone(),
            context.trace_id().clone(),
            context.principal().cloned(),
            context.deadline(),
            cancellation,
        );
        Ok((
            operation_context,
            OperationGuard {
                pool: self.clone(),
                operation_id,
                forced_shutdown,
            },
        ))
    }

    async fn execute_operation(
        self: &Arc<Self>,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
        request: ProviderHttpRequest,
    ) -> Result<ProviderHttpPooledResponse, ProviderHttpError> {
        let lease = self.checkout(context, evidence).await?;
        self.execute_lease(lease, context, request).await
    }

    async fn checkout(
        self: &Arc<Self>,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
    ) -> Result<CheckedOutConnection, ProviderHttpError> {
        let wait_deadline = Instant::now() + self.profile.timeouts().connect();
        let mut waiter = WaiterGuard::new(self.clone());
        loop {
            check_wait_context(context)?;
            let action = self.checkout_action(waiter.registered)?;
            if let Some(lease) = self
                .advance_checkout(action, &mut waiter, context, evidence, wait_deadline)
                .await?
            {
                return Ok(lease);
            }
        }
    }

    async fn advance_checkout(
        self: &Arc<Self>,
        action: CheckoutAction,
        waiter: &mut WaiterGuard,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
        wait_deadline: Instant,
    ) -> Result<Option<CheckedOutConnection>, ProviderHttpError> {
        match action {
            CheckoutAction::Reuse(idle) => {
                waiter.unregister();
                Ok(self.prepare_reuse(idle, evidence))
            }
            CheckoutAction::Connect(id) => {
                waiter.unregister();
                self.connect_reserved(id, context, evidence).await.map(Some)
            }
            CheckoutAction::Wait => {
                waiter.registered = true;
                wait_for_change(self, context, wait_deadline).await?;
                Ok(None)
            }
        }
    }

    fn checkout_action(&self, already_waiting: bool) -> Result<CheckoutAction, ProviderHttpError> {
        let mut state = lock_state(&self.state);
        if state.mode != PoolMode::Accepting {
            return Err(pool_shutdown_error());
        }
        self.purge_idle(&mut state);
        reap_finished_drivers(&mut state);
        if let Some(idle) = state.idle.pop_front() {
            return Ok(CheckoutAction::Reuse(idle));
        }
        if owned_driver_capacity(&state) < self.profile.pool().max_connections() {
            let id = reserve_connection(&mut state);
            return Ok(CheckoutAction::Connect(id));
        }
        register_waiter(
            &mut state,
            self.profile.pool().max_waiters(),
            already_waiting,
        )?;
        Ok(CheckoutAction::Wait)
    }

    fn purge_idle(&self, state: &mut PoolState) {
        let maximum_age = self.profile.timeouts().max_resolution_age();
        let now = Instant::now();
        let mut retained = VecDeque::with_capacity(state.idle.len());
        while let Some(entry) = state.idle.pop_front() {
            let fresh = entry.connection.is_reusable()
                && now.duration_since(entry.idle_since) <= maximum_age
                && self
                    .connector
                    .connection_is_current(&entry.connection, &self.profile);
            if fresh {
                retained.push_back(entry);
            } else {
                retire_live(state, entry.id);
            }
        }
        state.idle = retained;
    }

    fn prepare_reuse(
        &self,
        idle: Box<IdleConnection>,
        evidence: &ProviderAttemptEvidence,
    ) -> Option<CheckedOutConnection> {
        let IdleConnection { id, connection, .. } = *idle;
        if !connection.is_reusable()
            || connection
                .rebind_attempt(evidence, self.profile.limits())
                .is_err()
        {
            self.discard(id);
            return None;
        }
        Some(CheckedOutConnection { id, connection })
    }

    async fn connect_reserved(
        self: &Arc<Self>,
        id: u64,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
    ) -> Result<CheckedOutConnection, ProviderHttpError> {
        let mut reservation = ReservationGuard::new(self.clone(), id);
        let connection_result = self
            .connector
            .connect(&self.profile, context, evidence)
            .await;
        let connection = match connection_result {
            Ok(connection) => connection,
            Err(error) => return Err(error),
        };
        let result = self.register_connected_driver(id, connection);
        reservation.disarm();
        result
    }

    fn register_connected_driver(
        &self,
        id: u64,
        mut connection: ProviderHttpDirectConnection,
    ) -> Result<CheckedOutConnection, ProviderHttpError> {
        let driver = match connection.take_driver_for_join() {
            Some(driver) => driver,
            None => {
                self.release_reservation(id);
                return Err(ProviderHttpError::new(
                    ProviderHttpErrorCode::RuntimeUnavailable,
                ));
            }
        };
        self.store_connected_driver(id, connection, driver)
    }

    fn store_connected_driver(
        &self,
        id: u64,
        connection: ProviderHttpDirectConnection,
        driver: JoinHandle<()>,
    ) -> Result<CheckedOutConnection, ProviderHttpError> {
        let mut state = lock_state(&self.state);
        if state.mode == PoolMode::Accepting {
            state.reservations.remove(&id);
            state.drivers.insert(id, driver);
            return Ok(CheckedOutConnection { id, connection });
        }
        retire_pending_driver(&mut state, id, driver);
        drop(state);
        connection.abort_driver();
        drop(connection);
        self.changed.notify_waiters();
        Err(pool_shutdown_error())
    }

    async fn execute_lease(
        self: &Arc<Self>,
        lease: CheckedOutConnection,
        context: &RequestContext,
        request: ProviderHttpRequest,
    ) -> Result<ProviderHttpPooledResponse, ProviderHttpError> {
        let id = lease.id;
        let mut lease_guard = LeaseGuard::new(self.clone(), id);
        let mut exchange =
            ProviderHttpExchange::from_connection(lease.connection, self.profile.clone())?;
        match exchange.execute(context, request).await {
            Ok(response) => {
                let pooled = ProviderHttpPooledResponse {
                    response: Some(response),
                    pool: self.clone(),
                    connection_id: id,
                    released: false,
                };
                lease_guard.disarm();
                Ok(pooled)
            }
            Err(error) => Err(error),
        }
    }

    fn checkin(&self, id: u64, connection: ProviderHttpDirectConnection) {
        let reusable = connection.is_reusable()
            && self
                .connector
                .connection_is_current(&connection, &self.profile);
        let mut state = lock_state(&self.state);
        let has_capacity = state.idle.len() < self.profile.pool().max_idle();
        if state.mode == PoolMode::Accepting && reusable && has_capacity {
            state.idle.push_back(Box::new(IdleConnection {
                id,
                idle_since: Instant::now(),
                connection,
            }));
        } else {
            retire_live(&mut state, id);
            connection.abort_driver();
            drop(connection);
        }
        drop(state);
        self.changed.notify_waiters();
    }

    fn discard(&self, id: u64) {
        let mut state = lock_state(&self.state);
        retire_live(&mut state, id);
        drop(state);
        self.changed.notify_waiters();
    }

    fn release_reservation(&self, id: u64) {
        let mut state = lock_state(&self.state);
        if state.reservations.remove(&id) && state.live > 0 {
            state.live -= 1;
        }
        drop(state);
        self.changed.notify_waiters();
    }

    fn metrics(&self) -> ProviderHttpPoolMetrics {
        let state = lock_state(&self.state);
        ProviderHttpPoolMetrics {
            live_connections: state.live,
            idle_connections: state.idle.len(),
            waiters: state.waiters,
            shutdown: state.mode != PoolMode::Accepting,
        }
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        lock_state(&self.state)
    }
}

impl WaiterGuard {
    fn new(pool: Arc<PoolInner>) -> Self {
        Self {
            pool,
            registered: false,
        }
    }

    fn unregister(&mut self) {
        if self.registered {
            decrement_waiter(&self.pool);
            self.registered = false;
        }
    }
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.unregister();
    }
}

impl ReservationGuard {
    fn new(pool: Arc<PoolInner>, connection_id: u64) -> Self {
        Self {
            pool,
            connection_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.pool.release_reservation(self.connection_id);
        }
    }
}

impl LeaseGuard {
    fn new(pool: Arc<PoolInner>, connection_id: u64) -> Self {
        Self {
            pool,
            connection_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if self.armed {
            self.pool.discard(self.connection_id);
        }
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut state = lock_state(&self.pool.state);
        state.operations.remove(&self.operation_id);
        drop(state);
        self.pool.changed.notify_waiters();
    }
}

impl OperationGuard {
    fn forced_shutdown(&self) -> bool {
        self.forced_shutdown.load(Ordering::Acquire)
    }
}

fn reserve_connection(state: &mut PoolState) -> u64 {
    let id = state.next_connection_id;
    state.next_connection_id = state.next_connection_id.saturating_add(1);
    state.live += 1;
    state.reservations.insert(id);
    id
}

fn register_waiter(
    state: &mut PoolState,
    maximum: usize,
    already_waiting: bool,
) -> Result<(), ProviderHttpError> {
    if already_waiting {
        return Ok(());
    }
    if state.waiters >= maximum {
        return Err(ProviderHttpError::new(ProviderHttpErrorCode::PoolExhausted));
    }
    state.waiters += 1;
    Ok(())
}

fn decrement_waiter(pool: &PoolInner) {
    let mut state = lock_state(&pool.state);
    state.waiters = state.waiters.saturating_sub(1);
    drop(state);
    pool.changed.notify_waiters();
}

fn retire_live(state: &mut PoolState, id: u64) {
    let reservation = state.reservations.remove(&id);
    let driver = state.drivers.remove(&id);
    if reservation || driver.is_some() {
        state.live = state.live.saturating_sub(1);
    }
    if let Some(driver) = driver {
        driver.abort();
        state.retired_drivers.push(driver);
    }
}

fn retire_pending_driver(state: &mut PoolState, id: u64, driver: JoinHandle<()>) {
    if state.reservations.remove(&id) {
        state.live = state.live.saturating_sub(1);
    }
    driver.abort();
    state.retired_drivers.push(driver);
}

fn reap_finished_drivers(state: &mut PoolState) {
    state.retired_drivers.retain(|driver| !driver.is_finished());
}

fn owned_driver_capacity(state: &PoolState) -> usize {
    state.live.saturating_add(state.retired_drivers.len())
}

async fn wait_for_change(
    pool: &PoolInner,
    context: &RequestContext,
    deadline: Instant,
) -> Result<(), ProviderHttpError> {
    if Instant::now() >= deadline {
        return Err(ProviderHttpError::new(
            ProviderHttpErrorCode::AttemptTimeout,
        ));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let poll = pool.profile.timeouts().cancellation_poll().min(remaining);
    if tokio::time::timeout(poll, pool.changed.notified())
        .await
        .is_ok()
    {
        return Ok(());
    }
    check_wait_context(context)
}

fn check_wait_context(context: &RequestContext) -> Result<(), ProviderHttpError> {
    context.check_active().map_err(|error| {
        let code = if error.code() == ErrorCode::Cancelled {
            ProviderHttpErrorCode::Cancelled
        } else {
            ProviderHttpErrorCode::DeadlineExceeded
        };
        ProviderHttpError::new(code)
    })
}

fn validate_attempt_evidence(evidence: &ProviderAttemptEvidence) -> Result<(), ProviderHttpError> {
    let progress = evidence.progress();
    if progress.transmission() != ProviderTransmission::NotStarted
        || progress.upstream_response_started()
        || progress.downstream_delivery_started()
    {
        return Err(ProviderHttpError::with_phase(
            ProviderHttpErrorCode::RequestFailed,
            ProviderHttpPhase::RequestHeaders,
        ));
    }
    Ok(())
}

fn pool_shutdown_error() -> ProviderHttpError {
    ProviderHttpError::new(ProviderHttpErrorCode::PoolShutdown)
}

fn project_operation_result(
    result: Result<ProviderHttpPooledResponse, ProviderHttpError>,
    parent_context: &RequestContext,
    operation: &OperationGuard,
) -> Result<ProviderHttpPooledResponse, ProviderHttpError> {
    match result {
        Err(error)
            if error.code() == ProviderHttpErrorCode::Cancelled
                && operation.forced_shutdown()
                && parent_context.check_active().is_ok() =>
        {
            Err(pool_shutdown_error())
        }
        outcome => outcome,
    }
}

fn lock_state(state: &Mutex<PoolState>) -> MutexGuard<'_, PoolState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn begin_shutdown(inner: &PoolInner) -> usize {
    let mut state = inner.lock();
    if state.mode == PoolMode::Accepting {
        state.mode = PoolMode::Draining;
    }
    let idle = state.idle.drain(..).collect::<Vec<_>>();
    for entry in &idle {
        retire_live(&mut state, entry.id);
    }
    let idle_count = idle.len();
    drop(state);
    drop(idle);
    inner.changed.notify_waiters();
    idle_count
}

pub(crate) fn force_shutdown(inner: &PoolInner) -> usize {
    let mut state = inner.lock();
    state.mode = PoolMode::Stopped;
    for operation in state.operations.values() {
        operation.forced_shutdown.store(true, Ordering::Release);
        operation.cancellation.cancel();
    }
    let active = state.drivers.len();
    state.live = state.live.saturating_sub(active);
    for (_id, driver) in std::mem::take(&mut state.drivers) {
        driver.abort();
        state.retired_drivers.push(driver);
    }
    drop(state);
    inner.changed.notify_waiters();
    active
}

pub(crate) fn complete_shutdown(inner: &PoolInner) {
    let mut state = inner.lock();
    state.mode = PoolMode::Stopped;
    drop(state);
    inner.changed.notify_waiters();
}

pub(crate) fn collect_shutdown_drivers(inner: &PoolInner) -> Vec<JoinHandle<()>> {
    std::mem::take(&mut inner.lock().retired_drivers)
}

pub(crate) fn drain_complete(inner: &PoolInner) -> bool {
    let state = inner.lock();
    state.live == 0 && state.operations.is_empty()
}

pub(crate) fn forced_cleanup_complete(inner: &PoolInner) -> bool {
    let state = inner.lock();
    state.reservations.is_empty() && state.operations.is_empty()
}

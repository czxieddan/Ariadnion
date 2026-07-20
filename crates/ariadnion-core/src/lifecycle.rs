//! Failure-isolated module validation, startup, health, and shutdown supervision.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::capability::{CapabilityGraph, CapabilityRequirement, CapabilityResolution};
use crate::context::CancellationToken;
use crate::error::{CoreError, ErrorCode};
use crate::health::{HealthReasonCode, HealthReport, HealthStatus, ModuleHealthSnapshot};
use crate::ids::ModuleId;
use crate::module::{
    ModuleConfigurationSnapshot, ModuleContext, ModuleDescriptor, ModuleFactory, ModuleHandle,
    ModuleShutdownReport,
};
use crate::version::CORE_ABI_VERSION;

const MAX_MODULES: usize = 256;
const WORKER_THREAD_NAME: &str = "ariadnion-module-operation";

/// The stable module lifecycle states exposed by core diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ModuleState {
    /// Metadata was registered but not validated.
    Discovered = 0,
    /// Configuration and dependencies were validated without side effects.
    Validated = 1,
    /// The module factory is starting operational work.
    Starting = 2,
    /// The module is ready for normal work.
    Ready = 3,
    /// The module provides a reduced, explicitly bounded capability set.
    Degraded = 4,
    /// The module cannot safely provide its capabilities.
    Unavailable = 5,
    /// The module is rejecting new work and draining.
    Stopping = 6,
    /// The module completed shutdown.
    Stopped = 7,
}

impl ModuleState {
    /// Returns the stable machine-readable state name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        [
            "discovered",
            "validated",
            "starting",
            "ready",
            "degraded",
            "unavailable",
            "stopping",
            "stopped",
        ][self as usize]
    }
}

/// A safe immutable status entry for one module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleStatus {
    module_id: ModuleId,
    state: ModuleState,
    generation: u64,
    error_code: Option<ErrorCode>,
}

impl ModuleStatus {
    /// Returns the module identity.
    #[must_use]
    pub const fn module_id(&self) -> &ModuleId {
        &self.module_id
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ModuleState {
        self.state
    }

    /// Returns the operational generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the safe failure code, when unavailable.
    #[must_use]
    pub const fn error_code(&self) -> Option<ErrorCode> {
        self.error_code
    }
}

/// A bounded supervisor result that reports all modules without secret details.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LifecycleReport {
    statuses: Vec<ModuleStatus>,
    startup_order: Vec<ModuleId>,
}

impl LifecycleReport {
    /// Returns module statuses in registration order.
    #[must_use]
    pub fn statuses(&self) -> &[ModuleStatus] {
        &self.statuses
    }

    /// Returns module identities in their first successful startup order.
    #[must_use]
    pub fn startup_order(&self) -> &[ModuleId] {
        &self.startup_order
    }
}

struct ManagedModule {
    descriptor: ModuleDescriptor,
    factory: Arc<dyn ModuleFactory>,
    configuration: ModuleConfigurationSnapshot,
    resolution: Option<CapabilityResolution>,
    handle: Option<Box<dyn ModuleHandle>>,
    cancellation: CancellationToken,
    state: ModuleState,
    generation: u64,
    error_code: Option<ErrorCode>,
}

/// Supervises a bounded set of statically linked modules.
///
/// Synchronous module operations run on one-result bounded workers. When a
/// deadline expires, core cancels only that module, abandons the result slot,
/// and continues supervising other modules. Rust cannot terminate a blocked
/// thread safely, so the timed-out worker retains ownership of any live handle
/// and retires it before release. An uncooperative module can therefore retain
/// one detached worker for that failed operation, but core never retries an
/// unavailable module and never retains an unbounded queue of worker results.
pub struct LifecycleSupervisor {
    modules: Vec<ManagedModule>,
    startup_order: Vec<usize>,
    validation_order: Vec<usize>,
    cancellation: CancellationToken,
}

impl LifecycleSupervisor {
    /// Creates an empty supervisor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            startup_order: Vec::new(),
            validation_order: Vec::new(),
            cancellation: CancellationToken::new(),
        }
    }

    /// Registers a module without executing validation or side effects.
    ///
    /// Duplicate module identities return [`ErrorCode::Conflict`]. ABI or
    /// configuration schema mismatch isolates the module as `unavailable` while
    /// registration continues so core can report the failure.
    pub fn register(
        &mut self,
        factory: Arc<dyn ModuleFactory>,
        configuration: ModuleConfigurationSnapshot,
    ) -> Result<(), CoreError> {
        self.validate_registration(factory.descriptor())?;
        let descriptor = factory.descriptor().clone();
        let mut module = ManagedModule {
            descriptor,
            factory,
            configuration,
            resolution: None,
            handle: None,
            cancellation: self.cancellation.child(),
            state: ModuleState::Discovered,
            generation: 0,
            error_code: None,
        };
        validate_static_contracts(&mut module);
        self.modules.push(module);
        Ok(())
    }

    /// Validates capabilities, cycles, configuration, and new factories.
    ///
    /// Ready or degraded modules retain their live handles and are not
    /// revalidated. Failures are stored on individual modules and never stop
    /// validation of unrelated modules.
    #[must_use]
    pub fn validate_all(&mut self) -> LifecycleReport {
        let graph = self.build_capability_graph();
        self.resolve_requirements(&graph);
        let cycles = cycle_members(&self.modules);
        self.mark_cycles(&cycles);
        let order = dependency_order(&self.modules);
        self.validate_in_order(&order);
        self.validation_order = order;
        self.report()
    }

    /// Validates and starts every newly eligible module in dependency order.
    ///
    /// Existing ready or degraded modules are not restarted or replaced.
    /// Factory failures and deadlines isolate only the affected module while
    /// independent modules continue starting.
    #[must_use]
    pub fn start_all(&mut self) -> LifecycleReport {
        let _ = self.validate_all();
        let order = self.validation_order.clone();
        for index in order {
            if self.start_one(index) && !self.startup_order.contains(&index) {
                self.startup_order.push(index);
            }
        }
        self.report()
    }

    /// Refreshes health for started modules and returns an aggregate report.
    ///
    /// A failed, unavailable, or timed-out probe cancels the module context and
    /// retires the live handle within its declared shutdown budget.
    #[must_use]
    pub fn health(&mut self) -> HealthReport {
        let mut report = HealthReport::core_ready();
        for module in &mut self.modules {
            let Some(snapshot) = refresh_module_health(module) else {
                continue;
            };
            if report.add_module(snapshot).is_err() {
                return HealthReport::new(
                    HealthStatus::Unavailable,
                    HealthReasonCode::ResourceExhausted,
                );
            }
        }
        report
    }

    /// Stops modules in dependency-safe deterministic order.
    ///
    /// Consumers stop before providers. Independent modules use descending
    /// declared shutdown priority and then ascending module identity. Each
    /// handle receives the earlier of the caller deadline and its own shutdown
    /// budget; a slow handle cannot prevent later modules from receiving stop.
    #[must_use]
    pub fn shutdown_all(&mut self, deadline: SystemTime) -> LifecycleReport {
        self.cancellation.cancel();
        let order = shutdown_order(&self.modules);
        for index in order {
            self.shutdown_one(index, deadline);
        }
        self.report()
    }

    /// Returns the process cancellation token linked to every module context.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    fn validate_registration(&self, descriptor: &ModuleDescriptor) -> Result<(), CoreError> {
        if self.modules.len() >= MAX_MODULES {
            return Err(CoreError::from_code(ErrorCode::ResourceExhausted)
                .with_internal_context("module registration limit reached"));
        }
        if self
            .modules
            .iter()
            .any(|module| module.descriptor.id() == descriptor.id())
        {
            return Err(CoreError::from_code(ErrorCode::Conflict)
                .with_internal_context("module identity is already registered"));
        }
        Ok(())
    }

    fn build_capability_graph(&mut self) -> CapabilityGraph {
        let mut graph = CapabilityGraph::new();
        for module in &mut self.modules {
            register_module_capabilities(module, &mut graph);
        }
        graph
    }

    fn resolve_requirements(&mut self, graph: &CapabilityGraph) {
        for module in &mut self.modules {
            if !participates_in_resolution(module.state) {
                continue;
            }
            let requirements = descriptor_requirements(&module.descriptor);
            match graph.resolve(&requirements) {
                Ok(resolution) => module.resolution = Some(resolution),
                Err(error) => mark_unavailable(module, error.code()),
            }
        }
    }

    fn mark_cycles(&mut self, cycles: &[usize]) {
        for index in cycles {
            mark_unavailable(&mut self.modules[*index], ErrorCode::Conflict);
        }
    }

    fn validate_in_order(&mut self, order: &[usize]) {
        let accepted = [
            ModuleState::Validated,
            ModuleState::Ready,
            ModuleState::Degraded,
        ];
        for index in order {
            if self.modules[*index].state != ModuleState::Discovered {
                continue;
            }
            if !dependencies_in_states(&self.modules, *index, &accepted) {
                mark_unavailable(&mut self.modules[*index], ErrorCode::Unavailable);
                continue;
            }
            validate_module(&mut self.modules[*index]);
        }
    }

    fn start_one(&mut self, index: usize) -> bool {
        if is_live_state(self.modules[index].state) {
            return false;
        }
        if self.modules[index].state != ModuleState::Validated {
            return false;
        }
        let accepted = [ModuleState::Ready, ModuleState::Degraded];
        if !dependencies_in_states(&self.modules, index, &accepted) {
            mark_unavailable(&mut self.modules[index], ErrorCode::Unavailable);
            return false;
        }
        start_validated_module(&mut self.modules[index])
    }

    fn shutdown_one(&mut self, index: usize, caller_deadline: SystemTime) {
        if self.modules[index].handle.is_none() {
            return;
        }
        let module = &mut self.modules[index];
        module.state = ModuleState::Stopping;
        match run_shutdown_operation(module, Some(caller_deadline)) {
            ShutdownOutcome::Completed(Ok(_)) => mark_stopped(module),
            ShutdownOutcome::Completed(Err(error)) => mark_unavailable(module, error.code()),
            ShutdownOutcome::DeadlineExceeded => {
                mark_unavailable(module, ErrorCode::DeadlineExceeded);
            }
            ShutdownOutcome::Unavailable => mark_unavailable(module, ErrorCode::Unavailable),
            ShutdownOutcome::NoHandle => {}
        }
    }

    fn report(&self) -> LifecycleReport {
        let statuses = self.modules.iter().map(module_status).collect();
        let startup_order = self
            .startup_order
            .iter()
            .map(|index| self.modules[*index].descriptor.id().clone())
            .collect();
        LifecycleReport {
            statuses,
            startup_order,
        }
    }
}

impl Default for LifecycleSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

struct StartPreparation {
    factory: Arc<dyn ModuleFactory>,
    context: ModuleContext,
    cancellation: CancellationToken,
    generation: u64,
    startup_timeout: Duration,
    shutdown_timeout: Duration,
}

fn start_validated_module(module: &mut ManagedModule) -> bool {
    let preparation = match prepare_start(module) {
        Ok(preparation) => preparation,
        Err(code) => {
            mark_unavailable(module, code);
            return false;
        }
    };
    module.state = ModuleState::Starting;
    let cleanup_cancellation = preparation.cancellation.clone();
    let cleanup_timeout = preparation.shutdown_timeout;
    let outcome = run_bounded(
        preparation.startup_timeout,
        move || guarded_module_call(|| preparation.factory.start(preparation.context)),
        move |result| cleanup_late_start(result, cleanup_cancellation, cleanup_timeout),
    );
    apply_start_outcome(module, preparation.generation, outcome)
}

fn prepare_start(module: &ManagedModule) -> Result<StartPreparation, ErrorCode> {
    let resolution = module.resolution.clone().ok_or(ErrorCode::Unavailable)?;
    let generation = module
        .generation
        .checked_add(1)
        .ok_or(ErrorCode::ResourceExhausted)?;
    let lifecycle = module.descriptor.resources().lifecycle();
    Ok(StartPreparation {
        factory: module.factory.clone(),
        context: ModuleContext::new(module.cancellation.clone(), resolution),
        cancellation: module.cancellation.clone(),
        generation,
        startup_timeout: lifecycle.startup_timeout(),
        shutdown_timeout: lifecycle.shutdown_timeout(),
    })
}

fn apply_start_outcome(
    module: &mut ManagedModule,
    generation: u64,
    outcome: BoundedOutcome<Result<Box<dyn ModuleHandle>, CoreError>>,
) -> bool {
    match outcome {
        BoundedOutcome::Completed(Ok(handle)) => {
            module.handle = Some(handle);
            module.generation = generation;
            module.state = ModuleState::Ready;
            module.error_code = None;
            true
        }
        BoundedOutcome::Completed(Err(error)) => {
            mark_unavailable(module, error.code());
            false
        }
        BoundedOutcome::DeadlineExceeded => {
            mark_unavailable(module, ErrorCode::DeadlineExceeded);
            false
        }
        BoundedOutcome::Unavailable => {
            mark_unavailable(module, ErrorCode::Unavailable);
            false
        }
    }
}

fn cleanup_late_start(
    result: Result<Box<dyn ModuleHandle>, CoreError>,
    cancellation: CancellationToken,
    shutdown_timeout: Duration,
) {
    if let Ok(handle) = result {
        retire_detached_handle(handle, cancellation, shutdown_timeout);
    }
}

fn validate_static_contracts(module: &mut ManagedModule) {
    if module.descriptor.abi_version() != CORE_ABI_VERSION {
        mark_unavailable(module, ErrorCode::Conflict);
        return;
    }
    if module.configuration.schema_id() != module.descriptor.configuration().schema_id() {
        mark_unavailable(module, ErrorCode::Conflict);
    }
}

fn register_module_capabilities(module: &mut ManagedModule, graph: &mut CapabilityGraph) {
    if !participates_in_resolution(module.state) {
        return;
    }
    if let Err(error) = graph.register_batch(module.descriptor.provided_capabilities()) {
        mark_unavailable(module, error.code());
    }
}

fn descriptor_requirements(descriptor: &ModuleDescriptor) -> Vec<CapabilityRequirement> {
    descriptor
        .required_capabilities()
        .iter()
        .cloned()
        .chain(
            descriptor
                .required_secret_capabilities()
                .iter()
                .map(|secret| secret.requirement().clone()),
        )
        .collect()
}

fn cycle_members(modules: &[ManagedModule]) -> Vec<usize> {
    let dependencies = dependency_indices(modules);
    modules
        .iter()
        .enumerate()
        .filter(|(index, module)| {
            participates_in_resolution(module.state)
                && dependency_path_returns_to(*index, &dependencies)
        })
        .map(|(index, _)| index)
        .collect()
}

fn dependency_path_returns_to(origin: usize, dependencies: &[Vec<usize>]) -> bool {
    let mut pending = VecDeque::from(dependencies[origin].clone());
    let mut visited = vec![false; dependencies.len()];
    while let Some(index) = pending.pop_front() {
        if index == origin {
            return true;
        }
        if visited[index] {
            continue;
        }
        visited[index] = true;
        pending.extend(dependencies[index].iter().copied());
    }
    false
}

fn dependency_order(modules: &[ManagedModule]) -> Vec<usize> {
    let dependencies = dependency_indices(modules);
    let mut indegrees = dependencies.iter().map(Vec::len).collect::<Vec<_>>();
    let mut queue = initial_queue(modules, &indegrees);
    let mut order = Vec::with_capacity(modules.len());
    while let Some(provider) = queue.pop_front() {
        order.push(provider);
        release_dependents(provider, &dependencies, &mut indegrees, &mut queue);
    }
    order
}

fn dependency_indices(modules: &[ManagedModule]) -> Vec<Vec<usize>> {
    let mut dependencies = vec![Vec::new(); modules.len()];
    for (consumer_index, module) in modules.iter().enumerate() {
        if !participates_in_resolution(module.state) {
            continue;
        }
        let Some(resolution) = module.resolution.as_ref() else {
            continue;
        };
        add_active_dependencies(modules, resolution, &mut dependencies[consumer_index]);
    }
    dependencies
}

fn add_active_dependencies(
    modules: &[ManagedModule],
    resolution: &CapabilityResolution,
    dependencies: &mut Vec<usize>,
) {
    for binding in resolution.bindings() {
        let Some(provider) = module_index(modules, binding.provider().module_id()) else {
            continue;
        };
        if participates_in_resolution(modules[provider].state) {
            dependencies.push(provider);
        }
    }
    dependencies.sort_unstable();
    dependencies.dedup();
}

fn initial_queue(modules: &[ManagedModule], indegrees: &[usize]) -> VecDeque<usize> {
    modules
        .iter()
        .enumerate()
        .filter(|(index, module)| {
            participates_in_resolution(module.state) && indegrees[*index] == 0
        })
        .map(|(index, _)| index)
        .collect()
}

fn release_dependents(
    provider: usize,
    dependencies: &[Vec<usize>],
    indegrees: &mut [usize],
    queue: &mut VecDeque<usize>,
) {
    for consumer in 0..dependencies.len() {
        if dependencies[consumer].contains(&provider) && indegrees[consumer] > 0 {
            indegrees[consumer] -= 1;
            if indegrees[consumer] == 0 {
                queue.push_back(consumer);
            }
        }
    }
}

fn module_index(modules: &[ManagedModule], id: &ModuleId) -> Option<usize> {
    modules
        .iter()
        .position(|module| module.descriptor.id() == id)
}

fn dependencies_in_states(
    modules: &[ManagedModule],
    consumer: usize,
    accepted: &[ModuleState],
) -> bool {
    let Some(resolution) = modules[consumer].resolution.as_ref() else {
        return false;
    };
    resolution.bindings().iter().all(|binding| {
        module_index(modules, binding.provider().module_id())
            .is_some_and(|provider| accepted.contains(&modules[provider].state))
    })
}

fn validate_module(module: &mut ManagedModule) {
    let Some(resolution) = module.resolution.clone() else {
        mark_unavailable(module, ErrorCode::Unavailable);
        return;
    };
    let factory = module.factory.clone();
    let configuration = module.configuration.clone();
    let timeout = module.descriptor.resources().lifecycle().startup_timeout();
    let outcome = run_bounded(
        timeout,
        move || guarded_module_call(|| factory.validate(&configuration, &resolution)),
        |_| {},
    );
    apply_validation_outcome(module, outcome);
}

fn apply_validation_outcome(
    module: &mut ManagedModule,
    outcome: BoundedOutcome<Result<(), CoreError>>,
) {
    match outcome {
        BoundedOutcome::Completed(Ok(())) => {
            module.state = ModuleState::Validated;
            module.error_code = None;
        }
        BoundedOutcome::Completed(Err(error)) => mark_unavailable(module, error.code()),
        BoundedOutcome::DeadlineExceeded => {
            mark_unavailable(module, ErrorCode::DeadlineExceeded);
        }
        BoundedOutcome::Unavailable => mark_unavailable(module, ErrorCode::Unavailable),
    }
}

struct HealthOperation {
    handle: Box<dyn ModuleHandle>,
    result: Result<ModuleHealthSnapshot, CoreError>,
}

fn refresh_module_health(module: &mut ManagedModule) -> Option<ModuleHealthSnapshot> {
    let handle = module.handle.take()?;
    let cell = handle_cell(handle);
    let worker_cell = cell.clone();
    let cancellation = module.cancellation.clone();
    let cleanup_cancellation = cancellation.clone();
    let lifecycle = module.descriptor.resources().lifecycle();
    let shutdown_timeout = lifecycle.shutdown_timeout();
    let outcome = run_bounded(
        lifecycle.health_timeout(),
        move || execute_health(worker_cell),
        move |operation| {
            cleanup_late_health(operation, cleanup_cancellation, shutdown_timeout);
        },
    );
    apply_health_outcome(module, cell, outcome)
}

fn execute_health(cell: HandleCell) -> Option<HealthOperation> {
    let handle = take_handle(&cell)?;
    let result = guarded_module_call(|| handle.health());
    Some(HealthOperation { handle, result })
}

fn cleanup_late_health(
    operation: Option<HealthOperation>,
    cancellation: CancellationToken,
    shutdown_timeout: Duration,
) {
    if let Some(operation) = operation {
        retire_detached_handle(operation.handle, cancellation, shutdown_timeout);
    }
}

fn apply_health_outcome(
    module: &mut ManagedModule,
    cell: HandleCell,
    outcome: BoundedOutcome<Option<HealthOperation>>,
) -> Option<ModuleHealthSnapshot> {
    match outcome {
        BoundedOutcome::Completed(Some(operation)) => apply_completed_health(module, operation),
        BoundedOutcome::Completed(None) => Some(fail_health(module, ErrorCode::Internal)),
        BoundedOutcome::DeadlineExceeded => Some(fail_health(module, ErrorCode::DeadlineExceeded)),
        BoundedOutcome::Unavailable => {
            module.handle = take_handle(&cell);
            Some(fail_health(module, ErrorCode::Unavailable))
        }
    }
}

fn apply_completed_health(
    module: &mut ManagedModule,
    operation: HealthOperation,
) -> Option<ModuleHealthSnapshot> {
    module.handle = Some(operation.handle);
    match operation.result {
        Ok(snapshot) => Some(apply_health_snapshot(module, snapshot)),
        Err(error) => Some(fail_health(module, error.code())),
    }
}

fn apply_health_snapshot(
    module: &mut ManagedModule,
    snapshot: ModuleHealthSnapshot,
) -> ModuleHealthSnapshot {
    if snapshot.status() == HealthStatus::Unavailable {
        retire_unavailable(module, ErrorCode::Unavailable);
    } else {
        module.state = state_from_health(snapshot.status());
        module.error_code = None;
    }
    snapshot
}

fn fail_health(module: &mut ManagedModule, code: ErrorCode) -> ModuleHealthSnapshot {
    retire_unavailable(module, code);
    ModuleHealthSnapshot::new(
        module.descriptor.id().clone(),
        HealthStatus::Unavailable,
        HealthReasonCode::InternalFailure,
    )
}

fn retire_unavailable(module: &mut ManagedModule, code: ErrorCode) {
    mark_unavailable(module, code);
    let _ = run_shutdown_operation(module, None);
}

fn state_from_health(status: HealthStatus) -> ModuleState {
    match status {
        HealthStatus::Live => ModuleState::Starting,
        HealthStatus::Ready => ModuleState::Ready,
        HealthStatus::Degraded => ModuleState::Degraded,
        HealthStatus::Unavailable => ModuleState::Unavailable,
    }
}

struct ShutdownOperation {
    handle: Box<dyn ModuleHandle>,
    result: Result<ModuleShutdownReport, CoreError>,
}

enum ShutdownOutcome {
    Completed(Result<ModuleShutdownReport, CoreError>),
    DeadlineExceeded,
    Unavailable,
    NoHandle,
}

fn run_shutdown_operation(
    module: &mut ManagedModule,
    caller_deadline: Option<SystemTime>,
) -> ShutdownOutcome {
    let Some(handle) = module.handle.take() else {
        return ShutdownOutcome::NoHandle;
    };
    module.cancellation.cancel();
    let deadline = effective_shutdown_deadline(module, caller_deadline);
    let timeout = remaining_system_time(deadline);
    let cell = handle_cell(handle);
    let worker_cell = cell.clone();
    let outcome = run_bounded(
        timeout,
        move || execute_shutdown(worker_cell, deadline),
        drop_shutdown_operation,
    );
    map_shutdown_outcome(module, cell, outcome)
}

fn execute_shutdown(cell: HandleCell, deadline: SystemTime) -> Option<ShutdownOperation> {
    let mut handle = take_handle(&cell)?;
    let result = guarded_module_call(|| handle.shutdown(deadline));
    Some(ShutdownOperation { handle, result })
}

fn drop_shutdown_operation(operation: Option<ShutdownOperation>) {
    drop(operation);
}

fn map_shutdown_outcome(
    module: &mut ManagedModule,
    cell: HandleCell,
    outcome: BoundedOutcome<Option<ShutdownOperation>>,
) -> ShutdownOutcome {
    match outcome {
        BoundedOutcome::Completed(Some(operation)) => {
            let ShutdownOperation { handle, result } = operation;
            drop(handle);
            ShutdownOutcome::Completed(result)
        }
        BoundedOutcome::Completed(None) => ShutdownOutcome::Unavailable,
        BoundedOutcome::DeadlineExceeded => ShutdownOutcome::DeadlineExceeded,
        BoundedOutcome::Unavailable => {
            module.handle = take_handle(&cell);
            ShutdownOutcome::Unavailable
        }
    }
}

fn effective_shutdown_deadline(
    module: &ManagedModule,
    caller_deadline: Option<SystemTime>,
) -> SystemTime {
    let now = SystemTime::now();
    let budget = module.descriptor.resources().lifecycle().shutdown_timeout();
    let budget_deadline = now.checked_add(budget);
    match (budget_deadline, caller_deadline) {
        (Some(budget), Some(caller)) => std::cmp::min(budget, caller),
        (Some(budget), None) => budget,
        (None, Some(caller)) => caller,
        (None, None) => now,
    }
}

fn remaining_system_time(deadline: SystemTime) -> Duration {
    deadline
        .duration_since(SystemTime::now())
        .map_or(Duration::ZERO, |remaining| remaining)
}

fn retire_detached_handle(
    mut handle: Box<dyn ModuleHandle>,
    cancellation: CancellationToken,
    shutdown_timeout: Duration,
) {
    cancellation.cancel();
    let now = SystemTime::now();
    let deadline = now.checked_add(shutdown_timeout).map_or(now, |value| value);
    let _ = guarded_module_call(|| handle.shutdown(deadline));
}

type HandleCell = Arc<Mutex<Option<Box<dyn ModuleHandle>>>>;

fn handle_cell(handle: Box<dyn ModuleHandle>) -> HandleCell {
    Arc::new(Mutex::new(Some(handle)))
}

fn take_handle(cell: &HandleCell) -> Option<Box<dyn ModuleHandle>> {
    lock_recover(cell).take()
}

fn shutdown_order(modules: &[ManagedModule]) -> Vec<usize> {
    let dependencies = shutdown_dependencies(modules);
    let mut dependents = dependent_counts(&dependencies);
    let mut selected = vec![false; modules.len()];
    let target = modules
        .iter()
        .filter(|module| module.handle.is_some())
        .count();
    let mut order = Vec::with_capacity(target);
    while order.len() < target {
        let Some(index) = next_shutdown_module(modules, &dependents, &selected) else {
            break;
        };
        selected[index] = true;
        order.push(index);
        release_shutdown_dependencies(index, &dependencies, &mut dependents);
    }
    order
}

fn shutdown_dependencies(modules: &[ManagedModule]) -> Vec<Vec<usize>> {
    let mut dependencies = vec![Vec::new(); modules.len()];
    for (consumer, module) in modules.iter().enumerate() {
        let Some(resolution) = module
            .resolution
            .as_ref()
            .filter(|_| module.handle.is_some())
        else {
            continue;
        };
        add_shutdown_dependencies(modules, resolution, &mut dependencies[consumer]);
    }
    dependencies
}

fn add_shutdown_dependencies(
    modules: &[ManagedModule],
    resolution: &CapabilityResolution,
    dependencies: &mut Vec<usize>,
) {
    for binding in resolution.bindings() {
        let provider = module_index(modules, binding.provider().module_id());
        if provider.is_some_and(|index| modules[index].handle.is_some()) {
            dependencies.extend(provider);
        }
    }
    dependencies.sort_unstable();
    dependencies.dedup();
}

fn dependent_counts(dependencies: &[Vec<usize>]) -> Vec<usize> {
    let mut counts = vec![0_usize; dependencies.len()];
    for providers in dependencies {
        for provider in providers {
            counts[*provider] = counts[*provider].saturating_add(1);
        }
    }
    counts
}

fn next_shutdown_module(
    modules: &[ManagedModule],
    dependents: &[usize],
    selected: &[bool],
) -> Option<usize> {
    let mut eligible = shutdown_candidates(modules, dependents, selected, true);
    if eligible.is_empty() {
        eligible = shutdown_candidates(modules, dependents, selected, false);
    }
    eligible.sort_by(|left, right| compare_shutdown_order(modules, *left, *right));
    eligible.first().copied()
}

fn shutdown_candidates(
    modules: &[ManagedModule],
    dependents: &[usize],
    selected: &[bool],
    require_leaf: bool,
) -> Vec<usize> {
    modules
        .iter()
        .enumerate()
        .filter(|(index, module)| {
            module.handle.is_some()
                && !selected[*index]
                && (!require_leaf || dependents[*index] == 0)
        })
        .map(|(index, _)| index)
        .collect()
}

fn compare_shutdown_order(
    modules: &[ManagedModule],
    left: usize,
    right: usize,
) -> std::cmp::Ordering {
    modules[right]
        .descriptor
        .shutdown_priority()
        .cmp(&modules[left].descriptor.shutdown_priority())
        .then_with(|| {
            modules[left]
                .descriptor
                .id()
                .cmp(modules[right].descriptor.id())
        })
}

fn release_shutdown_dependencies(
    consumer: usize,
    dependencies: &[Vec<usize>],
    dependents: &mut [usize],
) {
    for provider in &dependencies[consumer] {
        dependents[*provider] = dependents[*provider].saturating_sub(1);
    }
}

fn participates_in_resolution(state: ModuleState) -> bool {
    matches!(
        state,
        ModuleState::Discovered
            | ModuleState::Validated
            | ModuleState::Starting
            | ModuleState::Ready
            | ModuleState::Degraded
    )
}

fn is_live_state(state: ModuleState) -> bool {
    matches!(
        state,
        ModuleState::Starting | ModuleState::Ready | ModuleState::Degraded
    )
}

fn module_status(module: &ManagedModule) -> ModuleStatus {
    ModuleStatus {
        module_id: module.descriptor.id().clone(),
        state: module.state,
        generation: module.generation,
        error_code: module.error_code,
    }
}

fn mark_unavailable(module: &mut ManagedModule, code: ErrorCode) {
    module.cancellation.cancel();
    module.state = ModuleState::Unavailable;
    module.error_code = Some(code);
}

fn mark_stopped(module: &mut ManagedModule) {
    module.state = ModuleState::Stopped;
    module.error_code = None;
}

enum BoundedOutcome<T> {
    Completed(T),
    DeadlineExceeded,
    Unavailable,
}

struct WorkerState<T> {
    output: Option<T>,
    abandoned: bool,
}

type WorkerShared<T> = Arc<(Mutex<WorkerState<T>>, Condvar)>;

fn run_bounded<T, W, C>(timeout: Duration, work: W, cleanup: C) -> BoundedOutcome<T>
where
    T: Send + 'static,
    W: FnOnce() -> T + Send + 'static,
    C: FnOnce(T) + Send + 'static,
{
    let started = Instant::now();
    let deadline = started.checked_add(timeout).unwrap_or(started);
    let shared = Arc::new((
        Mutex::new(WorkerState {
            output: None,
            abandoned: false,
        }),
        Condvar::new(),
    ));
    let worker_shared = shared.clone();
    let worker = thread::Builder::new()
        .name(WORKER_THREAD_NAME.into())
        .spawn(move || publish_worker_output(&worker_shared, work(), cleanup));
    if worker.is_err() {
        return BoundedOutcome::Unavailable;
    }
    drop(worker);
    await_worker_output(&shared, deadline)
}

fn publish_worker_output<T, C>(shared: &WorkerShared<T>, output: T, cleanup: C)
where
    C: FnOnce(T),
{
    let abandoned_output = {
        let (lock, condition) = &**shared;
        let mut state = lock_recover(lock);
        if state.abandoned {
            Some(output)
        } else {
            state.output = Some(output);
            condition.notify_one();
            None
        }
    };
    if let Some(output) = abandoned_output {
        cleanup(output);
    }
}

fn await_worker_output<T>(shared: &WorkerShared<T>, deadline: Instant) -> BoundedOutcome<T> {
    let (lock, condition) = &**shared;
    let mut state = lock_recover(lock);
    loop {
        if let Some(output) = state.output.take() {
            return BoundedOutcome::Completed(output);
        }
        let Some(remaining) = remaining_instant(deadline) else {
            state.abandoned = true;
            return BoundedOutcome::DeadlineExceeded;
        };
        state = wait_worker(condition, state, remaining);
    }
}

fn remaining_instant(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    (now < deadline).then(|| deadline.saturating_duration_since(now))
}

fn wait_worker<'a, T>(
    condition: &Condvar,
    state: MutexGuard<'a, WorkerState<T>>,
    remaining: Duration,
) -> MutexGuard<'a, WorkerState<T>> {
    match condition.wait_timeout(state, remaining) {
        Ok((next, _)) => next,
        Err(poisoned) => poisoned.into_inner().0,
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn guarded_module_call<T>(
    operation: impl FnOnce() -> Result<T, CoreError>,
) -> Result<T, CoreError> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => Err(CoreError::from_code(ErrorCode::Internal)
            .with_internal_context("module operation panicked")),
    }
}

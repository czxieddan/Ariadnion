//! Failure-isolated module validation, startup, health, and shutdown supervision.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::SystemTime;

use crate::capability::{CapabilityGraph, CapabilityResolution};
use crate::context::CancellationToken;
use crate::error::{CoreError, ErrorCode};
use crate::health::{HealthReasonCode, HealthReport, HealthStatus};
use crate::ids::ModuleId;
use crate::module::{
    ModuleConfigurationSnapshot, ModuleContext, ModuleDescriptor, ModuleFactory, ModuleHandle,
};
use crate::version::CORE_ABI_VERSION;

const MAX_MODULES: usize = 256;

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

    /// Returns successfully ordered module identities.
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
    state: ModuleState,
    generation: u64,
    error_code: Option<ErrorCode>,
}

/// Supervises a bounded set of statically linked modules.
pub struct LifecycleSupervisor {
    modules: Vec<ManagedModule>,
    startup_order: Vec<usize>,
    cancellation: CancellationToken,
}

impl LifecycleSupervisor {
    /// Creates an empty supervisor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            startup_order: Vec::new(),
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
            state: ModuleState::Discovered,
            generation: 0,
            error_code: None,
        };
        validate_static_contracts(&mut module);
        self.modules.push(module);
        Ok(())
    }

    /// Validates capabilities, cycles, configuration, and factories.
    ///
    /// Failures are stored on individual modules and never stop validation of
    /// unrelated modules. The returned report contains no internal error text.
    #[must_use]
    pub fn validate_all(&mut self) -> LifecycleReport {
        self.startup_order.clear();
        let graph = self.build_capability_graph();
        self.resolve_requirements(&graph);
        let order = dependency_order(&self.modules);
        self.mark_cycles(&order);
        self.validate_in_order(&order);
        self.startup_order = order;
        self.report()
    }

    /// Validates and starts every eligible module in dependency order.
    ///
    /// A factory error marks only that module unavailable. Modules whose
    /// dependencies failed remain unavailable while independent modules start.
    #[must_use]
    pub fn start_all(&mut self) -> LifecycleReport {
        let _ = self.validate_all();
        let order = self.startup_order.clone();
        for index in order {
            self.start_one(index);
        }
        self.report()
    }

    /// Refreshes health for started modules and returns an aggregate report.
    #[must_use]
    pub fn health(&mut self) -> HealthReport {
        let mut report = HealthReport::core_ready();
        for module in &mut self.modules {
            let snapshot = refresh_module_health(module);
            if let Some(snapshot) = snapshot {
                let result = report.add_module(snapshot);
                if result.is_err() {
                    return HealthReport::new(
                        HealthStatus::Unavailable,
                        HealthReasonCode::ResourceExhausted,
                    );
                }
            }
        }
        report
    }

    /// Stops modules in reverse successful startup order.
    ///
    /// Shutdown failures are isolated and recorded as unavailable. The caller's
    /// UTC deadline is forwarded unchanged to each module handle.
    #[must_use]
    pub fn shutdown_all(&mut self, deadline: SystemTime) -> LifecycleReport {
        let order = self.startup_order.clone();
        for index in order.into_iter().rev() {
            self.shutdown_one(index, deadline);
        }
        self.cancellation.cancel();
        self.report()
    }

    /// Returns the shared cancellation token for module contexts.
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
            if module.state == ModuleState::Unavailable {
                continue;
            }
            match graph.resolve(module.descriptor.required_capabilities()) {
                Ok(resolution) => module.resolution = Some(resolution),
                Err(error) => mark_unavailable(module, error.code()),
            }
        }
    }

    fn mark_cycles(&mut self, order: &[usize]) {
        for index in 0..self.modules.len() {
            let eligible = self.modules[index].state != ModuleState::Unavailable;
            if eligible && !order.contains(&index) {
                mark_unavailable(&mut self.modules[index], ErrorCode::Conflict);
            }
        }
    }

    fn validate_in_order(&mut self, order: &[usize]) {
        for index in order {
            if !dependencies_in_states(&self.modules, *index, &[ModuleState::Validated]) {
                mark_unavailable(&mut self.modules[*index], ErrorCode::Unavailable);
                continue;
            }
            validate_module(&mut self.modules[*index]);
        }
    }

    fn start_one(&mut self, index: usize) {
        if !dependencies_in_states(
            &self.modules,
            index,
            &[ModuleState::Ready, ModuleState::Degraded],
        ) {
            mark_unavailable(&mut self.modules[index], ErrorCode::Unavailable);
            return;
        }
        let module = &mut self.modules[index];
        if module.state != ModuleState::Validated {
            return;
        }
        let Some(resolution) = module.resolution.clone() else {
            mark_unavailable(module, ErrorCode::Unavailable);
            return;
        };
        let Some(generation) = module.generation.checked_add(1) else {
            mark_unavailable(module, ErrorCode::ResourceExhausted);
            return;
        };
        module.state = ModuleState::Starting;
        let context = ModuleContext::new(self.cancellation.clone(), resolution);
        match module.factory.start(context) {
            Ok(handle) => {
                module.handle = Some(handle);
                module.generation = generation;
                module.state = ModuleState::Ready;
                module.error_code = None;
            }
            Err(error) => mark_unavailable(module, error.code()),
        }
    }

    fn shutdown_one(&mut self, index: usize, deadline: SystemTime) {
        let module = &mut self.modules[index];
        let Some(mut handle) = module.handle.take() else {
            return;
        };
        module.state = ModuleState::Stopping;
        match handle.shutdown(deadline) {
            Ok(_) => {
                module.state = ModuleState::Stopped;
                module.error_code = None;
            }
            Err(error) => mark_unavailable(module, error.code()),
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
    if module.state == ModuleState::Unavailable {
        return;
    }
    if has_duplicate_provider(module, graph) {
        mark_unavailable(module, ErrorCode::Conflict);
        return;
    }
    for provider in module.descriptor.provided_capabilities() {
        if let Err(error) = graph.register(provider.clone()) {
            mark_unavailable(module, error.code());
            return;
        }
    }
}

fn has_duplicate_provider(module: &ManagedModule, graph: &CapabilityGraph) -> bool {
    module
        .descriptor
        .provided_capabilities()
        .iter()
        .any(|provider| {
            graph
                .providers()
                .iter()
                .any(|existing| existing.id() == provider.id())
        })
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
        if module.state == ModuleState::Unavailable {
            continue;
        }
        let Some(resolution) = module.resolution.as_ref() else {
            continue;
        };
        for binding in resolution.bindings() {
            if let Some(provider_index) = module_index(modules, binding.provider().module_id()) {
                dependencies[consumer_index].push(provider_index);
            }
        }
        dependencies[consumer_index].sort_unstable();
        dependencies[consumer_index].dedup();
    }
    dependencies
}

fn initial_queue(modules: &[ManagedModule], indegrees: &[usize]) -> VecDeque<usize> {
    modules
        .iter()
        .enumerate()
        .filter(|(index, module)| {
            module.state != ModuleState::Unavailable && indegrees[*index] == 0
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
    if module.state == ModuleState::Unavailable {
        return;
    }
    let Some(resolution) = module.resolution.as_ref() else {
        mark_unavailable(module, ErrorCode::Unavailable);
        return;
    };
    match module.factory.validate(&module.configuration, resolution) {
        Ok(()) => module.state = ModuleState::Validated,
        Err(error) => mark_unavailable(module, error.code()),
    }
}

fn refresh_module_health(
    module: &mut ManagedModule,
) -> Option<crate::health::ModuleHealthSnapshot> {
    let handle = module.handle.as_ref()?;
    match handle.health() {
        Ok(snapshot) => {
            module.state = state_from_health(snapshot.status());
            Some(snapshot)
        }
        Err(error) => {
            mark_unavailable(module, error.code());
            Some(crate::health::ModuleHealthSnapshot::new(
                module.descriptor.id().clone(),
                HealthStatus::Unavailable,
                HealthReasonCode::InternalFailure,
            ))
        }
    }
}

fn state_from_health(status: HealthStatus) -> ModuleState {
    match status {
        HealthStatus::Live => ModuleState::Starting,
        HealthStatus::Ready => ModuleState::Ready,
        HealthStatus::Degraded => ModuleState::Degraded,
        HealthStatus::Unavailable => ModuleState::Unavailable,
    }
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
    module.state = ModuleState::Unavailable;
    module.error_code = Some(code);
    module.handle = None;
}

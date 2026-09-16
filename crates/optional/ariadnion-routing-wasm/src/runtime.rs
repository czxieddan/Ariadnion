// crates/optional/ariadnion-routing-wasm/src/runtime.rs - Wasmtime routing component runtime.
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

use std::sync::{Mutex, mpsc};
use std::thread;

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, OutOfMemory, ResourceLimiter, Store, Trap};

use crate::{
    RoutingWasmDegradation, RoutingWasmError, RoutingWasmErrorCode, RoutingWasmEvaluator,
    RoutingWasmInput, RoutingWasmModuleDescriptor, RoutingWasmOutput, RoutingWasmResult, error,
};

wasmtime::component::bindgen!({
    path: "wit/routing.wit",
    world: "routing-component",
});

/// Component ABI version implemented by this runtime.
pub const ROUTING_WASM_ABI_VERSION: u16 = 1;
/// Maximum encoded component size accepted by the runtime.
pub const MAX_COMPONENT_BYTES: usize = 1 << 24;
/// Maximum core instances one invocation may instantiate.
pub const MAX_COMPONENT_INSTANCES: usize = 1 << 8;
/// Maximum linear memories one invocation may instantiate.
pub const MAX_COMPONENT_MEMORIES: usize = 1;
/// Maximum tables one invocation may instantiate.
pub const MAX_COMPONENT_TABLES: usize = 1 << 6;
/// Maximum elements permitted in each component-owned table.
pub const MAX_COMPONENT_TABLE_ELEMENTS: usize = 1 << 16;
/// Canonical WIT package implemented by routing components.
pub const ROUTING_WASM_WIT: &str = include_str!("../wit/routing.wit");

struct StoreState {
    limits: RoutingResourceLimiter,
}

struct RoutingResourceLimiter {
    memory_bytes: usize,
    exhausted: bool,
}

impl RoutingResourceLimiter {
    const fn new(memory_bytes: usize) -> Self {
        Self {
            memory_bytes,
            exhausted: false,
        }
    }

    const fn exhausted(&self) -> bool {
        self.exhausted
    }

    fn record_growth(
        &mut self,
        desired: usize,
        policy_limit: usize,
        guest_limit: Option<usize>,
    ) -> bool {
        let allowed = desired <= policy_limit && guest_limit.is_none_or(|limit| desired <= limit);
        self.exhausted |= !allowed;
        allowed
    }

    const fn record_failure(&mut self) {
        self.exhausted = true;
    }
}

impl ResourceLimiter for RoutingResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(self.record_growth(desired, self.memory_bytes, maximum))
    }

    fn memory_grow_failed(&mut self, _: wasmtime::Error) -> wasmtime::Result<()> {
        self.record_failure();
        Ok(())
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(self.record_growth(desired, MAX_COMPONENT_TABLE_ELEMENTS, maximum))
    }

    fn table_grow_failed(&mut self, _: wasmtime::Error) -> wasmtime::Result<()> {
        self.record_failure();
        Ok(())
    }

    fn instances(&self) -> usize {
        MAX_COMPONENT_INSTANCES
    }

    fn tables(&self) -> usize {
        MAX_COMPONENT_TABLES
    }

    fn memories(&self) -> usize {
        MAX_COMPONENT_MEMORIES
    }
}

/// Wasmtime 46 Component Model evaluator for one isolated routing component.
///
/// Construction validates the component bytes, the exact routing WIT world,
/// and the absence of host imports. Evaluation creates a fresh bounded store,
/// exposes no WASI or other host functions, and serializes invocations so an
/// epoch increment cannot escape its originating call. The synchronous
/// evaluator blocks the caller until the guest returns, consumes its fuel, or
/// reaches its wall-clock deadline; it does not provide a separate cancellation
/// handle.
pub struct WasmtimeRoutingRuntime {
    descriptor: RoutingWasmModuleDescriptor,
    component: RoutingComponentPre<StoreState>,
    invocation: Mutex<()>,
}

impl WasmtimeRoutingRuntime {
    /// Compiles and validates one encoded routing component.
    ///
    /// Components larger than [`MAX_COMPONENT_BYTES`] are rejected as resource
    /// exhaustion. Malformed components, unsupported ABI versions, imports, or
    /// exports that do not match [`ROUTING_WASM_WIT`] are invalid arguments.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`RoutingWasmErrorCode::ResourceExhausted`] when the
    /// encoded bytes or compiler allocation exceed a bound,
    /// [`RoutingWasmErrorCode::InvalidArgument`] for malformed or incompatible
    /// components, and [`RoutingWasmErrorCode::Unavailable`] when the Wasmtime
    /// engine cannot be initialized.
    pub fn new(
        descriptor: RoutingWasmModuleDescriptor,
        component_bytes: &[u8],
    ) -> Result<Self, RoutingWasmError> {
        validate_component_bytes(&descriptor, component_bytes)?;
        let engine = create_engine()?;
        let component =
            Component::from_binary(&engine, component_bytes).map_err(classify_component_load)?;
        let linker = Linker::<StoreState>::new(&engine);
        let prepared = linker
            .instantiate_pre(&component)
            .and_then(RoutingComponentPre::new)
            .map_err(classify_component_load)?;
        Ok(Self {
            descriptor,
            component: prepared,
            invocation: Mutex::new(()),
        })
    }

    /// Returns the immutable descriptor validated for this component.
    #[must_use]
    pub const fn descriptor(&self) -> &RoutingWasmModuleDescriptor {
        &self.descriptor
    }

    fn evaluate_bounded(
        &self,
        input: &RoutingWasmInput,
    ) -> Result<RoutingWasmResult, RoutingWasmError> {
        let budget = self.descriptor.policy().budget();
        let fuel = budget
            .fuel()
            .ok_or_else(|| runtime_error(RoutingWasmErrorCode::Unavailable))?;
        let memory = budget
            .max_memory_bytes()
            .ok_or_else(|| runtime_error(RoutingWasmErrorCode::Unavailable))?;
        let timeout = budget
            .epoch_timeout()
            .ok_or_else(|| runtime_error(RoutingWasmErrorCode::Unavailable))?;
        let mut store = create_store(self.component.engine(), memory, fuel)?;
        let candidates = guest_candidates(input);
        invoke_with_deadline(&self.component, &mut store, &candidates, timeout)
    }
}

impl RoutingWasmEvaluator for WasmtimeRoutingRuntime {
    fn evaluate(&self, input: &RoutingWasmInput) -> Result<RoutingWasmResult, RoutingWasmError> {
        let _guard = self
            .invocation
            .lock()
            .map_err(|_| runtime_error(RoutingWasmErrorCode::Trap))?;
        self.evaluate_bounded(input)
    }
}

fn validate_component_bytes(
    descriptor: &RoutingWasmModuleDescriptor,
    component_bytes: &[u8],
) -> Result<(), RoutingWasmError> {
    if component_bytes.len() > MAX_COMPONENT_BYTES {
        return Err(runtime_error(RoutingWasmErrorCode::ResourceExhausted));
    }
    if component_bytes.is_empty() || descriptor.abi_version() != ROUTING_WASM_ABI_VERSION {
        return Err(runtime_error(RoutingWasmErrorCode::InvalidArgument));
    }
    Ok(())
}

fn create_engine() -> Result<Engine, RoutingWasmError> {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .epoch_interruption(true)
        .wasm_component_model(true);
    Engine::new(&config).map_err(|_| runtime_error(RoutingWasmErrorCode::Unavailable))
}

fn create_store(
    engine: &Engine,
    memory: u64,
    fuel: u64,
) -> Result<Store<StoreState>, RoutingWasmError> {
    let memory = usize::try_from(memory)
        .map_err(|_| runtime_error(RoutingWasmErrorCode::ResourceExhausted))?;
    let limits = RoutingResourceLimiter::new(memory);
    let mut store = Store::new(engine, StoreState { limits });
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(fuel)
        .map_err(|_| runtime_error(RoutingWasmErrorCode::Unavailable))?;
    store.set_epoch_deadline(1);
    store.epoch_deadline_trap();
    Ok(store)
}

fn guest_candidates(input: &RoutingWasmInput) -> Vec<Candidate> {
    input
        .candidates()
        .iter()
        .map(|candidate| Candidate {
            identifier: candidate.candidate_id().into(),
            features: candidate.values().into(),
        })
        .collect()
}

fn invoke_with_deadline(
    component: &RoutingComponentPre<StoreState>,
    store: &mut Store<StoreState>,
    candidates: &[Candidate],
    timeout: std::time::Duration,
) -> Result<RoutingWasmResult, RoutingWasmError> {
    let (cancel, deadline) = mpsc::channel();
    let engine = component.engine().clone();
    let timer = thread::Builder::new()
        .name("ariadnion-routing-wasm-deadline".into())
        .spawn(move || wait_for_deadline(deadline, timeout, engine))
        .map_err(|_| runtime_error(RoutingWasmErrorCode::Unavailable))?;
    let result = invoke_component(component, store, candidates);
    let _ = cancel.send(());
    if timer.join().is_err() {
        return Ok(RoutingWasmResult::Degraded(RoutingWasmDegradation::Trap));
    }
    result
}

fn wait_for_deadline(deadline: mpsc::Receiver<()>, timeout: std::time::Duration, engine: Engine) {
    if matches!(
        deadline.recv_timeout(timeout),
        Err(mpsc::RecvTimeoutError::Timeout)
    ) {
        engine.increment_epoch();
    }
}

fn invoke_component(
    component: &RoutingComponentPre<StoreState>,
    store: &mut Store<StoreState>,
    candidates: &[Candidate],
) -> Result<RoutingWasmResult, RoutingWasmError> {
    let bindings = component
        .instantiate(&mut *store)
        .map_err(|failure| classify_instantiation(failure, store.data().limits.exhausted()));
    let bindings = match bindings {
        Ok(bindings) => bindings,
        Err(code) => return project_failure(code),
    };
    let decision = bindings.call_evaluate(&mut *store, candidates);
    let exhausted = store.data().limits.exhausted();
    match decision {
        Ok(_) if exhausted => project_failure(RoutingWasmErrorCode::ResourceExhausted),
        Ok(decision) => Ok(project_decision(decision, candidates)),
        Err(failure) => project_failure(classify_invocation(failure, exhausted)),
    }
}

fn project_decision(decision: Decision, candidates: &[Candidate]) -> RoutingWasmResult {
    match decision {
        Decision::Decline => RoutingWasmResult::Applied(RoutingWasmOutput::Decline),
        Decision::Select(index) => project_selection(index, candidates),
    }
}

fn project_selection(index: u32, candidates: &[Candidate]) -> RoutingWasmResult {
    let candidate = usize::try_from(index)
        .ok()
        .and_then(|index| candidates.get(index));
    match candidate {
        Some(candidate) => RoutingWasmResult::Applied(RoutingWasmOutput::Select(
            candidate.identifier.clone().into(),
        )),
        None => RoutingWasmResult::Degraded(RoutingWasmDegradation::InvalidOutput),
    }
}

fn project_failure(code: RoutingWasmErrorCode) -> Result<RoutingWasmResult, RoutingWasmError> {
    match code {
        RoutingWasmErrorCode::ResourceExhausted => Ok(RoutingWasmResult::Degraded(
            RoutingWasmDegradation::ResourceExhausted,
        )),
        RoutingWasmErrorCode::Timeout => {
            Ok(RoutingWasmResult::Degraded(RoutingWasmDegradation::Timeout))
        }
        RoutingWasmErrorCode::Trap => Ok(RoutingWasmResult::Degraded(RoutingWasmDegradation::Trap)),
        RoutingWasmErrorCode::InvalidOutput => Ok(RoutingWasmResult::Degraded(
            RoutingWasmDegradation::InvalidOutput,
        )),
        _ => Err(runtime_error(code)),
    }
}

fn classify_instantiation(failure: wasmtime::Error, exhausted: bool) -> RoutingWasmErrorCode {
    if exhausted || failure.downcast_ref::<OutOfMemory>().is_some() {
        return RoutingWasmErrorCode::ResourceExhausted;
    }
    classify_trap(&failure).unwrap_or(RoutingWasmErrorCode::ResourceExhausted)
}

fn classify_component_load(failure: wasmtime::Error) -> RoutingWasmError {
    if failure.downcast_ref::<OutOfMemory>().is_some() {
        return runtime_error(RoutingWasmErrorCode::ResourceExhausted);
    }
    runtime_error(RoutingWasmErrorCode::InvalidArgument)
}

fn classify_invocation(failure: wasmtime::Error, exhausted: bool) -> RoutingWasmErrorCode {
    if exhausted || failure.downcast_ref::<OutOfMemory>().is_some() {
        return RoutingWasmErrorCode::ResourceExhausted;
    }
    classify_trap(&failure).unwrap_or(RoutingWasmErrorCode::InvalidOutput)
}

fn classify_trap(failure: &wasmtime::Error) -> Option<RoutingWasmErrorCode> {
    match failure.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => Some(RoutingWasmErrorCode::ResourceExhausted),
        Some(Trap::Interrupt) => Some(RoutingWasmErrorCode::Timeout),
        Some(_) => Some(RoutingWasmErrorCode::Trap),
        None => None,
    }
}

const fn runtime_error(code: RoutingWasmErrorCode) -> RoutingWasmError {
    error(code)
}

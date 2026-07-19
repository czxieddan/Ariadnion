//! Bounded lifecycle, execution, and WASM resource budgets.

use std::time::Duration;

use crate::error::{CoreError, ErrorCode};

const MAX_LIFECYCLE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_RESTARTS: u16 = 1_024;
const MAX_QUEUE_CAPACITY: usize = 1_048_576;
const MAX_TASKS: usize = 65_536;
const MAX_MEMORY_BYTES: u64 = 1 << 40;
const MAX_WASM_FUEL: u64 = 1_000_000_000_000_000;

/// Inputs for a module's lifecycle deadlines and restart policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBudgetInput {
    /// Maximum duration for each validation or startup operation.
    pub startup_timeout: Duration,
    /// Maximum duration for a health probe.
    pub health_timeout: Duration,
    /// Maximum duration for a shutdown or handle-retirement operation.
    pub shutdown_timeout: Duration,
    /// Minimum delay before a permitted restart attempt.
    pub restart_delay: Duration,
    /// Maximum number of restart attempts in one supervisor generation.
    pub restart_limit: u16,
}

/// Immutable lifecycle deadlines and restart limits declared by a module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBudget {
    startup_timeout: Duration,
    health_timeout: Duration,
    shutdown_timeout: Duration,
    restart_delay: Duration,
    restart_limit: u16,
}

impl LifecycleBudget {
    /// Validates and creates lifecycle budgets.
    ///
    /// Every duration must be non-zero and no greater than 24 hours. The
    /// restart count may be zero to disable restarts and may not exceed 1,024.
    pub fn new(input: LifecycleBudgetInput) -> Result<Self, CoreError> {
        validate_lifecycle_input(input)?;
        Ok(Self {
            startup_timeout: input.startup_timeout,
            health_timeout: input.health_timeout,
            shutdown_timeout: input.shutdown_timeout,
            restart_delay: input.restart_delay,
            restart_limit: input.restart_limit,
        })
    }

    /// Returns the validation and startup deadline duration.
    #[must_use]
    pub const fn startup_timeout(self) -> Duration {
        self.startup_timeout
    }

    /// Returns the health probe deadline duration.
    #[must_use]
    pub const fn health_timeout(self) -> Duration {
        self.health_timeout
    }

    /// Returns the shutdown and retirement deadline duration.
    #[must_use]
    pub const fn shutdown_timeout(self) -> Duration {
        self.shutdown_timeout
    }

    /// Returns the minimum delay before a restart attempt.
    #[must_use]
    pub const fn restart_delay(self) -> Duration {
        self.restart_delay
    }

    /// Returns the maximum permitted restart count.
    #[must_use]
    pub const fn restart_limit(self) -> u16 {
        self.restart_limit
    }

    fn validate(self) -> Result<(), CoreError> {
        validate_lifecycle_input(LifecycleBudgetInput {
            startup_timeout: self.startup_timeout,
            health_timeout: self.health_timeout,
            shutdown_timeout: self.shutdown_timeout,
            restart_delay: self.restart_delay,
            restart_limit: self.restart_limit,
        })
    }
}

/// Inputs for a bounded WASM component execution budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmBudgetInput {
    /// Maximum fuel consumed by one component invocation.
    pub fuel: u64,
    /// Maximum linear memory available to the component in bytes.
    pub max_memory_bytes: u64,
    /// Maximum wall-clock epoch duration for one component invocation.
    pub epoch_timeout: Duration,
}

/// Validated limits for an enabled WASM component boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmBudgetLimits {
    fuel: u64,
    max_memory_bytes: u64,
    epoch_timeout: Duration,
}

/// Explicit WASM execution state for a module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WasmBudget {
    /// The module cannot execute WASM components.
    Disabled,
    /// The module may execute WASM only within the enclosed limits.
    Limited(WasmBudgetLimits),
}

impl WasmBudget {
    /// Creates an explicit disabled WASM budget.
    #[must_use]
    pub const fn disabled() -> Self {
        Self::Disabled
    }

    /// Validates and creates an enabled WASM budget.
    pub fn limited(input: WasmBudgetInput) -> Result<Self, CoreError> {
        validate_wasm_input(input)?;
        Ok(Self::Limited(WasmBudgetLimits {
            fuel: input.fuel,
            max_memory_bytes: input.max_memory_bytes,
            epoch_timeout: input.epoch_timeout,
        }))
    }

    /// Returns whether this module may execute WASM components.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Limited(_))
    }

    /// Returns the invocation fuel limit when WASM is enabled.
    #[must_use]
    pub const fn fuel(self) -> Option<u64> {
        match self {
            Self::Disabled => None,
            Self::Limited(limits) => Some(limits.fuel),
        }
    }

    /// Returns the component memory limit when WASM is enabled.
    #[must_use]
    pub const fn max_memory_bytes(self) -> Option<u64> {
        match self {
            Self::Disabled => None,
            Self::Limited(limits) => Some(limits.max_memory_bytes),
        }
    }

    /// Returns the component epoch deadline when WASM is enabled.
    #[must_use]
    pub const fn epoch_timeout(self) -> Option<Duration> {
        match self {
            Self::Disabled => None,
            Self::Limited(limits) => Some(limits.epoch_timeout),
        }
    }

    fn validate(self) -> Result<(), CoreError> {
        match self {
            Self::Disabled => Ok(()),
            Self::Limited(limits) => validate_wasm_input(WasmBudgetInput {
                fuel: limits.fuel,
                max_memory_bytes: limits.max_memory_bytes,
                epoch_timeout: limits.epoch_timeout,
            }),
        }
    }
}

/// Inputs for bounded native tasks, queues, memory, and WASM execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBudgetInput {
    /// Maximum number of module-owned background tasks.
    pub max_tasks: usize,
    /// Maximum number of queued work items.
    pub queue_capacity: usize,
    /// Maximum aggregate module memory in bytes.
    pub max_memory_bytes: u64,
    /// Explicit disabled or limited WASM execution policy.
    pub wasm: WasmBudget,
}

/// Immutable execution resource limits declared by a module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBudget {
    max_tasks: usize,
    queue_capacity: usize,
    max_memory_bytes: u64,
    wasm: WasmBudget,
}

impl ExecutionBudget {
    /// Validates and creates an execution budget.
    pub fn new(input: ExecutionBudgetInput) -> Result<Self, CoreError> {
        validate_execution_input(input)?;
        Ok(Self {
            max_tasks: input.max_tasks,
            queue_capacity: input.queue_capacity,
            max_memory_bytes: input.max_memory_bytes,
            wasm: input.wasm,
        })
    }

    /// Returns the maximum number of module-owned background tasks.
    #[must_use]
    pub const fn max_tasks(self) -> usize {
        self.max_tasks
    }

    /// Returns the bounded work queue capacity.
    #[must_use]
    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }

    /// Returns the aggregate module memory limit in bytes.
    #[must_use]
    pub const fn max_memory_bytes(self) -> u64 {
        self.max_memory_bytes
    }

    /// Returns the explicit WASM execution policy.
    #[must_use]
    pub const fn wasm(self) -> WasmBudget {
        self.wasm
    }

    fn validate(self) -> Result<(), CoreError> {
        validate_execution_input(ExecutionBudgetInput {
            max_tasks: self.max_tasks,
            queue_capacity: self.queue_capacity,
            max_memory_bytes: self.max_memory_bytes,
            wasm: self.wasm,
        })
    }
}

/// Complete immutable resource contract for one module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    lifecycle: LifecycleBudget,
    execution: ExecutionBudget,
}

impl ResourceBudget {
    /// Validates and combines lifecycle and execution budgets.
    ///
    /// An enabled WASM memory limit cannot exceed the module's aggregate
    /// memory limit.
    pub fn new(
        lifecycle: LifecycleBudget,
        execution: ExecutionBudget,
    ) -> Result<Self, CoreError> {
        let budget = Self {
            lifecycle,
            execution,
        };
        budget.validate()?;
        Ok(budget)
    }

    /// Returns a conservative native-only budget for core diagnostics.
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            lifecycle: LifecycleBudget {
                startup_timeout: Duration::from_secs(5),
                health_timeout: Duration::from_secs(2),
                shutdown_timeout: Duration::from_secs(20),
                restart_delay: Duration::from_secs(1),
                restart_limit: 3,
            },
            execution: ExecutionBudget {
                max_tasks: 8,
                queue_capacity: 128,
                max_memory_bytes: 16 * 1024 * 1024,
                wasm: WasmBudget::Disabled,
            },
        }
    }

    /// Validates nested limits and their cross-budget memory invariant.
    pub fn validate(self) -> Result<(), CoreError> {
        self.lifecycle.validate()?;
        self.execution.validate()?;
        validate_wasm_memory(self.execution)
    }

    /// Returns the lifecycle deadline and restart policy.
    #[must_use]
    pub const fn lifecycle(self) -> LifecycleBudget {
        self.lifecycle
    }

    /// Returns the task, queue, memory, and WASM limits.
    #[must_use]
    pub const fn execution(self) -> ExecutionBudget {
        self.execution
    }
}

fn validate_lifecycle_input(input: LifecycleBudgetInput) -> Result<(), CoreError> {
    validate_lifecycle_duration(input.startup_timeout)?;
    validate_lifecycle_duration(input.health_timeout)?;
    validate_lifecycle_duration(input.shutdown_timeout)?;
    validate_lifecycle_duration(input.restart_delay)?;
    validate_restart_limit(input.restart_limit)
}

fn validate_lifecycle_duration(value: Duration) -> Result<(), CoreError> {
    if value.is_zero() || value > MAX_LIFECYCLE_DURATION {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("module lifecycle duration is outside its bound"));
    }
    Ok(())
}

fn validate_restart_limit(limit: u16) -> Result<(), CoreError> {
    if limit > MAX_RESTARTS {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("module restart count is outside its bound"));
    }
    Ok(())
}

fn validate_execution_input(input: ExecutionBudgetInput) -> Result<(), CoreError> {
    validate_task_budget(input.max_tasks)?;
    validate_queue_capacity(input.queue_capacity)?;
    validate_memory_budget(input.max_memory_bytes)?;
    input.wasm.validate()
}

fn validate_queue_capacity(capacity: usize) -> Result<(), CoreError> {
    if capacity == 0 || capacity > MAX_QUEUE_CAPACITY {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("module queue capacity is outside its bound"));
    }
    Ok(())
}

fn validate_task_budget(tasks: usize) -> Result<(), CoreError> {
    if tasks == 0 || tasks > MAX_TASKS {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("module task budget is outside its bound"));
    }
    Ok(())
}

fn validate_memory_budget(bytes: u64) -> Result<(), CoreError> {
    if bytes == 0 || bytes > MAX_MEMORY_BYTES {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("module memory budget is outside its bound"));
    }
    Ok(())
}

fn validate_wasm_input(input: WasmBudgetInput) -> Result<(), CoreError> {
    validate_wasm_fuel(input.fuel)?;
    validate_memory_budget(input.max_memory_bytes)?;
    validate_lifecycle_duration(input.epoch_timeout)
}

fn validate_wasm_fuel(fuel: u64) -> Result<(), CoreError> {
    if fuel == 0 || fuel > MAX_WASM_FUEL {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("WASM fuel budget is outside its bound"));
    }
    Ok(())
}

fn validate_wasm_memory(execution: ExecutionBudget) -> Result<(), CoreError> {
    let exceeds_module_limit = execution
        .wasm()
        .max_memory_bytes()
        .is_some_and(|bytes| bytes > execution.max_memory_bytes());
    if exceeds_module_limit {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("WASM memory exceeds the module memory budget"));
    }
    Ok(())
}

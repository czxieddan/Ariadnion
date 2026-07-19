//! Bounded module resource budgets.

use std::time::Duration;

use crate::error::{CoreError, ErrorCode};

const MAX_QUEUE_CAPACITY: usize = 1_048_576;
const MAX_TASKS: usize = 65_536;
const MAX_MEMORY_BYTES: u64 = 1 << 40;

/// Startup, shutdown, concurrency, and memory limits declared by a module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    startup_timeout: Duration,
    shutdown_timeout: Duration,
    restart_limit: u16,
    queue_capacity: usize,
    max_tasks: usize,
    max_memory_bytes: u64,
}

impl ResourceBudget {
    /// Creates and validates a resource budget.
    pub fn new(
        startup_timeout: Duration,
        shutdown_timeout: Duration,
        restart_limit: u16,
        queue_capacity: usize,
        max_tasks: usize,
        max_memory_bytes: u64,
    ) -> Result<Self, CoreError> {
        let budget = Self {
            startup_timeout,
            shutdown_timeout,
            restart_limit,
            queue_capacity,
            max_tasks,
            max_memory_bytes,
        };
        budget.validate()?;
        Ok(budget)
    }

    /// Returns a conservative default budget for core diagnostics.
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            startup_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(20),
            restart_limit: 3,
            queue_capacity: 128,
            max_tasks: 8,
            max_memory_bytes: 16 * 1024 * 1024,
        }
    }

    /// Validates all hard bounds and non-zero durations.
    pub fn validate(&self) -> Result<(), CoreError> {
        validate_time_budget(self.startup_timeout, self.shutdown_timeout)?;
        validate_queue_capacity(self.queue_capacity)?;
        validate_task_budget(self.max_tasks)?;
        validate_memory_budget(self.max_memory_bytes)
    }

    /// Returns the startup timeout.
    #[must_use]
    pub const fn startup_timeout(self) -> Duration {
        self.startup_timeout
    }

    /// Returns the shutdown timeout.
    #[must_use]
    pub const fn shutdown_timeout(self) -> Duration {
        self.shutdown_timeout
    }

    /// Returns the permitted restart count.
    #[must_use]
    pub const fn restart_limit(self) -> u16 {
        self.restart_limit
    }

    /// Returns the bounded event queue capacity.
    #[must_use]
    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }

    /// Returns the maximum number of background tasks.
    #[must_use]
    pub const fn max_tasks(self) -> usize {
        self.max_tasks
    }

    /// Returns the maximum memory budget in bytes.
    #[must_use]
    pub const fn max_memory_bytes(self) -> u64 {
        self.max_memory_bytes
    }
}

fn validate_time_budget(startup: Duration, shutdown: Duration) -> Result<(), CoreError> {
    if startup.is_zero() || shutdown.is_zero() {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("module timeout must be non-zero"));
    }
    Ok(())
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

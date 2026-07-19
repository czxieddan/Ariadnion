//! Structured liveness, readiness, and module health reports.

use std::fmt::{self, Display, Formatter};
use std::time::SystemTime;

use crate::error::{CoreError, ErrorCode};
use crate::ids::ModuleId;

const MAX_MODULE_REPORTS: usize = 256;

/// Coarse health state used by core and module probes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum HealthStatus {
    /// The process is alive but not yet accepting normal work.
    Live = 0,
    /// The process and required core dependencies are ready.
    Ready = 1,
    /// The process is serving a reduced, explicitly bounded capability set.
    Degraded = 2,
    /// A required safety or capability condition prevents service.
    Unavailable = 3,
}

impl HealthStatus {
    /// Returns the stable lower-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        ["live", "ready", "degraded", "unavailable"][self as usize]
    }

    /// Returns whether the state can serve core-only diagnostic requests.
    #[must_use]
    pub const fn is_live(self) -> bool {
        !matches!(self, Self::Unavailable)
    }

    /// Returns whether the state is fully ready.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    fn severity(self) -> u8 {
        [1, 0, 2, 3][self as usize]
    }
}

impl Display for HealthStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable reason codes for health transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HealthReasonCode {
    /// Core is still constructing its immutable startup state.
    Starting = 0,
    /// Core has no required dependencies and is ready.
    CoreReady = 1,
    /// A module or optional dependency is operating in a reduced mode.
    DependencyDegraded = 2,
    /// A required module or safety precondition is unavailable.
    DependencyUnavailable = 3,
    /// Configuration failed validation.
    ConfigurationInvalid = 4,
    /// A bounded resource budget is exhausted.
    ResourceExhausted = 5,
    /// Shutdown has been requested.
    ShutdownRequested = 6,
    /// The report is intentionally generic because internal details are sensitive.
    InternalFailure = 7,
}

impl HealthReasonCode {
    /// Returns the stable machine-readable reason name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        [
            "starting",
            "core_ready",
            "dependency_degraded",
            "dependency_unavailable",
            "configuration_invalid",
            "resource_exhausted",
            "shutdown_requested",
            "internal_failure",
        ][self as usize]
    }
}

/// A single module's safe health snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleHealthSnapshot {
    module_id: ModuleId,
    status: HealthStatus,
    reason: HealthReasonCode,
}

impl ModuleHealthSnapshot {
    /// Creates a module snapshot without storing free-form diagnostic text.
    #[must_use]
    pub const fn new(module_id: ModuleId, status: HealthStatus, reason: HealthReasonCode) -> Self {
        Self {
            module_id,
            status,
            reason,
        }
    }

    /// Returns the module identifier.
    #[must_use]
    pub const fn module_id(&self) -> &ModuleId {
        &self.module_id
    }

    /// Returns the module state.
    #[must_use]
    pub const fn status(&self) -> HealthStatus {
        self.status
    }

    /// Returns the stable reason code.
    #[must_use]
    pub const fn reason(&self) -> HealthReasonCode {
        self.reason
    }
}

/// A bounded aggregate health report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthReport {
    status: HealthStatus,
    reason: HealthReasonCode,
    observed_at: SystemTime,
    modules: Vec<ModuleHealthSnapshot>,
}

impl HealthReport {
    /// Creates a report with no module entries.
    #[must_use]
    pub fn new(status: HealthStatus, reason: HealthReasonCode) -> Self {
        Self {
            status,
            reason,
            observed_at: SystemTime::now(),
            modules: Vec::new(),
        }
    }

    /// Creates a ready core-only report.
    #[must_use]
    pub fn core_ready() -> Self {
        Self::new(HealthStatus::Ready, HealthReasonCode::CoreReady)
    }

    /// Adds a bounded module snapshot.
    pub fn add_module(&mut self, module: ModuleHealthSnapshot) -> Result<(), CoreError> {
        if self.modules.len() >= MAX_MODULE_REPORTS {
            return Err(CoreError::from_code(ErrorCode::ResourceExhausted)
                .with_internal_context("module health report limit reached"));
        }
        let previous_status = self.status;
        self.status = worse_status(previous_status, module.status);
        if self.status != previous_status {
            self.reason = reason_for_status(self.status);
        }
        self.modules.push(module);
        Ok(())
    }

    /// Returns the aggregate state.
    #[must_use]
    pub const fn status(&self) -> HealthStatus {
        self.status
    }

    /// Returns the aggregate reason.
    #[must_use]
    pub const fn reason(&self) -> HealthReasonCode {
        self.reason
    }

    /// Returns the observation timestamp in UTC system time.
    #[must_use]
    pub const fn observed_at(&self) -> SystemTime {
        self.observed_at
    }

    /// Returns an immutable view of module snapshots.
    #[must_use]
    pub fn modules(&self) -> &[ModuleHealthSnapshot] {
        &self.modules
    }

    /// Returns a safe one-line representation for a health endpoint.
    #[must_use]
    pub fn render_line(&self) -> String {
        format!(
            "status={} reason={} modules={}",
            self.status,
            self.reason.as_str(),
            self.modules.len()
        )
    }
}

fn worse_status(left: HealthStatus, right: HealthStatus) -> HealthStatus {
    if left.severity() >= right.severity() {
        left
    } else {
        right
    }
}

fn reason_for_status(status: HealthStatus) -> HealthReasonCode {
    match status {
        HealthStatus::Live => HealthReasonCode::Starting,
        HealthStatus::Ready => HealthReasonCode::CoreReady,
        HealthStatus::Degraded => HealthReasonCode::DependencyDegraded,
        HealthStatus::Unavailable => HealthReasonCode::DependencyUnavailable,
    }
}

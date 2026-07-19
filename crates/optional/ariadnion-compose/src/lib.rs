//! Thin single-process composition orchestration without business logic.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ariadnion_core::{
    Bootstrap, BootstrapReport, CoreError, ErrorCode, HealthReport, LifecycleReport,
    LifecycleSupervisor, ModuleConfigurationSnapshot, ModuleFactory, ShutdownReason,
    ShutdownReport,
};

const MAX_PROFILE_BYTES: usize = 64;

/// The safe report produced by a one-shot composition validation run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionReport {
    profile: Box<str>,
    bootstrap: BootstrapReport,
    lifecycle: LifecycleReport,
    health: HealthReport,
    module_shutdown: LifecycleReport,
    core_shutdown: ShutdownReport,
}

impl CompositionReport {
    /// Returns the profile name.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns core startup evidence.
    #[must_use]
    pub const fn bootstrap(&self) -> &BootstrapReport {
        &self.bootstrap
    }

    /// Returns module startup evidence.
    #[must_use]
    pub const fn lifecycle(&self) -> &LifecycleReport {
        &self.lifecycle
    }

    /// Returns aggregate module health.
    #[must_use]
    pub const fn health(&self) -> &HealthReport {
        &self.health
    }

    /// Returns reverse-order module shutdown evidence.
    #[must_use]
    pub const fn module_shutdown(&self) -> &LifecycleReport {
        &self.module_shutdown
    }

    /// Returns core drain evidence.
    #[must_use]
    pub const fn core_shutdown(&self) -> ShutdownReport {
        self.core_shutdown
    }

    /// Returns one stable English diagnostic line.
    #[must_use]
    pub fn render_line(&self) -> String {
        format!(
            "profile={} modules={} health={} core_shutdown={}",
            self.profile,
            self.lifecycle.statuses().len(),
            self.health.status(),
            self.core_shutdown.reason().as_str()
        )
    }
}

/// Builds one statically linked module composition.
pub struct CompositionBuilder {
    profile: Box<str>,
    supervisor: LifecycleSupervisor,
}

impl CompositionBuilder {
    /// Creates a composition with a bounded ASCII profile name.
    pub fn new(profile: impl Into<Box<str>>) -> Result<Self, CoreError> {
        let profile = profile.into();
        validate_profile(&profile)?;
        Ok(Self {
            profile,
            supervisor: LifecycleSupervisor::new(),
        })
    }

    /// Registers a concrete module factory and immutable configuration reference.
    pub fn register(
        &mut self,
        factory: Arc<dyn ModuleFactory>,
        configuration: ModuleConfigurationSnapshot,
    ) -> Result<(), CoreError> {
        self.supervisor.register(factory, configuration)
    }

    /// Starts, probes, and shuts down this composition in one process.
    ///
    /// This command is used for composition verification, not as the final
    /// long-running server entry. Module shutdown receives a 20-second UTC
    /// deadline and core drain receives a one-second deadline after all module
    /// handles have completed.
    pub fn run_once(mut self) -> Result<CompositionReport, CoreError> {
        let bootstrap = Bootstrap::new();
        let bootstrap_report = bootstrap.start()?;
        let lifecycle = self.supervisor.start_all();
        let health = self.supervisor.health();
        let module_deadline = checked_deadline(Duration::from_secs(20))?;
        let module_shutdown = self.supervisor.shutdown_all(module_deadline);
        let core = bootstrap.shutdown();
        let _ = core.request(ShutdownReason::Operator);
        core.mark_drained()?;
        let core_shutdown = core.wait_for_drain(Duration::from_secs(1))?;
        Ok(CompositionReport {
            profile: self.profile,
            bootstrap: bootstrap_report,
            lifecycle,
            health,
            module_shutdown,
            core_shutdown,
        })
    }
}

fn checked_deadline(timeout: Duration) -> Result<SystemTime, CoreError> {
    SystemTime::now().checked_add(timeout).ok_or_else(|| {
        CoreError::from_code(ErrorCode::ResourceExhausted)
            .with_internal_context("composition shutdown deadline overflow")
    })
}

fn validate_profile(profile: &str) -> Result<(), CoreError> {
    if profile.is_empty() || profile.len() > MAX_PROFILE_BYTES || !profile.is_ascii() {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("composition profile is outside its bound"));
    }
    Ok(())
}

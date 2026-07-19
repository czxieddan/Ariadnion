//! Core-only startup orchestration and safe diagnostic reports.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use crate::error::{CoreError, ErrorCode};
use crate::health::{HealthReasonCode, HealthReport, HealthStatus};
use crate::shutdown::{ShutdownCoordinator, ShutdownReason};
use crate::version::{BuildInfo, CORE_ABI_VERSION};

/// Immutable startup state for a core-only process.
pub struct Bootstrap {
    instance_id: u64,
    build_info: BuildInfo,
    shutdown: ShutdownCoordinator,
    signal_installed: Arc<AtomicBool>,
}

struct SignalOwner {
    instance_id: u64,
    shutdown: ShutdownCoordinator,
}

type SignalRoute = Arc<Mutex<Option<SignalOwner>>>;

static SIGNAL_ROUTE: OnceLock<SignalRoute> = OnceLock::new();
static SIGNAL_HANDLER: OnceLock<Result<(), ()>> = OnceLock::new();
static NEXT_BOOTSTRAP_ID: AtomicU64 = AtomicU64::new(1);

fn signal_route() -> SignalRoute {
    SIGNAL_ROUTE
        .get_or_init(|| Arc::new(Mutex::new(None)))
        .clone()
}

fn lock_route(route: &SignalRoute) -> MutexGuard<'_, Option<SignalOwner>> {
    match route.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Bootstrap {
    /// Constructs core state without opening storage, sockets, or optional modules.
    #[must_use]
    pub fn new() -> Self {
        Self {
            instance_id: NEXT_BOOTSTRAP_ID.fetch_add(1, Ordering::Relaxed),
            build_info: BuildInfo::current(),
            shutdown: ShutdownCoordinator::new(),
            signal_installed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Installs one process signal handler and returns a startup report.
    ///
    /// Signal registration is process-global and idempotent for this instance.
    /// A concurrent active bootstrap returns [`ErrorCode::Conflict`]; OS handler
    /// registration failure returns [`ErrorCode::Unavailable`] without details.
    pub fn start(&self) -> Result<BootstrapReport, CoreError> {
        self.install_signal_handler()?;
        Ok(BootstrapReport {
            build_info: self.build_info,
            health: HealthReport::core_ready(),
            core_abi_version: CORE_ABI_VERSION,
            signal_handler_installed: self.signal_installed.load(Ordering::Acquire),
        })
    }

    /// Runs one core-only startup cycle without waiting for external work.
    ///
    /// The cycle requests an operator shutdown, marks the empty core workload
    /// drained, and includes the resulting shutdown report. Signal registration
    /// errors, state conflicts, and timeout overflow are returned to the caller.
    pub fn run_once(&self) -> Result<CoreRunReport, CoreError> {
        let startup = self.start()?;
        let shutdown = self.shutdown();
        let _ = shutdown.request(ShutdownReason::Operator);
        shutdown.mark_drained()?;
        let shutdown_report = shutdown.wait_for_drain(Duration::from_secs(1))?;
        Ok(CoreRunReport {
            startup,
            shutdown: Some(shutdown_report),
            exit_code: 0,
        })
    }

    /// Runs until a signal or operator request, then drains within the timeout.
    ///
    /// This blocks the calling thread until shutdown is requested. The timeout
    /// applies only to draining after the request; a reached drain deadline
    /// produces exit code 1 while preserving the structured shutdown report.
    pub fn run_until_shutdown(&self, timeout: Duration) -> Result<CoreRunReport, CoreError> {
        let startup = self.start()?;
        let shutdown = self.shutdown();
        let _reason = shutdown.wait_for_request();
        shutdown.mark_drained()?;
        let shutdown_report = shutdown.wait_for_drain(timeout)?;
        let exit_code = if shutdown_report.deadline_reached() {
            1
        } else {
            0
        };
        Ok(CoreRunReport {
            startup,
            shutdown: Some(shutdown_report),
            exit_code,
        })
    }

    /// Returns the shared shutdown coordinator.
    #[must_use]
    pub fn shutdown(&self) -> ShutdownCoordinator {
        self.shutdown.clone()
    }

    /// Returns the compiled build metadata.
    #[must_use]
    pub const fn build_info(&self) -> BuildInfo {
        self.build_info
    }

    fn install_signal_handler(&self) -> Result<(), CoreError> {
        let route = signal_route();
        claim_signal_route(&route, self.instance_id, self.shutdown.clone())?;
        let status = SIGNAL_HANDLER.get_or_init(|| {
            let route = route.clone();
            ctrlc::set_handler(move || {
                let active = lock_route(&route);
                if let Some(owner) = active.as_ref() {
                    let _ = owner.shutdown.request(ShutdownReason::Signal);
                }
            })
            .map(|_| ())
            .map_err(|_| ())
        });
        if status.is_err() {
            release_signal_route(&route, self.instance_id);
            return Err(CoreError::from_code(ErrorCode::Unavailable)
                .with_internal_context("signal handler registration failed"));
        }
        self.signal_installed.store(true, Ordering::Release);
        Ok(())
    }
}

fn claim_signal_route(
    route: &SignalRoute,
    instance_id: u64,
    shutdown: ShutdownCoordinator,
) -> Result<(), CoreError> {
    let mut active = lock_route(route);
    match active.as_ref() {
        Some(owner) if owner.instance_id == instance_id => Ok(()),
        Some(_) => Err(CoreError::from_code(ErrorCode::Conflict)
            .with_internal_context("another bootstrap owns the signal route")),
        None => {
            *active = Some(SignalOwner {
                instance_id,
                shutdown,
            });
            Ok(())
        }
    }
}

fn release_signal_route(route: &SignalRoute, instance_id: u64) {
    let mut active = lock_route(route);
    let owns_route = active
        .as_ref()
        .is_some_and(|owner| owner.instance_id == instance_id);
    if owns_route {
        *active = None;
    }
}

impl Drop for Bootstrap {
    fn drop(&mut self) {
        if self.signal_installed.load(Ordering::Acquire) {
            release_signal_route(&signal_route(), self.instance_id);
        }
    }
}

impl Default for Bootstrap {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of constructing and starting core-only services.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapReport {
    build_info: BuildInfo,
    health: HealthReport,
    core_abi_version: crate::ids::AbiVersion,
    signal_handler_installed: bool,
}

impl BootstrapReport {
    /// Returns build metadata.
    #[must_use]
    pub const fn build_info(&self) -> BuildInfo {
        self.build_info
    }

    /// Returns the aggregate core health report.
    #[must_use]
    pub const fn health(&self) -> &HealthReport {
        &self.health
    }

    /// Returns the core ABI version.
    #[must_use]
    pub const fn core_abi_version(&self) -> crate::ids::AbiVersion {
        self.core_abi_version
    }

    /// Returns whether signal registration succeeded.
    #[must_use]
    pub const fn signal_handler_installed(&self) -> bool {
        self.signal_handler_installed
    }

    /// Returns a safe one-line startup report.
    #[must_use]
    pub fn render_line(&self) -> String {
        format!(
            "{} health={} reason={} signal_handler={}",
            self.build_info,
            self.health.status(),
            self.health.reason().as_str(),
            self.signal_handler_installed
        )
    }
}

/// A bounded result for one core-only run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreRunReport {
    startup: BootstrapReport,
    shutdown: Option<crate::shutdown::ShutdownReport>,
    exit_code: u8,
}

impl CoreRunReport {
    /// Returns the startup report.
    #[must_use]
    pub const fn startup(&self) -> &BootstrapReport {
        &self.startup
    }

    /// Returns the process exit code selected by core.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_code
    }

    /// Returns the shutdown report when the run completed its drain path.
    #[must_use]
    pub const fn shutdown(&self) -> Option<crate::shutdown::ShutdownReport> {
        self.shutdown
    }

    /// Returns a safe one-line run report.
    #[must_use]
    pub fn render_line(&self) -> String {
        let shutdown = match self.shutdown {
            Some(report) => format!(" shutdown_reason={}", report.reason().as_str()),
            None => String::new(),
        };
        format!(
            "{} exit_code={}{}",
            self.startup.render_line(),
            self.exit_code,
            shutdown
        )
    }
}

/// Creates the health report used while core is constructing.
#[must_use]
pub fn starting_health() -> HealthReport {
    HealthReport::new(HealthStatus::Live, HealthReasonCode::Starting)
}

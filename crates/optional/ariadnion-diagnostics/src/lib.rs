//! Stateless core diagnostics module used by the edge composition.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use ariadnion_core::{
    CapabilityId, CapabilityProvider, CapabilityResolution, ConfigurationContract, CoreError,
    ErrorCode, HealthReasonCode, HealthStatus, ModuleConfigurationSnapshot, ModuleContext,
    ModuleDescriptor, ModuleDescriptorInput, ModuleFactory, ModuleHandle, ModuleHealthSnapshot,
    ModuleId, ModuleShutdownReport, ModuleVersion, PortKey, ResourceBudget, ShutdownPriority,
    CORE_ABI_VERSION,
};

/// SHA-256 of the canonical empty diagnostics configuration.
pub const DEFAULT_CONFIGURATION_DIGEST: &str =
    "81686777e9becb24f4ded0eaebfeb030434ed9091c1b171143b44e3f5262d96d";

const DIAGNOSTICS_BUILD_ID: &str = concat!("ariadnion-diagnostics-", env!("CARGO_PKG_VERSION"));
const DIAGNOSTICS_PORT_NAME: &str = "org.ariadnion.diagnostics.read.port";
const MODULE_METADATA: &str = include_str!("../module.toml");

/// A typed, read-only diagnostics operation exposed by the module.
pub trait DiagnosticsReadPort: Send + Sync {
    /// Reads a bounded metadata and lifecycle snapshot without side effects.
    fn read(&self) -> DiagnosticsSnapshot;
}

/// A safe immutable diagnostics response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticsSnapshot {
    module_id: ModuleId,
    version: ModuleVersion,
    status: HealthStatus,
}

impl DiagnosticsSnapshot {
    /// Returns the diagnostics module identity.
    #[must_use]
    pub const fn module_id(&self) -> &ModuleId {
        &self.module_id
    }

    /// Returns the diagnostics module implementation version.
    #[must_use]
    pub const fn version(&self) -> ModuleVersion {
        self.version
    }

    /// Returns the current module status.
    #[must_use]
    pub const fn status(&self) -> HealthStatus {
        self.status
    }
}

struct DiagnosticsService {
    module_id: ModuleId,
    version: ModuleVersion,
    status: Mutex<HealthStatus>,
}

impl DiagnosticsReadPort for DiagnosticsService {
    fn read(&self) -> DiagnosticsSnapshot {
        DiagnosticsSnapshot {
            module_id: self.module_id.clone(),
            version: self.version,
            status: *lock_status(&self.status),
        }
    }
}

impl DiagnosticsService {
    fn set_status(&self, status: HealthStatus) {
        *lock_status(&self.status) = status;
    }
}

/// A side-effect-free factory for the built-in diagnostics capability.
pub struct DiagnosticsModule {
    descriptor: ModuleDescriptor,
    service: Arc<DiagnosticsService>,
}

impl DiagnosticsModule {
    /// Creates the built-in descriptor and its read-only capability.
    pub fn new() -> Result<Self, CoreError> {
        let module_id = ModuleId::parse("org.ariadnion.diagnostics")?;
        let capability = CapabilityProvider::new(
            CapabilityId::parse("org.ariadnion.diagnostics.read")?,
            ModuleVersion::new(1, 0, 0),
            module_id.clone(),
        );
        let configuration = ConfigurationContract::new(
            "org.ariadnion.diagnostics.config",
            ModuleVersion::new(1, 0, 0),
            true,
        )?;
        let descriptor = ModuleDescriptor::new(ModuleDescriptorInput {
            id: module_id,
            version: ModuleVersion::new(0, 1, 0),
            build_commit: DIAGNOSTICS_BUILD_ID.into(),
            abi_version: CORE_ABI_VERSION,
            provided: vec![capability],
            required: Vec::new(),
            required_secret_capabilities: Vec::new(),
            configuration,
            resources: ResourceBudget::conservative(),
            shutdown_priority: ShutdownPriority::new(100)?,
            sensitive_paths: Vec::new(),
            observability_namespace: "ariadnion.diagnostics".into(),
            audit_namespace: "ariadnion.diagnostics".into(),
        })?;
        validate_embedded_metadata(&descriptor)?;
        let service = Arc::new(DiagnosticsService {
            module_id: descriptor.id().clone(),
            version: descriptor.version(),
            status: Mutex::new(HealthStatus::Live),
        });
        Ok(Self {
            descriptor,
            service,
        })
    }

    /// Returns the compile-time typed diagnostics port key.
    pub fn port_key() -> Result<PortKey<dyn DiagnosticsReadPort>, CoreError> {
        PortKey::new(DIAGNOSTICS_PORT_NAME)
    }

    /// Returns the concrete read-only diagnostics service.
    #[must_use]
    pub fn read_port(&self) -> Arc<dyn DiagnosticsReadPort> {
        self.service.clone()
    }
}

impl ModuleFactory for DiagnosticsModule {
    fn descriptor(&self) -> &ModuleDescriptor {
        &self.descriptor
    }

    fn validate(
        &self,
        configuration: &ModuleConfigurationSnapshot,
        _capabilities: &CapabilityResolution,
    ) -> Result<(), CoreError> {
        if configuration.schema_id() != self.descriptor.configuration().schema_id() {
            return Err(CoreError::from_code(ErrorCode::Conflict)
                .with_internal_context("diagnostics configuration schema mismatch"));
        }
        Ok(())
    }

    fn start(&self, _context: ModuleContext) -> Result<Box<dyn ModuleHandle>, CoreError> {
        self.service.set_status(HealthStatus::Ready);
        Ok(Box::new(DiagnosticsHandle {
            module_id: self.descriptor.id().clone(),
            service: self.service.clone(),
            configuration_version: 0,
            stopped: false,
        }))
    }
}

struct DiagnosticsHandle {
    module_id: ModuleId,
    service: Arc<DiagnosticsService>,
    configuration_version: u64,
    stopped: bool,
}

impl ModuleHandle for DiagnosticsHandle {
    fn health(&self) -> Result<ModuleHealthSnapshot, CoreError> {
        if self.stopped {
            return Ok(ModuleHealthSnapshot::new(
                self.module_id.clone(),
                HealthStatus::Unavailable,
                HealthReasonCode::ShutdownRequested,
            ));
        }
        Ok(ModuleHealthSnapshot::new(
            self.module_id.clone(),
            HealthStatus::Ready,
            HealthReasonCode::CoreReady,
        ))
    }

    fn reconfigure(&mut self, snapshot: ModuleConfigurationSnapshot) -> Result<(), CoreError> {
        if snapshot.schema_id() != "org.ariadnion.diagnostics.config" {
            return Err(CoreError::from_code(ErrorCode::Conflict)
                .with_internal_context("diagnostics configuration schema mismatch"));
        }
        if snapshot.version() <= self.configuration_version {
            return Err(CoreError::from_code(ErrorCode::Conflict)
                .with_internal_context("diagnostics configuration is not newer"));
        }
        self.configuration_version = snapshot.version();
        Ok(())
    }

    fn shutdown(&mut self, deadline: SystemTime) -> Result<ModuleShutdownReport, CoreError> {
        if deadline <= SystemTime::now() {
            return Err(CoreError::from_code(ErrorCode::DeadlineExceeded));
        }
        self.stopped = true;
        self.service.set_status(HealthStatus::Unavailable);
        Ok(ModuleShutdownReport::new(0, 0, true))
    }
}

fn lock_status(status: &Mutex<HealthStatus>) -> MutexGuard<'_, HealthStatus> {
    match status.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn validate_embedded_metadata(descriptor: &ModuleDescriptor) -> Result<(), CoreError> {
    validate_metadata_value("id", descriptor.id().as_str())?;
    validate_metadata_value("version", &descriptor.version().to_string())?;
    validate_metadata_value("abi", &descriptor.abi_version().to_string())
}

fn validate_metadata_value(key: &str, expected: &str) -> Result<(), CoreError> {
    let matches = MODULE_METADATA.lines().any(|line| {
        line.split_once('=').is_some_and(|(candidate, value)| {
            candidate.trim() == key && value.trim().trim_matches('"') == expected
        })
    });
    if !matches {
        return Err(CoreError::from_code(ErrorCode::Conflict)
            .with_internal_context("embedded diagnostics metadata differs from its descriptor"));
    }
    Ok(())
}

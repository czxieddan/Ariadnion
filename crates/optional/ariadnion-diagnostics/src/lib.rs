//! Stateless core diagnostics module used by the edge composition.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::time::SystemTime;

use ariadnion_core::{
    CapabilityId, CapabilityProvider, CapabilityResolution, ConfigurationContract, CoreError,
    ErrorCode, HealthReasonCode, HealthStatus, ModuleConfigurationSnapshot, ModuleContext,
    ModuleDescriptor, ModuleDescriptorInput, ModuleFactory, ModuleHandle, ModuleHealthSnapshot,
    ModuleId, ModuleShutdownReport, ModuleVersion, ResourceBudget, ShutdownPriority,
    CORE_ABI_VERSION,
};

/// A side-effect-free factory for the built-in diagnostics capability.
pub struct DiagnosticsModule {
    descriptor: ModuleDescriptor,
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
            build_commit: "0000000".into(),
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
        Ok(Self { descriptor })
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
        Ok(Box::new(DiagnosticsHandle {
            module_id: self.descriptor.id().clone(),
            configuration_version: 0,
            stopped: false,
        }))
    }
}

struct DiagnosticsHandle {
    module_id: ModuleId,
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
        Ok(ModuleShutdownReport::new(0, 0, true))
    }
}

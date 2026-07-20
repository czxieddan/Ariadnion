//! RNMDB relational-storage module descriptor and lifecycle adapter.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_core::{
    CORE_ABI_VERSION, CapabilityId, CapabilityProvider, CapabilityRequirement,
    CapabilityResolution, ConfigurationContract, CoreError, ErrorCode, ExecutionBudget,
    ExecutionBudgetInput, HealthReasonCode, HealthStatus, LifecycleBudget, LifecycleBudgetInput,
    ModuleConfigurationSnapshot, ModuleContext, ModuleDescriptor, ModuleDescriptorInput,
    ModuleFactory, ModuleHandle, ModuleHealthSnapshot, ModuleId, ModuleShutdownReport,
    ModuleVersion, RequestContext, RequestId, ResourceBudget, SecretCapabilityRequirement,
    ShutdownPriority, TraceId, WasmBudget,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};

use crate::{
    REVIEWED_RNMDB_COMMIT, RnmdbColumnSecurity, RnmdbMigrationRunner, RnmdbSessionOwner,
    SecretLocatorKeyMaterial, SessionOpenOptions, UtcTimestampMicros,
};

const MODULE_ID: &str = "org.ariadnion.storage.rnmdb";
const RELATIONAL_CAPABILITY: &str = "org.ariadnion.storage.relational";
const PAGE_KEY_CAPABILITY: &str = "org.ariadnion.secret.page-key";
const SECRET_LOCATOR_KEY_CAPABILITY: &str = "org.ariadnion.secret.locator-column-key";
const CONFIGURATION_SCHEMA: &str = "org.ariadnion.storage.rnmdb.config";
const MODULE_VERSION: ModuleVersion = ModuleVersion::new(0, 1, 0);
const CONTRACT_VERSION: ModuleVersion = ModuleVersion::new(1, 0, 0);
const MODULE_METADATA: &str = include_str!("../module.toml");

/// A single-use factory for one encrypted embedded RNMDB session.
///
/// Secret-bearing open options remain behind a mutex and are consumed exactly
/// once by [`ModuleFactory::start`]. The immutable descriptor contains only a
/// typed secret capability requirement and a sensitive configuration path.
pub struct StorageRnmdbModule {
    descriptor: ModuleDescriptor,
    options: Mutex<Option<StorageRnmdbModuleOptions>>,
}

/// Single-consumption secrets and paths needed to start RNMDB storage.
pub struct StorageRnmdbModuleOptions {
    session: SessionOpenOptions,
    secret_locator_key: SecretLocatorKeyMaterial,
}

impl StorageRnmdbModuleOptions {
    /// Combines encrypted-session options with the managed locator-column key.
    #[must_use]
    pub const fn new(
        session: SessionOpenOptions,
        secret_locator_key: SecretLocatorKeyMaterial,
    ) -> Self {
        Self {
            session,
            secret_locator_key,
        }
    }
}

impl StorageRnmdbModule {
    /// Creates a module factory with single-consumption session options.
    pub fn new(options: StorageRnmdbModuleOptions) -> Result<Self, CoreError> {
        Ok(Self {
            descriptor: build_descriptor()?,
            options: Mutex::new(Some(options)),
        })
    }
}

impl ModuleFactory for StorageRnmdbModule {
    fn descriptor(&self) -> &ModuleDescriptor {
        &self.descriptor
    }

    fn validate(
        &self,
        configuration: &ModuleConfigurationSnapshot,
        capabilities: &CapabilityResolution,
    ) -> Result<(), CoreError> {
        validate_configuration(&self.descriptor, configuration)?;
        validate_secret_resolution(&self.descriptor, capabilities)?;
        if lock_options(&self.options).is_none() {
            return Err(CoreError::from_code(ErrorCode::Conflict)
                .with_internal_context("RNMDB session options were already consumed"));
        }
        Ok(())
    }

    fn start(&self, context: ModuleContext) -> Result<Box<dyn ModuleHandle>, CoreError> {
        let cancellation = context.cancellation();
        cancellation.check_active()?;
        validate_secret_resolution(&self.descriptor, context.capabilities())?;
        let options = take_options(&self.options)?;
        let session = RnmdbSessionOwner::open(options.session)
            .map(Arc::new)
            .map_err(map_storage_error)?;
        let request = startup_request_context(cancellation.clone())?;
        apply_startup_migrations(&session, &request)?;
        RnmdbColumnSecurity::new(session.clone())
            .configure_secret_locator(options.secret_locator_key, &request)
            .map_err(map_storage_error)?;
        Ok(Box::new(StorageRnmdbHandle {
            module_id: self.descriptor.id().clone(),
            cancellation,
            session: Some(session),
        }))
    }
}

struct StorageRnmdbHandle {
    module_id: ModuleId,
    cancellation: ariadnion_core::CancellationToken,
    session: Option<Arc<RnmdbSessionOwner>>,
}

impl ModuleHandle for StorageRnmdbHandle {
    fn health(&self) -> Result<ModuleHealthSnapshot, CoreError> {
        let unavailable = self.session.is_none() || self.cancellation.is_cancelled();
        if unavailable {
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

    fn reconfigure(&mut self, _snapshot: ModuleConfigurationSnapshot) -> Result<(), CoreError> {
        Err(CoreError::from_code(ErrorCode::Conflict)
            .with_internal_context("RNMDB session configuration does not support hot reload"))
    }

    fn shutdown(&mut self, deadline: SystemTime) -> Result<ModuleShutdownReport, CoreError> {
        let Some(session) = self.session.as_ref() else {
            return Ok(ModuleShutdownReport::new(0, 0, true));
        };
        let rolled_back = session
            .shutdown_before(deadline)
            .map_err(map_storage_error)?;
        self.session = None;
        Ok(ModuleShutdownReport::new(usize::from(rolled_back), 0, true))
    }
}

fn build_descriptor() -> Result<ModuleDescriptor, CoreError> {
    let id = ModuleId::parse(MODULE_ID)?;
    let provided = relational_provider(&id)?;
    let page_key = page_key_requirement()?;
    let locator_key = secret_locator_key_requirement()?;
    let descriptor = ModuleDescriptor::new(ModuleDescriptorInput {
        id,
        version: MODULE_VERSION,
        build_commit: REVIEWED_RNMDB_COMMIT.into(),
        abi_version: CORE_ABI_VERSION,
        provided: vec![provided],
        required: Vec::new(),
        required_secret_capabilities: vec![page_key, locator_key],
        configuration: configuration_contract()?,
        resources: module_resource_budget()?,
        shutdown_priority: ShutdownPriority::new(512)?,
        sensitive_paths: vec![
            "storage.rnmdb.page_key_ref".into(),
            "storage.rnmdb.secret_locator_key_ref".into(),
        ],
        observability_namespace: "ariadnion.storage.rnmdb".into(),
        audit_namespace: "ariadnion.storage.rnmdb".into(),
    })?;
    validate_embedded_metadata(&descriptor)?;
    Ok(descriptor)
}

fn relational_provider(module_id: &ModuleId) -> Result<CapabilityProvider, CoreError> {
    Ok(CapabilityProvider::new(
        CapabilityId::parse(RELATIONAL_CAPABILITY)?,
        CONTRACT_VERSION,
        module_id.clone(),
    ))
}

fn page_key_requirement() -> Result<SecretCapabilityRequirement, CoreError> {
    Ok(SecretCapabilityRequirement::new(
        CapabilityRequirement::new(
            CapabilityId::parse(PAGE_KEY_CAPABILITY)?,
            CONTRACT_VERSION,
            Some(1),
        ),
    ))
}

fn secret_locator_key_requirement() -> Result<SecretCapabilityRequirement, CoreError> {
    Ok(SecretCapabilityRequirement::new(
        CapabilityRequirement::new(
            CapabilityId::parse(SECRET_LOCATOR_KEY_CAPABILITY)?,
            CONTRACT_VERSION,
            Some(1),
        ),
    ))
}

fn configuration_contract() -> Result<ConfigurationContract, CoreError> {
    ConfigurationContract::new(CONFIGURATION_SCHEMA, CONTRACT_VERSION, false)
}

fn module_resource_budget() -> Result<ResourceBudget, CoreError> {
    let lifecycle = LifecycleBudget::new(LifecycleBudgetInput {
        startup_timeout: Duration::from_secs(30),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(30),
        restart_delay: Duration::from_secs(5),
        restart_limit: 3,
    })?;
    let execution = ExecutionBudget::new(ExecutionBudgetInput {
        max_tasks: 16,
        queue_capacity: 1_024,
        max_memory_bytes: 512 * 1024 * 1024,
        wasm: WasmBudget::disabled(),
    })?;
    ResourceBudget::new(lifecycle, execution)
}

fn validate_configuration(
    descriptor: &ModuleDescriptor,
    configuration: &ModuleConfigurationSnapshot,
) -> Result<(), CoreError> {
    if configuration.schema_id() != descriptor.configuration().schema_id() {
        return Err(CoreError::from_code(ErrorCode::Conflict)
            .with_internal_context("RNMDB configuration schema does not match the descriptor"));
    }
    Ok(())
}

fn validate_secret_resolution(
    descriptor: &ModuleDescriptor,
    capabilities: &CapabilityResolution,
) -> Result<(), CoreError> {
    let requirements = descriptor.required_secret_capabilities();
    if requirements.len() != 2 {
        return Err(CoreError::from_code(ErrorCode::Internal)
            .with_internal_context("RNMDB secret requirements are incomplete"));
    }
    for requirement in requirements {
        if capabilities
            .provider_for(requirement.requirement().id())
            .is_none()
        {
            return Err(CoreError::from_code(ErrorCode::Unavailable)
                .with_internal_context("a required RNMDB secret capability is unavailable"));
        }
    }
    Ok(())
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
            .with_internal_context("embedded RNMDB metadata differs from its descriptor"));
    }
    Ok(())
}

fn take_options(
    options: &Mutex<Option<StorageRnmdbModuleOptions>>,
) -> Result<StorageRnmdbModuleOptions, CoreError> {
    lock_options(options).take().ok_or_else(|| {
        CoreError::from_code(ErrorCode::Conflict)
            .with_internal_context("RNMDB session options were already consumed")
    })
}

fn startup_request_context(
    cancellation: ariadnion_core::CancellationToken,
) -> Result<RequestContext, CoreError> {
    Ok(RequestContext::new(
        RequestId::parse("storage-rnmdb-startup")?,
        TraceId::parse("storage-rnmdb-startup")?,
        None,
        None,
        cancellation,
    ))
}

fn apply_startup_migrations(
    session: &Arc<RnmdbSessionOwner>,
    context: &RequestContext,
) -> Result<(), CoreError> {
    let applied_at = utc_micros(SystemTime::now())?;
    let runner = RnmdbMigrationRunner::new(session.clone());
    runner
        .apply_platform_initial(applied_at, context)
        .map_err(map_storage_error)?;
    runner
        .apply_platform_secret_references(applied_at, context)
        .map_err(map_storage_error)?;
    runner
        .apply_platform_outbox(applied_at, context)
        .map_err(map_storage_error)?;
    Ok(())
}

fn utc_micros(now: SystemTime) -> Result<UtcTimestampMicros, CoreError> {
    let duration = now.duration_since(UNIX_EPOCH).map_err(|_| {
        CoreError::from_code(ErrorCode::Internal)
            .with_internal_context("system clock is before the Unix epoch")
    })?;
    let micros = i64::try_from(duration.as_micros()).map_err(|_| {
        CoreError::from_code(ErrorCode::Internal)
            .with_internal_context("system clock exceeds the supported timestamp range")
    })?;
    UtcTimestampMicros::new(micros).map_err(map_storage_error)
}

fn lock_options(
    options: &Mutex<Option<StorageRnmdbModuleOptions>>,
) -> MutexGuard<'_, Option<StorageRnmdbModuleOptions>> {
    match options.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn map_storage_error(error: StorageError) -> CoreError {
    let code = match error.code() {
        StorageErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        StorageErrorCode::Conflict => ErrorCode::Conflict,
        StorageErrorCode::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        StorageErrorCode::Cancelled => ErrorCode::Cancelled,
        StorageErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        StorageErrorCode::NotFound | StorageErrorCode::Unavailable => ErrorCode::Unavailable,
        _ => ErrorCode::Internal,
    };
    CoreError::from_code(code).with_internal_context("RNMDB module operation failed")
}

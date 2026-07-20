//! RNMDB relational-storage module descriptor and lifecycle adapter.

use std::collections::BTreeSet;
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
const MODULE_LICENSE: &str = "AGPL-3.0-or-later";
const EMPTY_CONFIGURATION_DIGEST: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
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
    ///
    /// # Errors
    ///
    /// Returns a core validation error when the descriptor is invalid or the
    /// embedded module metadata does not match that descriptor.
    pub fn new(options: StorageRnmdbModuleOptions) -> Result<Self, CoreError> {
        Self::with_options(Some(options))
    }

    /// Creates a descriptor-only factory without paths, secrets, or open options.
    ///
    /// Validation reports [`ErrorCode::Unavailable`] until a configured factory
    /// is supplied. This permits the core lifecycle to report the optional
    /// storage module without attempting embedded-database side effects.
    ///
    /// # Errors
    ///
    /// Returns a core validation error when the descriptor is invalid or the
    /// embedded module metadata does not match that descriptor.
    pub fn deferred() -> Result<Self, CoreError> {
        Self::with_options(None)
    }

    /// Returns the version-one snapshot for the canonical empty configuration.
    ///
    /// Session paths and secret material are injected only through [`Self::new`]
    /// and are intentionally excluded from this immutable snapshot.
    ///
    /// # Errors
    ///
    /// Returns a core validation error if the module-owned schema, version, or
    /// digest constants do not satisfy the snapshot contract.
    pub fn configuration_snapshot() -> Result<ModuleConfigurationSnapshot, CoreError> {
        ModuleConfigurationSnapshot::new(CONFIGURATION_SCHEMA, 1, EMPTY_CONFIGURATION_DIGEST)
    }

    fn with_options(options: Option<StorageRnmdbModuleOptions>) -> Result<Self, CoreError> {
        Ok(Self {
            descriptor: build_descriptor()?,
            options: Mutex::new(options),
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
        validate_options_available(&self.options)
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
    let descriptor = ModuleDescriptor::new(descriptor_input()?)?;
    validate_embedded_metadata(&descriptor)?;
    Ok(descriptor)
}

fn descriptor_input() -> Result<ModuleDescriptorInput, CoreError> {
    let id = ModuleId::parse(MODULE_ID)?;
    let provided = relational_provider(&id)?;
    let page_key = page_key_requirement()?;
    let locator_key = secret_locator_key_requirement()?;
    let configuration = configuration_contract()?;
    let resources = module_resource_budget()?;
    let shutdown_priority = ShutdownPriority::new(512)?;
    Ok(ModuleDescriptorInput {
        id,
        version: MODULE_VERSION,
        build_commit: REVIEWED_RNMDB_COMMIT.into(),
        abi_version: CORE_ABI_VERSION,
        provided: vec![provided],
        required: Vec::new(),
        required_secret_capabilities: vec![page_key, locator_key],
        configuration,
        resources,
        shutdown_priority,
        sensitive_paths: vec![
            "storage.rnmdb.page_key_ref".into(),
            "storage.rnmdb.secret_locator_key_ref".into(),
        ],
        observability_namespace: "ariadnion.storage.rnmdb".into(),
        audit_namespace: "ariadnion.storage.rnmdb".into(),
    })
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
    validate_metadata_scalar("id", descriptor.id().as_str())?;
    validate_metadata_scalar("version", &descriptor.version().to_string())?;
    validate_metadata_scalar("abi", &descriptor.abi_version().to_string())?;
    validate_metadata_scalar("license", MODULE_LICENSE)?;
    validate_metadata_set("provides", &provided_metadata_set(descriptor))?;
    validate_metadata_set("requires", &required_metadata_set(descriptor))?;
    validate_metadata_set(
        "requires_secrets",
        &required_secret_metadata_set(descriptor),
    )
}

fn validate_metadata_scalar(key: &str, expected: &str) -> Result<(), CoreError> {
    if metadata_string(key)? != expected {
        return Err(metadata_mismatch());
    }
    Ok(())
}

fn validate_metadata_set(key: &str, expected: &BTreeSet<String>) -> Result<(), CoreError> {
    if &metadata_set(key)? != expected {
        return Err(metadata_mismatch());
    }
    Ok(())
}

fn provided_metadata_set(descriptor: &ModuleDescriptor) -> BTreeSet<String> {
    descriptor
        .provided_capabilities()
        .iter()
        .map(|provider| versioned_capability(provider.id(), provider.version()))
        .collect()
}

fn required_metadata_set(descriptor: &ModuleDescriptor) -> BTreeSet<String> {
    descriptor
        .required_capabilities()
        .iter()
        .map(|requirement| versioned_capability(requirement.id(), requirement.minimum()))
        .collect()
}

fn required_secret_metadata_set(descriptor: &ModuleDescriptor) -> BTreeSet<String> {
    descriptor
        .required_secret_capabilities()
        .iter()
        .map(SecretCapabilityRequirement::requirement)
        .map(|requirement| versioned_capability(requirement.id(), requirement.minimum()))
        .collect()
}

fn versioned_capability(id: &CapabilityId, version: ModuleVersion) -> String {
    format!("{id}@{version}")
}

fn metadata_string(key: &str) -> Result<&'static str, CoreError> {
    parse_metadata_string(metadata_value(key)?)
}

fn metadata_set(key: &str) -> Result<BTreeSet<String>, CoreError> {
    let members = metadata_array_members(metadata_value(key)?)?;
    if members.is_empty() {
        return Ok(BTreeSet::new());
    }
    let entries = members
        .split(',')
        .map(str::trim)
        .map(parse_metadata_string)
        .map(|entry| entry.map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    reject_duplicate_metadata_entries(&entries)?;
    Ok(entries.into_iter().collect())
}

fn metadata_value(key: &str) -> Result<&'static str, CoreError> {
    let mut found = None;
    for line in MODULE_METADATA.lines() {
        let Some((candidate, value)) = line.split_once('=') else {
            continue;
        };
        if candidate.trim() != key {
            continue;
        }
        if found.is_some() {
            return Err(metadata_mismatch());
        }
        found = Some(value.trim());
    }
    found.ok_or_else(metadata_mismatch)
}

fn parse_metadata_string(value: &'static str) -> Result<&'static str, CoreError> {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .filter(|inner| !inner.contains('"'))
        .ok_or_else(metadata_mismatch)
}

fn metadata_array_members(value: &'static str) -> Result<&'static str, CoreError> {
    value
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .map(str::trim)
        .ok_or_else(metadata_mismatch)
}

fn reject_duplicate_metadata_entries(entries: &[String]) -> Result<(), CoreError> {
    let unique: BTreeSet<&str> = entries.iter().map(String::as_str).collect();
    if unique.len() != entries.len() {
        return Err(metadata_mismatch());
    }
    Ok(())
}

fn metadata_mismatch() -> CoreError {
    CoreError::from_code(ErrorCode::Conflict)
        .with_internal_context("embedded RNMDB metadata differs from its descriptor")
}

fn validate_options_available(
    options: &Mutex<Option<StorageRnmdbModuleOptions>>,
) -> Result<(), CoreError> {
    if lock_options(options).is_none() {
        return Err(CoreError::from_code(ErrorCode::Unavailable)
            .with_internal_context("RNMDB session options are unavailable"));
    }
    Ok(())
}

fn take_options(
    options: &Mutex<Option<StorageRnmdbModuleOptions>>,
) -> Result<StorageRnmdbModuleOptions, CoreError> {
    lock_options(options).take().ok_or_else(|| {
        CoreError::from_code(ErrorCode::Unavailable)
            .with_internal_context("RNMDB session options are unavailable")
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

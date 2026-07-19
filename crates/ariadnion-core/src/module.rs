//! Immutable module descriptors and side-effect-bounded lifecycle contracts.

use std::sync::Arc;
use std::time::SystemTime;

use crate::capability::{CapabilityProvider, CapabilityRequirement, CapabilityResolution};
use crate::context::CancellationToken;
use crate::error::CoreError;
use crate::health::ModuleHealthSnapshot;
use crate::ids::{AbiVersion, ModuleId, ModuleVersion};
use crate::resource::ResourceBudget;

const MAX_CAPABILITIES: usize = 128;
const MAX_SENSITIVE_PATHS: usize = 64;
const MAX_NAMESPACE_BYTES: usize = 128;
const CONFIGURATION_DIGEST_BYTES: usize = 64;

/// Identifies an immutable module configuration schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationContract {
    schema_id: Box<str>,
    version: ModuleVersion,
    supports_hot_reload: bool,
}

impl ConfigurationContract {
    /// Creates a bounded configuration contract.
    pub fn new(
        schema_id: impl Into<Box<str>>,
        version: ModuleVersion,
        supports_hot_reload: bool,
    ) -> Result<Self, CoreError> {
        let schema_id = schema_id.into();
        validate_namespace(&schema_id)?;
        Ok(Self {
            schema_id,
            version,
            supports_hot_reload,
        })
    }

    /// Returns the stable schema identity.
    #[must_use]
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Returns the schema version.
    #[must_use]
    pub const fn version(&self) -> ModuleVersion {
        self.version
    }

    /// Returns whether immutable snapshots can be replaced at runtime.
    #[must_use]
    pub const fn supports_hot_reload(&self) -> bool {
        self.supports_hot_reload
    }
}

/// Immutable metadata used before a module executes side effects.
#[derive(Clone, Debug)]
pub struct ModuleDescriptor {
    id: ModuleId,
    version: ModuleVersion,
    build_commit: Box<str>,
    abi_version: AbiVersion,
    provided: Vec<CapabilityProvider>,
    required: Vec<CapabilityRequirement>,
    configuration: ConfigurationContract,
    resources: ResourceBudget,
    sensitive_paths: Vec<Box<str>>,
    observability_namespace: Box<str>,
    audit_namespace: Box<str>,
}

/// Inputs used to construct a module descriptor without an oversized function signature.
pub struct ModuleDescriptorInput {
    /// Stable module identity.
    pub id: ModuleId,
    /// Module implementation version.
    pub version: ModuleVersion,
    /// Build commit or immutable source identity.
    pub build_commit: Box<str>,
    /// Core/component ABI expected by the module.
    pub abi_version: AbiVersion,
    /// Capabilities implemented by the module.
    pub provided: Vec<CapabilityProvider>,
    /// Capabilities required by the module.
    pub required: Vec<CapabilityRequirement>,
    /// Configuration schema and hot-reload contract.
    pub configuration: ConfigurationContract,
    /// Resource and timeout budgets.
    pub resources: ResourceBudget,
    /// Configuration paths containing sensitive references.
    pub sensitive_paths: Vec<Box<str>>,
    /// Stable trace, metric, and log namespace.
    pub observability_namespace: Box<str>,
    /// Stable audit event namespace.
    pub audit_namespace: Box<str>,
}

impl ModuleDescriptor {
    /// Validates and creates an immutable descriptor.
    pub fn new(input: ModuleDescriptorInput) -> Result<Self, CoreError> {
        validate_descriptor_input(&input)?;
        Ok(Self {
            id: input.id,
            version: input.version,
            build_commit: input.build_commit,
            abi_version: input.abi_version,
            provided: input.provided,
            required: input.required,
            configuration: input.configuration,
            resources: input.resources,
            sensitive_paths: input.sensitive_paths,
            observability_namespace: input.observability_namespace,
            audit_namespace: input.audit_namespace,
        })
    }

    /// Returns the stable module identity.
    #[must_use]
    pub const fn id(&self) -> &ModuleId {
        &self.id
    }

    /// Returns the implementation version.
    #[must_use]
    pub const fn version(&self) -> ModuleVersion {
        self.version
    }

    /// Returns the immutable build identity.
    #[must_use]
    pub fn build_commit(&self) -> &str {
        &self.build_commit
    }

    /// Returns the ABI version.
    #[must_use]
    pub const fn abi_version(&self) -> AbiVersion {
        self.abi_version
    }

    /// Returns provided capabilities.
    #[must_use]
    pub fn provided_capabilities(&self) -> &[CapabilityProvider] {
        &self.provided
    }

    /// Returns required capabilities.
    #[must_use]
    pub fn required_capabilities(&self) -> &[CapabilityRequirement] {
        &self.required
    }

    /// Returns the configuration contract.
    #[must_use]
    pub const fn configuration(&self) -> &ConfigurationContract {
        &self.configuration
    }

    /// Returns the resource budget.
    #[must_use]
    pub const fn resources(&self) -> ResourceBudget {
        self.resources
    }

    /// Returns sensitive configuration paths.
    #[must_use]
    pub fn sensitive_paths(&self) -> &[Box<str>] {
        &self.sensitive_paths
    }

    /// Returns the observability namespace.
    #[must_use]
    pub fn observability_namespace(&self) -> &str {
        &self.observability_namespace
    }

    /// Returns the audit namespace.
    #[must_use]
    pub fn audit_namespace(&self) -> &str {
        &self.audit_namespace
    }
}

fn validate_descriptor_input(input: &ModuleDescriptorInput) -> Result<(), CoreError> {
    validate_capability_counts(input.provided.len(), input.required.len())?;
    validate_provider_ownership(&input.id, &input.provided)?;
    validate_namespace(&input.build_commit)?;
    validate_sensitive_paths(&input.sensitive_paths)?;
    validate_namespace(&input.observability_namespace)?;
    validate_namespace(&input.audit_namespace)?;
    input.resources.validate()
}

fn validate_provider_ownership(
    module_id: &ModuleId,
    providers: &[CapabilityProvider],
) -> Result<(), CoreError> {
    if providers
        .iter()
        .any(|provider| provider.module_id() != module_id)
    {
        return Err(
            crate::error::CoreError::from_code(crate::error::ErrorCode::Conflict)
                .with_internal_context("capability provider owner differs from module descriptor"),
        );
    }
    Ok(())
}

fn validate_capability_counts(provided: usize, required: usize) -> Result<(), CoreError> {
    if provided > MAX_CAPABILITIES || required > MAX_CAPABILITIES {
        return Err(
            crate::error::CoreError::from_code(crate::error::ErrorCode::ResourceExhausted)
                .with_internal_context("module capability declaration limit reached"),
        );
    }
    Ok(())
}

fn validate_sensitive_paths(paths: &[Box<str>]) -> Result<(), CoreError> {
    if paths.len() > MAX_SENSITIVE_PATHS {
        return Err(
            crate::error::CoreError::from_code(crate::error::ErrorCode::ResourceExhausted)
                .with_internal_context("module sensitive path limit reached"),
        );
    }
    for path in paths {
        validate_namespace(path)?;
    }
    Ok(())
}

fn validate_namespace(value: &str) -> Result<(), CoreError> {
    if value.is_empty() || value.len() > MAX_NAMESPACE_BYTES || !value.is_ascii() {
        return Err(
            crate::error::CoreError::from_code(crate::error::ErrorCode::InvalidArgument)
                .with_internal_context("module namespace is invalid"),
        );
    }
    Ok(())
}

/// A versioned immutable configuration snapshot presented to a module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleConfigurationSnapshot {
    schema_id: Box<str>,
    version: u64,
    digest: Box<str>,
}

impl ModuleConfigurationSnapshot {
    /// Creates a configuration snapshot reference.
    ///
    /// Versions start at one. Digests must contain exactly 64 ASCII
    /// hexadecimal characters. Invalid input returns
    /// [`crate::ErrorCode::InvalidArgument`] without retaining the input.
    pub fn new(
        schema_id: impl AsRef<str>,
        version: u64,
        digest: impl AsRef<str>,
    ) -> Result<Self, CoreError> {
        validate_configuration_version(version)?;
        let schema_id = schema_id.as_ref();
        let digest = digest.as_ref();
        validate_namespace(schema_id)?;
        validate_configuration_digest(digest)?;
        Ok(Self {
            schema_id: schema_id.into(),
            version,
            digest: digest.into(),
        })
    }

    /// Returns the schema identity.
    #[must_use]
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Returns the monotonic configuration version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the immutable content digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn validate_configuration_version(version: u64) -> Result<(), CoreError> {
    if version == 0 {
        return Err(
            crate::error::CoreError::from_code(crate::error::ErrorCode::InvalidArgument)
                .with_internal_context("configuration snapshot version must be positive"),
        );
    }
    Ok(())
}

fn validate_configuration_digest(digest: &str) -> Result<(), CoreError> {
    let valid = digest.len() == CONFIGURATION_DIGEST_BYTES
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !valid {
        return Err(
            crate::error::CoreError::from_code(crate::error::ErrorCode::InvalidArgument)
                .with_internal_context("configuration snapshot digest is invalid"),
        );
    }
    Ok(())
}

/// A restricted context supplied while starting a module.
#[derive(Clone)]
pub struct ModuleContext {
    cancellation: CancellationToken,
    capabilities: Arc<CapabilityResolution>,
}

impl ModuleContext {
    /// Creates a context from resolved capabilities.
    #[must_use]
    pub fn new(cancellation: CancellationToken, capabilities: CapabilityResolution) -> Self {
        Self {
            cancellation,
            capabilities: Arc::new(capabilities),
        }
    }

    /// Returns the cancellation token.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Returns resolved capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilityResolution {
        &self.capabilities
    }
}

/// Side-effect-free validation and module construction.
pub trait ModuleFactory: Send + Sync {
    /// Returns immutable module metadata without side effects.
    fn descriptor(&self) -> &ModuleDescriptor;

    /// Validates configuration and resolved capabilities without starting tasks.
    fn validate(
        &self,
        configuration: &ModuleConfigurationSnapshot,
        capabilities: &CapabilityResolution,
    ) -> Result<(), CoreError>;

    /// Starts module work and returns its operational handle.
    fn start(&self, context: ModuleContext) -> Result<Box<dyn ModuleHandle>, CoreError>;
}

/// Operational module behavior after successful startup.
pub trait ModuleHandle: Send {
    /// Returns a safe health snapshot.
    fn health(&self) -> Result<ModuleHealthSnapshot, CoreError>;

    /// Applies a new immutable configuration snapshot.
    fn reconfigure(&mut self, snapshot: ModuleConfigurationSnapshot) -> Result<(), CoreError>;

    /// Stops module work before the supplied UTC deadline.
    fn shutdown(&mut self, deadline: SystemTime) -> Result<ModuleShutdownReport, CoreError>;
}

/// A safe module shutdown result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleShutdownReport {
    tasks_completed: usize,
    tasks_incomplete: usize,
    flushed: bool,
}

impl ModuleShutdownReport {
    /// Creates a bounded shutdown report.
    #[must_use]
    pub const fn new(tasks_completed: usize, tasks_incomplete: usize, flushed: bool) -> Self {
        Self {
            tasks_completed,
            tasks_incomplete,
            flushed,
        }
    }

    /// Returns the number of completed tasks.
    #[must_use]
    pub const fn tasks_completed(self) -> usize {
        self.tasks_completed
    }

    /// Returns the number of incomplete tasks.
    #[must_use]
    pub const fn tasks_incomplete(self) -> usize {
        self.tasks_incomplete
    }

    /// Returns whether buffered state was flushed.
    #[must_use]
    pub const fn flushed(self) -> bool {
        self.flushed
    }
}

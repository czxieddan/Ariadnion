// crates/optional/ariadnion-storage-rnmdb/src/module.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! RNMDB relational-storage module descriptor and lifecycle adapter.

use std::collections::BTreeSet;
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_api_admin::AdminExecutionPort;
use ariadnion_api_files::FileCatalogServicePort;
use ariadnion_core::{
    CORE_ABI_VERSION, CapabilityId, CapabilityProvider, CapabilityRequirement,
    CapabilityResolution, ConfigurationContract, CoreError, ErrorCode, ExecutionBudget,
    ExecutionBudgetInput, HealthReasonCode, HealthStatus, LifecycleBudget, LifecycleBudgetInput,
    ModuleConfigurationSnapshot, ModuleContext, ModuleDescriptor, ModuleDescriptorInput,
    ModuleFactory, ModuleHandle, ModuleHealthSnapshot, ModuleId, ModuleShutdownReport,
    ModuleVersion, PortHandle, RequestContext, RequestId, ResourceBudget,
    SecretCapabilityRequirement, ShutdownPriority, TraceId, WasmBudget,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};

use crate::admin_execution::{AdminExecutionCapability, admin_execution_provider};
use crate::migration_definition::compiled_migration_definitions;
use crate::{
    AuditSubjectKeyMaterial, REVIEWED_RNMDB_COMMIT, RnmdbColumnSecurity, RnmdbMigrationRunner,
    RnmdbSessionOwner, SecretLocatorKeyMaterial, SessionOpenOptions, UtcTimestampMicros,
};

mod file_catalog;

use file_catalog::{FileCatalogCapability, file_catalog_provider};

const MODULE_ID: &str = "org.ariadnion.storage.rnmdb";
const RELATIONAL_CAPABILITY: &str = "org.ariadnion.storage.relational";
const PAGE_KEY_CAPABILITY: &str = "org.ariadnion.secret.page-key";
const SECRET_LOCATOR_KEY_CAPABILITY: &str = "org.ariadnion.secret.locator-column-key";
const AUDIT_SUBJECT_KEY_CAPABILITY: &str = "org.ariadnion.secret.audit-subject-key";
const FILE_CATALOG_LOOKUP_KEY_CAPABILITY: &str = "org.ariadnion.secret.file-catalog-lookup-key";
const FILE_CATALOG_COMMITMENT_KEYS_CAPABILITY: &str =
    "org.ariadnion.secret.file-catalog-commitment-keys";
const CONFIGURATION_SCHEMA: &str = "org.ariadnion.storage.rnmdb.config";
const MODULE_LICENSE: &str = "LicenseRef-AHCL-1.0";
const EMPTY_CONFIGURATION_DIGEST: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MODULE_VERSION: ModuleVersion = ModuleVersion::new(0, 1, 0);
const CONTRACT_VERSION: ModuleVersion = ModuleVersion::new(1, 0, 0);
const MODULE_METADATA: &str = include_str!("../module.toml");

/// A single-use factory for one encrypted embedded RNMDB session.
///
/// Secret-bearing open options remain behind a mutex and are consumed exactly
/// once by [`ModuleFactory::start`]. The immutable descriptor contains only a
/// typed set of page, locator-column, and audit-subject secret requirements and
/// their sensitive configuration paths.
pub struct StorageRnmdbModule {
    descriptor: ModuleDescriptor,
    options: Mutex<Option<StorageRnmdbModuleOptions>>,
    admin_execution: AdminExecutionCapability,
    file_catalog: FileCatalogCapability,
    #[cfg(feature = "test-hooks")]
    lifecycle_test_hooks: Arc<ModuleLifecycleTestHooks>,
}

/// Sanitized lifecycle observations for external module contract tests.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleLifecycleTestSnapshot {
    session_open_count: u64,
    admin_session_id: u64,
    catalog_session_id: u64,
    catalog_invalidation_event: u64,
    session_close_event: u64,
}

#[cfg(feature = "test-hooks")]
impl ModuleLifecycleTestSnapshot {
    /// Returns successful embedded-session opens observed by this factory.
    #[must_use]
    pub const fn session_open_count(self) -> u64 {
        self.session_open_count
    }

    /// Returns whether both published capabilities used the only opened session.
    #[must_use]
    pub const fn admin_and_catalog_share_session(self) -> bool {
        self.session_open_count == 1
            && self.admin_session_id != 0
            && self.admin_session_id == self.catalog_session_id
    }

    /// Returns whether catalog invalidation preceded the session close attempt.
    #[must_use]
    pub const fn catalog_invalidated_before_session_close(self) -> bool {
        self.catalog_invalidation_event != 0
            && self.session_close_event != 0
            && self.catalog_invalidation_event < self.session_close_event
    }
}

#[cfg(feature = "test-hooks")]
struct ModuleLifecycleTestHooks {
    next_event: AtomicU64,
    session_open_count: AtomicU64,
    admin_session_id: AtomicU64,
    catalog_session_id: AtomicU64,
    catalog_invalidation_event: AtomicU64,
    session_close_event: AtomicU64,
}

#[cfg(feature = "test-hooks")]
impl ModuleLifecycleTestHooks {
    fn new() -> Self {
        Self {
            next_event: AtomicU64::new(1),
            session_open_count: AtomicU64::new(0),
            admin_session_id: AtomicU64::new(0),
            catalog_session_id: AtomicU64::new(0),
            catalog_invalidation_event: AtomicU64::new(0),
            session_close_event: AtomicU64::new(0),
        }
    }

    fn record_session_open(&self) -> u64 {
        self.session_open_count.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn record_admin_session(&self, session_id: u64) {
        self.admin_session_id.store(session_id, Ordering::Release);
    }

    fn record_catalog_session(&self, session_id: u64) {
        self.catalog_session_id.store(session_id, Ordering::Release);
    }

    fn record_catalog_invalidation(&self) {
        self.record_event(&self.catalog_invalidation_event);
    }

    fn record_session_close(&self) {
        self.record_event(&self.session_close_event);
    }

    fn record_event(&self, destination: &AtomicU64) {
        destination.store(
            self.next_event.fetch_add(1, Ordering::AcqRel),
            Ordering::Release,
        );
    }

    fn snapshot(&self) -> ModuleLifecycleTestSnapshot {
        ModuleLifecycleTestSnapshot {
            session_open_count: self.session_open_count.load(Ordering::Acquire),
            admin_session_id: self.admin_session_id.load(Ordering::Acquire),
            catalog_session_id: self.catalog_session_id.load(Ordering::Acquire),
            catalog_invalidation_event: self.catalog_invalidation_event.load(Ordering::Acquire),
            session_close_event: self.session_close_event.load(Ordering::Acquire),
        }
    }
}

/// Single-consumption secrets and paths needed to start RNMDB storage.
pub struct StorageRnmdbModuleOptions {
    session: SessionOpenOptions,
    secret_locator_key: SecretLocatorKeyMaterial,
    audit_subject_key: AuditSubjectKeyMaterial,
    file_catalog_lookup_key: crate::FileCatalogLookupKeyMaterial,
    file_catalog_commitment_keys: crate::FileCatalogCommitmentKeys,
}

impl StorageRnmdbModuleOptions {
    /// Combines encrypted-session options with locator-column and audit-subject keys.
    #[must_use]
    pub const fn new(
        session: SessionOpenOptions,
        secret_locator_key: SecretLocatorKeyMaterial,
        audit_subject_key: AuditSubjectKeyMaterial,
        file_catalog_lookup_key: crate::FileCatalogLookupKeyMaterial,
        file_catalog_commitment_keys: crate::FileCatalogCommitmentKeys,
    ) -> Self {
        Self {
            session,
            secret_locator_key,
            audit_subject_key,
            file_catalog_lookup_key,
            file_catalog_commitment_keys,
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

    /// Resolves the shared administration executor for the current live generation.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Unavailable`] before successful startup and after
    /// shutdown invalidates the provider generation.
    pub fn resolve_admin_execution(&self) -> Result<PortHandle<dyn AdminExecutionPort>, CoreError> {
        self.admin_execution.resolve()
    }

    /// Resolves the durable file catalog for the current live generation.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Unavailable`] before successful startup and after
    /// shutdown invalidates the provider generation.
    pub fn resolve_file_catalog(
        &self,
    ) -> Result<PortHandle<dyn FileCatalogServicePort>, CoreError> {
        self.file_catalog.resolve()
    }

    /// Returns sanitized lifecycle evidence for external contract tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn lifecycle_test_snapshot(&self) -> ModuleLifecycleTestSnapshot {
        self.lifecycle_test_hooks.snapshot()
    }

    /// Arms one deterministic catalog publication failure for external contract tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn fail_next_file_catalog_publication_for_test(&self) -> Result<(), CoreError> {
        self.file_catalog.fail_next_publication_for_test()
    }

    fn with_options(options: Option<StorageRnmdbModuleOptions>) -> Result<Self, CoreError> {
        Ok(Self {
            descriptor: build_descriptor()?,
            options: Mutex::new(options),
            admin_execution: AdminExecutionCapability::new()?,
            file_catalog: FileCatalogCapability::new()?,
            #[cfg(feature = "test-hooks")]
            lifecycle_test_hooks: Arc::new(ModuleLifecycleTestHooks::new()),
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
        let ready = start_ready_storage(
            options,
            cancellation.clone(),
            #[cfg(feature = "test-hooks")]
            self.lifecycle_test_hooks.as_ref(),
        )?;
        let session = publish_storage_capabilities(
            &self.admin_execution,
            &self.file_catalog,
            ready,
            cancellation.clone(),
            #[cfg(feature = "test-hooks")]
            self.lifecycle_test_hooks.as_ref(),
        )?;
        Ok(Box::new(StorageRnmdbHandle {
            module_id: self.descriptor.id().clone(),
            cancellation,
            session: Some(session),
            admin_execution: Some(self.admin_execution.clone()),
            file_catalog: Some(self.file_catalog.clone()),
            #[cfg(feature = "test-hooks")]
            lifecycle_test_hooks: self.lifecycle_test_hooks.clone(),
        }))
    }
}

struct StorageRnmdbHandle {
    module_id: ModuleId,
    cancellation: ariadnion_core::CancellationToken,
    session: Option<Arc<RnmdbSessionOwner>>,
    admin_execution: Option<AdminExecutionCapability>,
    file_catalog: Option<FileCatalogCapability>,
    #[cfg(feature = "test-hooks")]
    lifecycle_test_hooks: Arc<ModuleLifecycleTestHooks>,
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
        invalidate_file_catalog(&mut self.file_catalog)?;
        #[cfg(feature = "test-hooks")]
        self.lifecycle_test_hooks.record_catalog_invalidation();
        invalidate_admin_execution(&mut self.admin_execution)?;
        let Some(session) = self.session.as_ref() else {
            return Ok(ModuleShutdownReport::new(0, 0, true));
        };
        #[cfg(feature = "test-hooks")]
        self.lifecycle_test_hooks.record_session_close();
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
    let provided = descriptor_providers(&id)?;
    let required_secret_capabilities = descriptor_secret_requirements()?;
    let configuration = configuration_contract()?;
    let resources = module_resource_budget()?;
    let shutdown_priority = ShutdownPriority::new(512)?;
    Ok(ModuleDescriptorInput {
        id,
        version: MODULE_VERSION,
        build_commit: REVIEWED_RNMDB_COMMIT.into(),
        abi_version: CORE_ABI_VERSION,
        provided,
        required: Vec::new(),
        required_secret_capabilities,
        configuration,
        resources,
        shutdown_priority,
        sensitive_paths: vec![
            "storage.rnmdb.page_key_ref".into(),
            "storage.rnmdb.secret_locator_key_ref".into(),
            "storage.rnmdb.audit_subject_key_ref".into(),
            "storage.rnmdb.file_catalog_lookup_key_ref".into(),
            "storage.rnmdb.file_catalog_commitment_keys_ref".into(),
        ],
        observability_namespace: "ariadnion.storage.rnmdb".into(),
        audit_namespace: "ariadnion.storage.rnmdb".into(),
    })
}

fn descriptor_providers(module_id: &ModuleId) -> Result<Vec<CapabilityProvider>, CoreError> {
    Ok(vec![
        relational_provider(module_id)?,
        admin_execution_provider(module_id, CONTRACT_VERSION)?,
        file_catalog_provider(module_id, CONTRACT_VERSION)?,
    ])
}

fn descriptor_secret_requirements() -> Result<Vec<SecretCapabilityRequirement>, CoreError> {
    Ok(vec![
        page_key_requirement()?,
        secret_locator_key_requirement()?,
        audit_subject_key_requirement()?,
        file_catalog_lookup_key_requirement()?,
        file_catalog_commitment_keys_requirement()?,
    ])
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

fn audit_subject_key_requirement() -> Result<SecretCapabilityRequirement, CoreError> {
    Ok(SecretCapabilityRequirement::new(
        CapabilityRequirement::new(
            CapabilityId::parse(AUDIT_SUBJECT_KEY_CAPABILITY)?,
            CONTRACT_VERSION,
            Some(1),
        ),
    ))
}

fn file_catalog_lookup_key_requirement() -> Result<SecretCapabilityRequirement, CoreError> {
    secret_requirement(FILE_CATALOG_LOOKUP_KEY_CAPABILITY)
}

fn file_catalog_commitment_keys_requirement() -> Result<SecretCapabilityRequirement, CoreError> {
    secret_requirement(FILE_CATALOG_COMMITMENT_KEYS_CAPABILITY)
}

fn secret_requirement(id: &str) -> Result<SecretCapabilityRequirement, CoreError> {
    Ok(SecretCapabilityRequirement::new(
        CapabilityRequirement::new(CapabilityId::parse(id)?, CONTRACT_VERSION, Some(1)),
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
    if requirements.len() != 5 {
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

fn invalidate_admin_execution(
    capability: &mut Option<AdminExecutionCapability>,
) -> Result<(), CoreError> {
    let Some(active) = capability.as_ref() else {
        return Ok(());
    };
    active.invalidate()?;
    *capability = None;
    Ok(())
}

fn invalidate_file_catalog(
    capability: &mut Option<FileCatalogCapability>,
) -> Result<(), CoreError> {
    let Some(active) = capability.as_ref() else {
        return Ok(());
    };
    active.invalidate()?;
    *capability = None;
    Ok(())
}

struct ReadyStorage {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
    file_catalog_lookup_key: crate::FileCatalogLookupKeyMaterial,
    file_catalog_commitment_keys: crate::FileCatalogCommitmentKeys,
    #[cfg(feature = "test-hooks")]
    session_id: u64,
}

fn start_ready_storage(
    options: StorageRnmdbModuleOptions,
    cancellation: ariadnion_core::CancellationToken,
    #[cfg(feature = "test-hooks")] lifecycle_test_hooks: &ModuleLifecycleTestHooks,
) -> Result<ReadyStorage, CoreError> {
    let session = RnmdbSessionOwner::open(options.session)
        .map(Arc::new)
        .map_err(map_storage_error)?;
    #[cfg(feature = "test-hooks")]
    let session_id = lifecycle_test_hooks.record_session_open();
    let request = startup_request_context(cancellation)?;
    apply_startup_migrations(&session, &request)?;
    RnmdbColumnSecurity::new(session.clone())
        .configure_secret_locator(options.secret_locator_key, &request)
        .map_err(map_storage_error)?;
    Ok(ReadyStorage {
        session,
        audit_subject_key: options.audit_subject_key,
        file_catalog_lookup_key: options.file_catalog_lookup_key,
        file_catalog_commitment_keys: options.file_catalog_commitment_keys,
        #[cfg(feature = "test-hooks")]
        session_id,
    })
}

fn publish_storage_capabilities(
    admin_execution: &AdminExecutionCapability,
    file_catalog: &FileCatalogCapability,
    ready: ReadyStorage,
    cancellation: ariadnion_core::CancellationToken,
    #[cfg(feature = "test-hooks")] lifecycle_test_hooks: &ModuleLifecycleTestHooks,
) -> Result<Arc<RnmdbSessionOwner>, CoreError> {
    let catalog = FileCatalogCapability::build(
        ready.session.clone(),
        ready.file_catalog_lookup_key,
        ready.file_catalog_commitment_keys,
    )?;
    #[cfg(feature = "test-hooks")]
    lifecycle_test_hooks.record_catalog_session(ready.session_id);
    admin_execution.publish(
        ready.session.clone(),
        ready.audit_subject_key,
        cancellation.clone(),
    )?;
    #[cfg(feature = "test-hooks")]
    lifecycle_test_hooks.record_admin_session(ready.session_id);
    if let Err(error) = file_catalog.publish(catalog, cancellation) {
        return rollback_admin_publication(admin_execution, error);
    }
    Ok(ready.session)
}

fn rollback_admin_publication(
    admin_execution: &AdminExecutionCapability,
    publication_error: CoreError,
) -> Result<Arc<RnmdbSessionOwner>, CoreError> {
    admin_execution.invalidate()?;
    Err(publication_error)
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
    let plan = compiled_migration_definitions()
        .and_then(|definitions| definitions.startup_plan())
        .map_err(map_storage_error)?;
    for descriptor in plan.steps() {
        let _status = runner
            .apply(descriptor, applied_at, context)
            .map_err(map_storage_error)?;
    }
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
        StorageErrorCode::NotFound
        | StorageErrorCode::Unavailable
        | StorageErrorCode::CommitIndeterminate => ErrorCode::Unavailable,
        _ => ErrorCode::Internal,
    };
    CoreError::from_code(code).with_internal_context("RNMDB module operation failed")
}

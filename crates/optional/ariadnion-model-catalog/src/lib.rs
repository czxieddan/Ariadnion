// crates/optional/ariadnion-model-catalog/src/lib.rs - Model catalog projections for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Immutable internal-to-provider model mappings and tenant-safe projections.
//!
//! The domain descriptor remains authoritative for model identity and capability
//! validation. This crate adds publication visibility and produces projections
//! that deliberately omit provider identities and provider-side model names.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU64;
use std::sync::{Arc, RwLock};

use ariadnion_core::TenantId;
use ariadnion_model_domain::{
    ModelAlias, ModelCapabilities, ModelCatalog, ModelDescriptor, ModelDomainErrorCode, ModelId,
    ModelLimits, ModelVersion, ProviderId, ProviderModelId,
};

/// Maximum number of model entries in one published snapshot.
pub const MAX_CATALOG_ENTRIES: usize = 4_096;
/// Maximum number of tenant identities in one restricted visibility rule.
pub const MAX_VISIBLE_TENANTS_PER_MODEL: usize = 4_096;

/// Stable machine-readable failures returned by model-catalog operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ModelCatalogErrorCode {
    /// An input is empty, malformed, or otherwise invalid.
    InvalidArgument,
    /// A catalog or visibility list exceeded a fixed bound.
    LimitExceeded,
    /// A catalog contains colliding identities, aliases, or provider mappings.
    Conflict,
    /// One internal model maps to more than one target for the same provider.
    AmbiguousProvider,
    /// The requested internal model or public selector is unavailable.
    ModelNotFound,
    /// The requested provider target is unavailable for the selected model.
    ProviderTargetNotFound,
    /// A monotonic snapshot version cannot advance without wrapping.
    VersionExhausted,
    /// The process-local snapshot owner cannot be read or updated safely.
    StateUnavailable,
}

impl ModelCatalogErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument | Self::LimitExceeded | Self::Conflict => {
                catalog_request_error_code(self)
            }
            Self::AmbiguousProvider | Self::ModelNotFound | Self::ProviderTargetNotFound => {
                catalog_lookup_error_code(self)
            }
            Self::VersionExhausted | Self::StateUnavailable => catalog_state_error_code(self),
        }
    }
}

const fn catalog_request_error_code(code: ModelCatalogErrorCode) -> &'static str {
    match code {
        ModelCatalogErrorCode::InvalidArgument => "MODEL_CATALOG_INVALID_ARGUMENT",
        ModelCatalogErrorCode::LimitExceeded => "MODEL_CATALOG_LIMIT_EXCEEDED",
        ModelCatalogErrorCode::Conflict => "MODEL_CATALOG_CONFLICT",
        _ => "MODEL_CATALOG_INVALID_ARGUMENT",
    }
}

const fn catalog_lookup_error_code(code: ModelCatalogErrorCode) -> &'static str {
    match code {
        ModelCatalogErrorCode::AmbiguousProvider => "MODEL_CATALOG_AMBIGUOUS_PROVIDER",
        ModelCatalogErrorCode::ModelNotFound => "MODEL_CATALOG_MODEL_NOT_FOUND",
        ModelCatalogErrorCode::ProviderTargetNotFound => "MODEL_CATALOG_PROVIDER_TARGET_NOT_FOUND",
        _ => "MODEL_CATALOG_MODEL_NOT_FOUND",
    }
}

const fn catalog_state_error_code(code: ModelCatalogErrorCode) -> &'static str {
    match code {
        ModelCatalogErrorCode::VersionExhausted => "MODEL_CATALOG_VERSION_EXHAUSTED",
        ModelCatalogErrorCode::StateUnavailable => "MODEL_CATALOG_STATE_UNAVAILABLE",
        _ => "MODEL_CATALOG_STATE_UNAVAILABLE",
    }
}

/// A redacted model-catalog failure containing only its stable code.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ModelCatalogError {
    code: ModelCatalogErrorCode,
}

impl ModelCatalogError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: ModelCatalogErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ModelCatalogErrorCode {
        self.code
    }
}

impl Debug for ModelCatalogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ModelCatalogError({})", self.code.as_str())
    }
}

impl Display for ModelCatalogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ModelCatalogError {}

/// A non-zero monotonic version identifying one immutable catalog snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CatalogVersion(NonZeroU64);

impl CatalogVersion {
    /// Returns the first publishable catalog version.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero catalog version.
    ///
    /// # Errors
    /// Returns [`ModelCatalogErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, ModelCatalogError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(ModelCatalogErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Advances the version without wrapping.
    ///
    /// # Errors
    /// Returns [`ModelCatalogErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, ModelCatalogError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(ModelCatalogErrorCode::VersionExhausted))
    }
}

/// Tenant visibility applied to one internal model descriptor.
#[derive(Clone, Eq, PartialEq)]
pub enum ModelVisibility {
    /// The model is visible to every authenticated tenant.
    Public,
    /// The model is visible only to a sorted, duplicate-free tenant allowlist.
    Restricted(Arc<[TenantId]>),
    /// The model remains available for internal provider resolution only.
    Internal,
}

impl ModelVisibility {
    /// Creates a restricted visibility rule from tenant identities.
    ///
    /// Tenant identities are sorted so projection behavior is deterministic.
    ///
    /// # Errors
    /// Returns a stable error for an empty, oversized, or duplicate allowlist.
    pub fn restricted(mut tenants: Vec<TenantId>) -> Result<Self, ModelCatalogError> {
        if tenants.is_empty() {
            return Err(error(ModelCatalogErrorCode::InvalidArgument));
        }
        if tenants.len() > MAX_VISIBLE_TENANTS_PER_MODEL {
            return Err(error(ModelCatalogErrorCode::LimitExceeded));
        }
        tenants.sort_unstable();
        if tenants.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(error(ModelCatalogErrorCode::Conflict));
        }
        Ok(Self::Restricted(Arc::from(tenants.into_boxed_slice())))
    }

    /// Reports whether the model is visible to a tenant.
    #[must_use]
    pub fn is_visible_to(&self, tenant_id: &TenantId) -> bool {
        match self {
            Self::Public => true,
            Self::Restricted(tenants) => tenants.binary_search(tenant_id).is_ok(),
            Self::Internal => false,
        }
    }

    /// Returns restricted tenant identities in deterministic order.
    #[must_use]
    pub fn tenants(&self) -> &[TenantId] {
        match self {
            Self::Restricted(tenants) => tenants,
            Self::Public | Self::Internal => &[],
        }
    }
}

impl Debug for ModelVisibility {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => formatter.write_str("ModelVisibility::Public"),
            Self::Restricted(tenants) => formatter
                .debug_struct("ModelVisibility::Restricted")
                .field("tenant_count", &tenants.len())
                .finish(),
            Self::Internal => formatter.write_str("ModelVisibility::Internal"),
        }
    }
}

/// One validated internal model and its publication visibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    descriptor: ModelDescriptor,
    visibility: ModelVisibility,
}

impl CatalogEntry {
    /// Creates an entry with unambiguous internal-to-provider mappings.
    ///
    /// # Errors
    /// Returns [`ModelCatalogErrorCode::AmbiguousProvider`] when the descriptor
    /// contains multiple primary targets for one provider identity.
    pub fn new(
        descriptor: ModelDescriptor,
        visibility: ModelVisibility,
    ) -> Result<Self, ModelCatalogError> {
        ensure_unique_providers(&descriptor)?;
        Ok(Self {
            descriptor,
            visibility,
        })
    }

    /// Returns the complete internal descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ModelDescriptor {
        &self.descriptor
    }

    /// Returns the canonical internal model identity.
    #[must_use]
    pub const fn model_id(&self) -> &ModelId {
        self.descriptor.id()
    }

    /// Returns the tenant visibility rule.
    #[must_use]
    pub const fn visibility(&self) -> &ModelVisibility {
        &self.visibility
    }
}

/// One resolved provider target for an internal model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderModelTarget {
    internal_model: ModelId,
    provider: ProviderId,
    provider_model: ProviderModelId,
}

impl ProviderModelTarget {
    /// Returns the provider-neutral internal model identity.
    #[must_use]
    pub const fn internal_model(&self) -> &ModelId {
        &self.internal_model
    }

    /// Returns the selected provider identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the provider-side primary model identity.
    #[must_use]
    pub const fn provider_model(&self) -> &ProviderModelId {
        &self.provider_model
    }

    /// Returns the provider-side model identity.
    #[must_use]
    pub const fn model(&self) -> &ProviderModelId {
        &self.provider_model
    }
}

/// A tenant-visible model projection without provider mapping details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantVisibleModel {
    id: ModelId,
    version: ModelVersion,
    capabilities: ModelCapabilities,
    limits: ModelLimits,
    aliases: Arc<[ModelAlias]>,
}

impl TenantVisibleModel {
    fn from_descriptor(descriptor: &ModelDescriptor) -> Self {
        Self {
            id: descriptor.id().clone(),
            version: descriptor.version(),
            capabilities: descriptor.capabilities(),
            limits: descriptor.limits(),
            aliases: Arc::from(descriptor.aliases().to_vec().into_boxed_slice()),
        }
    }

    /// Returns the canonical provider-neutral model identity.
    #[must_use]
    pub const fn id(&self) -> &ModelId {
        &self.id
    }

    /// Returns the canonical provider-neutral model identity.
    #[must_use]
    pub const fn model_id(&self) -> &ModelId {
        &self.id
    }

    /// Returns the immutable model descriptor version.
    #[must_use]
    pub const fn version(&self) -> ModelVersion {
        self.version
    }

    /// Returns public capabilities for this model.
    #[must_use]
    pub const fn capabilities(&self) -> ModelCapabilities {
        self.capabilities
    }

    /// Returns public request and response limits for this model.
    #[must_use]
    pub const fn limits(&self) -> ModelLimits {
        self.limits
    }

    /// Returns public aliases in deterministic order.
    #[must_use]
    pub fn aliases(&self) -> &[ModelAlias] {
        &self.aliases
    }

    fn matches(&self, selector: &str) -> bool {
        self.id.as_str() == selector || self.aliases.iter().any(|alias| alias.as_str() == selector)
    }
}

/// An immutable tenant-specific catalog view.
#[derive(Clone, Eq, PartialEq)]
pub struct TenantCatalogProjection {
    tenant_id: TenantId,
    version: CatalogVersion,
    models: Arc<[TenantVisibleModel]>,
}

impl TenantCatalogProjection {
    /// Returns the tenant for which this projection was constructed.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the source catalog version.
    #[must_use]
    pub const fn version(&self) -> CatalogVersion {
        self.version
    }

    /// Returns visible models in canonical identity order.
    #[must_use]
    pub fn models(&self) -> &[TenantVisibleModel] {
        &self.models
    }

    /// Resolves a visible canonical identity or alias.
    ///
    /// # Errors
    /// Returns [`ModelCatalogErrorCode::ModelNotFound`] without distinguishing
    /// hidden models from unknown models.
    pub fn resolve(&self, selector: &str) -> Result<&TenantVisibleModel, ModelCatalogError> {
        self.models
            .iter()
            .find(|model| model.matches(selector))
            .ok_or_else(|| error(ModelCatalogErrorCode::ModelNotFound))
    }
}

impl Debug for TenantCatalogProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantCatalogProjection")
            .field("tenant_id", &"<opaque>")
            .field("version", &self.version)
            .field("models", &self.models)
            .finish()
    }
}

/// A validated immutable model catalog publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCatalogSnapshot {
    version: CatalogVersion,
    entries: Arc<[CatalogEntry]>,
}

impl ModelCatalogSnapshot {
    /// Validates and freezes catalog entries into canonical identity order.
    ///
    /// Construction reuses the model-domain catalog validator, so identities,
    /// aliases, and provider-side names are unique across the complete snapshot.
    ///
    /// # Errors
    /// Returns a stable bounded or conflict error without retaining rejected data.
    pub fn new(
        version: CatalogVersion,
        mut entries: Vec<CatalogEntry>,
    ) -> Result<Self, ModelCatalogError> {
        if entries.len() > MAX_CATALOG_ENTRIES {
            return Err(error(ModelCatalogErrorCode::LimitExceeded));
        }
        validate_domain_catalog(&entries)?;
        entries.sort_unstable_by(|left, right| left.descriptor().id().cmp(right.descriptor().id()));
        Ok(Self {
            version,
            entries: Arc::from(entries.into_boxed_slice()),
        })
    }

    /// Returns the immutable snapshot version.
    #[must_use]
    pub const fn version(&self) -> CatalogVersion {
        self.version
    }

    /// Returns internal entries in canonical model identity order.
    #[must_use]
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// Resolves an internal model identity or alias.
    ///
    /// This internal lookup does not apply tenant visibility. Public callers
    /// must use a [`TenantCatalogProjection`].
    ///
    /// # Errors
    /// Returns [`ModelCatalogErrorCode::ModelNotFound`] for an absent selector.
    pub fn resolve_internal(&self, selector: &str) -> Result<&CatalogEntry, ModelCatalogError> {
        self.entries
            .iter()
            .find(|entry| descriptor_matches(entry.descriptor(), selector))
            .ok_or_else(|| error(ModelCatalogErrorCode::ModelNotFound))
    }

    /// Alias for [`Self::resolve_internal`] using lookup terminology.
    pub fn lookup(&self, selector: &str) -> Result<&CatalogEntry, ModelCatalogError> {
        self.resolve_internal(selector)
    }

    /// Resolves a canonical identity or alias to one provider target.
    ///
    /// # Errors
    /// Returns a stable not-found error when either selector or provider target
    /// is absent.
    pub fn resolve_provider_target(
        &self,
        selector: &str,
        provider: &ProviderId,
    ) -> Result<ProviderModelTarget, ModelCatalogError> {
        let entry = self.resolve_internal(selector)?;
        self.provider_target(entry.model_id(), provider)
    }

    /// Resolves one internal model to its primary provider-side target.
    ///
    /// # Errors
    /// Returns a stable not-found error when the model or provider target is absent.
    pub fn provider_target(
        &self,
        internal_model: &ModelId,
        provider: &ProviderId,
    ) -> Result<ProviderModelTarget, ModelCatalogError> {
        let entry = self
            .entries
            .binary_search_by(|candidate| candidate.descriptor().id().cmp(internal_model))
            .ok()
            .map(|index| &self.entries[index])
            .ok_or_else(|| error(ModelCatalogErrorCode::ModelNotFound))?;
        let mapping = entry
            .descriptor()
            .mappings()
            .iter()
            .find(|mapping| mapping.provider() == provider)
            .ok_or_else(|| error(ModelCatalogErrorCode::ProviderTargetNotFound))?;
        Ok(ProviderModelTarget {
            internal_model: internal_model.clone(),
            provider: provider.clone(),
            provider_model: mapping.provider_model().clone(),
        })
    }

    /// Produces a tenant-safe view without provider identities or provider models.
    #[must_use]
    pub fn project_for(&self, tenant_id: &TenantId) -> TenantCatalogProjection {
        let models = self
            .entries
            .iter()
            .filter(|entry| entry.visibility().is_visible_to(tenant_id))
            .map(|entry| TenantVisibleModel::from_descriptor(entry.descriptor()))
            .collect::<Vec<_>>();
        TenantCatalogProjection {
            tenant_id: tenant_id.clone(),
            version: self.version,
            models: Arc::from(models.into_boxed_slice()),
        }
    }
}

/// Read-only port exposing immutable model-catalog snapshots and projections.
pub trait ModelCatalogPort: Send + Sync {
    /// Returns the latest complete immutable snapshot.
    ///
    /// # Errors
    /// Returns a stable unavailable implementation error. Partial catalogs are
    /// not valid results.
    fn current_snapshot(&self) -> Result<Arc<ModelCatalogSnapshot>, ModelCatalogError>;

    /// Returns the latest tenant-safe model projection.
    ///
    /// # Errors
    /// Returns the same stable state error as [`Self::current_snapshot`].
    fn tenant_catalog(
        &self,
        tenant_id: &TenantId,
    ) -> Result<TenantCatalogProjection, ModelCatalogError> {
        self.current_snapshot()
            .map(|snapshot| snapshot.project_for(tenant_id))
    }
}

/// Process-local atomic owner for complete immutable model-catalog snapshots.
///
/// Publication swaps one validated [`Arc`] while holding the write lock, so
/// readers observe either the complete previous snapshot or the complete next
/// snapshot. This owner does not claim persistence or cross-process ordering;
/// durable catalog storage remains an adapter responsibility.
pub struct AtomicModelCatalog {
    current: RwLock<Arc<ModelCatalogSnapshot>>,
}

impl AtomicModelCatalog {
    /// Creates a process-local owner from one complete initial snapshot.
    #[must_use]
    pub fn new(initial: ModelCatalogSnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
        }
    }

    /// Publishes the exact successor of the caller-observed version.
    ///
    /// # Errors
    /// Returns [`ModelCatalogErrorCode::Conflict`] when the observed version is
    /// stale or the proposed snapshot is not its exact successor. Returns
    /// [`ModelCatalogErrorCode::StateUnavailable`] when the publication lock is
    /// poisoned, and propagates version exhaustion without replacing the current
    /// snapshot.
    pub fn publish(
        &self,
        expected: CatalogVersion,
        next: ModelCatalogSnapshot,
    ) -> Result<Arc<ModelCatalogSnapshot>, ModelCatalogError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| error(ModelCatalogErrorCode::StateUnavailable))?;
        if current.version() != expected {
            return Err(error(ModelCatalogErrorCode::Conflict));
        }
        let required = current.version().next()?;
        if next.version() != required {
            return Err(error(ModelCatalogErrorCode::Conflict));
        }
        let published = Arc::new(next);
        *current = Arc::clone(&published);
        Ok(published)
    }
}

impl ModelCatalogPort for AtomicModelCatalog {
    fn current_snapshot(&self) -> Result<Arc<ModelCatalogSnapshot>, ModelCatalogError> {
        self.current
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| error(ModelCatalogErrorCode::StateUnavailable))
    }
}

fn ensure_unique_providers(descriptor: &ModelDescriptor) -> Result<(), ModelCatalogError> {
    let mut providers = BTreeSet::new();
    for mapping in descriptor.mappings() {
        if !providers.insert(mapping.provider()) {
            return Err(error(ModelCatalogErrorCode::AmbiguousProvider));
        }
    }
    Ok(())
}

fn validate_domain_catalog(entries: &[CatalogEntry]) -> Result<(), ModelCatalogError> {
    ModelCatalog::new(entries.iter().map(|entry| entry.descriptor().clone()))
        .map(|_| ())
        .map_err(map_domain_error)
}

fn map_domain_error(value: ariadnion_model_domain::ModelDomainError) -> ModelCatalogError {
    let code = match value.code() {
        ModelDomainErrorCode::InvalidArgument => ModelCatalogErrorCode::InvalidArgument,
        ModelDomainErrorCode::LimitExceeded => ModelCatalogErrorCode::LimitExceeded,
        ModelDomainErrorCode::DuplicateModel
        | ModelDomainErrorCode::DuplicateAlias
        | ModelDomainErrorCode::DuplicateMapping => ModelCatalogErrorCode::Conflict,
        ModelDomainErrorCode::NotFound => ModelCatalogErrorCode::ModelNotFound,
        ModelDomainErrorCode::VersionExhausted => ModelCatalogErrorCode::VersionExhausted,
        _ => ModelCatalogErrorCode::Conflict,
    };
    error(code)
}

fn descriptor_matches(descriptor: &ModelDescriptor, selector: &str) -> bool {
    descriptor.id().as_str() == selector
        || descriptor
            .aliases()
            .iter()
            .any(|alias| alias.as_str() == selector)
}

const fn error(code: ModelCatalogErrorCode) -> ModelCatalogError {
    ModelCatalogError::new(code)
}

// crates/optional/ariadnion-model-domain/src/lib.rs - Model domain contracts for Ariadnion.
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
//! Immutable, provider-neutral model identities, capabilities, and lookup.
//!
//! The crate contains no persistence or network behavior. A [`ModelCatalog`] is
//! built once from validated descriptors and then shared as an immutable snapshot.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;

/// Maximum byte length of a model or provider identity.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum number of descriptors in one immutable catalog.
pub const MAX_MODELS: usize = 4_096;
/// Maximum aliases attached to one model descriptor.
pub const MAX_ALIASES_PER_MODEL: usize = 32;
/// Maximum provider mappings attached to one model descriptor.
pub const MAX_MAPPINGS_PER_MODEL: usize = 32;
/// Maximum capability count represented by the bitset.
pub const MAX_CAPABILITIES: usize = 32;
/// Maximum context-token limit accepted by the domain.
pub const MAX_CONTEXT_TOKENS: u32 = 1 << 21;
/// Maximum output-token limit accepted by the domain.
pub const MAX_OUTPUT_TOKENS: u32 = 1 << 20;
/// Maximum byte limit accepted for one request or response body.
pub const MAX_BODY_BYTES: u32 = 256 * 1024 * 1024;

/// Stable machine-readable failures returned by model-domain operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ModelDomainErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// A fixed collection bound would be exceeded.
    LimitExceeded,
    /// Two descriptors use the same canonical model identity.
    DuplicateModel,
    /// An alias is already owned by another model.
    DuplicateAlias,
    /// A provider mapping is duplicated.
    DuplicateMapping,
    /// A requested identity does not exist in the immutable catalog.
    NotFound,
    /// A monotonic model version cannot advance without wrapping.
    VersionExhausted,
}

impl ModelDomainErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "MODEL_INVALID_ARGUMENT",
            Self::LimitExceeded => "MODEL_LIMIT_EXCEEDED",
            Self::DuplicateModel => "MODEL_DUPLICATE_MODEL",
            Self::DuplicateAlias => "MODEL_DUPLICATE_ALIAS",
            Self::DuplicateMapping => "MODEL_DUPLICATE_MAPPING",
            Self::NotFound => "MODEL_NOT_FOUND",
            Self::VersionExhausted => "MODEL_VERSION_EXHAUSTED",
        }
    }
}

/// A redacted model-domain failure that retains no rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelDomainError {
    code: ModelDomainErrorCode,
}

impl ModelDomainError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: ModelDomainErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ModelDomainErrorCode {
        self.code
    }
}

impl Display for ModelDomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ModelDomainError {}

macro_rules! bounded_identity {
    ($name:ident, $doc:literal, $debug:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses a non-empty bounded ASCII identity.
            ///
            /// # Errors
            /// Returns [`ModelDomainErrorCode::InvalidArgument`] for empty,
            /// oversized, non-ASCII, or disallowed values.
            pub fn parse(value: &str) -> Result<Self, ModelDomainError> {
                if !valid_identity(value) {
                    return Err(error(ModelDomainErrorCode::InvalidArgument));
                }
                Ok(Self(value.into()))
            }

            /// Returns the validated identity.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($debug, "(<opaque>)"))
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
    };
}

bounded_identity!(
    ModelId,
    "A canonical provider-neutral model identity.",
    "ModelId"
);
bounded_identity!(
    ModelAlias,
    "A public alias resolving to a canonical model.",
    "ModelAlias"
);
bounded_identity!(
    ProviderId,
    "A provider identity used by a model mapping.",
    "ProviderId"
);
bounded_identity!(
    ProviderModelId,
    "A provider-side model identity.",
    "ProviderModelId"
);

/// Compatibility alias for callers that name the canonical identity explicitly.
pub type CanonicalModelId = ModelId;
/// Compatibility alias for callers that use provider-model naming terminology.
pub type ProviderModelName = ProviderModelId;

/// A non-zero immutable model descriptor version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelVersion(NonZeroU64);

impl ModelVersion {
    /// Returns the version assigned to a newly published descriptor.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero model version.
    ///
    /// # Errors
    /// Returns [`ModelDomainErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, ModelDomainError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(ModelDomainErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic version.
    ///
    /// # Errors
    /// Returns [`ModelDomainErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, ModelDomainError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(ModelDomainErrorCode::VersionExhausted))
    }
}

/// A model capability that can be tested without provider-specific strings.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ModelCapability {
    /// Text generation.
    TextGeneration,
    /// Incremental text generation.
    TextStreaming,
    /// Tool or function calls.
    ToolCalls,
    /// Structured output.
    StructuredOutput,
    /// Vision input.
    VisionInput,
    /// Audio input.
    AudioInput,
    /// Audio output.
    AudioOutput,
    /// Incremental audio output.
    AudioStreaming,
    /// Vector embeddings.
    Embeddings,
    /// Image generation.
    ImageGeneration,
    /// File operations.
    Files,
    /// Realtime sessions.
    Realtime,
    /// Batch operations.
    Batch,
    /// Reranking.
    Rerank,
    /// Content moderation.
    Moderation,
}

impl ModelCapability {
    const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

/// A deterministic set of model capabilities.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ModelCapabilities(u32);

impl ModelCapabilities {
    /// Creates a set containing one capability.
    #[must_use]
    pub const fn new(capability: ModelCapability) -> Self {
        Self(capability.bit())
    }

    /// Adds one capability and returns the updated set.
    #[must_use]
    pub const fn with(self, capability: ModelCapability) -> Self {
        Self(self.0 | capability.bit())
    }

    /// Returns whether the set contains a capability.
    #[must_use]
    pub const fn contains(self, capability: ModelCapability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Iterates capabilities in stable declaration order.
    pub fn iter(self) -> impl Iterator<Item = ModelCapability> {
        const ALL: [ModelCapability; 15] = [
            ModelCapability::TextGeneration,
            ModelCapability::TextStreaming,
            ModelCapability::ToolCalls,
            ModelCapability::StructuredOutput,
            ModelCapability::VisionInput,
            ModelCapability::AudioInput,
            ModelCapability::AudioOutput,
            ModelCapability::AudioStreaming,
            ModelCapability::Embeddings,
            ModelCapability::ImageGeneration,
            ModelCapability::Files,
            ModelCapability::Realtime,
            ModelCapability::Batch,
            ModelCapability::Rerank,
            ModelCapability::Moderation,
        ];
        ALL.into_iter()
            .filter(move |capability| self.contains(*capability))
    }
}

/// Bounded token and body limits advertised by a model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelLimits {
    context_tokens: Option<NonZeroU32>,
    output_tokens: Option<NonZeroU32>,
    input_bytes: Option<NonZeroU32>,
    output_bytes: Option<NonZeroU32>,
}

impl ModelLimits {
    /// Creates validated limits. `None` means the provider did not advertise a limit.
    ///
    /// # Errors
    /// Returns [`ModelDomainErrorCode::InvalidArgument`] for zero values and
    /// [`ModelDomainErrorCode::LimitExceeded`] for values above fixed bounds.
    pub fn new(
        context_tokens: Option<u32>,
        output_tokens: Option<u32>,
        input_bytes: Option<u32>,
        output_bytes: Option<u32>,
    ) -> Result<Self, ModelDomainError> {
        Ok(Self {
            context_tokens: checked_limit(context_tokens, MAX_CONTEXT_TOKENS)?,
            output_tokens: checked_limit(output_tokens, MAX_OUTPUT_TOKENS)?,
            input_bytes: checked_limit(input_bytes, MAX_BODY_BYTES)?,
            output_bytes: checked_limit(output_bytes, MAX_BODY_BYTES)?,
        })
    }

    /// Returns the optional context-token limit.
    #[must_use]
    pub const fn context_tokens(self) -> Option<NonZeroU32> {
        self.context_tokens
    }

    /// Returns the optional output-token limit.
    #[must_use]
    pub const fn output_tokens(self) -> Option<NonZeroU32> {
        self.output_tokens
    }

    /// Returns the optional input-body byte limit.
    #[must_use]
    pub const fn input_bytes(self) -> Option<NonZeroU32> {
        self.input_bytes
    }

    /// Returns the optional output-body byte limit.
    #[must_use]
    pub const fn output_bytes(self) -> Option<NonZeroU32> {
        self.output_bytes
    }
}

/// A provider-side mapping for one canonical model.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProviderModelMapping {
    provider: ProviderId,
    model: ProviderModelId,
    aliases: Arc<[ProviderModelId]>,
}

impl ProviderModelMapping {
    /// Creates a mapping without provider-side aliases.
    #[must_use]
    pub fn new(provider: ProviderId, model: ProviderModelId) -> Self {
        Self {
            provider,
            model,
            aliases: Arc::from([]),
        }
    }

    /// Creates a mapping with bounded provider-side aliases.
    ///
    /// # Errors
    /// Returns [`ModelDomainErrorCode::LimitExceeded`] when more than
    /// [`MAX_ALIASES_PER_MODEL`] aliases are supplied and
    /// [`ModelDomainErrorCode::DuplicateAlias`] for duplicate aliases.
    pub fn with_aliases<I>(
        provider: ProviderId,
        model: ProviderModelId,
        aliases: I,
    ) -> Result<Self, ModelDomainError>
    where
        I: IntoIterator<Item = ProviderModelId>,
    {
        let mut aliases = aliases.into_iter().collect::<Vec<_>>();
        if aliases.len() > MAX_ALIASES_PER_MODEL {
            return Err(error(ModelDomainErrorCode::LimitExceeded));
        }
        aliases.sort_unstable();
        if aliases.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(error(ModelDomainErrorCode::DuplicateAlias));
        }
        if aliases.iter().any(|alias| alias == &model) {
            return Err(error(ModelDomainErrorCode::DuplicateAlias));
        }
        Ok(Self {
            provider,
            model,
            aliases: Arc::from(aliases.into_boxed_slice()),
        })
    }

    /// Returns the provider identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the primary provider-side model identity.
    #[must_use]
    pub const fn model(&self) -> &ProviderModelId {
        &self.model
    }

    /// Returns the primary provider-side model identity.
    #[must_use]
    pub const fn provider_model(&self) -> &ProviderModelId {
        &self.model
    }

    /// Returns provider-side aliases in deterministic order.
    #[must_use]
    pub fn aliases(&self) -> &[ProviderModelId] {
        &self.aliases
    }

    fn matches(&self, model: &ProviderModelId) -> bool {
        &self.model == model || self.aliases.iter().any(|alias| alias == model)
    }
}

/// An immutable, versioned model capability descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelDescriptor {
    id: ModelId,
    version: ModelVersion,
    capabilities: ModelCapabilities,
    limits: ModelLimits,
    aliases: Arc<[ModelAlias]>,
    mappings: Arc<[ProviderModelMapping]>,
}

impl ModelDescriptor {
    /// Builds and freezes one validated model descriptor.
    ///
    /// Aliases and provider mappings are sorted deterministically. Duplicate
    /// aliases or duplicate provider/model pairs are rejected.
    pub fn new<I, J>(
        id: ModelId,
        version: ModelVersion,
        capabilities: ModelCapabilities,
        limits: ModelLimits,
        aliases: I,
        mappings: J,
    ) -> Result<Self, ModelDomainError>
    where
        I: IntoIterator<Item = ModelAlias>,
        J: IntoIterator<Item = ProviderModelMapping>,
    {
        let mut aliases = aliases.into_iter().collect::<Vec<_>>();
        if aliases.len() > MAX_ALIASES_PER_MODEL {
            return Err(error(ModelDomainErrorCode::LimitExceeded));
        }
        aliases.sort_unstable();
        if aliases.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(error(ModelDomainErrorCode::DuplicateAlias));
        }
        if aliases.iter().any(|alias| alias.as_str() == id.as_str()) {
            return Err(error(ModelDomainErrorCode::DuplicateAlias));
        }
        let mut mappings = mappings.into_iter().collect::<Vec<_>>();
        if mappings.len() > MAX_MAPPINGS_PER_MODEL {
            return Err(error(ModelDomainErrorCode::LimitExceeded));
        }
        mappings.sort_unstable_by(|left, right| {
            left.provider
                .cmp(&right.provider)
                .then_with(|| left.model.cmp(&right.model))
        });
        if mappings
            .windows(2)
            .any(|pair| pair[0].provider == pair[1].provider && pair[0].model == pair[1].model)
        {
            return Err(error(ModelDomainErrorCode::DuplicateMapping));
        }
        validate_mapping_conflicts(&mappings)?;
        Ok(Self {
            id,
            version,
            capabilities,
            limits,
            aliases: Arc::from(aliases.into_boxed_slice()),
            mappings: Arc::from(mappings.into_boxed_slice()),
        })
    }

    /// Returns the canonical model identity.
    #[must_use]
    pub const fn id(&self) -> &ModelId {
        &self.id
    }

    /// Returns the canonical model identity.
    #[must_use]
    pub const fn model_id(&self) -> &ModelId {
        &self.id
    }

    /// Returns the immutable descriptor version.
    #[must_use]
    pub const fn version(&self) -> ModelVersion {
        self.version
    }

    /// Returns the capability set.
    #[must_use]
    pub const fn capabilities(&self) -> ModelCapabilities {
        self.capabilities
    }

    /// Returns the advertised limits.
    #[must_use]
    pub const fn limits(&self) -> ModelLimits {
        self.limits
    }

    /// Returns public aliases in deterministic order.
    #[must_use]
    pub fn aliases(&self) -> &[ModelAlias] {
        &self.aliases
    }

    /// Returns provider mappings in deterministic order.
    #[must_use]
    pub fn mappings(&self) -> &[ProviderModelMapping] {
        &self.mappings
    }
}

/// An immutable, sorted model catalog with deterministic identity lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCatalog {
    models: Arc<[ModelDescriptor]>,
}

impl ModelCatalog {
    /// Validates and freezes model descriptors into a deterministic snapshot.
    ///
    /// Canonical IDs sort by bytes. Aliases must be unique across the catalog,
    /// and a provider-side mapping may belong to only one canonical model.
    pub fn new<I>(models: I) -> Result<Self, ModelDomainError>
    where
        I: IntoIterator<Item = ModelDescriptor>,
    {
        let mut models = models.into_iter().collect::<Vec<_>>();
        if models.len() > MAX_MODELS {
            return Err(error(ModelDomainErrorCode::LimitExceeded));
        }
        models.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        if models.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(error(ModelDomainErrorCode::DuplicateModel));
        }
        validate_catalog_conflicts(&models)?;
        Ok(Self {
            models: Arc::from(models.into_boxed_slice()),
        })
    }

    /// Returns all descriptors in canonical-ID order.
    #[must_use]
    pub fn models(&self) -> &[ModelDescriptor] {
        &self.models
    }

    /// Looks up a canonical model identity.
    #[must_use]
    pub fn get(&self, id: &ModelId) -> Option<&ModelDescriptor> {
        self.models
            .binary_search_by(|candidate| candidate.id.cmp(id))
            .ok()
            .map(|index| &self.models[index])
    }

    /// Resolves a canonical identity or public alias.
    ///
    /// # Errors
    /// Returns [`ModelDomainErrorCode::NotFound`] when the identity is absent.
    pub fn resolve(&self, value: &str) -> Result<&ModelDescriptor, ModelDomainError> {
        let id = ModelId::parse(value).map_err(|_| error(ModelDomainErrorCode::NotFound))?;
        if let Some(model) = self.get(&id) {
            return Ok(model);
        }
        self.models
            .iter()
            .find(|model| model.aliases.iter().any(|alias| alias.as_str() == value))
            .ok_or_else(|| error(ModelDomainErrorCode::NotFound))
    }

    /// Alias for [`Self::resolve`] using lookup terminology.
    pub fn lookup(&self, value: &str) -> Result<&ModelDescriptor, ModelDomainError> {
        self.resolve(value)
    }

    /// Resolves a provider-side model identity to its canonical descriptor.
    ///
    /// # Errors
    /// Returns [`ModelDomainErrorCode::NotFound`] when no mapping or alias matches.
    pub fn resolve_provider(
        &self,
        provider: &ProviderId,
        model: &ProviderModelId,
    ) -> Result<&ModelDescriptor, ModelDomainError> {
        self.models
            .iter()
            .find(|descriptor| {
                descriptor
                    .mappings
                    .iter()
                    .any(|mapping| mapping.provider == *provider && mapping.matches(model))
            })
            .ok_or_else(|| error(ModelDomainErrorCode::NotFound))
    }

    /// Alias for [`Self::resolve_provider`] using lookup terminology.
    pub fn lookup_provider(
        &self,
        provider: &ProviderId,
        model: &ProviderModelId,
    ) -> Result<&ModelDescriptor, ModelDomainError> {
        self.resolve_provider(provider, model)
    }
}

fn validate_catalog_conflicts(models: &[ModelDescriptor]) -> Result<(), ModelDomainError> {
    for (index, model) in models.iter().enumerate() {
        for other in models.iter().skip(index + 1) {
            if model_aliases_conflict(model, other) {
                return Err(error(ModelDomainErrorCode::DuplicateAlias));
            }
            if model_mappings_conflict(model, other) {
                return Err(error(ModelDomainErrorCode::DuplicateMapping));
            }
        }
    }
    Ok(())
}

fn model_aliases_conflict(left: &ModelDescriptor, right: &ModelDescriptor) -> bool {
    left.aliases.iter().any(|alias| {
        alias.as_str() == right.id.as_str() || right.aliases.iter().any(|other| other == alias)
    }) || right
        .aliases
        .iter()
        .any(|alias| alias.as_str() == left.id.as_str())
}

fn model_mappings_conflict(left: &ModelDescriptor, right: &ModelDescriptor) -> bool {
    left.mappings.iter().any(|mapping| {
        right
            .mappings
            .iter()
            .any(|other| mapping_conflicts(mapping, other))
    })
}

fn validate_mapping_conflicts(mappings: &[ProviderModelMapping]) -> Result<(), ModelDomainError> {
    for (index, mapping) in mappings.iter().enumerate() {
        if mappings
            .iter()
            .skip(index + 1)
            .any(|other| mapping_conflicts(mapping, other))
        {
            return Err(error(ModelDomainErrorCode::DuplicateMapping));
        }
    }
    Ok(())
}

fn mapping_conflicts(left: &ProviderModelMapping, right: &ProviderModelMapping) -> bool {
    left.provider == right.provider
        && mapping_names(left).any(|name| mapping_names(right).any(|other| name == other))
}

fn mapping_names(mapping: &ProviderModelMapping) -> impl Iterator<Item = &ProviderModelId> {
    std::iter::once(&mapping.model).chain(mapping.aliases.iter())
}

fn checked_limit(value: Option<u32>, maximum: u32) -> Result<Option<NonZeroU32>, ModelDomainError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    if raw == 0 {
        return Err(error(ModelDomainErrorCode::InvalidArgument));
    }
    if raw > maximum {
        return Err(error(ModelDomainErrorCode::LimitExceeded));
    }
    Ok(NonZeroU32::new(raw))
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

const fn error(code: ModelDomainErrorCode) -> ModelDomainError {
    ModelDomainError::new(code)
}

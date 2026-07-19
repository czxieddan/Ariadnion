//! Typed capability requirements, providers, and dependency resolution.

use std::fmt::{self, Display, Formatter};

use crate::error::{CoreError, ErrorCode};
use crate::ids::{CapabilityId, ModuleId, ModuleVersion};

const MAX_GRAPH_CAPABILITIES: usize = 256;

/// A bounded semantic version requirement for one capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRequirement {
    id: CapabilityId,
    minimum: ModuleVersion,
    maximum_major: Option<u16>,
}

/// Compatibility name for a capability semantic-version requirement.
pub type CapabilityVersionReq = CapabilityRequirement;

impl CapabilityRequirement {
    /// Creates a requirement with an inclusive minimum and optional major ceiling.
    #[must_use]
    pub const fn new(id: CapabilityId, minimum: ModuleVersion, maximum_major: Option<u16>) -> Self {
        Self {
            id,
            minimum,
            maximum_major,
        }
    }

    /// Returns the capability identity.
    #[must_use]
    pub const fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Returns the inclusive minimum version.
    #[must_use]
    pub const fn minimum(&self) -> ModuleVersion {
        self.minimum
    }

    /// Returns the optional maximum major version.
    #[must_use]
    pub const fn maximum_major(&self) -> Option<u16> {
        self.maximum_major
    }

    /// Returns whether a provider version satisfies this requirement.
    #[must_use]
    pub fn accepts(&self, version: ModuleVersion) -> bool {
        version >= self.minimum
            && self
                .maximum_major
                .is_none_or(|maximum| version.major() <= maximum)
    }
}

/// A capability implementation offered by a module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityProvider {
    id: CapabilityId,
    version: ModuleVersion,
    module_id: ModuleId,
}

impl CapabilityProvider {
    /// Creates a provider declaration.
    #[must_use]
    pub const fn new(id: CapabilityId, version: ModuleVersion, module_id: ModuleId) -> Self {
        Self {
            id,
            version,
            module_id,
        }
    }

    /// Returns the capability identity.
    #[must_use]
    pub const fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Returns the implementation version.
    #[must_use]
    pub const fn version(&self) -> ModuleVersion {
        self.version
    }

    /// Returns the providing module.
    #[must_use]
    pub const fn module_id(&self) -> &ModuleId {
        &self.module_id
    }
}

/// A resolved requirement-to-provider binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityBinding {
    requirement: CapabilityRequirement,
    provider: CapabilityProvider,
}

impl CapabilityBinding {
    /// Returns the original requirement.
    #[must_use]
    pub const fn requirement(&self) -> &CapabilityRequirement {
        &self.requirement
    }

    /// Returns the selected provider.
    #[must_use]
    pub const fn provider(&self) -> &CapabilityProvider {
        &self.provider
    }
}

/// A bounded resolution result with deterministic provider ordering.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityResolution {
    bindings: Vec<CapabilityBinding>,
}

impl CapabilityResolution {
    /// Returns all selected bindings.
    #[must_use]
    pub fn bindings(&self) -> &[CapabilityBinding] {
        &self.bindings
    }

    /// Returns the provider selected for a requirement identity.
    #[must_use]
    pub fn provider_for(&self, id: &CapabilityId) -> Option<&CapabilityProvider> {
        self.bindings
            .iter()
            .find(|binding| binding.requirement.id() == id)
            .map(|binding| binding.provider())
    }
}

/// A deterministic capability graph used during startup validation.
#[derive(Clone, Debug, Default)]
pub struct CapabilityGraph {
    providers: Vec<CapabilityProvider>,
}

impl CapabilityGraph {
    /// Creates an empty graph.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Registers one provider and rejects duplicate identities.
    ///
    /// Returns [`ErrorCode::ResourceExhausted`] before growing the graph when
    /// the 256-provider limit has been reached.
    pub fn register(&mut self, provider: CapabilityProvider) -> Result<(), CoreError> {
        self.register_batch(std::slice::from_ref(&provider))
    }

    /// Atomically registers a bounded provider batch.
    ///
    /// Capacity, existing-provider conflicts, and duplicate identities within
    /// the batch are preflighted before the graph changes. Any error therefore
    /// leaves every previously registered provider unchanged and exposes none
    /// of the rejected batch.
    pub fn register_batch(&mut self, providers: &[CapabilityProvider]) -> Result<(), CoreError> {
        validate_batch_capacity(self.providers.len(), providers.len())?;
        if has_existing_provider(&self.providers, providers) || has_batch_duplicate(providers) {
            return Err(CoreError::from_code(ErrorCode::Conflict)
                .with_internal_context("duplicate capability provider"));
        }
        self.providers.extend_from_slice(providers);
        Ok(())
    }

    /// Resolves all requirements against registered providers.
    ///
    /// Returns [`ErrorCode::ResourceExhausted`] before allocating bindings when
    /// more than 256 requirements are supplied.
    pub fn resolve(
        &self,
        requirements: &[CapabilityRequirement],
    ) -> Result<CapabilityResolution, CoreError> {
        if requirements.len() > MAX_GRAPH_CAPABILITIES {
            return Err(CoreError::from_code(ErrorCode::ResourceExhausted)
                .with_internal_context("capability resolution limit reached"));
        }
        let mut bindings = Vec::with_capacity(requirements.len());
        for requirement in requirements {
            let provider = self
                .providers
                .iter()
                .find(|candidate| candidate.id() == requirement.id())
                .ok_or_else(|| {
                    CoreError::from_code(ErrorCode::Unavailable)
                        .with_internal_context("required capability is missing")
                })?;
            if !requirement.accepts(provider.version()) {
                return Err(CoreError::from_code(ErrorCode::Conflict)
                    .with_internal_context("capability version is incompatible"));
            }
            bindings.push(CapabilityBinding {
                requirement: requirement.clone(),
                provider: provider.clone(),
            });
        }
        Ok(CapabilityResolution { bindings })
    }

    /// Returns all registered providers in registration order.
    #[must_use]
    pub fn providers(&self) -> &[CapabilityProvider] {
        &self.providers
    }
}

fn validate_batch_capacity(current: usize, incoming: usize) -> Result<(), CoreError> {
    if incoming > MAX_GRAPH_CAPABILITIES.saturating_sub(current) {
        return Err(CoreError::from_code(ErrorCode::ResourceExhausted)
            .with_internal_context("capability provider limit reached"));
    }
    Ok(())
}

fn has_existing_provider(
    existing: &[CapabilityProvider],
    incoming: &[CapabilityProvider],
) -> bool {
    incoming.iter().any(|candidate| {
        existing
            .iter()
            .any(|registered| registered.id() == candidate.id())
    })
}

fn has_batch_duplicate(providers: &[CapabilityProvider]) -> bool {
    providers.iter().enumerate().any(|(index, candidate)| {
        providers
            .iter()
            .skip(index.saturating_add(1))
            .any(|other| other.id() == candidate.id())
    })
}

impl Display for CapabilityRequirement {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self.maximum_major {
            Some(maximum) => write!(
                formatter,
                "{} >= {} <= major {}",
                self.id, self.minimum, maximum
            ),
            None => write!(formatter, "{} >= {}", self.id, self.minimum),
        }
    }
}

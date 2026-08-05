// crates/optional/ariadnion-provider-sdk/src/contract.rs - Provider capability contracts for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Bounded provider identity, capability, and resource contracts.

use std::fmt::{self, Debug, Display, Formatter};

const MAX_PROVIDER_ID_BYTES: usize = 256;
const MAX_PROVIDER_MODEL_ID_BYTES: usize = 256;
/// The hard upper bound for one provider request payload.
pub const MAX_PROVIDER_REQUEST_BYTES: usize = 16_777_216;
/// The hard upper bound for one provider stream delta.
pub const MAX_PROVIDER_DELTA_BYTES: usize = 65_536;
/// The hard upper bound for aggregate provider stream text.
pub const MAX_PROVIDER_STREAM_BYTES: usize = 16_777_216;
/// The hard upper bound for provider stream events in one attempt.
pub const MAX_PROVIDER_STREAM_EVENTS: usize = 262_144;

/// Stable construction failures for provider contracts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderContractErrorCode {
    /// The value is empty or has invalid syntax.
    InvalidArgument,
    /// The value exceeds a fixed byte or count bound.
    LimitExceeded,
    /// Capabilities or limits are mutually inconsistent.
    CapabilityConflict,
}

impl ProviderContractErrorCode {
    /// Returns the stable machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "provider_invalid_argument",
            Self::LimitExceeded => "provider_limit_exceeded",
            Self::CapabilityConflict => "provider_capability_conflict",
        }
    }
}

/// A redacted provider contract construction error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderContractError {
    code: ProviderContractErrorCode,
}

impl ProviderContractError {
    pub(crate) const fn new(code: ProviderContractErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable error code.
    #[must_use]
    pub const fn code(self) -> ProviderContractErrorCode {
        self.code
    }
}

impl Display for ProviderContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ProviderContractError {}

/// A provider-neutral capability supported by an adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum ProviderCapability {
    /// Text generation is available.
    TextGeneration = 0,
    /// Incremental text streaming is available.
    TextStreaming = 1,
    /// Tool calls are available.
    ToolCalls = 2,
    /// Structured output is available.
    StructuredOutput = 3,
    /// Vision input is available.
    VisionInput = 4,
    /// Audio input is available.
    AudioInput = 5,
    /// Audio output is available.
    AudioOutput = 6,
    /// Embeddings are available.
    Embeddings = 7,
    /// File inputs or outputs are available.
    Files = 8,
    /// Realtime sessions are available.
    Realtime = 9,
    /// Batch requests are available.
    Batch = 10,
}

impl ProviderCapability {
    const fn bit(self) -> u16 {
        1_u16 << (self as u8)
    }
}

/// A compact deterministic set of provider capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCapabilities(u16);

impl ProviderCapabilities {
    /// Creates a set containing one capability.
    #[must_use]
    pub const fn new(capability: ProviderCapability) -> Self {
        Self(capability.bit())
    }

    /// Adds one capability and returns the updated set.
    #[must_use]
    pub const fn with(self, capability: ProviderCapability) -> Self {
        Self(self.0 | capability.bit())
    }

    /// Returns whether the set contains a capability.
    #[must_use]
    pub const fn contains(self, capability: ProviderCapability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Returns whether no capability is present.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// A bounded provider identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(Box<str>);

impl ProviderId {
    /// Validates and copies a provider identifier.
    ///
    /// Empty, non-ASCII, whitespace, control, or overlong values are rejected
    /// without retaining the rejected value.
    pub fn new(value: &str) -> Result<Self, ProviderContractError> {
        validate_identifier(value, MAX_PROVIDER_ID_BYTES).map(|()| Self(value.into()))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ProviderId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderId")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A bounded provider-specific model identifier carried by a neutral attempt.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderModelId(Box<str>);

impl ProviderModelId {
    /// Validates and copies a provider model identifier.
    pub fn new(value: &str) -> Result<Self, ProviderContractError> {
        validate_identifier(value, MAX_PROVIDER_MODEL_ID_BYTES).map(|()| Self(value.into()))
    }

    /// Returns the validated model identifier to a trusted adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ProviderModelId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderModelId")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Checked hard limits for one provider descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLimits {
    max_request_bytes: usize,
    max_delta_bytes: usize,
    max_stream_bytes: usize,
    max_stream_events: usize,
}

impl ProviderLimits {
    /// Creates limits within the SDK hard bounds.
    pub const fn new(
        max_request_bytes: usize,
        max_delta_bytes: usize,
        max_stream_bytes: usize,
        max_stream_events: usize,
    ) -> Result<Self, ProviderContractError> {
        if let Err(error) =
            validate_required_sizes(max_request_bytes, max_delta_bytes, max_stream_bytes)
        {
            return Err(error);
        }
        if let Err(error) = validate_hard_limits(
            max_request_bytes,
            max_delta_bytes,
            max_stream_bytes,
            max_stream_events,
        ) {
            return Err(error);
        }
        Ok(Self {
            max_request_bytes,
            max_delta_bytes,
            max_stream_bytes,
            max_stream_events,
        })
    }

    /// Returns the maximum request size.
    #[must_use]
    pub const fn max_request_bytes(self) -> usize {
        self.max_request_bytes
    }

    /// Returns the maximum one-delta size.
    #[must_use]
    pub const fn max_delta_bytes(self) -> usize {
        self.max_delta_bytes
    }

    /// Returns the maximum aggregate stream size.
    #[must_use]
    pub const fn max_stream_bytes(self) -> usize {
        self.max_stream_bytes
    }

    /// Returns the maximum stream event count.
    #[must_use]
    pub const fn max_stream_events(self) -> usize {
        self.max_stream_events
    }
}

const fn validate_required_sizes(
    max_request_bytes: usize,
    max_delta_bytes: usize,
    max_stream_bytes: usize,
) -> Result<(), ProviderContractError> {
    if max_request_bytes == 0 || max_delta_bytes == 0 || max_stream_bytes == 0 {
        return Err(ProviderContractError::new(
            ProviderContractErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

const fn validate_hard_limits(
    max_request_bytes: usize,
    max_delta_bytes: usize,
    max_stream_bytes: usize,
    max_stream_events: usize,
) -> Result<(), ProviderContractError> {
    if max_request_bytes > MAX_PROVIDER_REQUEST_BYTES
        || max_delta_bytes > MAX_PROVIDER_DELTA_BYTES
        || max_stream_bytes > MAX_PROVIDER_STREAM_BYTES
        || max_stream_events == 0
        || max_stream_events > MAX_PROVIDER_STREAM_EVENTS
    {
        return Err(ProviderContractError::new(
            ProviderContractErrorCode::LimitExceeded,
        ));
    }
    Ok(())
}

impl Default for ProviderLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: MAX_PROVIDER_REQUEST_BYTES,
            max_delta_bytes: MAX_PROVIDER_DELTA_BYTES,
            max_stream_bytes: MAX_PROVIDER_STREAM_BYTES,
            max_stream_events: MAX_PROVIDER_STREAM_EVENTS,
        }
    }
}

/// Immutable provider metadata used during capability negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderDescriptor {
    id: ProviderId,
    capabilities: ProviderCapabilities,
    limits: ProviderLimits,
}

impl ProviderDescriptor {
    /// Creates a descriptor with the SDK default hard limits.
    pub fn new(
        id: ProviderId,
        capabilities: ProviderCapabilities,
    ) -> Result<Self, ProviderContractError> {
        Self::with_limits(id, capabilities, ProviderLimits::default())
    }

    /// Creates a descriptor with checked provider-neutral limits.
    pub fn with_limits(
        id: ProviderId,
        capabilities: ProviderCapabilities,
        limits: ProviderLimits,
    ) -> Result<Self, ProviderContractError> {
        validate_capabilities(capabilities)?;
        Ok(Self {
            id,
            capabilities,
            limits,
        })
    }

    /// Returns the provider identity.
    #[must_use]
    pub const fn id(&self) -> &ProviderId {
        &self.id
    }

    /// Returns the advertised capability set.
    #[must_use]
    pub const fn capabilities(&self) -> ProviderCapabilities {
        self.capabilities
    }

    /// Returns the checked resource limits.
    #[must_use]
    pub const fn limits(&self) -> ProviderLimits {
        self.limits
    }
}

fn validate_identifier(value: &str, limit: usize) -> Result<(), ProviderContractError> {
    if value.is_empty() || !value.is_ascii() || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ProviderContractError::new(
            ProviderContractErrorCode::InvalidArgument,
        ));
    }
    if value.len() > limit {
        return Err(ProviderContractError::new(
            ProviderContractErrorCode::LimitExceeded,
        ));
    }
    Ok(())
}

fn validate_capabilities(capabilities: ProviderCapabilities) -> Result<(), ProviderContractError> {
    if capabilities.is_empty() {
        return Err(ProviderContractError::new(
            ProviderContractErrorCode::InvalidArgument,
        ));
    }
    if capabilities.contains(ProviderCapability::TextStreaming)
        && !capabilities.contains(ProviderCapability::TextGeneration)
    {
        return Err(ProviderContractError::new(
            ProviderContractErrorCode::CapabilityConflict,
        ));
    }
    Ok(())
}

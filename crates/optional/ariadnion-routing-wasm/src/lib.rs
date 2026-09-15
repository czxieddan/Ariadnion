// crates/optional/ariadnion-routing-wasm/src/lib.rs - Routing WASM boundary for Ariadnion.
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
//! Runtime-neutral, capability-safe routing WASM contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::time::Duration;

use ariadnion_core::{CoreError, WasmBudget, WasmBudgetInput};

/// Maximum candidate records accepted by one component invocation.
pub const MAX_CANDIDATES: usize = 1 << 12;
/// Maximum feature values carried by one candidate.
pub const MAX_FEATURES_PER_CANDIDATE: usize = 1 << 6;
/// Maximum component name or candidate identifier length in bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 1 << 8;

/// Stable failure observed at the WASM capability boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoutingWasmErrorCode {
    /// The capability is disabled or not installed.
    Unavailable,
    /// The component exceeded its declared epoch deadline.
    Timeout,
    /// The runtime trapped while invoking the component.
    Trap,
    /// The component returned an unknown or inconsistent candidate result.
    InvalidOutput,
    /// The invocation exceeded a bounded input or output resource.
    ResourceExhausted,
    /// The supplied contract value is malformed.
    InvalidArgument,
}

impl RoutingWasmErrorCode {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "ROUTING_WASM_UNAVAILABLE",
            Self::Timeout => "ROUTING_WASM_TIMEOUT",
            Self::Trap => "ROUTING_WASM_TRAP",
            Self::InvalidOutput => "ROUTING_WASM_INVALID_OUTPUT",
            Self::ResourceExhausted => "ROUTING_WASM_RESOURCE_EXHAUSTED",
            Self::InvalidArgument => "ROUTING_WASM_INVALID_ARGUMENT",
        }
    }
}

impl Display for RoutingWasmErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted routing WASM boundary failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RoutingWasmError(RoutingWasmErrorCode);

impl RoutingWasmError {
    /// Creates a failure with the supplied stable code.
    #[must_use]
    pub const fn new(code: RoutingWasmErrorCode) -> Self {
        Self(code)
    }

    /// Returns the stable failure code.
    #[must_use]
    pub const fn code(self) -> RoutingWasmErrorCode {
        self.0
    }
}

impl Display for RoutingWasmError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl std::error::Error for RoutingWasmError {}

impl From<CoreError> for RoutingWasmError {
    fn from(_: CoreError) -> Self {
        Self::new(RoutingWasmErrorCode::InvalidArgument)
    }
}

/// Explicit host capabilities visible to a routing component.
///
/// All ambient capabilities are permanently disabled by this contract. A
/// future runtime may add a capability only through a new ABI version and an
/// explicit security review; the current descriptor cannot express host access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCapabilities {
    /// Filesystem access is always denied.
    pub filesystem: bool,
    /// Network access is always denied.
    pub network: bool,
    /// Clock access is always denied.
    pub clock: bool,
    /// Randomness access is always denied.
    pub randomness: bool,
    /// Secret or credential access is always denied.
    pub secrets: bool,
}

impl HostCapabilities {
    /// Returns the only capability set accepted by the current ABI.
    #[must_use]
    pub const fn isolated() -> Self {
        Self {
            filesystem: false,
            network: false,
            clock: false,
            randomness: false,
            secrets: false,
        }
    }
}

/// Validated resource and host policy for one routing component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingWasmPolicy {
    budget: WasmBudget,
    host: HostCapabilities,
}

impl RoutingWasmPolicy {
    /// Validates an isolated component execution policy.
    ///
    /// A zero fuel, memory, or epoch value is rejected by the core budget
    /// validator. Host capabilities must equal [`HostCapabilities::isolated`].
    pub fn new(
        fuel: u64,
        max_memory_bytes: u64,
        epoch_timeout: Duration,
        host: HostCapabilities,
    ) -> Result<Self, RoutingWasmError> {
        if host != HostCapabilities::isolated() {
            return Err(error(RoutingWasmErrorCode::InvalidArgument));
        }
        let budget = WasmBudget::limited(WasmBudgetInput {
            fuel,
            max_memory_bytes,
            epoch_timeout,
        })
        .map_err(|_| error(RoutingWasmErrorCode::InvalidArgument))?;
        Ok(Self { budget, host })
    }

    /// Returns the validated core WASM budget.
    #[must_use]
    pub const fn budget(self) -> WasmBudget {
        self.budget
    }

    /// Returns the permanently isolated host capability set.
    #[must_use]
    pub const fn host(self) -> HostCapabilities {
        self.host
    }
}

/// Stable descriptor for one independently loaded routing component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingWasmModuleDescriptor {
    name: Box<str>,
    version: Box<str>,
    abi_version: u16,
    policy: RoutingWasmPolicy,
}

impl RoutingWasmModuleDescriptor {
    /// Creates a descriptor with explicit identity, ABI, and resource policy.
    pub fn new(
        name: &str,
        version: &str,
        abi_version: u16,
        policy: RoutingWasmPolicy,
    ) -> Result<Self, RoutingWasmError> {
        validate_identifier(name)?;
        validate_identifier(version)?;
        if abi_version == 0 {
            return Err(error(RoutingWasmErrorCode::InvalidArgument));
        }
        Ok(Self {
            name: name.into(),
            version: version.into(),
            abi_version,
            policy,
        })
    }

    /// Returns the module name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the module version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the stable component ABI version.
    #[must_use]
    pub const fn abi_version(&self) -> u16 {
        self.abi_version
    }

    /// Returns the resource and host policy.
    #[must_use]
    pub const fn policy(&self) -> RoutingWasmPolicy {
        self.policy
    }
}

/// One bounded deterministic feature vector for a candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateFeatures {
    candidate_id: Box<str>,
    values: Box<[i64]>,
}

impl CandidateFeatures {
    /// Creates a candidate feature vector.
    pub fn new<I>(candidate_id: &str, values: I) -> Result<Self, RoutingWasmError>
    where
        I: IntoIterator<Item = i64>,
    {
        validate_identifier(candidate_id)?;
        let values: Vec<i64> = values.into_iter().collect();
        if values.len() > MAX_FEATURES_PER_CANDIDATE {
            return Err(error(RoutingWasmErrorCode::ResourceExhausted));
        }
        Ok(Self {
            candidate_id: candidate_id.into(),
            values: values.into_boxed_slice(),
        })
    }

    /// Returns the stable candidate identifier.
    #[must_use]
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    /// Returns the immutable feature values in caller-defined order.
    #[must_use]
    pub fn values(&self) -> &[i64] {
        &self.values
    }
}

/// Deterministic, bounded input passed to a routing component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingWasmInput {
    candidates: Box<[CandidateFeatures]>,
}

impl RoutingWasmInput {
    /// Creates an input after checking count and duplicate ordering invariants.
    pub fn new<I>(candidates: I) -> Result<Self, RoutingWasmError>
    where
        I: IntoIterator<Item = CandidateFeatures>,
    {
        let candidates: Vec<CandidateFeatures> = candidates.into_iter().collect();
        if candidates.is_empty() || candidates.len() > MAX_CANDIDATES {
            return Err(error(RoutingWasmErrorCode::InvalidArgument));
        }
        if candidates
            .windows(2)
            .any(|pair| pair[0].candidate_id() >= pair[1].candidate_id())
        {
            return Err(error(RoutingWasmErrorCode::InvalidArgument));
        }
        Ok(Self {
            candidates: candidates.into_boxed_slice(),
        })
    }

    /// Returns candidates in deterministic ascending identifier order.
    #[must_use]
    pub fn candidates(&self) -> &[CandidateFeatures] {
        &self.candidates
    }
}

/// A component's only permitted routing result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutingWasmOutput {
    /// Selects one candidate already present in the input.
    Select(Box<str>),
    /// Declines to select; the native policy decides the next step.
    Decline,
}

/// Execution outcome including explicit fail-closed degradation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingWasmDegradation {
    /// No component capability was installed.
    Unavailable,
    /// The invocation exceeded the epoch deadline.
    Timeout,
    /// The runtime trapped.
    Trap,
    /// The component output failed validation.
    InvalidOutput,
}

/// Validated result of one component invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutingWasmResult {
    /// A validated component output.
    Applied(RoutingWasmOutput),
    /// The component was not used and native routing must apply degradation.
    Degraded(RoutingWasmDegradation),
}

/// Runtime-neutral invocation port for a routing WASM component.
pub trait RoutingWasmEvaluator: Send + Sync {
    /// Evaluates one bounded deterministic input.
    ///
    /// Implementations must enforce the descriptor's fuel, memory, and epoch
    /// policy. They must not expose WASI or ambient host capabilities.
    fn evaluate(&self, input: &RoutingWasmInput) -> Result<RoutingWasmResult, RoutingWasmError>;
}

/// Validates a component output against its exact input candidate set.
pub fn validate_output(
    input: &RoutingWasmInput,
    output: RoutingWasmOutput,
) -> Result<RoutingWasmOutput, RoutingWasmError> {
    if let RoutingWasmOutput::Select(candidate) = &output
        && !input
            .candidates()
            .iter()
            .any(|entry| entry.candidate_id() == candidate.as_ref())
    {
        return Err(error(RoutingWasmErrorCode::InvalidOutput));
    }
    Ok(output)
}

fn validate_identifier(value: &str) -> Result<(), RoutingWasmError> {
    if identifier_shape_invalid(value) {
        return Err(error(RoutingWasmErrorCode::InvalidArgument));
    }
    if identifier_contains_forbidden_byte(value) {
        return Err(error(RoutingWasmErrorCode::InvalidArgument));
    }
    Ok(())
}

fn identifier_shape_invalid(value: &str) -> bool {
    value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || !value.is_ascii()
}

fn identifier_contains_forbidden_byte(value: &str) -> bool {
    value.bytes().any(is_forbidden_identifier_byte)
}

fn is_forbidden_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_control() || byte == b'/' || byte == b'\\'
}

const fn error(code: RoutingWasmErrorCode) -> RoutingWasmError {
    RoutingWasmError::new(code)
}

// crates/optional/ariadnion-routing-domain/src/lib.rs - Routing domain contracts for Ariadnion.
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
//! Immutable routing contexts, candidate snapshots, and explainable decisions.
//!
//! This crate contains only transport-neutral domain contracts. Snapshot
//! construction is deterministic and bounded; selection algorithms remain in
//! policy crates, while adapters own persistence, health probes, and scheduling.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_account_domain::{AccountId, ProviderId};
use ariadnion_core::{CapabilityId, RequestId, TenantId};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU64;

/// Maximum number of candidates retained in one immutable snapshot.
pub const MAX_CANDIDATES: usize = 4_096;
/// Maximum byte length of a candidate key.
pub const MAX_CANDIDATE_KEY_BYTES: usize = 128;
/// Maximum byte length of a model selector.
pub const MAX_MODEL_BYTES: usize = 160;
/// Maximum number of required capabilities in one routing context.
pub const MAX_REQUIRED_CAPABILITIES: usize = 64;

/// Stable machine-readable failures returned by routing-domain contracts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RoutingDomainErrorCode {
    /// An input is empty, malformed, or exceeds its bound.
    InvalidArgument,
    /// A snapshot must contain at least one candidate.
    EmptySnapshot,
    /// A snapshot or capability list exceeded its bounded size.
    TooManyEntries,
    /// A candidate key appeared more than once in one snapshot.
    DuplicateCandidateId,
    /// A monotonic snapshot version cannot advance.
    SnapshotVersionExhausted,
    /// A selected candidate is absent from the referenced snapshot.
    CandidateNotFound,
    /// A decision was evaluated against a different snapshot version.
    SnapshotVersionMismatch,
    /// A decision selected a candidate for a different model.
    ModelMismatch,
    /// A required capability appeared more than once.
    DuplicateCapability,
}

impl RoutingDomainErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ROUTING_INVALID_ARGUMENT",
            Self::EmptySnapshot => "ROUTING_EMPTY_SNAPSHOT",
            Self::TooManyEntries => "ROUTING_TOO_MANY_ENTRIES",
            Self::DuplicateCandidateId => "ROUTING_DUPLICATE_CANDIDATE_ID",
            Self::SnapshotVersionExhausted => "ROUTING_SNAPSHOT_VERSION_EXHAUSTED",
            Self::CandidateNotFound => "ROUTING_CANDIDATE_NOT_FOUND",
            Self::SnapshotVersionMismatch => "ROUTING_SNAPSHOT_VERSION_MISMATCH",
            Self::ModelMismatch => "ROUTING_MODEL_MISMATCH",
            Self::DuplicateCapability => "ROUTING_DUPLICATE_CAPABILITY",
        }
    }
}

/// A redacted routing-domain error containing only its stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingDomainError {
    code: RoutingDomainErrorCode,
}

impl RoutingDomainError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: RoutingDomainErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> RoutingDomainErrorCode {
        self.code
    }
}

impl Display for RoutingDomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for RoutingDomainError {}

/// A bounded provider-model selector used by routing contexts and candidates.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteModel(Box<str>);

impl RouteModel {
    /// Parses a visible ASCII model selector.
    ///
    /// # Errors
    /// Returns [`RoutingDomainErrorCode::InvalidArgument`] when the selector is
    /// empty, overlong, non-ASCII, or contains a control byte.
    pub fn parse(value: &str) -> Result<Self, RoutingDomainError> {
        if value.is_empty()
            || value.len() > MAX_MODEL_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(error(RoutingDomainErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated selector.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RouteModel {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RouteModel").field(&self.0).finish()
    }
}

impl Display for RouteModel {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A stable bounded key for one candidate in a routing snapshot.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateKey(Box<str>);

impl CandidateKey {
    /// Parses a non-empty ASCII candidate key.
    ///
    /// # Errors
    /// Returns [`RoutingDomainErrorCode::InvalidArgument`] when the key is
    /// empty, overlong, non-ASCII, or contains a control byte.
    pub fn parse(value: &str) -> Result<Self, RoutingDomainError> {
        if value.is_empty()
            || value.len() > MAX_CANDIDATE_KEY_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(error(RoutingDomainErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for CandidateKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CandidateKey")
            .field(&self.0)
            .finish()
    }
}

impl Display for CandidateKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A candidate reference without health, quota, or credential material.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CandidateRef {
    key: CandidateKey,
    account_id: AccountId,
    provider_id: ProviderId,
    model: RouteModel,
}

impl CandidateRef {
    /// Creates a candidate reference from bounded domain identities.
    ///
    /// # Errors
    /// Returns [`RoutingDomainErrorCode::InvalidArgument`] when `key` is not a
    /// valid bounded candidate key.
    pub fn new(
        key: &str,
        account_id: AccountId,
        provider_id: ProviderId,
        model: RouteModel,
    ) -> Result<Self, RoutingDomainError> {
        Ok(Self {
            key: CandidateKey::parse(key)?,
            account_id,
            provider_id,
            model,
        })
    }

    /// Returns the stable candidate key.
    #[must_use]
    pub const fn key(&self) -> &CandidateKey {
        &self.key
    }

    /// Returns the account identity represented by this candidate.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the provider identity represented by this candidate.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the provider-model selector.
    #[must_use]
    pub const fn model(&self) -> &RouteModel {
        &self.model
    }
}

impl Debug for CandidateRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateRef")
            .field("key", &self.key)
            .field("account_id", &"<opaque>")
            .field("provider_id", &"<opaque>")
            .field("model", &self.model)
            .finish()
    }
}

/// A monotonic immutable routing-snapshot version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteSnapshotVersion(NonZeroU64);

impl RouteSnapshotVersion {
    /// Returns the first snapshot version.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero snapshot version.
    ///
    /// # Errors
    /// Returns [`RoutingDomainErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, RoutingDomainError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(RoutingDomainErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Advances the version without wrapping.
    ///
    /// # Errors
    /// Returns [`RoutingDomainErrorCode::SnapshotVersionExhausted`] at
    /// `u64::MAX`.
    pub fn next(self) -> Result<Self, RoutingDomainError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(RoutingDomainErrorCode::SnapshotVersionExhausted))
    }
}

/// An immutable, duplicate-free set of routable candidate references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSnapshot {
    version: RouteSnapshotVersion,
    candidates: Vec<CandidateRef>,
}

impl RouteSnapshot {
    /// Validates and creates an immutable candidate snapshot.
    ///
    /// # Errors
    /// Returns a stable error for an empty, oversized, or duplicate-key input.
    pub fn new(
        version: RouteSnapshotVersion,
        candidates: Vec<CandidateRef>,
    ) -> Result<Self, RoutingDomainError> {
        validate_snapshot_size(candidates.len())?;
        let mut keys = BTreeSet::new();
        for candidate in &candidates {
            if !keys.insert(candidate.key().clone()) {
                return Err(error(RoutingDomainErrorCode::DuplicateCandidateId));
            }
        }
        Ok(Self {
            version,
            candidates,
        })
    }

    /// Returns the immutable snapshot version.
    #[must_use]
    pub const fn version(&self) -> RouteSnapshotVersion {
        self.version
    }

    /// Returns candidates in their supplied deterministic order.
    #[must_use]
    pub fn candidates(&self) -> &[CandidateRef] {
        &self.candidates
    }

    /// Finds a candidate by stable key.
    #[must_use]
    pub fn candidate(&self, key: &CandidateKey) -> Option<&CandidateRef> {
        self.candidates
            .iter()
            .find(|candidate| candidate.key() == key)
    }
}

fn validate_snapshot_size(size: usize) -> Result<(), RoutingDomainError> {
    if size == 0 {
        return Err(error(RoutingDomainErrorCode::EmptySnapshot));
    }
    if size > MAX_CANDIDATES {
        return Err(error(RoutingDomainErrorCode::TooManyEntries));
    }
    Ok(())
}

/// Request-scoped routing input independent of transport and persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingContext {
    tenant_id: TenantId,
    request_id: RequestId,
    model: RouteModel,
    required_capabilities: Vec<CapabilityId>,
}

impl RoutingContext {
    /// Creates a context with no additional capability requirements.
    #[must_use]
    pub const fn new(tenant_id: TenantId, request_id: RequestId, model: RouteModel) -> Self {
        Self {
            tenant_id,
            request_id,
            model,
            required_capabilities: Vec::new(),
        }
    }

    /// Adds a bounded, duplicate-free capability requirement list.
    ///
    /// # Errors
    /// Returns a stable error when the list is oversized or contains a duplicate.
    pub fn with_capabilities(
        mut self,
        capabilities: Vec<CapabilityId>,
    ) -> Result<Self, RoutingDomainError> {
        if capabilities.len() > MAX_REQUIRED_CAPABILITIES {
            return Err(error(RoutingDomainErrorCode::TooManyEntries));
        }
        let mut seen = BTreeSet::new();
        for capability in &capabilities {
            if !seen.insert(capability.clone()) {
                return Err(error(RoutingDomainErrorCode::DuplicateCapability));
            }
        }
        self.required_capabilities = capabilities;
        Ok(self)
    }

    /// Returns the tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the request correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the requested model selector.
    #[must_use]
    pub const fn model(&self) -> &RouteModel {
        &self.model
    }

    /// Returns the required capability identifiers in caller order.
    #[must_use]
    pub fn required_capabilities(&self) -> &[CapabilityId] {
        &self.required_capabilities
    }
}

/// A selected candidate bound to the snapshot that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecision {
    snapshot_version: RouteSnapshotVersion,
    selected: CandidateKey,
}

impl RouteDecision {
    /// Creates a decision with a validated candidate key.
    ///
    /// # Errors
    /// Returns [`RoutingDomainErrorCode::InvalidArgument`] for an invalid key.
    pub fn new(
        snapshot_version: RouteSnapshotVersion,
        selected: CandidateKey,
    ) -> Result<Self, RoutingDomainError> {
        if selected.as_str().is_empty() {
            return Err(error(RoutingDomainErrorCode::InvalidArgument));
        }
        Ok(Self {
            snapshot_version,
            selected,
        })
    }

    /// Returns the snapshot version used for selection.
    #[must_use]
    pub const fn snapshot_version(&self) -> RouteSnapshotVersion {
        self.snapshot_version
    }

    /// Returns the selected candidate key.
    #[must_use]
    pub const fn selected(&self) -> &CandidateKey {
        &self.selected
    }

    /// Validates that the decision still refers to the supplied snapshot.
    ///
    /// # Errors
    /// Returns a version mismatch or missing-candidate error without exposing
    /// internal identifiers in the error value.
    pub fn validate_against(&self, snapshot: &RouteSnapshot) -> Result<(), RoutingDomainError> {
        if self.snapshot_version != snapshot.version() {
            return Err(error(RoutingDomainErrorCode::SnapshotVersionMismatch));
        }
        if snapshot.candidate(&self.selected).is_none() {
            return Err(error(RoutingDomainErrorCode::CandidateNotFound));
        }
        Ok(())
    }
}

/// A candidate excluded while explaining a routing evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateExclusion {
    key: CandidateKey,
    reason: ExclusionReason,
}

impl CandidateExclusion {
    /// Creates an exclusion record for a validated candidate key.
    #[must_use]
    pub const fn new(key: CandidateKey, reason: ExclusionReason) -> Self {
        Self { key, reason }
    }

    /// Returns the excluded candidate key.
    #[must_use]
    pub const fn key(&self) -> &CandidateKey {
        &self.key
    }

    /// Returns the stable exclusion reason.
    #[must_use]
    pub const fn reason(&self) -> ExclusionReason {
        self.reason
    }
}

/// Stable reasons a candidate may be absent from a route decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExclusionReason {
    /// The candidate exposes a different model selector.
    ModelMismatch,
    /// The candidate was removed by an upstream health or policy snapshot.
    PolicyExcluded,
}

/// A transport-neutral explanation of one routing decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingEvaluation {
    context: RoutingContext,
    snapshot_version: RouteSnapshotVersion,
    decision: RouteDecision,
    exclusions: Vec<CandidateExclusion>,
}

impl RoutingEvaluation {
    /// Creates an evaluation after binding the decision to context and snapshot.
    ///
    /// # Errors
    /// Returns a stable error if the decision is not present in the snapshot or
    /// if the selected candidate serves a different model.
    pub fn new(
        context: RoutingContext,
        snapshot: &RouteSnapshot,
        decision: RouteDecision,
        exclusions: Vec<CandidateExclusion>,
    ) -> Result<Self, RoutingDomainError> {
        decision.validate_against(snapshot)?;
        let selected = snapshot
            .candidate(decision.selected())
            .ok_or_else(|| error(RoutingDomainErrorCode::CandidateNotFound))?;
        if selected.model() != context.model() {
            return Err(error(RoutingDomainErrorCode::ModelMismatch));
        }
        Ok(Self {
            context,
            snapshot_version: snapshot.version(),
            decision,
            exclusions,
        })
    }

    /// Returns the request context.
    #[must_use]
    pub const fn context(&self) -> &RoutingContext {
        &self.context
    }

    /// Returns the source snapshot version.
    #[must_use]
    pub const fn snapshot_version(&self) -> RouteSnapshotVersion {
        self.snapshot_version
    }

    /// Returns the validated decision.
    #[must_use]
    pub const fn decision(&self) -> &RouteDecision {
        &self.decision
    }

    /// Returns exclusions in deterministic caller-provided order.
    #[must_use]
    pub fn exclusions(&self) -> &[CandidateExclusion] {
        &self.exclusions
    }
}

/// Synchronous port for reading a tenant's immutable routing snapshot.
pub trait CandidateSnapshotPort {
    /// Loads the current snapshot for a tenant.
    ///
    /// Implementations must return a complete immutable snapshot or a stable
    /// error; partial candidate lists are not valid routing input.
    fn current_snapshot(&self, tenant_id: &TenantId) -> Result<RouteSnapshot, RoutingDomainError>;
}

const fn error(code: RoutingDomainErrorCode) -> RoutingDomainError {
    RoutingDomainError::new(code)
}

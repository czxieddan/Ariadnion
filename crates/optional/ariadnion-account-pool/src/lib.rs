// crates/optional/ariadnion-account-pool/src/lib.rs - Account pool contracts for Ariadnion.
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
//! Versioned account imports and immutable candidate snapshots.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// crates/optional/ariadnion-account-pool/src/error.rs - Account pool errors.
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

use std::fmt;

const UNKNOWN_ERROR_CODE: &str = "ACCOUNT_POOL_UNKNOWN";

/// Stable machine-readable account-pool failure codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AccountPoolErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// The import schema version is unsupported.
    UnsupportedSchemaVersion,
    /// The import has too many records.
    TooManyRecords,
    /// An account identity appears more than once in an import.
    DuplicateAccount,
    /// A candidate identity appears more than once in a snapshot.
    DuplicateCandidate,
    /// The candidate set exceeds its bound.
    TooManyCandidates,
    /// The publication expected a stale pool generation.
    GenerationConflict,
    /// A snapshot version cannot advance without wrapping.
    VersionExhausted,
    /// A record cannot produce a routable candidate.
    InvalidCandidate,
    /// Internal publication state could not be read or updated.
    StateUnavailable,
    /// A candidate belongs to a different tenant than the requested projection.
    TenantMismatch,
    /// A candidate snapshot could not be represented by routing-domain bounds.
    RoutingProjectionFailed,
}

impl AccountPoolErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument
            | Self::UnsupportedSchemaVersion
            | Self::TooManyRecords
            | Self::DuplicateAccount => import_error_code(self),
            Self::DuplicateCandidate
            | Self::TooManyCandidates
            | Self::GenerationConflict
            | Self::VersionExhausted => snapshot_error_code(self),
            Self::InvalidCandidate
            | Self::StateUnavailable
            | Self::TenantMismatch
            | Self::RoutingProjectionFailed => projection_error_code(self),
        }
    }
}

const fn import_error_code(code: AccountPoolErrorCode) -> &'static str {
    match code {
        AccountPoolErrorCode::InvalidArgument => "ACCOUNT_POOL_INVALID_ARGUMENT",
        AccountPoolErrorCode::UnsupportedSchemaVersion => "ACCOUNT_POOL_UNSUPPORTED_SCHEMA_VERSION",
        AccountPoolErrorCode::TooManyRecords => "ACCOUNT_POOL_TOO_MANY_RECORDS",
        AccountPoolErrorCode::DuplicateAccount => "ACCOUNT_POOL_DUPLICATE_ACCOUNT",
        _ => UNKNOWN_ERROR_CODE,
    }
}

const fn snapshot_error_code(code: AccountPoolErrorCode) -> &'static str {
    match code {
        AccountPoolErrorCode::DuplicateCandidate => "ACCOUNT_POOL_DUPLICATE_CANDIDATE",
        AccountPoolErrorCode::TooManyCandidates => "ACCOUNT_POOL_TOO_MANY_CANDIDATES",
        AccountPoolErrorCode::GenerationConflict => "ACCOUNT_POOL_GENERATION_CONFLICT",
        AccountPoolErrorCode::VersionExhausted => "ACCOUNT_POOL_VERSION_EXHAUSTED",
        _ => UNKNOWN_ERROR_CODE,
    }
}

const fn projection_error_code(code: AccountPoolErrorCode) -> &'static str {
    match code {
        AccountPoolErrorCode::InvalidCandidate => "ACCOUNT_POOL_INVALID_CANDIDATE",
        AccountPoolErrorCode::StateUnavailable => "ACCOUNT_POOL_STATE_UNAVAILABLE",
        AccountPoolErrorCode::TenantMismatch => "ACCOUNT_POOL_TENANT_MISMATCH",
        AccountPoolErrorCode::RoutingProjectionFailed => "ACCOUNT_POOL_ROUTING_PROJECTION_FAILED",
        _ => UNKNOWN_ERROR_CODE,
    }
}

impl fmt::Display for AccountPoolErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted account-pool failure carrying no rejected input or secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountPoolError {
    code: AccountPoolErrorCode,
}

impl AccountPoolError {
    pub(crate) const fn new(code: AccountPoolErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AccountPoolErrorCode {
        self.code
    }
}

impl fmt::Display for AccountPoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AccountPoolError {}

// crates/optional/ariadnion-account-pool/src/model.rs - Account pool models.
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

use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

use ariadnion_account_domain::{Account, AccountId, ModelName, ProviderId};
use ariadnion_core::TenantId;
use ariadnion_routing_domain::{CandidateRef, RouteModel, RouteSnapshot, RouteSnapshotVersion};

/// Maximum records accepted by one account import.
pub const MAX_IMPORT_RECORDS: usize = 1 << 17;
/// Maximum candidates held by one immutable snapshot.
pub const MAX_SNAPSHOT_CANDIDATES: usize = 1 << 17;
/// Maximum supported candidate weight.
pub const MAX_WEIGHT: u32 = 1 << 20;
/// Maximum supported instantaneous load value.
pub const MAX_LOAD: u32 = 1 << 30;
const MAX_CANDIDATE_ID_BYTES: usize = 128;
const CURRENT_SCHEMA_VERSION: u16 = 1;

/// Version of the account import schema.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountSchemaVersion(u16);

impl AccountSchemaVersion {
    /// Returns the schema version implemented by this crate.
    #[must_use]
    pub const fn current() -> Self {
        Self(CURRENT_SCHEMA_VERSION)
    }

    /// Creates an explicit schema version for parsing or compatibility checks.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric schema version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    pub(crate) const fn is_supported(self) -> bool {
        self.0 == CURRENT_SCHEMA_VERSION
    }
}

/// Monotonic generation used for optimistic atomic publication.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PoolGeneration(u64);

impl PoolGeneration {
    /// Returns the generation before any successful publication.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Creates a generation reconstructed from durable state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn next(self) -> Result<Self, AccountPoolError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| model_error(AccountPoolErrorCode::VersionExhausted))
    }
}

/// Stable identity of one published candidate snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SnapshotId(u64);

impl SnapshotId {
    /// Creates an identity reconstructed from durable state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic version of an immutable candidate snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SnapshotVersion(u64);

impl SnapshotVersion {
    /// Creates a version reconstructed from durable state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable bounded identity of a routable candidate.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateId(Box<str>);

impl CandidateId {
    /// Parses a non-empty ASCII identifier of at most 128 bytes.
    ///
    /// # Errors
    /// Returns [`AccountPoolErrorCode::InvalidArgument`] for an empty,
    /// oversized, non-ASCII, or syntactically invalid identity.
    pub fn parse(value: &str) -> Result<Self, AccountPoolError> {
        if !valid_candidate_id(value) {
            return Err(model_error(AccountPoolErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    pub(crate) fn from_account(account_id: &AccountId) -> Self {
        Self(account_id.as_str().into())
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for CandidateId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CandidateId(<opaque>)")
    }
}

impl Display for CandidateId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Priority tier where lower numeric values are preferred.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Priority(u16);

impl Priority {
    /// Creates a priority tier.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric priority.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Bounded relative routing weight.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Weight(u32);

impl Weight {
    /// Creates a bounded weight. Zero is retained for explicit policy exclusion.
    ///
    /// # Errors
    /// Returns [`AccountPoolErrorCode::InvalidArgument`] above [`MAX_WEIGHT`].
    pub const fn new(value: u32) -> Result<Self, AccountPoolError> {
        if value > MAX_WEIGHT {
            Err(model_error(AccountPoolErrorCode::InvalidArgument))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric weight.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Bounded instantaneous candidate load.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Load(u32);

impl Load {
    /// Creates a bounded load value.
    ///
    /// # Errors
    /// Returns [`AccountPoolErrorCode::InvalidArgument`] above [`MAX_LOAD`].
    pub const fn new(value: u32) -> Result<Self, AccountPoolError> {
        if value > MAX_LOAD {
            Err(model_error(AccountPoolErrorCode::InvalidArgument))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric load.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Availability supplied to a routing selector by the published snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Availability {
    /// The candidate may be evaluated by a selection policy.
    Available,
    /// The candidate must be excluded before policy comparison.
    Unavailable,
}

/// One versioned import record containing account and routing metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountImportRecord {
    account: Account,
    priority: Priority,
    weight: Weight,
    load: Load,
    availability: Availability,
}

impl AccountImportRecord {
    /// Creates an import record from validated account-domain and routing values.
    #[must_use]
    pub const fn new(
        account: Account,
        priority: Priority,
        weight: Weight,
        load: Load,
        availability: Availability,
    ) -> Self {
        Self {
            account,
            priority,
            weight,
            load,
            availability,
        }
    }

    /// Returns the immutable account aggregate.
    #[must_use]
    pub const fn account(&self) -> &Account {
        &self.account
    }

    /// Returns the configured priority.
    #[must_use]
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Returns the configured weight.
    #[must_use]
    pub const fn weight(&self) -> Weight {
        self.weight
    }

    /// Returns the instantaneous load captured by the import.
    #[must_use]
    pub const fn load(&self) -> Load {
        self.load
    }

    /// Returns the imported availability fact.
    #[must_use]
    pub const fn availability(&self) -> Availability {
        self.availability
    }
}

/// Bounded versioned account import document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountImport {
    schema_version: AccountSchemaVersion,
    records: Arc<[AccountImportRecord]>,
}

impl AccountImport {
    /// Creates a bounded import document without publishing it.
    ///
    /// Schema compatibility and cross-record uniqueness are checked by dry run
    /// so callers can receive a deterministic report before publication.
    ///
    /// # Errors
    /// Returns [`AccountPoolErrorCode::TooManyRecords`] when the record count
    /// exceeds [`MAX_IMPORT_RECORDS`].
    pub fn new(
        schema_version: AccountSchemaVersion,
        records: Vec<AccountImportRecord>,
    ) -> Result<Self, AccountPoolError> {
        if records.len() > MAX_IMPORT_RECORDS {
            return Err(model_error(AccountPoolErrorCode::TooManyRecords));
        }
        Ok(Self {
            schema_version,
            records: records.into(),
        })
    }

    /// Returns the declared schema version.
    #[must_use]
    pub const fn schema_version(&self) -> AccountSchemaVersion {
        self.schema_version
    }

    /// Returns import records in source order.
    #[must_use]
    pub fn records(&self) -> &[AccountImportRecord] {
        &self.records
    }
}

/// Secret-free routing metadata projected from an account import record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateMetadata {
    id: CandidateId,
    tenant_id: Option<TenantId>,
    account_id: AccountId,
    provider_id: ProviderId,
    model: Option<ModelName>,
    priority: Priority,
    weight: Weight,
    load: Load,
    availability: Availability,
}

impl CandidateMetadata {
    /// Creates secret-free metadata for one routing candidate.
    #[must_use]
    pub const fn new(
        id: CandidateId,
        account_id: AccountId,
        provider_id: ProviderId,
        model: Option<ModelName>,
        routing: CandidateRoutingMetadata,
    ) -> Self {
        Self {
            id,
            tenant_id: None,
            account_id,
            provider_id,
            model,
            priority: routing.priority,
            weight: routing.weight,
            load: routing.load,
            availability: routing.availability,
        }
    }

    pub(crate) fn from_record(record: &AccountImportRecord) -> Self {
        let account = record.account();
        let mut candidate = Self::new(
            CandidateId::from_account(account.id()),
            account.id().clone(),
            account.provider().id().clone(),
            account.config().default_model().cloned(),
            CandidateRoutingMetadata::new(
                record.priority(),
                record.weight(),
                record.load(),
                record.availability(),
            ),
        );
        candidate.tenant_id = Some(account.tenant_id().clone());
        candidate
    }

    /// Returns the stable candidate identity.
    #[must_use]
    pub const fn id(&self) -> &CandidateId {
        &self.id
    }

    /// Returns the account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the source tenant when this candidate came from an account record.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// Returns the provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the configured provider model, when present.
    #[must_use]
    pub const fn model(&self) -> Option<&ModelName> {
        self.model.as_ref()
    }

    /// Returns the priority tier.
    #[must_use]
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Returns the relative routing weight.
    #[must_use]
    pub const fn weight(&self) -> Weight {
        self.weight
    }

    /// Returns the captured instantaneous load.
    #[must_use]
    pub const fn load(&self) -> Load {
        self.load
    }

    /// Returns the captured availability fact.
    #[must_use]
    pub const fn availability(&self) -> Availability {
        self.availability
    }
}

/// Routing fields grouped for bounded candidate construction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidateRoutingMetadata {
    priority: Priority,
    weight: Weight,
    load: Load,
    availability: Availability,
}

impl CandidateRoutingMetadata {
    /// Creates routing metadata from validated bounded values.
    #[must_use]
    pub const fn new(
        priority: Priority,
        weight: Weight,
        load: Load,
        availability: Availability,
    ) -> Self {
        Self {
            priority,
            weight,
            load,
            availability,
        }
    }
}

/// Immutable, shareable candidate set published as one atomic value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateSnapshot {
    id: SnapshotId,
    version: SnapshotVersion,
    candidates: Arc<[CandidateMetadata]>,
}

impl CandidateSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            id: SnapshotId::new(0),
            version: SnapshotVersion::new(0),
            candidates: Arc::from([]),
        }
    }

    /// Creates a bounded immutable snapshot and sorts candidates by identity.
    ///
    /// # Errors
    /// Returns a stable error when the candidate count exceeds
    /// [`MAX_SNAPSHOT_CANDIDATES`] or a candidate identity is duplicated.
    pub fn new(
        id: SnapshotId,
        version: SnapshotVersion,
        mut candidates: Vec<CandidateMetadata>,
    ) -> Result<Self, AccountPoolError> {
        if candidates.len() > MAX_SNAPSHOT_CANDIDATES {
            return Err(model_error(AccountPoolErrorCode::TooManyCandidates));
        }
        candidates.sort_by(|left, right| left.id().cmp(right.id()));
        if candidates
            .windows(2)
            .any(|pair| pair[0].id() == pair[1].id())
        {
            return Err(model_error(AccountPoolErrorCode::DuplicateCandidate));
        }
        Ok(Self {
            id,
            version,
            candidates: candidates.into(),
        })
    }

    /// Returns the stable snapshot identity.
    #[must_use]
    pub const fn id(&self) -> SnapshotId {
        self.id
    }

    /// Returns the monotonic snapshot version.
    #[must_use]
    pub const fn version(&self) -> SnapshotVersion {
        self.version
    }

    /// Returns candidates sorted by ascending candidate identity.
    #[must_use]
    pub fn candidates(&self) -> &[CandidateMetadata] {
        &self.candidates
    }

    /// Projects this immutable candidate set into a tenant-bound routing snapshot.
    ///
    /// Unavailable candidates are excluded before projection. Candidates retain
    /// deterministic candidate-ID order, while the routing snapshot version is
    /// copied without exposing account-pool internals.
    ///
    /// # Errors
    /// Returns a redacted account-pool error when a candidate crosses the
    /// requested tenant boundary, lacks a model, or exceeds routing-domain
    /// validation bounds.
    pub fn to_route_snapshot(
        &self,
        tenant_id: &TenantId,
    ) -> Result<RouteSnapshot, AccountPoolError> {
        let version = RouteSnapshotVersion::new(self.version.get())
            .map_err(|_| error(AccountPoolErrorCode::RoutingProjectionFailed))?;
        let mut projected = Vec::with_capacity(self.candidates.len());
        for candidate in self.candidates.iter() {
            if let Some(route_candidate) = project_candidate(candidate, tenant_id)? {
                projected.push(route_candidate);
            }
        }
        RouteSnapshot::new(tenant_id.clone(), version, projected).map_err(projected_routing_error)
    }

    /// Alias for [`Self::to_route_snapshot`] using projection terminology.
    pub fn project_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<RouteSnapshot, AccountPoolError> {
        self.to_route_snapshot(tenant_id)
    }
}

fn project_candidate(
    candidate: &CandidateMetadata,
    tenant_id: &TenantId,
) -> Result<Option<CandidateRef>, AccountPoolError> {
    ensure_candidate_tenant(candidate, tenant_id)?;
    if candidate.availability() != Availability::Available {
        return Ok(None);
    }
    build_route_candidate(candidate, tenant_id).map(Some)
}

fn ensure_candidate_tenant(
    candidate: &CandidateMetadata,
    tenant_id: &TenantId,
) -> Result<(), AccountPoolError> {
    let source_tenant = candidate
        .tenant_id()
        .ok_or_else(|| error(AccountPoolErrorCode::InvalidCandidate))?;
    if source_tenant != tenant_id {
        return Err(error(AccountPoolErrorCode::TenantMismatch));
    }
    Ok(())
}

fn build_route_candidate(
    candidate: &CandidateMetadata,
    tenant_id: &TenantId,
) -> Result<CandidateRef, AccountPoolError> {
    let model = candidate
        .model()
        .ok_or_else(|| error(AccountPoolErrorCode::InvalidCandidate))?;
    let model = RouteModel::parse(model.as_str())
        .map_err(|_| error(AccountPoolErrorCode::InvalidCandidate))?;
    CandidateRef::new(
        tenant_id.clone(),
        candidate.id().as_str(),
        candidate.account_id().clone(),
        candidate.provider_id().clone(),
        model,
    )
    .map_err(|_| error(AccountPoolErrorCode::InvalidCandidate))
}

fn valid_candidate_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CANDIDATE_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(is_candidate_id_byte)
}

fn is_candidate_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

const fn model_error(code: AccountPoolErrorCode) -> AccountPoolError {
    AccountPoolError::new(code)
}

// crates/optional/ariadnion-account-pool/src/pool.rs - Account pool publication.
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

use std::collections::BTreeSet;
use std::sync::RwLock;

use ariadnion_account_domain::AccountStatus;

/// Successful read-only validation of an account import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportReport {
    schema_version: AccountSchemaVersion,
    record_count: usize,
    candidate_count: usize,
    current_generation: PoolGeneration,
    publish_generation: PoolGeneration,
}

impl ImportReport {
    /// Returns the validated schema version.
    #[must_use]
    pub const fn schema_version(self) -> AccountSchemaVersion {
        self.schema_version
    }

    /// Returns the number of source records.
    #[must_use]
    pub const fn record_count(self) -> usize {
        self.record_count
    }

    /// Returns the number of projected candidates.
    #[must_use]
    pub const fn candidate_count(self) -> usize {
        self.candidate_count
    }

    /// Returns the generation observed by the dry run.
    #[must_use]
    pub const fn current_generation(self) -> PoolGeneration {
        self.current_generation
    }

    /// Returns the generation that a publish would create if state is unchanged.
    #[must_use]
    pub const fn publish_generation(self) -> PoolGeneration {
        self.publish_generation
    }
}

/// Evidence returned after one atomic snapshot publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReceipt {
    previous_generation: PoolGeneration,
    generation: PoolGeneration,
    snapshot: Arc<CandidateSnapshot>,
}

impl PublishReceipt {
    /// Returns the generation replaced by this publication.
    #[must_use]
    pub const fn previous_generation(&self) -> PoolGeneration {
        self.previous_generation
    }

    /// Returns the committed pool generation.
    #[must_use]
    pub const fn generation(&self) -> PoolGeneration {
        self.generation
    }

    /// Returns the immutable snapshot committed by the publication.
    #[must_use]
    pub fn snapshot(&self) -> Arc<CandidateSnapshot> {
        Arc::clone(&self.snapshot)
    }
}

#[derive(Debug)]
struct PoolState {
    generation: PoolGeneration,
    snapshot: Arc<CandidateSnapshot>,
}

/// Concurrent account pool with generation-checked atomic publication.
///
/// Import validation and candidate construction complete before the write lock
/// is acquired. A successful publication replaces the generation and snapshot
/// together, while failed validation or stale generations leave state unchanged.
#[derive(Debug)]
pub struct AccountPool {
    state: RwLock<PoolState>,
}

impl Default for AccountPool {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountPool {
    /// Creates an empty pool at generation zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(PoolState {
                generation: PoolGeneration::initial(),
                snapshot: Arc::new(CandidateSnapshot::empty()),
            }),
        }
    }

    /// Validates an import without changing the published snapshot.
    ///
    /// Validation is deterministic: records are inspected in source order and
    /// the first stable failure is returned. A later concurrent publication may
    /// invalidate the reported generation, so callers must pass
    /// [`ImportReport::current_generation`] to [`Self::publish`].
    ///
    /// # Errors
    /// Returns a stable schema, bound, duplicate, lifecycle, version, or state
    /// error without retaining rejected input.
    pub fn dry_run(&self, import: &AccountImport) -> Result<ImportReport, AccountPoolError> {
        let candidates = build_candidates(import)?;
        let current_generation = self.generation()?;
        let publish_generation = current_generation.next()?;
        Ok(ImportReport {
            schema_version: import.schema_version(),
            record_count: import.records().len(),
            candidate_count: candidates.len(),
            current_generation,
            publish_generation,
        })
    }

    /// Atomically publishes a fully validated account import.
    ///
    /// Candidate construction occurs before state mutation. The write lock then
    /// verifies the caller's expected generation, advances the generation, and
    /// swaps one immutable snapshot. Existing readers retain their prior `Arc`
    /// and never observe a partially built candidate set.
    ///
    /// # Errors
    /// Returns [`AccountPoolErrorCode::GenerationConflict`] for stale state and
    /// stable validation or state errors for all other failures.
    pub fn publish(
        &self,
        import: &AccountImport,
        expected_generation: PoolGeneration,
    ) -> Result<PublishReceipt, AccountPoolError> {
        let candidates = build_candidates(import)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| error(AccountPoolErrorCode::StateUnavailable))?;
        ensure_generation(state.generation, expected_generation)?;
        let generation = state.generation.next()?;
        let snapshot = Arc::new(CandidateSnapshot::new(
            SnapshotId::new(generation.get()),
            SnapshotVersion::new(generation.get()),
            candidates,
        )?);
        let previous_generation = state.generation;
        state.generation = generation;
        state.snapshot = Arc::clone(&snapshot);
        Ok(PublishReceipt {
            previous_generation,
            generation,
            snapshot,
        })
    }

    /// Returns the currently published generation.
    ///
    /// # Errors
    /// Returns [`AccountPoolErrorCode::StateUnavailable`] when a prior panic
    /// poisoned the internal lock. Production control flow never causes poison.
    pub fn generation(&self) -> Result<PoolGeneration, AccountPoolError> {
        self.state
            .read()
            .map(|state| state.generation)
            .map_err(|_| error(AccountPoolErrorCode::StateUnavailable))
    }
}

/// Read-only port exposing the latest immutable candidate snapshot.
///
/// Routing domains should depend on this port or on [`CandidateSnapshot`], not
/// on account-pool publication internals. The account-pool crate intentionally
/// does not depend on a routing policy crate, preventing a future dependency
/// cycle when policy implementations consume these candidates.
pub trait CandidateSelectionPort: Send + Sync {
    /// Returns a shared immutable view of the latest complete snapshot.
    ///
    /// # Errors
    /// Returns a stable state error if the implementation cannot read its
    /// authoritative snapshot.
    fn candidate_snapshot(&self) -> Result<Arc<CandidateSnapshot>, AccountPoolError>;
}

impl CandidateSelectionPort for AccountPool {
    fn candidate_snapshot(&self) -> Result<Arc<CandidateSnapshot>, AccountPoolError> {
        self.state
            .read()
            .map(|state| Arc::clone(&state.snapshot))
            .map_err(|_| error(AccountPoolErrorCode::StateUnavailable))
    }
}

fn build_candidates(import: &AccountImport) -> Result<Vec<CandidateMetadata>, AccountPoolError> {
    validate_schema(import.schema_version())?;
    let mut account_ids = BTreeSet::<&AccountId>::new();
    let mut candidates = Vec::with_capacity(import.records().len());
    for record in import.records() {
        if !account_ids.insert(record.account().id()) {
            return Err(error(AccountPoolErrorCode::DuplicateAccount));
        }
        validate_record(record)?;
        candidates.push(CandidateMetadata::from_record(record));
    }
    candidates.sort_by(|left, right| left.id().cmp(right.id()));
    Ok(candidates)
}

fn validate_schema(version: AccountSchemaVersion) -> Result<(), AccountPoolError> {
    if version.is_supported() {
        Ok(())
    } else {
        Err(error(AccountPoolErrorCode::UnsupportedSchemaVersion))
    }
}

fn validate_record(record: &AccountImportRecord) -> Result<(), AccountPoolError> {
    let available = record.availability() == Availability::Available;
    let active = record.account().status() == AccountStatus::Active;
    if available && !active {
        Err(error(AccountPoolErrorCode::InvalidCandidate))
    } else {
        Ok(())
    }
}

fn ensure_generation(
    actual: PoolGeneration,
    expected: PoolGeneration,
) -> Result<(), AccountPoolError> {
    if actual == expected {
        Ok(())
    } else {
        Err(error(AccountPoolErrorCode::GenerationConflict))
    }
}

const fn error(code: AccountPoolErrorCode) -> AccountPoolError {
    AccountPoolError::new(code)
}

fn projected_routing_error(
    routing_error: ariadnion_routing_domain::RoutingDomainError,
) -> AccountPoolError {
    use ariadnion_routing_domain::RoutingDomainErrorCode;

    let code = match routing_error.code() {
        RoutingDomainErrorCode::DuplicateCandidateId => AccountPoolErrorCode::DuplicateCandidate,
        RoutingDomainErrorCode::SnapshotVersionExhausted => AccountPoolErrorCode::VersionExhausted,
        RoutingDomainErrorCode::TenantMismatch => AccountPoolErrorCode::TenantMismatch,
        _ => AccountPoolErrorCode::RoutingProjectionFailed,
    };
    AccountPoolError::new(code)
}

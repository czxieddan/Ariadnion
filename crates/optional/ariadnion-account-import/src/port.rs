// crates/optional/ariadnion-account-import/src/port.rs - Durable account import ports for Ariadnion.
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
//! Tenant-scoped durable publication and reconciliation contracts.

use std::fmt::{self, Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use ariadnion_account_domain::{
    AccountId, AccountStatus, ModelName, ProviderId, SecretPurpose, SecretRef,
};
use ariadnion_core::{RequestContext, TenantId};

use crate::{ImportGeneration, MAX_IMPORT_ENTRIES, PublishIntent};

/// Maximum bytes in one caller-stable import mutation identity.
pub const MAX_IMPORT_MUTATION_ID_BYTES: usize = 1 << 7;
/// Maximum accounts returned by one authoritative projection snapshot.
pub const MAX_ACCOUNT_PROJECTION_ACCOUNTS: usize = MAX_IMPORT_ENTRIES;

/// A boxed, sendable durable import operation future.
pub type BoxImportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ImportPortError>> + Send + 'a>>;

/// Stable failures returned by a durable account import adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ImportPortErrorCode {
    /// A mutation identity or receipt field is malformed.
    InvalidArgument,
    /// The request has no authenticated tenant.
    Unauthenticated,
    /// The authenticated principal cannot perform the requested account-store operation.
    PermissionDenied,
    /// The requested durable generation does not match the current authoritative projection.
    ProjectionConflict,
    /// The requested durable account binding or mutation conflicts with authoritative state.
    Conflict,
    /// Cancellation won before a new durable effect began.
    Cancelled,
    /// The absolute deadline won before a new durable effect began.
    DeadlineExceeded,
    /// A bounded adapter resource cannot accept more work.
    ResourceExhausted,
    /// The durable account store is temporarily unavailable.
    Unavailable,
    /// A commit outcome is ambiguous and requires reconciliation.
    CommitIndeterminate,
    /// Durable state failed structural or integrity validation.
    CorruptState,
}

impl ImportPortErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        if let Some(code) = request_error_code(self) {
            return code;
        }
        if let Some(code) = execution_error_code(self) {
            return code;
        }
        adapter_error_code(self)
    }
}

const fn request_error_code(code: ImportPortErrorCode) -> Option<&'static str> {
    match code {
        ImportPortErrorCode::InvalidArgument => Some("ACCOUNT_IMPORT_PORT_INVALID_ARGUMENT"),
        ImportPortErrorCode::Unauthenticated => Some("ACCOUNT_IMPORT_PORT_UNAUTHENTICATED"),
        ImportPortErrorCode::PermissionDenied => Some("ACCOUNT_IMPORT_PORT_PERMISSION_DENIED"),
        ImportPortErrorCode::Conflict => Some("ACCOUNT_IMPORT_PORT_CONFLICT"),
        ImportPortErrorCode::ProjectionConflict => Some("ACCOUNT_IMPORT_PORT_PROJECTION_CONFLICT"),
        _ => None,
    }
}

const fn execution_error_code(code: ImportPortErrorCode) -> Option<&'static str> {
    match code {
        ImportPortErrorCode::Cancelled => Some("ACCOUNT_IMPORT_PORT_CANCELLED"),
        ImportPortErrorCode::DeadlineExceeded => Some("ACCOUNT_IMPORT_PORT_DEADLINE_EXCEEDED"),
        ImportPortErrorCode::ResourceExhausted => Some("ACCOUNT_IMPORT_PORT_RESOURCE_EXHAUSTED"),
        _ => None,
    }
}

const fn adapter_error_code(code: ImportPortErrorCode) -> &'static str {
    match code {
        ImportPortErrorCode::Unavailable => "ACCOUNT_IMPORT_PORT_UNAVAILABLE",
        ImportPortErrorCode::CommitIndeterminate => "ACCOUNT_IMPORT_PORT_COMMIT_INDETERMINATE",
        ImportPortErrorCode::CorruptState => "ACCOUNT_IMPORT_PORT_CORRUPT_STATE",
        _ => "ACCOUNT_IMPORT_PORT_CORRUPT_STATE",
    }
}

/// A redacted durable import failure containing no tenant or account data.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ImportPortError {
    code: ImportPortErrorCode,
}

impl ImportPortError {
    /// Creates a redacted adapter failure.
    #[must_use]
    pub const fn new(code: ImportPortErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ImportPortErrorCode {
        self.code
    }

    /// Reports whether callers must reconcile instead of replaying the mutation.
    #[must_use]
    pub const fn requires_reconciliation(self) -> bool {
        matches!(self.code, ImportPortErrorCode::CommitIndeterminate)
    }
}

impl Debug for ImportPortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ImportPortError({})", self.code.as_str())
    }
}

impl Display for ImportPortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ImportPortError {}

/// A tenant-local, caller-stable identity for one durable publication attempt.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImportMutationId(Box<str>);

impl ImportMutationId {
    /// Parses a non-empty bounded ASCII mutation identity.
    ///
    /// The first byte must be alphanumeric. Remaining bytes may also contain
    /// `.`, `-`, `_`, or `:`. Reconciliation must reuse the exact same value.
    ///
    /// # Errors
    ///
    /// Returns [`ImportPortErrorCode::InvalidArgument`] for malformed input.
    pub fn parse(value: &str) -> Result<Self, ImportPortError> {
        if !valid_mutation_id(value) {
            return Err(ImportPortError::new(ImportPortErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ImportMutationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ImportMutationId")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for ImportMutationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A request for one tenant-scoped durable account projection snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountProjectionRequest {
    expected_generation: ImportGeneration,
}

impl AccountProjectionRequest {
    /// Creates a snapshot request bound to one immutable import generation.
    #[must_use]
    pub const fn new(expected_generation: ImportGeneration) -> Self {
        Self {
            expected_generation,
        }
    }

    /// Returns the generation that all projected rows must not exceed.
    #[must_use]
    pub const fn expected_generation(&self) -> ImportGeneration {
        self.expected_generation
    }
}

/// A request to resolve one active account's external credential reference.
///
/// The authenticated tenant is taken exclusively from the accompanying
/// [`RequestContext`]. The account, provider, configuration version, secret
/// purpose, and import generation form one revalidatable identity. This value
/// never carries credential bytes or a mutable tenant selector.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountCredentialReferenceRequest {
    account_id: AccountId,
    provider_id: ProviderId,
    config_version: u64,
    purpose: SecretPurpose,
    expected_generation: ImportGeneration,
}

impl AccountCredentialReferenceRequest {
    /// Creates a request bound to one non-zero configuration and import generation.
    ///
    /// # Errors
    ///
    /// Returns [`ImportPortErrorCode::InvalidArgument`] when the configuration
    /// version is zero or the expected generation is initial.
    pub fn new(
        account_id: AccountId,
        provider_id: ProviderId,
        config_version: u64,
        purpose: SecretPurpose,
        expected_generation: ImportGeneration,
    ) -> Result<Self, ImportPortError> {
        if config_version == 0 || expected_generation == ImportGeneration::initial() {
            return Err(ImportPortError::new(ImportPortErrorCode::InvalidArgument));
        }
        Ok(Self {
            account_id,
            provider_id,
            config_version,
            purpose,
            expected_generation,
        })
    }

    /// Returns the exact tenant-local account identity to resolve.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the expected upstream provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the exact non-zero account configuration version.
    #[must_use]
    pub const fn config_version(&self) -> u64 {
        self.config_version
    }

    /// Returns the required external-secret purpose.
    #[must_use]
    pub const fn purpose(&self) -> &SecretPurpose {
        &self.purpose
    }

    /// Returns the generation that must still be current for resolution.
    #[must_use]
    pub const fn expected_generation(&self) -> ImportGeneration {
        self.expected_generation
    }
}

impl Debug for AccountCredentialReferenceRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountCredentialReferenceRequest")
            .field("account_id", &self.account_id)
            .field("provider_id", &self.provider_id)
            .field("config_version", &self.config_version)
            .field("purpose", &self.purpose)
            .field("expected_generation", &self.expected_generation)
            .finish()
    }
}

/// An authenticated, generation-bound reference to one account credential.
///
/// The value carries a [`SecretRef`] locator and validation metadata only. It
/// never contains credential bytes, a credential digest, or secret-manager key
/// material. Callers revalidate it by passing [`Self::revalidation_request`] to
/// [`AccountCredentialReferencePort::account_credential_reference`].
#[derive(Clone, Eq, PartialEq)]
pub struct AccountCredentialReference {
    tenant_id: TenantId,
    account_id: AccountId,
    provider_id: ProviderId,
    config_version: u64,
    purpose: SecretPurpose,
    import_generation: ImportGeneration,
    secret_ref: SecretRef,
}

impl AccountCredentialReference {
    /// Creates one reference whose declared and embedded secret purposes agree.
    ///
    /// # Errors
    ///
    /// Returns [`ImportPortErrorCode::InvalidArgument`] when the configuration
    /// version or import generation is zero, or when the secret reference has a
    /// different purpose than the supplied binding.
    pub fn new(
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        config_version: u64,
        purpose: SecretPurpose,
        import_generation: ImportGeneration,
        secret_ref: SecretRef,
    ) -> Result<Self, ImportPortError> {
        if config_version == 0
            || import_generation == ImportGeneration::initial()
            || secret_ref.purpose() != &purpose
        {
            return Err(ImportPortError::new(ImportPortErrorCode::InvalidArgument));
        }
        Ok(Self {
            tenant_id,
            account_id,
            provider_id,
            config_version,
            purpose,
            import_generation,
            secret_ref,
        })
    }

    /// Returns the tenant authenticated when this reference was resolved.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the exact resolved account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the exact resolved upstream provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the exact resolved configuration version.
    #[must_use]
    pub const fn config_version(&self) -> u64 {
        self.config_version
    }

    /// Returns the declared purpose of the resolved secret reference.
    #[must_use]
    pub const fn purpose(&self) -> &SecretPurpose {
        &self.purpose
    }

    /// Returns the tenant import generation verified during resolution.
    #[must_use]
    pub const fn import_generation(&self) -> ImportGeneration {
        self.import_generation
    }

    /// Returns the metadata-only external secret reference.
    #[must_use]
    pub const fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Reconstructs the exact request required to revalidate this reference.
    #[must_use]
    pub fn revalidation_request(&self) -> AccountCredentialReferenceRequest {
        AccountCredentialReferenceRequest {
            account_id: self.account_id.clone(),
            provider_id: self.provider_id.clone(),
            config_version: self.config_version,
            purpose: self.purpose.clone(),
            expected_generation: self.import_generation,
        }
    }
}

impl Debug for AccountCredentialReference {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountCredentialReference")
            .field("tenant_id", &"<redacted>")
            .field("account_id", &self.account_id)
            .field("provider_id", &self.provider_id)
            .field("config_version", &self.config_version)
            .field("purpose", &self.purpose)
            .field("import_generation", &self.import_generation)
            .field("secret_ref", &self.secret_ref)
            .finish()
    }
}

/// Secret-free account state reconstructed from the durable account registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAccountIdentity {
    tenant_id: TenantId,
    account_id: AccountId,
    provider_id: ProviderId,
    default_model: Option<ModelName>,
}

impl DurableAccountIdentity {
    /// Creates the non-secret identity and routing selector fields.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        default_model: Option<ModelName>,
    ) -> Self {
        Self {
            tenant_id,
            account_id,
            provider_id,
            default_model,
        }
    }
}

/// Bounded persisted state required to rebuild an account candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableAccountState {
    max_concurrency: u32,
    config_version: u64,
    account_version: u64,
    status: AccountStatus,
    import_generation: ImportGeneration,
}

impl DurableAccountState {
    /// Creates validated persisted routing and lifecycle state.
    ///
    /// # Errors
    /// Returns [`ImportPortErrorCode::InvalidArgument`] for zero versions,
    /// zero concurrency, or generation zero.
    pub fn new(
        max_concurrency: u32,
        config_version: u64,
        account_version: u64,
        status: AccountStatus,
        import_generation: ImportGeneration,
    ) -> Result<Self, ImportPortError> {
        if max_concurrency == 0
            || config_version == 0
            || account_version == 0
            || import_generation == ImportGeneration::initial()
            || (status == AccountStatus::Deleted && account_version == 1)
        {
            return Err(ImportPortError::new(ImportPortErrorCode::InvalidArgument));
        }
        Ok(Self {
            max_concurrency,
            config_version,
            account_version,
            status,
            import_generation,
        })
    }
}

/// Secret-free account state reconstructed from the durable account registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAccountProjection {
    tenant_id: TenantId,
    account_id: AccountId,
    provider_id: ProviderId,
    default_model: Option<ModelName>,
    max_concurrency: u32,
    config_version: u64,
    account_version: u64,
    status: AccountStatus,
    import_generation: ImportGeneration,
}

impl DurableAccountProjection {
    /// Creates a validated secret-free persisted account projection.
    /// The component constructors validate every bounded persisted field.
    #[must_use]
    pub fn new(identity: DurableAccountIdentity, state: DurableAccountState) -> Self {
        Self {
            tenant_id: identity.tenant_id,
            account_id: identity.account_id,
            provider_id: identity.provider_id,
            default_model: identity.default_model,
            max_concurrency: state.max_concurrency,
            config_version: state.config_version,
            account_version: state.account_version,
            status: state.status,
            import_generation: state.import_generation,
        }
    }

    /// Returns the owning tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the stable account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the optional default model selector.
    #[must_use]
    pub const fn default_model(&self) -> Option<&ModelName> {
        self.default_model.as_ref()
    }

    /// Returns the persisted concurrency limit.
    #[must_use]
    pub const fn max_concurrency(&self) -> u32 {
        self.max_concurrency
    }

    /// Returns the persisted configuration version.
    #[must_use]
    pub const fn config_version(&self) -> u64 {
        self.config_version
    }

    /// Returns the persisted account version.
    #[must_use]
    pub const fn account_version(&self) -> u64 {
        self.account_version
    }

    /// Returns the persisted lifecycle status.
    #[must_use]
    pub const fn status(&self) -> AccountStatus {
        self.status
    }

    /// Returns the durable import generation that last changed this row.
    #[must_use]
    pub const fn import_generation(&self) -> ImportGeneration {
        self.import_generation
    }
}

/// One bounded authoritative durable account projection snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountProjectionSnapshot {
    generation: ImportGeneration,
    accounts: Vec<DurableAccountProjection>,
}

impl AccountProjectionSnapshot {
    /// Creates a validated projection snapshot in deterministic account-ID order.
    ///
    /// # Errors
    /// Returns [`ImportPortErrorCode::InvalidArgument`] when the snapshot exceeds
    /// [`MAX_ACCOUNT_PROJECTION_ACCOUNTS`], is unordered, or contains a future row.
    pub fn new(
        generation: ImportGeneration,
        accounts: Vec<DurableAccountProjection>,
    ) -> Result<Self, ImportPortError> {
        if accounts.len() > MAX_ACCOUNT_PROJECTION_ACCOUNTS
            || (generation == ImportGeneration::initial() && !accounts.is_empty())
            || accounts
                .iter()
                .any(|row| row.import_generation > generation)
            || accounts.windows(2).any(|rows| {
                rows[0].tenant_id != rows[1].tenant_id || rows[0].account_id >= rows[1].account_id
            })
        {
            return Err(ImportPortError::new(ImportPortErrorCode::InvalidArgument));
        }
        Ok(Self {
            generation,
            accounts,
        })
    }

    /// Returns the authoritative generation used for this snapshot.
    #[must_use]
    pub const fn generation(&self) -> ImportGeneration {
        self.generation
    }

    /// Returns rows in strictly ascending account-ID order.
    #[must_use]
    pub fn accounts(&self) -> &[DurableAccountProjection] {
        &self.accounts
    }

    /// Consumes the snapshot into its generation and ordered account rows.
    #[must_use]
    pub fn into_parts(self) -> (ImportGeneration, Vec<DurableAccountProjection>) {
        (self.generation, self.accounts)
    }
}

/// One immutable publication intent bound to its durable mutation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePublishRequest {
    mutation_id: ImportMutationId,
    intent: PublishIntent,
}

impl DurablePublishRequest {
    /// Binds a caller-stable mutation identity to one validated intent.
    #[must_use]
    pub const fn new(mutation_id: ImportMutationId, intent: PublishIntent) -> Self {
        Self {
            mutation_id,
            intent,
        }
    }

    /// Returns the tenant-local mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &ImportMutationId {
        &self.mutation_id
    }

    /// Returns the immutable generation-bound publication intent.
    #[must_use]
    pub const fn intent(&self) -> &PublishIntent {
        &self.intent
    }

    /// Consumes the request into its durable identity and immutable intent.
    #[must_use]
    pub fn into_parts(self) -> (ImportMutationId, PublishIntent) {
        (self.mutation_id, self.intent)
    }
}

/// Durable evidence for one committed account publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePublishReceipt {
    mutation_id: ImportMutationId,
    generation: ImportGeneration,
    published_count: usize,
    committed_at: SystemTime,
}

impl DurablePublishReceipt {
    /// Creates a receipt only after the adapter confirms durable commit.
    ///
    /// # Errors
    ///
    /// Returns [`ImportPortErrorCode::InvalidArgument`] for generation zero or
    /// an entry count above [`MAX_IMPORT_ENTRIES`].
    pub fn new(
        mutation_id: ImportMutationId,
        generation: ImportGeneration,
        published_count: usize,
        committed_at: SystemTime,
    ) -> Result<Self, ImportPortError> {
        if generation == ImportGeneration::initial() || published_count > MAX_IMPORT_ENTRIES {
            return Err(ImportPortError::new(ImportPortErrorCode::InvalidArgument));
        }
        Ok(Self {
            mutation_id,
            generation,
            published_count,
            committed_at,
        })
    }

    /// Returns the mutation identity used for reconciliation.
    #[must_use]
    pub const fn mutation_id(&self) -> &ImportMutationId {
        &self.mutation_id
    }

    /// Returns the committed durable generation.
    #[must_use]
    pub const fn generation(&self) -> ImportGeneration {
        self.generation
    }

    /// Returns the number of entries applied by the transaction.
    #[must_use]
    pub const fn published_count(&self) -> usize {
        self.published_count
    }

    /// Returns the adapter-reported UTC commit time.
    #[must_use]
    pub const fn committed_at(&self) -> SystemTime {
        self.committed_at
    }
}

/// Durable, tenant-scoped account import publication port.
///
/// Implementations authenticate the tenant from [`RequestContext`], compare the
/// intent generation and mutation identity inside one transaction, and persist
/// the resulting account state, generation, request fingerprint, and receipt
/// atomically. A repeated mutation identity is idempotent only when its original
/// request fingerprint matches. [`ImportPortErrorCode::CommitIndeterminate`]
/// requires [`Self::reconcile`]; callers must not invent a new mutation identity.
pub trait AccountImportPort: Send + Sync {
    /// Atomically publishes one validated account import intent.
    fn publish<'a>(
        &'a self,
        request: DurablePublishRequest,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, DurablePublishReceipt>;

    /// Reconciles one prior mutation without replaying its account effects.
    fn reconcile<'a>(
        &'a self,
        mutation_id: &'a ImportMutationId,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, Option<DurablePublishReceipt>>;

    /// Loads the tenant's authoritative durable import generation.
    fn generation<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, ImportGeneration>;
}

/// Authenticated tenant-scoped read port for rebuilding durable account state.
///
/// Implementations must authorize every snapshot independently and return only the
/// authenticated tenant's rows. A request generation is an immutable snapshot
/// token: adapters return [`ImportPortErrorCode::ProjectionConflict`] when the
/// current generation differs, rather than mixing rows from different states.
/// Returned values contain no secret reference, credential digest, or key data.
pub trait AccountProjectionPort: Send + Sync {
    /// Loads one deterministic account-ID ordered projection snapshot.
    fn account_projection<'a>(
        &'a self,
        request: AccountProjectionRequest,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, AccountProjectionSnapshot>;
}

/// Authenticated tenant-scoped read port for one active credential reference.
///
/// Adapters authorize this read independently from projection access, derive the
/// tenant only from the authenticated context, and verify the request generation
/// before returning a reference. A stale generation returns
/// [`ImportPortErrorCode::ProjectionConflict`]; missing, inactive, or mismatched
/// rows return a redacted conflict without disclosing durable account state.
/// Cancellation and deadlines remain effective until the read transaction ends.
pub trait AccountCredentialReferencePort: Send + Sync {
    /// Resolves one exact active account credential reference without credential bytes.
    fn account_credential_reference<'a>(
        &'a self,
        request: AccountCredentialReferenceRequest,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, AccountCredentialReference>;
}

fn valid_mutation_id(value: &str) -> bool {
    let Some(first) = value.as_bytes().first() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.len() <= MAX_IMPORT_MUTATION_ID_BYTES
        && value.bytes().all(valid_mutation_id_byte)
}

fn valid_mutation_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

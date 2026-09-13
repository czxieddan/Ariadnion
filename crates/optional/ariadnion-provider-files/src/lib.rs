// crates/optional/ariadnion-provider-files/src/lib.rs - Provider file mapping contracts for Ariadnion.
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
//! Immutable provider file mapping contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_api_domain::{FileReference, IdempotencyKey};
use ariadnion_core::{CoreError, ErrorCode, RequestContext, TenantId};

pub use ariadnion_provider_sdk::ProviderId;

/// Maximum UTF-8 byte length of one provider account identifier.
pub const MAX_PROVIDER_ACCOUNT_ID_BYTES: usize = 128;
/// Maximum ASCII byte length of one provider file identifier.
pub const MAX_PROVIDER_FILE_ID_BYTES: usize = 256;
/// Maximum ASCII byte length of one provider file purpose.
pub const MAX_PROVIDER_FILE_PURPOSE_BYTES: usize = 64;
/// Maximum number of records accepted by one immutable mapping snapshot.
pub const MAX_PROVIDER_FILE_MAPPINGS: usize = 100_000;
/// Maximum mappings returned by one provider-file page.
pub const MAX_PROVIDER_FILE_PAGE_RESULTS: usize = 1_000;

/// A boxed, lazy, sendable provider-file operation future.
pub type BoxProviderFileFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Stable failures returned by provider-file mapping operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderFilesErrorCode {
    /// A supplied identifier or timestamp relationship is invalid.
    InvalidArgument,
    /// A supplied value or snapshot exceeds a fixed bound.
    LimitExceeded,
    /// The request has no authenticated tenant context.
    Unauthenticated,
    /// The alias is unknown, foreign, or no longer available.
    NotFound,
    /// A static snapshot contains a duplicate mapping key.
    Conflict,
    /// Cancellation stopped the lookup.
    Cancelled,
    /// The request deadline expired before lookup.
    DeadlineExceeded,
    /// A bounded mapping resource is unavailable.
    ResourceExhausted,
    /// The mapping capability is unavailable.
    Unavailable,
    /// Durable publication may have committed and requires idempotent replay.
    CommitIndeterminate,
    /// The operation failed without a safe external explanation.
    Internal,
}

impl ProviderFilesErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument
            | Self::LimitExceeded
            | Self::Unauthenticated
            | Self::NotFound
            | Self::Conflict => request_machine_code(self),
            Self::Cancelled
            | Self::DeadlineExceeded
            | Self::ResourceExhausted
            | Self::Unavailable
            | Self::CommitIndeterminate
            | Self::Internal => execution_machine_code(self),
        }
    }
}

const fn request_machine_code(code: ProviderFilesErrorCode) -> &'static str {
    match code {
        ProviderFilesErrorCode::InvalidArgument => "PROVIDER_FILES_INVALID_ARGUMENT",
        ProviderFilesErrorCode::LimitExceeded => "PROVIDER_FILES_LIMIT_EXCEEDED",
        ProviderFilesErrorCode::Unauthenticated => "PROVIDER_FILES_UNAUTHENTICATED",
        ProviderFilesErrorCode::NotFound => "PROVIDER_FILES_NOT_FOUND",
        ProviderFilesErrorCode::Conflict => "PROVIDER_FILES_CONFLICT",
        _ => "PROVIDER_FILES_INTERNAL",
    }
}

const fn execution_machine_code(code: ProviderFilesErrorCode) -> &'static str {
    match code {
        ProviderFilesErrorCode::Cancelled => "PROVIDER_FILES_CANCELLED",
        ProviderFilesErrorCode::DeadlineExceeded => "PROVIDER_FILES_DEADLINE_EXCEEDED",
        ProviderFilesErrorCode::ResourceExhausted => "PROVIDER_FILES_RESOURCE_EXHAUSTED",
        ProviderFilesErrorCode::Unavailable => "PROVIDER_FILES_UNAVAILABLE",
        ProviderFilesErrorCode::CommitIndeterminate => "PROVIDER_FILES_COMMIT_INDETERMINATE",
        _ => "PROVIDER_FILES_INTERNAL",
    }
}

/// A redacted provider-file mapping error containing only its stable code.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProviderFilesError {
    code: ProviderFilesErrorCode,
}

impl ProviderFilesError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: ProviderFilesErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ProviderFilesErrorCode {
        self.code
    }
}

impl Debug for ProviderFilesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ProviderFilesError({})", self.code.as_str())
    }
}

impl Display for ProviderFilesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ProviderFilesError {}

impl From<CoreError> for ProviderFilesError {
    fn from(value: CoreError) -> Self {
        Self::new(match value.code() {
            ErrorCode::InvalidArgument => ProviderFilesErrorCode::InvalidArgument,
            ErrorCode::Conflict => ProviderFilesErrorCode::Conflict,
            ErrorCode::Cancelled => ProviderFilesErrorCode::Cancelled,
            ErrorCode::DeadlineExceeded => ProviderFilesErrorCode::DeadlineExceeded,
            ErrorCode::Unavailable => ProviderFilesErrorCode::Unavailable,
            ErrorCode::ResourceExhausted => ProviderFilesErrorCode::ResourceExhausted,
            ErrorCode::Internal => ProviderFilesErrorCode::Internal,
        })
    }
}

fn error(code: ProviderFilesErrorCode) -> ProviderFilesError {
    ProviderFilesError::new(code)
}

/// A validated provider account scope that is independent of P5 account state.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderAccountId(Box<str>);

impl ProviderAccountId {
    /// Validates and copies one provider account identifier.
    ///
    /// The identifier is non-empty ASCII and may contain only letters, digits,
    /// `-`, `_`, `.`, or `:`. It is a lookup scope, not credential material.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderFilesErrorCode::LimitExceeded`] above the hard bound,
    /// otherwise [`ProviderFilesErrorCode::InvalidArgument`] for malformed
    /// input. Rejected input is never retained by the error.
    pub fn new(value: &str) -> Result<Self, ProviderFilesError> {
        validate_token(value, MAX_PROVIDER_ACCOUNT_ID_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated account identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the UTF-8 byte length of the identifier.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.0.len()
    }
}

impl Debug for ProviderAccountId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAccountId")
            .field("bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

/// A validated provider-owned file alias.
///
/// This type is deliberately distinct from [`FileReference`]. There is no
/// conversion between the two types, and the alias never carries durable
/// storage bytes or a path.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderFileId(Box<str>);

impl ProviderFileId {
    /// Validates and copies one provider file identifier.
    ///
    /// The identifier is non-empty visible ASCII and may contain only letters,
    /// digits, `-`, `_`, `.`, or `:`. Slash and backslash are rejected so an
    /// alias cannot be interpreted as a local path.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderFilesErrorCode::LimitExceeded`] above the hard bound,
    /// otherwise [`ProviderFilesErrorCode::InvalidArgument`] for malformed
    /// input. Rejected input is never retained by the error.
    pub fn new(value: &str) -> Result<Self, ProviderFilesError> {
        validate_token(value, MAX_PROVIDER_FILE_ID_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated provider alias.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the alias's ASCII byte length.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.0.len()
    }
}

impl Debug for ProviderFileId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFileId")
            .field("bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

/// A validated provider file purpose retained by an immutable mapping.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderFilePurpose(Box<str>);

impl ProviderFilePurpose {
    /// Validates and copies one lower-level provider purpose token.
    ///
    /// Purpose allowlists belong to the protocol adapter. This neutral contract
    /// preserves the bounded token without deciding provider-specific semantics.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderFilesErrorCode::LimitExceeded`] above the hard bound,
    /// otherwise [`ProviderFilesErrorCode::InvalidArgument`] for malformed
    /// input.
    pub fn new(value: &str) -> Result<Self, ProviderFilesError> {
        validate_token(value, MAX_PROVIDER_FILE_PURPOSE_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns a canonical `batch` purpose.
    #[must_use]
    pub fn batch() -> Self {
        Self(Box::from("batch"))
    }

    /// Returns a canonical `user_data` purpose.
    #[must_use]
    pub fn user_data() -> Self {
        Self(Box::from("user_data"))
    }

    /// Returns the validated purpose token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reports whether this purpose is `batch`.
    #[must_use]
    pub fn is_batch(&self) -> bool {
        self.as_str() == "batch"
    }

    /// Reports whether this purpose is `user_data`.
    #[must_use]
    pub fn is_user_data(&self) -> bool {
        self.as_str() == "user_data"
    }
}

impl Debug for ProviderFilePurpose {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFilePurpose")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

fn validate_token(value: &str, limit: usize) -> Result<(), ProviderFilesError> {
    if value.len() > limit {
        return Err(error(ProviderFilesErrorCode::LimitExceeded));
    }
    if value.is_empty() || !value.is_ascii() {
        return Err(error(ProviderFilesErrorCode::InvalidArgument));
    }
    if value.bytes().any(is_invalid_token_byte) {
        return Err(error(ProviderFilesErrorCode::InvalidArgument));
    }
    Ok(())
}

fn is_invalid_token_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.' | b':')
}

/// A non-negative Unix timestamp retained by a provider file mapping.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderFileUnixSeconds(u64);

impl ProviderFileUnixSeconds {
    /// Creates a Unix-seconds timestamp.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the Unix-seconds value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One exact tenant/provider/account alias lookup.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProviderFileLookup {
    provider: ProviderId,
    account_id: ProviderAccountId,
    provider_file_id: ProviderFileId,
}

impl ProviderFileLookup {
    /// Creates a lookup from already validated provider scope values.
    #[must_use]
    pub const fn new(
        provider: ProviderId,
        account_id: ProviderAccountId,
        provider_file_id: ProviderFileId,
    ) -> Self {
        Self {
            provider,
            account_id,
            provider_file_id,
        }
    }

    /// Returns the provider namespace.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the account scope.
    #[must_use]
    pub const fn account_id(&self) -> &ProviderAccountId {
        &self.account_id
    }

    /// Returns the provider-owned file alias.
    #[must_use]
    pub const fn provider_file_id(&self) -> &ProviderFileId {
        &self.provider_file_id
    }
}

impl Debug for ProviderFileLookup {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFileLookup")
            .field("provider", &self.provider)
            .field("account_id", &self.account_id)
            .field("provider_file_id", &self.provider_file_id)
            .finish_non_exhaustive()
    }
}

/// One provider and account namespace used for reverse lookup and listing.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProviderFileScope {
    provider: ProviderId,
    account_id: ProviderAccountId,
}

impl ProviderFileScope {
    /// Creates an immutable provider/account scope without acquiring credentials.
    #[must_use]
    pub const fn new(provider: ProviderId, account_id: ProviderAccountId) -> Self {
        Self {
            provider,
            account_id,
        }
    }

    /// Returns the provider namespace.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the provider account scope.
    #[must_use]
    pub const fn account_id(&self) -> &ProviderAccountId {
        &self.account_id
    }

    /// Creates an exact public-alias lookup in this scope.
    #[must_use]
    pub fn lookup(&self, provider_file_id: ProviderFileId) -> ProviderFileLookup {
        ProviderFileLookup::new(
            self.provider.clone(),
            self.account_id.clone(),
            provider_file_id,
        )
    }
}

impl Debug for ProviderFileScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFileScope")
            .field("provider", &self.provider)
            .field("account_id", &self.account_id)
            .finish()
    }
}

/// A validated non-zero maximum for one provider-file mapping page.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderFilePageLimit(NonZeroUsize);

impl ProviderFilePageLimit {
    /// Validates a page limit in the inclusive range `1..=1000`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for zero and `LimitExceeded` above the bound.
    pub const fn new(value: usize) -> Result<Self, ProviderFilesError> {
        if value > MAX_PROVIDER_FILE_PAGE_RESULTS {
            return Err(ProviderFilesError::new(
                ProviderFilesErrorCode::LimitExceeded,
            ));
        }
        let Some(value) = NonZeroUsize::new(value) else {
            return Err(ProviderFilesError::new(
                ProviderFilesErrorCode::InvalidArgument,
            ));
        };
        Ok(Self(value))
    }

    /// Returns the checked page limit.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// One tenant-authenticated provider-file mapping list request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFileListRequest {
    scope: ProviderFileScope,
    after: Option<ProviderFileId>,
    limit: ProviderFilePageLimit,
}

impl ProviderFileListRequest {
    /// Creates a bounded exclusive-cursor list request.
    #[must_use]
    pub const fn new(
        scope: ProviderFileScope,
        after: Option<ProviderFileId>,
        limit: ProviderFilePageLimit,
    ) -> Self {
        Self {
            scope,
            after,
            limit,
        }
    }

    /// Returns the provider/account namespace.
    #[must_use]
    pub const fn scope(&self) -> &ProviderFileScope {
        &self.scope
    }

    /// Returns the optional exclusive public-alias cursor.
    #[must_use]
    pub const fn after(&self) -> Option<&ProviderFileId> {
        self.after.as_ref()
    }

    /// Returns the checked result limit.
    #[must_use]
    pub const fn limit(&self) -> ProviderFilePageLimit {
        self.limit
    }
}

/// One bounded page of immutable provider-file mappings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFileMappingPage {
    data: Box<[ProviderFileMapping]>,
    first_id: Option<ProviderFileId>,
    last_id: Option<ProviderFileId>,
    has_more: bool,
}

impl ProviderFileMappingPage {
    /// Creates a checked page and derives its first and last public IDs.
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` above the request limit and `Internal` when an
    /// empty page claims that a following page exists.
    pub fn new(
        data: Vec<ProviderFileMapping>,
        limit: ProviderFilePageLimit,
        has_more: bool,
    ) -> Result<Self, ProviderFilesError> {
        if data.len() > limit.get() {
            return Err(error(ProviderFilesErrorCode::LimitExceeded));
        }
        if data.is_empty() && has_more {
            return Err(error(ProviderFilesErrorCode::Internal));
        }
        let first_id = data.first().map(|mapping| mapping.provider_file_id.clone());
        let last_id = data.last().map(|mapping| mapping.provider_file_id.clone());
        Ok(Self {
            data: data.into_boxed_slice(),
            first_id,
            last_id,
            has_more,
        })
    }

    /// Returns mappings in deterministic public-ID order.
    #[must_use]
    pub fn data(&self) -> &[ProviderFileMapping] {
        &self.data
    }

    /// Returns the first public ID, when the page is non-empty.
    #[must_use]
    pub const fn first_id(&self) -> Option<&ProviderFileId> {
        self.first_id.as_ref()
    }

    /// Returns the last public ID, when the page is non-empty.
    #[must_use]
    pub const fn last_id(&self) -> Option<&ProviderFileId> {
        self.last_id.as_ref()
    }

    /// Reports whether another page follows this result.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

/// Immutable metadata retained alongside one provider file alias.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProviderFileMappingMetadata {
    file_reference: FileReference,
    purpose: ProviderFilePurpose,
    created_at: ProviderFileUnixSeconds,
    expires_at: Option<ProviderFileUnixSeconds>,
}

impl ProviderFileMappingMetadata {
    /// Creates metadata for one already validated provider file.
    #[must_use]
    pub const fn new(
        file_reference: FileReference,
        purpose: ProviderFilePurpose,
        created_at: ProviderFileUnixSeconds,
        expires_at: Option<ProviderFileUnixSeconds>,
    ) -> Self {
        Self {
            file_reference,
            purpose,
            created_at,
            expires_at,
        }
    }

    /// Returns the trusted internal durable reference.
    #[must_use]
    pub const fn file_reference(&self) -> &FileReference {
        &self.file_reference
    }

    /// Returns the retained provider purpose.
    #[must_use]
    pub const fn purpose(&self) -> &ProviderFilePurpose {
        &self.purpose
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> ProviderFileUnixSeconds {
        self.created_at
    }

    /// Returns the optional absolute expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> Option<ProviderFileUnixSeconds> {
        self.expires_at
    }
}

impl Debug for ProviderFileMappingMetadata {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFileMappingMetadata")
            .field("file_reference", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// One immutable alias record binding a provider ID to an Ariadnion reference.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProviderFileMapping {
    tenant_id: TenantId,
    provider: ProviderId,
    account_id: ProviderAccountId,
    provider_file_id: ProviderFileId,
    file_reference: FileReference,
    purpose: ProviderFilePurpose,
    created_at: ProviderFileUnixSeconds,
    expires_at: Option<ProviderFileUnixSeconds>,
}

impl ProviderFileMapping {
    /// Creates one validated immutable alias record.
    ///
    /// An expiry, when present, must be strictly later than creation. The
    /// provider alias remains separate from the durable [`FileReference`].
    ///
    /// # Errors
    ///
    /// Returns [`ProviderFilesErrorCode::InvalidArgument`] when expiry is not
    /// strictly later than creation.
    pub fn new(
        tenant_id: TenantId,
        provider: ProviderId,
        account_id: ProviderAccountId,
        provider_file_id: ProviderFileId,
        metadata: ProviderFileMappingMetadata,
    ) -> Result<Self, ProviderFilesError> {
        if metadata
            .expires_at
            .is_some_and(|expiry| expiry <= metadata.created_at)
        {
            return Err(error(ProviderFilesErrorCode::InvalidArgument));
        }
        Ok(Self {
            tenant_id,
            provider,
            account_id,
            provider_file_id,
            file_reference: metadata.file_reference,
            purpose: metadata.purpose,
            created_at: metadata.created_at,
            expires_at: metadata.expires_at,
        })
    }

    /// Returns the tenant scope owned by the mapping snapshot.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the provider namespace.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the account scope.
    #[must_use]
    pub const fn account_id(&self) -> &ProviderAccountId {
        &self.account_id
    }

    /// Returns the provider-owned file alias.
    #[must_use]
    pub const fn provider_file_id(&self) -> &ProviderFileId {
        &self.provider_file_id
    }

    /// Returns the trusted internal durable reference for a file adapter.
    #[must_use]
    pub const fn file_reference(&self) -> &FileReference {
        &self.file_reference
    }

    /// Returns the retained provider purpose.
    #[must_use]
    pub const fn purpose(&self) -> &ProviderFilePurpose {
        &self.purpose
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> ProviderFileUnixSeconds {
        self.created_at
    }

    /// Returns the optional absolute expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> Option<ProviderFileUnixSeconds> {
        self.expires_at
    }

    fn key(&self) -> ProviderFileMappingKey {
        ProviderFileMappingKey {
            tenant_id: self.tenant_id.clone(),
            provider: self.provider.clone(),
            account_id: self.account_id.clone(),
            provider_file_id: self.provider_file_id.clone(),
        }
    }

    fn expired_at(&self, now: SystemTime) -> bool {
        self.expires_at
            .is_some_and(|expiry| unix_seconds(now) >= expiry.get())
    }
}

impl Debug for ProviderFileMapping {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFileMapping")
            .field("tenant_id", &RedactedText(self.tenant_id.as_str()))
            .field("provider", &self.provider)
            .field("account_id", &self.account_id)
            .field("provider_file_id", &self.provider_file_id)
            .field("file_reference", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

struct RedactedText<'a>(&'a str);

impl Debug for RedactedText<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedText")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Resolves provider-owned file aliases using an authenticated tenant context.
///
/// Implementations must be immutable or externally synchronized and must not
/// perform account persistence, credential resolution, health checks, quota
/// accounting, candidate selection, or routing. The returned future is lazy and
/// `Send`; construction performs no lookup or context inspection.
pub trait ProviderFileMappingPort: Send + Sync {
    /// Lazily resolves one exact provider/account alias.
    ///
    /// The first poll checks authentication, cancellation, and deadline before
    /// reading the mapping. Unknown, foreign, and expired aliases all return
    /// [`ProviderFilesErrorCode::NotFound`] so the capability does not disclose
    /// tenant ownership or expiry state.
    fn resolve<'a>(
        &'a self,
        lookup: ProviderFileLookup,
        context: &'a RequestContext,
    ) -> BoxProviderFileFuture<'a, Result<ProviderFileMapping, ProviderFilesError>>;

    /// Alias for [`Self::resolve`] using lookup terminology.
    fn lookup<'a>(
        &'a self,
        lookup: ProviderFileLookup,
        context: &'a RequestContext,
    ) -> BoxProviderFileFuture<'a, Result<ProviderFileMapping, ProviderFilesError>> {
        self.resolve(lookup, context)
    }

    /// Lazily resolves an internal reference back to its public alias.
    ///
    /// This operation is required when a provider-neutral domain operation
    /// returns a file reference that must cross a public protocol boundary.
    /// Unknown, foreign, expired, and multiply mapped references must fail
    /// without exposing the internal reference bytes.
    fn resolve_reference<'a>(
        &'a self,
        scope: ProviderFileScope,
        reference: FileReference,
        context: &'a RequestContext,
    ) -> BoxProviderFileFuture<'a, Result<ProviderFileMapping, ProviderFilesError>> {
        Box::pin(async move {
            let _ = (scope, reference, context);
            Err(error(ProviderFilesErrorCode::Unavailable))
        })
    }

    /// Lazily lists one deterministic tenant-scoped mapping page.
    fn list<'a>(
        &'a self,
        request: ProviderFileListRequest,
        context: &'a RequestContext,
    ) -> BoxProviderFileFuture<'a, Result<ProviderFileMappingPage, ProviderFilesError>> {
        Box::pin(async move {
            let _ = (request, context);
            Err(error(ProviderFilesErrorCode::Unavailable))
        })
    }
}

/// A validated request to publish a new immutable public file alias.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderFilePublishRequest {
    scope: ProviderFileScope,
    metadata: ProviderFileMappingMetadata,
    idempotency_key: IdempotencyKey,
}

impl ProviderFilePublishRequest {
    /// Creates a publication request from checked scope, metadata, and replay key.
    #[must_use]
    pub const fn new(
        scope: ProviderFileScope,
        metadata: ProviderFileMappingMetadata,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            scope,
            metadata,
            idempotency_key,
        }
    }

    /// Returns the provider/account namespace.
    #[must_use]
    pub const fn scope(&self) -> &ProviderFileScope {
        &self.scope
    }

    /// Returns immutable file mapping metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ProviderFileMappingMetadata {
        &self.metadata
    }

    /// Returns opaque publication idempotency material.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

impl Debug for ProviderFilePublishRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFilePublishRequest")
            .field("scope", &self.scope)
            .field("metadata", &self.metadata)
            .field("idempotency_key", &"<redacted>")
            .finish()
    }
}

/// Publishes immutable public aliases for newly durable internal files.
///
/// Implementations own cryptographically unpredictable alias issuance,
/// tenant-scoped idempotency, collision handling, and durable publication. The
/// protocol adapter never derives an alias from `FileReference`, request text,
/// a clock, or a caller-selected identifier. Construction of the returned future
/// must perform no authentication, entropy access, lookup, or write.
pub trait ProviderFilePublisherPort: Send + Sync {
    /// Publishes one immutable alias or returns the exact prior mapping on replay.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted authentication, conflict, context, resource,
    /// availability, or internal failure. A commit-indeterminate outcome must be
    /// represented by the implementing durable boundary and must never cause the
    /// adapter to invent or retry with a different alias.
    fn publish<'a>(
        &'a self,
        request: ProviderFilePublishRequest,
        context: &'a RequestContext,
    ) -> BoxProviderFileFuture<'a, Result<ProviderFileMapping, ProviderFilesError>>;
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ProviderFileMappingKey {
    tenant_id: TenantId,
    provider: ProviderId,
    account_id: ProviderAccountId,
    provider_file_id: ProviderFileId,
}

/// An immutable, bounded mapping snapshot suitable for P4 composition.
///
/// The snapshot has no mutation methods. P5-owned persistence and routing can
/// replace the capability between requests, but cannot mutate a snapshot while
/// a lookup is in flight.
#[derive(Clone)]
pub struct StaticProviderFileMappings {
    entries: BTreeMap<ProviderFileMappingKey, ProviderFileMapping>,
}

impl StaticProviderFileMappings {
    /// Builds one immutable mapping snapshot from validated records.
    ///
    /// Duplicate `(tenant, provider, account, provider_file_id)` keys return
    /// [`ProviderFilesErrorCode::Conflict`]. More than
    /// [`MAX_PROVIDER_FILE_MAPPINGS`] records return
    /// [`ProviderFilesErrorCode::LimitExceeded`].
    pub fn new<I>(records: I) -> Result<Self, ProviderFilesError>
    where
        I: IntoIterator<Item = ProviderFileMapping>,
    {
        let mut entries = BTreeMap::new();
        for record in records {
            let key = record.key();
            if entries.contains_key(&key) {
                return Err(error(ProviderFilesErrorCode::Conflict));
            }
            if entries.len() >= MAX_PROVIDER_FILE_MAPPINGS {
                return Err(error(ProviderFilesErrorCode::LimitExceeded));
            }
            entries.insert(key, record);
        }
        Ok(Self { entries })
    }

    /// Returns the number of immutable records in the snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether the snapshot has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Debug for StaticProviderFileMappings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticProviderFileMappings")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl ProviderFileMappingPort for StaticProviderFileMappings {
    fn resolve<'a>(
        &'a self,
        lookup: ProviderFileLookup,
        context: &'a RequestContext,
    ) -> BoxProviderFileFuture<'a, Result<ProviderFileMapping, ProviderFilesError>> {
        Box::pin(async move {
            let principal = context
                .principal()
                .ok_or_else(|| error(ProviderFilesErrorCode::Unauthenticated))?;
            context.check_active().map_err(ProviderFilesError::from)?;
            let key = ProviderFileMappingKey {
                tenant_id: principal.tenant_id().clone(),
                provider: lookup.provider,
                account_id: lookup.account_id,
                provider_file_id: lookup.provider_file_id,
            };
            let mapping = self
                .entries
                .get(&key)
                .ok_or_else(|| error(ProviderFilesErrorCode::NotFound))?;
            if mapping.expired_at(SystemTime::now()) {
                return Err(error(ProviderFilesErrorCode::NotFound));
            }
            Ok(mapping.clone())
        })
    }

    fn resolve_reference<'a>(
        &'a self,
        scope: ProviderFileScope,
        reference: FileReference,
        context: &'a RequestContext,
    ) -> BoxProviderFileFuture<'a, Result<ProviderFileMapping, ProviderFilesError>> {
        Box::pin(async move {
            let tenant_id = authenticated_tenant(context)?;
            let now = SystemTime::now();
            let mut matches = self.entries.values().filter(|mapping| {
                mapping_matches_scope(mapping, tenant_id, &scope)
                    && mapping.file_reference == reference
                    && !mapping.expired_at(now)
            });
            let mapping = matches
                .next()
                .ok_or_else(|| error(ProviderFilesErrorCode::NotFound))?;
            if matches.next().is_some() {
                return Err(error(ProviderFilesErrorCode::Conflict));
            }
            Ok(mapping.clone())
        })
    }

    fn list<'a>(
        &'a self,
        request: ProviderFileListRequest,
        context: &'a RequestContext,
    ) -> BoxProviderFileFuture<'a, Result<ProviderFileMappingPage, ProviderFilesError>> {
        Box::pin(async move {
            let tenant_id = authenticated_tenant(context)?;
            let now = SystemTime::now();
            let mut data = Vec::with_capacity(request.limit.get().saturating_add(1));
            for mapping in self.entries.values() {
                if mapping_is_list_candidate(mapping, tenant_id, &request, now) {
                    data.push(mapping.clone());
                }
                if data.len() > request.limit.get() {
                    break;
                }
            }
            let has_more = data.len() > request.limit.get();
            if has_more {
                data.pop();
            }
            ProviderFileMappingPage::new(data, request.limit, has_more)
        })
    }
}

fn authenticated_tenant(context: &RequestContext) -> Result<&TenantId, ProviderFilesError> {
    let principal = context
        .principal()
        .ok_or_else(|| error(ProviderFilesErrorCode::Unauthenticated))?;
    context.check_active().map_err(ProviderFilesError::from)?;
    Ok(principal.tenant_id())
}

fn mapping_matches_scope(
    mapping: &ProviderFileMapping,
    tenant_id: &TenantId,
    scope: &ProviderFileScope,
) -> bool {
    mapping.tenant_id == *tenant_id
        && mapping.provider == scope.provider
        && mapping.account_id == scope.account_id
}

fn mapping_is_list_candidate(
    mapping: &ProviderFileMapping,
    tenant_id: &TenantId,
    request: &ProviderFileListRequest,
    now: SystemTime,
) -> bool {
    mapping_matches_scope(mapping, tenant_id, &request.scope)
        && !mapping.expired_at(now)
        && request
            .after
            .as_ref()
            .is_none_or(|after| mapping.provider_file_id > *after)
}

fn unix_seconds(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Compatibility alias for callers that use the singular error naming.
pub type ProviderFileError = ProviderFilesError;

/// Compatibility alias for callers that use the singular error-code naming.
pub type ProviderFileErrorCode = ProviderFilesErrorCode;

/// Compatibility alias for the immutable mapping snapshot.
pub type StaticProviderFileMapping = StaticProviderFileMappings;

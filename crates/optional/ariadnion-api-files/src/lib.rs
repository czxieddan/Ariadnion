// crates/optional/ariadnion-api-files/src/lib.rs - Rust source for Ariadnion.
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
//! Bounded provider-neutral file service values.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod catalog;
mod port;

use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroUsize;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, FileDescriptor, FileReference, FileUploadSpecification,
    IdempotencyKey,
};
use ariadnion_core::{CoreError, ErrorCode};

pub use catalog::FileCatalogRecord;
pub use port::{
    BoxFileFuture, FileCatalogPort, FileDownloadSink, FileReferenceIssuerPort, FileServicePort,
    FileUploadSource,
};

/// Maximum number of bytes carried by one in-memory file chunk.
pub const MAX_FILE_CHUNK_BYTES: usize = 65_536;
/// Maximum number of opaque bytes in one file-list cursor.
pub const MAX_FILE_LIST_CURSOR_BYTES: usize = 512;
/// Maximum number of file descriptors in one list page.
pub const MAX_FILE_PAGE_RESULTS: usize = 1_000;

/// Stable machine-readable failures returned by file operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ApiFilesErrorCode {
    /// A supplied value is empty or violates its documented syntax.
    InvalidArgument,
    /// A supplied value exceeds its documented hard limit.
    LimitExceeded,
    /// The operation has no authenticated principal.
    Unauthenticated,
    /// The requested file does not exist in authoritative state.
    NotFound,
    /// Current state conflicts with the requested operation.
    Conflict,
    /// Trusted file metadata or result state failed integrity validation.
    IntegrityFailure,
    /// Authoritative policy rejected the operation.
    PolicyRejected,
    /// Cancellation stopped the operation.
    Cancelled,
    /// The operation exceeded its declared deadline.
    DeadlineExceeded,
    /// A bounded resource budget was exhausted.
    ResourceExhausted,
    /// A required file capability is unavailable.
    Unavailable,
    /// Durable commit may have completed and requires reconciliation.
    CommitIndeterminate,
    /// The operation failed without a safe external explanation.
    Internal,
}

impl ApiFilesErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "API_FILES_INVALID_ARGUMENT",
            Self::LimitExceeded => "API_FILES_LIMIT_EXCEEDED",
            Self::Unauthenticated => "API_FILES_UNAUTHENTICATED",
            Self::NotFound => "API_FILES_NOT_FOUND",
            Self::Conflict => "API_FILES_CONFLICT",
            Self::IntegrityFailure => "API_FILES_INTEGRITY_FAILURE",
            Self::PolicyRejected
            | Self::Cancelled
            | Self::DeadlineExceeded
            | Self::ResourceExhausted
            | Self::Unavailable
            | Self::CommitIndeterminate
            | Self::Internal => execution_machine_code(self),
        }
    }
}

const fn execution_machine_code(code: ApiFilesErrorCode) -> &'static str {
    match code {
        ApiFilesErrorCode::PolicyRejected => "API_FILES_POLICY_REJECTED",
        ApiFilesErrorCode::Cancelled => "API_FILES_CANCELLED",
        ApiFilesErrorCode::DeadlineExceeded => "API_FILES_DEADLINE_EXCEEDED",
        ApiFilesErrorCode::ResourceExhausted => "API_FILES_RESOURCE_EXHAUSTED",
        ApiFilesErrorCode::Unavailable => "API_FILES_UNAVAILABLE",
        ApiFilesErrorCode::CommitIndeterminate => "API_FILES_COMMIT_INDETERMINATE",
        ApiFilesErrorCode::Internal => "API_FILES_INTERNAL",
        _ => "API_FILES_INTERNAL",
    }
}

/// A redacted file-operation error that retains only its stable code.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApiFilesError {
    code: ApiFilesErrorCode,
}

impl ApiFilesError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: ApiFilesErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ApiFilesErrorCode {
        self.code
    }
}

impl Debug for ApiFilesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApiFilesError({})", self.code.as_str())
    }
}

impl Display for ApiFilesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ApiFilesError {}

impl From<CoreError> for ApiFilesError {
    fn from(value: CoreError) -> Self {
        Self::new(project_core_error(value.code()))
    }
}

impl From<ApiDomainError> for ApiFilesError {
    fn from(value: ApiDomainError) -> Self {
        Self::new(project_domain_error(value.code()))
    }
}

const fn project_core_error(code: ErrorCode) -> ApiFilesErrorCode {
    match code {
        ErrorCode::InvalidArgument => ApiFilesErrorCode::InvalidArgument,
        ErrorCode::Conflict => ApiFilesErrorCode::Conflict,
        ErrorCode::Cancelled => ApiFilesErrorCode::Cancelled,
        ErrorCode::DeadlineExceeded => ApiFilesErrorCode::DeadlineExceeded,
        ErrorCode::ResourceExhausted => ApiFilesErrorCode::ResourceExhausted,
        ErrorCode::Unavailable => ApiFilesErrorCode::Unavailable,
        ErrorCode::Internal => ApiFilesErrorCode::Internal,
    }
}

const fn project_domain_error(code: ApiDomainErrorCode) -> ApiFilesErrorCode {
    match code {
        ApiDomainErrorCode::InvalidArgument | ApiDomainErrorCode::UnsupportedVersion => {
            ApiFilesErrorCode::InvalidArgument
        }
        ApiDomainErrorCode::LimitExceeded => ApiFilesErrorCode::LimitExceeded,
        ApiDomainErrorCode::Conflict => ApiFilesErrorCode::Conflict,
        ApiDomainErrorCode::Cancelled => ApiFilesErrorCode::Cancelled,
        _ => project_domain_service_error(code),
    }
}

const fn project_domain_service_error(code: ApiDomainErrorCode) -> ApiFilesErrorCode {
    match code {
        ApiDomainErrorCode::DeadlineExceeded => ApiFilesErrorCode::DeadlineExceeded,
        ApiDomainErrorCode::ResourceExhausted => ApiFilesErrorCode::ResourceExhausted,
        ApiDomainErrorCode::Unavailable => ApiFilesErrorCode::Unavailable,
        ApiDomainErrorCode::Internal => ApiFilesErrorCode::Internal,
        _ => ApiFilesErrorCode::Internal,
    }
}

/// One non-empty bounded chunk of file bytes.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FileChunk(Vec<u8>);

impl FileChunk {
    /// Validates and owns one file byte chunk.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::InvalidArgument`] for an empty chunk and
    /// [`ApiFilesErrorCode::LimitExceeded`] above 64 KiB.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ApiFilesError> {
        validate_non_empty_length(bytes.len(), MAX_FILE_CHUNK_BYTES)?;
        Ok(Self(bytes))
    }

    /// Returns the owned file bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the chunk length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the chunk is empty.
    ///
    /// Valid construction guarantees this always returns `false`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the chunk and returns its owned bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Debug for FileChunk {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileChunk")
            .field("byte_count", &self.len())
            .finish_non_exhaustive()
    }
}

/// One copied, non-empty opaque cursor issued by a trusted file service.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FileListCursor(Box<[u8]>);

impl FileListCursor {
    /// Validates and copies one opaque list cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::InvalidArgument`] for an empty cursor and
    /// [`ApiFilesErrorCode::LimitExceeded`] above 512 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, ApiFilesError> {
        validate_non_empty_length(bytes.len(), MAX_FILE_LIST_CURSOR_BYTES)?;
        Ok(Self(bytes.into()))
    }

    /// Returns the opaque cursor bytes to a trusted file adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for FileListCursor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileListCursor")
            .field("byte_count", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A validated non-zero maximum number of file descriptors in one page.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FilePageLimit(NonZeroUsize);

impl FilePageLimit {
    /// Validates a requested page size.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::InvalidArgument`] for zero and
    /// [`ApiFilesErrorCode::LimitExceeded`] above 1,000 results.
    pub const fn new(value: usize) -> Result<Self, ApiFilesError> {
        if value > MAX_FILE_PAGE_RESULTS {
            return Err(error(ApiFilesErrorCode::LimitExceeded));
        }
        let Some(value) = NonZeroUsize::new(value) else {
            return Err(error(ApiFilesErrorCode::InvalidArgument));
        };
        Ok(Self(value))
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// One bounded request for a page of file descriptors.
#[derive(Clone, Eq, PartialEq)]
pub struct FileListRequest {
    cursor: Option<FileListCursor>,
    limit: FilePageLimit,
}

impl FileListRequest {
    /// Owns a validated cursor and page limit.
    #[must_use]
    pub const fn new(cursor: Option<FileListCursor>, limit: FilePageLimit) -> Self {
        Self { cursor, limit }
    }

    /// Returns the optional opaque continuation cursor.
    #[must_use]
    pub const fn cursor(&self) -> Option<&FileListCursor> {
        self.cursor.as_ref()
    }

    /// Returns the requested page result limit.
    #[must_use]
    pub const fn limit(&self) -> FilePageLimit {
        self.limit
    }
}

impl Debug for FileListRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileListRequest")
            .field("cursor_present", &self.cursor.is_some())
            .field("limit", &self.limit)
            .finish()
    }
}

/// One integrity-checked page returned by a trusted file service.
#[derive(Clone, Eq, PartialEq)]
pub struct FileListPage {
    files: Box<[FileDescriptor]>,
    next_cursor: Option<FileListCursor>,
}

impl FileListPage {
    /// Validates and owns one page of file descriptors and its next cursor.
    ///
    /// The descriptor count must not exceed the request limit. An empty page
    /// cannot carry a next cursor because that result would not make progress.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::IntegrityFailure`] when either result
    /// invariant is violated.
    pub fn new(
        files: Vec<FileDescriptor>,
        next_cursor: Option<FileListCursor>,
        requested_limit: FilePageLimit,
    ) -> Result<Self, ApiFilesError> {
        validate_page_result(files.len(), next_cursor.is_some(), requested_limit)?;
        Ok(Self {
            files: files.into_boxed_slice(),
            next_cursor,
        })
    }

    /// Returns the verified file descriptors in this page.
    #[must_use]
    pub fn files(&self) -> &[FileDescriptor] {
        &self.files
    }

    /// Returns the optional cursor for the next page.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<&FileListCursor> {
        self.next_cursor.as_ref()
    }
}

impl Debug for FileListPage {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileListPage")
            .field("result_count", &self.files.len())
            .field("next_cursor_present", &self.next_cursor.is_some())
            .finish()
    }
}

/// One validated upload request and its opaque idempotency key.
#[derive(Clone, Eq, PartialEq)]
pub struct FileUploadRequest {
    specification: FileUploadSpecification,
    idempotency_key: IdempotencyKey,
}

impl FileUploadRequest {
    /// Owns validated upload metadata and idempotency material.
    #[must_use]
    pub const fn new(
        specification: FileUploadSpecification,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            specification,
            idempotency_key,
        }
    }

    /// Returns the validated upload metadata.
    #[must_use]
    pub const fn specification(&self) -> &FileUploadSpecification {
        &self.specification
    }

    /// Returns the opaque idempotency key to a trusted adapter.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

impl Debug for FileUploadRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileUploadRequest")
            .finish_non_exhaustive()
    }
}

/// One validated file deletion request and its opaque idempotency key.
#[derive(Clone, Eq, PartialEq)]
pub struct FileDeleteRequest {
    reference: FileReference,
    idempotency_key: IdempotencyKey,
}

impl FileDeleteRequest {
    /// Owns a service-issued file reference and validated idempotency material.
    #[must_use]
    pub const fn new(reference: FileReference, idempotency_key: IdempotencyKey) -> Self {
        Self {
            reference,
            idempotency_key,
        }
    }

    /// Returns the opaque file reference to a trusted adapter.
    #[must_use]
    pub const fn reference(&self) -> &FileReference {
        &self.reference
    }

    /// Returns the opaque idempotency key to a trusted adapter.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

impl Debug for FileDeleteRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileDeleteRequest")
            .finish_non_exhaustive()
    }
}

/// Authoritative reconciliation result for an indeterminate upload commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileUploadReconciliation {
    /// The upload committed with the returned verified descriptor.
    Committed(FileDescriptor),
    /// The upload did not commit.
    NotCommitted,
}

/// Authoritative reconciliation result for an indeterminate deletion commit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FileDeleteReconciliation {
    /// The file was deleted.
    Deleted,
    /// The file was not deleted.
    NotDeleted,
}

const fn error(code: ApiFilesErrorCode) -> ApiFilesError {
    ApiFilesError::new(code)
}

fn validate_non_empty_length(length: usize, maximum: usize) -> Result<(), ApiFilesError> {
    if length > maximum {
        return Err(error(ApiFilesErrorCode::LimitExceeded));
    }
    if length == 0 {
        return Err(error(ApiFilesErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_page_result(
    result_count: usize,
    next_cursor_present: bool,
    requested_limit: FilePageLimit,
) -> Result<(), ApiFilesError> {
    if result_count > requested_limit.get() || (result_count == 0 && next_cursor_present) {
        return Err(error(ApiFilesErrorCode::IntegrityFailure));
    }
    Ok(())
}

// crates/optional/ariadnion-api-domain/src/batch.rs - Bounded Batch contracts for Ariadnion.
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
//! Provider-neutral, bounded Batch operation values and ports.

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use ariadnion_core::{CoreError, ErrorCode};

use crate::{ApiDomainError, ApiDomainErrorCode, FileByteLength, FileReference, IdempotencyKey};

mod port;
mod timestamps;

pub use port::{BatchOperationPort, BatchPage, BoxBatchFuture};
pub use timestamps::{BatchTimestampTransitions, BatchTimestamps};

/// Maximum encoded size of one Batch input file in bytes.
pub const MAX_BATCH_INPUT_BYTES: usize = 200 * 1024 * 1024;
/// Maximum number of non-empty JSONL requests in one Batch input file.
pub const MAX_BATCH_REQUESTS: usize = 50_000;
/// Maximum encoded size of one caller-provided Batch custom identifier.
pub const MAX_BATCH_CUSTOM_ID_BYTES: usize = 512;
/// Maximum encoded size of one durable Batch operation identifier.
pub const MAX_BATCH_OPERATION_ID_BYTES: usize = 128;
/// Maximum number of itemized validation errors retained in one Batch object.
pub const MAX_BATCH_ERROR_ITEMS: usize = 1_000;
/// Default number of Batch objects returned by one list request.
pub const DEFAULT_BATCH_LIST_LIMIT: usize = 20;
/// Maximum number of Batch objects returned by one list request.
pub const MAX_BATCH_LIST_LIMIT: usize = 100;

/// Stable machine-readable failures returned by the Batch contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ApiBatchErrorCode {
    /// A supplied value is empty or violates its documented syntax.
    InvalidArgument,
    /// A supplied value exceeds a documented hard limit.
    LimitExceeded,
    /// The request has no authenticated tenant context.
    Unauthenticated,
    /// The requested Batch operation is not visible in authoritative state.
    NotFound,
    /// The requested operation conflicts with authoritative state.
    Conflict,
    /// Trusted operation evidence failed integrity validation.
    IntegrityFailure,
    /// Request cancellation stopped the operation.
    Cancelled,
    /// The request deadline expired before the operation completed.
    DeadlineExceeded,
    /// A bounded operation resource budget was exhausted.
    ResourceExhausted,
    /// The injected durable operation capability is unavailable.
    Unavailable,
    /// The operation failed without a safe external explanation.
    Internal,
}

impl ApiBatchErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument
            | Self::LimitExceeded
            | Self::Unauthenticated
            | Self::NotFound
            | Self::Conflict
            | Self::IntegrityFailure => request_error_code(self),
            Self::Cancelled
            | Self::DeadlineExceeded
            | Self::ResourceExhausted
            | Self::Unavailable
            | Self::Internal => execution_error_code(self),
        }
    }
}

const fn request_error_code(code: ApiBatchErrorCode) -> &'static str {
    match code {
        ApiBatchErrorCode::InvalidArgument => "API_BATCH_INVALID_ARGUMENT",
        ApiBatchErrorCode::LimitExceeded => "API_BATCH_LIMIT_EXCEEDED",
        ApiBatchErrorCode::Unauthenticated => "API_BATCH_UNAUTHENTICATED",
        ApiBatchErrorCode::NotFound => "API_BATCH_NOT_FOUND",
        ApiBatchErrorCode::Conflict => "API_BATCH_CONFLICT",
        ApiBatchErrorCode::IntegrityFailure => "API_BATCH_INTEGRITY_FAILURE",
        _ => "API_BATCH_INTERNAL",
    }
}

const fn execution_error_code(code: ApiBatchErrorCode) -> &'static str {
    match code {
        ApiBatchErrorCode::Cancelled => "API_BATCH_CANCELLED",
        ApiBatchErrorCode::DeadlineExceeded => "API_BATCH_DEADLINE_EXCEEDED",
        ApiBatchErrorCode::ResourceExhausted => "API_BATCH_RESOURCE_EXHAUSTED",
        ApiBatchErrorCode::Unavailable => "API_BATCH_UNAVAILABLE",
        ApiBatchErrorCode::Internal => "API_BATCH_INTERNAL",
        _ => "API_BATCH_INTERNAL",
    }
}

/// A redacted Batch error that retains only its stable code.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApiBatchError {
    code: ApiBatchErrorCode,
}

impl ApiBatchError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: ApiBatchErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ApiBatchErrorCode {
        self.code
    }
}

impl Debug for ApiBatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApiBatchError({})", self.code.as_str())
    }
}

impl Display for ApiBatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ApiBatchError {}

impl From<ApiDomainError> for ApiBatchError {
    fn from(value: ApiDomainError) -> Self {
        Self::new(map_domain_error(value.code()))
    }
}

impl From<CoreError> for ApiBatchError {
    fn from(value: CoreError) -> Self {
        Self::new(map_core_error(value.code()))
    }
}

fn map_domain_error(code: ApiDomainErrorCode) -> ApiBatchErrorCode {
    match code {
        ApiDomainErrorCode::InvalidArgument | ApiDomainErrorCode::UnsupportedVersion => {
            ApiBatchErrorCode::InvalidArgument
        }
        other => map_domain_execution_error(other),
    }
}

fn map_domain_execution_error(code: ApiDomainErrorCode) -> ApiBatchErrorCode {
    match code {
        ApiDomainErrorCode::InvalidArgument | ApiDomainErrorCode::UnsupportedVersion => {
            ApiBatchErrorCode::InvalidArgument
        }
        ApiDomainErrorCode::LimitExceeded => ApiBatchErrorCode::LimitExceeded,
        ApiDomainErrorCode::Conflict => ApiBatchErrorCode::Conflict,
        other => map_domain_runtime_error(other),
    }
}

fn map_domain_runtime_error(code: ApiDomainErrorCode) -> ApiBatchErrorCode {
    match code {
        ApiDomainErrorCode::Cancelled => ApiBatchErrorCode::Cancelled,
        ApiDomainErrorCode::DeadlineExceeded => ApiBatchErrorCode::DeadlineExceeded,
        ApiDomainErrorCode::Unavailable => ApiBatchErrorCode::Unavailable,
        ApiDomainErrorCode::ResourceExhausted => ApiBatchErrorCode::ResourceExhausted,
        ApiDomainErrorCode::Internal => ApiBatchErrorCode::Internal,
        _ => ApiBatchErrorCode::Internal,
    }
}

fn map_core_error(code: ErrorCode) -> ApiBatchErrorCode {
    match code {
        ErrorCode::InvalidArgument => ApiBatchErrorCode::InvalidArgument,
        ErrorCode::Conflict => ApiBatchErrorCode::Conflict,
        ErrorCode::Cancelled => ApiBatchErrorCode::Cancelled,
        ErrorCode::DeadlineExceeded => ApiBatchErrorCode::DeadlineExceeded,
        ErrorCode::Unavailable => ApiBatchErrorCode::Unavailable,
        ErrorCode::ResourceExhausted => ApiBatchErrorCode::ResourceExhausted,
        ErrorCode::Internal => ApiBatchErrorCode::Internal,
    }
}

const fn invalid_argument() -> ApiBatchError {
    ApiBatchError::new(ApiBatchErrorCode::InvalidArgument)
}

const fn limit_exceeded() -> ApiBatchError {
    ApiBatchError::new(ApiBatchErrorCode::LimitExceeded)
}

const fn conflict() -> ApiBatchError {
    ApiBatchError::new(ApiBatchErrorCode::Conflict)
}

const fn integrity_failure() -> ApiBatchError {
    ApiBatchError::new(ApiBatchErrorCode::IntegrityFailure)
}

/// An endpoint whose request grammar is implemented by the P4 Batch profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BatchEndpoint {
    /// OpenAI Responses requests.
    Responses,
    /// OpenAI Chat Completions requests.
    ChatCompletions,
    /// OpenAI Embeddings requests.
    Embeddings,
    /// OpenAI legacy Completions requests.
    Completions,
    /// OpenAI image-generation requests.
    ImagesGenerations,
}

impl BatchEndpoint {
    /// Parses one exact supported endpoint path.
    ///
    /// Endpoints owned by later phases, including moderation, image edits, and
    /// video generation, are rejected rather than silently accepted for a future
    /// decoder.
    ///
    /// # Errors
    ///
    /// Returns [`ApiBatchErrorCode::InvalidArgument`] for every unsupported path.
    pub fn parse(value: &str) -> Result<Self, ApiBatchError> {
        match value {
            "/v1/responses" => Ok(Self::Responses),
            "/v1/chat/completions" => Ok(Self::ChatCompletions),
            "/v1/embeddings" => Ok(Self::Embeddings),
            "/v1/completions" => Ok(Self::Completions),
            "/v1/images/generations" => Ok(Self::ImagesGenerations),
            _ => Err(invalid_argument()),
        }
    }

    /// Returns the exact relative endpoint path used in a JSONL request line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Responses => "/v1/responses",
            Self::ChatCompletions => "/v1/chat/completions",
            Self::Embeddings => "/v1/embeddings",
            Self::Completions => "/v1/completions",
            Self::ImagesGenerations => "/v1/images/generations",
        }
    }
}

impl Display for BatchEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The only completion window accepted by the P4 Batch profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BatchCompletionWindow {
    /// The owner-defined twenty-four-hour window.
    Hours24,
}

impl BatchCompletionWindow {
    /// Parses the exact owner-defined completion-window value.
    ///
    /// # Errors
    ///
    /// Returns [`ApiBatchErrorCode::InvalidArgument`] for every value other than
    /// `24h`.
    pub fn parse(value: &str) -> Result<Self, ApiBatchError> {
        match value {
            "24h" => Ok(Self::Hours24),
            _ => Err(invalid_argument()),
        }
    }

    /// Returns the exact completion-window value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "24h"
    }
}

impl Display for BatchCompletionWindow {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded durable operation identifier returned by an injected operation port.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchOperationId(Box<str>);

impl BatchOperationId {
    /// Parses an ASCII operation identity without exposing rejected input.
    ///
    /// The value is limited to 128 bytes and accepts only ASCII letters, digits,
    /// `.`, `-`, `_`, and `:` so it can be safely embedded in a route segment.
    ///
    /// # Errors
    ///
    /// Returns [`ApiBatchErrorCode::InvalidArgument`] for empty, non-ASCII, or
    /// malformed values and [`ApiBatchErrorCode::LimitExceeded`] above the bound.
    pub fn parse(value: &str) -> Result<Self, ApiBatchError> {
        if value.len() > MAX_BATCH_OPERATION_ID_BYTES {
            return Err(limit_exceeded());
        }
        if value.is_empty() || !value.is_ascii() || !value.bytes().all(valid_identifier_byte) {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated operation identity for wire serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for BatchOperationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchOperationId")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Display for BatchOperationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for BatchOperationId {
    type Err = ApiBatchError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// A bounded caller-unique identifier attached to one JSONL request line.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchCustomId(Box<str>);

impl BatchCustomId {
    /// Validates and copies one caller-provided custom identifier.
    ///
    /// Control characters and NUL are rejected. Other UTF-8 text is preserved so
    /// the protocol adapter can apply the owner grammar without lossy conversion.
    ///
    /// # Errors
    ///
    /// Returns [`ApiBatchErrorCode::InvalidArgument`] for empty or control-bearing
    /// values and [`ApiBatchErrorCode::LimitExceeded`] above the byte bound.
    pub fn new(value: &str) -> Result<Self, ApiBatchError> {
        if value.len() > MAX_BATCH_CUSTOM_ID_BYTES {
            return Err(limit_exceeded());
        }
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated custom identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for BatchCustomId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchCustomId")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// One validated JSONL request-line summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRequestLine {
    custom_id: BatchCustomId,
    endpoint: BatchEndpoint,
}

impl BatchRequestLine {
    /// Creates a request-line summary for the fixed `POST` method.
    ///
    /// The method is intentionally not a runtime string: this type represents
    /// only the owner-required `POST` grammar. The request body is validated by
    /// the protocol adapter before this summary crosses the domain boundary.
    ///
    /// # Errors
    ///
    /// Returns a bounded identifier error from [`BatchCustomId::new`].
    pub fn new(custom_id: &str, endpoint: BatchEndpoint) -> Result<Self, ApiBatchError> {
        Ok(Self {
            custom_id: BatchCustomId::new(custom_id)?,
            endpoint,
        })
    }

    /// Returns the caller-unique identifier.
    #[must_use]
    pub const fn custom_id(&self) -> &BatchCustomId {
        &self.custom_id
    }

    /// Returns the validated relative endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> BatchEndpoint {
        self.endpoint
    }

    /// Returns the fixed HTTP method represented by this line.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        "POST"
    }
}

/// A bounded validation summary for one tenant-scoped Batch input file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchInputFile {
    reference: FileReference,
    byte_length: FileByteLength,
    lines: Box<[BatchRequestLine]>,
}

impl BatchInputFile {
    /// Builds a bounded summary from validated JSONL request-line summaries.
    ///
    /// The iterator is consumed only until the hard request limit is exceeded;
    /// no request body bytes are retained. Duplicate custom identifiers are
    /// rejected before the summary becomes available to a durable operation port.
    /// The supplied reference is the internal [`FileReference`] after the public
    /// provider alias has already been resolved by an adapter.
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` for files above 200 MiB or more than 50,000 lines,
    /// `InvalidArgument` for an empty input, and `Conflict` for duplicate IDs.
    pub fn from_lines<I>(
        reference: FileReference,
        byte_length: FileByteLength,
        lines: I,
    ) -> Result<Self, ApiBatchError>
    where
        I: IntoIterator<Item = BatchRequestLine>,
    {
        validate_input_size(byte_length)?;
        let owned = collect_lines(lines)?;
        if owned.is_empty() {
            return Err(invalid_argument());
        }
        Ok(Self {
            reference,
            byte_length,
            lines: owned.into_boxed_slice(),
        })
    }

    /// Returns the tenant-scoped durable file reference.
    #[must_use]
    pub const fn reference(&self) -> &FileReference {
        &self.reference
    }

    /// Returns the verified input byte length.
    #[must_use]
    pub const fn byte_length(&self) -> FileByteLength {
        self.byte_length
    }

    /// Returns the number of validated request lines.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Returns the bounded request-line summaries in source order.
    #[must_use]
    pub fn lines(&self) -> &[BatchRequestLine] {
        &self.lines
    }

    /// Returns whether every line targets the supplied endpoint.
    #[must_use]
    pub fn targets(&self, endpoint: BatchEndpoint) -> bool {
        self.lines.iter().all(|line| line.endpoint() == endpoint)
    }
}

fn collect_lines<I>(lines: I) -> Result<Vec<BatchRequestLine>, ApiBatchError>
where
    I: IntoIterator<Item = BatchRequestLine>,
{
    let mut owned = Vec::new();
    let mut identifiers = BTreeSet::new();
    for line in lines {
        if owned.len() >= MAX_BATCH_REQUESTS {
            return Err(limit_exceeded());
        }
        if !identifiers.insert(line.custom_id.clone()) {
            return Err(conflict());
        }
        owned.push(line);
    }
    Ok(owned)
}

fn validate_input_size(byte_length: FileByteLength) -> Result<(), ApiBatchError> {
    if byte_length.get() > MAX_BATCH_INPUT_BYTES {
        return Err(limit_exceeded());
    }
    Ok(())
}

/// A validated Batch create request passed to the durable operation port.
#[derive(Clone, Eq, PartialEq)]
pub struct BatchCreateRequest {
    input_file: BatchInputFile,
    endpoint: BatchEndpoint,
    completion_window: BatchCompletionWindow,
    idempotency_key: Option<IdempotencyKey>,
}

impl BatchCreateRequest {
    /// Creates a Batch request after checking endpoint parity with every input line.
    ///
    /// The request contains only validated metadata and an internal
    /// [`FileReference`]. It does not execute or queue any JSONL body. The
    /// operation port remains responsible for durable identity, lifecycle, and
    /// restart recovery.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` when one line targets a different endpoint.
    #[must_use = "validate the request before dispatching it"]
    pub fn new(
        input_file: BatchInputFile,
        endpoint: BatchEndpoint,
        completion_window: BatchCompletionWindow,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Result<Self, ApiBatchError> {
        if !input_file.targets(endpoint) {
            return Err(invalid_argument());
        }
        Ok(Self {
            input_file,
            endpoint,
            completion_window,
            idempotency_key,
        })
    }

    /// Returns the bounded input-file summary.
    #[must_use]
    pub const fn input_file(&self) -> &BatchInputFile {
        &self.input_file
    }

    /// Returns the selected endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> BatchEndpoint {
        self.endpoint
    }

    /// Returns the completion window.
    #[must_use]
    pub const fn completion_window(&self) -> BatchCompletionWindow {
        self.completion_window
    }

    /// Returns the optional idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

impl Debug for BatchCreateRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchCreateRequest")
            .field("input_file", &self.input_file)
            .field("endpoint", &self.endpoint)
            .field("completion_window", &self.completion_window)
            .field(
                "idempotency_key",
                &self.idempotency_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A validated request to cancel one Batch operation.
#[derive(Clone, Eq, PartialEq)]
pub struct BatchCancelRequest {
    operation_id: BatchOperationId,
    idempotency_key: Option<IdempotencyKey>,
}

impl BatchCancelRequest {
    /// Creates a cancellation request for one operation identity.
    #[must_use]
    pub const fn new(
        operation_id: BatchOperationId,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Self {
        Self {
            operation_id,
            idempotency_key,
        }
    }

    /// Returns the operation identity to cancel.
    #[must_use]
    pub const fn operation_id(&self) -> &BatchOperationId {
        &self.operation_id
    }

    /// Returns the optional idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

impl Debug for BatchCancelRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchCancelRequest")
            .field("operation_id", &self.operation_id)
            .field(
                "idempotency_key",
                &self.idempotency_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A validated bounded list limit.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchListLimit(usize);

impl BatchListLimit {
    /// Validates a public Batch list limit in the inclusive `1..=100` range.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for zero and `LimitExceeded` above 100.
    pub const fn new(value: usize) -> Result<Self, ApiBatchError> {
        if value == 0 {
            return Err(invalid_argument());
        }
        if value > MAX_BATCH_LIST_LIMIT {
            return Err(limit_exceeded());
        }
        Ok(Self(value))
    }

    /// Returns the validated list limit.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl Default for BatchListLimit {
    fn default() -> Self {
        Self(DEFAULT_BATCH_LIST_LIMIT)
    }
}

/// A cursor and limit for one Batch list operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchListRequest {
    after: Option<BatchOperationId>,
    limit: BatchListLimit,
}

impl BatchListRequest {
    /// Creates a bounded list request.
    #[must_use]
    pub const fn new(after: Option<BatchOperationId>, limit: BatchListLimit) -> Self {
        Self { after, limit }
    }

    /// Returns the optional exclusive cursor.
    #[must_use]
    pub const fn after(&self) -> Option<&BatchOperationId> {
        self.after.as_ref()
    }

    /// Returns the requested result limit.
    #[must_use]
    pub const fn limit(&self) -> BatchListLimit {
        self.limit
    }
}

/// A bounded lifecycle status for one Batch operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BatchStatus {
    /// Input is being validated.
    Validating,
    /// Input validation or execution failed.
    Failed,
    /// Requests are being processed.
    InProgress,
    /// Output files are being finalized.
    Finalizing,
    /// The operation completed successfully.
    Completed,
    /// The completion window expired.
    Expired,
    /// Cancellation has been requested.
    Cancelling,
    /// Cancellation completed.
    Cancelled,
}

impl BatchStatus {
    /// Parses one exact owner-defined lifecycle status.
    ///
    /// # Errors
    ///
    /// Returns [`ApiBatchErrorCode::InvalidArgument`] for unknown statuses.
    pub fn parse(value: &str) -> Result<Self, ApiBatchError> {
        parse_status(value).ok_or_else(invalid_argument)
    }

    /// Returns the exact wire status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validating | Self::Failed | Self::InProgress | Self::Finalizing => {
                active_status_text(self)
            }
            Self::Completed | Self::Expired | Self::Cancelling | Self::Cancelled => {
                terminal_status_text(self)
            }
        }
    }
}

fn parse_status(value: &str) -> Option<BatchStatus> {
    match value {
        "validating" => Some(BatchStatus::Validating),
        "failed" => Some(BatchStatus::Failed),
        "in_progress" => Some(BatchStatus::InProgress),
        "finalizing" => Some(BatchStatus::Finalizing),
        _ => parse_terminal_status(value),
    }
}

fn parse_terminal_status(value: &str) -> Option<BatchStatus> {
    match value {
        "completed" => Some(BatchStatus::Completed),
        "expired" => Some(BatchStatus::Expired),
        "cancelling" => Some(BatchStatus::Cancelling),
        "cancelled" => Some(BatchStatus::Cancelled),
        _ => None,
    }
}

const fn active_status_text(status: BatchStatus) -> &'static str {
    match status {
        BatchStatus::Validating => "validating",
        BatchStatus::Failed => "failed",
        BatchStatus::InProgress => "in_progress",
        BatchStatus::Finalizing => "finalizing",
        _ => "internal",
    }
}

const fn terminal_status_text(status: BatchStatus) -> &'static str {
    match status {
        BatchStatus::Completed => "completed",
        BatchStatus::Expired => "expired",
        BatchStatus::Cancelling => "cancelling",
        BatchStatus::Cancelled => "cancelled",
        _ => "internal",
    }
}

impl Display for BatchStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One bounded itemized validation or execution error in a Batch object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchValidationError {
    code: ApiBatchErrorCode,
    line: Option<u32>,
}

impl BatchValidationError {
    /// Creates a redacted error optionally associated with a one-based line number.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for a zero line number.
    pub const fn new(code: ApiBatchErrorCode, line: Option<u32>) -> Result<Self, ApiBatchError> {
        if matches!(line, Some(0)) {
            return Err(invalid_argument());
        }
        Ok(Self { code, line })
    }

    /// Returns the stable item error code.
    #[must_use]
    pub const fn code(self) -> ApiBatchErrorCode {
        self.code
    }

    /// Returns the optional one-based input line number.
    #[must_use]
    pub const fn line(self) -> Option<u32> {
        self.line
    }
}

/// Request counts reported by authoritative Batch operation evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchRequestCounts {
    total: u32,
    completed: u32,
    failed: u32,
}

impl BatchRequestCounts {
    /// Creates counts that remain within the input bound and sum consistently.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for zero totals or inconsistent values and
    /// `LimitExceeded` above the 50,000-request bound.
    pub const fn new(total: u32, completed: u32, failed: u32) -> Result<Self, ApiBatchError> {
        if let Err(error) = validate_count_total(total) {
            return Err(error);
        }
        let processed = match completed.checked_add(failed) {
            Some(processed) => processed,
            None => return Err(invalid_argument()),
        };
        if let Err(error) = validate_count_values(total, completed, failed, processed) {
            return Err(error);
        }
        Ok(Self {
            total,
            completed,
            failed,
        })
    }

    /// Returns the total input request count.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.total
    }

    /// Returns the completed request count.
    #[must_use]
    pub const fn completed(self) -> u32 {
        self.completed
    }

    /// Returns the failed request count.
    #[must_use]
    pub const fn failed(self) -> u32 {
        self.failed
    }
}

const fn validate_count_total(total: u32) -> Result<(), ApiBatchError> {
    if total == 0 {
        return Err(invalid_argument());
    }
    if total as usize > MAX_BATCH_REQUESTS {
        return Err(limit_exceeded());
    }
    Ok(())
}

const fn validate_count_values(
    total: u32,
    completed: u32,
    failed: u32,
    processed: u32,
) -> Result<(), ApiBatchError> {
    if completed > total || failed > total || processed > total {
        return Err(invalid_argument());
    }
    Ok(())
}

/// One authoritative Batch operation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchOperation {
    id: BatchOperationId,
    endpoint: BatchEndpoint,
    input_file: FileReference,
    completion_window: BatchCompletionWindow,
    status: BatchStatus,
    timestamps: BatchTimestamps,
    output_file: Option<FileReference>,
    error_file: Option<FileReference>,
    errors: Box<[BatchValidationError]>,
    request_counts: BatchRequestCounts,
}

/// Non-identity evidence attached to one Batch operation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchOperationEvidence {
    timestamps: BatchTimestamps,
    output_file: Option<FileReference>,
    error_file: Option<FileReference>,
    errors: Box<[BatchValidationError]>,
    request_counts: BatchRequestCounts,
}

impl BatchOperationEvidence {
    /// Creates bounded lifecycle, file, error, and count evidence.
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` above [`MAX_BATCH_ERROR_ITEMS`].
    pub fn new(
        timestamps: BatchTimestamps,
        output_file: Option<FileReference>,
        error_file: Option<FileReference>,
        errors: Vec<BatchValidationError>,
        request_counts: BatchRequestCounts,
    ) -> Result<Self, ApiBatchError> {
        if errors.len() > MAX_BATCH_ERROR_ITEMS {
            return Err(limit_exceeded());
        }
        Ok(Self {
            timestamps,
            output_file,
            error_file,
            errors: errors.into_boxed_slice(),
            request_counts,
        })
    }

    /// Returns lifecycle timestamps.
    #[must_use]
    pub const fn timestamps(&self) -> BatchTimestamps {
        self.timestamps
    }

    /// Returns the optional output-file reference.
    #[must_use]
    pub const fn output_file(&self) -> Option<&FileReference> {
        self.output_file.as_ref()
    }

    /// Returns the optional error-file reference.
    #[must_use]
    pub const fn error_file(&self) -> Option<&FileReference> {
        self.error_file.as_ref()
    }

    /// Returns bounded itemized errors.
    #[must_use]
    pub fn errors(&self) -> &[BatchValidationError] {
        &self.errors
    }

    /// Returns authoritative request counts.
    #[must_use]
    pub const fn request_counts(&self) -> BatchRequestCounts {
        self.request_counts
    }
}

impl BatchOperation {
    /// Creates a complete, bounded operation projection from authoritative evidence.
    ///
    /// No lifecycle state is stored or advanced by this value. P10-owned durable
    /// implementations supply the operation identity, timestamps, file references,
    /// and counts through [`BatchOperationPort`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` above [`MAX_BATCH_ERROR_ITEMS`], `InvalidArgument`
    /// for a missing status transition timestamp, and the validation errors from
    /// the supplied timestamp and count values.
    pub fn new(
        id: BatchOperationId,
        endpoint: BatchEndpoint,
        input_file: FileReference,
        completion_window: BatchCompletionWindow,
        status: BatchStatus,
        evidence: BatchOperationEvidence,
    ) -> Result<Self, ApiBatchError> {
        if !status_has_timestamp(status, evidence.timestamps()) {
            return Err(invalid_argument());
        }
        Ok(Self {
            id,
            endpoint,
            input_file,
            completion_window,
            status,
            timestamps: evidence.timestamps,
            output_file: evidence.output_file,
            error_file: evidence.error_file,
            errors: evidence.errors,
            request_counts: evidence.request_counts,
        })
    }

    /// Returns the owner object discriminator, always `batch`.
    #[must_use]
    pub const fn object(&self) -> &'static str {
        "batch"
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn id(&self) -> &BatchOperationId {
        &self.id
    }

    /// Returns the validated endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> BatchEndpoint {
        self.endpoint
    }

    /// Returns the internal input file reference.
    #[must_use]
    pub const fn input_file(&self) -> &FileReference {
        &self.input_file
    }

    /// Returns the completion window.
    #[must_use]
    pub const fn completion_window(&self) -> BatchCompletionWindow {
        self.completion_window
    }

    /// Returns the current lifecycle status.
    #[must_use]
    pub const fn status(&self) -> BatchStatus {
        self.status
    }

    /// Returns the lifecycle timestamps.
    #[must_use]
    pub const fn timestamps(&self) -> BatchTimestamps {
        self.timestamps
    }

    /// Returns the optional internal output-file reference.
    #[must_use]
    pub const fn output_file(&self) -> Option<&FileReference> {
        self.output_file.as_ref()
    }

    /// Returns the optional internal error-file reference.
    #[must_use]
    pub const fn error_file(&self) -> Option<&FileReference> {
        self.error_file.as_ref()
    }

    /// Returns bounded itemized errors.
    #[must_use]
    pub fn errors(&self) -> &[BatchValidationError] {
        &self.errors
    }

    /// Returns authoritative request counts.
    #[must_use]
    pub const fn request_counts(&self) -> BatchRequestCounts {
        self.request_counts
    }
}

fn status_has_timestamp(status: BatchStatus, timestamps: BatchTimestamps) -> bool {
    match status {
        BatchStatus::Validating => true,
        BatchStatus::Failed
        | BatchStatus::InProgress
        | BatchStatus::Finalizing
        | BatchStatus::Completed => active_status_timestamp(status, timestamps),
        BatchStatus::Expired | BatchStatus::Cancelling | BatchStatus::Cancelled => {
            terminal_status_timestamp(status, timestamps)
        }
    }
}

fn active_status_timestamp(status: BatchStatus, timestamps: BatchTimestamps) -> bool {
    match status {
        BatchStatus::Failed => timestamps.failed_at().is_some(),
        BatchStatus::InProgress => timestamps.in_progress_at().is_some(),
        BatchStatus::Finalizing => timestamps.finalizing_at().is_some(),
        BatchStatus::Completed => timestamps.completed_at().is_some(),
        _ => false,
    }
}

fn terminal_status_timestamp(status: BatchStatus, timestamps: BatchTimestamps) -> bool {
    match status {
        BatchStatus::Expired => timestamps.expired_at().is_some(),
        BatchStatus::Cancelling => timestamps.cancelling_at().is_some(),
        BatchStatus::Cancelled => timestamps.cancelled_at().is_some(),
        _ => false,
    }
}

fn valid_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

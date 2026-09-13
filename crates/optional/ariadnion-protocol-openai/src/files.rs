// crates/optional/ariadnion-protocol-openai/src/files.rs - OpenAI Files compatibility adapter.
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
//! Strict OpenAI Files projection over provider-neutral file capabilities.

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;

use ariadnion_api_domain::{FileDescriptor, IdempotencyKey};
use ariadnion_api_files::{
    ApiFilesError, FileDeleteRequest, FileDownloadSink, FileServicePort, FileUploadRequest,
    FileUploadSource,
};
use ariadnion_core::RequestContext;
use ariadnion_provider_files::{
    ProviderFileId, ProviderFileListRequest, ProviderFileMapping, ProviderFileMappingMetadata,
    ProviderFileMappingPort, ProviderFilePageLimit, ProviderFilePublishRequest,
    ProviderFilePublisherPort, ProviderFilePurpose, ProviderFileScope, ProviderFileUnixSeconds,
    ProviderFilesError,
};
use serde::Serialize;

/// Stable failures produced by the OpenAI Files compatibility boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiFilesError {
    /// The public request does not match the frozen Files subset.
    InvalidRequest,
    /// A provider alias operation failed without exposing scoped identifiers.
    Mapping(ProviderFilesError),
    /// A provider-neutral file operation failed without exposing internal state.
    Service(ApiFilesError),
    /// Trusted mapping and file metadata disagree.
    IntegrityFailure,
}

impl Display for OpenAiFilesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("OPENAI_FILES_INVALID_REQUEST"),
            Self::Mapping(error) => Display::fmt(error, formatter),
            Self::Service(error) => Display::fmt(error, formatter),
            Self::IntegrityFailure => formatter.write_str("OPENAI_FILES_INTEGRITY_FAILURE"),
        }
    }
}

impl std::error::Error for OpenAiFilesError {}

impl From<ProviderFilesError> for OpenAiFilesError {
    fn from(value: ProviderFilesError) -> Self {
        Self::Mapping(value)
    }
}

impl From<ApiFilesError> for OpenAiFilesError {
    fn from(value: ApiFilesError) -> Self {
        Self::Service(value)
    }
}

/// A strictly decoded OpenAI Files list query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiFileListQuery {
    after: Option<ProviderFileId>,
    limit: ProviderFilePageLimit,
}

impl OpenAiFileListQuery {
    /// Returns the optional exclusive public alias cursor.
    #[must_use]
    pub const fn after(&self) -> Option<&ProviderFileId> {
        self.after.as_ref()
    }

    /// Returns the required bounded page size.
    #[must_use]
    pub const fn limit(&self) -> ProviderFilePageLimit {
        self.limit
    }
}

/// Decodes the exact frozen Files list query.
///
/// `limit` is required exactly once and must be in `1..=1000`. `after` is
/// optional and may occur at most once. Every other field, empty component,
/// encoded delimiter, and duplicate is rejected.
///
/// # Errors
///
/// Returns [`OpenAiFilesError::InvalidRequest`] for any unsupported or malformed
/// query and preserves no rejected input in the error.
pub fn parse_list_query(query: Option<&str>) -> Result<OpenAiFileListQuery, OpenAiFilesError> {
    let query = query.filter(|value| !value.is_empty()).ok_or(invalid())?;
    let mut after = None;
    let mut limit = None;
    for component in query.split('&') {
        let (name, value) = component.split_once('=').ok_or(invalid())?;
        parse_list_component(name, value, &mut after, &mut limit)?;
    }
    Ok(OpenAiFileListQuery {
        after,
        limit: limit.ok_or(invalid())?,
    })
}

fn parse_list_component(
    name: &str,
    value: &str,
    after: &mut Option<ProviderFileId>,
    limit: &mut Option<ProviderFilePageLimit>,
) -> Result<(), OpenAiFilesError> {
    match name {
        "after" => parse_after_component(value, after),
        "limit" => parse_limit_component(value, limit),
        _ => Err(invalid()),
    }
}

fn parse_after_component(
    value: &str,
    after: &mut Option<ProviderFileId>,
) -> Result<(), OpenAiFilesError> {
    if after.is_some() {
        return Err(invalid());
    }
    *after = Some(ProviderFileId::new(value).map_err(|_| invalid())?);
    Ok(())
}

fn parse_limit_component(
    value: &str,
    limit: &mut Option<ProviderFilePageLimit>,
) -> Result<(), OpenAiFilesError> {
    if limit.is_some() {
        return Err(invalid());
    }
    let value = value.parse::<usize>().map_err(|_| invalid())?;
    *limit = Some(ProviderFilePageLimit::new(value).map_err(|_| invalid())?);
    Ok(())
}

/// Exact public OpenAI file representation for the frozen P4 subset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiFileObject {
    id: String,
    object: &'static str,
    bytes: usize,
    created_at: u64,
    filename: String,
    purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

/// Projects an authoritative mapping and descriptor into one public file object.
///
/// The internal [`ariadnion_api_domain::FileReference`] and digest are never
/// serialized. The mapping reference must exactly match the descriptor and the
/// retained purpose must be one of the two frozen P4 purposes.
///
/// # Errors
///
/// Returns [`OpenAiFilesError::IntegrityFailure`] when trusted inputs disagree
/// or contain a purpose outside `batch` and `user_data`.
pub fn file_object(
    mapping: &ProviderFileMapping,
    descriptor: &FileDescriptor,
) -> Result<OpenAiFileObject, OpenAiFilesError> {
    validate_projection(mapping, descriptor)?;
    Ok(OpenAiFileObject {
        id: mapping.provider_file_id().as_str().to_owned(),
        object: "file",
        bytes: descriptor.byte_length().get(),
        created_at: mapping.created_at().get(),
        filename: descriptor.display_name().as_str().to_owned(),
        purpose: mapping.purpose().as_str().to_owned(),
        expires_at: mapping.expires_at().map(ProviderFileUnixSeconds::get),
    })
}

fn validate_projection(
    mapping: &ProviderFileMapping,
    descriptor: &FileDescriptor,
) -> Result<(), OpenAiFilesError> {
    if mapping.file_reference() != descriptor.reference() {
        return Err(OpenAiFilesError::IntegrityFailure);
    }
    if !mapping.purpose().is_batch() && !mapping.purpose().is_user_data() {
        return Err(OpenAiFilesError::IntegrityFailure);
    }
    Ok(())
}

/// Exact OpenAI list response for the frozen P4 subset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiFileList {
    object: &'static str,
    data: Vec<OpenAiFileObject>,
    first_id: Option<String>,
    last_id: Option<String>,
    has_more: bool,
}

/// Exact successful OpenAI file deletion response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiFileDeletion {
    id: String,
    object: &'static str,
    deleted: bool,
}

/// Port-backed OpenAI Files compatibility facade.
///
/// The facade owns no credentials, routing state, persistence, clocks, or file
/// bytes. Its fixed scope is selected by trusted composition and every public
/// alias is resolved through the authenticated mapping capability.
pub struct OpenAiFilesAdapter {
    service: Arc<dyn FileServicePort>,
    mappings: Arc<dyn ProviderFileMappingPort>,
    publisher: Arc<dyn ProviderFilePublisherPort>,
    scope: ProviderFileScope,
}

impl Debug for OpenAiFilesAdapter {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiFilesAdapter")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl OpenAiFilesAdapter {
    /// Creates a facade from explicitly injected provider-neutral capabilities.
    #[must_use]
    pub fn new(
        service: Arc<dyn FileServicePort>,
        mappings: Arc<dyn ProviderFileMappingPort>,
        publisher: Arc<dyn ProviderFilePublisherPort>,
        scope: ProviderFileScope,
    ) -> Self {
        Self {
            service,
            mappings,
            publisher,
            scope,
        }
    }

    /// Retrieves one tenant-visible file's authoritative public metadata.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted mapping, service, request, or integrity error.
    pub async fn retrieve(
        &self,
        file_id: &str,
        context: &RequestContext,
    ) -> Result<OpenAiFileObject, OpenAiFilesError> {
        let mapping = self.resolve(file_id, context).await?;
        let descriptor = self
            .service
            .metadata(mapping.file_reference(), context)
            .await?;
        owned_file_object(mapping, descriptor)
    }

    /// Lists tenant-visible file metadata using the explicit bounded query.
    ///
    /// Every mapping is revalidated against authoritative file metadata before
    /// projection; a missing or inconsistent descriptor fails the whole page.
    pub async fn list(
        &self,
        query: &OpenAiFileListQuery,
        context: &RequestContext,
    ) -> Result<OpenAiFileList, OpenAiFilesError> {
        let request =
            ProviderFileListRequest::new(self.scope.clone(), query.after.clone(), query.limit());
        let page = self.mappings.list(request, context).await?;
        let mut data = Vec::with_capacity(page.data().len());
        for mapping in page.data() {
            let descriptor = self
                .service
                .metadata(mapping.file_reference(), context)
                .await?;
            data.push(file_object(mapping, &descriptor)?);
        }
        Ok(OpenAiFileList {
            object: "list",
            first_id: page.first_id().map(|value| value.as_str().to_owned()),
            last_id: page.last_id().map(|value| value.as_str().to_owned()),
            has_more: page.has_more(),
            data,
        })
    }

    /// Streams one tenant-visible file through the supplied bounded sink.
    ///
    /// The service retains sequential backpressure, digest verification, finish,
    /// cancellation, and deadline ownership. This facade never buffers content.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted mapping, service, request, or integrity error.
    pub async fn content(
        &self,
        file_id: &str,
        sink: &mut dyn FileDownloadSink,
        context: &RequestContext,
    ) -> Result<FileDescriptor, OpenAiFilesError> {
        let mapping = self.resolve(file_id, context).await?;
        let descriptor = self
            .service
            .content(mapping.file_reference(), sink, context)
            .await?;
        validate_projection(&mapping, &descriptor)?;
        Ok(descriptor)
    }

    /// Deletes one tenant-visible file after exact public-alias resolution.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted mapping, service, request, or integrity error.
    pub async fn delete(
        &self,
        file_id: &str,
        idempotency_key: IdempotencyKey,
        context: &RequestContext,
    ) -> Result<OpenAiFileDeletion, OpenAiFilesError> {
        let mapping = self.resolve(file_id, context).await?;
        let request = FileDeleteRequest::new(*mapping.file_reference(), idempotency_key);
        self.service.delete(request, context).await?;
        Ok(OpenAiFileDeletion {
            id: file_id.to_owned(),
            object: "file",
            deleted: true,
        })
    }

    /// Uploads verified bytes and then publishes an immutable public alias.
    ///
    /// Alias publication occurs only after the provider-neutral service returns
    /// a durable descriptor. Publication idempotency uses the exact upload key;
    /// an indeterminate publication is returned unchanged and never retried with
    /// a fabricated alias.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted mapping, service, request, or integrity error.
    pub async fn upload(
        &self,
        request: FileUploadRequest,
        source: &mut dyn FileUploadSource,
        purpose: ProviderFilePurpose,
        created_at: ProviderFileUnixSeconds,
        expires_at: Option<ProviderFileUnixSeconds>,
        context: &RequestContext,
    ) -> Result<OpenAiFileObject, OpenAiFilesError> {
        validate_purpose(&purpose)?;
        let key = request.idempotency_key().clone();
        let descriptor = self.service.upload(request, source, context).await?;
        let metadata = ProviderFileMappingMetadata::new(
            *descriptor.reference(),
            purpose,
            created_at,
            expires_at,
        );
        let publication = ProviderFilePublishRequest::new(self.scope.clone(), metadata, key);
        let mapping = self.publisher.publish(publication, context).await?;
        owned_file_object(mapping, descriptor)
    }

    async fn resolve(
        &self,
        file_id: &str,
        context: &RequestContext,
    ) -> Result<ProviderFileMapping, OpenAiFilesError> {
        let file_id = ProviderFileId::new(file_id).map_err(|_| invalid())?;
        Ok(self
            .mappings
            .resolve(self.scope.lookup(file_id), context)
            .await?)
    }
}

fn owned_file_object(
    mapping: ProviderFileMapping,
    descriptor: FileDescriptor,
) -> Result<OpenAiFileObject, OpenAiFilesError> {
    file_object(&mapping, &descriptor)
}

fn validate_purpose(purpose: &ProviderFilePurpose) -> Result<(), OpenAiFilesError> {
    if purpose.is_batch() || purpose.is_user_data() {
        return Ok(());
    }
    Err(invalid())
}

const fn invalid() -> OpenAiFilesError {
    OpenAiFilesError::InvalidRequest
}

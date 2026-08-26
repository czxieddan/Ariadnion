// crates/optional/ariadnion-api-http/src/public/files.rs - Native file HTTP ingress for Ariadnion.
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

//! Native streaming upload and metadata-only file routes.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_api_domain::{
    ApiDomainError, FileByteLength, FileDescriptor, FileDigest, FileDisplayName, FileMediaType,
    FileReference, FileUploadSpecification, MAX_FILE_BYTES,
};
use ariadnion_api_files::{ApiFilesError, ApiFilesErrorCode, FileChunk, FileUploadRequest};
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext, RequestId};
use axum::body::{Body, BodyDataStream};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_core::Stream;
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;

use super::error::{ResponseFailure, domain_failure, failure, response_with_request_id};
use super::{ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpRequestIdentity, execution};

const FILE_NAME_HEADER: &str = "x-file-name";
const FILE_DIGEST_HEADER: &str = "x-file-digest";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const REFERENCE_HEX_BYTES: usize = FileReference::BYTE_LENGTH * 2;

/// Handles one authenticated, bounded streaming file upload.
pub(super) async fn handle_upload(
    State(state): State<HttpApiState>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let admission = match admit_request(&state, &parts.headers) {
        Ok(admission) => admission,
        Err(response) => return *response,
    };
    let prepared = match prepare_upload(&state, parts.headers, body, admission).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let PreparedUpload {
        permit,
        identity,
        service,
        mut lifetime,
        mut source,
        request,
        context,
    } = prepared;
    let result = service.upload(request, &mut source, &context).await;
    drop(permit);
    finish_upload(identity, &mut lifetime, source, result)
}

/// Handles one authenticated metadata lookup without reading a request body.
pub(super) async fn handle_metadata(
    State(state): State<HttpApiState>,
    request: Request<Body>,
) -> Response {
    let (parts, _body) = request.into_parts();
    let reference_text = parts
        .uri
        .path()
        .strip_prefix("/v1/files/")
        .filter(|value| !value.is_empty() && !value.contains('/'));
    let admission = match admit_request(&state, &parts.headers) {
        Ok(admission) => admission,
        Err(response) => return *response,
    };
    let prepared = match prepare_metadata(&state, &parts.headers, reference_text, admission).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let PreparedMetadata {
        permit,
        identity,
        service,
        reference,
        mut lifetime,
        context,
    } = prepared;
    let result = load_metadata(&service, &reference, &context).await;
    drop(permit);
    finish_metadata(identity, &reference, &mut lifetime, result)
}

struct RequestAdmission {
    identity: HttpRequestIdentity,
    deadline: SystemTime,
    permit: OwnedSemaphorePermit,
}

fn admit_request(
    state: &HttpApiState,
    headers: &HeaderMap,
) -> Result<RequestAdmission, Box<Response>> {
    let generated = state.identity.issue().map_err(|error| {
        Box::new(failure(state.identity.fallback_identity(), error).into_response())
    })?;
    let permit = state.admission.clone().try_acquire_owned().map_err(|_| {
        Box::new(
            failure(
                generated.clone(),
                ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted),
            )
            .into_response(),
        )
    })?;
    let (identity, deadline) = admit_identity(generated, headers)
        .map_err(|(identity, error)| Box::new(failure(identity, error).into_response()))?;
    Ok(RequestAdmission {
        identity,
        deadline,
        permit,
    })
}

struct PreparedUpload {
    permit: OwnedSemaphorePermit,
    identity: HttpRequestIdentity,
    service: Arc<dyn ariadnion_api_files::FileServicePort>,
    lifetime: RequestLifetime,
    source: AxumFileUploadSource,
    request: FileUploadRequest,
    context: RequestContext,
}

async fn prepare_upload(
    state: &HttpApiState,
    headers: HeaderMap,
    body: Body,
    admission: RequestAdmission,
) -> Result<PreparedUpload, Box<Response>> {
    let RequestAdmission {
        identity,
        deadline,
        permit,
    } = admission;
    let service = state.file_service.clone().ok_or_else(|| {
        Box::new(
            ResponseFailure::file(
                identity.clone(),
                ApiFilesError::new(ApiFilesErrorCode::Unavailable),
            )
            .into_response(),
        )
    })?;
    let (specification, idempotency_key) = parse_upload_headers(&headers)
        .map_err(|error| Box::new(file_failure_response(identity.clone(), error)))?;
    let authorization = execution::parse_authorization(&headers)
        .map_err(|error| Box::new(failure(identity.clone(), error).into_response()))?;
    let lifetime = RequestLifetime::new(&state.shutdown);
    let context = authenticate_context(state, &identity, deadline, authorization, &lifetime)
        .await
        .map_err(|error| Box::new(file_failure_response(identity.clone(), error)))?;
    let source = AxumFileUploadSource::new(
        body.into_data_stream(),
        specification.byte_length().get(),
        lifetime.token(),
    );
    Ok(PreparedUpload {
        permit,
        identity,
        service,
        lifetime,
        source,
        request: FileUploadRequest::new(specification, idempotency_key),
        context,
    })
}

struct PreparedMetadata {
    permit: OwnedSemaphorePermit,
    identity: HttpRequestIdentity,
    service: Arc<dyn ariadnion_api_files::FileServicePort>,
    reference: FileReference,
    lifetime: RequestLifetime,
    context: RequestContext,
}

async fn prepare_metadata(
    state: &HttpApiState,
    headers: &HeaderMap,
    reference_text: Option<&str>,
    admission: RequestAdmission,
) -> Result<PreparedMetadata, Box<Response>> {
    let RequestAdmission {
        identity,
        deadline,
        permit,
    } = admission;
    let service = state.file_service.clone().ok_or_else(|| {
        Box::new(
            ResponseFailure::file(
                identity.clone(),
                ApiFilesError::new(ApiFilesErrorCode::Unavailable),
            )
            .into_response(),
        )
    })?;
    let authorization = execution::parse_authorization(headers)
        .map_err(|error| Box::new(failure(identity.clone(), error).into_response()))?;
    let reference = reference_text.and_then(decode_reference).ok_or_else(|| {
        Box::new(
            ResponseFailure::file(
                identity.clone(),
                ApiFilesError::new(ApiFilesErrorCode::NotFound),
            )
            .into_response(),
        )
    })?;
    let lifetime = RequestLifetime::new(&state.shutdown);
    let context = authenticate_context(state, &identity, deadline, authorization, &lifetime)
        .await
        .map_err(|error| Box::new(file_failure_response(identity.clone(), error)))?;
    Ok(PreparedMetadata {
        permit,
        identity,
        service,
        reference,
        lifetime,
        context,
    })
}

async fn authenticate_context(
    state: &HttpApiState,
    identity: &HttpRequestIdentity,
    deadline: SystemTime,
    authorization: super::PresentedBearer,
    lifetime: &RequestLifetime,
) -> Result<RequestContext, FileFailure> {
    let anonymous = RequestContext::new(
        identity.request_id().clone(),
        identity.trace_id().clone(),
        None,
        Some(deadline),
        lifetime.token(),
    );
    anonymous
        .check_active()
        .map_err(|error| FileFailure::Domain(error.into()))?;
    let evidence = authenticate(state, authorization, &anonymous).await?;
    Ok(RequestContext::new(
        identity.request_id().clone(),
        identity.trace_id().clone(),
        Some(PrincipalContext::new(
            evidence.tenant_id().clone(),
            evidence.principal_id().clone(),
        )),
        Some(deadline),
        lifetime.token(),
    ))
}

fn finish_upload(
    identity: HttpRequestIdentity,
    lifetime: &mut RequestLifetime,
    source: AxumFileUploadSource,
    result: Result<FileDescriptor, ApiFilesError>,
) -> Response {
    match result {
        Ok(descriptor) if source.is_complete() => {
            lifetime.disarm();
            match upload_response(&identity, &descriptor) {
                Ok(response) => response,
                Err(error) => failure(identity, error).into_response(),
            }
        }
        Ok(_) => file_failure_response(
            identity,
            ApiFilesError::new(ApiFilesErrorCode::InvalidArgument),
        ),
        Err(error) => file_failure_response(identity, FileFailure::Files(error)),
    }
}

async fn load_metadata(
    service: &Arc<dyn ariadnion_api_files::FileServicePort>,
    reference: &FileReference,
    context: &RequestContext,
) -> Result<FileDescriptor, FileFailure> {
    match execution::within_request_context(context, service.metadata(reference, context)).await {
        Ok(result) => result.map_err(FileFailure::Files),
        Err(error) => Err(FileFailure::Files(error.into())),
    }
}

fn finish_metadata(
    identity: HttpRequestIdentity,
    reference: &FileReference,
    lifetime: &mut RequestLifetime,
    result: Result<FileDescriptor, FileFailure>,
) -> Response {
    match result {
        Ok(descriptor) if descriptor.reference() == reference => {
            lifetime.disarm();
            metadata_response(&identity, &descriptor)
        }
        Ok(_) => file_failure_response(identity, ApiFilesError::new(ApiFilesErrorCode::NotFound)),
        Err(error) => file_failure_response(identity, error),
    }
}

async fn authenticate(
    state: &HttpApiState,
    authorization: super::PresentedBearer,
    context: &RequestContext,
) -> Result<ariadnion_principal_binding::AuthenticatedPrincipalEvidence, FileFailure> {
    let result = execution::within_request_context(
        context,
        state.authentication.authenticate(&authorization, context),
    )
    .await
    .map_err(|error| FileFailure::Files(error.into()))?;
    result.map_err(FileFailure::Http)
}

fn admit_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<(HttpRequestIdentity, std::time::SystemTime), (HttpRequestIdentity, ApiHttpError)> {
    execution::validate_header_budget(headers).map_err(|error| (generated.clone(), error))?;
    let identity = resolve_identity(generated, headers)?;
    let deadline = execution::parse_deadline(headers, SystemTime::now())
        .map_err(|error| (identity.clone(), error))?;
    Ok((identity, deadline))
}

fn resolve_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<HttpRequestIdentity, (HttpRequestIdentity, ApiHttpError)> {
    let value = execution::one_header(headers, "x-request-id", false)
        .map_err(|error| (generated.clone(), error))?;
    let Some(value) = value else {
        return Ok(generated);
    };
    let text = value.to_str().map_err(|_| {
        (
            generated.clone(),
            ApiHttpError::new(ApiHttpErrorCode::InvalidRequest),
        )
    })?;
    let request_id = RequestId::parse(text).map_err(|_| {
        (
            generated.clone(),
            ApiHttpError::new(ApiHttpErrorCode::InvalidRequest),
        )
    })?;
    Ok(HttpRequestIdentity::new(
        request_id,
        generated.trace_id().clone(),
    ))
}

fn parse_upload_headers(
    headers: &HeaderMap,
) -> Result<(FileUploadSpecification, super::IdempotencyKey), FileFailure> {
    let length = parse_length(headers)?;
    let media_type = parse_media_type(headers)?;
    let display_name = parse_display_name(headers)?;
    let idempotency_key = parse_idempotency_key(headers)?;
    let expected_digest = parse_expected_digest(headers)?;
    Ok((
        FileUploadSpecification::new(display_name, media_type, length, expected_digest),
        idempotency_key,
    ))
}

fn parse_length(headers: &HeaderMap) -> Result<FileByteLength, FileFailure> {
    let value = execution::one_header(headers, header::CONTENT_LENGTH.as_str(), true)
        .map_err(|_| file_invalid())?
        .ok_or_else(file_invalid)?;
    let length = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(file_invalid)?;
    let length = usize::try_from(length)
        .ok()
        .ok_or(FileFailure::Files(ApiFilesError::new(
            ApiFilesErrorCode::LimitExceeded,
        )))?;
    FileByteLength::new(length).map_err(|error| FileFailure::Files(error.into()))
}

fn parse_media_type(headers: &HeaderMap) -> Result<FileMediaType, FileFailure> {
    let value = execution::one_header(headers, header::CONTENT_TYPE.as_str(), true)
        .map_err(|_| file_invalid())?
        .ok_or_else(file_invalid)?;
    let value = value.to_str().map_err(|_| file_invalid())?;
    FileMediaType::new(value).map_err(|error| FileFailure::Files(error.into()))
}

fn parse_display_name(headers: &HeaderMap) -> Result<FileDisplayName, FileFailure> {
    let value = execution::one_header(headers, FILE_NAME_HEADER, true)
        .map_err(|_| file_invalid())?
        .ok_or_else(file_invalid)?;
    let value = value.to_str().map_err(|_| file_invalid())?;
    FileDisplayName::new(value).map_err(|error| FileFailure::Files(error.into()))
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<super::IdempotencyKey, FileFailure> {
    let value = execution::one_header(headers, IDEMPOTENCY_HEADER, true)
        .map_err(|_| file_invalid())?
        .ok_or_else(file_invalid)?;
    let value = value.to_str().map_err(|_| file_invalid())?;
    super::IdempotencyKey::new(value).map_err(|error| FileFailure::Files(error.into()))
}

fn parse_expected_digest(headers: &HeaderMap) -> Result<Option<FileDigest>, FileFailure> {
    let Some(value) =
        execution::one_header(headers, FILE_DIGEST_HEADER, false).map_err(|_| file_invalid())?
    else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| file_invalid())?;
    decode_digest(value)
        .map(FileDigest::new)
        .map(Some)
        .ok_or_else(file_invalid)
}

fn file_invalid() -> FileFailure {
    FileFailure::Files(ApiFilesError::new(ApiFilesErrorCode::InvalidArgument))
}

fn decode_digest(value: &str) -> Option<[u8; FileDigest::BYTE_LENGTH]> {
    if value.len() != REFERENCE_HEX_BYTES {
        return None;
    }
    let mut output = [0_u8; FileDigest::BYTE_LENGTH];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_lower_hex(pair[0])?;
        let low = decode_lower_hex(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

fn decode_reference(value: &str) -> Option<FileReference> {
    if value.len() != REFERENCE_HEX_BYTES {
        return None;
    }
    let mut output = [0_u8; FileReference::BYTE_LENGTH];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_lower_hex(pair[0])?;
        let low = decode_lower_hex(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(FileReference::new(output))
}

fn decode_lower_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn upload_response(
    identity: &HttpRequestIdentity,
    descriptor: &FileDescriptor,
) -> Result<Response, ApiHttpError> {
    let body = serde_json::to_vec(&FileDescriptorDto::from_descriptor(descriptor))
        .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::Internal))?;
    let mut response = (StatusCode::OK, Body::from(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response_with_request_id(identity, response))
}

fn metadata_response(identity: &HttpRequestIdentity, descriptor: &FileDescriptor) -> Response {
    match upload_response(identity, descriptor) {
        Ok(response) => response,
        Err(error) => failure(identity.clone(), error).into_response(),
    }
}

#[derive(Serialize)]
struct FileDescriptorDto {
    reference: String,
    display_name: String,
    media_type: String,
    byte_length: usize,
    digest: String,
}

impl FileDescriptorDto {
    fn from_descriptor(descriptor: &FileDescriptor) -> Self {
        Self {
            reference: encode_hex(descriptor.reference().as_bytes()),
            display_name: descriptor.display_name().as_str().to_owned(),
            media_type: descriptor.media_type().as_str().to_owned(),
            byte_length: descriptor.byte_length().get(),
            digest: encode_hex(descriptor.digest().as_bytes()),
        }
    }
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

enum FileFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
    Files(ApiFilesError),
}

impl From<ApiHttpError> for FileFailure {
    fn from(error: ApiHttpError) -> Self {
        Self::Http(error)
    }
}

impl From<ApiDomainError> for FileFailure {
    fn from(error: ApiDomainError) -> Self {
        Self::Domain(error)
    }
}

impl From<ApiFilesError> for FileFailure {
    fn from(error: ApiFilesError) -> Self {
        Self::Files(error)
    }
}

fn file_failure_response(
    identity: HttpRequestIdentity,
    failure_value: impl Into<FileFailure>,
) -> Response {
    match failure_value.into() {
        FileFailure::Http(error) => failure(identity, error).into_response(),
        FileFailure::Domain(error) => domain_failure(identity, error).into_response(),
        FileFailure::Files(error) => ResponseFailure::file(identity, error).into_response(),
    }
}

struct RequestLifetime {
    cancellation: CancellationToken,
    armed: bool,
}

impl RequestLifetime {
    fn new(shutdown: &CancellationToken) -> Self {
        Self {
            cancellation: shutdown.child(),
            armed: true,
        }
    }

    fn token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RequestLifetime {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}

struct AxumFileUploadSource {
    stream: BodyDataStream,
    pending: Option<Bytes>,
    declared: usize,
    received: usize,
    delivered: usize,
    eof: bool,
    terminal: Option<ApiFilesError>,
    cancellation: CancellationToken,
}

enum SourceStep {
    Chunk(FileChunk),
    Continue,
    Eof,
}

impl AxumFileUploadSource {
    fn new(stream: BodyDataStream, declared: usize, cancellation: CancellationToken) -> Self {
        Self {
            stream,
            pending: None,
            declared,
            received: 0,
            delivered: 0,
            eof: false,
            terminal: None,
            cancellation,
        }
    }

    fn is_complete(&self) -> bool {
        self.eof
            && self.pending.is_none()
            && self.terminal.is_none()
            && self.received == self.declared
            && self.delivered == self.declared
    }

    fn take_pending_chunk(&mut self) -> Result<Option<FileChunk>, ApiFilesError> {
        let Some(mut bytes) = self.pending.take() else {
            return Ok(None);
        };
        if bytes.is_empty() {
            return Ok(None);
        }
        let chunk_length = bytes.len().min(ariadnion_api_files::MAX_FILE_CHUNK_BYTES);
        let chunk = bytes.split_to(chunk_length);
        self.pending = Some(bytes);
        self.delivered = self
            .delivered
            .checked_add(chunk.len())
            .ok_or_else(|| ApiFilesError::new(ApiFilesErrorCode::LimitExceeded))?;
        FileChunk::new(chunk.to_vec()).map(Some)
    }

    async fn poll_body(
        &mut self,
        context: &RequestContext,
    ) -> Result<Option<Bytes>, ApiFilesError> {
        let next = match execution::within_request_context(
            context,
            poll_fn(|task| Pin::new(&mut self.stream).poll_next(task)),
        )
        .await
        {
            Ok(next) => next,
            Err(error) => return Err(error.into()),
        };
        match next {
            Some(Ok(bytes)) => Ok(Some(bytes)),
            Some(Err(_)) => Err(ApiFilesError::new(ApiFilesErrorCode::Unavailable)),
            None => Ok(None),
        }
    }

    fn record_frame(&mut self, bytes: Bytes) -> Result<(), ApiFilesError> {
        let received = match self.received.checked_add(bytes.len()) {
            Some(received) => received,
            None => return self.fail(ApiFilesErrorCode::LimitExceeded),
        };
        if received > self.declared || received > MAX_FILE_BYTES {
            return self.fail(ApiFilesErrorCode::InvalidArgument);
        }
        self.received = received;
        self.pending = Some(bytes);
        Ok(())
    }

    fn finish_eof(&mut self) -> Result<SourceStep, ApiFilesError> {
        self.eof = true;
        if self.received != self.declared || self.delivered != self.declared {
            return Err(self.fail_error(ApiFilesErrorCode::InvalidArgument));
        }
        Ok(SourceStep::Eof)
    }

    fn fail(&mut self, code: ApiFilesErrorCode) -> Result<(), ApiFilesError> {
        Err(self.fail_error(code))
    }

    fn fail_error(&mut self, code: ApiFilesErrorCode) -> ApiFilesError {
        let error = ApiFilesError::new(code);
        self.terminal = Some(error);
        error
    }

    fn terminal_or_eof(&self) -> Option<Result<Option<FileChunk>, ApiFilesError>> {
        if let Some(error) = self.terminal {
            Some(Err(error))
        } else if self.eof {
            Some(Ok(None))
        } else {
            None
        }
    }

    async fn read_step(&mut self, context: &RequestContext) -> Result<SourceStep, ApiFilesError> {
        match self.take_pending_chunk() {
            Ok(Some(chunk)) => return Ok(SourceStep::Chunk(chunk)),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        let next = self.poll_body(context).await;
        self.process_body_result(next)
    }

    fn process_body_result(
        &mut self,
        result: Result<Option<Bytes>, ApiFilesError>,
    ) -> Result<SourceStep, ApiFilesError> {
        match result {
            Ok(Some(bytes)) => {
                self.record_frame(bytes)?;
                Ok(SourceStep::Continue)
            }
            Ok(None) => self.finish_eof(),
            Err(error) => {
                self.terminal = Some(error);
                Err(error)
            }
        }
    }

    async fn poll_until_chunk(
        &mut self,
        context: &RequestContext,
    ) -> Result<Option<FileChunk>, ApiFilesError> {
        loop {
            match self.read_step(context).await? {
                SourceStep::Chunk(chunk) => return Ok(Some(chunk)),
                SourceStep::Continue => continue,
                SourceStep::Eof => return Ok(None),
            }
        }
    }
}

impl ariadnion_api_files::FileUploadSource for AxumFileUploadSource {
    fn next_chunk<'a>(
        &'a mut self,
        context: &'a RequestContext,
    ) -> ariadnion_api_files::BoxFileFuture<'a, Result<Option<FileChunk>, ApiFilesError>> {
        Box::pin(async move {
            if let Some(result) = self.terminal_or_eof() {
                return result;
            }
            self.poll_until_chunk(context).await
        })
    }
}

impl Drop for AxumFileUploadSource {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

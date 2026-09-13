// crates/optional/ariadnion-protocol-openai/src/files_http.rs - OpenAI Files HTTP adapter.
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
//! Authenticated OpenAI Files routes over provider-neutral file capabilities.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ariadnion_api_domain::{
    FileByteLength, FileDisplayName, FileMediaType, FileUploadSpecification, IdempotencyKey,
    MAX_FILE_BYTES,
};
use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, FileChunk, FileDownloadSink, FileServicePort,
    FileUploadRequest, FileUploadSource,
};
use ariadnion_api_http::{
    BoxProtocolOperationFuture, HttpOperationProtocolAdapter, HttpRequestIdentity,
    ProtocolBufferedResponse, ProtocolFailure, ProtocolOperationResponse, ProtocolStreamResponse,
};
use ariadnion_core::RequestContext;
use ariadnion_provider_files::{
    ProviderFileMapping, ProviderFileMappingPort, ProviderFilePublisherPort, ProviderFilePurpose,
    ProviderFileScope, ProviderFileUnixSeconds, ProviderFilesError,
};
use axum::body::{Body, Bytes, HttpBody, to_bytes};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use futures_core::Stream;
use serde_json::to_vec;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::files::{OpenAiFilesAdapter, OpenAiFilesError, parse_list_query};
use crate::{OpenAiTimestampPort, SystemOpenAiTimestamp};

const MAX_MULTIPART_BODY_BYTES: usize = MAX_FILE_BYTES + (1024 * 1024);
const MAX_MULTIPART_HEADER_BYTES: usize = 8 * 1024;
const MAX_UPLOAD_CHUNK_BYTES: usize = 65_536;

/// Authenticated OpenAI Files operation adapter.
pub struct OpenAiFilesHttpAdapter {
    facade: Arc<OpenAiFilesAdapter>,
    service: Arc<dyn FileServicePort>,
    mappings: Arc<dyn ProviderFileMappingPort>,
    scope: ProviderFileScope,
    clock: Arc<dyn OpenAiTimestampPort>,
}

impl OpenAiFilesHttpAdapter {
    /// Creates the adapter with provider-neutral file and mapping capabilities.
    #[must_use]
    pub fn new(
        service: Arc<dyn FileServicePort>,
        mappings: Arc<dyn ProviderFileMappingPort>,
        publisher: Arc<dyn ProviderFilePublisherPort>,
        scope: ProviderFileScope,
    ) -> Self {
        let facade = Arc::new(OpenAiFilesAdapter::new(
            Arc::clone(&service),
            Arc::clone(&mappings),
            publisher,
            scope.clone(),
        ));
        Self {
            facade,
            service,
            mappings,
            scope,
            clock: Arc::new(SystemOpenAiTimestamp),
        }
    }

    /// Replaces the wall-clock source used for upload mapping timestamps.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn OpenAiTimestampPort>) -> Self {
        self.clock = clock;
        self
    }

    /// Wraps a previously assembled Files facade and its stream capabilities.
    #[must_use]
    pub fn from_facade(
        facade: Arc<OpenAiFilesAdapter>,
        service: Arc<dyn FileServicePort>,
        mappings: Arc<dyn ProviderFileMappingPort>,
        scope: ProviderFileScope,
    ) -> Self {
        Self {
            facade,
            service,
            mappings,
            scope,
            clock: Arc::new(SystemOpenAiTimestamp),
        }
    }
}

impl HttpOperationProtocolAdapter for OpenAiFilesHttpAdapter {
    fn execute<'a>(
        &'a self,
        request: Request<Body>,
        identity: &'a HttpRequestIdentity,
        context: &'a RequestContext,
    ) -> BoxProtocolOperationFuture<'a> {
        Box::pin(async move {
            context.check_active().map_err(|error| {
                ProtocolFailure::from(ariadnion_api_domain::ApiDomainError::from(error))
            })?;
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let query = request.uri().query().map(str::to_owned);
            let result = self
                .dispatch(method, path, query, request, identity, context)
                .await?;
            Ok(result)
        })
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        crate::response::project_failure(identity, failure)
    }
}

impl OpenAiFilesHttpAdapter {
    fn dispatch<'a>(
        &'a self,
        method: Method,
        path: String,
        query: Option<String>,
        request: Request<Body>,
        identity: &'a HttpRequestIdentity,
        context: &'a RequestContext,
    ) -> BoxProtocolOperationFuture<'a> {
        Box::pin(async move {
            let route = route(&method, &path);
            self.dispatch_route(route, query.as_deref(), request, identity, context)
                .await
        })
    }

    async fn dispatch_route<'a>(
        &'a self,
        route: FileRoute<'a>,
        query: Option<&str>,
        request: Request<Body>,
        identity: &'a HttpRequestIdentity,
        context: &'a RequestContext,
    ) -> Result<ProtocolOperationResponse, ProtocolFailure> {
        match route {
            FileRoute::List => {
                require_bodyless(&request)?;
                self.list(query, context).await
            }
            FileRoute::Retrieve(id) => {
                require_no_query(query)?;
                require_bodyless(&request)?;
                self.retrieve(id, context).await
            }
            FileRoute::Content(id) => {
                require_no_query(query)?;
                require_bodyless(&request)?;
                self.content(id, context).await
            }
            FileRoute::Delete(id) => {
                require_no_query(query)?;
                require_bodyless(&request)?;
                self.delete(id, request.headers(), identity, context).await
            }
            FileRoute::Upload => {
                require_no_query(query)?;
                self.upload(request, identity, context).await
            }
            FileRoute::Unsupported => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy)]
enum FileRoute<'a> {
    List,
    Upload,
    Retrieve(&'a str),
    Content(&'a str),
    Delete(&'a str),
    Unsupported,
}

fn route<'a>(method: &Method, path: &'a str) -> FileRoute<'a> {
    if path == "/v1/files" {
        return collection_route(method);
    }
    path.strip_prefix("/v1/files/")
        .map_or(FileRoute::Unsupported, |suffix| item_route(method, suffix))
}

fn item_route<'a>(method: &Method, suffix: &'a str) -> FileRoute<'a> {
    suffix.strip_suffix("/content").map_or_else(
        || item_method_route(method, suffix),
        |file_id| content_route(method, file_id),
    )
}

fn content_route<'a>(method: &Method, file_id: &'a str) -> FileRoute<'a> {
    if *method == Method::GET {
        FileRoute::Content(file_id)
    } else {
        FileRoute::Unsupported
    }
}

fn item_method_route<'a>(method: &Method, suffix: &'a str) -> FileRoute<'a> {
    match *method {
        Method::GET => FileRoute::Retrieve(suffix),
        Method::DELETE => FileRoute::Delete(suffix),
        _ => FileRoute::Unsupported,
    }
}

fn collection_route(method: &Method) -> FileRoute<'static> {
    match *method {
        Method::GET => FileRoute::List,
        Method::POST => FileRoute::Upload,
        _ => FileRoute::Unsupported,
    }
}

impl OpenAiFilesHttpAdapter {
    async fn list(
        &self,
        query: Option<&str>,
        context: &RequestContext,
    ) -> Result<ProtocolOperationResponse, ProtocolFailure> {
        let query = parse_list_query(query).map_err(map_files_error)?;
        let page = self
            .facade
            .list(&query, context)
            .await
            .map_err(map_files_error)?;
        buffered_json(StatusCode::OK, to_vec(&page).map_err(|_| internal()))
    }

    async fn retrieve(
        &self,
        file_id: &str,
        context: &RequestContext,
    ) -> Result<ProtocolOperationResponse, ProtocolFailure> {
        let object = self
            .facade
            .retrieve(file_id, context)
            .await
            .map_err(map_files_error)?;
        buffered_json(StatusCode::OK, to_vec(&object).map_err(|_| internal()))
    }

    async fn delete(
        &self,
        file_id: &str,
        headers: &HeaderMap,
        identity: &HttpRequestIdentity,
        context: &RequestContext,
    ) -> Result<ProtocolOperationResponse, ProtocolFailure> {
        let key = request_idempotency(headers, identity)?;
        let object = self
            .facade
            .delete(file_id, key, context)
            .await
            .map_err(map_files_error)?;
        buffered_json(StatusCode::OK, to_vec(&object).map_err(|_| internal()))
    }

    async fn upload(
        &self,
        request: Request<Body>,
        identity: &HttpRequestIdentity,
        context: &RequestContext,
    ) -> Result<ProtocolOperationResponse, ProtocolFailure> {
        let (parts, purpose, idempotency) = self.prepare_upload(request, identity, context).await?;
        let display_name = FileDisplayName::new(&parts.filename).map_err(|_| invalid())?;
        let media_type = FileMediaType::new(&parts.media_type).map_err(|_| invalid())?;
        let length = FileByteLength::new(parts.bytes.len()).map_err(|_| payload_too_large())?;
        let specification = FileUploadSpecification::new(display_name, media_type, length, None);
        let upload = FileUploadRequest::new(specification, idempotency);
        let mut source = VecUploadSource::new(parts.bytes);
        let created_at = ProviderFileUnixSeconds::new(self.clock.unix_seconds()?);
        let object = self
            .facade
            .upload(upload, &mut source, purpose, created_at, None, context)
            .await
            .map_err(map_files_error)?;
        ensure_upload_complete(&source)?;
        buffered_json(StatusCode::OK, to_vec(&object).map_err(|_| internal()))
    }

    async fn prepare_upload(
        &self,
        request: Request<Body>,
        identity: &HttpRequestIdentity,
        context: &RequestContext,
    ) -> Result<(MultipartParts, ProviderFilePurpose, IdempotencyKey), ProtocolFailure> {
        let content_type = request_content_type(request.headers())?;
        let boundary = parse_boundary(&content_type)?;
        let idempotency = request_idempotency(request.headers(), identity)?;
        context.check_active().map_err(|error| {
            ProtocolFailure::from(ariadnion_api_domain::ApiDomainError::from(error))
        })?;
        // Multipart parsing uses bounded staging; service-side chunk polling
        // preserves backpressure after the request body has been validated.
        let bytes = to_bytes(request.into_body(), MAX_MULTIPART_BODY_BYTES)
            .await
            .map_err(|_| body_read_failure(context))?;
        let parts = parse_multipart(bytes, &boundary)?;
        let purpose = validate_upload_purpose(&parts)?;
        Ok((parts, purpose, idempotency))
    }

    async fn content(
        &self,
        file_id: &str,
        context: &RequestContext,
    ) -> Result<ProtocolOperationResponse, ProtocolFailure> {
        let mapping = self.resolve_mapping(file_id, context).await?;
        let descriptor = self
            .service
            .metadata(mapping.file_reference(), context)
            .await
            .map_err(map_api_files)?;
        if descriptor.reference() != mapping.file_reference() {
            return Err(integrity());
        }
        let (sender, receiver) = mpsc::channel(1);
        let service = Arc::clone(&self.service);
        let reference = *mapping.file_reference();
        let expected = descriptor.clone();
        let worker_context = context.clone();
        let worker_sender = sender.clone();
        tokio::spawn(async move {
            run_download(service, reference, expected, worker_sender, worker_context).await;
        });
        let watch_sender = sender.clone();
        let watch_context = context.clone();
        let watch = tokio::spawn(async move {
            watch_download_context(watch_sender, watch_context).await;
        });
        let stream = DownloadBody::new(
            receiver,
            descriptor.byte_length().get(),
            context.clone(),
            watch,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(descriptor.media_type().as_str()).map_err(|_| internal())?,
        );
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&descriptor.byte_length().get().to_string())
                .map_err(|_| internal())?,
        );
        let projected = ProtocolStreamResponse::new(StatusCode::OK, headers, Box::pin(stream))?;
        Ok(ProtocolOperationResponse::Stream(projected))
    }

    async fn resolve_mapping(
        &self,
        file_id: &str,
        context: &RequestContext,
    ) -> Result<ProviderFileMapping, ProtocolFailure> {
        let id = ariadnion_provider_files::ProviderFileId::new(file_id).map_err(|_| invalid())?;
        self.mappings
            .resolve(self.scope.lookup(id), context)
            .await
            .map_err(map_provider)
    }
}

fn ensure_upload_complete(source: &VecUploadSource) -> Result<(), ProtocolFailure> {
    source.is_complete().then_some(()).ok_or_else(integrity)
}

fn validate_upload_purpose(parts: &MultipartParts) -> Result<ProviderFilePurpose, ProtocolFailure> {
    let purpose = ProviderFilePurpose::new(&parts.purpose).map_err(|_| invalid())?;
    if !purpose.is_batch() && !purpose.is_user_data() {
        return Err(invalid());
    }
    if purpose.is_batch() && !parts.filename.ends_with(".jsonl") {
        return Err(invalid());
    }
    Ok(purpose)
}

fn buffered_json(
    status: StatusCode,
    body: Result<Vec<u8>, ProtocolFailure>,
) -> Result<ProtocolOperationResponse, ProtocolFailure> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let response = ProtocolBufferedResponse::new(status, headers, Bytes::from(body?))?;
    Ok(ProtocolOperationResponse::Buffered(response))
}

pub(crate) fn require_no_query(query: Option<&str>) -> Result<(), ProtocolFailure> {
    query.is_none().then_some(()).ok_or_else(invalid)
}

pub(crate) fn require_bodyless(request: &Request<Body>) -> Result<(), ProtocolFailure> {
    if request.headers().contains_key(header::TRANSFER_ENCODING)
        || !request.body().is_end_stream()
    {
        return Err(invalid());
    }
    let mut lengths = request.headers().get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = lengths.next() else {
        return Ok(());
    };
    if lengths.next().is_some() {
        return Err(invalid());
    }
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let length = value
        .to_str()
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(invalid)?;
    if length == 0 {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn request_idempotency(
    headers: &HeaderMap,
    identity: &HttpRequestIdentity,
) -> Result<IdempotencyKey, ProtocolFailure> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(first) = values.next() else {
        return IdempotencyKey::new(identity.request_id().as_str()).map_err(|_| invalid());
    };
    if values.next().is_some() {
        return Err(invalid());
    }
    let value = first.to_str().map_err(|_| invalid())?;
    IdempotencyKey::new(value).map_err(|_| invalid())
}

fn request_content_type(headers: &HeaderMap) -> Result<String, ProtocolFailure> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(unsupported_media_type());
    };
    if values.next().is_some() {
        return Err(invalid());
    }
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|_| unsupported_media_type())
}

fn parse_boundary(value: &str) -> Result<String, ProtocolFailure> {
    let mut pieces = value.split(';');
    validate_multipart_media_type(pieces.next().ok_or_else(unsupported_media_type)?)?;
    parse_boundary_parameters(pieces)
}

fn validate_multipart_media_type(value: &str) -> Result<(), ProtocolFailure> {
    if value.trim().eq_ignore_ascii_case("multipart/form-data") {
        Ok(())
    } else {
        Err(unsupported_media_type())
    }
}

fn parse_boundary_parameters<'a>(
    pieces: impl Iterator<Item = &'a str>,
) -> Result<String, ProtocolFailure> {
    let mut boundary = None;
    for piece in pieces {
        let (name, parameter) = piece.trim().split_once('=').ok_or_else(invalid)?;
        if !name.eq_ignore_ascii_case("boundary") || boundary.is_some() {
            return Err(invalid());
        }
        boundary = Some(parse_boundary_parameter(parameter)?);
    }
    boundary.ok_or_else(invalid)
}

fn parse_boundary_parameter(value: &str) -> Result<String, ProtocolFailure> {
    let parameter = value.trim();
    let candidate = if parameter.starts_with('"') {
        if parameter.len() < 2 || !parameter.ends_with('"') {
            return Err(invalid());
        }
        let inner = &parameter[1..parameter.len() - 1];
        if inner.contains('"') || inner.contains('\\') {
            return Err(invalid());
        }
        inner
    } else {
        parameter
    };
    valid_boundary(candidate)
        .then(|| candidate.to_owned())
        .ok_or_else(invalid)
}

fn valid_boundary(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 70
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'\''
                        | b'('
                        | b')'
                        | b'+'
                        | b'_'
                        | b','
                        | b'-'
                        | b'.'
                        | b'/'
                        | b':'
                        | b'='
                        | b'?',
                )
        })
}

struct MultipartParts {
    filename: String,
    media_type: String,
    purpose: String,
    bytes: Bytes,
}

fn parse_multipart(body: Bytes, boundary: &str) -> Result<MultipartParts, ProtocolFailure> {
    let marker = format!("--{boundary}").into_bytes();
    let mut cursor = 0;
    let mut file = None;
    let mut purpose = None;
    while cursor < body.len() {
        let Some(next) =
            parse_next_multipart_part(&body, &body, &marker, cursor, &mut file, &mut purpose)?
        else {
            break;
        };
        cursor = next;
    }
    let (filename, media_type, bytes) = file.ok_or_else(invalid)?;
    let purpose = purpose.ok_or_else(invalid)?;
    Ok(MultipartParts {
        filename,
        media_type,
        purpose,
        bytes,
    })
}

fn parse_next_multipart_part(
    body: &[u8],
    source: &Bytes,
    marker: &[u8],
    cursor: usize,
    file: &mut Option<(String, String, Bytes)>,
    purpose: &mut Option<String>,
) -> Result<Option<usize>, ProtocolFailure> {
    let cursor = consume_delimiter(body, marker, cursor)?;
    if cursor == body.len() {
        return Ok(None);
    }
    let (headers, content_start) = parse_part_headers(body, cursor)?;
    let (content_end, next) = find_part_end(body, marker, content_start)?;
    parse_multipart_part(
        body,
        source,
        &headers,
        content_start,
        content_end,
        file,
        purpose,
    )?;
    Ok(Some(next))
}

fn parse_multipart_part(
    body: &[u8],
    source: &Bytes,
    headers: &[String],
    content_start: usize,
    content_end: usize,
    file: &mut Option<(String, String, Bytes)>,
    purpose: &mut Option<String>,
) -> Result<(), ProtocolFailure> {
    let name = disposition_parameter(headers, "name").ok_or_else(invalid)?;
    match name {
        "file" => assign_file_part(file, source, headers, content_start, content_end),
        "purpose" => assign_purpose_part(purpose, body, content_start, content_end),
        _ => Err(invalid()),
    }
}

fn assign_file_part(
    file: &mut Option<(String, String, Bytes)>,
    source: &Bytes,
    headers: &[String],
    content_start: usize,
    content_end: usize,
) -> Result<(), ProtocolFailure> {
    if file.is_some() {
        return Err(invalid());
    }
    *file = Some(parse_file_part(
        source,
        headers,
        content_start,
        content_end,
    )?);
    Ok(())
}

fn assign_purpose_part(
    purpose: &mut Option<String>,
    body: &[u8],
    content_start: usize,
    content_end: usize,
) -> Result<(), ProtocolFailure> {
    if purpose.is_some() {
        return Err(invalid());
    }
    *purpose = Some(parse_text_part(body, content_start, content_end)?);
    Ok(())
}

fn parse_file_part(
    body: &Bytes,
    headers: &[String],
    content_start: usize,
    content_end: usize,
) -> Result<(String, String, Bytes), ProtocolFailure> {
    let filename = disposition_parameter(headers, "filename").ok_or_else(invalid)?;
    let media_type = header_value(headers, "content-type")
        .filter(|value| !value.is_empty())
        .unwrap_or("application/octet-stream")
        .to_owned();
    body.get(content_start..content_end).ok_or_else(invalid)?;
    let bytes = body.slice(content_start..content_end);
    Ok((filename.to_owned(), media_type, bytes))
}

fn consume_delimiter(body: &[u8], marker: &[u8], cursor: usize) -> Result<usize, ProtocolFailure> {
    let start = delimiter_start(body, cursor)?;
    let marker_end = start.checked_add(marker.len()).ok_or_else(invalid)?;
    require_marker(body, marker, start, marker_end)?;
    let suffix = body.get(marker_end..).ok_or_else(invalid)?;
    parse_delimiter_suffix(suffix, marker_end, body.len())
}

fn delimiter_start(body: &[u8], cursor: usize) -> Result<usize, ProtocolFailure> {
    if cursor == 0 {
        return Ok(0);
    }
    if body.get(cursor..cursor.saturating_add(2)) == Some(b"\r\n") {
        return Ok(cursor + 2);
    }
    Err(invalid())
}

fn require_marker(
    body: &[u8],
    marker: &[u8],
    start: usize,
    marker_end: usize,
) -> Result<(), ProtocolFailure> {
    if body.get(start..marker_end) == Some(marker) {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn parse_delimiter_suffix(
    suffix: &[u8],
    marker_end: usize,
    body_length: usize,
) -> Result<usize, ProtocolFailure> {
    if suffix.starts_with(b"--") {
        return terminal_delimiter(&suffix[2..], body_length);
    }
    if suffix.starts_with(b"\r\n") {
        return marker_end.checked_add(2).ok_or_else(invalid);
    }
    Err(invalid())
}

fn terminal_delimiter(trailing: &[u8], body_length: usize) -> Result<usize, ProtocolFailure> {
    if trailing.is_empty() || trailing == b"\r\n" {
        Ok(body_length)
    } else {
        Err(invalid())
    }
}

fn parse_part_headers(body: &[u8], cursor: usize) -> Result<(Vec<String>, usize), ProtocolFailure> {
    let relative = header_block_end(body, cursor)?;
    ensure_header_limit(relative)?;
    let header_end = cursor.checked_add(relative).ok_or_else(invalid)?;
    let text = header_text(body, cursor, header_end)?;
    let headers = collect_part_headers(text)?;
    let content_start = content_start(header_end, body.len())?;
    Ok((headers, content_start))
}

fn ensure_header_limit(relative: usize) -> Result<(), ProtocolFailure> {
    if relative > MAX_MULTIPART_HEADER_BYTES {
        Err(payload_too_large())
    } else {
        Ok(())
    }
}

fn header_text(body: &[u8], cursor: usize, header_end: usize) -> Result<&str, ProtocolFailure> {
    let header_bytes = body.get(cursor..header_end).ok_or_else(invalid)?;
    std::str::from_utf8(header_bytes).map_err(|_| invalid())
}

fn header_block_end(body: &[u8], cursor: usize) -> Result<usize, ProtocolFailure> {
    body.get(cursor..)
        .ok_or_else(invalid)?
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(invalid)
}

#[derive(Default)]
struct HeaderPresence {
    disposition: bool,
    content_type: bool,
}

fn collect_part_headers(text: &str) -> Result<Vec<String>, ProtocolFailure> {
    let mut headers = Vec::new();
    let mut presence = HeaderPresence::default();
    for line in text.split("\r\n") {
        headers.push(parse_part_header(line, &mut presence)?);
    }
    Ok(headers)
}

fn parse_part_header(line: &str, presence: &mut HeaderPresence) -> Result<String, ProtocolFailure> {
    let (name, value) = line.split_once(':').ok_or_else(invalid)?;
    validate_header_syntax(name, value)?;
    if name.eq_ignore_ascii_case("content-disposition") {
        mark_header(&mut presence.disposition)?;
    } else if name.eq_ignore_ascii_case("content-type") {
        mark_header(&mut presence.content_type)?;
    } else {
        return Err(invalid());
    }
    Ok(line.to_owned())
}

fn validate_header_syntax(name: &str, value: &str) -> Result<(), ProtocolFailure> {
    if name.is_empty() || name.trim() != name || !name.is_ascii() || value.trim().is_empty() {
        Err(invalid())
    } else {
        Ok(())
    }
}

fn mark_header(seen: &mut bool) -> Result<(), ProtocolFailure> {
    if *seen {
        Err(invalid())
    } else {
        *seen = true;
        Ok(())
    }
}

fn content_start(header_end: usize, body_length: usize) -> Result<usize, ProtocolFailure> {
    let content_start = header_end.checked_add(4).ok_or_else(invalid)?;
    if content_start > body_length {
        Err(invalid())
    } else {
        Ok(content_start)
    }
}

fn find_part_end(
    body: &[u8],
    marker: &[u8],
    content_start: usize,
) -> Result<(usize, usize), ProtocolFailure> {
    let relative = part_delimiter_offset(body, marker, content_start)?;
    let content_end = content_start.checked_add(relative).ok_or_else(invalid)?;
    let after = delimiter_end(content_end, marker)?;
    resolve_part_end(body, after, content_end)
}

fn part_delimiter_offset(
    body: &[u8],
    marker: &[u8],
    content_start: usize,
) -> Result<usize, ProtocolFailure> {
    body.get(content_start..)
        .ok_or_else(invalid)?
        .windows(marker.len() + 2)
        .position(|window| window.starts_with(b"\r\n") && &window[2..] == marker)
        .ok_or_else(invalid)
}

fn delimiter_end(content_end: usize, marker: &[u8]) -> Result<usize, ProtocolFailure> {
    content_end
        .checked_add(2)
        .and_then(|start| start.checked_add(marker.len()))
        .ok_or_else(invalid)
}

fn resolve_part_end(
    body: &[u8],
    after: usize,
    content_end: usize,
) -> Result<(usize, usize), ProtocolFailure> {
    if body.get(after..after.saturating_add(2)) == Some(b"--") {
        return terminal_part_end(body, after, content_end);
    }
    if body.get(after..after.saturating_add(2)) == Some(b"\r\n") {
        return Ok((content_end, after + 2));
    }
    Err(invalid())
}

fn terminal_part_end(
    body: &[u8],
    after: usize,
    content_end: usize,
) -> Result<(usize, usize), ProtocolFailure> {
    let trailing = body.get(after + 2..).ok_or_else(invalid)?;
    if trailing.is_empty() || trailing == b"\r\n" {
        Ok((content_end, body.len()))
    } else {
        Err(invalid())
    }
}

fn disposition_parameter<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    let line = header_value(headers, "content-disposition")?;
    let mut pieces = line.split(';');
    validate_disposition_type(pieces.next()?)?;
    find_disposition_parameter(pieces, name)
}

fn validate_disposition_type(value: &str) -> Option<()> {
    value.trim().eq_ignore_ascii_case("form-data").then_some(())
}

fn find_disposition_parameter<'a>(
    pieces: impl Iterator<Item = &'a str>,
    name: &str,
) -> Option<&'a str> {
    for piece in pieces {
        let Some(candidate) = parse_disposition_piece(piece, name)? else {
            continue;
        };
        return Some(candidate);
    }
    None
}

fn parse_disposition_piece<'a>(piece: &'a str, name: &str) -> Option<Option<&'a str>> {
    let (parameter_name, value) = piece.trim().split_once('=')?;
    if !parameter_name.eq_ignore_ascii_case(name) {
        return Some(None);
    }
    Some(Some(parse_quoted_disposition_value(value)?))
}

fn parse_quoted_disposition_value(value: &str) -> Option<&str> {
    let value = value.trim();
    let inner = quoted_disposition_inner(value)?;
    valid_disposition_inner(inner)
}

fn quoted_disposition_inner(value: &str) -> Option<&str> {
    if value.len() < 2 {
        return None;
    }
    if !value.starts_with('"') {
        return None;
    }
    if !value.ends_with('"') {
        return None;
    }
    Some(&value[1..value.len() - 1])
}

fn valid_disposition_inner(value: &str) -> Option<&str> {
    if value.is_empty() {
        return None;
    }
    if value.contains('"') {
        return None;
    }
    if value.contains('\\') {
        return None;
    }
    Some(value)
}

fn header_value<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn parse_text_part(body: &[u8], start: usize, end: usize) -> Result<String, ProtocolFailure> {
    let bytes = body.get(start..end).ok_or_else(invalid)?;
    let value = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if value.is_empty() || value.contains('\r') || value.contains('\n') {
        return Err(invalid());
    }
    Ok(value.to_owned())
}

struct VecUploadSource {
    bytes: Bytes,
    offset: usize,
    complete: bool,
}

impl VecUploadSource {
    fn new(bytes: Bytes) -> Self {
        Self {
            bytes,
            offset: 0,
            complete: false,
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

impl FileUploadSource for VecUploadSource {
    fn next_chunk<'a>(
        &'a mut self,
        context: &'a RequestContext,
    ) -> ariadnion_api_files::BoxFileFuture<'a, Result<Option<FileChunk>, ApiFilesError>> {
        Box::pin(async move {
            if self.complete {
                return Ok(None);
            }
            context.check_active().map_err(ApiFilesError::from)?;
            if self.offset == self.bytes.len() {
                self.complete = true;
                return Ok(None);
            }
            let end = self
                .offset
                .saturating_add(MAX_UPLOAD_CHUNK_BYTES)
                .min(self.bytes.len());
            let chunk = FileChunk::new(self.bytes[self.offset..end].to_vec())
                .map_err(|_| ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure))?;
            self.offset = end;
            Ok(Some(chunk))
        })
    }
}

enum DownloadMessage {
    Chunk(Bytes),
    Complete,
    Error(ApiFilesError),
}

struct ChannelDownloadSink {
    sender: mpsc::Sender<DownloadMessage>,
    finished: bool,
}

impl ChannelDownloadSink {
    fn new(sender: mpsc::Sender<DownloadMessage>) -> Self {
        Self {
            sender,
            finished: false,
        }
    }
}

impl FileDownloadSink for ChannelDownloadSink {
    fn write_chunk<'a>(
        &'a mut self,
        chunk: FileChunk,
        context: &'a RequestContext,
    ) -> ariadnion_api_files::BoxFileFuture<'a, Result<(), ApiFilesError>> {
        Box::pin(async move {
            if self.finished {
                return Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure));
            }
            context.check_active().map_err(ApiFilesError::from)?;
            self.sender
                .send(DownloadMessage::Chunk(Bytes::from(chunk.into_bytes())))
                .await
                .map_err(|_| ApiFilesError::new(ApiFilesErrorCode::Cancelled))
        })
    }

    fn finish<'a>(
        &'a mut self,
        context: &'a RequestContext,
    ) -> ariadnion_api_files::BoxFileFuture<'a, Result<(), ApiFilesError>> {
        Box::pin(async move {
            if self.finished {
                return Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure));
            }
            context.check_active().map_err(ApiFilesError::from)?;
            self.finished = true;
            Ok(())
        })
    }
}

async fn run_download(
    service: Arc<dyn FileServicePort>,
    reference: ariadnion_api_domain::FileReference,
    expected: ariadnion_api_domain::FileDescriptor,
    sender: mpsc::Sender<DownloadMessage>,
    context: RequestContext,
) {
    let mut sink = ChannelDownloadSink::new(sender.clone());
    let result = service.content(&reference, &mut sink, &context).await;
    let message = match result {
        Ok(descriptor) if sink.finished && descriptor == expected => DownloadMessage::Complete,
        Ok(_) => DownloadMessage::Error(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure)),
        Err(error) => DownloadMessage::Error(error),
    };
    let _ = sender.send(message).await;
}

async fn watch_download_context(sender: mpsc::Sender<DownloadMessage>, context: RequestContext) {
    loop {
        if let Err(error) = context.check_active() {
            let _ = sender
                .send(DownloadMessage::Error(ApiFilesError::from(error)))
                .await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct DownloadBody {
    receiver: mpsc::Receiver<DownloadMessage>,
    expected: usize,
    delivered: usize,
    context: RequestContext,
    watch: Option<JoinHandle<()>>,
    done: bool,
}

impl DownloadBody {
    fn new(
        receiver: mpsc::Receiver<DownloadMessage>,
        expected: usize,
        context: RequestContext,
        watch: JoinHandle<()>,
    ) -> Self {
        Self {
            receiver,
            expected,
            delivered: 0,
            context,
            watch: Some(watch),
            done: false,
        }
    }

    fn finish(&mut self) {
        if !self.done {
            self.done = true;
            if let Some(watch) = self.watch.take() {
                watch.abort();
            }
            self.context.cancellation().cancel();
        }
    }

    fn process(
        &mut self,
        message: DownloadMessage,
    ) -> Poll<Option<Result<Bytes, ariadnion_api_http::ApiHttpError>>> {
        match message {
            DownloadMessage::Chunk(bytes) => self.process_chunk(bytes),
            DownloadMessage::Complete => self.process_complete(),
            DownloadMessage::Error(error) => self.process_error(error),
        }
    }

    fn process_chunk(
        &mut self,
        bytes: Bytes,
    ) -> Poll<Option<Result<Bytes, ariadnion_api_http::ApiHttpError>>> {
        let Some(next) = self.delivered.checked_add(bytes.len()) else {
            return self.integrity_failure();
        };
        if bytes.is_empty() || next > self.expected {
            return self.integrity_failure();
        }
        self.delivered = next;
        Poll::Ready(Some(Ok(bytes)))
    }

    fn process_complete(
        &mut self,
    ) -> Poll<Option<Result<Bytes, ariadnion_api_http::ApiHttpError>>> {
        let valid = self.delivered == self.expected;
        self.finish();
        if valid {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Err(http_files(ApiFilesErrorCode::IntegrityFailure))))
        }
    }

    fn process_error(
        &mut self,
        error: ApiFilesError,
    ) -> Poll<Option<Result<Bytes, ariadnion_api_http::ApiHttpError>>> {
        self.finish();
        Poll::Ready(Some(Err(map_api_error(error))))
    }

    fn integrity_failure(
        &mut self,
    ) -> Poll<Option<Result<Bytes, ariadnion_api_http::ApiHttpError>>> {
        self.finish();
        Poll::Ready(Some(Err(http_files(ApiFilesErrorCode::IntegrityFailure))))
    }
}

impl Stream for DownloadBody {
    type Item = Result<Bytes, ariadnion_api_http::ApiHttpError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Err(error) = self.context.check_active() {
            self.finish();
            return Poll::Ready(Some(Err(map_context_error(error))));
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(message)) => self.process(message),
            Poll::Ready(None) => {
                self.finish();
                Poll::Ready(Some(Err(http_files(ApiFilesErrorCode::Internal))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DownloadBody {
    fn drop(&mut self) {
        self.finish();
    }
}

fn map_files_error(error: OpenAiFilesError) -> ProtocolFailure {
    match error {
        OpenAiFilesError::Mapping(error) => map_provider(error),
        OpenAiFilesError::Service(error) => map_api_files(error),
        OpenAiFilesError::InvalidRequest => invalid(),
        OpenAiFilesError::IntegrityFailure => integrity(),
    }
}

fn map_provider(error: ProviderFilesError) -> ProtocolFailure {
    match error.code() {
        ariadnion_provider_files::ProviderFilesErrorCode::InvalidArgument => invalid(),
        ariadnion_provider_files::ProviderFilesErrorCode::LimitExceeded => payload_too_large(),
        ariadnion_provider_files::ProviderFilesErrorCode::NotFound => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::NotFound)
        }
        ariadnion_provider_files::ProviderFilesErrorCode::Unavailable => unavailable(),
        code => map_provider_secondary(code),
    }
}

fn map_provider_secondary(
    code: ariadnion_provider_files::ProviderFilesErrorCode,
) -> ProtocolFailure {
    match code {
        ariadnion_provider_files::ProviderFilesErrorCode::Unauthenticated => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::Unauthenticated)
        }
        ariadnion_provider_files::ProviderFilesErrorCode::Conflict => {
            ProtocolFailure::Domain(ariadnion_api_domain::ApiDomainError::new(
                ariadnion_api_domain::ApiDomainErrorCode::Conflict,
            ))
        }
        ariadnion_provider_files::ProviderFilesErrorCode::Cancelled => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::Cancelled)
        }
        ariadnion_provider_files::ProviderFilesErrorCode::DeadlineExceeded => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::DeadlineExceeded)
        }
        code => map_provider_terminal(code),
    }
}

fn map_provider_terminal(
    code: ariadnion_provider_files::ProviderFilesErrorCode,
) -> ProtocolFailure {
    match code {
        ariadnion_provider_files::ProviderFilesErrorCode::ResourceExhausted => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::ResourceExhausted)
        }
        ariadnion_provider_files::ProviderFilesErrorCode::CommitIndeterminate
        | ariadnion_provider_files::ProviderFilesErrorCode::Internal => internal(),
        _ => internal(),
    }
}

fn map_api_files(error: ApiFilesError) -> ProtocolFailure {
    match error.code() {
        ApiFilesErrorCode::InvalidArgument => invalid(),
        ApiFilesErrorCode::NotFound => http_error(ariadnion_api_http::ApiHttpErrorCode::NotFound),
        ApiFilesErrorCode::Unavailable => unavailable(),
        ApiFilesErrorCode::Unauthenticated => map_api_auth(),
        ApiFilesErrorCode::LimitExceeded => payload_too_large(),
        code => map_api_secondary(code),
    }
}

fn map_api_auth() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::Unauthenticated)
}

fn map_api_secondary(code: ApiFilesErrorCode) -> ProtocolFailure {
    match code {
        ApiFilesErrorCode::Conflict => {
            ProtocolFailure::Domain(ariadnion_api_domain::ApiDomainError::new(
                ariadnion_api_domain::ApiDomainErrorCode::Conflict,
            ))
        }
        ApiFilesErrorCode::PolicyRejected => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::Forbidden)
        }
        ApiFilesErrorCode::Cancelled => http_error(ariadnion_api_http::ApiHttpErrorCode::Cancelled),
        ApiFilesErrorCode::DeadlineExceeded => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::DeadlineExceeded)
        }
        code => map_api_terminal(code),
    }
}

fn map_api_terminal(code: ApiFilesErrorCode) -> ProtocolFailure {
    match code {
        ApiFilesErrorCode::ResourceExhausted => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::ResourceExhausted)
        }
        ApiFilesErrorCode::CommitIndeterminate | ApiFilesErrorCode::IntegrityFailure => internal(),
        ApiFilesErrorCode::Internal => internal(),
        _ => internal(),
    }
}

fn map_api_error(error: ApiFilesError) -> ariadnion_api_http::ApiHttpError {
    match map_api_files(error) {
        ProtocolFailure::Http(error) => error,
        _ => ariadnion_api_http::ApiHttpError::new(ariadnion_api_http::ApiHttpErrorCode::Internal),
    }
}

fn http_files(code: ApiFilesErrorCode) -> ariadnion_api_http::ApiHttpError {
    map_api_error(ApiFilesError::new(code))
}

fn map_context_error(error: ariadnion_core::CoreError) -> ariadnion_api_http::ApiHttpError {
    let code = match error.code() {
        ariadnion_core::ErrorCode::Cancelled => ariadnion_api_http::ApiHttpErrorCode::Cancelled,
        ariadnion_core::ErrorCode::DeadlineExceeded => {
            ariadnion_api_http::ApiHttpErrorCode::DeadlineExceeded
        }
        _ => ariadnion_api_http::ApiHttpErrorCode::Internal,
    };
    ariadnion_api_http::ApiHttpError::new(code)
}

fn http_error(code: ariadnion_api_http::ApiHttpErrorCode) -> ProtocolFailure {
    ProtocolFailure::Http(ariadnion_api_http::ApiHttpError::new(code))
}

fn invalid() -> ProtocolFailure {
    ProtocolFailure::invalid_parameter(None)
}

fn unsupported_media_type() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::UnsupportedMediaType)
}

fn integrity() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::Internal)
}

fn internal() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::Internal)
}

fn unavailable() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::Unavailable)
}

fn payload_too_large() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::PayloadTooLarge)
}

fn body_read_failure(context: &RequestContext) -> ProtocolFailure {
    match context.check_active() {
        Ok(()) => payload_too_large(),
        Err(error) => ProtocolFailure::from(ariadnion_api_domain::ApiDomainError::from(error)),
    }
}

// crates/optional/ariadnion-api-http/src/public/file_list.rs - Native file list HTTP ingress.
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

//! Native bounded metadata-list projection.

use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_api_domain::{ApiDomainError, FileDescriptor};
use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, FileListCursor, FileListPage, FileListRequest, FilePageLimit,
    FileServicePort,
};
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;

use super::error::{ResponseFailure, domain_failure, failure, response_with_request_id};
use super::{ApiHttpError, HttpApiState, HttpRequestIdentity, execution};

const DEFAULT_FILE_PAGE_LIMIT: usize = 100;
const MAX_FILE_LIST_QUERY_BYTES: usize = 4 * 1024;

/// Handles one authenticated, bounded metadata-list request.
pub(super) async fn handle_list(
    State(state): State<HttpApiState>,
    request: Request<Body>,
) -> Response {
    let (parts, _body) = request.into_parts();
    let admission = match admit_request(&state, &parts.headers) {
        Ok(admission) => admission,
        Err(response) => return *response,
    };
    let prepared = match prepare_list(&state, &parts.headers, parts.uri.query(), admission).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    execute_list(prepared).await
}

async fn execute_list(prepared: PreparedList) -> Response {
    let PreparedList {
        permit,
        identity,
        service,
        mut lifetime,
        context,
        request,
    } = prepared;
    let result = execution::within_request_context(&context, service.list(request, &context)).await;
    drop(permit);
    match result {
        Ok(Ok(page)) => {
            lifetime.disarm();
            list_response(&identity, &page)
        }
        Ok(Err(error)) => file_failure_response(identity, FileFailure::Files(error)),
        Err(error) => file_failure_response(identity, FileFailure::Files(error.into())),
    }
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
                ApiHttpError::new(super::ApiHttpErrorCode::ResourceExhausted),
            )
            .into_response(),
        )
    })?;
    execution::validate_header_budget(headers)
        .map_err(|error| Box::new(failure(generated.clone(), error).into_response()))?;
    let identity = resolve_identity(generated, headers)
        .map_err(|(identity, error)| Box::new(failure(identity, error).into_response()))?;
    let deadline = execution::parse_deadline(headers, SystemTime::now())
        .map_err(|error| Box::new(failure(identity.clone(), error).into_response()))?;
    Ok(RequestAdmission {
        identity,
        deadline,
        permit,
    })
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
            ApiHttpError::new(super::ApiHttpErrorCode::InvalidRequest),
        )
    })?;
    let request_id = ariadnion_core::RequestId::parse(text).map_err(|_| {
        (
            generated.clone(),
            ApiHttpError::new(super::ApiHttpErrorCode::InvalidRequest),
        )
    })?;
    Ok(HttpRequestIdentity::new(
        request_id,
        generated.trace_id().clone(),
    ))
}

struct PreparedList {
    permit: OwnedSemaphorePermit,
    identity: HttpRequestIdentity,
    service: Arc<dyn FileServicePort>,
    lifetime: RequestLifetime,
    context: RequestContext,
    request: FileListRequest,
}

async fn prepare_list(
    state: &HttpApiState,
    headers: &HeaderMap,
    query: Option<&str>,
    admission: RequestAdmission,
) -> Result<PreparedList, Box<Response>> {
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
    let request = parse_list_request(query).map_err(|error| {
        Box::new(ResponseFailure::file(identity.clone(), error).into_response())
    })?;
    let authorization = execution::parse_authorization(headers)
        .map_err(|error| Box::new(failure(identity.clone(), error).into_response()))?;
    let lifetime = RequestLifetime::new(&state.shutdown);
    let context = authenticate_context(state, &identity, deadline, authorization, &lifetime)
        .await
        .map_err(|error| Box::new(file_failure_response(identity.clone(), error)))?;
    Ok(PreparedList {
        permit,
        identity,
        service,
        lifetime,
        context,
        request,
    })
}

fn parse_list_request(query: Option<&str>) -> Result<FileListRequest, ApiFilesError> {
    match query {
        Some(query) => parse_present_list_request(query),
        None => default_list_request(),
    }
}

fn parse_present_list_request(query: &str) -> Result<FileListRequest, ApiFilesError> {
    if query.is_empty() || query.len() > MAX_FILE_LIST_QUERY_BYTES {
        return Err(file_invalid());
    }
    let (limit, cursor) = parse_query_pairs(query)?;
    let limit = limit.unwrap_or(default_page_limit()?);
    Ok(FileListRequest::new(cursor, limit))
}

fn parse_query_pairs(
    query: &str,
) -> Result<(Option<FilePageLimit>, Option<FileListCursor>), ApiFilesError> {
    let mut limit = None;
    let mut cursor = None;
    for pair in query.split('&') {
        let (key, value) = parse_query_pair(pair)?;
        match key {
            "limit" => assign_limit(&mut limit, value),
            "cursor" => assign_cursor(&mut cursor, value),
            _ => Err(file_invalid()),
        }?;
    }
    Ok((limit, cursor))
}

fn parse_query_pair(pair: &str) -> Result<(&str, &str), ApiFilesError> {
    let Some((key, value)) = pair.split_once('=') else {
        return Err(file_invalid());
    };
    if key.is_empty() || value.is_empty() {
        return Err(file_invalid());
    }
    Ok((key, value))
}

fn assign_limit(slot: &mut Option<FilePageLimit>, value: &str) -> Result<(), ApiFilesError> {
    if slot.is_some() {
        return Err(file_invalid());
    }
    *slot = Some(parse_limit(value)?);
    Ok(())
}

fn assign_cursor(slot: &mut Option<FileListCursor>, value: &str) -> Result<(), ApiFilesError> {
    if slot.is_some() {
        return Err(file_invalid());
    }
    *slot = Some(parse_cursor(value)?);
    Ok(())
}

fn default_list_request() -> Result<FileListRequest, ApiFilesError> {
    Ok(FileListRequest::new(None, default_page_limit()?))
}

fn default_page_limit() -> Result<FilePageLimit, ApiFilesError> {
    FilePageLimit::new(DEFAULT_FILE_PAGE_LIMIT)
}

fn parse_limit(value: &str) -> Result<FilePageLimit, ApiFilesError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(file_invalid());
    }
    let parsed = value.parse::<usize>().map_err(|_| file_invalid())?;
    if parsed.to_string() != value {
        return Err(file_invalid());
    }
    FilePageLimit::new(parsed)
}

fn parse_cursor(value: &str) -> Result<FileListCursor, ApiFilesError> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| file_invalid())?;
    let cursor = FileListCursor::new(&decoded)?;
    let canonical = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cursor.as_bytes());
    if canonical != value {
        return Err(file_invalid());
    }
    Ok(cursor)
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
    let evidence = execution::within_request_context(
        &anonymous,
        state
            .authentication
            .authenticate(&authorization, &anonymous),
    )
    .await
    .map_err(|error| FileFailure::Files(error.into()))?
    .map_err(FileFailure::Http)?;
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

fn list_response(identity: &HttpRequestIdentity, page: &FileListPage) -> Response {
    let body = ListResponseDto::from_page(page);
    let body = match serde_json::to_vec(&body) {
        Ok(body) => body,
        Err(_) => {
            return failure(
                identity.clone(),
                ApiHttpError::new(super::ApiHttpErrorCode::Internal),
            )
            .into_response();
        }
    };
    let mut response = (StatusCode::OK, Body::from(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response_with_request_id(identity, response)
}

#[derive(Serialize)]
struct ListResponseDto {
    files: Vec<FileDescriptorDto>,
    next_cursor: Option<String>,
}

impl ListResponseDto {
    fn from_page(page: &FileListPage) -> Self {
        Self {
            files: page
                .files()
                .iter()
                .map(FileDescriptorDto::from_descriptor)
                .collect(),
            next_cursor: page.next_cursor().map(|cursor| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cursor.as_bytes())
            }),
        }
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

fn file_failure_response(identity: HttpRequestIdentity, error: FileFailure) -> Response {
    match error {
        FileFailure::Http(error) => failure(identity, error).into_response(),
        FileFailure::Domain(error) => domain_failure(identity, error).into_response(),
        FileFailure::Files(error) => ResponseFailure::file(identity, error).into_response(),
    }
}

fn file_invalid() -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::InvalidArgument)
}

enum FileFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
    Files(ApiFilesError),
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

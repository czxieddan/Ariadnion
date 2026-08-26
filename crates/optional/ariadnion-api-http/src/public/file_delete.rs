// crates/optional/ariadnion-api-http/src/public/file_delete.rs - Native file deletion HTTP ingress.
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

//! Native authenticated file deletion over the provider-neutral file port.

use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_api_domain::{ApiDomainError, FileReference};
use ariadnion_api_files::{ApiFilesError, ApiFilesErrorCode, FileDeleteRequest, FileServicePort};
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext, RequestId};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio::sync::OwnedSemaphorePermit;

use super::error::{ResponseFailure, domain_failure, failure, response_with_request_id};
use super::{ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpRequestIdentity, execution};

const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const REFERENCE_HEX_BYTES: usize = FileReference::BYTE_LENGTH * 2;

/// Handles one authenticated deletion without reading the request body.
pub(super) async fn handle_delete(
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
    let prepared = match prepare_delete(&state, &parts.headers, reference_text, admission).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    execute_delete(prepared).await
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

struct PreparedDelete {
    permit: OwnedSemaphorePermit,
    identity: HttpRequestIdentity,
    service: Arc<dyn FileServicePort>,
    reference: FileReference,
    idempotency_key: super::IdempotencyKey,
    lifetime: RequestLifetime,
    context: RequestContext,
}

async fn prepare_delete(
    state: &HttpApiState,
    headers: &HeaderMap,
    reference_text: Option<&str>,
    admission: RequestAdmission,
) -> Result<PreparedDelete, Box<Response>> {
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
    let idempotency_key = parse_idempotency_key(headers)
        .map_err(|error| Box::new(file_failure_response(identity.clone(), error)))?;
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
    Ok(PreparedDelete {
        permit,
        identity,
        service,
        reference,
        idempotency_key,
        lifetime,
        context,
    })
}

async fn execute_delete(prepared: PreparedDelete) -> Response {
    let PreparedDelete {
        permit,
        identity,
        service,
        reference,
        idempotency_key,
        lifetime: _lifetime,
        context,
    } = prepared;
    let request = FileDeleteRequest::new(reference, idempotency_key);
    if let Err(error) = context.check_active() {
        drop(permit);
        return file_failure_response(identity, ApiFilesError::from(error));
    }
    // Do not wrap this future in within_request_context: a service that reports
    // CommitIndeterminate after cancelling its context must retain that outcome.
    let result = service.delete(request, &context).await;
    drop(permit);
    match result {
        Ok(()) => delete_response(&identity),
        Err(error) => file_failure_response(identity, error),
    }
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

fn parse_idempotency_key(headers: &HeaderMap) -> Result<super::IdempotencyKey, FileFailure> {
    let value = execution::one_header(headers, IDEMPOTENCY_HEADER, true)
        .map_err(|_| file_invalid())?
        .ok_or_else(file_invalid)?;
    let value = value.to_str().map_err(|_| file_invalid())?;
    super::IdempotencyKey::new(value).map_err(|_| file_invalid())
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

fn delete_response(identity: &HttpRequestIdentity) -> Response {
    let response = StatusCode::NO_CONTENT.into_response();
    response_with_request_id(identity, response)
}

fn admit_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<(HttpRequestIdentity, SystemTime), (HttpRequestIdentity, ApiHttpError)> {
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

fn file_invalid() -> FileFailure {
    FileFailure::Files(ApiFilesError::new(ApiFilesErrorCode::InvalidArgument))
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

fn file_failure_response(identity: HttpRequestIdentity, error: impl Into<FileFailure>) -> Response {
    match error.into() {
        FileFailure::Http(error) => failure(identity, error).into_response(),
        FileFailure::Domain(error) => domain_failure(identity, error).into_response(),
        FileFailure::Files(error) => ResponseFailure::file(identity, error).into_response(),
    }
}

struct RequestLifetime {
    cancellation: CancellationToken,
}

impl RequestLifetime {
    fn new(shutdown: &CancellationToken) -> Self {
        Self {
            cancellation: shutdown.child(),
        }
    }

    fn token(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

impl Drop for RequestLifetime {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

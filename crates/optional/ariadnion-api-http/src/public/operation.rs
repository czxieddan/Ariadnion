// crates/optional/ariadnion-api-http/src/public/operation.rs - Authenticated protocol operations.
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
//! Shared authenticated execution for protocol-owned REST operations.

use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use ariadnion_api_domain::ApiDomainError;
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext, RequestId};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, get, post};
use futures_core::Stream;
use tokio::sync::OwnedSemaphorePermit;

use super::execution;
use super::protocol::validate_response_header_budget;
use super::{
    ApiHttpError, ApiHttpErrorCode, BoxHttpBodyStream, HttpApiState, HttpRequestIdentity,
    ProtocolBufferedResponse, ProtocolFailure, ProtocolStreamResponse,
};

const REQUEST_ID_HEADER: &str = "x-request-id";

/// One authenticated protocol operation response.
///
/// Operation adapters use this type for REST surfaces whose work cannot be
/// represented by the shared service-dispatch enum. Both variants retain the
/// same bounded response validation and HTTP lifetime as ordinary projections.
pub enum ProtocolOperationResponse {
    /// A finite response validated before HTTP commitment.
    Buffered(ProtocolBufferedResponse),
    /// A non-buffering response whose body retains request cancellation.
    Stream(ProtocolStreamResponse),
}

/// A boxed authenticated protocol operation future.
pub type BoxProtocolOperationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<ProtocolOperationResponse, ProtocolFailure>> + Send + 'a>,
>;

/// Executes one protocol-owned REST operation after common authentication.
///
/// Shared execution validates the aggregate header budget, resolves request and
/// trace identity, applies global admission, authenticates the bounded Bearer
/// credential, removes that credential, and supplies one authenticated context.
/// The adapter owns method-specific body, query, content-type, and wire grammar.
pub trait HttpOperationProtocolAdapter: Send + Sync {
    /// Executes one authenticated request under the supplied lifecycle context.
    ///
    /// The request body is not polled before this method is called. An adapter
    /// can therefore reject a missing capability, invalid header, or inactive
    /// context before consuming a large streaming upload.
    fn execute<'a>(
        &'a self,
        request: Request<Body>,
        identity: &'a HttpRequestIdentity,
        context: &'a RequestContext,
    ) -> BoxProtocolOperationFuture<'a>;

    /// Projects a classified pre-commit failure into bounded protocol bytes.
    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure>;
}

/// Cloneable state for one authenticated protocol operation route family.
#[derive(Clone)]
pub struct ProtocolOperationExecutionState {
    http: HttpApiState,
    protocol: Arc<dyn HttpOperationProtocolAdapter>,
}

impl ProtocolOperationExecutionState {
    /// Creates operation state over shared public HTTP capabilities.
    #[must_use]
    pub const fn new(
        http: HttpApiState,
        protocol: Arc<dyn HttpOperationProtocolAdapter>,
    ) -> Self {
        Self { http, protocol }
    }
}

impl Debug for ProtocolOperationExecutionState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolOperationExecutionState")
            .finish_non_exhaustive()
    }
}

/// Returns the shared authenticated GET operation handler.
pub fn protocol_operation_get_route() -> MethodRouter<ProtocolOperationExecutionState> {
    get(handle_operation)
}

/// Returns the shared authenticated POST operation handler.
pub fn protocol_operation_post_route() -> MethodRouter<ProtocolOperationExecutionState> {
    post(handle_operation)
}

/// Returns the shared authenticated DELETE operation handler.
pub fn protocol_operation_delete_route() -> MethodRouter<ProtocolOperationExecutionState> {
    delete(handle_operation)
}

async fn handle_operation(
    State(state): State<ProtocolOperationExecutionState>,
    request: Request<Body>,
) -> Response {
    match try_handle_operation(&state, request).await {
        Ok(response) => response,
        Err(failure) => project_failure(state.protocol.as_ref(), failure),
    }
}

async fn try_handle_operation(
    state: &ProtocolOperationExecutionState,
    request: Request<Body>,
) -> Result<Response, OperationFailure> {
    let (identity, permit) = issue_and_admit(&state.http)?;
    let admitted = admit_request(&state.http, identity, request)?;
    let authenticated = authenticate_request(&state.http, admitted).await?;
    run_adapter(state.protocol.as_ref(), authenticated, permit).await
}

fn issue_and_admit(
    state: &HttpApiState,
) -> Result<(HttpRequestIdentity, OwnedSemaphorePermit), OperationFailure> {
    let identity = state
        .identity
        .issue()
        .map_err(|error| OperationFailure::http(state.identity.fallback_identity(), error))?;
    let permit = state.admission.clone().try_acquire_owned().map_err(|_| {
        OperationFailure::http(
            identity.clone(),
            ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted),
        )
    })?;
    Ok((identity, permit))
}

fn admit_request(
    state: &HttpApiState,
    generated: HttpRequestIdentity,
    request: Request<Body>,
) -> Result<OperationAdmission, OperationFailure> {
    let (mut parts, body) = request.into_parts();
    execution::validate_header_budget(&parts.headers)
        .map_err(|error| OperationFailure::http(generated.clone(), error))?;
    let identity = resolve_identity(generated, &parts.headers)?;
    let deadline = execution::parse_deadline(&parts.headers, SystemTime::now())
        .map_err(|error| OperationFailure::http(identity.clone(), error))?;
    let cancellation = OperationCancellation::new(&state.shutdown);
    let anonymous = request_context(&identity, deadline, cancellation.token(), None);
    check_context(&identity, &anonymous)?;
    let authorization = execution::parse_authorization(&parts.headers)
        .map_err(|error| OperationFailure::authentication(identity.clone(), error))?;
    parts.headers.remove(header::AUTHORIZATION);
    Ok(OperationAdmission {
        identity,
        deadline,
        cancellation,
        anonymous,
        authorization,
        request: Request::from_parts(parts, body),
    })
}

async fn authenticate_request(
    state: &HttpApiState,
    admission: OperationAdmission,
) -> Result<AuthenticatedOperation, OperationFailure> {
    let result = execution::within_request_context(
        &admission.anonymous,
        state
            .authentication
            .authenticate(&admission.authorization, &admission.anonymous),
    )
    .await
    .map_err(|error| OperationFailure::domain(admission.identity.clone(), error))?;
    let evidence = result.map_err(|error| {
        OperationFailure::authentication(admission.identity.clone(), error)
    })?;
    let principal = PrincipalContext::new(
        evidence.tenant_id().clone(),
        evidence.principal_id().clone(),
    );
    let context = request_context(
        &admission.identity,
        admission.deadline,
        admission.cancellation.token(),
        Some(principal),
    );
    check_context(&admission.identity, &context)?;
    Ok(AuthenticatedOperation {
        identity: admission.identity,
        cancellation: admission.cancellation,
        context,
        request: admission.request,
    })
}

async fn run_adapter(
    protocol: &dyn HttpOperationProtocolAdapter,
    operation: AuthenticatedOperation,
    permit: OwnedSemaphorePermit,
) -> Result<Response, OperationFailure> {
    let AuthenticatedOperation {
        identity,
        mut cancellation,
        context,
        request,
    } = operation;
    let projected = protocol
        .execute(request, &identity, &context)
        .await
        .map_err(|failure| OperationFailure::new(identity.clone(), failure))?;
    match projected {
        ProtocolOperationResponse::Buffered(response) => {
            check_context(&identity, &context)?;
            let response = finalize_buffered(&identity, response, false)?;
            cancellation.disarm();
            drop(permit);
            Ok(response)
        }
        ProtocolOperationResponse::Stream(response) => {
            finalize_stream(&identity, response, cancellation, permit)
        }
    }
}

fn resolve_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<HttpRequestIdentity, OperationFailure> {
    let value = execution::one_header(headers, REQUEST_ID_HEADER, false)
        .map_err(|error| OperationFailure::http(generated.clone(), error))?;
    let Some(value) = value else {
        return Ok(generated);
    };
    let text = value.to_str().map_err(|_| {
        OperationFailure::http(
            generated.clone(),
            ApiHttpError::new(ApiHttpErrorCode::InvalidRequest),
        )
    })?;
    let request_id = RequestId::parse(text).map_err(|_| {
        OperationFailure::http(
            generated.clone(),
            ApiHttpError::new(ApiHttpErrorCode::InvalidRequest),
        )
    })?;
    Ok(generated.replace_request_id(request_id))
}

fn request_context(
    identity: &HttpRequestIdentity,
    deadline: SystemTime,
    cancellation: CancellationToken,
    principal: Option<PrincipalContext>,
) -> RequestContext {
    RequestContext::new(
        identity.request_id().clone(),
        identity.trace_id().clone(),
        principal,
        Some(deadline),
        cancellation,
    )
}

fn check_context(
    identity: &HttpRequestIdentity,
    context: &RequestContext,
) -> Result<(), OperationFailure> {
    context
        .check_active()
        .map_err(ApiDomainError::from)
        .map_err(|error| OperationFailure::domain(identity.clone(), error))
}

fn finalize_buffered(
    identity: &HttpRequestIdentity,
    projected: ProtocolBufferedResponse,
    challenge: bool,
) -> Result<Response, OperationFailure> {
    let (status, headers, body) = projected.into_parts();
    let headers = finalize_headers(identity, headers, challenge)?;
    let mut response = Body::from(body).into_response();
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn finalize_stream(
    identity: &HttpRequestIdentity,
    projected: ProtocolStreamResponse,
    cancellation: OperationCancellation,
    permit: OwnedSemaphorePermit,
) -> Result<Response, OperationFailure> {
    let (status, headers, stream) = projected.into_parts();
    let headers = finalize_headers(identity, headers, false)?;
    let lifecycle = OperationBodyStream::new(stream, cancellation, permit);
    let mut response = Body::from_stream(lifecycle).into_response();
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn finalize_headers(
    identity: &HttpRequestIdentity,
    mut headers: HeaderMap,
    challenge: bool,
) -> Result<HeaderMap, OperationFailure> {
    headers.remove(header::WWW_AUTHENTICATE);
    if challenge {
        headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    let request_id = HeaderValue::from_str(identity.request_id().as_str()).map_err(|_| {
        OperationFailure::http(
            identity.clone(),
            ApiHttpError::new(ApiHttpErrorCode::Internal),
        )
    })?;
    headers.insert(REQUEST_ID_HEADER, request_id);
    validate_response_header_budget(&headers)
        .map_err(|failure| OperationFailure::new(identity.clone(), failure))?;
    Ok(headers)
}

fn project_failure(
    protocol: &dyn HttpOperationProtocolAdapter,
    failure: OperationFailure,
) -> Response {
    let challenge = failure.bearer_challenge;
    match protocol.project_failure(&failure.identity, failure.failure) {
        Ok(projected) => finalize_buffered(&failure.identity, projected, challenge)
            .unwrap_or_else(|_| internal_fallback(&failure.identity)),
        Err(_) => internal_fallback(&failure.identity),
    }
}

fn internal_fallback(identity: &HttpRequestIdentity) -> Response {
    let mut response = Body::from("Internal Server Error").into_response();
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(value) = HeaderValue::from_str(identity.request_id().as_str()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

struct OperationAdmission {
    identity: HttpRequestIdentity,
    deadline: SystemTime,
    cancellation: OperationCancellation,
    anonymous: RequestContext,
    authorization: super::PresentedBearer,
    request: Request<Body>,
}

struct AuthenticatedOperation {
    identity: HttpRequestIdentity,
    cancellation: OperationCancellation,
    context: RequestContext,
    request: Request<Body>,
}

struct OperationFailure {
    identity: HttpRequestIdentity,
    failure: ProtocolFailure,
    bearer_challenge: bool,
}

impl OperationFailure {
    const fn new(identity: HttpRequestIdentity, failure: ProtocolFailure) -> Self {
        Self {
            identity,
            failure,
            bearer_challenge: false,
        }
    }

    const fn http(identity: HttpRequestIdentity, error: ApiHttpError) -> Self {
        Self::new(identity, ProtocolFailure::Http(error))
    }

    const fn domain(identity: HttpRequestIdentity, error: ApiDomainError) -> Self {
        Self::new(identity, ProtocolFailure::Domain(error))
    }

    fn authentication(identity: HttpRequestIdentity, error: ApiHttpError) -> Self {
        let bearer_challenge = error.code() == ApiHttpErrorCode::Unauthenticated;
        Self {
            identity,
            failure: ProtocolFailure::Http(error),
            bearer_challenge,
        }
    }
}

struct OperationCancellation {
    cancellation: CancellationToken,
    armed: bool,
}

impl OperationCancellation {
    fn new(shutdown: &CancellationToken) -> Self {
        Self {
            cancellation: shutdown.child(),
            armed: true,
        }
    }

    fn token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for OperationCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.cancel();
        }
    }
}

struct OperationBodyStream {
    stream: BoxHttpBodyStream,
    cancellation: OperationCancellation,
    permit: Option<OwnedSemaphorePermit>,
    finished: bool,
}

impl OperationBodyStream {
    fn new(
        stream: BoxHttpBodyStream,
        cancellation: OperationCancellation,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            stream,
            cancellation,
            permit: Some(permit),
            finished: false,
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.cancellation.cancel();
        self.permit.take();
    }
}

impl Stream for OperationBodyStream {
    type Item = Result<axum::body::Bytes, ApiHttpError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = self.stream.as_mut().poll_next(context);
        if matches!(next, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.finish();
        }
        next
    }
}

impl Drop for OperationBodyStream {
    fn drop(&mut self) {
        self.finish();
    }
}

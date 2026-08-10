// crates/optional/ariadnion-api-http/src/public/execution.rs - Shared authenticated HTTP execution for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Shared admission, authentication, dispatch, cancellation, and body lifetime.

use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_api_dispatch::ServiceDispatchOutcome;
use ariadnion_api_domain::{ApiDomainError, ApiDomainErrorCode, ResponseMode};
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext, RequestId};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_core::Stream;
use tokio::sync::OwnedSemaphorePermit;
use zeroize::Zeroize;

use super::error::{invalid_request, response_with_request_id, unauthenticated};
use super::protocol::validate_response_header_budget;
use super::{
    ApiHttpError, ApiHttpErrorCode, BoxHttpBodyStream, HttpApiState, HttpProtocolAdapter,
    HttpProtocolProjection, HttpRequestIdentity, MAX_PRESENTED_BEARER_BYTES, MAX_PUBLIC_BODY_BYTES,
    MAX_PUBLIC_HEADER_BYTES, MAX_PUBLIC_HEADERS, ProtocolBufferedResponse, ProtocolExecutionState,
    ProtocolFailure, ProtocolRequest, ProtocolRequestBody, ProtocolStreamResponse,
};

const DEFAULT_DEADLINE_WINDOW: Duration = Duration::from_secs(30);
const MAX_DEADLINE_WINDOW: Duration = Duration::from_secs(120);
// Core cancellation is deliberately callback-free, so bounded waits poll it
// at this interval while the absolute request deadline remains authoritative.
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);
const DEADLINE_HEADER: &str = "x-ariadnion-deadline-unix-ms";
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Ephemeral Bearer credential material presented to an authentication port.
pub struct PresentedBearer {
    credential: Box<[u8]>,
}

impl PresentedBearer {
    /// Parses one bounded Bearer authorization field.
    ///
    /// # Errors
    ///
    /// Returns ApiHttpErrorCode::Unauthenticated without retaining rejected
    /// material when the scheme or credential syntax is invalid.
    pub fn parse(value: &[u8]) -> Result<Self, ApiHttpError> {
        let credential = value
            .strip_prefix(b"Bearer ")
            .filter(|token| valid_bearer_token(value, token))
            .ok_or_else(unauthenticated)?;
        Ok(Self {
            credential: Box::from(credential),
        })
    }

    /// Borrows the credential for immediate authentication.
    ///
    /// Callers must not retain, format, trace, or log the returned bytes.
    #[must_use]
    pub fn credential_bytes(&self) -> &[u8] {
        &self.credential
    }
}

impl Debug for PresentedBearer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PresentedBearer(<redacted>)")
    }
}

impl Drop for PresentedBearer {
    fn drop(&mut self) {
        self.credential.zeroize();
    }
}

pub(super) async fn handle_protocol(
    State(state): State<ProtocolExecutionState>,
    request: Request<Body>,
) -> Response {
    handle_request(state.http(), state.protocol(), request).await
}

pub(super) async fn handle_request(
    state: &HttpApiState,
    protocol: &dyn HttpProtocolAdapter,
    request: Request<Body>,
) -> Response {
    let generated = state.identity.issue();
    let permit = match state.admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return project_capacity_failure(protocol, generated),
    };
    match execute_request(state, protocol, generated, request, permit).await {
        Ok(response) => response,
        Err(failure) => project_failure(protocol, failure),
    }
}

fn project_capacity_failure(
    protocol: &dyn HttpProtocolAdapter,
    identity: HttpRequestIdentity,
) -> Response {
    let failure = ExecutionFailure::http(
        identity,
        ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted),
    );
    project_failure(protocol, failure)
}

async fn execute_request(
    state: &HttpApiState,
    protocol: &dyn HttpProtocolAdapter,
    generated: HttpRequestIdentity,
    request: Request<Body>,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ExecutionFailure> {
    let admission = admit_request(state, protocol, generated, request).await?;
    let authenticated = authenticate_request(state, admission).await?;
    dispatch_request(state, authenticated, permit).await
}

async fn admit_request(
    state: &HttpApiState,
    protocol: &dyn HttpProtocolAdapter,
    generated: HttpRequestIdentity,
    request: Request<Body>,
) -> Result<RequestAdmission, ExecutionFailure> {
    let (mut parts, body) = request.into_parts();
    let (identity, deadline) = admit_headers(generated, &parts.headers)?;
    let cancellation = RequestCancellation::new(&state.shutdown);
    let anonymous = anonymous_context(&identity, deadline, cancellation.token());
    check_active(&anonymous).map_err(|error| ExecutionFailure::domain(identity.clone(), error))?;
    let authorization = parse_authorization(&parts.headers)
        .map_err(|error| ExecutionFailure::authentication(identity.clone(), error))?;
    parts.headers.remove(header::AUTHORIZATION);
    let bytes = collect_body(&anonymous, body)
        .await
        .map_err(|failure| failure.with_identity(identity.clone()))?;
    let request = protocol
        .decode(ProtocolRequestBody::new(bytes, parts.headers))
        .map_err(|failure| ExecutionFailure::new(identity.clone(), failure))?;
    check_active(&anonymous).map_err(|error| ExecutionFailure::domain(identity.clone(), error))?;
    Ok(RequestAdmission {
        identity,
        deadline,
        cancellation,
        anonymous,
        request,
        authorization,
    })
}

fn admit_headers(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<(HttpRequestIdentity, SystemTime), ExecutionFailure> {
    validate_header_budget(headers)
        .map_err(|error| ExecutionFailure::http(generated.clone(), error))?;
    let identity = resolve_identity(generated, headers)?;
    validate_media_type(headers)
        .map_err(|error| ExecutionFailure::http(identity.clone(), error))?;
    validate_content_length(headers)
        .map_err(|error| ExecutionFailure::http(identity.clone(), error))?;
    let deadline = parse_deadline(headers, SystemTime::now())
        .map_err(|error| ExecutionFailure::http(identity.clone(), error))?;
    Ok((identity, deadline))
}

async fn authenticate_request(
    state: &HttpApiState,
    admission: RequestAdmission,
) -> Result<AuthenticatedRequest, ExecutionFailure> {
    let evidence = authenticate(
        state,
        &admission.authorization,
        &admission.anonymous,
        admission.deadline,
    )
    .await
    .map_err(|failure| failure.with_identity(admission.identity.clone()))?;
    require_stream_capability(
        admission.request.response_mode(),
        admission.request.projection().supports_streaming(),
    )
    .map_err(|error| ExecutionFailure::http(admission.identity.clone(), error))?;
    let context = authenticated_context(
        &admission.identity,
        admission.deadline,
        admission.cancellation.token(),
        &evidence,
    );
    let (request, response_mode, projection) = admission.request.into_parts();
    Ok(AuthenticatedRequest {
        identity: admission.identity,
        deadline: admission.deadline,
        cancellation: admission.cancellation,
        request,
        response_mode,
        projection,
        evidence,
        context,
    })
}

async fn dispatch_request(
    state: &HttpApiState,
    request: AuthenticatedRequest,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ExecutionFailure> {
    let AuthenticatedRequest {
        identity,
        deadline,
        cancellation,
        request,
        response_mode,
        projection,
        evidence,
        context,
    } = request;
    let result = within_deadline(
        deadline,
        state.dispatch.dispatch(request, &evidence, &context),
    )
    .await
    .map_err(|error| ExecutionFailure::domain(identity.clone(), error))?;
    let outcome = result.map_err(|error| ExecutionFailure::domain(identity.clone(), error))?;
    let dispatched = DispatchedRequest {
        identity,
        cancellation,
        response_mode,
        projection,
        context,
    };
    project_dispatch_outcome(dispatched, outcome, permit)
}

fn project_dispatch_outcome(
    request: DispatchedRequest,
    outcome: ServiceDispatchOutcome,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ExecutionFailure> {
    match (request.response_mode, outcome) {
        (ResponseMode::Complete, ServiceDispatchOutcome::Complete(response)) => {
            complete_dispatch_response(request, response, permit)
        }
        (ResponseMode::Stream, ServiceDispatchOutcome::Stream(subscriber)) => {
            stream_dispatch_response(request, subscriber, permit)
        }
        (ResponseMode::Complete, ServiceDispatchOutcome::Stream(subscriber)) => {
            subscriber.cancellation().cancel();
            Err(internal_execution_failure(request.identity))
        }
        _ => Err(internal_execution_failure(request.identity)),
    }
}

fn complete_dispatch_response(
    mut request: DispatchedRequest,
    response: ariadnion_api_domain::ServiceResponse,
    _permit: OwnedSemaphorePermit,
) -> Result<Response, ExecutionFailure> {
    let projected = request
        .projection
        .project_complete(&request.identity, response)
        .map_err(|failure| ExecutionFailure::new(request.identity.clone(), failure))?;
    let response = project_buffered_response(&request.identity, projected, false)
        .map_err(|failure| ExecutionFailure::new(request.identity.clone(), failure))?;
    request.cancellation.disarm();
    Ok(response)
}

fn stream_dispatch_response(
    request: DispatchedRequest,
    subscriber: ariadnion_core::EventSubscriber<ariadnion_api_domain::ServiceStreamEvent>,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ExecutionFailure> {
    let subscriber_cancellation = SubscriberCancellation::new(subscriber.cancellation());
    let projected = request
        .projection
        .project_stream(&request.identity, subscriber, &request.context)
        .map_err(|failure| ExecutionFailure::new(request.identity.clone(), failure))?;
    let projected = finalize_stream_projection(&request.identity, projected)
        .map_err(|failure| ExecutionFailure::new(request.identity.clone(), failure))?;
    let channel_cancellation = subscriber_cancellation.into_retained_token();
    Ok(project_stream_response(
        request,
        projected,
        channel_cancellation,
        permit,
    ))
}

fn project_stream_response(
    request: DispatchedRequest,
    projected: FinalizedStreamProjection,
    channel_cancellation: CancellationToken,
    permit: OwnedSemaphorePermit,
) -> Response {
    let FinalizedStreamProjection {
        status,
        headers,
        stream,
    } = projected;
    let lifecycle =
        HttpBodyLifecycleStream::new(stream, request.cancellation, channel_cancellation, permit);
    let mut response = Body::from_stream(lifecycle).into_response();
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn project_failure(protocol: &dyn HttpProtocolAdapter, execution: ExecutionFailure) -> Response {
    let challenge = execution.bearer_challenge;
    match protocol.project_failure(&execution.identity, execution.failure) {
        Ok(projected) => match project_buffered_response(&execution.identity, projected, challenge)
        {
            Ok(response) => response,
            Err(_) => project_internal_fallback(&execution.identity),
        },
        Err(_) => project_internal_fallback(&execution.identity),
    }
}

fn project_buffered_response(
    identity: &HttpRequestIdentity,
    projected: ProtocolBufferedResponse,
    challenge: bool,
) -> Result<Response, ProtocolFailure> {
    let (status, headers, body) = projected.into_parts();
    let headers = finalize_response_headers(identity, headers, challenge)?;
    let mut response = Body::from(body).into_response();
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn project_internal_fallback(identity: &HttpRequestIdentity) -> Response {
    let mut response = Body::from("Internal Server Error").into_response();
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response_with_request_id(identity, response)
}

fn finalize_stream_projection(
    identity: &HttpRequestIdentity,
    projected: ProtocolStreamResponse,
) -> Result<FinalizedStreamProjection, ProtocolFailure> {
    let (status, headers, stream) = projected.into_parts();
    let headers = finalize_response_headers(identity, headers, false)?;
    Ok(FinalizedStreamProjection {
        status,
        headers,
        stream,
    })
}

fn finalize_response_headers(
    identity: &HttpRequestIdentity,
    mut headers: HeaderMap,
    challenge: bool,
) -> Result<HeaderMap, ProtocolFailure> {
    headers.remove(header::WWW_AUTHENTICATE);
    if challenge {
        headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    let request_id = HeaderValue::from_str(identity.request_id().as_str())
        .map_err(|_| internal_protocol_failure())?;
    headers.insert(REQUEST_ID_HEADER, request_id);
    validate_response_header_budget(&headers)?;
    Ok(headers)
}

async fn authenticate(
    state: &HttpApiState,
    authorization: &PresentedBearer,
    context: &RequestContext,
    deadline: SystemTime,
) -> Result<AuthenticatedPrincipalEvidence, ExecutionAuthenticationFailure> {
    let result = within_deadline(
        deadline,
        state.authentication.authenticate(authorization, context),
    )
    .await
    .map_err(ExecutionAuthenticationFailure::Domain)?;
    result.map_err(ExecutionAuthenticationFailure::Http)
}

async fn collect_body(
    context: &RequestContext,
    body: Body,
) -> Result<axum::body::Bytes, ExecutionBodyFailure> {
    let result = within_request_context(context, to_bytes(body, MAX_PUBLIC_BODY_BYTES))
        .await
        .map_err(ExecutionBodyFailure::Domain)?;
    result.map_err(|_| {
        ExecutionBodyFailure::Http(ApiHttpError::new(ApiHttpErrorCode::PayloadTooLarge))
    })
}

async fn within_deadline<T>(
    deadline: SystemTime,
    future: impl Future<Output = T>,
) -> Result<T, ApiDomainError> {
    let remaining = deadline
        .duration_since(SystemTime::now())
        .map_err(|_| ApiDomainError::new(ApiDomainErrorCode::DeadlineExceeded))?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| ApiDomainError::new(ApiDomainErrorCode::DeadlineExceeded))
}

async fn within_request_context<T>(
    context: &RequestContext,
    future: impl Future<Output = T>,
) -> Result<T, ApiDomainError> {
    let mut future = Box::pin(future);
    loop {
        check_active(context)?;
        let remaining = context.remaining().map_err(ApiDomainError::from)?;
        let wait = remaining
            .unwrap_or(CANCELLATION_POLL_INTERVAL)
            .min(CANCELLATION_POLL_INTERVAL);
        if let Ok(output) = tokio::time::timeout(wait, future.as_mut()).await {
            check_active(context)?;
            return Ok(output);
        }
    }
}

fn check_active(context: &RequestContext) -> Result<(), ApiDomainError> {
    context.check_active().map_err(ApiDomainError::from)
}

pub(super) fn resolve_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<HttpRequestIdentity, ExecutionFailure> {
    let value = one_header(headers, REQUEST_ID_HEADER, false)
        .map_err(|error| ExecutionFailure::http(generated.clone(), error))?;
    let Some(value) = value else {
        return Ok(generated);
    };
    let text = value
        .to_str()
        .map_err(|_| ExecutionFailure::http(generated.clone(), invalid_request()))?;
    let request_id = RequestId::parse(text)
        .map_err(|_| ExecutionFailure::http(generated.clone(), invalid_request()))?;
    Ok(generated.replace_request_id(request_id))
}

fn validate_header_budget(headers: &HeaderMap) -> Result<(), ApiHttpError> {
    if headers.len() > MAX_PUBLIC_HEADERS {
        return Err(invalid_request());
    }
    let mut total = 0_usize;
    for (name, value) in headers {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .ok_or_else(invalid_request)?;
        if total > MAX_PUBLIC_HEADER_BYTES {
            return Err(invalid_request());
        }
    }
    Ok(())
}

fn validate_media_type(headers: &HeaderMap) -> Result<(), ApiHttpError> {
    let value = one_header(headers, header::CONTENT_TYPE.as_str(), false)?
        .ok_or_else(|| ApiHttpError::new(ApiHttpErrorCode::UnsupportedMediaType))?;
    let valid = value
        .to_str()
        .ok()
        .and_then(|text| text.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if valid {
        Ok(())
    } else {
        Err(ApiHttpError::new(ApiHttpErrorCode::UnsupportedMediaType))
    }
}

fn validate_content_length(headers: &HeaderMap) -> Result<(), ApiHttpError> {
    let Some(value) = one_header(headers, header::CONTENT_LENGTH.as_str(), false)? else {
        return Ok(());
    };
    let length = value
        .to_str()
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(invalid_request)?;
    if length > MAX_PUBLIC_BODY_BYTES as u64 {
        return Err(ApiHttpError::new(ApiHttpErrorCode::PayloadTooLarge));
    }
    Ok(())
}

fn parse_deadline(headers: &HeaderMap, now: SystemTime) -> Result<SystemTime, ApiHttpError> {
    let Some(value) = one_header(headers, DEADLINE_HEADER, false)? else {
        return now
            .checked_add(DEFAULT_DEADLINE_WINDOW)
            .ok_or_else(|| ApiHttpError::new(ApiHttpErrorCode::Internal));
    };
    let milliseconds = value
        .to_str()
        .ok()
        .filter(|text| !text.is_empty() && text.len() <= 20)
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(invalid_request)?;
    let deadline = UNIX_EPOCH
        .checked_add(Duration::from_millis(milliseconds))
        .ok_or_else(invalid_request)?;
    validate_deadline_window(now, deadline)?;
    Ok(deadline)
}

fn validate_deadline_window(now: SystemTime, deadline: SystemTime) -> Result<(), ApiHttpError> {
    let future_window = deadline.duration_since(now).ok();
    if future_window.is_some_and(|remaining| remaining > MAX_DEADLINE_WINDOW) {
        return Err(ApiHttpError::new(ApiHttpErrorCode::InvalidRequest));
    }
    Ok(())
}

fn parse_authorization(headers: &HeaderMap) -> Result<PresentedBearer, ApiHttpError> {
    let value =
        one_header(headers, header::AUTHORIZATION.as_str(), false)?.ok_or_else(unauthenticated)?;
    PresentedBearer::parse(value.as_bytes())
}

pub(super) fn one_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    required: bool,
) -> Result<Option<&'a HeaderValue>, ApiHttpError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(invalid_request());
    }
    if required && first.is_none() {
        return Err(invalid_request());
    }
    Ok(first)
}

fn require_stream_capability(mode: ResponseMode, available: bool) -> Result<(), ApiHttpError> {
    if mode == ResponseMode::Stream && !available {
        return Err(ApiHttpError::new(ApiHttpErrorCode::StreamUnavailable));
    }
    Ok(())
}

fn anonymous_context(
    identity: &HttpRequestIdentity,
    deadline: SystemTime,
    cancellation: CancellationToken,
) -> RequestContext {
    RequestContext::new(
        identity.request_id.clone(),
        identity.trace_id.clone(),
        None,
        Some(deadline),
        cancellation,
    )
}

fn authenticated_context(
    identity: &HttpRequestIdentity,
    deadline: SystemTime,
    cancellation: CancellationToken,
    evidence: &AuthenticatedPrincipalEvidence,
) -> RequestContext {
    let principal = PrincipalContext::new(
        evidence.tenant_id().clone(),
        evidence.principal_id().clone(),
    );
    RequestContext::new(
        identity.request_id.clone(),
        identity.trace_id.clone(),
        Some(principal),
        Some(deadline),
        cancellation,
    )
}

struct RequestAdmission {
    identity: HttpRequestIdentity,
    deadline: SystemTime,
    cancellation: RequestCancellation,
    anonymous: RequestContext,
    request: ProtocolRequest,
    authorization: PresentedBearer,
}

struct AuthenticatedRequest {
    identity: HttpRequestIdentity,
    deadline: SystemTime,
    cancellation: RequestCancellation,
    request: ariadnion_api_domain::ServiceRequest,
    response_mode: ResponseMode,
    projection: Arc<dyn HttpProtocolProjection>,
    evidence: AuthenticatedPrincipalEvidence,
    context: RequestContext,
}

struct DispatchedRequest {
    identity: HttpRequestIdentity,
    cancellation: RequestCancellation,
    response_mode: ResponseMode,
    projection: Arc<dyn HttpProtocolProjection>,
    context: RequestContext,
}

struct FinalizedStreamProjection {
    status: StatusCode,
    headers: HeaderMap,
    stream: BoxHttpBodyStream,
}

pub(super) struct ExecutionFailure {
    identity: HttpRequestIdentity,
    failure: ProtocolFailure,
    bearer_challenge: bool,
}

impl ExecutionFailure {
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

enum ExecutionAuthenticationFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
}

impl ExecutionAuthenticationFailure {
    fn with_identity(self, identity: HttpRequestIdentity) -> ExecutionFailure {
        match self {
            Self::Http(error) => ExecutionFailure::authentication(identity, error),
            Self::Domain(error) => ExecutionFailure::domain(identity, error),
        }
    }
}

enum ExecutionBodyFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
}

impl ExecutionBodyFailure {
    fn with_identity(self, identity: HttpRequestIdentity) -> ExecutionFailure {
        match self {
            Self::Http(error) => ExecutionFailure::http(identity, error),
            Self::Domain(error) => ExecutionFailure::domain(identity, error),
        }
    }
}

struct RequestCancellation {
    cancellation: CancellationToken,
    armed: bool,
}

impl RequestCancellation {
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

impl Drop for RequestCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}

struct SubscriberCancellation {
    cancellation: CancellationToken,
    armed: bool,
}

impl SubscriberCancellation {
    fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    fn into_retained_token(mut self) -> CancellationToken {
        self.armed = false;
        self.cancellation.clone()
    }
}

impl Drop for SubscriberCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}

struct HttpBodyLifecycleStream {
    stream: BoxHttpBodyStream,
    cancellation: RequestCancellation,
    channel_cancellation: CancellationToken,
    permit: Option<OwnedSemaphorePermit>,
    finished: bool,
}

impl HttpBodyLifecycleStream {
    fn new(
        stream: BoxHttpBodyStream,
        cancellation: RequestCancellation,
        channel_cancellation: CancellationToken,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            stream,
            cancellation,
            channel_cancellation,
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
        self.channel_cancellation.cancel();
        self.permit.take();
    }
}

impl Stream for HttpBodyLifecycleStream {
    type Item = Result<axum::body::Bytes, ApiHttpError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = self.stream.as_mut().poll_next(context);
        if matches!(next, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.finish();
        }
        next
    }
}

impl Drop for HttpBodyLifecycleStream {
    fn drop(&mut self) {
        self.finish();
    }
}

fn internal_execution_failure(identity: HttpRequestIdentity) -> ExecutionFailure {
    ExecutionFailure::http(identity, ApiHttpError::new(ApiHttpErrorCode::Internal))
}

const fn internal_protocol_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

fn valid_bearer_token(field: &[u8], token: &[u8]) -> bool {
    field.len() <= MAX_PRESENTED_BEARER_BYTES
        && !token.is_empty()
        && token.iter().all(|byte| byte.is_ascii_graphic())
}

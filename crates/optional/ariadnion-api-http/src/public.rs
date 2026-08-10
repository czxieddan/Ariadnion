// crates/optional/ariadnion-api-http/src/public.rs - Public HTTP service ingress for Ariadnion.
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
//! Axum ingress for bounded, transport-neutral public service requests.

mod error;

use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_api_dispatch::{ServiceDispatchOutcome, ServiceDispatchPort};
use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, FinishReason, IdempotencyKey, ModelSelector,
    OutputTokenLimit, ResponseMode, ServiceContractVersion, ServiceRequest, ServiceResponse,
    ServiceStreamEvent, TextInput, TextServiceRequest,
};
use ariadnion_core::{
    CancellationToken, EventSubscriber, PrincipalContext, RequestContext, RequestId, TraceId,
};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use bytes::Bytes;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroize;

pub use error::{ApiHttpError, ApiHttpErrorCode};
use error::{
    AuthenticationFailure, BodyFailure, ResponseFailure, domain_failure, failure, invalid_request,
    response_with_request_id, unauthenticated,
};

/// Maximum encoded body admitted by the public HTTP ingress.
pub const MAX_PUBLIC_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum aggregate encoded header-name and header-value bytes.
pub const MAX_PUBLIC_HEADER_BYTES: usize = 32 * 1024;
/// Maximum number of encoded header values admitted per request.
pub const MAX_PUBLIC_HEADERS: usize = 64;
/// Maximum number of public requests admitted to parsing or service ports.
pub const MAX_PUBLIC_IN_FLIGHT_REQUESTS: usize = 64;
/// Maximum encoded authorization value retained during authentication.
pub const MAX_PRESENTED_BEARER_BYTES: usize = 8 * 1024;

const DEFAULT_DEADLINE_WINDOW: Duration = Duration::from_secs(30);
const MAX_DEADLINE_WINDOW: Duration = Duration::from_secs(120);
// Core cancellation is deliberately callback-free, so bounded body waits poll
// it at this interval while the absolute request deadline remains authoritative.
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);
const DEADLINE_HEADER: &str = "x-ariadnion-deadline-unix-ms";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Boxed asynchronous result used by public HTTP adapter ports.
pub type BoxHttpFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A non-buffering HTTP response body stream produced by a transport bridge.
///
/// Each item is one already encoded body fragment or a redacted transport
/// failure. Dropping the owning HTTP body cancels the request and releases its
/// shared admission permit. Implementations must not retain request secrets in
/// diagnostics and must remain compatible with Axum's streaming body contract.
pub type BoxHttpBodyStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, ApiHttpError>> + Send + 'static>>;

/// A server-issued request and trace identity pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequestIdentity {
    request_id: RequestId,
    trace_id: TraceId,
}

impl HttpRequestIdentity {
    /// Creates an identity pair from validated core identifiers.
    #[must_use]
    pub const fn new(request_id: RequestId, trace_id: TraceId) -> Self {
        Self {
            request_id,
            trace_id,
        }
    }

    /// Returns the request correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the distributed trace identifier.
    #[must_use]
    pub const fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    fn replace_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = request_id;
        self
    }
}

/// Issues server-controlled request and trace identifiers without blocking.
pub trait RequestIdentityPort: Send + Sync {
    /// Issues a fresh validated identity pair.
    fn issue(&self) -> HttpRequestIdentity;
}

/// Ephemeral Bearer credential material presented to an authentication port.
pub struct PresentedBearer {
    credential: Box<[u8]>,
}

impl PresentedBearer {
    /// Parses one bounded `Bearer` authorization field.
    ///
    /// # Errors
    ///
    /// Returns [`ApiHttpErrorCode::Unauthenticated`] without retaining rejected
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

/// Authenticates one public request against bounded Bearer material.
pub trait ServiceAuthenticationPort: Send + Sync {
    /// Produces authoritative principal evidence from an anonymous context.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted transport error when authentication is denied
    /// or its authoritative dependency is unavailable.
    fn authenticate<'a>(
        &'a self,
        authorization: &'a PresentedBearer,
        context: &'a RequestContext,
    ) -> BoxHttpFuture<'a, Result<AuthenticatedPrincipalEvidence, ApiHttpError>>;
}

/// Converts a service event subscriber into a non-buffering HTTP body stream.
///
/// The bridge receives the authenticated request context, including its
/// deadline and cancellation token. It must return only redacted transport
/// errors. The HTTP adapter owns the returned stream and cancels the request
/// and subscriber channel when the response body is dropped.
pub trait ServiceStreamBridgePort: Send + Sync {
    /// Builds the encoded HTTP body stream for one service subscriber.
    ///
    /// # Errors
    ///
    /// Returns a stable [`ApiHttpError`] when the subscriber cannot be bridged.
    fn bridge(
        &self,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Result<BoxHttpBodyStream, ApiHttpError>;
}

/// Shared ports and shutdown state for the public HTTP router.
#[derive(Clone)]
pub struct HttpApiState {
    identity: Arc<dyn RequestIdentityPort>,
    authentication: Arc<dyn ServiceAuthenticationPort>,
    dispatch: Arc<dyn ServiceDispatchPort>,
    stream_bridge: Option<Arc<dyn ServiceStreamBridgePort>>,
    shutdown: CancellationToken,
    admission: Arc<Semaphore>,
}

impl HttpApiState {
    /// Creates public ingress state from typed ports and a server shutdown token.
    ///
    /// The router derives a child cancellation token for each admitted request.
    /// At most [`MAX_PUBLIC_IN_FLIGHT_REQUESTS`] handlers enter parsing or ports
    /// across all clones of this state; excess requests fail without polling the
    /// body or invoking authentication and dispatch.
    #[must_use]
    pub fn new(
        identity: Arc<dyn RequestIdentityPort>,
        authentication: Arc<dyn ServiceAuthenticationPort>,
        dispatch: Arc<dyn ServiceDispatchPort>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            identity,
            authentication,
            dispatch,
            stream_bridge: None,
            shutdown,
            admission: Arc::new(Semaphore::new(MAX_PUBLIC_IN_FLIGHT_REQUESTS)),
        }
    }

    /// Installs the optional service-to-HTTP response stream bridge.
    ///
    /// Without this capability, stream-mode requests fail with a stable 503
    /// before service dispatch. Installing a bridge does not change complete
    /// response bytes or headers. Returned stream bodies retain request
    /// cancellation and shared admission until body drop.
    #[must_use]
    pub fn with_stream_bridge(mut self, bridge: Arc<dyn ServiceStreamBridgePort>) -> Self {
        self.stream_bridge = Some(bridge);
        self
    }
}

/// Builds the bounded version-one public HTTP router.
///
/// `POST /v1/text` accepts strict JSON with `Content-Type: application/json`
/// and one bounded `Authorization: Bearer` field. A validated `X-Request-Id`,
/// absolute UTC deadline, and idempotency key are propagated when present.
/// Header, body, credential, deadline-window, and aggregate in-flight limits are
/// enforced before the relevant allocation or service call. Complete responses
/// and all failures use stable redacted JSON. Streaming requires an explicitly
/// installed bridge and uses non-buffering server-sent-event response bodies.
///
/// Handler drop and timeout cancel the request child token. Authentication and
/// dispatch ports receive the same deadline and cancellation context and must
/// observe it before every externally visible side effect.
pub fn public_router(state: HttpApiState) -> Router {
    Router::new()
        .route("/v1/text", post(handle_text))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
}

async fn handle_text(State(state): State<HttpApiState>, request: Request<Body>) -> Response {
    let generated = state.identity.issue();
    let permit = match state.admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return failure(
                generated,
                ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted),
            )
            .into_response();
        }
    };
    match execute_text(&state, generated.clone(), request, permit).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn execute_text(
    state: &HttpApiState,
    generated: HttpRequestIdentity,
    request: Request<Body>,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ResponseFailure> {
    let admission = admit_request(state, generated, request).await?;
    let authenticated = authenticate_request(state, admission).await?;
    dispatch_request(state, authenticated, permit).await
}

async fn admit_request(
    state: &HttpApiState,
    generated: HttpRequestIdentity,
    request: Request<Body>,
) -> Result<RequestAdmission, ResponseFailure> {
    let (parts, body) = request.into_parts();
    let (identity, deadline) = admit_headers(generated, &parts.headers)?;
    let cancellation = RequestCancellation::new(&state.shutdown);
    let anonymous = anonymous_context(&identity, deadline, cancellation.token());
    anonymous
        .check_active()
        .map_err(ApiDomainError::from)
        .map_err(|error| domain_failure(identity.clone(), error))?;
    let authorization =
        parse_authorization(&parts.headers).map_err(|error| failure(identity.clone(), error))?;
    let body_result = within_request_context(&anonymous, parse_body(body, &parts.headers))
        .await
        .map_err(|error| domain_failure(identity.clone(), error))?;
    let domain = body_result.map_err(|error| error.with_identity(identity.clone()))?;
    Ok(RequestAdmission {
        identity,
        deadline,
        cancellation,
        anonymous,
        domain,
        authorization,
    })
}

fn admit_headers(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<(HttpRequestIdentity, SystemTime), ResponseFailure> {
    validate_header_budget(headers).map_err(|error| failure(generated.clone(), error))?;
    let identity = resolve_identity(generated, headers)?;
    validate_media_type(headers).map_err(|error| failure(identity.clone(), error))?;
    validate_content_length(headers).map_err(|error| failure(identity.clone(), error))?;
    let deadline = parse_deadline(headers, SystemTime::now())
        .map_err(|error| failure(identity.clone(), error))?;
    Ok((identity, deadline))
}

async fn authenticate_request(
    state: &HttpApiState,
    admission: RequestAdmission,
) -> Result<AuthenticatedRequest, ResponseFailure> {
    let evidence = authenticate(
        state,
        &admission.authorization,
        &admission.anonymous,
        admission.deadline,
    )
    .await
    .map_err(|error| error.with_identity(admission.identity.clone()))?;
    require_stream_bridge(
        admission.domain.response_mode,
        state.stream_bridge.is_some(),
    )
    .map_err(|error| failure(admission.identity.clone(), error))?;
    let context = authenticated_context(
        &admission.identity,
        admission.deadline,
        admission.cancellation.token(),
        &evidence,
    );
    Ok(AuthenticatedRequest {
        identity: admission.identity,
        deadline: admission.deadline,
        cancellation: admission.cancellation,
        request: admission.domain.request,
        response_mode: admission.domain.response_mode,
        evidence,
        context,
    })
}

async fn dispatch_request(
    state: &HttpApiState,
    request: AuthenticatedRequest,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ResponseFailure> {
    let AuthenticatedRequest {
        identity,
        deadline,
        cancellation,
        request,
        response_mode,
        evidence,
        context,
    } = request;
    let result = within_deadline(
        deadline,
        state.dispatch.dispatch(request, &evidence, &context),
    )
    .await;
    let outcome = result
        .map_err(|error| domain_failure(identity.clone(), error))?
        .map_err(|error| domain_failure(identity.clone(), error))?;
    let dispatched = DispatchedRequest {
        identity,
        cancellation,
        response_mode,
        context,
    };
    project_dispatch_outcome(dispatched, outcome, state.stream_bridge.as_ref(), permit)
}

fn project_dispatch_outcome(
    request: DispatchedRequest,
    outcome: ServiceDispatchOutcome,
    bridge: Option<&Arc<dyn ServiceStreamBridgePort>>,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ResponseFailure> {
    match (request.response_mode, outcome) {
        (ResponseMode::Complete, ServiceDispatchOutcome::Complete(response)) => {
            complete_dispatch_response(request, response, permit)
        }
        (ResponseMode::Stream, ServiceDispatchOutcome::Stream(subscriber)) => {
            stream_dispatch_response(request, subscriber, bridge, permit)
        }
        (ResponseMode::Complete, ServiceDispatchOutcome::Stream(subscriber)) => {
            subscriber.cancellation().cancel();
            Err(failure(
                request.identity,
                ApiHttpError::new(ApiHttpErrorCode::Internal),
            ))
        }
        _ => Err(failure(
            request.identity,
            ApiHttpError::new(ApiHttpErrorCode::Internal),
        )),
    }
}

fn complete_dispatch_response(
    mut request: DispatchedRequest,
    response: ServiceResponse,
    _permit: OwnedSemaphorePermit,
) -> Result<Response, ResponseFailure> {
    let projected = project_service_response(&request.identity, response)
        .map_err(|error| failure(request.identity.clone(), error))?;
    request.cancellation.disarm();
    Ok(projected)
}

fn stream_dispatch_response(
    request: DispatchedRequest,
    subscriber: EventSubscriber<ServiceStreamEvent>,
    bridge: Option<&Arc<dyn ServiceStreamBridgePort>>,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ResponseFailure> {
    let subscriber_cancellation = SubscriberCancellation::new(subscriber.cancellation());
    let bridge = bridge.ok_or_else(|| {
        failure(
            request.identity.clone(),
            ApiHttpError::new(ApiHttpErrorCode::StreamUnavailable),
        )
    })?;
    let stream = bridge
        .bridge(subscriber, &request.context)
        .map_err(|error| failure(request.identity.clone(), error))?;
    let channel_cancellation = subscriber_cancellation.into_retained_token();
    let lifecycle =
        HttpBodyLifecycleStream::new(stream, request.cancellation, channel_cancellation, permit);
    Ok(stream_response(&request.identity, lifecycle))
}

fn stream_response(identity: &HttpRequestIdentity, stream: HttpBodyLifecycleStream) -> Response {
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response_with_request_id(identity, response)
}

async fn authenticate(
    state: &HttpApiState,
    authorization: &PresentedBearer,
    context: &RequestContext,
    deadline: SystemTime,
) -> Result<AuthenticatedPrincipalEvidence, AuthenticationFailure> {
    let result = within_deadline(
        deadline,
        state.authentication.authenticate(authorization, context),
    )
    .await
    .map_err(AuthenticationFailure::Domain)?;
    result.map_err(AuthenticationFailure::Http)
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
        context.check_active().map_err(ApiDomainError::from)?;
        let remaining = context.remaining().map_err(ApiDomainError::from)?;
        let wait = remaining
            .unwrap_or(CANCELLATION_POLL_INTERVAL)
            .min(CANCELLATION_POLL_INTERVAL);
        if let Ok(output) = tokio::time::timeout(wait, future.as_mut()).await {
            context.check_active().map_err(ApiDomainError::from)?;
            return Ok(output);
        }
    }
}

fn resolve_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<HttpRequestIdentity, ResponseFailure> {
    let value = one_header(headers, REQUEST_ID_HEADER, false)
        .map_err(|error| failure(generated.clone(), error))?;
    let Some(value) = value else {
        return Ok(generated);
    };
    let text = value
        .to_str()
        .map_err(|_| failure(generated.clone(), invalid_request()))?;
    let request_id =
        RequestId::parse(text).map_err(|_| failure(generated.clone(), invalid_request()))?;
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

fn one_header<'a>(
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

async fn parse_body(body: Body, headers: &HeaderMap) -> Result<ParsedRequest, BodyFailure> {
    let bytes = to_bytes(body, MAX_PUBLIC_BODY_BYTES)
        .await
        .map_err(|_| BodyFailure::Http(ApiHttpError::new(ApiHttpErrorCode::PayloadTooLarge)))?;
    let dto: TextRequestDto = serde_json::from_slice(&bytes)
        .map_err(|_| BodyFailure::Http(ApiHttpError::new(ApiHttpErrorCode::InvalidRequest)))?;
    let idempotency = parse_idempotency(headers)?;
    dto.into_domain(idempotency).map_err(BodyFailure::Domain)
}

fn parse_idempotency(headers: &HeaderMap) -> Result<Option<IdempotencyKey>, BodyFailure> {
    let value = one_header(headers, IDEMPOTENCY_HEADER, false).map_err(BodyFailure::Http)?;
    value
        .map(|header| {
            header
                .to_str()
                .map_err(|_| ApiDomainError::new(ApiDomainErrorCode::InvalidArgument))
                .and_then(IdempotencyKey::new)
                .map_err(BodyFailure::Domain)
        })
        .transpose()
}

fn require_stream_bridge(mode: ResponseMode, available: bool) -> Result<(), ApiHttpError> {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextRequestDto {
    version: u16,
    model: String,
    input: String,
    max_output_tokens: u32,
    response_mode: ResponseModeDto,
}

impl TextRequestDto {
    fn into_domain(
        self,
        idempotency: Option<IdempotencyKey>,
    ) -> Result<ParsedRequest, ApiDomainError> {
        let mode = self.response_mode.into_domain();
        let request = TextServiceRequest::new(
            ServiceContractVersion::parse(self.version)?,
            ModelSelector::new(&self.model)?,
            TextInput::new(&self.input)?,
            OutputTokenLimit::new(self.max_output_tokens)?,
            mode,
            idempotency,
        );
        Ok(ParsedRequest {
            request: ServiceRequest::Text(request),
            response_mode: mode,
        })
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseModeDto {
    Complete,
    Stream,
}

impl ResponseModeDto {
    const fn into_domain(self) -> ResponseMode {
        match self {
            Self::Complete => ResponseMode::Complete,
            Self::Stream => ResponseMode::Stream,
        }
    }
}

struct ParsedRequest {
    request: ServiceRequest,
    response_mode: ResponseMode,
}

struct RequestAdmission {
    identity: HttpRequestIdentity,
    deadline: SystemTime,
    cancellation: RequestCancellation,
    anonymous: RequestContext,
    domain: ParsedRequest,
    authorization: PresentedBearer,
}

struct AuthenticatedRequest {
    identity: HttpRequestIdentity,
    deadline: SystemTime,
    cancellation: RequestCancellation,
    request: ServiceRequest,
    response_mode: ResponseMode,
    evidence: AuthenticatedPrincipalEvidence,
    context: RequestContext,
}

struct DispatchedRequest {
    identity: HttpRequestIdentity,
    cancellation: RequestCancellation,
    response_mode: ResponseMode,
    context: RequestContext,
}

#[derive(Serialize)]
struct TextResponseDto<'a> {
    version: u16,
    output: &'a str,
    finish_reason: &'static str,
}

fn project_service_response(
    identity: &HttpRequestIdentity,
    response: ServiceResponse,
) -> Result<Response, ApiHttpError> {
    match response {
        ServiceResponse::Text(response) => {
            let version = project_version(response.version())?;
            let finish_reason = project_finish_reason(response.finish_reason())?;
            let projected = Json(TextResponseDto {
                version,
                output: response.output().as_str(),
                finish_reason,
            })
            .into_response();
            Ok(response_with_request_id(identity, projected))
        }
        _ => Err(ApiHttpError::new(ApiHttpErrorCode::Internal)),
    }
}

const fn project_version(version: ServiceContractVersion) -> Result<u16, ApiHttpError> {
    match version {
        ServiceContractVersion::V1 => Ok(1),
        _ => Err(ApiHttpError::new(ApiHttpErrorCode::Internal)),
    }
}

const fn project_finish_reason(reason: FinishReason) -> Result<&'static str, ApiHttpError> {
    match reason {
        FinishReason::Completed => Ok("completed"),
        FinishReason::OutputLimitReached => Ok("output_limit_reached"),
        _ => Err(ApiHttpError::new(ApiHttpErrorCode::Internal)),
    }
}

async fn not_found(State(state): State<HttpApiState>, request: Request<Body>) -> Response {
    static_route_error(&state, request.headers(), ApiHttpErrorCode::NotFound)
}

async fn method_not_allowed(State(state): State<HttpApiState>, request: Request<Body>) -> Response {
    static_route_error(
        &state,
        request.headers(),
        ApiHttpErrorCode::MethodNotAllowed,
    )
}

fn static_route_error(
    state: &HttpApiState,
    headers: &HeaderMap,
    code: ApiHttpErrorCode,
) -> Response {
    let generated = state.identity.issue();
    let identity = resolve_identity(generated.clone(), headers).unwrap_or(generated);
    failure(identity, ApiHttpError::new(code)).into_response()
}

struct RequestCancellation {
    cancellation: CancellationToken,
    armed: bool,
}

struct SubscriberCancellation {
    cancellation: CancellationToken,
    armed: bool,
}

struct HttpBodyLifecycleStream {
    stream: BoxHttpBodyStream,
    _cancellation: RequestCancellation,
    channel_cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
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
            _cancellation: cancellation,
            channel_cancellation,
            _permit: permit,
        }
    }
}

impl Stream for HttpBodyLifecycleStream {
    type Item = Result<Bytes, ApiHttpError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.as_mut().poll_next(context)
    }
}

impl Drop for HttpBodyLifecycleStream {
    fn drop(&mut self) {
        self.channel_cancellation.cancel();
    }
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

fn valid_bearer_token(field: &[u8], token: &[u8]) -> bool {
    field.len() <= MAX_PRESENTED_BEARER_BYTES
        && !token.is_empty()
        && token.iter().all(|byte| byte.is_ascii_graphic())
}

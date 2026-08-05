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

use std::fmt::{self, Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, FinishReason, IdempotencyKey, ModelSelector,
    OutputTokenLimit, ResponseMode, ServiceContractVersion, ServiceRequest, ServiceResponse,
    TextInput, TextServiceRequest,
};
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext, RequestId, TraceId};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use zeroize::Zeroize;

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

/// Stable transport failures produced before or around service dispatch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ApiHttpErrorCode {
    /// Request syntax, headers, or framing are invalid.
    InvalidRequest,
    /// Authentication evidence is absent or invalid.
    Unauthenticated,
    /// The authenticated principal lacks permission.
    Forbidden,
    /// The request context was cancelled.
    Cancelled,
    /// The absolute request deadline elapsed.
    DeadlineExceeded,
    /// No public route matches the request target.
    NotFound,
    /// The route does not support the request method.
    MethodNotAllowed,
    /// The encoded request body exceeds its hard limit.
    PayloadTooLarge,
    /// Every public ingress execution permit is in use.
    ResourceExhausted,
    /// An authoritative authentication dependency is unavailable.
    Unavailable,
    /// The request media type is not supported.
    UnsupportedMediaType,
    /// The optional response-stream bridge is unavailable.
    StreamUnavailable,
    /// The transport failed without a safe external explanation.
    Internal,
}

impl ApiHttpErrorCode {
    /// Returns the stable transport machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "API_HTTP_INVALID_REQUEST",
            Self::Unauthenticated => "API_HTTP_UNAUTHENTICATED",
            Self::Forbidden => "API_HTTP_FORBIDDEN",
            Self::NotFound => "API_HTTP_NOT_FOUND",
            Self::MethodNotAllowed => "API_HTTP_METHOD_NOT_ALLOWED",
            Self::PayloadTooLarge
            | Self::Cancelled
            | Self::DeadlineExceeded
            | Self::ResourceExhausted
            | Self::Unavailable
            | Self::UnsupportedMediaType
            | Self::StreamUnavailable
            | Self::Internal => extended_http_code(self),
        }
    }
}

const fn extended_http_code(code: ApiHttpErrorCode) -> &'static str {
    match code {
        ApiHttpErrorCode::PayloadTooLarge => "API_HTTP_PAYLOAD_TOO_LARGE",
        ApiHttpErrorCode::UnsupportedMediaType => "API_HTTP_UNSUPPORTED_MEDIA_TYPE",
        ApiHttpErrorCode::StreamUnavailable => "API_HTTP_STREAM_UNAVAILABLE",
        ApiHttpErrorCode::Cancelled
        | ApiHttpErrorCode::DeadlineExceeded
        | ApiHttpErrorCode::ResourceExhausted
        | ApiHttpErrorCode::Unavailable
        | ApiHttpErrorCode::Internal => service_http_code(code),
        _ => "API_HTTP_INTERNAL",
    }
}

const fn service_http_code(code: ApiHttpErrorCode) -> &'static str {
    match code {
        ApiHttpErrorCode::Cancelled => "API_HTTP_CANCELLED",
        ApiHttpErrorCode::DeadlineExceeded => "API_HTTP_DEADLINE_EXCEEDED",
        ApiHttpErrorCode::ResourceExhausted => "API_HTTP_RESOURCE_EXHAUSTED",
        ApiHttpErrorCode::Unavailable => "API_HTTP_UNAVAILABLE",
        ApiHttpErrorCode::Internal => "API_HTTP_INTERNAL",
        _ => "API_HTTP_INTERNAL",
    }
}

/// A redacted HTTP adapter error that retains no request material.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApiHttpError {
    code: ApiHttpErrorCode,
}

impl ApiHttpError {
    /// Creates a redacted error from its stable code.
    #[must_use]
    pub const fn new(code: ApiHttpErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable transport error code.
    #[must_use]
    pub const fn code(self) -> ApiHttpErrorCode {
        self.code
    }
}

impl Debug for ApiHttpError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApiHttpError({})", self.code.as_str())
    }
}

impl Display for ApiHttpError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ApiHttpError {}

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

/// Dispatches a validated complete public-service request.
pub trait ServiceDispatchPort: Send + Sync {
    /// Executes one request with independent authentication evidence and context.
    ///
    /// The implementation owns idempotent replay, canonical request digests,
    /// and durable outcome semantics. It must observe context cancellation and
    /// the UTC deadline before every externally visible side effect.
    fn dispatch<'a>(
        &'a self,
        request: ServiceRequest,
        evidence: &'a AuthenticatedPrincipalEvidence,
        context: &'a RequestContext,
    ) -> BoxHttpFuture<'a, Result<ServiceResponse, ApiDomainError>>;
}

/// Shared ports and shutdown state for the public HTTP router.
#[derive(Clone)]
pub struct HttpApiState {
    identity: Arc<dyn RequestIdentityPort>,
    authentication: Arc<dyn ServiceAuthenticationPort>,
    dispatch: Arc<dyn ServiceDispatchPort>,
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
            shutdown,
            admission: Arc::new(Semaphore::new(MAX_PUBLIC_IN_FLIGHT_REQUESTS)),
        }
    }
}

/// Builds the bounded version-one public HTTP router.
///
/// `POST /v1/text` accepts strict JSON with `Content-Type: application/json`
/// and one bounded `Authorization: Bearer` field. A validated `X-Request-Id`,
/// absolute UTC deadline, and idempotency key are propagated when present.
/// Header, body, credential, deadline-window, and aggregate in-flight limits are
/// enforced before the relevant allocation or service call. Complete responses
/// and all failures use stable redacted JSON; streaming fails with a stable 503
/// until the independent stream bridge is installed in P4.3.
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
    let _permit = match state.admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return failure(
                generated,
                ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted),
            )
            .into_response();
        }
    };
    match execute_text(&state, generated.clone(), request).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn execute_text(
    state: &HttpApiState,
    generated: HttpRequestIdentity,
    request: Request<Body>,
) -> Result<Response, ResponseFailure> {
    let admission = admit_request(state, generated, request).await?;
    let authenticated = authenticate_request(state, admission).await?;
    dispatch_request(state, authenticated).await
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
    reject_stream(admission.domain.response_mode)
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
        evidence,
        context,
    })
}

async fn dispatch_request(
    state: &HttpApiState,
    mut request: AuthenticatedRequest,
) -> Result<Response, ResponseFailure> {
    let result = within_deadline(
        request.deadline,
        state
            .dispatch
            .dispatch(request.request, &request.evidence, &request.context),
    )
    .await;
    if result.is_ok() {
        request.cancellation.disarm();
    }
    let response = result
        .map_err(|error| domain_failure(request.identity.clone(), error))?
        .map_err(|error| domain_failure(request.identity.clone(), error))?;
    project_service_response(&request.identity, response)
        .map_err(|error| failure(request.identity, error))
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

fn reject_stream(mode: ResponseMode) -> Result<(), ApiHttpError> {
    if mode == ResponseMode::Stream {
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
    evidence: AuthenticatedPrincipalEvidence,
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
            let mut projected = Json(TextResponseDto {
                version,
                output: response.output().as_str(),
                finish_reason,
            })
            .into_response();
            attach_request_id(&mut projected, identity.request_id());
            Ok(projected)
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

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    request_id: String,
    details: EmptyDetails,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
}

#[derive(Serialize)]
struct EmptyDetails {}

struct ErrorProjection {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

fn project_http_error(error: ApiHttpError) -> ErrorProjection {
    let code = error.code();
    ErrorProjection {
        status: http_status(code),
        code: code.as_str(),
        message: http_message(code),
        retryable: matches!(
            code,
            ApiHttpErrorCode::DeadlineExceeded
                | ApiHttpErrorCode::ResourceExhausted
                | ApiHttpErrorCode::StreamUnavailable
                | ApiHttpErrorCode::Unavailable
        ),
    }
}

fn project_domain_error(error: ApiDomainError) -> ErrorProjection {
    let code = error.code();
    ErrorProjection {
        status: domain_status(code),
        code: code.as_str(),
        message: domain_message(code),
        retryable: domain_retryable(code),
    }
}

const fn http_status(code: ApiHttpErrorCode) -> StatusCode {
    match code {
        ApiHttpErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
        ApiHttpErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        ApiHttpErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ApiHttpErrorCode::NotFound => StatusCode::NOT_FOUND,
        ApiHttpErrorCode::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        ApiHttpErrorCode::PayloadTooLarge
        | ApiHttpErrorCode::Cancelled
        | ApiHttpErrorCode::DeadlineExceeded
        | ApiHttpErrorCode::ResourceExhausted
        | ApiHttpErrorCode::Unavailable
        | ApiHttpErrorCode::UnsupportedMediaType
        | ApiHttpErrorCode::StreamUnavailable
        | ApiHttpErrorCode::Internal => extended_http_status(code),
    }
}

const fn extended_http_status(code: ApiHttpErrorCode) -> StatusCode {
    match code {
        ApiHttpErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ApiHttpErrorCode::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ApiHttpErrorCode::StreamUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        ApiHttpErrorCode::Cancelled
        | ApiHttpErrorCode::DeadlineExceeded
        | ApiHttpErrorCode::ResourceExhausted
        | ApiHttpErrorCode::Unavailable
        | ApiHttpErrorCode::Internal => service_http_status(code),
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

const fn service_http_status(code: ApiHttpErrorCode) -> StatusCode {
    match code {
        ApiHttpErrorCode::Cancelled => status_499(),
        ApiHttpErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        ApiHttpErrorCode::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        ApiHttpErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ApiHttpErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

const fn domain_status(code: ApiDomainErrorCode) -> StatusCode {
    match code {
        ApiDomainErrorCode::InvalidArgument
        | ApiDomainErrorCode::UnsupportedVersion
        | ApiDomainErrorCode::LimitExceeded => StatusCode::UNPROCESSABLE_ENTITY,
        ApiDomainErrorCode::Conflict => StatusCode::CONFLICT,
        ApiDomainErrorCode::Cancelled => status_499(),
        ApiDomainErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        ApiDomainErrorCode::Unavailable
        | ApiDomainErrorCode::ResourceExhausted
        | ApiDomainErrorCode::Internal => service_domain_status(code),
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

const fn service_domain_status(code: ApiDomainErrorCode) -> StatusCode {
    match code {
        ApiDomainErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ApiDomainErrorCode::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        ApiDomainErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

const fn status_499() -> StatusCode {
    match StatusCode::from_u16(499) {
        Ok(status) => status,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

const fn http_message(code: ApiHttpErrorCode) -> &'static str {
    match code {
        ApiHttpErrorCode::InvalidRequest => "The request is invalid.",
        ApiHttpErrorCode::Unauthenticated => "Authentication is required.",
        ApiHttpErrorCode::Forbidden => "The request is not permitted.",
        ApiHttpErrorCode::NotFound => "The requested endpoint was not found.",
        ApiHttpErrorCode::MethodNotAllowed => "The request method is not supported.",
        ApiHttpErrorCode::PayloadTooLarge
        | ApiHttpErrorCode::Cancelled
        | ApiHttpErrorCode::DeadlineExceeded
        | ApiHttpErrorCode::ResourceExhausted
        | ApiHttpErrorCode::Unavailable
        | ApiHttpErrorCode::UnsupportedMediaType
        | ApiHttpErrorCode::StreamUnavailable
        | ApiHttpErrorCode::Internal => extended_http_message(code),
    }
}

const fn extended_http_message(code: ApiHttpErrorCode) -> &'static str {
    match code {
        ApiHttpErrorCode::PayloadTooLarge => "The request body is too large.",
        ApiHttpErrorCode::UnsupportedMediaType => "The request media type is not supported.",
        ApiHttpErrorCode::StreamUnavailable => "Response streaming is unavailable.",
        ApiHttpErrorCode::Cancelled
        | ApiHttpErrorCode::DeadlineExceeded
        | ApiHttpErrorCode::ResourceExhausted
        | ApiHttpErrorCode::Unavailable
        | ApiHttpErrorCode::Internal => service_http_message(code),
        _ => "The request could not be completed.",
    }
}

const fn service_http_message(code: ApiHttpErrorCode) -> &'static str {
    match code {
        ApiHttpErrorCode::Cancelled => "The request was cancelled.",
        ApiHttpErrorCode::DeadlineExceeded => "The request deadline was exceeded.",
        ApiHttpErrorCode::ResourceExhausted => "Public request capacity is exhausted.",
        ApiHttpErrorCode::Unavailable => "An authentication dependency is unavailable.",
        ApiHttpErrorCode::Internal => "The request could not be completed.",
        _ => "The request could not be completed.",
    }
}

const fn domain_message(code: ApiDomainErrorCode) -> &'static str {
    match code {
        ApiDomainErrorCode::InvalidArgument
        | ApiDomainErrorCode::UnsupportedVersion
        | ApiDomainErrorCode::LimitExceeded
        | ApiDomainErrorCode::Conflict => request_domain_message(code),
        ApiDomainErrorCode::Cancelled => "The request was cancelled.",
        ApiDomainErrorCode::DeadlineExceeded => "The request deadline was exceeded.",
        ApiDomainErrorCode::Unavailable
        | ApiDomainErrorCode::ResourceExhausted
        | ApiDomainErrorCode::Internal => service_domain_message(code),
        _ => "The request could not be completed.",
    }
}

const fn request_domain_message(code: ApiDomainErrorCode) -> &'static str {
    match code {
        ApiDomainErrorCode::InvalidArgument => "A request value is invalid.",
        ApiDomainErrorCode::UnsupportedVersion => "The request version is not supported.",
        ApiDomainErrorCode::LimitExceeded => "A request limit was exceeded.",
        ApiDomainErrorCode::Conflict => "The request conflicts with current state.",
        _ => "The request could not be completed.",
    }
}

const fn service_domain_message(code: ApiDomainErrorCode) -> &'static str {
    match code {
        ApiDomainErrorCode::Unavailable => "A required service is unavailable.",
        ApiDomainErrorCode::ResourceExhausted => "A request resource was exhausted.",
        ApiDomainErrorCode::Internal => "The request could not be completed.",
        _ => "The request could not be completed.",
    }
}

const fn domain_retryable(code: ApiDomainErrorCode) -> bool {
    matches!(
        code,
        ApiDomainErrorCode::DeadlineExceeded
            | ApiDomainErrorCode::Unavailable
            | ApiDomainErrorCode::ResourceExhausted
    )
}

fn response_from_projection(
    identity: &HttpRequestIdentity,
    projection: ErrorProjection,
) -> Response {
    let challenge = projection.status == StatusCode::UNAUTHORIZED;
    let mut response = (
        projection.status,
        Json(ErrorBody {
            code: projection.code,
            message: projection.message,
            request_id: identity.request_id.as_str().to_owned(),
            details: EmptyDetails {},
            retryable: projection.retryable,
            retry_after_ms: None,
        }),
    )
        .into_response();
    attach_request_id(&mut response, identity.request_id());
    if challenge {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

fn attach_request_id(response: &mut Response, request_id: &RequestId) {
    if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
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
    response_from_projection(&identity, project_http_error(ApiHttpError::new(code)))
}

struct ResponseFailure {
    identity: HttpRequestIdentity,
    projection: ErrorProjection,
}

impl ResponseFailure {
    fn into_response(self) -> Response {
        response_from_projection(&self.identity, self.projection)
    }
}

enum AuthenticationFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
}

enum BodyFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
}

impl BodyFailure {
    fn with_identity(self, identity: HttpRequestIdentity) -> ResponseFailure {
        match self {
            Self::Http(error) => failure(identity, error),
            Self::Domain(error) => domain_failure(identity, error),
        }
    }
}

impl AuthenticationFailure {
    fn with_identity(self, identity: HttpRequestIdentity) -> ResponseFailure {
        match self {
            Self::Http(error) => failure(identity, error),
            Self::Domain(error) => domain_failure(identity, error),
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

fn failure(identity: HttpRequestIdentity, error: ApiHttpError) -> ResponseFailure {
    ResponseFailure {
        identity,
        projection: project_http_error(error),
    }
}

fn domain_failure(identity: HttpRequestIdentity, error: ApiDomainError) -> ResponseFailure {
    ResponseFailure {
        identity,
        projection: project_domain_error(error),
    }
}

const fn invalid_request() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::InvalidRequest)
}

const fn unauthenticated() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::Unauthenticated)
}

fn valid_bearer_token(field: &[u8], token: &[u8]) -> bool {
    field.len() <= MAX_PRESENTED_BEARER_BYTES
        && !token.is_empty()
        && token.iter().all(|byte| byte.is_ascii_graphic())
}

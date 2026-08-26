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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Axum ingress and native service projection over shared protocol execution.

mod audio;
mod authentication;
mod base64_encoding;
mod embedding;
mod error;
mod execution;
mod file_content;
mod file_delete;
mod file_list;
mod files;
mod identity;
mod image;
mod json;
mod protocol;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, FinishReason, IdempotencyKey, ModelSelector,
    OutputTokenLimit, ResponseMode, ServiceContractVersion, ServiceRequest, ServiceResponse,
    ServiceStreamEvent, TextInput, TextServiceRequest,
};
use ariadnion_api_files::FileServicePort;
use ariadnion_core::{CancellationToken, EventSubscriber, RequestContext, RequestId, TraceId};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use bytes::Bytes;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

pub use authentication::UnavailableServiceAuthentication;
pub use error::{ApiHttpError, ApiHttpErrorCode};
use error::{
    AuthenticationFailure as NativeAuthenticationFailure, BodyFailure as NativeBodyFailure,
    ResponseFailure, domain_failure, failure as http_failure,
};
pub use execution::PresentedBearer;
pub use identity::MonotonicRequestIdentityIssuer;
pub use protocol::{
    HttpProtocolAdapter, HttpProtocolProjection, ProtocolBufferedResponse, ProtocolExecutionState,
    ProtocolFailure, ProtocolRequest, ProtocolRequestBody, ProtocolStreamResponse,
    protocol_post_route,
};

/// Maximum encoded request body admitted or protocol response body buffered.
pub const MAX_PUBLIC_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum aggregate public request or protocol response header bytes.
pub const MAX_PUBLIC_HEADER_BYTES: usize = 32 * 1024;
/// Maximum number of encoded header values in a request or protocol response.
pub const MAX_PUBLIC_HEADERS: usize = 64;
/// Maximum number of public requests admitted to parsing or service ports.
pub const MAX_PUBLIC_IN_FLIGHT_REQUESTS: usize = 64;
/// Maximum encoded authorization value retained during authentication.
pub const MAX_PRESENTED_BEARER_BYTES: usize = 8 * 1024;

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
    ///
    /// # Errors
    ///
    /// Returns a stable resource error when the bounded issuer is exhausted or
    /// cannot construct a validated pair. The HTTP adapter does not admit,
    /// parse, authenticate, or dispatch a request after this failure.
    fn issue(&self) -> Result<HttpRequestIdentity, ApiHttpError>;

    /// Returns a stable non-secret identity used only to project an issuance
    /// failure. Implementations must keep this value independent of request
    /// headers and credentials.
    #[must_use]
    fn fallback_identity(&self) -> HttpRequestIdentity;
}

/// Authenticates one public request against bounded Bearer material.
pub trait ServiceAuthenticationPort: Send + Sync {
    /// Produces authoritative principal evidence from an anonymous context.
    ///
    /// Implementations must observe the supplied context's cancellation token
    /// and absolute deadline before and during authentication, and must stop
    /// without publishing evidence after either boundary is reached.
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
    /// Returns a stable ApiHttpError when the subscriber cannot be bridged.
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
    dispatch: Arc<dyn ariadnion_api_dispatch::ServiceDispatchPort>,
    stream_bridge: Option<Arc<dyn ServiceStreamBridgePort>>,
    file_service: Option<Arc<dyn FileServicePort>>,
    shutdown: CancellationToken,
    admission: Arc<Semaphore>,
}

impl HttpApiState {
    /// Creates public ingress state from typed ports and a server shutdown token.
    ///
    /// The router derives a child cancellation token for each admitted request.
    /// At most MAX_PUBLIC_IN_FLIGHT_REQUESTS handlers enter parsing or service
    /// ports across all native and externally mounted protocol routes. Excess
    /// requests fail without polling the body or invoking authentication.
    #[must_use]
    pub fn new(
        identity: Arc<dyn RequestIdentityPort>,
        authentication: Arc<dyn ServiceAuthenticationPort>,
        dispatch: Arc<dyn ariadnion_api_dispatch::ServiceDispatchPort>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            identity,
            authentication,
            dispatch,
            stream_bridge: None,
            file_service: None,
            shutdown,
            admission: Arc::new(Semaphore::new(MAX_PUBLIC_IN_FLIGHT_REQUESTS)),
        }
    }

    /// Installs the optional native service-to-HTTP response stream bridge.
    ///
    /// Without this capability, native stream-mode requests fail with a stable
    /// 503 before service dispatch. Installing a bridge does not change complete
    /// response bytes or headers. Returned stream bodies retain request
    /// cancellation and shared admission until EOF, body error, or body drop.
    /// Externally mounted protocols declare and own their independent stream
    /// projection capability.
    #[must_use]
    pub fn with_stream_bridge(mut self, bridge: Arc<dyn ServiceStreamBridgePort>) -> Self {
        self.stream_bridge = Some(bridge);
        self
    }

    /// Installs the optional authenticated file-service capability.
    ///
    /// Without this capability, native file routes fail with a stable
    /// service-unavailable response before polling an upload body. The service
    /// owns tenant authorization, streaming persistence, integrity checks, and
    /// commit reconciliation; HTTP only supplies validated metadata and bytes.
    #[must_use]
    pub fn with_file_service(mut self, service: Arc<dyn FileServicePort>) -> Self {
        self.file_service = Some(service);
        self
    }
}

/// The concrete HTTP router returned by the Ariadnion-native public API.
///
/// Composition crates use this alias to expose their assembled router without
/// acquiring a separate direct dependency on Axum.
pub type PublicApiRouter = Router;

/// Builds the bounded version-one Ariadnion-native public HTTP router.
///
/// POST /v1/text, POST /v1/embeddings, POST /v1/images, and POST /v1/audio accept
/// strict JSON with application/json media type and one bounded Bearer authorization
/// field. Embedding, image, and audio requests use complete delivery only. A validated
/// request ID, absolute UTC deadline, and idempotency key are propagated when present.
/// When [`HttpApiState::with_file_service`] is configured, POST /v1/files accepts a
/// bounded streaming upload, GET /v1/files lists verified metadata pages,
/// GET /v1/files/{reference} returns verified metadata, and
/// GET /v1/files/{reference}/content streams verified bytes with bounded
/// backpressure; without that capability native file operations fail closed as
/// unavailable. The list route defaults to a page limit of 100 and returns
/// `files` plus a nullable `next_cursor`. DELETE /v1/files/{reference} requires
/// one canonical lowercase reference and one bounded idempotency key, then
/// returns an empty 204 response after the file service confirms deletion.
/// Header, body, credential, deadline-window, and aggregate in-flight limits
/// are shared with every external protocol route. Complete responses and
/// failures retain their stable native bytes and headers.
///
/// Handler drop and timeout cancel the request child token. Authentication and
/// dispatch ports receive the same deadline and cancellation context and must
/// observe it before every externally visible side effect.
pub fn public_router(state: HttpApiState) -> PublicApiRouter {
    Router::new()
        .route("/v1/text", post(handle_text))
        .route("/v1/embeddings", post(embedding::handle_embeddings))
        .route("/v1/images", post(image::handle_images))
        .route("/v1/audio", post(audio::handle_audio))
        .route("/v1/files", post(files::handle_upload))
        .route("/v1/files", get(file_list::handle_list))
        .route(
            "/v1/files/{reference}/content",
            get(file_content::handle_content),
        )
        .route(
            "/v1/files/{reference}",
            get(files::handle_metadata).delete(file_delete::handle_delete),
        )
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
}

async fn handle_text(State(state): State<HttpApiState>, request: Request<Body>) -> Response {
    let protocol = NativeTextProtocol::new(state.stream_bridge.clone());
    execution::handle_request(&state, &protocol, request).await
}

struct NativeTextProtocol {
    stream_bridge: Option<Arc<dyn ServiceStreamBridgePort>>,
}

impl NativeTextProtocol {
    const fn new(stream_bridge: Option<Arc<dyn ServiceStreamBridgePort>>) -> Self {
        Self { stream_bridge }
    }
}

impl HttpProtocolAdapter for NativeTextProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let dto: TextRequestDto = serde_json::from_slice(body.bytes())
            .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::InvalidRequest))?;
        let idempotency = parse_idempotency(body.headers())?;
        let projection = Arc::new(NativeTextProjection::new(self.stream_bridge.clone()));
        dto.into_protocol(idempotency, projection)
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        projection: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_native_failure(identity, projection)
    }
}

struct NativeTextProjection {
    stream_bridge: Option<Arc<dyn ServiceStreamBridgePort>>,
}

impl NativeTextProjection {
    const fn new(stream_bridge: Option<Arc<dyn ServiceStreamBridgePort>>) -> Self {
        Self { stream_bridge }
    }
}

impl HttpProtocolProjection for NativeTextProjection {
    fn supports_streaming(&self) -> bool {
        self.stream_bridge.is_some()
    }

    fn project_complete(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_service_response(response)
    }

    fn project_stream(
        &self,
        _identity: &HttpRequestIdentity,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Result<ProtocolStreamResponse, ProtocolFailure> {
        let bridge = self.stream_bridge.as_ref().ok_or_else(stream_unavailable)?;
        let stream = bridge.bridge(subscriber, context)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
        ProtocolStreamResponse::new(StatusCode::OK, headers, stream)
    }
}

fn project_native_failure(
    identity: &HttpRequestIdentity,
    projection: ProtocolFailure,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let failure = match projection {
        ProtocolFailure::Http(error) => project_native_http_failure(identity, error),
        ProtocolFailure::Domain(error) => project_native_domain_failure(identity, error),
    };
    failure.into_protocol_response()
}

fn project_native_http_failure(
    identity: &HttpRequestIdentity,
    error: ApiHttpError,
) -> ResponseFailure {
    match error.code() {
        ApiHttpErrorCode::Unauthenticated | ApiHttpErrorCode::Unavailable => {
            NativeAuthenticationFailure::Http(error).with_identity(identity.clone())
        }
        ApiHttpErrorCode::InvalidRequest
        | ApiHttpErrorCode::PayloadTooLarge
        | ApiHttpErrorCode::UnsupportedMediaType => {
            NativeBodyFailure::Http(error).with_identity(identity.clone())
        }
        _ => http_failure(identity.clone(), error),
    }
}

fn project_native_domain_failure(
    identity: &HttpRequestIdentity,
    error: ApiDomainError,
) -> ResponseFailure {
    match error.code() {
        ApiDomainErrorCode::InvalidArgument
        | ApiDomainErrorCode::UnsupportedVersion
        | ApiDomainErrorCode::LimitExceeded => {
            NativeBodyFailure::Domain(error).with_identity(identity.clone())
        }
        ApiDomainErrorCode::DeadlineExceeded => {
            NativeAuthenticationFailure::Domain(error).with_identity(identity.clone())
        }
        _ => domain_failure(identity.clone(), error),
    }
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
    fn into_protocol(
        self,
        idempotency: Option<IdempotencyKey>,
        projection: Arc<dyn HttpProtocolProjection>,
    ) -> Result<ProtocolRequest, ProtocolFailure> {
        let mode = self.response_mode.into_domain();
        let request = TextServiceRequest::new(
            ServiceContractVersion::parse(self.version)?,
            ModelSelector::new(&self.model)?,
            TextInput::new(&self.input)?,
            OutputTokenLimit::new(self.max_output_tokens)?,
            mode,
            idempotency,
        );
        ProtocolRequest::new(ServiceRequest::Text(request), mode, projection)
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

fn parse_idempotency(headers: &HeaderMap) -> Result<Option<IdempotencyKey>, ProtocolFailure> {
    let value = execution::one_header(headers, IDEMPOTENCY_HEADER, false)?;
    value
        .map(|header| {
            header
                .to_str()
                .map_err(|_| ApiDomainError::new(ApiDomainErrorCode::InvalidArgument))
                .and_then(IdempotencyKey::new)
                .map_err(ProtocolFailure::from)
        })
        .transpose()
}

#[derive(Serialize)]
struct TextResponseDto<'a> {
    version: u16,
    output: &'a str,
    finish_reason: &'static str,
}

fn project_service_response(
    response: ServiceResponse,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    match response {
        ServiceResponse::Text(response) => {
            let version = project_version(response.version())?;
            let finish_reason = project_finish_reason(response.finish_reason())?;
            let body = serde_json::to_vec(&TextResponseDto {
                version,
                output: response.output().as_str(),
                finish_reason,
            })
            .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::Internal))?;
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            ProtocolBufferedResponse::new(StatusCode::OK, headers, Bytes::from(body))
        }
        _ => Err(ApiHttpError::new(ApiHttpErrorCode::Internal).into()),
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
    let generated = match state.identity.issue() {
        Ok(identity) => identity,
        Err(error) => {
            return http_failure(state.identity.fallback_identity(), error).into_response();
        }
    };
    let identity = match execution::resolve_identity(generated.clone(), headers) {
        Ok(identity) => identity,
        Err(_) => generated,
    };
    http_failure(identity, ApiHttpError::new(code)).into_response()
}

const fn stream_unavailable() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::StreamUnavailable))
}

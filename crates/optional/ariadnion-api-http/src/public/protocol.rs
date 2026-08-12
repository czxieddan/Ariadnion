// crates/optional/ariadnion-api-http/src/public/protocol.rs - Reusable HTTP protocol execution contracts for Ariadnion.
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
//! Typed contracts for protocol-owned public HTTP routes and wire projection.

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, ResponseMode, ServiceRequest, ServiceResponse,
    ServiceStreamEvent,
};
use ariadnion_core::{EventSubscriber, RequestContext};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{MethodRouter, post};

use super::{
    ApiHttpError, ApiHttpErrorCode, BoxHttpBodyStream, HttpApiState, HttpRequestIdentity,
    MAX_PUBLIC_BODY_BYTES, MAX_PUBLIC_HEADER_BYTES, MAX_PUBLIC_HEADERS, execution,
};

const REQUEST_ID_HEADER: &str = "x-request-id";
const UNSAFE_RESPONSE_HEADERS: [&str; 10] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// A bounded request body and its validated, non-credential headers.
///
/// Common execution has already enforced the shared header, media type,
/// content-length, deadline, cancellation, and body-size limits. It has also
/// removed the authorization field after parsing the ephemeral Bearer value.
/// Protocol adapters may inspect remaining protocol-specific headers but must
/// apply their own value bounds before allocating or retaining them.
pub struct ProtocolRequestBody {
    bytes: Bytes,
    headers: HeaderMap,
}

impl ProtocolRequestBody {
    pub(super) const fn new(bytes: Bytes, headers: HeaderMap) -> Self {
        Self { bytes, headers }
    }

    /// Borrows the complete bounded encoded body.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows globally validated headers with authorization material removed.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

/// A protocol-decoded service request and its required response delivery mode.
///
/// Construction verifies that the declared mode matches the bounded domain
/// request. This prevents a protocol adapter from dispatching a request whose
/// outcome lifetime cannot be projected safely by common HTTP execution.
pub struct ProtocolRequest {
    request: ServiceRequest,
    response_mode: ResponseMode,
    projection: Arc<dyn HttpProtocolProjection>,
}

impl ProtocolRequest {
    /// Creates a checked protocol request from transport-neutral domain values.
    ///
    /// # Errors
    ///
    /// Returns a redacted internal HTTP failure when the declared response mode
    /// does not match the domain request or the request variant is unknown to
    /// this version of the execution adapter.
    pub fn new(
        request: ServiceRequest,
        response_mode: ResponseMode,
        projection: Arc<dyn HttpProtocolProjection>,
    ) -> Result<Self, ProtocolFailure> {
        validate_request_mode(&request, response_mode)?;
        Ok(Self {
            request,
            response_mode,
            projection,
        })
    }

    /// Borrows the validated transport-neutral service request.
    #[must_use]
    pub const fn request(&self) -> &ServiceRequest {
        &self.request
    }

    /// Returns the checked response delivery mode.
    #[must_use]
    pub const fn response_mode(&self) -> ResponseMode {
        self.response_mode
    }

    /// Borrows the request-owned wire projection state.
    #[must_use]
    pub fn projection(&self) -> &dyn HttpProtocolProjection {
        self.projection.as_ref()
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        ServiceRequest,
        ResponseMode,
        Arc<dyn HttpProtocolProjection>,
    ) {
        (self.request, self.response_mode, self.projection)
    }
}

/// A redacted failure retaining HTTP-facing versus service-domain classification.
///
/// Protocol adapters receive only stable error values and the authoritative
/// request identity when projecting failure bytes. This public classification
/// never establishes authentication provenance; common execution tracks genuine
/// Bearer failures privately. The enum never retains credentials, body data,
/// internal paths, SQL, or provider diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtocolFailure {
    /// A stable HTTP-facing failure without authentication provenance.
    Http(ApiHttpError),
    /// A failure owned by transport-neutral request or dispatch semantics.
    Domain(ApiDomainError),
}

impl ProtocolFailure {
    /// Returns the stable HTTP code when this is an HTTP-ingress failure.
    #[must_use]
    pub const fn http_code(self) -> Option<ApiHttpErrorCode> {
        match self {
            Self::Http(error) => Some(error.code()),
            Self::Domain(_) => None,
        }
    }

    /// Returns the stable domain code when this is a service-domain failure.
    #[must_use]
    pub const fn domain_code(self) -> Option<ApiDomainErrorCode> {
        match self {
            Self::Domain(error) => Some(error.code()),
            Self::Http(_) => None,
        }
    }
}

impl Debug for ProtocolFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => write!(formatter, "ProtocolFailure::Http({error})"),
            Self::Domain(error) => write!(formatter, "ProtocolFailure::Domain({error})"),
        }
    }
}

impl Display for ProtocolFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => Display::fmt(error, formatter),
            Self::Domain(error) => Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for ProtocolFailure {}

impl From<ApiHttpError> for ProtocolFailure {
    fn from(error: ApiHttpError) -> Self {
        Self::Http(error)
    }
}

impl From<ApiDomainError> for ProtocolFailure {
    fn from(error: ApiDomainError) -> Self {
        Self::Domain(error)
    }
}

/// A finite protocol-owned response validated before common HTTP commitment.
///
/// The private byte buffer cannot contain a pending or unbounded body. Public
/// construction enforces the shared body, header-count, and aggregate header
/// byte limits, rejects protocol-controlled framing and hop-by-hop fields, and
/// removes request-ID and authentication-challenge fields reserved for common
/// execution.
pub struct ProtocolBufferedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl ProtocolBufferedResponse {
    /// Creates a checked finite response from protocol-owned wire bytes.
    ///
    /// # Errors
    ///
    /// Returns a redacted internal failure when the status is not a final HTTP
    /// status, a body is attached to a body-forbidden status, the body or headers
    /// exceed public response limits, or headers attempt to control HTTP framing,
    /// connection lifetime, proxy authentication, trailers, or upgrades.
    pub fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Self, ProtocolFailure> {
        validate_buffered_response_status(status, body.len())?;
        let headers = checked_response_headers(headers)?;
        validate_response_body(body.len())?;
        Ok(Self {
            status,
            headers,
            body,
        })
    }

    /// Returns the protocol-selected response status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Borrows the checked protocol response headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Borrows the complete finite encoded response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub(super) fn into_parts(self) -> (StatusCode, HeaderMap, Bytes) {
        (self.status, self.headers, self.body)
    }
}

/// A protocol-owned streaming response before common lifetime retention.
///
/// The protocol controls the status, safe response headers, and exact encoded
/// byte stream. Common execution wraps the stream to retain request admission
/// and cancellation until EOF or body drop, then overwrites the request ID with
/// the authoritative value.
pub struct ProtocolStreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    stream: BoxHttpBodyStream,
}

impl ProtocolStreamResponse {
    /// Creates a streaming wire projection from checked protocol-owned parts.
    ///
    /// # Errors
    ///
    /// Returns a redacted internal failure when the status is not final or
    /// cannot carry a streaming body, the headers exceed shared response limits,
    /// or headers attempt to control framing, connection lifetime, proxy
    /// authentication, trailers, or upgrades.
    pub fn new(
        status: StatusCode,
        headers: HeaderMap,
        stream: BoxHttpBodyStream,
    ) -> Result<Self, ProtocolFailure> {
        validate_stream_response_status(status)?;
        let headers = checked_response_headers(headers)?;
        Ok(Self {
            status,
            headers,
            stream,
        })
    }

    /// Returns the protocol-selected response status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Borrows the protocol-selected response headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub(super) fn into_parts(self) -> (StatusCode, HeaderMap, BoxHttpBodyStream) {
        (self.status, self.headers, self.stream)
    }
}

/// Projects response bytes with protocol-owned state retained for one request.
///
/// A decoder creates one projection value for each accepted request. It may
/// retain bounded non-secret protocol metadata such as the requested model or
/// stream options without a global request registry. Common execution keeps it
/// beside the service request until dispatch completes, fails, or starts a stream.
pub trait HttpProtocolProjection: Send + Sync {
    /// Reports whether this request can project a streaming service outcome.
    ///
    /// Common execution checks this after authentication and before dispatch.
    fn supports_streaming(&self) -> bool;

    /// Projects a matching complete service response into exact protocol bytes.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted failure when the response variant or value
    /// cannot be represented by this request's protocol state.
    fn project_complete(
        &self,
        identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure>;

    /// Projects a matching service subscriber into an exact streaming response.
    ///
    /// The returned stream must remain non-buffering and observe the authenticated
    /// context's cancellation and deadline. Common execution retains and cancels
    /// both request and subscriber lifetimes when the HTTP body ends or is dropped.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted failure before response headers are committed.
    fn project_stream(
        &self,
        identity: &HttpRequestIdentity,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Result<ProtocolStreamResponse, ProtocolFailure>;
}

/// Decodes and projects failures for one independently mounted HTTP protocol.
///
/// Implementations own protocol DTOs, strict body decoding, complete bytes,
/// streaming bytes and failure envelopes. They must not retain credentials or
/// request bodies in diagnostics. Common execution owns admission, correlation,
/// framing validation, bounded collection, Bearer authentication, dispatch
/// deadlines, cancellation, response-mode matching, and stream lifetime.
pub trait HttpProtocolAdapter: Send + Sync {
    /// Decodes one bounded body into a checked transport-neutral request.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted failure for invalid protocol syntax, unsupported
    /// values, exceeded protocol limits, or incompatible response mode.
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure>;

    /// Projects a classified redacted failure into protocol-owned wire bytes.
    ///
    /// Common execution overwrites the request ID response header and adds the
    /// Bearer challenge only when common Bearer authentication genuinely failed.
    ///
    /// # Errors
    ///
    /// Returns a redacted projection failure when the protocol cannot produce
    /// a bounded safe envelope. Common execution then emits one fixed internal
    /// response without invoking the protocol again.
    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure>;
}

/// Cloneable shared execution state for one externally owned protocol route.
#[derive(Clone)]
pub struct ProtocolExecutionState {
    http: HttpApiState,
    protocol: Arc<dyn HttpProtocolAdapter>,
}

impl ProtocolExecutionState {
    /// Binds one protocol adapter to existing shared HTTP ingress state.
    ///
    /// Cloning either input preserves the same global in-flight admission budget,
    /// authentication port, dispatch port, shutdown tree, and optional native SSE
    /// bridge used by the Ariadnion-native public router.
    #[must_use]
    pub const fn new(http: HttpApiState, protocol: Arc<dyn HttpProtocolAdapter>) -> Self {
        Self { http, protocol }
    }

    pub(super) const fn http(&self) -> &HttpApiState {
        &self.http
    }

    pub(super) fn protocol(&self) -> &dyn HttpProtocolAdapter {
        self.protocol.as_ref()
    }
}

/// Returns a strongly typed POST method route for protocol-owner mounting.
///
/// The calling protocol crate supplies the path through Axum Router::route;
/// this crate does not register, branch on, or retain protocol names or paths.
pub fn protocol_post_route() -> MethodRouter<ProtocolExecutionState> {
    post(execution::handle_protocol)
}

fn validate_request_mode(
    request: &ServiceRequest,
    declared: ResponseMode,
) -> Result<(), ProtocolFailure> {
    let actual = match request {
        ServiceRequest::Text(request) => request.response_mode(),
        ServiceRequest::Chat(request) => request.response_mode(),
        ServiceRequest::Embedding(_) => ResponseMode::Complete,
        _ => return Err(internal_failure()),
    };
    if actual != declared {
        return Err(internal_failure());
    }
    Ok(())
}

fn checked_response_headers(mut headers: HeaderMap) -> Result<HeaderMap, ProtocolFailure> {
    validate_response_header_budget(&headers)?;
    reject_unsafe_response_headers(&headers)?;
    headers.remove(REQUEST_ID_HEADER);
    headers.remove(header::WWW_AUTHENTICATE);
    Ok(headers)
}

fn validate_response_body(length: usize) -> Result<(), ProtocolFailure> {
    if length > MAX_PUBLIC_BODY_BYTES {
        return Err(internal_failure());
    }
    Ok(())
}

fn validate_buffered_response_status(
    status: StatusCode,
    body_length: usize,
) -> Result<(), ProtocolFailure> {
    validate_final_response_status(status)?;
    if response_body_forbidden(status) && body_length != 0 {
        return Err(internal_failure());
    }
    Ok(())
}

fn validate_stream_response_status(status: StatusCode) -> Result<(), ProtocolFailure> {
    validate_final_response_status(status)?;
    if response_body_forbidden(status) {
        return Err(internal_failure());
    }
    Ok(())
}

fn validate_final_response_status(status: StatusCode) -> Result<(), ProtocolFailure> {
    if status.is_informational() || status.as_u16() > 599 {
        return Err(internal_failure());
    }
    Ok(())
}

const fn response_body_forbidden(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
    )
}

pub(super) fn validate_response_header_budget(headers: &HeaderMap) -> Result<(), ProtocolFailure> {
    if headers.len() > MAX_PUBLIC_HEADERS {
        return Err(internal_failure());
    }
    let mut total = 0_usize;
    for (name, value) in headers {
        total = checked_header_total(total, name.as_str().len(), value.as_bytes().len())?;
        if total > MAX_PUBLIC_HEADER_BYTES {
            return Err(internal_failure());
        }
    }
    Ok(())
}

fn checked_header_total(total: usize, name: usize, value: usize) -> Result<usize, ProtocolFailure> {
    total
        .checked_add(name)
        .and_then(|size| size.checked_add(value))
        .ok_or_else(internal_failure)
}

fn reject_unsafe_response_headers(headers: &HeaderMap) -> Result<(), ProtocolFailure> {
    if UNSAFE_RESPONSE_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return Err(internal_failure());
    }
    Ok(())
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

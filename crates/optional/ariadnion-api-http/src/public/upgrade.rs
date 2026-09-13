// crates/optional/ariadnion-api-http/src/public/upgrade.rs - Bounded protocol-neutral WebSocket ingress.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Shared authenticated WebSocket admission without protocol-specific grammar.

use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_api_domain::ApiDomainError;
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext, RequestId};
use axum::body::{Body, HttpBody};
use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get};
use tokio::sync::OwnedSemaphorePermit;

use super::execution;
use super::{
    ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpRequestIdentity, ProtocolBufferedResponse,
    ProtocolFailure,
};

const DEADLINE_HEADER: &str = "x-ariadnion-deadline-unix-ms";
const REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_UPGRADE_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_UPGRADE_FRAME_BYTES: usize = 256 * 1024;
const MAX_UPGRADE_WRITE_OVERHEAD_BYTES: usize = 256;
const MAX_UPGRADE_SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// A boxed protocol-owned WebSocket session future.
///
/// The future owns the socket and must finish when its supplied request context
/// becomes inactive. Common execution also drops the future at cancellation or
/// deadline so a protocol implementation cannot retain the socket indefinitely.
pub type BoxHttpUpgradeFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// A boxed protocol-owned WebSocket session prepared from one request target.
///
/// The session is single-use so query-derived state cannot be shared between
/// concurrent upgrades. Common HTTP execution retains it only for the request
/// that produced it and transfers it after authentication and handshake checks.
pub type BoxHttpUpgradeSession = Box<dyn HttpUpgradeSession + 'static>;

/// One protocol-owned, single-use WebSocket session.
pub trait HttpUpgradeSession: Send {
    /// Drives the upgraded socket under the authenticated request context.
    ///
    /// The future receives exclusive socket ownership and must preserve frame
    /// ordering and protocol backpressure. Common execution cancels and drops it
    /// when the request, server, or absolute session deadline becomes inactive.
    fn serve(
        self: Box<Self>,
        socket: WebSocket,
        identity: HttpRequestIdentity,
        context: RequestContext,
    ) -> BoxHttpUpgradeFuture;
}

/// Protocol-owned validation and execution for one authenticated WebSocket route.
///
/// Implementations validate only their query grammar and drive only their public
/// frame protocol. Shared HTTP execution owns identity, global admission, Bearer
/// authentication, absolute deadlines, cancellation, handshake validation, and
/// transport limits. Implementations must not retain credentials or replace the
/// authenticated principal in the supplied context.
pub trait HttpUpgradeProtocolAdapter: Send + Sync {
    /// Validates the raw query and prepares request-local protocol state.
    ///
    /// # Errors
    ///
    /// Returns a bounded protocol failure for a missing, duplicate, malformed,
    /// or unsupported query member. No socket or service work has started yet.
    fn prepare(&self, query: Option<&str>) -> Result<BoxHttpUpgradeSession, ProtocolFailure>;

    /// Projects a pre-upgrade failure into finite protocol-owned response bytes.
    ///
    /// Authentication failures receive a common `WWW-Authenticate: Bearer`
    /// header after projection. The adapter must not echo credentials, query
    /// secrets, internal paths, or provider diagnostics.
    ///
    /// # Errors
    ///
    /// Returns a projection failure when no bounded safe envelope can be built;
    /// common execution then emits a fixed internal response.
    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure>;
}

/// Hard transport and lifetime bounds for one WebSocket route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolUpgradeLimits {
    max_message_bytes: usize,
    max_frame_bytes: usize,
    session_lifetime: Duration,
}

impl ProtocolUpgradeLimits {
    /// Creates validated non-zero limits within the P4 Realtime hard bounds.
    ///
    /// A frame cannot exceed its containing message. Message and frame bounds
    /// are each at most 256 KiB, and the session lifetime is at most 60 minutes.
    ///
    /// # Errors
    ///
    /// Returns [`ApiHttpErrorCode::InvalidRequest`] for zero, inverted, or
    /// oversized values.
    pub fn new(
        max_message_bytes: usize,
        max_frame_bytes: usize,
        session_lifetime: Duration,
    ) -> Result<Self, ApiHttpError> {
        validate_limits(max_message_bytes, max_frame_bytes, session_lifetime)?;
        Ok(Self {
            max_message_bytes,
            max_frame_bytes,
            session_lifetime,
        })
    }

    /// Returns the maximum decoded message size.
    #[must_use]
    pub const fn max_message_bytes(self) -> usize {
        self.max_message_bytes
    }

    /// Returns the maximum decoded frame size.
    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }

    /// Returns the maximum absolute session lifetime.
    #[must_use]
    pub const fn session_lifetime(self) -> Duration {
        self.session_lifetime
    }
}

/// Cloneable Axum state for one protocol-owned WebSocket route.
#[derive(Clone)]
pub struct ProtocolUpgradeExecutionState {
    http: HttpApiState,
    protocol: Arc<dyn HttpUpgradeProtocolAdapter>,
    limits: ProtocolUpgradeLimits,
}

impl ProtocolUpgradeExecutionState {
    /// Creates a route state over shared HTTP ports and fixed transport limits.
    #[must_use]
    pub const fn new(
        http: HttpApiState,
        protocol: Arc<dyn HttpUpgradeProtocolAdapter>,
        limits: ProtocolUpgradeLimits,
    ) -> Self {
        Self {
            http,
            protocol,
            limits,
        }
    }
}

impl Debug for ProtocolUpgradeExecutionState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolUpgradeExecutionState")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Returns the shared authenticated GET-to-WebSocket route handler.
pub fn protocol_upgrade_route() -> MethodRouter<ProtocolUpgradeExecutionState> {
    get(handle_upgrade)
}

async fn handle_upgrade(
    State(state): State<ProtocolUpgradeExecutionState>,
    request: Request<Body>,
) -> Response {
    match try_handle_upgrade(&state, request).await {
        Ok(response) => response,
        Err(failure) => project_upgrade_failure(state.protocol.as_ref(), failure),
    }
}

async fn try_handle_upgrade(
    state: &ProtocolUpgradeExecutionState,
    request: Request<Body>,
) -> Result<Response, UpgradeFailure> {
    let generated =
        state.http.identity.issue().map_err(|error| {
            UpgradeFailure::http(state.http.identity.fallback_identity(), error)
        })?;
    let permit = state
        .http
        .admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| UpgradeFailure::resource_exhausted(generated.clone()))?;
    execute_upgrade(state, generated, request, permit).await
}

async fn execute_upgrade(
    state: &ProtocolUpgradeExecutionState,
    generated: HttpRequestIdentity,
    request: Request<Body>,
    permit: OwnedSemaphorePermit,
) -> Result<Response, UpgradeFailure> {
    let admission = admit_upgrade(state, generated, request, permit)?;
    let authenticated = authenticate_upgrade(state, admission).await?;
    complete_upgrade(state, authenticated).await
}

fn admit_upgrade(
    state: &ProtocolUpgradeExecutionState,
    generated: HttpRequestIdentity,
    request: Request<Body>,
    permit: OwnedSemaphorePermit,
) -> Result<UpgradeAdmission, UpgradeFailure> {
    let (mut parts, body) = request.into_parts();
    execution::validate_header_budget(&parts.headers)
        .map_err(|error| UpgradeFailure::http(generated.clone(), error))?;
    let identity = resolve_identity(generated, &parts.headers)
        .map_err(|error| UpgradeFailure::http(error.0, error.1))?;
    let deadline = parse_upgrade_deadline(
        &parts.headers,
        SystemTime::now(),
        state.limits.session_lifetime(),
    )
    .map_err(|error| UpgradeFailure::http(identity.clone(), error))?;
    let lifetime = UpgradeLifetime::new(&state.http.shutdown, permit);
    let anonymous = request_context(&identity, deadline, lifetime.token(), None);
    check_context(&anonymous).map_err(|error| UpgradeFailure::domain(identity.clone(), error))?;
    validate_bodyless(&parts.headers, &body)
        .map_err(|error| UpgradeFailure::http(identity.clone(), error))?;
    let session = state
        .protocol
        .prepare(parts.uri.query())
        .map_err(|failure| UpgradeFailure::new(identity.clone(), failure))?;
    let authorization = execution::parse_authorization(&parts.headers)
        .map_err(|error| UpgradeFailure::authentication(identity.clone(), error))?;
    parts.headers.remove(header::AUTHORIZATION);
    drop(body);
    Ok(UpgradeAdmission {
        identity,
        deadline,
        lifetime,
        anonymous,
        authorization,
        session,
        parts,
    })
}

async fn authenticate_upgrade(
    state: &ProtocolUpgradeExecutionState,
    admission: UpgradeAdmission,
) -> Result<AuthenticatedUpgrade, UpgradeFailure> {
    let result = execution::within_request_context(
        &admission.anonymous,
        state
            .http
            .authentication
            .authenticate(&admission.authorization, &admission.anonymous),
    )
    .await
    .map_err(|error| UpgradeFailure::domain(admission.identity.clone(), error))?;
    let evidence = result
        .map_err(|error| UpgradeFailure::authentication(admission.identity.clone(), error))?;
    let context = request_context(
        &admission.identity,
        admission.deadline,
        admission.lifetime.token(),
        Some(PrincipalContext::new(
            evidence.tenant_id().clone(),
            evidence.principal_id().clone(),
        )),
    );
    check_context(&context)
        .map_err(|error| UpgradeFailure::domain(admission.identity.clone(), error))?;
    Ok(AuthenticatedUpgrade {
        identity: admission.identity,
        lifetime: admission.lifetime,
        context,
        session: admission.session,
        parts: admission.parts,
    })
}

async fn complete_upgrade(
    state: &ProtocolUpgradeExecutionState,
    mut request: AuthenticatedUpgrade,
) -> Result<Response, UpgradeFailure> {
    let websocket = WebSocketUpgrade::from_request_parts(&mut request.parts, &())
        .await
        .map_err(|_| UpgradeFailure::http(request.identity.clone(), invalid_request()))?;
    check_context(&request.context)
        .map_err(|error| UpgradeFailure::domain(request.identity.clone(), error))?;
    let response_identity = request.identity.clone();
    let limits = state.limits;
    let response = websocket
        .read_buffer_size(limits.max_frame_bytes().min(64 * 1024))
        .write_buffer_size(0)
        .max_write_buffer_size(limits.max_message_bytes() + MAX_UPGRADE_WRITE_OVERHEAD_BYTES)
        .max_message_size(limits.max_message_bytes())
        .max_frame_size(limits.max_frame_bytes())
        .on_upgrade(move |socket| serve_upgrade(socket, request));
    finalize_upgrade_response(&response_identity, response)
        .map_err(|failure| UpgradeFailure::new(response_identity, failure))
}

async fn serve_upgrade(socket: WebSocket, request: AuthenticatedUpgrade) {
    let AuthenticatedUpgrade {
        identity,
        lifetime,
        context,
        session,
        ..
    } = request;
    let _lifetime = lifetime;
    if check_context(&context).is_err() {
        return;
    }
    let watchdog = context.clone();
    let future = session.serve(socket, identity, context);
    let _ = execution::within_request_context(&watchdog, future).await;
}

fn validate_limits(
    max_message_bytes: usize,
    max_frame_bytes: usize,
    session_lifetime: Duration,
) -> Result<(), ApiHttpError> {
    let invalid_bytes = max_message_bytes == 0
        || max_message_bytes > MAX_UPGRADE_MESSAGE_BYTES
        || max_frame_bytes == 0
        || max_frame_bytes > MAX_UPGRADE_FRAME_BYTES
        || max_frame_bytes > max_message_bytes;
    if invalid_bytes
        || session_lifetime.is_zero()
        || session_lifetime > MAX_UPGRADE_SESSION_LIFETIME
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn resolve_identity(
    generated: HttpRequestIdentity,
    headers: &HeaderMap,
) -> Result<HttpRequestIdentity, (HttpRequestIdentity, ApiHttpError)> {
    let value = execution::one_header(headers, REQUEST_ID_HEADER, false)
        .map_err(|error| (generated.clone(), error))?;
    let Some(value) = value else {
        return Ok(generated);
    };
    let text = value
        .to_str()
        .map_err(|_| (generated.clone(), invalid_request()))?;
    let request_id = RequestId::parse(text).map_err(|_| (generated.clone(), invalid_request()))?;
    Ok(generated.replace_request_id(request_id))
}

fn parse_upgrade_deadline(
    headers: &HeaderMap,
    now: SystemTime,
    session_lifetime: Duration,
) -> Result<SystemTime, ApiHttpError> {
    let Some(value) = execution::one_header(headers, DEADLINE_HEADER, false)? else {
        return now.checked_add(session_lifetime).ok_or_else(internal_error);
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
    if deadline
        .duration_since(now)
        .is_ok_and(|remaining| remaining > session_lifetime)
    {
        return Err(invalid_request());
    }
    Ok(deadline)
}

fn validate_bodyless(headers: &HeaderMap, body: &Body) -> Result<(), ApiHttpError> {
    if headers.contains_key(header::TRANSFER_ENCODING) || !body.is_end_stream() {
        return Err(invalid_request());
    }
    let length = execution::one_header(headers, header::CONTENT_LENGTH.as_str(), false)?
        .map(parse_content_length)
        .transpose()?;
    if length.is_some_and(|value| value != 0) {
        return Err(invalid_request());
    }
    Ok(())
}

fn parse_content_length(value: &HeaderValue) -> Result<u64, ApiHttpError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(invalid_request());
    }
    value
        .to_str()
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(invalid_request)
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

fn check_context(context: &RequestContext) -> Result<(), ApiDomainError> {
    context.check_active().map_err(ApiDomainError::from)
}

fn project_upgrade_failure(
    protocol: &dyn HttpUpgradeProtocolAdapter,
    failure: UpgradeFailure,
) -> Response {
    let (identity, failure, challenge) = failure.into_parts();
    match protocol.project_failure(&identity, failure) {
        Ok(projected) => finalize_buffered_response(&identity, projected, challenge)
            .unwrap_or_else(|_| internal_fallback(&identity)),
        Err(_) => internal_fallback(&identity),
    }
}

fn finalize_buffered_response(
    identity: &HttpRequestIdentity,
    projected: ProtocolBufferedResponse,
    challenge: bool,
) -> Result<Response, ProtocolFailure> {
    let (status, headers, body) = projected.into_parts();
    let headers = finalize_headers(identity, headers, challenge)?;
    let mut response = Body::from(body).into_response();
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn finalize_upgrade_response(
    identity: &HttpRequestIdentity,
    mut response: Response,
) -> Result<Response, ProtocolFailure> {
    let headers = std::mem::take(response.headers_mut());
    *response.headers_mut() = finalize_headers(identity, headers, false)?;
    Ok(response)
}

fn finalize_headers(
    identity: &HttpRequestIdentity,
    mut headers: HeaderMap,
    challenge: bool,
) -> Result<HeaderMap, ProtocolFailure> {
    headers.remove(header::WWW_AUTHENTICATE);
    if challenge {
        headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    let request_id = HeaderValue::from_str(identity.request_id().as_str())
        .map_err(|_| ProtocolFailure::Http(internal_error()))?;
    headers.insert(REQUEST_ID_HEADER, request_id);
    execution::validate_header_budget(&headers).map_err(ProtocolFailure::Http)?;
    Ok(headers)
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

struct UpgradeAdmission {
    identity: HttpRequestIdentity,
    deadline: SystemTime,
    lifetime: UpgradeLifetime,
    anonymous: RequestContext,
    authorization: super::PresentedBearer,
    session: BoxHttpUpgradeSession,
    parts: axum::http::request::Parts,
}

struct AuthenticatedUpgrade {
    identity: HttpRequestIdentity,
    lifetime: UpgradeLifetime,
    context: RequestContext,
    session: BoxHttpUpgradeSession,
    parts: axum::http::request::Parts,
}

struct UpgradeLifetime {
    cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
}

impl UpgradeLifetime {
    fn new(shutdown: &CancellationToken, permit: OwnedSemaphorePermit) -> Self {
        Self {
            cancellation: shutdown.child(),
            _permit: permit,
        }
    }

    fn token(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

impl Drop for UpgradeLifetime {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct UpgradeFailure {
    identity: HttpRequestIdentity,
    failure: ProtocolFailure,
    bearer_challenge: bool,
}

impl UpgradeFailure {
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

    fn resource_exhausted(identity: HttpRequestIdentity) -> Self {
        Self::http(
            identity,
            ApiHttpError::new(ApiHttpErrorCode::ResourceExhausted),
        )
    }

    fn into_parts(self) -> (HttpRequestIdentity, ProtocolFailure, bool) {
        (self.identity, self.failure, self.bearer_challenge)
    }
}

const fn invalid_request() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::InvalidRequest)
}

const fn internal_error() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::Internal)
}

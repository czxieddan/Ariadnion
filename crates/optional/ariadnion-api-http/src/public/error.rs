// crates/optional/ariadnion-api-http/src/public/error.rs - Public HTTP error contracts and projections for Ariadnion.
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
//! Stable public HTTP error contracts and redacted response projections.

use std::fmt::{self, Debug, Display, Formatter};

use ariadnion_api_domain::{ApiDomainError, ApiDomainErrorCode};
use ariadnion_api_files::{ApiFilesError, ApiFilesErrorCode};
use ariadnion_core::RequestId;
use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde::Serialize;

use super::protocol::{ProtocolBufferedResponse, ProtocolFailure};
use super::{HttpRequestIdentity, REQUEST_ID_HEADER};

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

pub(super) struct ResponseFailure {
    identity: HttpRequestIdentity,
    projection: ErrorProjection,
}

impl ResponseFailure {
    pub(super) fn into_response(self) -> Response {
        projected_response(&self.identity, self.projection)
    }

    pub(super) fn into_protocol_response(
        self,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let Self {
            identity,
            projection,
        } = self;
        let body = serde_json::to_vec(&ErrorBody {
            code: projection.code,
            message: projection.message,
            request_id: identity.request_id().as_str().to_owned(),
            details: EmptyDetails {},
            retryable: projection.retryable,
            retry_after_ms: None,
        })
        .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::Internal))?;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        ProtocolBufferedResponse::new(projection.status, headers, Bytes::from(body))
    }
}

pub(super) enum AuthenticationFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
}

pub(super) enum BodyFailure {
    Http(ApiHttpError),
    Domain(ApiDomainError),
}

impl BodyFailure {
    pub(super) fn with_identity(self, identity: HttpRequestIdentity) -> ResponseFailure {
        match self {
            Self::Http(error) => failure(identity, error),
            Self::Domain(error) => domain_failure(identity, error),
        }
    }
}

impl AuthenticationFailure {
    pub(super) fn with_identity(self, identity: HttpRequestIdentity) -> ResponseFailure {
        match self {
            Self::Http(error) => failure(identity, error),
            Self::Domain(error) => domain_failure(identity, error),
        }
    }
}

impl ResponseFailure {
    pub(super) fn file(identity: HttpRequestIdentity, error: ApiFilesError) -> Self {
        Self {
            identity,
            projection: project_files_error(error),
        }
    }
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

fn project_files_error(error: ApiFilesError) -> ErrorProjection {
    let code = error.code();
    ErrorProjection {
        status: files_status(code),
        code: code.as_str(),
        message: files_message(code),
        retryable: files_retryable(code),
    }
}

const fn files_status(code: ApiFilesErrorCode) -> StatusCode {
    match code {
        ApiFilesErrorCode::InvalidArgument
        | ApiFilesErrorCode::LimitExceeded
        | ApiFilesErrorCode::Unauthenticated
        | ApiFilesErrorCode::NotFound => files_client_status(code),
        ApiFilesErrorCode::Conflict
        | ApiFilesErrorCode::PolicyRejected
        | ApiFilesErrorCode::Cancelled
        | ApiFilesErrorCode::DeadlineExceeded
        | ApiFilesErrorCode::ResourceExhausted => files_operational_status(code),
        ApiFilesErrorCode::Unavailable | ApiFilesErrorCode::CommitIndeterminate => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        ApiFilesErrorCode::IntegrityFailure | ApiFilesErrorCode::Internal | _ => internal_status(),
    }
}

const fn files_client_status(code: ApiFilesErrorCode) -> StatusCode {
    match code {
        ApiFilesErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
        ApiFilesErrorCode::LimitExceeded => StatusCode::PAYLOAD_TOO_LARGE,
        ApiFilesErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        ApiFilesErrorCode::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

const fn files_operational_status(code: ApiFilesErrorCode) -> StatusCode {
    match code {
        ApiFilesErrorCode::Conflict => StatusCode::CONFLICT,
        ApiFilesErrorCode::PolicyRejected => StatusCode::FORBIDDEN,
        ApiFilesErrorCode::Cancelled => status_499(),
        ApiFilesErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        ApiFilesErrorCode::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

const fn internal_status() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

const fn files_message(code: ApiFilesErrorCode) -> &'static str {
    match code {
        ApiFilesErrorCode::InvalidArgument
        | ApiFilesErrorCode::LimitExceeded
        | ApiFilesErrorCode::Unauthenticated
        | ApiFilesErrorCode::NotFound => files_client_message(code),
        ApiFilesErrorCode::Conflict
        | ApiFilesErrorCode::PolicyRejected
        | ApiFilesErrorCode::Cancelled
        | ApiFilesErrorCode::DeadlineExceeded
        | ApiFilesErrorCode::ResourceExhausted => files_operational_message(code),
        ApiFilesErrorCode::Unavailable | ApiFilesErrorCode::CommitIndeterminate => {
            files_availability_message(code)
        }
        ApiFilesErrorCode::IntegrityFailure | ApiFilesErrorCode::Internal | _ => {
            "The file request could not be completed."
        }
    }
}

const fn files_client_message(code: ApiFilesErrorCode) -> &'static str {
    match code {
        ApiFilesErrorCode::InvalidArgument => "A file request value is invalid.",
        ApiFilesErrorCode::LimitExceeded => "A file request limit was exceeded.",
        ApiFilesErrorCode::Unauthenticated => "Authentication is required.",
        ApiFilesErrorCode::NotFound => "The requested file was not found.",
        _ => "The file request could not be completed.",
    }
}

const fn files_operational_message(code: ApiFilesErrorCode) -> &'static str {
    match code {
        ApiFilesErrorCode::Conflict => "The file request conflicts with current state.",
        ApiFilesErrorCode::PolicyRejected => "The file request is not permitted.",
        ApiFilesErrorCode::Cancelled => "The file request was cancelled.",
        ApiFilesErrorCode::DeadlineExceeded => "The file request deadline was exceeded.",
        ApiFilesErrorCode::ResourceExhausted => "File service capacity is exhausted.",
        _ => "The file request could not be completed.",
    }
}

const fn files_availability_message(code: ApiFilesErrorCode) -> &'static str {
    match code {
        ApiFilesErrorCode::Unavailable => "The file service is unavailable.",
        ApiFilesErrorCode::CommitIndeterminate => "The file commit requires reconciliation.",
        _ => "The file request could not be completed.",
    }
}

const fn files_retryable(code: ApiFilesErrorCode) -> bool {
    matches!(
        code,
        ApiFilesErrorCode::DeadlineExceeded
            | ApiFilesErrorCode::ResourceExhausted
            | ApiFilesErrorCode::Unavailable
    )
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

pub(super) fn response_with_request_id(
    identity: &HttpRequestIdentity,
    mut response: Response,
) -> Response {
    attach_request_id(&mut response, identity.request_id());
    response
}

fn projected_response(identity: &HttpRequestIdentity, projection: ErrorProjection) -> Response {
    let challenge = projection.status == StatusCode::UNAUTHORIZED;
    let mut response = (
        projection.status,
        Json(ErrorBody {
            code: projection.code,
            message: projection.message,
            request_id: identity.request_id().as_str().to_owned(),
            details: EmptyDetails {},
            retryable: projection.retryable,
            retry_after_ms: None,
        }),
    )
        .into_response();
    response = response_with_request_id(identity, response);
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

pub(super) fn failure(identity: HttpRequestIdentity, error: ApiHttpError) -> ResponseFailure {
    ResponseFailure {
        identity,
        projection: project_http_error(error),
    }
}

pub(super) fn domain_failure(
    identity: HttpRequestIdentity,
    error: ApiDomainError,
) -> ResponseFailure {
    ResponseFailure {
        identity,
        projection: project_domain_error(error),
    }
}

pub(super) const fn invalid_request() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::InvalidRequest)
}

pub(super) const fn unauthenticated() -> ApiHttpError {
    ApiHttpError::new(ApiHttpErrorCode::Unauthenticated)
}

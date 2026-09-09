// crates/optional/ariadnion-protocol-openai/src/responses/response.rs - OpenAI Responses JSON projection.
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
//! Complete Responses object projection over the provider-neutral text domain.

mod request;
pub(crate) mod stream;

pub(crate) use request::decode as decode_request;

use std::fmt::{self, Debug, Formatter};

use ariadnion_api_domain::{
    ApiDomainErrorCode, FinishReason, ServiceContractVersion, ServiceResponse, TextServiceResponse,
};
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, HttpProtocolProjection, HttpRequestIdentity,
    ProtocolBufferedResponse, ProtocolFailure, ProtocolStreamResponse,
};
use ariadnion_core::{EventSubscriber, RequestContext};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;

pub(crate) struct OpenAiResponsesProjection {
    pub(crate) model: Box<str>,
    pub(crate) created_at: u64,
}

impl OpenAiResponsesProjection {
    pub(crate) fn new(model: Box<str>) -> Self {
        Self {
            model,
            created_at: 0,
        }
    }
}

impl Debug for OpenAiResponsesProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiResponsesProjection(<redacted>)")
    }
}

impl HttpProtocolProjection for OpenAiResponsesProjection {
    fn supports_streaming(&self) -> bool {
        true
    }

    fn project_complete(
        &self,
        identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let ServiceResponse::Text(response) = response else {
            return Err(internal_failure());
        };
        complete_response(identity, &self.model, &response, self.created_at)
    }

    fn project_stream(
        &self,
        identity: &HttpRequestIdentity,
        subscriber: EventSubscriber<ariadnion_api_domain::ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Result<ProtocolStreamResponse, ProtocolFailure> {
        stream::project_stream(identity, &self.model, self.created_at, subscriber, context)
    }
}

fn complete_response(
    identity: &HttpRequestIdentity,
    model: &str,
    response: &TextServiceResponse,
    created_at: u64,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    if response.version() != ServiceContractVersion::V1 {
        return Err(internal_failure());
    }
    let (status, incomplete_details) = match response.finish_reason() {
        FinishReason::Completed => ("completed", None),
        FinishReason::OutputLimitReached => (
            "incomplete",
            Some(IncompleteDetails {
                reason: "max_output_tokens",
            }),
        ),
        FinishReason::ContentFiltered | _ => return Err(internal_failure()),
    };
    let message = OutputMessage {
        id: format!("msg-{}", identity.request_id().as_str()),
        message_type: "message",
        role: "assistant",
        status,
        content: [OutputContent {
            content_type: "output_text",
            text: response.output().as_str(),
            annotations: [],
        }],
    };
    let body = ResponseBody {
        id: format!("resp-{}", identity.request_id().as_str()),
        object: "response",
        created_at,
        status,
        model,
        output: [message],
        error: None,
        incomplete_details,
        usage: None,
    };
    json_response(StatusCode::OK, &body)
}

pub(crate) fn project_failure(
    _identity: &HttpRequestIdentity,
    failure: ProtocolFailure,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let parameter = failure.public_parameter();
    let profile = failure_profile(failure);
    json_response(
        profile.status,
        &ErrorEnvelope {
            error: ErrorBody {
                message: profile.message,
                error_type: profile.error_type,
                parameter,
                code: profile.code,
            },
        },
    )
}

#[derive(Clone, Copy)]
struct ErrorProfile {
    status: StatusCode,
    message: &'static str,
    error_type: &'static str,
    code: &'static str,
}

const fn failure_profile(failure: ProtocolFailure) -> ErrorProfile {
    match failure {
        ProtocolFailure::Http(error) => http_failure_profile(error.code()),
        ProtocolFailure::Domain(error) => domain_failure_profile(error.code()),
        _ => INTERNAL_ERROR,
    }
}

const fn http_failure_profile(code: ApiHttpErrorCode) -> ErrorProfile {
    match code {
        ApiHttpErrorCode::InvalidRequest | ApiHttpErrorCode::MethodNotAllowed => INVALID_REQUEST,
        ApiHttpErrorCode::NotFound => NOT_FOUND,
        ApiHttpErrorCode::Unauthenticated => AUTHENTICATION_FAILED,
        ApiHttpErrorCode::Forbidden => PERMISSION_DENIED,
        ApiHttpErrorCode::PayloadTooLarge => REQUEST_TOO_LARGE,
        ApiHttpErrorCode::UnsupportedMediaType => UNSUPPORTED_MEDIA_TYPE,
        _ => service_http_failure_profile(code),
    }
}

const fn domain_failure_profile(code: ApiDomainErrorCode) -> ErrorProfile {
    match code {
        ApiDomainErrorCode::Cancelled => CANCELLED,
        ApiDomainErrorCode::DeadlineExceeded => DEADLINE_EXCEEDED,
        ApiDomainErrorCode::Unavailable => SERVICE_UNAVAILABLE,
        ApiDomainErrorCode::ResourceExhausted => RATE_LIMITED,
        ApiDomainErrorCode::Conflict => CONFLICT,
        ApiDomainErrorCode::InvalidArgument
        | ApiDomainErrorCode::UnsupportedVersion
        | ApiDomainErrorCode::LimitExceeded => INVALID_REQUEST,
        _ => INTERNAL_ERROR,
    }
}

const fn service_http_failure_profile(code: ApiHttpErrorCode) -> ErrorProfile {
    match code {
        ApiHttpErrorCode::ResourceExhausted => RATE_LIMITED,
        ApiHttpErrorCode::Unavailable | ApiHttpErrorCode::StreamUnavailable => SERVICE_UNAVAILABLE,
        ApiHttpErrorCode::Cancelled => CANCELLED,
        ApiHttpErrorCode::DeadlineExceeded => DEADLINE_EXCEEDED,
        ApiHttpErrorCode::Internal | _ => INTERNAL_ERROR,
    }
}

fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let encoded = serde_json::to_vec(body).map_err(|_| internal_failure())?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    ProtocolBufferedResponse::new(status, headers, Bytes::from(encoded))
}

pub(crate) const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

const fn status_499() -> StatusCode {
    match StatusCode::from_u16(499) {
        Ok(status) => status,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Serialize)]
struct ResponseBody<'a> {
    id: String,
    object: &'static str,
    created_at: u64,
    status: &'static str,
    model: &'a str,
    output: [OutputMessage<'a>; 1],
    error: Option<()>,
    incomplete_details: Option<IncompleteDetails>,
    usage: Option<UsageBody>,
}
#[derive(Serialize)]
struct OutputMessage<'a> {
    id: String,
    #[serde(rename = "type")]
    message_type: &'static str,
    role: &'static str,
    status: &'static str,
    content: [OutputContent<'a>; 1],
}
#[derive(Serialize)]
struct OutputContent<'a> {
    #[serde(rename = "type")]
    content_type: &'static str,
    text: &'a str,
    annotations: [(); 0],
}
#[derive(Serialize)]
struct IncompleteDetails {
    reason: &'static str,
}
#[derive(Serialize)]
struct UsageBody {}
#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}
#[derive(Serialize)]
struct ErrorBody {
    message: &'static str,
    #[serde(rename = "type")]
    error_type: &'static str,
    #[serde(rename = "param")]
    parameter: Option<&'static str>,
    code: &'static str,
}

const INVALID_REQUEST: ErrorProfile = ErrorProfile {
    status: StatusCode::BAD_REQUEST,
    message: "The request is invalid.",
    error_type: "invalid_request_error",
    code: "invalid_request",
};
const NOT_FOUND: ErrorProfile = ErrorProfile {
    status: StatusCode::NOT_FOUND,
    message: "The requested resource was not found.",
    error_type: "invalid_request_error",
    code: "not_found",
};
const AUTHENTICATION_FAILED: ErrorProfile = ErrorProfile {
    status: StatusCode::UNAUTHORIZED,
    message: "Authentication failed.",
    error_type: "authentication_error",
    code: "authentication_failed",
};
const PERMISSION_DENIED: ErrorProfile = ErrorProfile {
    status: StatusCode::FORBIDDEN,
    message: "Permission was denied.",
    error_type: "permission_error",
    code: "permission_denied",
};
const REQUEST_TOO_LARGE: ErrorProfile = ErrorProfile {
    status: StatusCode::PAYLOAD_TOO_LARGE,
    message: "The request exceeds a supported limit.",
    error_type: "invalid_request_error",
    code: "request_too_large",
};
const UNSUPPORTED_MEDIA_TYPE: ErrorProfile = ErrorProfile {
    status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
    message: "The request media type is unsupported.",
    error_type: "invalid_request_error",
    code: "unsupported_media_type",
};
const CONFLICT: ErrorProfile = ErrorProfile {
    status: StatusCode::CONFLICT,
    message: "The request conflicts with current state.",
    error_type: "invalid_request_error",
    code: "conflict",
};
const CANCELLED: ErrorProfile = ErrorProfile {
    status: status_499(),
    message: "The request was cancelled.",
    error_type: "server_error",
    code: "cancelled",
};
const DEADLINE_EXCEEDED: ErrorProfile = ErrorProfile {
    status: StatusCode::GATEWAY_TIMEOUT,
    message: "The request deadline was exceeded.",
    error_type: "server_error",
    code: "deadline_exceeded",
};
const RATE_LIMITED: ErrorProfile = ErrorProfile {
    status: StatusCode::TOO_MANY_REQUESTS,
    message: "The request cannot be admitted at this time.",
    error_type: "rate_limit_error",
    code: "rate_limit_exceeded",
};
const SERVICE_UNAVAILABLE: ErrorProfile = ErrorProfile {
    status: StatusCode::SERVICE_UNAVAILABLE,
    message: "The service is unavailable.",
    error_type: "server_error",
    code: "service_unavailable",
};
const INTERNAL_ERROR: ErrorProfile = ErrorProfile {
    status: StatusCode::INTERNAL_SERVER_ERROR,
    message: "The request could not be completed.",
    error_type: "server_error",
    code: "internal_error",
};

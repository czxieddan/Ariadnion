// crates/optional/ariadnion-protocol-openai/src/response.rs - OpenAI complete and error projection for Ariadnion.
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
//! Protocol-owned JSON response values without provider or internal DTO exposure.

use std::fmt::{self, Debug, Formatter};

use ariadnion_api_domain::ServiceStreamEvent;
use ariadnion_api_domain::{
    ApiDomainErrorCode, ChatServiceResponse, FinishReason, ServiceContractVersion, ServiceResponse,
};
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, HttpProtocolProjection, HttpRequestIdentity,
    ProtocolBufferedResponse, ProtocolFailure, ProtocolStreamResponse,
};
use ariadnion_core::{EventSubscriber, RequestContext};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;

const CREATED_EPOCH_SECONDS: u64 = 0;

pub(crate) struct OpenAiProjection {
    model: Box<str>,
    include_usage: bool,
}

impl OpenAiProjection {
    pub(crate) const fn new(model: Box<str>, include_usage: bool) -> Self {
        Self {
            model,
            include_usage,
        }
    }
}

impl Debug for OpenAiProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiProjection")
            .field("include_usage", &self.include_usage)
            .finish_non_exhaustive()
    }
}

impl HttpProtocolProjection for OpenAiProjection {
    fn supports_streaming(&self) -> bool {
        true
    }

    fn project_complete(
        &self,
        identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let ServiceResponse::Chat(response) = response else {
            return Err(internal_failure());
        };
        validate_response(&response)?;
        complete_response(identity, &self.model, &response)
    }

    fn project_stream(
        &self,
        identity: &HttpRequestIdentity,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        context: &RequestContext,
    ) -> Result<ProtocolStreamResponse, ProtocolFailure> {
        crate::stream::project_stream(
            identity,
            &self.model,
            self.include_usage,
            subscriber,
            context,
        )
    }
}

pub(crate) fn project_failure(
    _identity: &HttpRequestIdentity,
    failure: ProtocolFailure,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let profile = failure_profile(failure);
    let body = ErrorEnvelope {
        error: ErrorBody {
            message: profile.message,
            error_type: profile.error_type,
            parameter: None,
            code: profile.code,
        },
    };
    json_response(profile.status, &body)
}

fn complete_response(
    identity: &HttpRequestIdentity,
    model: &str,
    response: &ChatServiceResponse,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let usage = response.usage();
    let finish_reason = finish_reason(response.finish_reason())?;
    let body = CompletionBody {
        id: format!("chatcmpl-{}", identity.request_id().as_str()),
        object: "chat.completion",
        created: CREATED_EPOCH_SECONDS,
        model,
        choices: [CompletionChoice {
            index: 0,
            message: AssistantMessage {
                role: "assistant",
                content: response.output().as_str(),
            },
            finish_reason,
        }],
        usage: UsageBody {
            prompt_tokens: usage.input_tokens(),
            completion_tokens: usage.output_tokens(),
            total_tokens: usage.total_tokens(),
        },
    };
    json_response(StatusCode::OK, &body)
}

fn validate_response(response: &ChatServiceResponse) -> Result<(), ProtocolFailure> {
    if response.version() != ServiceContractVersion::V1 {
        return Err(internal_failure());
    }
    Ok(())
}

fn finish_reason(reason: FinishReason) -> Result<&'static str, ProtocolFailure> {
    match reason {
        FinishReason::Completed => Ok("stop"),
        FinishReason::OutputLimitReached => Ok("length"),
        FinishReason::ContentFiltered => Ok("content_filter"),
        _ => Err(internal_failure()),
    }
}

fn json_response<T>(
    status: StatusCode,
    body: &T,
) -> Result<ProtocolBufferedResponse, ProtocolFailure>
where
    T: Serialize,
{
    let encoded = serde_json::to_vec(body).map_err(|_| internal_failure())?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    ProtocolBufferedResponse::new(status, headers, Bytes::from(encoded))
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
        ApiHttpErrorCode::InvalidRequest
        | ApiHttpErrorCode::NotFound
        | ApiHttpErrorCode::MethodNotAllowed => INVALID_REQUEST,
        ApiHttpErrorCode::Unauthenticated => AUTHENTICATION_FAILED,
        ApiHttpErrorCode::Forbidden => PERMISSION_DENIED,
        ApiHttpErrorCode::PayloadTooLarge => REQUEST_TOO_LARGE,
        ApiHttpErrorCode::UnsupportedMediaType => UNSUPPORTED_MEDIA_TYPE,
        _ => service_http_failure_profile(code),
    }
}

const fn service_http_failure_profile(code: ApiHttpErrorCode) -> ErrorProfile {
    match code {
        ApiHttpErrorCode::Cancelled => CANCELLED,
        ApiHttpErrorCode::DeadlineExceeded => DEADLINE_EXCEEDED,
        ApiHttpErrorCode::ResourceExhausted => RATE_LIMITED,
        ApiHttpErrorCode::Unavailable | ApiHttpErrorCode::StreamUnavailable => SERVICE_UNAVAILABLE,
        ApiHttpErrorCode::Internal => INTERNAL_ERROR,
        _ => INTERNAL_ERROR,
    }
}

const fn domain_failure_profile(code: ApiDomainErrorCode) -> ErrorProfile {
    match code {
        ApiDomainErrorCode::InvalidArgument | ApiDomainErrorCode::UnsupportedVersion => {
            INVALID_REQUEST
        }
        ApiDomainErrorCode::LimitExceeded => INVALID_REQUEST,
        ApiDomainErrorCode::Conflict => CONFLICT,
        _ => service_domain_failure_profile(code),
    }
}

const fn service_domain_failure_profile(code: ApiDomainErrorCode) -> ErrorProfile {
    match code {
        ApiDomainErrorCode::Cancelled => CANCELLED,
        ApiDomainErrorCode::DeadlineExceeded => DEADLINE_EXCEEDED,
        ApiDomainErrorCode::Unavailable => SERVICE_UNAVAILABLE,
        ApiDomainErrorCode::ResourceExhausted => RATE_LIMITED,
        ApiDomainErrorCode::Internal => INTERNAL_ERROR,
        _ => INTERNAL_ERROR,
    }
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

#[derive(Serialize)]
struct CompletionBody<'a> {
    id: String,
    object: &'static str,
    created: u64,
    model: &'a str,
    choices: [CompletionChoice<'a>; 1],
    usage: UsageBody,
}

#[derive(Serialize)]
struct CompletionChoice<'a> {
    index: u8,
    message: AssistantMessage<'a>,
    finish_reason: &'static str,
}

#[derive(Serialize)]
struct AssistantMessage<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(Serialize)]
struct UsageBody {
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
}

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

#[derive(Clone, Copy)]
struct ErrorProfile {
    status: StatusCode,
    message: &'static str,
    error_type: &'static str,
    code: &'static str,
}

const INVALID_REQUEST: ErrorProfile = ErrorProfile {
    status: StatusCode::BAD_REQUEST,
    message: "The request is invalid.",
    error_type: "invalid_request_error",
    code: "invalid_request",
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

const fn status_499() -> StatusCode {
    match StatusCode::from_u16(499) {
        Ok(status) => status,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

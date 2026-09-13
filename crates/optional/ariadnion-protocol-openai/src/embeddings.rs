// crates/optional/ariadnion-protocol-openai/src/embeddings.rs - OpenAI Embeddings protocol adapter.
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
//! Strict complete-only OpenAI Embeddings projection for the frozen P4 subset.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, EmbeddingInput, EmbeddingInputs, EmbeddingServiceRequest,
    EmbeddingServiceResponse, MAX_EMBEDDING_INPUTS, ModelSelector, ResponseMode,
    ServiceContractVersion, ServiceRequest, ServiceResponse, ServiceStreamEvent,
};
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpProtocolAdapter, HttpProtocolProjection,
    HttpRequestIdentity, ProtocolBufferedResponse, ProtocolExecutionState, ProtocolFailure,
    ProtocolRequest, ProtocolRequestBody, ProtocolStreamResponse, protocol_post_route,
};
use ariadnion_core::{EventSubscriber, RequestContext};
use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;
use serde::de::{self, Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};

const REQUEST_FIELDS: &[&str] = &["model", "input", "encoding_format"];

/// Public route owned by the OpenAI Embeddings adapter.
pub const OPENAI_EMBEDDINGS_PATH: &str = "/v1/embeddings";

/// Concrete router type returned by [`openai_embeddings_router`].
pub type OpenAiEmbeddingsRouter = Router;

/// Strict decoder and projector for the P4 OpenAI Embeddings subset.
#[derive(Clone, Copy, Default)]
pub struct OpenAiEmbeddingsProtocol;

impl OpenAiEmbeddingsProtocol {
    /// Creates a stateless OpenAI Embeddings adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Debug for OpenAiEmbeddingsProtocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiEmbeddingsProtocol")
    }
}

impl HttpProtocolAdapter for OpenAiEmbeddingsProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let decoded = decode_request(body.bytes())?;
        let projection = Arc::new(OpenAiEmbeddingsProjection::new(decoded.model));
        ProtocolRequest::new(
            ServiceRequest::Embedding(decoded.request),
            ResponseMode::Complete,
            projection,
        )
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_failure(identity, failure)
    }
}

/// Mounts `POST /v1/embeddings` over shared authenticated HTTP state.
pub fn openai_embeddings_router(http: HttpApiState) -> OpenAiEmbeddingsRouter {
    let protocol: Arc<dyn HttpProtocolAdapter> = Arc::new(OpenAiEmbeddingsProtocol::new());
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_EMBEDDINGS_PATH, protocol_post_route())
        .with_state(state)
}

pub(crate) struct DecodedRequest {
    request: EmbeddingServiceRequest,
    model: Box<str>,
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<DecodedRequest, ProtocolFailure> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = RawRequest::deserialize(&mut deserializer).map_err(|_| invalid_request())?;
    deserializer.end().map_err(|_| invalid_request())?;
    raw.into_domain().map_err(ProtocolFailure::from)
}

struct RawRequest<'a> {
    model: Cow<'a, str>,
    input: RawInputs<'a>,
}

impl RawRequest<'_> {
    fn into_domain(self) -> Result<DecodedRequest, ApiDomainError> {
        let model = ModelSelector::new(self.model.as_ref())?;
        let projection_model = model.as_str().into();
        let request = EmbeddingServiceRequest::new(
            ServiceContractVersion::V1,
            model,
            self.input.into_domain()?,
            None,
        );
        Ok(DecodedRequest {
            request,
            model: projection_model,
        })
    }
}

impl<'de> Deserialize<'de> for RawRequest<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RequestVisitor)
    }
}

struct RequestVisitor;

impl<'de> Visitor<'de> for RequestVisitor {
    type Value = RawRequest<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenAI embeddings request object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = RequestValues::default();
        while let Some(field) = map.next_key::<&str>()? {
            values.read(field, &mut map)?;
        }
        values.finish()
    }
}

#[derive(Default)]
struct RequestValues<'a> {
    model: Option<Cow<'a, str>>,
    input: Option<RawInputs<'a>>,
    encoding_format_seen: bool,
}

impl<'de> RequestValues<'de> {
    fn read<A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "model" => read_once(&mut self.model, "model", map),
            "input" => read_once(&mut self.input, "input", map),
            "encoding_format" => self.read_encoding_format(map),
            _ => Err(A::Error::unknown_field(field, REQUEST_FIELDS)),
        }
    }

    fn read_encoding_format<A>(&mut self, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.encoding_format_seen {
            return Err(A::Error::duplicate_field("encoding_format"));
        }
        let value = map.next_value::<Cow<'de, str>>()?;
        if value != "float" {
            return Err(A::Error::custom("unsupported encoding format"));
        }
        self.encoding_format_seen = true;
        Ok(())
    }

    fn finish<E>(self) -> Result<RawRequest<'de>, E>
    where
        E: de::Error,
    {
        if !self.encoding_format_seen {
            return Err(E::missing_field("encoding_format"));
        }
        Ok(RawRequest {
            model: self.model.ok_or_else(|| E::missing_field("model"))?,
            input: self.input.ok_or_else(|| E::missing_field("input"))?,
        })
    }
}

enum RawInputs<'a> {
    One(Cow<'a, str>),
    Many(Vec<Cow<'a, str>>),
}

impl RawInputs<'_> {
    fn into_domain(self) -> Result<EmbeddingInputs, ApiDomainError> {
        let values = match self {
            Self::One(value) => vec![EmbeddingInput::new(value.as_ref())?],
            Self::Many(values) => values
                .iter()
                .map(|value| EmbeddingInput::new(value.as_ref()))
                .collect::<Result<Vec<_>, _>>()?,
        };
        EmbeddingInputs::new(values)
    }
}

impl<'de> Deserialize<'de> for RawInputs<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(InputsVisitor)
    }
}

struct InputsVisitor;

impl<'de> Visitor<'de> for InputsVisitor {
    type Value = RawInputs<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("one embedding input string or an array of input strings")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(RawInputs::One(Cow::Borrowed(value)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(RawInputs::One(Cow::Owned(value.to_owned())))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(
            sequence
                .size_hint()
                .map_or(0, |size| size.min(MAX_EMBEDDING_INPUTS)),
        );
        while let Some(value) = sequence.next_element::<Cow<'de, str>>()? {
            if values.len() == MAX_EMBEDDING_INPUTS {
                return Err(A::Error::custom("too many embedding inputs"));
            }
            values.push(value);
        }
        Ok(RawInputs::Many(values))
    }
}

fn read_once<'de, A, T>(
    slot: &mut Option<T>,
    field: &'static str,
    map: &mut A,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
    T: Deserialize<'de>,
{
    if slot.is_some() {
        return Err(A::Error::duplicate_field(field));
    }
    *slot = Some(map.next_value()?);
    Ok(())
}

struct OpenAiEmbeddingsProjection {
    model: Box<str>,
}

impl OpenAiEmbeddingsProjection {
    const fn new(model: Box<str>) -> Self {
        Self { model }
    }
}

impl Debug for OpenAiEmbeddingsProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiEmbeddingsProjection")
    }
}

impl HttpProtocolProjection for OpenAiEmbeddingsProjection {
    fn supports_streaming(&self) -> bool {
        false
    }

    fn project_complete(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let ServiceResponse::Embedding(response) = response else {
            return Err(internal_failure());
        };
        project_complete_response(&self.model, response)
    }

    fn project_stream(
        &self,
        _identity: &HttpRequestIdentity,
        _subscriber: EventSubscriber<ServiceStreamEvent>,
        _context: &RequestContext,
    ) -> Result<ProtocolStreamResponse, ProtocolFailure> {
        Err(internal_failure())
    }
}

fn project_complete_response(
    model: &str,
    response: EmbeddingServiceResponse,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    if response.version() != ServiceContractVersion::V1 {
        return Err(internal_failure());
    }
    let vectors = response.vectors().as_slice();
    let data = vectors
        .iter()
        .enumerate()
        .map(|(index, vector)| EmbeddingData {
            object: "embedding",
            embedding: vector.as_slice(),
            index,
        })
        .collect::<Vec<_>>();
    let usage = response.usage();
    let body = EmbeddingsResponse {
        object: "list",
        data,
        model,
        usage: Usage {
            prompt_tokens: usage.input_tokens(),
            total_tokens: usage.total_tokens(),
        },
    };
    json_response(StatusCode::OK, &body)
}

#[derive(Serialize)]
struct EmbeddingsResponse<'a> {
    object: &'static str,
    data: Vec<EmbeddingData<'a>>,
    model: &'a str,
    usage: Usage,
}

#[derive(Serialize)]
struct EmbeddingData<'a> {
    object: &'static str,
    embedding: &'a [f32],
    index: usize,
}

#[derive(Serialize)]
struct Usage {
    prompt_tokens: u64,
    total_tokens: u64,
}

fn project_failure(
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

fn json_response<T>(
    status: StatusCode,
    body: &T,
) -> Result<ProtocolBufferedResponse, ProtocolFailure>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|_| internal_failure())?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    ProtocolBufferedResponse::new(status, headers, Bytes::from(body))
}

const fn failure_profile(failure: ProtocolFailure) -> ErrorProfile {
    match failure {
        ProtocolFailure::Domain(error) => domain_failure_profile(error.code()),
        ProtocolFailure::Http(error) => http_failure_profile(error.code()),
        _ => INTERNAL_ERROR,
    }
}

const fn domain_failure_profile(code: ApiDomainErrorCode) -> ErrorProfile {
    match code {
        ApiDomainErrorCode::InvalidArgument
        | ApiDomainErrorCode::UnsupportedVersion
        | ApiDomainErrorCode::LimitExceeded => INVALID_REQUEST,
        ApiDomainErrorCode::Conflict => CONFLICT,
        ApiDomainErrorCode::Cancelled => CANCELLED,
        ApiDomainErrorCode::DeadlineExceeded => DEADLINE_EXCEEDED,
        ApiDomainErrorCode::Unavailable => SERVICE_UNAVAILABLE,
        ApiDomainErrorCode::ResourceExhausted => RATE_LIMITED,
        ApiDomainErrorCode::Internal | _ => INTERNAL_ERROR,
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
        _ => http_runtime_failure_profile(code),
    }
}

const fn http_runtime_failure_profile(code: ApiHttpErrorCode) -> ErrorProfile {
    match code {
        ApiHttpErrorCode::Cancelled => CANCELLED,
        ApiHttpErrorCode::DeadlineExceeded => DEADLINE_EXCEEDED,
        ApiHttpErrorCode::ResourceExhausted => RATE_LIMITED,
        ApiHttpErrorCode::Unavailable | ApiHttpErrorCode::StreamUnavailable => SERVICE_UNAVAILABLE,
        _ => INTERNAL_ERROR,
    }
}

const fn invalid_request() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::InvalidRequest))
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
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
    message: "The request deadline elapsed.",
    error_type: "server_error",
    code: "deadline_exceeded",
};
const RATE_LIMITED: ErrorProfile = ErrorProfile {
    status: StatusCode::TOO_MANY_REQUESTS,
    message: "A request resource limit was reached.",
    error_type: "rate_limit_error",
    code: "rate_limit_exceeded",
};
const SERVICE_UNAVAILABLE: ErrorProfile = ErrorProfile {
    status: StatusCode::SERVICE_UNAVAILABLE,
    message: "The requested service is unavailable.",
    error_type: "server_error",
    code: "service_unavailable",
};
const INTERNAL_ERROR: ErrorProfile = ErrorProfile {
    status: StatusCode::INTERNAL_SERVER_ERROR,
    message: "An internal error occurred.",
    error_type: "server_error",
    code: "internal_error",
};

const fn status_499() -> StatusCode {
    match StatusCode::from_u16(499) {
        Ok(status) => status,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

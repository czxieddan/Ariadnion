// crates/optional/ariadnion-protocol-openai/src/speech.rs - OpenAI Speech protocol adapter for Ariadnion.
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
//! Strict OpenAI raw-WAV Speech projection for the frozen P4 subset.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, AudioMediaType, AudioOutputSpecification,
    AudioServiceRequest, AudioServiceResponse, AudioText, AudioVoiceSelector, IdempotencyKey,
    ModelSelector, ResponseMode, ServiceContractVersion, ServiceRequest, ServiceResponse,
    ServiceStreamEvent,
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
use serde::de::{self, Deserialize, Deserializer, Error as _, MapAccess, Visitor};

const REQUEST_FIELDS: &[&str] = &[
    "model",
    "input",
    "voice",
    "response_format",
    "stream_format",
];
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const MAX_SPEECH_INPUT_SCALARS: usize = 4_096;
const AUDIO_COPY_CHUNK_BYTES: usize = 65_536;

/// Public route owned by the OpenAI Speech adapter.
pub const OPENAI_SPEECH_PATH: &str = "/v1/audio/speech";

/// Concrete router type returned by [`openai_speech_router`].
pub type OpenAiSpeechRouter = Router;

/// Strict decoder and projector for the frozen OpenAI raw-WAV Speech subset.
#[derive(Clone, Copy)]
pub struct OpenAiSpeechProtocol {
    output: AudioOutputSpecification,
}

impl OpenAiSpeechProtocol {
    /// Creates an OpenAI Speech adapter with one immutable output profile.
    ///
    /// The public frozen request grammar does not expose sample-rate or channel
    /// selection. Composition therefore supplies the checked PCM layout rather
    /// than the adapter inventing a hidden request default.
    #[must_use]
    pub const fn new(output: AudioOutputSpecification) -> Self {
        Self { output }
    }
}

impl Debug for OpenAiSpeechProtocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiSpeechProtocol")
    }
}

impl HttpProtocolAdapter for OpenAiSpeechProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let idempotency = parse_idempotency(body.headers())?;
        let request = decode_request(body.bytes(), idempotency, self.output)?;
        ProtocolRequest::new(
            ServiceRequest::Audio(request),
            ResponseMode::Complete,
            Arc::new(OpenAiSpeechProjection {
                output: self.output,
            }),
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

/// Mounts `POST /v1/audio/speech` over shared authenticated HTTP state.
///
/// `output` is an immutable composition capability for the physical WAV layout;
/// it does not add a public request member or reveal provider configuration.
pub fn openai_speech_router(
    http: HttpApiState,
    output: AudioOutputSpecification,
) -> OpenAiSpeechRouter {
    let protocol: Arc<dyn HttpProtocolAdapter> = Arc::new(OpenAiSpeechProtocol::new(output));
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_SPEECH_PATH, protocol_post_route())
        .with_state(state)
}

fn decode_request(
    bytes: &[u8],
    idempotency: Option<IdempotencyKey>,
    output: AudioOutputSpecification,
) -> Result<AudioServiceRequest, ProtocolFailure> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = RawRequest::deserialize(&mut deserializer).map_err(|_| invalid_request())?;
    deserializer.end().map_err(|_| invalid_request())?;
    raw.into_domain(idempotency, output)
        .map_err(ProtocolFailure::from)
}

struct RawRequest<'a> {
    model: Cow<'a, str>,
    input: Cow<'a, str>,
    voice: Cow<'a, str>,
}

impl RawRequest<'_> {
    fn into_domain(
        self,
        idempotency: Option<IdempotencyKey>,
        output: AudioOutputSpecification,
    ) -> Result<AudioServiceRequest, ApiDomainError> {
        validate_input_scalars(&self.input)?;
        Ok(AudioServiceRequest::new(
            ServiceContractVersion::V1,
            ModelSelector::new(&self.model)?,
            AudioText::new(&self.input)?,
            AudioVoiceSelector::new(&self.voice)?,
            output,
            idempotency,
        ))
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
        formatter.write_str("an OpenAI raw-WAV speech request object")
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
    input: Option<Cow<'a, str>>,
    voice: Option<Cow<'a, str>>,
    response_format: bool,
    stream_format: bool,
}

impl<'de> RequestValues<'de> {
    fn read<A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "model" => read_once(&mut self.model, "model", map),
            "input" => read_once(&mut self.input, "input", map),
            "voice" => read_once(&mut self.voice, "voice", map),
            "response_format" => {
                read_required_literal(&mut self.response_format, "response_format", "wav", map)
            }
            "stream_format" => {
                read_required_literal(&mut self.stream_format, "stream_format", "audio", map)
            }
            _ => Err(A::Error::unknown_field(field, REQUEST_FIELDS)),
        }
    }

    fn finish<E>(self) -> Result<RawRequest<'de>, E>
    where
        E: de::Error,
    {
        if !self.response_format {
            return Err(E::missing_field("response_format"));
        }
        if !self.stream_format {
            return Err(E::missing_field("stream_format"));
        }
        Ok(RawRequest {
            model: self.model.ok_or_else(|| E::missing_field("model"))?,
            input: self.input.ok_or_else(|| E::missing_field("input"))?,
            voice: self.voice.ok_or_else(|| E::missing_field("voice"))?,
        })
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

fn read_required_literal<'de, A>(
    seen: &mut bool,
    field: &'static str,
    expected: &'static str,
    map: &mut A,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    if *seen {
        return Err(A::Error::duplicate_field(field));
    }
    let value = map.next_value::<Cow<'de, str>>()?;
    if value != expected {
        return Err(A::Error::custom("unsupported speech option"));
    }
    *seen = true;
    Ok(())
}

fn validate_input_scalars(value: &str) -> Result<(), ApiDomainError> {
    if value.chars().count() > MAX_SPEECH_INPUT_SCALARS {
        return Err(ApiDomainError::new(ApiDomainErrorCode::LimitExceeded));
    }
    Ok(())
}

fn parse_idempotency(headers: &HeaderMap) -> Result<Option<IdempotencyKey>, ProtocolFailure> {
    let mut values = headers.get_all(IDEMPOTENCY_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(invalid_request());
    }
    let value = value.to_str().map_err(|_| invalid_request())?;
    IdempotencyKey::new(value)
        .map(Some)
        .map_err(ProtocolFailure::from)
}

struct OpenAiSpeechProjection {
    output: AudioOutputSpecification,
}

impl Debug for OpenAiSpeechProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiSpeechProjection")
    }
}

impl HttpProtocolProjection for OpenAiSpeechProjection {
    fn supports_streaming(&self) -> bool {
        false
    }

    fn project_complete(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_audio(response, self.output, None)
    }

    fn project_complete_cancellable(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_audio(response, self.output, Some(context))
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

fn project_audio(
    response: ServiceResponse,
    output: AudioOutputSpecification,
    context: Option<&RequestContext>,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let ServiceResponse::Audio(response) = response else {
        return Err(internal_failure());
    };
    validate_audio_response(&response, output)?;
    let body = copy_audio(response.audio().as_bytes(), context)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(AudioMediaType::WavPcm16.as_str()),
    );
    ProtocolBufferedResponse::new(StatusCode::OK, headers, body)
}

fn validate_audio_response(
    response: &AudioServiceResponse,
    output: AudioOutputSpecification,
) -> Result<(), ProtocolFailure> {
    if response.version() != ServiceContractVersion::V1 {
        return Err(internal_failure());
    }
    let audio = response.audio();
    if AudioOutputSpecification::new(
        audio.media_type(),
        audio.sample_rate(),
        audio.channel_count(),
    ) != output
    {
        return Err(internal_failure());
    }
    Ok(())
}

fn copy_audio(source: &[u8], context: Option<&RequestContext>) -> Result<Bytes, ProtocolFailure> {
    let mut copied = Vec::with_capacity(source.len());
    for chunk in source.chunks(AUDIO_COPY_CHUNK_BYTES) {
        check_context(context)?;
        copied.extend_from_slice(chunk);
    }
    check_context(context)?;
    Ok(Bytes::from(copied))
}

fn check_context(context: Option<&RequestContext>) -> Result<(), ProtocolFailure> {
    context
        .map(RequestContext::check_active)
        .transpose()
        .map_err(ApiDomainError::from)?;
    Ok(())
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

fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
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
        _ => service_http_failure_profile(code),
    }
}

const fn service_http_failure_profile(code: ApiHttpErrorCode) -> ErrorProfile {
    match code {
        ApiHttpErrorCode::Cancelled => CANCELLED,
        ApiHttpErrorCode::DeadlineExceeded => DEADLINE_EXCEEDED,
        ApiHttpErrorCode::ResourceExhausted => RATE_LIMITED,
        ApiHttpErrorCode::Unavailable | ApiHttpErrorCode::StreamUnavailable => SERVICE_UNAVAILABLE,
        ApiHttpErrorCode::Internal | _ => INTERNAL_ERROR,
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

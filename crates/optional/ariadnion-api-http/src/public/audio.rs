// crates/optional/ariadnion-api-http/src/public/audio.rs - Native audio HTTP projection for Ariadnion.
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
//! Strict complete-only audio synthesis ingress and bounded Base64 projection.

use std::sync::Arc;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, AudioChannelCount, AudioMediaType,
    AudioOutputSpecification, AudioSampleRate, AudioServiceRequest, AudioServiceResponse,
    AudioText, AudioVoiceSelector, GeneratedAudio, IdempotencyKey, ModelSelector, ResponseMode,
    ServiceContractVersion, ServiceRequest, ServiceResponse, ServiceStreamEvent,
};
use ariadnion_core::{EventSubscriber, RequestContext};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::base64_encoding::{encode_bounded, encode_bounded_cancellable};
use super::json::{serialize_bounded, serialize_bounded_cancellable};
use super::protocol::{
    HttpProtocolAdapter, HttpProtocolProjection, ProtocolBufferedResponse, ProtocolFailure,
    ProtocolRequest, ProtocolRequestBody, ProtocolStreamResponse,
};
use super::{
    ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpRequestIdentity, execution,
    parse_idempotency, project_native_failure,
};

pub(super) async fn handle_audio(
    State(state): State<HttpApiState>,
    request: Request<Body>,
) -> Response {
    execution::handle_request(&state, &NativeAudioProtocol, request).await
}

struct NativeAudioProtocol;

impl HttpProtocolAdapter for NativeAudioProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let dto: AudioRequestDto = serde_json::from_slice(body.bytes())
            .map_err(|_| ApiHttpError::new(ApiHttpErrorCode::InvalidRequest))?;
        let idempotency = parse_idempotency(body.headers())?;
        dto.into_protocol(idempotency)
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_native_failure(identity, failure)
    }
}

struct NativeAudioProjection;

impl HttpProtocolProjection for NativeAudioProjection {
    fn supports_streaming(&self) -> bool {
        false
    }

    fn project_complete(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_matching_response(response, None)
    }

    fn project_complete_cancellable(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        check_context(Some(context))?;
        let projected = project_matching_response(response, Some(context));
        check_context(Some(context))?;
        projected
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AudioRequestDto {
    version: u16,
    model: String,
    input: String,
    voice: String,
    media_type: AudioMediaTypeDto,
    sample_rate_hz: u32,
    channels: u16,
}

impl AudioRequestDto {
    fn into_protocol(
        self,
        idempotency: Option<IdempotencyKey>,
    ) -> Result<ProtocolRequest, ProtocolFailure> {
        let output = AudioOutputSpecification::new(
            self.media_type.into_domain(),
            parse_sample_rate(self.sample_rate_hz)?,
            parse_channel_count(self.channels)?,
        );
        let request = AudioServiceRequest::new(
            ServiceContractVersion::parse(self.version)?,
            ModelSelector::new(&self.model)?,
            AudioText::new(&self.input)?,
            AudioVoiceSelector::new(&self.voice)?,
            output,
            idempotency,
        );
        ProtocolRequest::new(
            ServiceRequest::Audio(request),
            ResponseMode::Complete,
            Arc::new(NativeAudioProjection),
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AudioMediaTypeDto {
    WavPcm16,
}

impl AudioMediaTypeDto {
    const fn into_domain(self) -> AudioMediaType {
        match self {
            Self::WavPcm16 => AudioMediaType::WavPcm16,
        }
    }
}

#[derive(Serialize)]
struct AudioResponseDto {
    version: u16,
    audio: AudioResponseItemDto,
}

#[derive(Serialize)]
struct AudioResponseItemDto {
    media_type: &'static str,
    sample_rate_hz: u32,
    channels: u16,
    duration_millis: u64,
    base64: String,
}

fn project_matching_response(
    response: ServiceResponse,
    context: Option<&RequestContext>,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    match response {
        ServiceResponse::Audio(response) => project_audio_response(response, context),
        _ => Err(internal_failure()),
    }
}

fn project_audio_response(
    response: AudioServiceResponse,
    context: Option<&RequestContext>,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let version = project_version(response.version())?;
    let audio = encode_audio(response.audio(), context)?;
    let body = serialize_audio_response(&AudioResponseDto { version, audio }, context)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    ProtocolBufferedResponse::new(StatusCode::OK, headers, body)
}

fn encode_audio(
    audio: &GeneratedAudio,
    context: Option<&RequestContext>,
) -> Result<AudioResponseItemDto, ProtocolFailure> {
    let base64 = match context {
        Some(context) => encode_bounded_cancellable(audio.as_bytes(), context)?,
        None => encode_bounded(audio.as_bytes())?,
    };
    Ok(AudioResponseItemDto {
        media_type: audio.media_type().as_str(),
        sample_rate_hz: audio.sample_rate().as_hz(),
        channels: audio.channel_count().as_u16(),
        duration_millis: audio.duration_millis(),
        base64,
    })
}

fn serialize_audio_response(
    response: &AudioResponseDto,
    context: Option<&RequestContext>,
) -> Result<axum::body::Bytes, ProtocolFailure> {
    match context {
        Some(context) => serialize_bounded_cancellable(response, context),
        None => serialize_bounded(response),
    }
}

const fn parse_sample_rate(value: u32) -> Result<AudioSampleRate, ApiDomainError> {
    match value {
        8_000 => Ok(AudioSampleRate::Hz8000),
        16_000 => Ok(AudioSampleRate::Hz16000),
        24_000 => Ok(AudioSampleRate::Hz24000),
        48_000 => Ok(AudioSampleRate::Hz48000),
        _ => Err(invalid_argument()),
    }
}

const fn parse_channel_count(value: u16) -> Result<AudioChannelCount, ApiDomainError> {
    match value {
        1 => Ok(AudioChannelCount::Mono),
        2 => Ok(AudioChannelCount::Stereo),
        _ => Err(invalid_argument()),
    }
}

fn check_context(context: Option<&RequestContext>) -> Result<(), ProtocolFailure> {
    context
        .map(RequestContext::check_active)
        .transpose()
        .map_err(ApiDomainError::from)?;
    Ok(())
}

const fn project_version(version: ServiceContractVersion) -> Result<u16, ProtocolFailure> {
    match version {
        ServiceContractVersion::V1 => Ok(1),
        _ => Err(internal_failure()),
    }
}

const fn invalid_argument() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::InvalidArgument)
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

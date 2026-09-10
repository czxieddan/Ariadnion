// crates/optional/ariadnion-protocol-openai/src/images.rs - OpenAI Images protocol adapter for Ariadnion.
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
//! Strict complete-only OpenAI Images generation projection.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_api_domain::{
    ApiDomainError, GeneratedImage, GeneratedImages, IdempotencyKey, ImageCount, ImageDimensions,
    ImageMediaType, ImageOutputSpecification, ImagePrompt, ImageServiceRequest,
    ImageServiceResponse, ModelSelector, ResponseMode, ServiceContractVersion, ServiceRequest,
    ServiceResponse, ServiceStreamEvent,
};
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpProtocolAdapter, HttpProtocolProjection,
    HttpRequestIdentity, MAX_PUBLIC_BODY_BYTES, ProtocolBufferedResponse, ProtocolExecutionState,
    ProtocolFailure, ProtocolRequest, ProtocolRequestBody, ProtocolStreamResponse,
    protocol_post_route,
};
use ariadnion_core::{EventSubscriber, RequestContext};
use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::de::{self, Deserialize, Deserializer, Error as _, MapAccess, Visitor};

use crate::{OpenAiTimestampPort, SystemOpenAiTimestamp};

const REQUEST_FIELDS: &[&str] = &["model", "prompt", "n", "size", "output_format"];
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const BASE64_INPUT_CHUNK_BYTES: usize = 12 * 1024;

/// Public route owned by the OpenAI Images generation adapter.
pub const OPENAI_IMAGES_GENERATIONS_PATH: &str = "/v1/images/generations";

/// Concrete router type returned by [`openai_images_router`].
pub type OpenAiImagesRouter = Router;

/// Strict decoder and projector for the frozen OpenAI Images generation subset.
#[derive(Clone)]
pub struct OpenAiImagesProtocol {
    clock: Arc<dyn OpenAiTimestampPort>,
}

impl OpenAiImagesProtocol {
    /// Creates an Images adapter backed by the system UTC clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clock: Arc::new(SystemOpenAiTimestamp),
        }
    }

    /// Creates an Images adapter with an authoritative timestamp port.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn OpenAiTimestampPort>) -> Self {
        Self { clock }
    }
}

impl Default for OpenAiImagesProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for OpenAiImagesProtocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiImagesProtocol")
    }
}

impl HttpProtocolAdapter for OpenAiImagesProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let idempotency = parse_idempotency(body.headers())?;
        let decoded = decode_request(body.bytes(), idempotency)?;
        let created = self.clock.unix_seconds()?;
        let projection = Arc::new(OpenAiImagesProjection::new(decoded.output, created));
        ProtocolRequest::new(
            ServiceRequest::Image(decoded.request),
            ResponseMode::Complete,
            projection,
        )
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        crate::response::project_failure(identity, failure)
    }
}

/// Mounts `POST /v1/images/generations` over shared authenticated HTTP state.
pub fn openai_images_router(http: HttpApiState) -> OpenAiImagesRouter {
    openai_images_router_with_clock(http, Arc::new(SystemOpenAiTimestamp))
}

/// Mounts the Images generation route with an explicit timestamp port.
pub fn openai_images_router_with_clock(
    http: HttpApiState,
    clock: Arc<dyn OpenAiTimestampPort>,
) -> OpenAiImagesRouter {
    let protocol: Arc<dyn HttpProtocolAdapter> = Arc::new(OpenAiImagesProtocol::with_clock(clock));
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_IMAGES_GENERATIONS_PATH, protocol_post_route())
        .with_state(state)
}

struct DecodedRequest {
    request: ImageServiceRequest,
    output: ImageOutputSpecification,
}

fn decode_request(
    bytes: &[u8],
    idempotency: Option<IdempotencyKey>,
) -> Result<DecodedRequest, ProtocolFailure> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = RawRequest::deserialize(&mut deserializer).map_err(|_| invalid_request())?;
    deserializer.end().map_err(|_| invalid_request())?;
    raw.into_domain(idempotency)
}

struct RawRequest<'a> {
    model: Cow<'a, str>,
    prompt: Cow<'a, str>,
    count: usize,
    size: Cow<'a, str>,
    output_format: Cow<'a, str>,
}

impl RawRequest<'_> {
    fn into_domain(
        self,
        idempotency: Option<IdempotencyKey>,
    ) -> Result<DecodedRequest, ProtocolFailure> {
        let model = parse_model(&self.model)?;
        let prompt = field_value(ImagePrompt::new(&self.prompt), "prompt")?;
        let count = field_value(ImageCount::new(self.count), "n")?;
        let dimensions = parse_dimensions(&self.size)?;
        let media_type = parse_output_format(&self.output_format)?;
        let output = ImageOutputSpecification::new(count, dimensions, media_type);
        let request = ImageServiceRequest::new(
            ServiceContractVersion::V1,
            model,
            prompt,
            output,
            idempotency,
        );
        Ok(DecodedRequest { request, output })
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
        formatter.write_str("an OpenAI image generation request object")
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
    prompt: Option<Cow<'a, str>>,
    count: Option<usize>,
    size: Option<Cow<'a, str>>,
    output_format: Option<Cow<'a, str>>,
}

impl<'de> RequestValues<'de> {
    fn read<A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "model" => read_once(&mut self.model, "model", map),
            "prompt" => read_once(&mut self.prompt, "prompt", map),
            "n" => read_once(&mut self.count, "n", map),
            "size" => read_once(&mut self.size, "size", map),
            "output_format" => read_once(&mut self.output_format, "output_format", map),
            _ => Err(A::Error::unknown_field(field, REQUEST_FIELDS)),
        }
    }

    fn finish<E>(self) -> Result<RawRequest<'de>, E>
    where
        E: de::Error,
    {
        Ok(RawRequest {
            model: self.model.ok_or_else(|| E::missing_field("model"))?,
            prompt: self.prompt.ok_or_else(|| E::missing_field("prompt"))?,
            count: self.count.ok_or_else(|| E::missing_field("n"))?,
            size: self.size.ok_or_else(|| E::missing_field("size"))?,
            output_format: self
                .output_format
                .ok_or_else(|| E::missing_field("output_format"))?,
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

fn field_value<T>(
    value: Result<T, ApiDomainError>,
    parameter: &'static str,
) -> Result<T, ProtocolFailure> {
    value.map_err(|_| ProtocolFailure::invalid_parameter(Some(parameter)))
}

fn parse_model(value: &str) -> Result<ModelSelector, ProtocolFailure> {
    if matches!(value, "dall-e-2" | "dall-e-3") {
        return Err(ProtocolFailure::unsupported_parameter(Some("model")));
    }
    field_value(ModelSelector::new(value), "model")
}

fn parse_dimensions(value: &str) -> Result<ImageDimensions, ProtocolFailure> {
    let (width, height) = match value {
        "1024x1024" => (1024, 1024),
        "1536x1024" => (1536, 1024),
        "1024x1536" => (1024, 1536),
        _ => return Err(ProtocolFailure::invalid_parameter(Some("size"))),
    };
    field_value(ImageDimensions::new(width, height), "size")
}

fn parse_output_format(value: &str) -> Result<ImageMediaType, ProtocolFailure> {
    match value {
        "png" => Ok(ImageMediaType::Png),
        "jpeg" => Ok(ImageMediaType::Jpeg),
        "webp" => Ok(ImageMediaType::WebP),
        _ => Err(ProtocolFailure::unsupported_parameter(Some(
            "output_format",
        ))),
    }
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

struct OpenAiImagesProjection {
    output: ImageOutputSpecification,
    created: u64,
}

impl OpenAiImagesProjection {
    const fn new(output: ImageOutputSpecification, created: u64) -> Self {
        Self { output, created }
    }
}

impl Debug for OpenAiImagesProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiImagesProjection")
    }
}

impl HttpProtocolProjection for OpenAiImagesProjection {
    fn supports_streaming(&self) -> bool {
        false
    }

    fn project_complete(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_images(response, self.output, self.created, None)
    }

    fn project_complete_cancellable(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        project_images(response, self.output, self.created, Some(context))
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

fn project_images(
    response: ServiceResponse,
    expected: ImageOutputSpecification,
    created: u64,
    context: Option<&RequestContext>,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let ServiceResponse::Image(response) = response else {
        return Err(internal_failure());
    };
    validate_response(&response, expected)?;
    let body = encode_response(response.images(), created, context)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    ProtocolBufferedResponse::new(StatusCode::OK, headers, body)
}

fn validate_response(
    response: &ImageServiceResponse,
    expected: ImageOutputSpecification,
) -> Result<(), ProtocolFailure> {
    if response.version() != ServiceContractVersion::V1 {
        return Err(internal_failure());
    }
    let images = response.images().as_slice();
    if images.len() != expected.count().get()
        || !images.iter().all(|image| image_matches(image, expected))
    {
        return Err(internal_failure());
    }
    Ok(())
}

fn image_matches(image: &GeneratedImage, expected: ImageOutputSpecification) -> bool {
    image.media_type() == expected.media_type() && image.dimensions() == expected.dimensions()
}

fn encode_response(
    images: &GeneratedImages,
    created: u64,
    context: Option<&RequestContext>,
) -> Result<Bytes, ProtocolFailure> {
    let mut body = Vec::new();
    append_bytes(&mut body, br#"{"created":"#)?;
    append_decimal(&mut body, created)?;
    append_bytes(&mut body, br#", "data":["#)?;
    append_image_data(&mut body, images.as_slice(), context)?;
    append_bytes(&mut body, br#"]}"#)?;
    check_context(context)?;
    Ok(Bytes::from(body))
}

fn append_decimal(body: &mut Vec<u8>, value: u64) -> Result<(), ProtocolFailure> {
    append_bytes(body, value.to_string().as_bytes())
}

fn append_image_data(
    body: &mut Vec<u8>,
    images: &[GeneratedImage],
    context: Option<&RequestContext>,
) -> Result<(), ProtocolFailure> {
    for (index, image) in images.iter().enumerate() {
        check_context(context)?;
        if index != 0 {
            append_bytes(body, b",")?;
        }
        append_bytes(body, b"{\"b64_json\":\"")?;
        append_base64(body, image.as_bytes(), context)?;
        append_bytes(body, b"\"}")?;
        check_context(context)?;
    }
    Ok(())
}

fn append_base64(
    body: &mut Vec<u8>,
    input: &[u8],
    context: Option<&RequestContext>,
) -> Result<(), ProtocolFailure> {
    let total = encoded_length(input.len())?;
    let start = reserve_append(body, total)?;
    let end = start.checked_add(total).ok_or_else(internal_failure)?;
    body.resize(end, 0);
    let mut offset = start;
    for chunk in input.chunks(BASE64_INPUT_CHUNK_BYTES) {
        check_context(context)?;
        offset = encode_chunk(chunk, body, offset)?;
        check_context(context)?;
    }
    if offset != end {
        return Err(internal_failure());
    }
    Ok(())
}

fn encode_chunk(input: &[u8], output: &mut [u8], offset: usize) -> Result<usize, ProtocolFailure> {
    let length = encoded_length(input.len())?;
    let end = offset.checked_add(length).ok_or_else(internal_failure)?;
    let target = output.get_mut(offset..end).ok_or_else(internal_failure)?;
    let written = STANDARD
        .encode_slice(input, target)
        .map_err(|_| internal_failure())?;
    if written != length {
        return Err(internal_failure());
    }
    Ok(end)
}

fn append_bytes(body: &mut Vec<u8>, input: &[u8]) -> Result<(), ProtocolFailure> {
    reserve_append(body, input.len())?;
    body.extend_from_slice(input);
    Ok(())
}

fn reserve_append(body: &mut Vec<u8>, additional: usize) -> Result<usize, ProtocolFailure> {
    let start = body.len();
    let end = start.checked_add(additional).ok_or_else(internal_failure)?;
    if end > MAX_PUBLIC_BODY_BYTES {
        return Err(internal_failure());
    }
    body.try_reserve_exact(additional)
        .map_err(|_| internal_failure())?;
    Ok(start)
}

fn encoded_length(input: usize) -> Result<usize, ProtocolFailure> {
    base64::encoded_len(input, true).ok_or_else(internal_failure)
}

fn check_context(context: Option<&RequestContext>) -> Result<(), ProtocolFailure> {
    context
        .map(RequestContext::check_active)
        .transpose()
        .map_err(ApiDomainError::from)?;
    Ok(())
}

const fn invalid_request() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::InvalidRequest))
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

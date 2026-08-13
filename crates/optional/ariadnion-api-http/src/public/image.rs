// crates/optional/ariadnion-api-http/src/public/image.rs - Native image HTTP projection for Ariadnion.
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
//! Strict complete-only image ingress and cancellable bounded Base64 projection.

use std::sync::Arc;

use ariadnion_api_domain::{
    ApiDomainError, GeneratedImage, GeneratedImages, IdempotencyKey, ImageCount, ImageDimensions,
    ImageMediaType, ImageOutputSpecification, ImagePrompt, ImageServiceRequest,
    ImageServiceResponse, ModelSelector, ResponseMode, ServiceContractVersion, ServiceRequest,
    ServiceResponse, ServiceStreamEvent,
};
use ariadnion_core::{EventSubscriber, RequestContext};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::json::{serialize_bounded, serialize_bounded_cancellable};
use super::protocol::{
    HttpProtocolAdapter, HttpProtocolProjection, ProtocolBufferedResponse, ProtocolFailure,
    ProtocolRequest, ProtocolRequestBody, ProtocolStreamResponse,
};
use super::{
    ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpRequestIdentity, MAX_PUBLIC_BODY_BYTES,
    execution, parse_idempotency, project_native_failure,
};

const BASE64_INPUT_CHUNK_BYTES: usize = 12 * 1024;

pub(super) async fn handle_images(
    State(state): State<HttpApiState>,
    request: Request<Body>,
) -> Response {
    execution::handle_request(&state, &NativeImageProtocol, request).await
}

struct NativeImageProtocol;

impl HttpProtocolAdapter for NativeImageProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let dto: ImageRequestDto = serde_json::from_slice(body.bytes())
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

struct NativeImageProjection;

impl HttpProtocolProjection for NativeImageProjection {
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
struct ImageRequestDto {
    version: u16,
    model: String,
    prompt: String,
    count: usize,
    width: usize,
    height: usize,
    media_type: ImageMediaTypeDto,
}

impl ImageRequestDto {
    fn into_protocol(
        self,
        idempotency: Option<IdempotencyKey>,
    ) -> Result<ProtocolRequest, ProtocolFailure> {
        let output = ImageOutputSpecification::new(
            ImageCount::new(self.count)?,
            ImageDimensions::new(self.width, self.height)?,
            self.media_type.into_domain(),
        );
        let request = ImageServiceRequest::new(
            ServiceContractVersion::parse(self.version)?,
            ModelSelector::new(&self.model)?,
            ImagePrompt::new(&self.prompt)?,
            output,
            idempotency,
        );
        ProtocolRequest::new(
            ServiceRequest::Image(request),
            ResponseMode::Complete,
            Arc::new(NativeImageProjection),
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ImageMediaTypeDto {
    Png,
    Jpeg,
    Webp,
}

impl ImageMediaTypeDto {
    const fn into_domain(self) -> ImageMediaType {
        match self {
            Self::Png => ImageMediaType::Png,
            Self::Jpeg => ImageMediaType::Jpeg,
            Self::Webp => ImageMediaType::WebP,
        }
    }
}

#[derive(Serialize)]
struct ImageResponseDto {
    version: u16,
    images: Vec<ImageResponseItemDto>,
}

#[derive(Serialize)]
struct ImageResponseItemDto {
    media_type: &'static str,
    width: usize,
    height: usize,
    base64: String,
}

fn project_matching_response(
    response: ServiceResponse,
    context: Option<&RequestContext>,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    match response {
        ServiceResponse::Image(response) => project_image_response(response, context),
        _ => Err(internal_failure()),
    }
}

fn project_image_response(
    response: ImageServiceResponse,
    context: Option<&RequestContext>,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let version = project_version(response.version())?;
    let images = encode_images(response.images(), context)?;
    let body = serialize_image_response(&ImageResponseDto { version, images }, context)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    ProtocolBufferedResponse::new(StatusCode::OK, headers, body)
}

fn serialize_image_response(
    response: &ImageResponseDto,
    context: Option<&RequestContext>,
) -> Result<axum::body::Bytes, ProtocolFailure> {
    match context {
        Some(context) => serialize_bounded_cancellable(response, context),
        None => serialize_bounded(response),
    }
}

fn encode_images(
    images: &GeneratedImages,
    context: Option<&RequestContext>,
) -> Result<Vec<ImageResponseItemDto>, ProtocolFailure> {
    validate_encoded_budget(images.as_slice())?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(images.len())
        .map_err(|_| internal_failure())?;
    for image in images.as_slice() {
        encoded.push(encode_image_item(image, context)?);
    }
    Ok(encoded)
}

fn validate_encoded_budget(images: &[GeneratedImage]) -> Result<(), ProtocolFailure> {
    let mut total = 0_usize;
    for image in images {
        total = total
            .checked_add(base64_length(image.encoded_bytes())?)
            .ok_or_else(internal_failure)?;
    }
    if total > MAX_PUBLIC_BODY_BYTES {
        return Err(internal_failure());
    }
    Ok(())
}

fn encode_image_item(
    image: &GeneratedImage,
    context: Option<&RequestContext>,
) -> Result<ImageResponseItemDto, ProtocolFailure> {
    let dimensions = image.dimensions();
    Ok(ImageResponseItemDto {
        media_type: image.media_type().as_str(),
        width: dimensions.width(),
        height: dimensions.height(),
        base64: encode_image_bytes(image.as_bytes(), context)?,
    })
}

fn encode_image_bytes(
    input: &[u8],
    context: Option<&RequestContext>,
) -> Result<String, ProtocolFailure> {
    check_context(context)?;
    let output_length = base64_length(input.len())?;
    let mut output = allocate_encoding(output_length)?;
    encode_chunks(input, &mut output, context)?;
    check_context(context)?;
    String::from_utf8(output).map_err(|_| internal_failure())
}

fn allocate_encoding(length: usize) -> Result<Vec<u8>, ProtocolFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| internal_failure())?;
    output.resize(length, 0);
    Ok(output)
}

fn encode_chunks(
    input: &[u8],
    output: &mut [u8],
    context: Option<&RequestContext>,
) -> Result<(), ProtocolFailure> {
    let mut offset = 0_usize;
    for chunk in input.chunks(BASE64_INPUT_CHUNK_BYTES) {
        check_context(context)?;
        offset = encode_chunk(chunk, output, offset)?;
        check_context(context)?;
    }
    if offset != output.len() {
        return Err(internal_failure());
    }
    Ok(())
}

fn encode_chunk(input: &[u8], output: &mut [u8], offset: usize) -> Result<usize, ProtocolFailure> {
    let encoded_length = base64_length(input.len())?;
    let end = offset
        .checked_add(encoded_length)
        .ok_or_else(internal_failure)?;
    let target = output.get_mut(offset..end).ok_or_else(internal_failure)?;
    let written = STANDARD
        .encode_slice(input, target)
        .map_err(|_| internal_failure())?;
    if written != encoded_length {
        return Err(internal_failure());
    }
    Ok(end)
}

fn check_context(context: Option<&RequestContext>) -> Result<(), ProtocolFailure> {
    context
        .map(RequestContext::check_active)
        .transpose()
        .map_err(ApiDomainError::from)?;
    Ok(())
}

fn base64_length(input_length: usize) -> Result<usize, ProtocolFailure> {
    base64::encoded_len(input_length, true).ok_or_else(internal_failure)
}

const fn project_version(version: ServiceContractVersion) -> Result<u16, ProtocolFailure> {
    match version {
        ServiceContractVersion::V1 => Ok(1),
        _ => Err(internal_failure()),
    }
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

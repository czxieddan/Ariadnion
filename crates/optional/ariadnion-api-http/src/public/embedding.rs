// crates/optional/ariadnion-api-http/src/public/embedding.rs - Native embedding HTTP projection for Ariadnion.
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
//! Strict complete-only embedding ingress and bounded JSON response encoding.

use std::fmt;
use std::sync::Arc;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, EmbeddingInput, EmbeddingInputs, EmbeddingServiceRequest,
    EmbeddingServiceResponse, EmbeddingVector, IdempotencyKey, MAX_EMBEDDING_INPUTS, ModelSelector,
    ResponseMode, ServiceContractVersion, ServiceRequest, ServiceResponse, ServiceStreamEvent,
};
use ariadnion_core::{EventSubscriber, RequestContext};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::Response;
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Deserializer, Serialize};

use super::json::serialize_bounded;
use super::protocol::{
    HttpProtocolAdapter, HttpProtocolProjection, ProtocolBufferedResponse, ProtocolFailure,
    ProtocolRequest, ProtocolRequestBody, ProtocolStreamResponse,
};
use super::{
    HttpApiState, HttpRequestIdentity, execution, parse_idempotency, project_native_failure,
};

pub(super) async fn handle_embeddings(
    State(state): State<HttpApiState>,
    request: Request<Body>,
) -> Response {
    execution::handle_request(&state, &NativeEmbeddingProtocol, request).await
}

struct NativeEmbeddingProtocol;

impl HttpProtocolAdapter for NativeEmbeddingProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let dto: EmbeddingRequestDto = serde_json::from_slice(body.bytes())
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

struct NativeEmbeddingProjection;

impl HttpProtocolProjection for NativeEmbeddingProjection {
    fn supports_streaming(&self) -> bool {
        false
    }

    fn project_complete(
        &self,
        _identity: &HttpRequestIdentity,
        response: ServiceResponse,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        match response {
            ServiceResponse::Embedding(response) => project_embedding_response(response),
            _ => Err(internal_failure()),
        }
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
struct EmbeddingRequestDto {
    version: u16,
    model: String,
    inputs: EmbeddingInputListDto,
}

impl EmbeddingRequestDto {
    fn into_protocol(
        self,
        idempotency: Option<IdempotencyKey>,
    ) -> Result<ProtocolRequest, ProtocolFailure> {
        let inputs = self.inputs.into_domain()?;
        let request = EmbeddingServiceRequest::new(
            ServiceContractVersion::parse(self.version)?,
            ModelSelector::new(&self.model)?,
            inputs,
            idempotency,
        );
        ProtocolRequest::new(
            ServiceRequest::Embedding(request),
            ResponseMode::Complete,
            Arc::new(NativeEmbeddingProjection),
        )
    }
}

struct EmbeddingInputListDto {
    values: Vec<String>,
    exceeded: bool,
}

impl EmbeddingInputListDto {
    fn into_domain(self) -> Result<EmbeddingInputs, ApiDomainError> {
        if self.exceeded {
            return Err(ApiDomainError::new(ApiDomainErrorCode::LimitExceeded));
        }
        let inputs = self
            .values
            .iter()
            .map(|value| EmbeddingInput::new(value))
            .collect::<Result<Vec<_>, _>>()?;
        EmbeddingInputs::new(inputs)
    }
}

impl<'de> Deserialize<'de> for EmbeddingInputListDto {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(EmbeddingInputListVisitor)
    }
}

struct EmbeddingInputListVisitor;

impl<'de> Visitor<'de> for EmbeddingInputListVisitor {
    type Value = EmbeddingInputListDto;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of embedding input strings")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(MAX_EMBEDDING_INPUTS);
        while values.len() < MAX_EMBEDDING_INPUTS {
            let Some(value) = sequence.next_element::<String>()? else {
                return Ok(EmbeddingInputListDto {
                    values,
                    exceeded: false,
                });
            };
            values.push(value);
        }
        let exceeded = sequence.next_element::<IgnoredAny>()?.is_some();
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(EmbeddingInputListDto { values, exceeded })
    }
}

#[derive(Serialize)]
struct EmbeddingResponseDto<'a> {
    version: u16,
    vectors: EmbeddingVectorBatchDto<'a>,
    dimensions: usize,
    usage: EmbeddingUsageDto,
}

struct EmbeddingVectorBatchDto<'a>(&'a [EmbeddingVector]);

impl Serialize for EmbeddingVectorBatchDto<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for vector in self.0 {
            sequence.serialize_element(vector.as_slice())?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct EmbeddingUsageDto {
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
}

fn project_embedding_response(
    response: EmbeddingServiceResponse,
) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let version = project_version(response.version())?;
    let vectors = response.vectors();
    let usage = response.usage();
    let body = serialize_bounded(&EmbeddingResponseDto {
        version,
        vectors: EmbeddingVectorBatchDto(vectors.as_slice()),
        dimensions: vectors.dimensions(),
        usage: EmbeddingUsageDto {
            input_tokens: usage.input_tokens(),
            output_tokens: usage.output_tokens(),
            total_tokens: usage.total_tokens(),
        },
    })?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    ProtocolBufferedResponse::new(StatusCode::OK, headers, body)
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

use super::{ApiHttpError, ApiHttpErrorCode};

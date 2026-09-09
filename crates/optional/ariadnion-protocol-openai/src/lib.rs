// crates/optional/ariadnion-protocol-openai/src/lib.rs - OpenAI protocol adapter for Ariadnion.
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
//! Strict OpenAI-compatible public protocol projection for Ariadnion chat services.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod completions;
pub mod embeddings;
pub mod models;
pub mod realtime;
mod request;
mod response;
#[path = "responses/response.rs"]
mod responses;
mod route_manifest;
pub mod speech;
mod stream;

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_api_domain::ServiceRequest;
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, HttpApiState, HttpProtocolAdapter, HttpRequestIdentity,
    ProtocolBufferedResponse, ProtocolExecutionState, ProtocolFailure, ProtocolRequest,
    ProtocolRequestBody, protocol_post_route,
};
use axum::Router;

use response::OpenAiProjection;

pub use completions::{
    OPENAI_COMPLETIONS_PATH, OpenAiCompletionsProtocol, OpenAiCompletionsRouter,
    openai_completions_router, openai_completions_router_with_clock,
};
pub use embeddings::{
    OPENAI_EMBEDDINGS_PATH, OpenAiEmbeddingsProtocol, OpenAiEmbeddingsRouter,
    openai_embeddings_router,
};
pub use models::{
    MAX_MODEL_OWNER_BYTES, MAX_OPENAI_MODELS, OPENAI_MODELS_PATH, OpenAiModelCatalog,
    OpenAiModelDescriptor, OpenAiModelsProtocol, OpenAiModelsRouter, openai_models_router,
};
pub use realtime::{
    OPENAI_REALTIME_PATH, OpenAiRealtimeDecodedEvent, OpenAiRealtimeError, OpenAiRealtimeErrorCode,
    OpenAiRealtimeFileAlias, OpenAiRealtimeOutboundFrame, OpenAiRealtimeProtocol,
    OpenAiRealtimeServerEventKind, OpenAiRealtimeSessionProjection,
};
pub use route_manifest::OpenAiRouteManifest;
pub use speech::{
    OPENAI_SPEECH_PATH, OpenAiSpeechProtocol, OpenAiSpeechRouter, openai_speech_router,
};

/// Supplies validated Unix-second timestamps for OpenAI response objects.
///
/// Production composition must inject an authoritative UTC source. The protocol
/// crate never samples ambient time while decoding or projecting a request, so a
/// caller can make timestamp provenance explicit and testable.
pub trait OpenAiTimestampPort: Send + Sync {
    /// Returns one current Unix timestamp in whole seconds.
    ///
    /// # Errors
    ///
    /// Returns a redacted protocol failure when the authoritative clock cannot
    /// provide a representable timestamp.
    fn unix_seconds(&self) -> Result<u64, ProtocolFailure>;
}

/// Deterministic timestamp source for focused protocol characterization.
///
/// This type is intended for tests and deterministic mock-only assembly. A
/// production bundle should inject its own authoritative [`OpenAiTimestampPort`]
/// implementation instead of retaining the epoch value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedOpenAiTimestamp(u64);

impl FixedOpenAiTimestamp {
    /// Creates a fixed Unix-second timestamp source.
    #[must_use]
    pub const fn new(unix_seconds: u64) -> Self {
        Self(unix_seconds)
    }
}

impl OpenAiTimestampPort for FixedOpenAiTimestamp {
    fn unix_seconds(&self) -> Result<u64, ProtocolFailure> {
        Ok(self.0)
    }
}

/// Authoritative wall-clock timestamp source for production protocol assembly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemOpenAiTimestamp;

impl OpenAiTimestampPort for SystemOpenAiTimestamp {
    fn unix_seconds(&self) -> Result<u64, ProtocolFailure> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal)))
    }
}

/// Public route owned by the create-only OpenAI Responses adapter.
pub const OPENAI_RESPONSES_PATH: &str = "/v1/responses";

/// Concrete router type returned by [`openai_responses_router`].
pub type OpenAiResponsesRouter = Router;

/// The OpenAI-compatible chat completions route owned by this protocol crate.
pub const OPENAI_CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";

/// The concrete HTTP router returned by the OpenAI chat completions adapter.
///
/// Composition crates use this alias to expose their assembled router without
/// acquiring a separate direct dependency on the underlying HTTP framework.
pub type OpenAiChatCompletionsRouter = Router;

/// Strict decoder and projector for the supported OpenAI chat request subset.
#[derive(Clone, Copy, Default)]
pub struct OpenAiProtocol;

impl OpenAiProtocol {
    /// Creates a stateless OpenAI protocol adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Debug for OpenAiProtocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiProtocol")
    }
}

impl HttpProtocolAdapter for OpenAiProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let decoded = request::decode(body.bytes())?;
        let response_mode = decoded.request.response_mode();
        let projection = Arc::new(OpenAiProjection::new(decoded.model, decoded.include_usage));
        ProtocolRequest::new(
            ServiceRequest::Chat(decoded.request),
            response_mode,
            projection,
        )
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        response::project_failure(identity, failure)
    }
}

/// Strict decoder and projector for the P4 create-only OpenAI Responses subset.
pub struct OpenAiResponsesProtocol {
    clock: Arc<dyn OpenAiTimestampPort>,
}

impl OpenAiResponsesProtocol {
    /// Creates a Responses adapter backed by the system UTC clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clock: Arc::new(SystemOpenAiTimestamp),
        }
    }

    /// Creates a Responses adapter with an authoritative timestamp port.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn OpenAiTimestampPort>) -> Self {
        Self { clock }
    }
}

impl Default for OpenAiResponsesProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for OpenAiResponsesProtocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiResponsesProtocol")
    }
}

impl HttpProtocolAdapter for OpenAiResponsesProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let decoded = responses::decode_request(body.bytes())?;
        let created_at = self.clock.unix_seconds()?;
        let mut projection = responses::OpenAiResponsesProjection::new(decoded.model);
        projection.created_at = created_at;
        let projection = Arc::new(projection);
        ProtocolRequest::new(
            ServiceRequest::Text(decoded.request),
            decoded.response_mode,
            projection,
        )
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        responses::project_failure(identity, failure)
    }
}

/// Mounts the OpenAI chat completions POST route over shared authenticated HTTP state.
///
/// The returned router owns only `/v1/chat/completions`; it does not install a
/// protocol registry or modify Ariadnion-native routes. Complete requests use
/// [`ariadnion_api_domain::ResponseMode::Complete`]. Streaming requests use a
/// protocol-owned bounded SSE projection over the same authenticated lifecycle.
pub fn openai_chat_completions_router(http: HttpApiState) -> OpenAiChatCompletionsRouter {
    let protocol: Arc<dyn HttpProtocolAdapter> = Arc::new(OpenAiProtocol::new());
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_CHAT_COMPLETIONS_PATH, protocol_post_route())
        .with_state(state)
}

/// Mounts `POST /v1/responses` over shared authenticated HTTP state.
///
/// The returned router owns only the frozen create-only Responses endpoint.
/// Complete and streamed Responses reuse the common admission, authentication,
/// cancellation, deadline, and response-lifetime execution boundary.
pub fn openai_responses_router(http: HttpApiState) -> OpenAiResponsesRouter {
    let protocol: Arc<dyn HttpProtocolAdapter> = Arc::new(OpenAiResponsesProtocol::new());
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_RESPONSES_PATH, protocol_post_route())
        .with_state(state)
}

/// Mounts the production Responses route with an explicit timestamp port.
pub fn openai_responses_router_with_clock(
    http: HttpApiState,
    clock: Arc<dyn OpenAiTimestampPort>,
) -> OpenAiResponsesRouter {
    let protocol: Arc<dyn HttpProtocolAdapter> =
        Arc::new(OpenAiResponsesProtocol::with_clock(clock));
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_RESPONSES_PATH, protocol_post_route())
        .with_state(state)
}

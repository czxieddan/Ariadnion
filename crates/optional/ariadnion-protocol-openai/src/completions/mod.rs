// crates/optional/ariadnion-protocol-openai/src/completions/mod.rs - OpenAI legacy Completions protocol adapter.
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
//! Strict, bounded OpenAI legacy Completions projection.

#![forbid(unsafe_code)]

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_api_domain::ServiceRequest;
use ariadnion_api_http::{
    HttpApiState, HttpProtocolAdapter, HttpRequestIdentity, ProtocolBufferedResponse,
    ProtocolExecutionState, ProtocolFailure, ProtocolRequest, ProtocolRequestBody,
    protocol_post_route,
};
use axum::Router;

use crate::{OpenAiTimestampPort, SystemOpenAiTimestamp};

mod request;
mod response;
mod stream;

use response::OpenAiCompletionsProjection;

/// Public route owned by the legacy OpenAI Completions adapter.
pub const OPENAI_COMPLETIONS_PATH: &str = "/v1/completions";

/// Concrete router type returned by [`openai_completions_router`].
pub type OpenAiCompletionsRouter = Router;

/// Strict decoder and projector for the P4 legacy Completions subset.
pub struct OpenAiCompletionsProtocol {
    clock: Arc<dyn OpenAiTimestampPort>,
}

impl OpenAiCompletionsProtocol {
    /// Creates a legacy Completions adapter backed by the system UTC clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clock: Arc::new(SystemOpenAiTimestamp),
        }
    }

    /// Creates a legacy Completions adapter with an authoritative timestamp port.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn OpenAiTimestampPort>) -> Self {
        Self { clock }
    }
}

impl Default for OpenAiCompletionsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for OpenAiCompletionsProtocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiCompletionsProtocol")
    }
}

impl HttpProtocolAdapter for OpenAiCompletionsProtocol {
    fn decode(&self, body: ProtocolRequestBody) -> Result<ProtocolRequest, ProtocolFailure> {
        let decoded = request::decode(body.bytes())?;
        let created = self.clock.unix_seconds()?;
        let projection = Arc::new(OpenAiCompletionsProjection::new(
            decoded.model,
            decoded.include_usage,
            created,
        ));
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
        response::project_failure(identity, failure)
    }
}

/// Mounts `POST /v1/completions` over shared authenticated HTTP state.
pub fn openai_completions_router(http: HttpApiState) -> OpenAiCompletionsRouter {
    let protocol: Arc<dyn HttpProtocolAdapter> = Arc::new(OpenAiCompletionsProtocol::new());
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_COMPLETIONS_PATH, protocol_post_route())
        .with_state(state)
}

/// Mounts the production legacy Completions route with an explicit timestamp port.
pub fn openai_completions_router_with_clock(
    http: HttpApiState,
    clock: Arc<dyn OpenAiTimestampPort>,
) -> OpenAiCompletionsRouter {
    let protocol: Arc<dyn HttpProtocolAdapter> =
        Arc::new(OpenAiCompletionsProtocol::with_clock(clock));
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_COMPLETIONS_PATH, protocol_post_route())
        .with_state(state)
}

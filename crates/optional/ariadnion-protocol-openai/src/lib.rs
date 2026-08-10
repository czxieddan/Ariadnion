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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Strict OpenAI-compatible public protocol projection for Ariadnion chat services.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod request;
mod response;

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_api_domain::ServiceRequest;
use ariadnion_api_http::{
    HttpApiState, HttpProtocolAdapter, HttpRequestIdentity, ProtocolBufferedResponse,
    ProtocolExecutionState, ProtocolFailure, ProtocolRequest, ProtocolRequestBody,
    protocol_post_route,
};
use axum::Router;

use response::OpenAiProjection;

/// The OpenAI-compatible chat completions route owned by this protocol crate.
pub const OPENAI_CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";

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

/// Mounts the OpenAI chat completions POST route over shared authenticated HTTP state.
///
/// The returned router owns only `/v1/chat/completions`; it does not install a
/// protocol registry or modify Ariadnion-native routes. Complete requests use
/// [`ariadnion_api_domain::ResponseMode::Complete`]. Streaming requests are
/// decoded for compatibility but fail closed until the streaming projector is installed.
pub fn openai_chat_completions_router(http: HttpApiState) -> Router {
    let protocol: Arc<dyn HttpProtocolAdapter> = Arc::new(OpenAiProtocol::new());
    let state = ProtocolExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_CHAT_COMPLETIONS_PATH, protocol_post_route())
        .with_state(state)
}

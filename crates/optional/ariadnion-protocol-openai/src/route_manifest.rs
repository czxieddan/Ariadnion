// crates/optional/ariadnion-protocol-openai/src/route_manifest.rs - OpenAI route composition for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Explicit composition of the currently production-ready OpenAI route leaves.

use std::sync::Arc;

use ariadnion_api_domain::AudioOutputSpecification;
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, BoxProtocolOperationFuture, HttpApiState,
    HttpOperationProtocolAdapter, HttpRequestIdentity, HttpUpgradeProtocolAdapter,
    ProtocolBufferedResponse, ProtocolFailure, ProtocolOperationExecutionState,
    ProtocolUpgradeExecutionState, ProtocolUpgradeLimits, protocol_operation_delete_route,
    protocol_operation_get_route, protocol_operation_post_route, protocol_upgrade_route,
};
use ariadnion_core::RequestContext;
use axum::Router;
use axum::body::Body;
use axum::http::Request;

use crate::{
    OpenAiModelCatalog, OpenAiTimestampPort, SystemOpenAiTimestamp, openai_chat_completions_router,
    openai_chat_completions_router_with_clock, openai_completions_router_with_clock,
    openai_embeddings_router, openai_images_router, openai_images_router_with_clock,
    openai_models_router, openai_responses_router_with_clock, openai_speech_router,
};

/// Explicit optional capabilities used while composing the OpenAI route family.
///
/// Chat Completions, Embeddings, Images, Files, Batch, and Realtime are mounted by
/// [`Self::mount`]. Files, Batch, and Realtime use a stable unavailable projection
/// until their explicit capabilities are supplied. Legacy Completions and Responses
/// require the same explicit timestamp capability and are omitted when it is absent.
/// Models and Speech retain their method and path ownership with a stable unavailable
/// projection until their typed composition capabilities are supplied.
#[derive(Clone)]
pub struct OpenAiRouteManifest {
    models: Option<Arc<OpenAiModelCatalog>>,
    speech_output: Option<AudioOutputSpecification>,
    timestamp: Option<Arc<dyn OpenAiTimestampPort>>,
    files: Option<Arc<dyn HttpOperationProtocolAdapter>>,
    batch: Option<Arc<dyn HttpOperationProtocolAdapter>>,
    realtime: Option<RealtimeCapability>,
}

#[derive(Clone)]
struct RealtimeCapability {
    protocol: Arc<dyn HttpUpgradeProtocolAdapter>,
    limits: ProtocolUpgradeLimits,
}

impl OpenAiRouteManifest {
    /// Creates a manifest with the unconditional routes and fail-closed P4
    /// capability leaves.
    #[must_use]
    pub fn new() -> Self {
        Self {
            models: None,
            speech_output: None,
            timestamp: Some(Arc::new(SystemOpenAiTimestamp)),
            files: Some(Arc::new(UnavailableOperationAdapter)),
            batch: Some(Arc::new(UnavailableOperationAdapter)),
            realtime: None,
        }
    }

    /// Adds the immutable model catalog route capability.
    #[must_use]
    pub fn with_models(mut self, catalog: Arc<OpenAiModelCatalog>) -> Self {
        self.models = Some(catalog);
        self
    }

    /// Adds the explicit raw-WAV Speech output capability.
    #[must_use]
    pub const fn with_speech_output(mut self, output: AudioOutputSpecification) -> Self {
        self.speech_output = Some(output);
        self
    }

    /// Adds the authoritative timestamp capability required by time-bearing routes.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: Arc<dyn OpenAiTimestampPort>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Adds the authenticated Files operation adapter.
    ///
    /// The adapter owns request decoding and provider capability mapping. When
    /// absent, the Files paths retain the stable unavailable projection.
    #[must_use]
    pub fn with_files_adapter(mut self, adapter: Arc<dyn HttpOperationProtocolAdapter>) -> Self {
        self.files = Some(adapter);
        self
    }

    /// Adds the authenticated Batch operation adapter.
    ///
    /// The adapter is mounted for collection, retrieval, listing, and cancel
    /// paths. When absent, the Batch paths retain the stable unavailable
    /// projection.
    #[must_use]
    pub fn with_batch_adapter(mut self, adapter: Arc<dyn HttpOperationProtocolAdapter>) -> Self {
        self.batch = Some(adapter);
        self
    }

    /// Adds the authenticated Realtime WebSocket adapter and transport limits.
    ///
    /// Limits are validated by [`ProtocolUpgradeLimits::new`] before they are
    /// supplied here. When absent, the Realtime path retains the stable
    /// unavailable projection.
    #[must_use]
    pub fn with_realtime_adapter(
        mut self,
        adapter: Arc<dyn HttpUpgradeProtocolAdapter>,
        limits: ProtocolUpgradeLimits,
    ) -> Self {
        self.realtime = Some(RealtimeCapability {
            protocol: adapter,
            limits,
        });
        self
    }

    /// Mounts each route enabled by this manifest over shared HTTP state.
    ///
    /// Every leaf receives a clone of the same authenticated state, preserving
    /// one admission budget, shutdown tree, identity issuer, and dispatch port.
    /// This method only merges already-built routers; it performs no I/O,
    /// configuration lookup, protocol negotiation, or listener setup.
    #[must_use = "retain the composed OpenAI router for the public listener owner"]
    pub fn mount(&self, http: HttpApiState) -> Router {
        let router = self.mount_base(http.clone());
        let router = self.mount_timestamp_routes(router, http.clone());
        let router = self.mount_optional_routes(router, http.clone());
        self.mount_realtime(router, http)
    }

    fn mount_base(&self, http: HttpApiState) -> Router {
        match &self.timestamp {
            Some(timestamp) => {
                openai_chat_completions_router_with_clock(http.clone(), Arc::clone(timestamp))
            }
            None => openai_chat_completions_router(http.clone()),
        }
        .merge(openai_embeddings_router(http))
    }

    fn mount_timestamp_routes(&self, router: Router, http: HttpApiState) -> Router {
        match &self.timestamp {
            Some(timestamp) => router.merge(openai_images_router_with_clock(
                http.clone(),
                Arc::clone(timestamp),
            )),
            None => router.merge(openai_images_router(http)),
        }
    }

    fn mount_optional_routes(&self, mut router: Router, http: HttpApiState) -> Router {
        if let Some(timestamp) = &self.timestamp {
            router = router
                .merge(openai_completions_router_with_clock(
                    http.clone(),
                    Arc::clone(timestamp),
                ))
                .merge(openai_responses_router_with_clock(
                    http.clone(),
                    Arc::clone(timestamp),
                ));
        }
        router = router.merge(self.mount_models(http.clone()));
        router = router.merge(self.mount_speech(http.clone()));
        if let Some(adapter) = &self.files {
            router = router.merge(openai_files_router(http.clone(), Arc::clone(adapter)));
        }
        if let Some(adapter) = &self.batch {
            router = router.merge(openai_batch_router(http.clone(), Arc::clone(adapter)));
        }
        router
    }

    fn mount_models(&self, http: HttpApiState) -> Router {
        match &self.models {
            Some(catalog) => openai_models_router(http, Arc::clone(catalog)),
            None => openai_unavailable_models_router(http),
        }
    }

    fn mount_speech(&self, http: HttpApiState) -> Router {
        match self.speech_output {
            Some(output) => openai_speech_router(http, output),
            None => openai_unavailable_speech_router(http),
        }
    }

    fn mount_realtime(&self, router: Router, http: HttpApiState) -> Router {
        match self.realtime.clone() {
            Some(realtime) => router.merge(openai_realtime_router(
                http,
                realtime.protocol,
                realtime.limits,
            )),
            None => router.merge(openai_unavailable_realtime_router(http)),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct UnavailableOperationAdapter;

impl HttpOperationProtocolAdapter for UnavailableOperationAdapter {
    fn execute<'a>(
        &'a self,
        _request: Request<Body>,
        _identity: &'a HttpRequestIdentity,
        _context: &'a RequestContext,
    ) -> BoxProtocolOperationFuture<'a> {
        Box::pin(async { Err(unavailable_failure()) })
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        crate::response::project_failure(identity, failure)
    }
}

fn unavailable_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Unavailable))
}

fn openai_unavailable_models_router(http: HttpApiState) -> Router {
    let state = unavailable_operation_state(http);
    Router::new()
        .route(crate::OPENAI_MODELS_PATH, protocol_operation_get_route())
        .with_state(state)
}

fn openai_unavailable_speech_router(http: HttpApiState) -> Router {
    let state = unavailable_operation_state(http);
    Router::new()
        .route(crate::OPENAI_SPEECH_PATH, protocol_operation_post_route())
        .with_state(state)
}

fn openai_unavailable_realtime_router(http: HttpApiState) -> Router {
    let state = unavailable_operation_state(http);
    Router::new()
        .route(crate::OPENAI_REALTIME_PATH, protocol_operation_get_route())
        .with_state(state)
}

fn unavailable_operation_state(http: HttpApiState) -> ProtocolOperationExecutionState {
    ProtocolOperationExecutionState::new(http, Arc::new(UnavailableOperationAdapter))
}

/// Builds the OpenAI Files compatibility router over one authenticated adapter.
pub fn openai_files_router(
    http: HttpApiState,
    adapter: Arc<dyn HttpOperationProtocolAdapter>,
) -> Router {
    let state = ProtocolOperationExecutionState::new(http, adapter);
    Router::new()
        .route(
            "/v1/files",
            protocol_operation_get_route().merge(protocol_operation_post_route()),
        )
        .route(
            "/v1/files/{file_id}",
            protocol_operation_get_route().merge(protocol_operation_delete_route()),
        )
        .route(
            "/v1/files/{file_id}/content",
            protocol_operation_get_route(),
        )
        .with_state(state)
}

/// Builds the OpenAI Batch compatibility router over one authenticated adapter.
pub fn openai_batch_router(
    http: HttpApiState,
    adapter: Arc<dyn HttpOperationProtocolAdapter>,
) -> Router {
    let state = ProtocolOperationExecutionState::new(http, adapter);
    Router::new()
        .route(
            "/v1/batches",
            protocol_operation_get_route().merge(protocol_operation_post_route()),
        )
        .route("/v1/batches/{batch_id}", protocol_operation_get_route())
        .route(
            "/v1/batches/{batch_id}/cancel",
            protocol_operation_post_route(),
        )
        .with_state(state)
}

/// Builds the OpenAI Realtime upgrade router over one authenticated adapter.
pub fn openai_realtime_router(
    http: HttpApiState,
    adapter: Arc<dyn HttpUpgradeProtocolAdapter>,
    limits: ProtocolUpgradeLimits,
) -> Router {
    let state = ProtocolUpgradeExecutionState::new(http, adapter, limits);
    Router::new()
        .route(crate::OPENAI_REALTIME_PATH, protocol_upgrade_route())
        .with_state(state)
}

impl Default for OpenAiRouteManifest {
    fn default() -> Self {
        Self::new()
    }
}

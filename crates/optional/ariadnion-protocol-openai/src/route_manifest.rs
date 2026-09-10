// crates/optional/ariadnion-protocol-openai/src/route_manifest.rs - OpenAI route composition for Ariadnion.
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
//! Explicit composition of the currently production-ready OpenAI route leaves.

use std::sync::Arc;

use ariadnion_api_domain::AudioOutputSpecification;
use ariadnion_api_http::HttpApiState;
use axum::Router;

use crate::{
    OpenAiModelCatalog, OpenAiTimestampPort, SystemOpenAiTimestamp, openai_chat_completions_router,
    openai_chat_completions_router_with_clock, openai_completions_router_with_clock,
    openai_embeddings_router, openai_images_router, openai_images_router_with_clock,
    openai_models_router, openai_responses_router_with_clock, openai_speech_router,
};

/// Explicit optional capabilities used while composing the OpenAI route family.
///
/// Chat Completions, Embeddings, and Images are always mounted by [`Self::mount`].
/// Legacy Completions and Responses require the same explicit timestamp capability
/// and are omitted when it is absent. Models and Speech are mounted only when their
/// typed composition capabilities are supplied.
#[derive(Clone)]
pub struct OpenAiRouteManifest {
    models: Option<Arc<OpenAiModelCatalog>>,
    speech_output: Option<AudioOutputSpecification>,
    timestamp: Option<Arc<dyn OpenAiTimestampPort>>,
}

impl OpenAiRouteManifest {
    /// Creates a manifest containing the unconditional text and embedding routes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            models: None,
            speech_output: None,
            timestamp: Some(Arc::new(SystemOpenAiTimestamp)),
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

    /// Mounts each route enabled by this manifest over shared HTTP state.
    ///
    /// Every leaf receives a clone of the same authenticated state, preserving
    /// one admission budget, shutdown tree, identity issuer, and dispatch port.
    /// This method only merges already-built routers; it performs no I/O,
    /// configuration lookup, protocol negotiation, or listener setup.
    #[must_use = "retain the composed OpenAI router for the public listener owner"]
    pub fn mount(&self, http: HttpApiState) -> Router {
        let mut router = match &self.timestamp {
            Some(timestamp) => {
                openai_chat_completions_router_with_clock(http.clone(), Arc::clone(timestamp))
            }
            None => openai_chat_completions_router(http.clone()),
        }
        .merge(openai_embeddings_router(http.clone()));
        router = match &self.timestamp {
            Some(timestamp) => router.merge(openai_images_router_with_clock(
                http.clone(),
                Arc::clone(timestamp),
            )),
            None => router.merge(openai_images_router(http.clone())),
        };
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
        if let Some(catalog) = &self.models {
            router = router.merge(openai_models_router(http.clone(), Arc::clone(catalog)));
        }
        if let Some(output) = self.speech_output {
            router = router.merge(openai_speech_router(http, output));
        }
        router
    }
}

impl Default for OpenAiRouteManifest {
    fn default() -> Self {
        Self::new()
    }
}

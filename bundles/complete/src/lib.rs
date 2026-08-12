// bundles/complete/src/lib.rs - Rust source for Ariadnion.
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
//! Reusable complete-bundle assembly boundaries.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

use ariadnion_api_domain::ModelSelector;
use ariadnion_api_http::{
    HttpApiState, MonotonicRequestIdentityIssuer, PublicApiRouter, ServiceAuthenticationPort,
    public_router,
};
use ariadnion_api_stream::SseBridge;
use ariadnion_core::{CancellationToken, CoreError, ErrorCode};
use ariadnion_protocol_openai::{OpenAiChatCompletionsRouter, openai_chat_completions_router};
use ariadnion_provider_dispatch::{
    MonotonicAttemptIdIssuer, ProviderDispatcher, StaticProviderModelResolver,
};
use ariadnion_provider_mock::{
    DeterministicMockProvider, MOCK_PROVIDER_EMBEDDING_MODEL_ID, MOCK_PROVIDER_MODEL_ID,
    MOCK_PROVIDER_TEXT_MODEL_ID,
};
use ariadnion_provider_sdk::{ProviderModelId, ProviderPort};

/// Assembles the complete bundle's bounded OpenAI-compatible mock loop.
///
/// The caller supplies the authentication port so the same static closure can be
/// exercised by external contracts. The production entry injects the fail-closed
/// unavailable authentication service until a durable authentication adapter is
/// composed. Assembly creates no network, clock, randomness, or credential access.
///
/// # Errors
///
/// Returns a redacted internal error if a fixed selector, provider model, resolver,
/// deterministic provider, or request identity issuer cannot be constructed.
pub fn assemble_openai_mock_loop(
    authentication: Arc<dyn ServiceAuthenticationPort>,
) -> Result<OpenAiChatCompletionsRouter, CoreError> {
    let provider = DeterministicMockProvider::new()
        .map_err(|_| assembly_error("complete mock provider is unavailable"))?;
    assemble_openai_mock_loop_with_provider(authentication, Arc::new(provider))
}

/// Assembles the complete bundle's bounded OpenAI-compatible loop with one provider.
///
/// The bundle retains ownership of model resolution, attempt and request identity,
/// cancellation, authentication, dispatch, and OpenAI response projection. Assembly
/// performs no provider call and grants the supplied provider no additional capability.
///
/// # Errors
///
/// Returns a redacted internal error if the fixed selector, provider model, resolver,
/// or request identity issuer cannot be constructed.
pub fn assemble_openai_mock_loop_with_provider(
    authentication: Arc<dyn ServiceAuthenticationPort>,
    provider: Arc<dyn ProviderPort>,
) -> Result<OpenAiChatCompletionsRouter, CoreError> {
    let selector = ModelSelector::new("mock-chat")
        .map_err(|_| assembly_error("complete OpenAI selector is invalid"))?;
    let model = ProviderModelId::new(MOCK_PROVIDER_MODEL_ID)
        .map_err(|_| assembly_error("complete mock provider model is invalid"))?;
    let resolver = StaticProviderModelResolver::new([(selector, model)])
        .map_err(|_| assembly_error("complete model mapping is invalid"))?;
    let dispatcher = Arc::new(ProviderDispatcher::new(
        Arc::new(resolver),
        Arc::new(MonotonicAttemptIdIssuer::new()),
        provider,
    ));
    let identity = Arc::new(
        MonotonicRequestIdentityIssuer::new()
            .map_err(|_| assembly_error("complete request identity is unavailable"))?,
    );
    let state = HttpApiState::new(
        identity,
        authentication,
        dispatcher,
        CancellationToken::new(),
    );
    Ok(openai_chat_completions_router(state))
}

/// Assembles the complete bundle's Ariadnion-native mock loop.
///
/// The caller supplies the authentication port. The bundle owns the fixed text
/// and embedding model mappings, request and attempt identities, checked provider
/// dispatch, cancellation, and bounded native SSE bridge. Both native routes share
/// one provider, resolver, dispatcher, HTTP state, and public router. Assembly
/// performs no provider call or external I/O.
///
/// # Errors
///
/// Returns a redacted internal error if the deterministic provider, a fixed model
/// mapping, or the request identity issuer cannot be constructed.
pub fn assemble_native_text_mock_loop(
    authentication: Arc<dyn ServiceAuthenticationPort>,
) -> Result<PublicApiRouter, CoreError> {
    let provider = Arc::new(
        DeterministicMockProvider::new()
            .map_err(|_| assembly_error("complete native mock provider is unavailable"))?,
    );
    let resolver = native_model_resolver()?;
    let dispatcher = Arc::new(ProviderDispatcher::new(
        Arc::new(resolver),
        Arc::new(MonotonicAttemptIdIssuer::new()),
        provider,
    ));
    let identity = Arc::new(
        MonotonicRequestIdentityIssuer::new()
            .map_err(|_| assembly_error("complete native request identity is unavailable"))?,
    );
    let state = HttpApiState::new(
        identity,
        authentication,
        dispatcher,
        CancellationToken::new(),
    )
    .with_stream_bridge(Arc::new(SseBridge::default()));
    Ok(public_router(state))
}

fn native_model_resolver() -> Result<StaticProviderModelResolver, CoreError> {
    let text_selector = ModelSelector::new("mock-text")
        .map_err(|_| assembly_error("complete native text selector is invalid"))?;
    let text_model = ProviderModelId::new(MOCK_PROVIDER_TEXT_MODEL_ID)
        .map_err(|_| assembly_error("complete native text provider model is invalid"))?;
    let embedding_selector = ModelSelector::new("mock-embedding")
        .map_err(|_| assembly_error("complete native embedding selector is invalid"))?;
    let embedding_model = ProviderModelId::new(MOCK_PROVIDER_EMBEDDING_MODEL_ID)
        .map_err(|_| assembly_error("complete native embedding provider model is invalid"))?;
    StaticProviderModelResolver::new([
        (text_selector, text_model),
        (embedding_selector, embedding_model),
    ])
    .map_err(|_| assembly_error("complete native model mapping is invalid"))
}

fn assembly_error(context: &'static str) -> CoreError {
    CoreError::from_code(ErrorCode::Internal).with_internal_context(context)
}

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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
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
    DeterministicMockProvider, MOCK_PROVIDER_AUDIO_MODEL_ID, MOCK_PROVIDER_EMBEDDING_MODEL_ID,
    MOCK_PROVIDER_IMAGE_MODEL_ID, MOCK_PROVIDER_MODEL_ID, MOCK_PROVIDER_TEXT_MODEL_ID,
};
use ariadnion_provider_sdk::{ProviderModelId, ProviderPort};

/// Selects the single public API route family assembled by the complete bundle.
///
/// `Native` retains Ariadnion-native request and response contracts.
/// `Compatibility` retains the stable OpenAI-compatible contract declared by
/// [`COMPLETE_COMPATIBILITY_PROTOCOL_FAMILIES`]. This type is intentionally
/// copyable so a caller can select the fixed profile before assembly without
/// mutable registry state, protocol sniffing, or runtime fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletePublicApiProfile {
    /// Assemble only Ariadnion-native public routes.
    Native,
    /// Assemble only the fixed OpenAI-compatible public routes.
    Compatibility,
}

/// Lists the stable compatibility protocol families included by this bundle.
///
/// This slice is informational only. It is not a lookup registry, does not
/// enable protocol discovery, and does not authorize routes beyond the selected
/// [`CompletePublicApiProfile::Compatibility`] router.
pub const COMPLETE_COMPATIBILITY_PROTOCOL_FAMILIES: &[&str] = &["openai"];

/// Assembles exactly one verification-only mock public API profile.
///
/// The caller selects a static profile and supplies the authentication security
/// boundary. Assembly returns that profile's router without merging route
/// families, accepting runtime protocol selection, or starting a listener.
/// The returned router is solely for controlled verification and must never be
/// served by the P10 listener or used as a production public API.
///
/// The supplied authentication implementation remains responsible for
/// fail-closed authorization and must not expose credentials through errors or
/// logs. The caller must invoke the router from a compatible asynchronous runtime
/// and propagate request cancellation; assembly itself performs no external I/O.
/// The compatibility profile remains limited to the stable protocol families in
/// [`COMPLETE_COMPATIBILITY_PROTOCOL_FAMILIES`].
///
/// # Errors
///
/// Returns a redacted internal error when the selected mock factory cannot build
/// its fixed provider, model mapping, resolver, or request identity issuer.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
///
/// use ariadnion_api_http::ServiceAuthenticationPort;
/// use ariadnion_bundle_complete::{
///     assemble_mock_public_api, CompletePublicApiProfile,
/// };
/// use ariadnion_core::CoreError;
///
/// fn assemble_for_verification(
///     authentication: Arc<dyn ServiceAuthenticationPort>,
/// ) -> Result<(), CoreError> {
///     let router = assemble_mock_public_api(
///         CompletePublicApiProfile::Compatibility,
///         authentication,
///     )?;
///     let _ = router;
///     Ok(())
/// }
/// ```
pub fn assemble_mock_public_api(
    profile: CompletePublicApiProfile,
    authentication: Arc<dyn ServiceAuthenticationPort>,
) -> Result<PublicApiRouter, CoreError> {
    match profile {
        CompletePublicApiProfile::Native => assemble_native_text_mock_loop(authentication),
        CompletePublicApiProfile::Compatibility => assemble_openai_mock_loop(authentication),
    }
}

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
/// The caller supplies the authentication port. The bundle owns the fixed text,
/// embedding, image, and audio model mappings, request and attempt identities,
/// checked provider dispatch, cancellation, and bounded native SSE bridge. All four
/// native routes share one provider, resolver, dispatcher, HTTP state, and public
/// router. Assembly performs no provider call or external I/O.
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
    let image_selector = ModelSelector::new("mock-image")
        .map_err(|_| assembly_error("complete native image selector is invalid"))?;
    let image_model = ProviderModelId::new(MOCK_PROVIDER_IMAGE_MODEL_ID)
        .map_err(|_| assembly_error("complete native image provider model is invalid"))?;
    let audio_mapping = native_audio_mapping()?;
    StaticProviderModelResolver::new([
        (text_selector, text_model),
        (embedding_selector, embedding_model),
        (image_selector, image_model),
        audio_mapping,
    ])
    .map_err(|_| assembly_error("complete native model mapping is invalid"))
}

fn native_audio_mapping() -> Result<(ModelSelector, ProviderModelId), CoreError> {
    let selector = ModelSelector::new("mock-audio")
        .map_err(|_| assembly_error("complete native audio selector is invalid"))?;
    let model = ProviderModelId::new(MOCK_PROVIDER_AUDIO_MODEL_ID)
        .map_err(|_| assembly_error("complete native audio provider model is invalid"))?;
    Ok((selector, model))
}

fn assembly_error(context: &'static str) -> CoreError {
    CoreError::from_code(ErrorCode::Internal).with_internal_context(context)
}

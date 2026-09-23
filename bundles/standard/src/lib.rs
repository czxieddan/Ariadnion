// bundles/standard/src/lib.rs - Rust source for Ariadnion.
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
//! Reusable standard-bundle assembly boundaries.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

use ariadnion_account_vault::SecretLeaseLifetime;
use ariadnion_api_domain::{AudioOutputSpecification, ModelSelector};
use ariadnion_api_files::{FileCatalogServicePort, FileReferenceIssuerPort, FileServicePort};
use ariadnion_api_http::{
    HttpApiState, HttpOperationProtocolAdapter, HttpUpgradeProtocolAdapter,
    MonotonicRequestIdentityIssuer, ProtocolUpgradeLimits, PublicApiRouter, RequestIdentityPort,
    ServiceAuthenticationPort, ServiceDispatchPort, ServiceStreamBridgePort, public_router,
};
use ariadnion_api_stream::SseBridge;
use ariadnion_core::{CancellationToken, CoreError, ErrorCode};
use ariadnion_file_service::DurableFileService;
use ariadnion_protocol_openai::{
    OpenAiChatCompletionsRouter, OpenAiModelCatalog, OpenAiRouteManifest, OpenAiTimestampPort,
    openai_chat_completions_router,
};
use ariadnion_provider_dispatch::{
    MonotonicAttemptIdIssuer, ProviderDispatcher, StaticProviderModelResolver,
};
use ariadnion_provider_mock::{
    DeterministicMockProvider, MOCK_PROVIDER_AUDIO_MODEL_ID, MOCK_PROVIDER_EMBEDDING_MODEL_ID,
    MOCK_PROVIDER_IMAGE_MODEL_ID, MOCK_PROVIDER_MODEL_ID, MOCK_PROVIDER_TEXT_MODEL_ID,
};
use ariadnion_provider_sdk::{ProviderModelId, ProviderPort};
use ariadnion_routing_admission::RoutingAdmissionCoordinator;
use ariadnion_routing_coordinator::{
    CoordinatorError, MAX_CANDIDATES, RoutingAdmissionAssembly, RoutingCoordinator,
    build_routing_admission_coordinator,
};
use ariadnion_routing_runtime::{
    MAX_RUNTIME_ATTEMPTS, RoutingRuntime, RoutingRuntimeError, RuntimePorts,
};
use ariadnion_storage_asset::LocalVolumeAssetStoragePort;

/// Describes where an assembled routing coordinator keeps admission state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoutingCoordinatorStateScope {
    /// Rate, concurrency, and budget state lives only in the current process.
    ProcessLocal,
}

impl RoutingCoordinatorStateScope {
    /// Returns the stable report value for this state scope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessLocal => "process-local",
        }
    }
}

/// Typed facts about one standard-bundle routing coordinator assembly.
///
/// The report deliberately distinguishes compile-time composition from durable
/// runtime integration. `ProcessLocal` means that the supplied admission engine
/// does not survive process loss and does not provide cross-process reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingCoordinatorAssemblyReport {
    state_scope: RoutingCoordinatorStateScope,
    max_candidates: usize,
}

impl RoutingCoordinatorAssemblyReport {
    /// Returns the coordinator's admission-state scope.
    #[must_use]
    pub const fn state_scope(self) -> RoutingCoordinatorStateScope {
        self.state_scope
    }

    /// Returns the binary candidate limit enforced by the coordinator.
    #[must_use]
    pub const fn max_candidates(self) -> usize {
        self.max_candidates
    }

    /// Reports whether this assembly includes durable admission state.
    #[must_use]
    pub const fn has_durable_admission(self) -> bool {
        false
    }
}

/// Owns the standard bundle's shared in-process routing coordinator and report.
#[derive(Clone, Debug)]
pub struct RoutingCoordinatorAssembly {
    coordinator: Arc<RoutingCoordinator>,
    report: RoutingCoordinatorAssemblyReport,
}

impl RoutingCoordinatorAssembly {
    /// Returns the shared coordinator for dependency injection into runtime adapters.
    #[must_use]
    pub const fn coordinator(&self) -> &Arc<RoutingCoordinator> {
        &self.coordinator
    }

    /// Returns the typed assembly facts without performing runtime work.
    #[must_use]
    pub const fn report(&self) -> RoutingCoordinatorAssemblyReport {
        self.report
    }

    /// Consumes the assembly and returns the shared coordinator.
    #[must_use]
    pub fn into_coordinator(self) -> Arc<RoutingCoordinator> {
        self.coordinator
    }
}

/// Assembles the standard bundle's routing coordinator from combined admission inputs.
///
/// The coordinator crate owns construction of the coupled rate, concurrency,
/// and budget engine, including binding account concurrency to the exact source
/// snapshot generation. This bundle only wraps the resulting coordinator through
/// its existing process-local assembly path.
///
/// # Errors
///
/// Returns the coordinator's redacted stable error when admission assembly fails.
#[must_use = "handle the assembly result and retain the coordinator for dependency injection"]
pub fn assemble_routing_coordinator(
    assembly: RoutingAdmissionAssembly,
) -> Result<RoutingCoordinatorAssembly, CoordinatorError> {
    build_routing_admission_coordinator(assembly).map(assemble_process_local_routing_coordinator)
}

/// Assembles the standard bundle's existing routing coordinator in process.
///
/// The caller supplies an already configured coupled admission engine. This
/// function performs no storage access, creates no policies or account state,
/// and does not claim durable recovery. Immutable pool, model, health, circuit,
/// quota, schedule, proxy, affinity, and pricing snapshots remain explicit
/// inputs to each coordinator decision.
#[must_use = "retain the coordinator assembly for runtime dependency injection"]
pub fn assemble_in_process_routing_coordinator(
    admission: RoutingAdmissionCoordinator,
) -> RoutingCoordinatorAssembly {
    assemble_process_local_routing_coordinator(RoutingCoordinator::new(admission))
}

fn assemble_process_local_routing_coordinator(
    coordinator: RoutingCoordinator,
) -> RoutingCoordinatorAssembly {
    RoutingCoordinatorAssembly {
        coordinator: Arc::new(coordinator),
        report: RoutingCoordinatorAssemblyReport {
            state_scope: RoutingCoordinatorStateScope::ProcessLocal,
            max_candidates: MAX_CANDIDATES,
        },
    }
}

/// Typed facts about one standard-bundle routing runtime assembly.
///
/// The report describes only the statically assembled runtime. The supplied
/// ports retain responsibility for their own durability and availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingRuntimeAssemblyReport {
    coordinator: RoutingCoordinatorAssemblyReport,
    max_attempts: usize,
}

impl RoutingRuntimeAssemblyReport {
    /// Returns the coordinator facts inherited by the runtime.
    #[must_use]
    pub const fn coordinator(self) -> RoutingCoordinatorAssemblyReport {
        self.coordinator
    }

    /// Returns the maximum physical attempts accepted by one runtime request.
    #[must_use]
    pub const fn max_attempts(self) -> usize {
        self.max_attempts
    }

    /// Reports that all account, model, credential, vault, and clock ports are injected.
    ///
    /// The final provider executor is intentionally supplied for each request
    /// and is not included in this shared-port statement.
    #[must_use]
    pub const fn uses_injected_ports(self) -> bool {
        true
    }

    /// Reports that each runtime request must supply its final provider executor.
    ///
    /// Provider-specific payload encoding and response projection belong to the
    /// request adapter, so the bundle does not claim a generic wire executor.
    #[must_use]
    pub const fn requires_request_scoped_executor(self) -> bool {
        true
    }
}

/// Owns the standard bundle's shared typed routing runtime and report.
#[derive(Clone, Debug)]
pub struct RoutingRuntimeAssembly {
    runtime: Arc<RoutingRuntime>,
    report: RoutingRuntimeAssemblyReport,
}

impl RoutingRuntimeAssembly {
    /// Returns the shared runtime for injection into request adapters.
    #[must_use]
    pub const fn runtime(&self) -> &Arc<RoutingRuntime> {
        &self.runtime
    }

    /// Returns the typed assembly facts without performing runtime work.
    #[must_use]
    pub const fn report(&self) -> RoutingRuntimeAssemblyReport {
        self.report
    }

    /// Consumes the assembly and returns the shared runtime.
    #[must_use]
    pub fn into_runtime(self) -> Arc<RoutingRuntime> {
        self.runtime
    }
}

/// Assembles the standard bundle's routing runtime from explicit typed ports.
///
/// The coordinator retains process-local admission state. The caller remains
/// responsible for supplying concrete tenant-scoped account, model, credential,
/// vault, and monotonic-clock implementations through [`RuntimePorts`].
/// Each [`ariadnion_routing_runtime::RuntimeRequest`] separately supplies the
/// final provider executor that owns provider-specific payload and response work.
///
/// # Errors
///
/// Returns the runtime's stable invariant error if compiled provider credential
/// identifiers are invalid.
pub fn assemble_routing_runtime(
    coordinator: &RoutingCoordinatorAssembly,
    ports: RuntimePorts,
    lease_lifetime: SecretLeaseLifetime,
) -> Result<RoutingRuntimeAssembly, RoutingRuntimeError> {
    let runtime = RoutingRuntime::new(
        coordinator.coordinator().as_ref().clone(),
        ports,
        lease_lifetime,
    )?;
    Ok(RoutingRuntimeAssembly {
        runtime: Arc::new(runtime),
        report: RoutingRuntimeAssemblyReport {
            coordinator: coordinator.report(),
            max_attempts: MAX_RUNTIME_ATTEMPTS,
        },
    })
}

/// Selects the single public API route family assembled by the standard bundle.
///
/// `Native` retains Ariadnion-native request and response contracts.
/// `Compatibility` retains the stable OpenAI-compatible contract declared by
/// [`STANDARD_COMPATIBILITY_PROTOCOL_FAMILIES`]. This type is intentionally
/// copyable so a caller can select the fixed profile before assembly without
/// mutable registry state, protocol sniffing, or runtime fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardPublicApiProfile {
    /// Assemble only Ariadnion-native public routes.
    Native,
    /// Assemble only the fixed OpenAI-compatible public routes.
    Compatibility,
}

/// Lists the stable compatibility protocol families included by this bundle.
///
/// This slice is informational only. It is not a lookup registry, does not
/// enable protocol discovery, and does not authorize routes beyond the selected
/// [`StandardPublicApiProfile::Compatibility`] router.
pub const STANDARD_COMPATIBILITY_PROTOCOL_FAMILIES: &[&str] = &["openai"];

/// Carries already constructed capabilities into the standard production router.
///
/// The bundle owns only this typed assembly boundary. It does not parse
/// configuration, open storage sessions, resolve secrets, construct paths, bind a
/// listener, or start an executor. The optional capabilities remain absent unless
/// the caller explicitly installs them, so downstream routes fail closed when a
/// capability is unavailable.
pub struct PublicApiInputs {
    identity: Arc<dyn RequestIdentityPort>,
    authentication: Arc<dyn ServiceAuthenticationPort>,
    dispatch: Arc<dyn ServiceDispatchPort>,
    shutdown: CancellationToken,
    stream_bridge: Option<Arc<dyn ServiceStreamBridgePort>>,
    file_service: Option<Arc<dyn FileServicePort>>,
    openai_models: Option<Arc<OpenAiModelCatalog>>,
    openai_speech_output: Option<AudioOutputSpecification>,
    openai_timestamp: Option<Arc<dyn OpenAiTimestampPort>>,
    openai_files: Option<Arc<dyn HttpOperationProtocolAdapter>>,
    openai_batch: Option<Arc<dyn HttpOperationProtocolAdapter>>,
    openai_realtime: Option<(Arc<dyn HttpUpgradeProtocolAdapter>, ProtocolUpgradeLimits)>,
}

struct OpenAiCompatibilityInputs {
    models: Option<Arc<OpenAiModelCatalog>>,
    speech_output: Option<AudioOutputSpecification>,
    timestamp: Option<Arc<dyn OpenAiTimestampPort>>,
    files: Option<Arc<dyn HttpOperationProtocolAdapter>>,
    batch: Option<Arc<dyn HttpOperationProtocolAdapter>>,
    realtime: Option<(Arc<dyn HttpUpgradeProtocolAdapter>, ProtocolUpgradeLimits)>,
}

impl PublicApiInputs {
    /// Creates production assembly inputs from the required HTTP capabilities.
    ///
    /// The supplied shutdown token is shared by every request admitted through the
    /// assembled router. No I/O or capability lookup occurs during construction.
    #[must_use]
    pub fn new(
        identity: Arc<dyn RequestIdentityPort>,
        authentication: Arc<dyn ServiceAuthenticationPort>,
        dispatch: Arc<dyn ServiceDispatchPort>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            identity,
            authentication,
            dispatch,
            shutdown,
            stream_bridge: None,
            file_service: None,
            openai_models: None,
            openai_speech_output: None,
            openai_timestamp: None,
            openai_files: None,
            openai_batch: None,
            openai_realtime: None,
        }
    }

    /// Installs the optional native streaming bridge for this assembly.
    #[must_use]
    pub fn with_stream_bridge(mut self, bridge: Arc<dyn ServiceStreamBridgePort>) -> Self {
        self.stream_bridge = Some(bridge);
        self
    }

    /// Installs the optional authenticated durable-file service for this assembly.
    #[must_use]
    pub fn with_file_service(mut self, service: Arc<dyn FileServicePort>) -> Self {
        self.file_service = Some(service);
        self
    }

    /// Installs the immutable model catalog for the OpenAI compatibility profile.
    #[must_use]
    pub fn with_openai_models(mut self, catalog: Arc<OpenAiModelCatalog>) -> Self {
        self.openai_models = Some(catalog);
        self
    }

    /// Installs the explicit raw-WAV output capability for OpenAI Speech.
    #[must_use]
    pub const fn with_openai_speech_output(mut self, output: AudioOutputSpecification) -> Self {
        self.openai_speech_output = Some(output);
        self
    }

    /// Installs the authoritative UTC timestamp source for OpenAI time-bearing routes.
    #[must_use]
    pub fn with_openai_timestamp(mut self, timestamp: Arc<dyn OpenAiTimestampPort>) -> Self {
        self.openai_timestamp = Some(timestamp);
        self
    }

    /// Installs the provider-neutral OpenAI Files compatibility capability.
    #[must_use]
    pub fn with_openai_files(mut self, files: Arc<dyn HttpOperationProtocolAdapter>) -> Self {
        self.openai_files = Some(files);
        self
    }

    /// Installs the durable OpenAI Batch operation capability.
    #[must_use]
    pub fn with_openai_batch(mut self, batch: Arc<dyn HttpOperationProtocolAdapter>) -> Self {
        self.openai_batch = Some(batch);
        self
    }

    /// Installs the OpenAI Realtime WebSocket transport capability.
    #[must_use]
    pub fn with_openai_realtime(
        mut self,
        realtime: Arc<dyn HttpUpgradeProtocolAdapter>,
        limits: ProtocolUpgradeLimits,
    ) -> Self {
        self.openai_realtime = Some((realtime, limits));
        self
    }
}

/// Constructs the durable file service from a live typed catalog capability.
///
/// The catalog handle is validated for cancellation and generation freshness before
/// the service retains its catalog view. The issuer and asset storage ports are
/// already constructed by the runtime owner; this function never opens paths,
/// sessions, keys, configuration, or listeners. The concrete owner is returned so
/// the runtime can call [`DurableFileService::shutdown`] and join its worker before
/// invalidating storage capabilities. Callers may coerce the returned `Arc` to an
/// `Arc<dyn FileServicePort>` for [`PublicApiInputs::with_file_service`].
///
/// # Errors
///
/// Returns the catalog handle's stable cancellation or unavailable error when the
/// handle is inactive or stale. No service is returned in that case.
pub fn assemble_durable_file_service(
    catalog: ariadnion_core::PortHandle<dyn FileCatalogServicePort>,
    issuer: Arc<dyn FileReferenceIssuerPort>,
    assets: Arc<dyn LocalVolumeAssetStoragePort>,
) -> Result<Arc<DurableFileService>, CoreError> {
    let catalog = catalog.service()?;
    Ok(Arc::new(DurableFileService::new(catalog, issuer, assets)))
}

/// Assembles exactly one dependency-injected standard public API profile.
///
/// `Native` receives Ariadnion-native routes, while `Compatibility` receives only
/// the fixed OpenAI-compatible routes described by
/// [`STANDARD_COMPATIBILITY_PROTOCOL_FAMILIES`]. The same fully configured HTTP
/// state is passed to the selected router; profiles are never merged, selected by
/// request content, or served by this function. Listener ownership and process
/// shutdown remain outside the bundle in P10.
///
/// Missing optional stream or file capabilities remain absent and therefore fail
/// closed at their existing HTTP boundaries. Once the typed inputs exist, assembly
/// performs no fallible external work and returns the selected router directly.
#[must_use = "retain the assembled router for the runtime owner"]
pub fn assemble_public_api(
    profile: StandardPublicApiProfile,
    inputs: PublicApiInputs,
) -> PublicApiRouter {
    let PublicApiInputs {
        identity,
        authentication,
        dispatch,
        shutdown,
        stream_bridge,
        file_service,
        openai_models,
        openai_speech_output,
        openai_timestamp,
        openai_files,
        openai_batch,
        openai_realtime,
    } = inputs;
    let state = apply_http_capabilities(
        HttpApiState::new(identity, authentication, dispatch, shutdown),
        stream_bridge,
        file_service,
    );
    match profile {
        StandardPublicApiProfile::Native => public_router(state),
        StandardPublicApiProfile::Compatibility => mount_openai_compatibility(
            state,
            OpenAiCompatibilityInputs {
                models: openai_models,
                speech_output: openai_speech_output,
                timestamp: openai_timestamp,
                files: openai_files,
                batch: openai_batch,
                realtime: openai_realtime,
            },
        ),
    }
}

fn apply_http_capabilities(
    mut state: HttpApiState,
    stream_bridge: Option<Arc<dyn ServiceStreamBridgePort>>,
    file_service: Option<Arc<dyn FileServicePort>>,
) -> HttpApiState {
    if let Some(bridge) = stream_bridge {
        state = state.with_stream_bridge(bridge);
    }
    if let Some(service) = file_service {
        state = state.with_file_service(service);
    }
    state
}

fn mount_openai_compatibility(
    state: HttpApiState,
    inputs: OpenAiCompatibilityInputs,
) -> PublicApiRouter {
    let OpenAiCompatibilityInputs {
        models,
        speech_output,
        timestamp,
        files,
        batch,
        realtime,
    } = inputs;
    let mut manifest = OpenAiRouteManifest::new();
    if let Some(catalog) = models {
        manifest = manifest.with_models(catalog);
    }
    if let Some(output) = speech_output {
        manifest = manifest.with_speech_output(output);
    }
    if let Some(clock) = timestamp {
        manifest = manifest.with_timestamp(clock);
    }
    if let Some(adapter) = files {
        manifest = manifest.with_files_adapter(adapter);
    }
    if let Some(adapter) = batch {
        manifest = manifest.with_batch_adapter(adapter);
    }
    if let Some((adapter, limits)) = realtime {
        manifest = manifest.with_realtime_adapter(adapter, limits);
    }
    manifest.mount(state)
}

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
/// [`STANDARD_COMPATIBILITY_PROTOCOL_FAMILIES`].
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
/// use ariadnion_bundle_standard::{
///     assemble_mock_public_api, StandardPublicApiProfile,
/// };
/// use ariadnion_core::CoreError;
///
/// fn assemble_for_verification(
///     authentication: Arc<dyn ServiceAuthenticationPort>,
/// ) -> Result<(), CoreError> {
///     let router = assemble_mock_public_api(
///         StandardPublicApiProfile::Compatibility,
///         authentication,
///     )?;
///     let _ = router;
///     Ok(())
/// }
/// ```
pub fn assemble_mock_public_api(
    profile: StandardPublicApiProfile,
    authentication: Arc<dyn ServiceAuthenticationPort>,
) -> Result<PublicApiRouter, CoreError> {
    match profile {
        StandardPublicApiProfile::Native => assemble_native_text_mock_loop(authentication),
        StandardPublicApiProfile::Compatibility => assemble_openai_mock_loop(authentication),
    }
}

/// Assembles the standard bundle's bounded OpenAI-compatible mock loop.
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
    let provider = Arc::new(
        DeterministicMockProvider::new()
            .map_err(|_| assembly_error("standard mock provider is unavailable"))?,
    );
    assemble_openai_mock_loop_with_provider(authentication, provider)
}

/// Assembles the standard bundle's bounded OpenAI-compatible loop with a provider.
///
/// The bundle retains ownership of model resolution, dispatch, request and attempt
/// identities, cancellation, authentication, and OpenAI response projection. The
/// caller-provided provider is used only for the provider execution boundary.
///
/// # Errors
///
/// Returns a redacted internal error if a fixed selector, provider model, resolver,
/// or request identity issuer cannot be constructed.
pub fn assemble_openai_mock_loop_with_provider(
    authentication: Arc<dyn ServiceAuthenticationPort>,
    provider: Arc<dyn ProviderPort>,
) -> Result<OpenAiChatCompletionsRouter, CoreError> {
    let selector = ModelSelector::new("mock-chat")
        .map_err(|_| assembly_error("standard OpenAI selector is invalid"))?;
    let model = ProviderModelId::new(MOCK_PROVIDER_MODEL_ID)
        .map_err(|_| assembly_error("standard mock provider model is invalid"))?;
    let resolver = StaticProviderModelResolver::new([(selector, model)])
        .map_err(|_| assembly_error("standard model mapping is invalid"))?;
    let dispatcher = Arc::new(ProviderDispatcher::new(
        Arc::new(resolver),
        Arc::new(MonotonicAttemptIdIssuer::new()),
        provider,
    ));
    let identity = Arc::new(
        MonotonicRequestIdentityIssuer::new()
            .map_err(|_| assembly_error("standard request identity is unavailable"))?,
    );
    let state = HttpApiState::new(
        identity,
        authentication,
        dispatcher,
        CancellationToken::new(),
    );
    Ok(openai_chat_completions_router(state))
}

/// Assembles the standard bundle's Ariadnion-native mock loop.
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
            .map_err(|_| assembly_error("standard native mock provider is unavailable"))?,
    );
    let resolver = native_model_resolver()?;
    let dispatcher = Arc::new(ProviderDispatcher::new(
        Arc::new(resolver),
        Arc::new(MonotonicAttemptIdIssuer::new()),
        provider,
    ));
    let identity = Arc::new(
        MonotonicRequestIdentityIssuer::new()
            .map_err(|_| assembly_error("standard native request identity is unavailable"))?,
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
        .map_err(|_| assembly_error("standard native text selector is invalid"))?;
    let text_model = ProviderModelId::new(MOCK_PROVIDER_TEXT_MODEL_ID)
        .map_err(|_| assembly_error("standard native text provider model is invalid"))?;
    let embedding_selector = ModelSelector::new("mock-embedding")
        .map_err(|_| assembly_error("standard native embedding selector is invalid"))?;
    let embedding_model = ProviderModelId::new(MOCK_PROVIDER_EMBEDDING_MODEL_ID)
        .map_err(|_| assembly_error("standard native embedding provider model is invalid"))?;
    let image_selector = ModelSelector::new("mock-image")
        .map_err(|_| assembly_error("standard native image selector is invalid"))?;
    let image_model = ProviderModelId::new(MOCK_PROVIDER_IMAGE_MODEL_ID)
        .map_err(|_| assembly_error("standard native image provider model is invalid"))?;
    let audio_mapping = native_audio_mapping()?;
    StaticProviderModelResolver::new([
        (text_selector, text_model),
        (embedding_selector, embedding_model),
        (image_selector, image_model),
        audio_mapping,
    ])
    .map_err(|_| assembly_error("standard native model mapping is invalid"))
}

fn native_audio_mapping() -> Result<(ModelSelector, ProviderModelId), CoreError> {
    let selector = ModelSelector::new("mock-audio")
        .map_err(|_| assembly_error("standard native audio selector is invalid"))?;
    let model = ProviderModelId::new(MOCK_PROVIDER_AUDIO_MODEL_ID)
        .map_err(|_| assembly_error("standard native audio provider model is invalid"))?;
    Ok((selector, model))
}

fn assembly_error(context: &'static str) -> CoreError {
    CoreError::from_code(ErrorCode::Internal).with_internal_context(context)
}

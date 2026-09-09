// crates/optional/ariadnion-protocol-openai/src/models.rs - OpenAI Models list adapter for Ariadnion.
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
//! Bounded OpenAI Models discovery over immutable composition capabilities.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_api_domain::{ApiDomainError, ApiDomainErrorCode, ModelSelector};
use ariadnion_api_http::{
    HttpApiState, HttpGetProtocolAdapter, HttpRequestIdentity, ProtocolBufferedResponse,
    ProtocolFailure, ProtocolGetExecutionState, protocol_get_route,
};
use ariadnion_core::RequestContext;
use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;

/// The OpenAI-compatible Models list path.
pub const OPENAI_MODELS_PATH: &str = "/v1/models";

/// Maximum number of immutable model descriptors exposed by one profile.
pub const MAX_OPENAI_MODELS: usize = 1_000;

/// Maximum UTF-8 byte length of one model owner label.
pub const MAX_MODEL_OWNER_BYTES: usize = 256;

/// A bounded immutable model descriptor exposed by a selected public profile.
///
/// The descriptor contains only public capability evidence. It does not carry
/// account IDs, credentials, health, quota, cost, routing, or provider state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiModelDescriptor {
    id: ModelSelector,
    created: u64,
    owned_by: Box<str>,
    shutdown_date: Option<u64>,
}

impl OpenAiModelDescriptor {
    /// Creates a bounded immutable descriptor for one public model.
    ///
    /// `id` uses the shared provider-neutral model-selector bounds. `owned_by`
    /// is non-empty, trimmed, control-free, and limited to 256 UTF-8 bytes.
    /// `shutdown_date` is optional owner evidence and is never synthesized.
    ///
    /// # Errors
    ///
    /// Returns [`ApiDomainErrorCode::InvalidArgument`] for empty, trimmed, or
    /// control-containing values and [`ApiDomainErrorCode::LimitExceeded`] for
    /// values beyond the fixed byte bounds.
    pub fn new(
        id: &str,
        created: u64,
        owned_by: &str,
        shutdown_date: Option<u64>,
    ) -> Result<Self, ApiDomainError> {
        let id = ModelSelector::new(id)?;
        validate_owner(owned_by)?;
        Ok(Self {
            id,
            created,
            owned_by: owned_by.into(),
            shutdown_date,
        })
    }

    /// Returns the public model identifier.
    #[must_use]
    pub fn id(&self) -> &ModelSelector {
        &self.id
    }

    /// Returns the owner-provided creation timestamp in Unix seconds.
    #[must_use]
    pub const fn created(&self) -> u64 {
        self.created
    }

    /// Returns the public owner label.
    #[must_use]
    pub fn owned_by(&self) -> &str {
        &self.owned_by
    }

    /// Returns the optional owner-provided shutdown timestamp.
    #[must_use]
    pub const fn shutdown_date(&self) -> Option<u64> {
        self.shutdown_date
    }
}

/// A sorted, duplicate-free immutable model-list capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiModelCatalog {
    models: Arc<[OpenAiModelDescriptor]>,
}

impl OpenAiModelCatalog {
    /// Validates and freezes a static model capability for one public profile.
    ///
    /// Entries are sorted by the UTF-8 bytes of their public IDs, which gives a
    /// deterministic ASCII-compatible order for the profile's stable model names.
    /// The iterator is consumed only up to `MAX_OPENAI_MODELS + 1`; overflow is
    /// rejected rather than silently truncated.
    ///
    /// # Errors
    ///
    /// Returns [`ApiDomainErrorCode::InvalidArgument`] for duplicate IDs and
    /// [`ApiDomainErrorCode::LimitExceeded`] when more than 1,000 entries are
    /// supplied.
    pub fn new<I>(models: I) -> Result<Self, ApiDomainError>
    where
        I: IntoIterator<Item = OpenAiModelDescriptor>,
    {
        let iterator = models.into_iter();
        let capacity = iterator
            .size_hint()
            .0
            .min(MAX_OPENAI_MODELS.saturating_add(1));
        let mut models = Vec::with_capacity(capacity);
        for model in iterator {
            if models.len() >= MAX_OPENAI_MODELS {
                return Err(limit_exceeded());
            }
            models.push(model);
        }
        models.sort_unstable_by(|left, right| {
            left.id
                .as_str()
                .as_bytes()
                .cmp(right.id.as_str().as_bytes())
        });
        if models
            .windows(2)
            .any(|pair| pair[0].id.as_str() == pair[1].id.as_str())
        {
            return Err(invalid_argument());
        }
        Ok(Self {
            models: Arc::from(models.into_boxed_slice()),
        })
    }

    /// Borrows the deterministic public model descriptors.
    #[must_use]
    pub fn models(&self) -> &[OpenAiModelDescriptor] {
        &self.models
    }
}

/// The concrete HTTP router returned by the OpenAI Models adapter.
pub type OpenAiModelsRouter = Router;

/// Stateless protocol adapter over one immutable model-list capability.
pub struct OpenAiModelsProtocol {
    catalog: Arc<OpenAiModelCatalog>,
}

impl OpenAiModelsProtocol {
    /// Creates a Models adapter that does not access persistence or provider state.
    #[must_use]
    pub const fn new(catalog: Arc<OpenAiModelCatalog>) -> Self {
        Self { catalog }
    }
}

impl Debug for OpenAiModelsProtocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiModelsProtocol")
            .field("model_count", &self.catalog.models().len())
            .finish()
    }
}

impl HttpGetProtocolAdapter for OpenAiModelsProtocol {
    fn validate_target(&self, query: Option<&str>) -> Result<(), ProtocolFailure> {
        if query.is_some() {
            return Err(invalid_request().into());
        }
        Ok(())
    }

    fn project_get(
        &self,
        _identity: &HttpRequestIdentity,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        check_active(context)?;
        let data = self
            .catalog
            .models()
            .iter()
            .map(ModelWire::from_descriptor)
            .collect::<Vec<_>>();
        let body = ModelsWire {
            object: "list",
            data,
        };
        let encoded = serde_json::to_vec(&body).map_err(|_| internal_failure())?;
        check_active(context)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        ProtocolBufferedResponse::new(StatusCode::OK, headers, Bytes::from(encoded))
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        crate::response::project_failure(identity, failure)
    }
}

/// Mounts the authenticated OpenAI Models list route over shared HTTP state.
///
/// The router owns only `GET /v1/models`; it does not mount retrieve/delete
/// routes, query pagination, or mutable model operations.
pub fn openai_models_router(
    http: HttpApiState,
    catalog: Arc<OpenAiModelCatalog>,
) -> OpenAiModelsRouter {
    let protocol: Arc<dyn HttpGetProtocolAdapter> = Arc::new(OpenAiModelsProtocol::new(catalog));
    let state = ProtocolGetExecutionState::new(http, protocol);
    Router::new()
        .route(OPENAI_MODELS_PATH, protocol_get_route())
        .with_state(state)
}

fn validate_owner(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_MODEL_OWNER_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn check_active(context: &RequestContext) -> Result<(), ProtocolFailure> {
    context
        .check_active()
        .map_err(ApiDomainError::from)
        .map_err(ProtocolFailure::from)
}

const fn invalid_request() -> ariadnion_api_http::ApiHttpError {
    ariadnion_api_http::ApiHttpError::new(ariadnion_api_http::ApiHttpErrorCode::InvalidRequest)
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ariadnion_api_http::ApiHttpError::new(
        ariadnion_api_http::ApiHttpErrorCode::Internal,
    ))
}

const fn invalid_argument() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::InvalidArgument)
}

const fn limit_exceeded() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::LimitExceeded)
}

#[derive(Serialize)]
struct ModelsWire<'a> {
    object: &'static str,
    data: Vec<ModelWire<'a>>,
}

#[derive(Serialize)]
struct ModelWire<'a> {
    id: &'a str,
    object: &'static str,
    created: u64,
    owned_by: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    shutdown_date: Option<u64>,
}

impl<'a> ModelWire<'a> {
    fn from_descriptor(model: &'a OpenAiModelDescriptor) -> Self {
        Self {
            id: model.id().as_str(),
            object: "model",
            created: model.created(),
            owned_by: model.owned_by(),
            shutdown_date: model.shutdown_date(),
        }
    }
}

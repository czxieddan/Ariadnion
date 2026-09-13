// crates/optional/ariadnion-protocol-openai/src/batch_http.rs - OpenAI Batch HTTP adapter.
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
//! Authenticated OpenAI Batch lifecycle projection over typed Ariadnion ports.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_api_domain::{
    ApiBatchErrorCode, BatchCancelRequest, BatchCreateRequest, BatchEndpoint, BatchListLimit,
    BatchListRequest, BatchOperation, BatchOperationId, FileReference, IdempotencyKey,
    MAX_BATCH_INPUT_BYTES, MAX_BATCH_REQUESTS,
};
use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, FileChunk, FileDownloadSink, FileServicePort,
};
use ariadnion_api_http::{
    BoxProtocolOperationFuture, HttpOperationProtocolAdapter, HttpRequestIdentity,
    ProtocolBufferedResponse, ProtocolFailure, ProtocolOperationResponse,
};
use ariadnion_core::RequestContext;
use ariadnion_provider_files::{
    ProviderFileId, ProviderFileMappingPort, ProviderFileScope, ProviderFilesError,
};
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use serde_json::{Value, json};

use crate::batch::{BatchCreateBody, parse_create_members, validate_jsonl_with};
use crate::files_http::{require_bodyless, require_no_query};

/// Batch collection route.
pub const OPENAI_BATCH_HTTP_PATH: &str = "/v1/batches";

const MAX_CREATE_BODY_BYTES: usize = 64 * 1024;

/// Authenticated Batch operation adapter.
///
/// The operation port owns durable IDs, lifecycle transitions, recovery, and
/// expiry. File mappings and content are required for create and for projecting
/// file IDs; when any required capability is absent the adapter fails closed.
pub struct OpenAiBatchHttpAdapter {
    port: Option<Arc<dyn ariadnion_api_domain::BatchOperationPort>>,
    mappings: Option<Arc<dyn ProviderFileMappingPort>>,
    files: Option<Arc<dyn FileServicePort>>,
    scope: Option<ProviderFileScope>,
}

impl OpenAiBatchHttpAdapter {
    /// Creates an adapter with only a durable operation port.
    ///
    /// Retrieval and listing remain unavailable until a file mapping scope is
    /// supplied because every public file ID must cross that capability.
    #[must_use]
    pub const fn new(port: Option<Arc<dyn ariadnion_api_domain::BatchOperationPort>>) -> Self {
        Self {
            port,
            mappings: None,
            files: None,
            scope: None,
        }
    }

    /// Adds the provider-file mapping and content capabilities used by Batch.
    #[must_use]
    pub fn with_file_capabilities(
        mut self,
        mappings: Arc<dyn ProviderFileMappingPort>,
        files: Arc<dyn FileServicePort>,
        scope: ProviderFileScope,
    ) -> Self {
        self.mappings = Some(mappings);
        self.files = Some(files);
        self.scope = Some(scope);
        self
    }
}

struct DecodedCreate {
    input_file_id: Box<str>,
    endpoint: BatchEndpoint,
    completion_window: ariadnion_api_domain::BatchCompletionWindow,
    idempotency: IdempotencyKey,
}

async fn decode_create_request(
    request: Request<Body>,
    identity: &HttpRequestIdentity,
    context: &RequestContext,
) -> Result<DecodedCreate, ProtocolFailure> {
    require_json(request.headers())?;
    let idempotency = header_idempotency(request.headers(), identity)?;
    context.check_active().map_err(|error| {
        ProtocolFailure::from(ariadnion_api_domain::ApiDomainError::from(error))
    })?;
    let body = to_bytes(request.into_body(), MAX_CREATE_BODY_BYTES)
        .await
        .map_err(|_| body_read_failure(context))?;
    let decoded: BatchCreateBody<'_> = serde_json::from_slice(&body).map_err(|_| invalid())?;
    let (endpoint, completion_window) =
        parse_create_members(decoded.endpoint, decoded.completion_window).map_err(map_batch)?;
    Ok(DecodedCreate {
        input_file_id: decoded.input_file_id.into(),
        endpoint,
        completion_window,
        idempotency,
    })
}

fn validate_batch_mapping(
    mapping: &ariadnion_provider_files::ProviderFileMapping,
) -> Result<(), ProtocolFailure> {
    if mapping.purpose().is_batch() {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn validate_batch_content(
    sink: &BatchContentSink,
    descriptor: &ariadnion_api_domain::FileDescriptor,
    reference: &FileReference,
) -> Result<(), ProtocolFailure> {
    if sink.is_complete() && descriptor.reference() == reference {
        Ok(())
    } else {
        Err(integrity())
    }
}

fn validate_batch_jsonl_content(
    sink: &BatchContentSink,
    reference: FileReference,
    endpoint: BatchEndpoint,
) -> Result<ariadnion_api_domain::BatchInputFile, ariadnion_api_domain::ApiBatchError> {
    let mut embedding_inputs = 0_usize;
    validate_jsonl_with(
        &sink.bytes,
        reference,
        endpoint,
        |line_endpoint, line_body| {
            crate::validate_batch_endpoint_body(line_endpoint, line_body)?;
            if line_endpoint == BatchEndpoint::Embeddings {
                let count = embedding_input_count(line_body)?;
                embedding_inputs = embedding_inputs
                    .checked_add(count)
                    .ok_or_else(batch_limit_error)?;
                if embedding_inputs > MAX_BATCH_REQUESTS {
                    return Err(batch_limit_error());
                }
            }
            Ok(())
        },
    )
}

fn batch_limit_error() -> ariadnion_api_domain::ApiBatchError {
    ariadnion_api_domain::ApiBatchError::new(ApiBatchErrorCode::LimitExceeded)
}

impl HttpOperationProtocolAdapter for OpenAiBatchHttpAdapter {
    fn execute<'a>(
        &'a self,
        request: Request<Body>,
        identity: &'a HttpRequestIdentity,
        context: &'a RequestContext,
    ) -> BoxProtocolOperationFuture<'a> {
        Box::pin(async move {
            context.check_active().map_err(|error| {
                ProtocolFailure::from(ariadnion_api_domain::ApiDomainError::from(error))
            })?;
            let path = request.uri().path().to_owned();
            let query = request.uri().query().map(str::to_owned);
            let method = request.method().clone();
            let result = self
                .dispatch(method, path, query.as_deref(), request, identity, context)
                .await?;
            Ok(ProtocolOperationResponse::Buffered(result))
        })
    }

    fn project_failure(
        &self,
        identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        crate::response::project_failure(identity, failure)
    }
}

impl OpenAiBatchHttpAdapter {
    async fn dispatch(
        &self,
        method: Method,
        path: String,
        query: Option<&str>,
        request: Request<Body>,
        identity: &HttpRequestIdentity,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        match route_kind(&path) {
            RouteKind::Collection => {
                self.dispatch_collection(method, query, request, identity, context)
                    .await
            }
            RouteKind::Retrieve(id) => {
                if method != Method::GET {
                    return Err(invalid());
                }
                require_no_query(query)?;
                require_bodyless(&request)?;
                self.retrieve(id, context).await
            }
            RouteKind::Cancel(id) => {
                if method != Method::POST {
                    return Err(invalid());
                }
                require_no_query(query)?;
                require_bodyless(&request)?;
                self.cancel(id, context).await
            }
            RouteKind::Unsupported => Err(invalid()),
        }
    }

    async fn dispatch_collection(
        &self,
        method: Method,
        query: Option<&str>,
        request: Request<Body>,
        identity: &HttpRequestIdentity,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        match method {
            Method::GET => {
                require_bodyless(&request)?;
                self.list(query, context).await
            }
            Method::POST => {
                require_no_query(query)?;
                self.create(request, identity, context).await
            }
            _ => Err(invalid()),
        }
    }

}

#[derive(Clone, Copy)]
enum RouteKind<'a> {
    Collection,
    Retrieve(&'a str),
    Cancel(&'a str),
    Unsupported,
}

fn route_kind(path: &str) -> RouteKind<'_> {
    if path == OPENAI_BATCH_HTTP_PATH {
        return RouteKind::Collection;
    }
    let Some(suffix) = path.strip_prefix("/v1/batches/") else {
        return RouteKind::Unsupported;
    };
    if let Some(id) = suffix.strip_suffix("/cancel") {
        return RouteKind::Cancel(id);
    }
    RouteKind::Retrieve(suffix)
}

impl OpenAiBatchHttpAdapter {
    async fn retrieve(
        &self,
        id: &str,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let port = self.port.as_ref().ok_or_else(unavailable)?;
        let operation_id = BatchOperationId::parse(id).map_err(|_| invalid())?;
        let operation = port
            .retrieve(&operation_id, context)
            .await
            .map_err(map_batch)?;
        self.project_operation(operation, context).await
    }

    async fn list(
        &self,
        query: Option<&str>,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let port = self.port.as_ref().ok_or_else(unavailable)?;
        let request = parse_list_request(query)?;
        let page = port.list(&request, context).await.map_err(map_batch)?;
        let mut data = Vec::with_capacity(page.data().len());
        for operation in page.data() {
            data.push(self.operation_value(operation, context).await?);
        }
        response(
            StatusCode::OK,
            json!({
                "object": "list",
                "data": data,
                "first_id": page.first_id().map(ToString::to_string),
                "last_id": page.last_id().map(ToString::to_string),
                "has_more": page.has_more(),
            }),
        )
    }

    async fn cancel(
        &self,
        id: &str,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let port = self.port.as_ref().ok_or_else(unavailable)?;
        let operation_id = BatchOperationId::parse(id).map_err(|_| invalid())?;
        let operation = port
            .cancel(BatchCancelRequest::new(operation_id, None), context)
            .await
            .map_err(map_batch)?;
        self.project_operation(operation, context).await
    }

    async fn create(
        &self,
        request: Request<Body>,
        identity: &HttpRequestIdentity,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let port = self.port.as_ref().ok_or_else(unavailable)?;
        let decoded = decode_create_request(request, identity, context).await?;
        let input = self
            .load_input(&decoded.input_file_id, decoded.endpoint, context)
            .await?;
        let request = BatchCreateRequest::new(
            input,
            decoded.endpoint,
            decoded.completion_window,
            Some(decoded.idempotency),
        )
        .map_err(map_batch)?;
        let operation = port.create(request, context).await.map_err(map_batch)?;
        self.project_operation(operation, context).await
    }

    async fn load_input(
        &self,
        input_file_id: &str,
        endpoint: BatchEndpoint,
        context: &RequestContext,
    ) -> Result<ariadnion_api_domain::BatchInputFile, ProtocolFailure> {
        let mapping = self.resolve_batch_mapping(input_file_id, context).await?;
        validate_batch_mapping(&mapping)?;
        let (sink, descriptor) = self.download_batch_content(&mapping, context).await?;
        validate_batch_content(&sink, &descriptor, mapping.file_reference())?;
        validate_batch_jsonl_content(&sink, *mapping.file_reference(), endpoint).map_err(map_batch)
    }

    async fn resolve_batch_mapping(
        &self,
        input_file_id: &str,
        context: &RequestContext,
    ) -> Result<ariadnion_provider_files::ProviderFileMapping, ProtocolFailure> {
        let mappings = self.mappings.as_ref().ok_or_else(unavailable)?;
        let scope = self.scope.as_ref().ok_or_else(unavailable)?;
        let provider_id = ProviderFileId::new(input_file_id).map_err(|_| invalid())?;
        mappings
            .resolve(scope.lookup(provider_id), context)
            .await
            .map_err(map_provider)
    }

    async fn download_batch_content(
        &self,
        mapping: &ariadnion_provider_files::ProviderFileMapping,
        context: &RequestContext,
    ) -> Result<(BatchContentSink, ariadnion_api_domain::FileDescriptor), ProtocolFailure> {
        let files = self.files.as_ref().ok_or_else(unavailable)?;
        let mut sink = BatchContentSink::new();
        let descriptor = files
            .content(mapping.file_reference(), &mut sink, context)
            .await
            .map_err(map_files)?;
        Ok((sink, descriptor))
    }

    async fn project_operation(
        &self,
        operation: BatchOperation,
        context: &RequestContext,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        response(
            StatusCode::OK,
            self.operation_value(&operation, context).await?,
        )
    }

    async fn operation_value(
        &self,
        operation: &BatchOperation,
        context: &RequestContext,
    ) -> Result<Value, ProtocolFailure> {
        let input_file_id = self.file_alias(operation.input_file(), context).await?;
        let output_file_id = self
            .optional_file_alias(operation.output_file(), context)
            .await?;
        let error_file_id = self
            .optional_file_alias(operation.error_file(), context)
            .await?;
        let timestamps = operation.timestamps();
        let created_at = unix_seconds(timestamps.created_at()).ok_or_else(unavailable)?;
        Ok(json!({
            "id": operation.id().as_str(),
            "object": operation.object(),
            "endpoint": operation.endpoint().as_str(),
            "input_file_id": input_file_id,
            "completion_window": operation.completion_window().as_str(),
            "status": operation.status().as_str(),
            "created_at": created_at,
            "in_progress_at": timestamps.in_progress_at().and_then(unix_seconds),
            "expires_at": timestamps.expires_at().and_then(unix_seconds),
            "finalizing_at": timestamps.finalizing_at().and_then(unix_seconds),
            "completed_at": timestamps.completed_at().and_then(unix_seconds),
            "failed_at": timestamps.failed_at().and_then(unix_seconds),
            "expired_at": timestamps.expired_at().and_then(unix_seconds),
            "cancelling_at": timestamps.cancelling_at().and_then(unix_seconds),
            "cancelled_at": timestamps.cancelled_at().and_then(unix_seconds),
            "output_file_id": output_file_id,
            "error_file_id": error_file_id,
            "errors": operation.errors().iter().map(error_value).collect::<Vec<_>>(),
            "request_counts": {
                "total": operation.request_counts().total(),
                "completed": operation.request_counts().completed(),
                "failed": operation.request_counts().failed(),
            },
        }))
    }

    async fn file_alias(
        &self,
        reference: &FileReference,
        context: &RequestContext,
    ) -> Result<String, ProtocolFailure> {
        let mappings = self.mappings.as_ref().ok_or_else(unavailable)?;
        let scope = self.scope.as_ref().ok_or_else(unavailable)?;
        let mapping = mappings
            .resolve_reference(scope.clone(), *reference, context)
            .await
            .map_err(map_provider)?;
        Ok(mapping.provider_file_id().as_str().to_owned())
    }

    async fn optional_file_alias(
        &self,
        reference: Option<&FileReference>,
        context: &RequestContext,
    ) -> Result<Option<String>, ProtocolFailure> {
        match reference {
            Some(reference) => self.file_alias(reference, context).await.map(Some),
            None => Ok(None),
        }
    }
}

fn parse_list_request(query: Option<&str>) -> Result<BatchListRequest, ProtocolFailure> {
    let Some(query) = query else {
        return Ok(BatchListRequest::new(None, BatchListLimit::default()));
    };
    if query.is_empty() {
        return Err(invalid());
    }
    let mut state = ListQueryState::default();
    for component in query.split('&') {
        parse_list_component(component, &mut state)?;
    }
    Ok(BatchListRequest::new(state.after, state.limit))
}

#[derive(Default)]
struct ListQueryState {
    after: Option<BatchOperationId>,
    limit: BatchListLimit,
    limit_seen: bool,
}

fn parse_list_component(
    component: &str,
    state: &mut ListQueryState,
) -> Result<(), ProtocolFailure> {
    let (name, value) = component.split_once('=').ok_or_else(invalid)?;
    match name {
        "after" => parse_after_component(value, state),
        "limit" => parse_limit_component(value, state),
        _ => Err(invalid()),
    }
}

fn parse_after_component(value: &str, state: &mut ListQueryState) -> Result<(), ProtocolFailure> {
    if state.after.is_some() {
        return Err(invalid());
    }
    state.after = Some(BatchOperationId::parse(value).map_err(|_| invalid())?);
    Ok(())
}

fn parse_limit_component(value: &str, state: &mut ListQueryState) -> Result<(), ProtocolFailure> {
    if state.limit_seen {
        return Err(invalid());
    }
    let parsed = value.parse::<usize>().map_err(|_| invalid())?;
    state.limit = BatchListLimit::new(parsed).map_err(|_| invalid())?;
    state.limit_seen = true;
    Ok(())
}

fn require_json(headers: &HeaderMap) -> Result<(), ProtocolFailure> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(unsupported_media_type());
    };
    if values.next().is_some() {
        return Err(invalid());
    }
    let value = value.to_str().map_err(|_| unsupported_media_type())?;
    if value.split(';').next().map(str::trim) == Some("application/json") {
        Ok(())
    } else {
        Err(unsupported_media_type())
    }
}

fn embedding_input_count(body: &str) -> Result<usize, ariadnion_api_domain::ApiBatchError> {
    let value: Value = serde_json::from_str(body).map_err(|_| batch_invalid())?;
    let Some(input) = value.get("input") else {
        return Err(batch_invalid());
    };
    match input {
        Value::String(_) => Ok(1),
        Value::Array(values) => Ok(values.len()),
        _ => Err(batch_invalid()),
    }
}

fn batch_invalid() -> ariadnion_api_domain::ApiBatchError {
    ariadnion_api_domain::ApiBatchError::new(ApiBatchErrorCode::InvalidArgument)
}

fn header_idempotency(
    headers: &HeaderMap,
    identity: &HttpRequestIdentity,
) -> Result<IdempotencyKey, ProtocolFailure> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return IdempotencyKey::new(identity.request_id().as_str()).map_err(|_| invalid());
    };
    if values.next().is_some() {
        return Err(invalid());
    }
    let value = value.to_str().map_err(|_| invalid())?;
    IdempotencyKey::new(value).map_err(|_| invalid())
}

fn error_value(error: &ariadnion_api_domain::BatchValidationError) -> Value {
    json!({"code": error.code().as_str(), "line": error.line()})
}

fn unix_seconds(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn response(status: StatusCode, value: Value) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
    let body = serde_json::to_vec(&value).map_err(|_| unavailable())?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    ProtocolBufferedResponse::new(status, headers, Bytes::from(body))
}

fn map_batch(error: ariadnion_api_domain::ApiBatchError) -> ProtocolFailure {
    match error.code() {
        ApiBatchErrorCode::InvalidArgument => invalid(),
        ApiBatchErrorCode::LimitExceeded => payload_too_large(),
        ApiBatchErrorCode::Cancelled
        | ApiBatchErrorCode::DeadlineExceeded
        | ApiBatchErrorCode::ResourceExhausted => map_batch_runtime(error.code()),
        _ => map_batch_other(error.code()),
    }
}

fn map_batch_other(code: ApiBatchErrorCode) -> ProtocolFailure {
    match code {
        ApiBatchErrorCode::NotFound => map_not_found(),
        ApiBatchErrorCode::Unavailable => unavailable(),
        ApiBatchErrorCode::Unauthenticated => map_unauthenticated(),
        ApiBatchErrorCode::Conflict => map_conflict(),
        _ => map_internal(),
    }
}

fn map_batch_runtime(code: ApiBatchErrorCode) -> ProtocolFailure {
    match code {
        ApiBatchErrorCode::Cancelled => http_error(ariadnion_api_http::ApiHttpErrorCode::Cancelled),
        ApiBatchErrorCode::DeadlineExceeded => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::DeadlineExceeded)
        }
        ApiBatchErrorCode::ResourceExhausted => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::ResourceExhausted)
        }
        _ => http_error(ariadnion_api_http::ApiHttpErrorCode::Internal),
    }
}

fn map_provider(error: ProviderFilesError) -> ProtocolFailure {
    match error.code() {
        ariadnion_provider_files::ProviderFilesErrorCode::InvalidArgument => invalid(),
        ariadnion_provider_files::ProviderFilesErrorCode::LimitExceeded => payload_too_large(),
        ariadnion_provider_files::ProviderFilesErrorCode::Cancelled
        | ariadnion_provider_files::ProviderFilesErrorCode::DeadlineExceeded
        | ariadnion_provider_files::ProviderFilesErrorCode::ResourceExhausted => {
            map_provider_runtime(error.code())
        }
        _ => map_provider_other(error.code()),
    }
}

fn map_provider_other(code: ariadnion_provider_files::ProviderFilesErrorCode) -> ProtocolFailure {
    match code {
        ariadnion_provider_files::ProviderFilesErrorCode::NotFound => map_not_found(),
        ariadnion_provider_files::ProviderFilesErrorCode::Unavailable => unavailable(),
        ariadnion_provider_files::ProviderFilesErrorCode::Unauthenticated => map_unauthenticated(),
        ariadnion_provider_files::ProviderFilesErrorCode::Conflict => map_conflict(),
        _ => map_internal(),
    }
}

fn map_provider_runtime(code: ariadnion_provider_files::ProviderFilesErrorCode) -> ProtocolFailure {
    match code {
        ariadnion_provider_files::ProviderFilesErrorCode::Cancelled => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::Cancelled)
        }
        ariadnion_provider_files::ProviderFilesErrorCode::DeadlineExceeded => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::DeadlineExceeded)
        }
        ariadnion_provider_files::ProviderFilesErrorCode::ResourceExhausted => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::ResourceExhausted)
        }
        _ => map_internal(),
    }
}

fn map_files(error: ApiFilesError) -> ProtocolFailure {
    match error.code() {
        ApiFilesErrorCode::InvalidArgument => invalid(),
        ApiFilesErrorCode::LimitExceeded => payload_too_large(),
        ApiFilesErrorCode::PolicyRejected => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::Forbidden)
        }
        ApiFilesErrorCode::Cancelled
        | ApiFilesErrorCode::DeadlineExceeded
        | ApiFilesErrorCode::ResourceExhausted => map_files_runtime(error.code()),
        _ => map_files_other(error.code()),
    }
}

fn map_files_other(code: ApiFilesErrorCode) -> ProtocolFailure {
    match code {
        ApiFilesErrorCode::NotFound => map_not_found(),
        ApiFilesErrorCode::Unavailable => unavailable(),
        ApiFilesErrorCode::Unauthenticated => map_unauthenticated(),
        ApiFilesErrorCode::Conflict => map_conflict(),
        _ => map_internal(),
    }
}

fn map_files_runtime(code: ApiFilesErrorCode) -> ProtocolFailure {
    match code {
        ApiFilesErrorCode::Cancelled => http_error(ariadnion_api_http::ApiHttpErrorCode::Cancelled),
        ApiFilesErrorCode::DeadlineExceeded => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::DeadlineExceeded)
        }
        ApiFilesErrorCode::ResourceExhausted => {
            http_error(ariadnion_api_http::ApiHttpErrorCode::ResourceExhausted)
        }
        _ => map_internal(),
    }
}

fn map_not_found() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::NotFound)
}

fn map_unauthenticated() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::Unauthenticated)
}

fn map_conflict() -> ProtocolFailure {
    ProtocolFailure::Domain(ariadnion_api_domain::ApiDomainError::new(
        ariadnion_api_domain::ApiDomainErrorCode::Conflict,
    ))
}

fn map_internal() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::Internal)
}

fn http_error(code: ariadnion_api_http::ApiHttpErrorCode) -> ProtocolFailure {
    ProtocolFailure::Http(ariadnion_api_http::ApiHttpError::new(code))
}

fn invalid() -> ProtocolFailure {
    ProtocolFailure::invalid_parameter(None)
}

fn payload_too_large() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::PayloadTooLarge)
}

fn body_read_failure(context: &RequestContext) -> ProtocolFailure {
    match context.check_active() {
        Ok(()) => payload_too_large(),
        Err(error) => ProtocolFailure::from(ariadnion_api_domain::ApiDomainError::from(error)),
    }
}

fn unsupported_media_type() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::UnsupportedMediaType)
}

fn integrity() -> ProtocolFailure {
    ProtocolFailure::Http(ariadnion_api_http::ApiHttpError::new(
        ariadnion_api_http::ApiHttpErrorCode::Internal,
    ))
}

fn unavailable() -> ProtocolFailure {
    http_error(ariadnion_api_http::ApiHttpErrorCode::Unavailable)
}

struct BatchContentSink {
    bytes: Vec<u8>,
    complete: bool,
}

impl BatchContentSink {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            complete: false,
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

impl FileDownloadSink for BatchContentSink {
    fn write_chunk<'a>(
        &'a mut self,
        chunk: FileChunk,
        context: &'a RequestContext,
    ) -> ariadnion_api_files::BoxFileFuture<'a, Result<(), ApiFilesError>> {
        Box::pin(async move {
            if self.complete {
                return Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure));
            }
            context.check_active().map_err(ApiFilesError::from)?;
            let next = self
                .bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| ApiFilesError::new(ApiFilesErrorCode::LimitExceeded))?;
            if next > MAX_BATCH_INPUT_BYTES {
                return Err(ApiFilesError::new(ApiFilesErrorCode::LimitExceeded));
            }
            self.bytes.extend_from_slice(chunk.as_bytes());
            Ok(())
        })
    }

    fn finish<'a>(
        &'a mut self,
        context: &'a RequestContext,
    ) -> ariadnion_api_files::BoxFileFuture<'a, Result<(), ApiFilesError>> {
        Box::pin(async move {
            context.check_active().map_err(ApiFilesError::from)?;
            if self.complete {
                return Err(ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure));
            }
            self.complete = true;
            Ok(())
        })
    }
}

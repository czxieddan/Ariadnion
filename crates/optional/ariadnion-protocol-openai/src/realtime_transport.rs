// crates/optional/ariadnion-protocol-openai/src/realtime_transport.rs - OpenAI Realtime transport.
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
//! Protocol-owned OpenAI Realtime transport over the neutral HTTP upgrade.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, RealtimeServerEvent, RealtimeSessionCloseReason,
    RealtimeSessionPort,
};
use ariadnion_api_http::{
    ApiHttpError, ApiHttpErrorCode, BoxHttpUpgradeFuture, BoxHttpUpgradeSession,
    HttpRequestIdentity, HttpUpgradeProtocolAdapter, HttpUpgradeSession, ProtocolBufferedResponse,
    ProtocolFailure,
};
use ariadnion_core::{CancellationToken, RequestContext as CoreRequestContext};
use ariadnion_provider_files::{
    ProviderFileId, ProviderFileMappingPort, ProviderFileScope, ProviderFilesError,
};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};

use crate::realtime::{
    OpenAiRealtimeError, OpenAiRealtimeErrorCode, OpenAiRealtimeProtocol,
    OpenAiRealtimeSessionProjection,
};

const MAX_RESPONSE_EVENT_COUNT: usize = 8;
const CLOSE_WATCH_INTERVAL: Duration = Duration::from_millis(10);

/// A boxed asynchronous provider-file alias resolution result.
pub type BoxRealtimeFileFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ariadnion_api_domain::FileReference, OpenAiRealtimeError>>
            + Send
            + 'a,
    >,
>;

/// Resolves a public OpenAI file alias inside the authenticated request scope.
pub trait RealtimeFileAliasResolver: Send + Sync {
    /// Resolves one alias to an opaque internal file reference.
    fn resolve<'a>(
        &'a self,
        alias: &'a str,
        context: &'a CoreRequestContext,
    ) -> BoxRealtimeFileFuture<'a>;
}

/// Provider-file mapping implementation for Realtime `input_file` content.
pub struct ProviderRealtimeFileAliasResolver {
    mappings: Arc<dyn ProviderFileMappingPort>,
    scope: ProviderFileScope,
}

impl ProviderRealtimeFileAliasResolver {
    /// Creates a resolver scoped to one provider account.
    #[must_use]
    pub fn new(mappings: Arc<dyn ProviderFileMappingPort>, scope: ProviderFileScope) -> Self {
        Self { mappings, scope }
    }
}

impl RealtimeFileAliasResolver for ProviderRealtimeFileAliasResolver {
    fn resolve<'a>(
        &'a self,
        alias: &'a str,
        context: &'a CoreRequestContext,
    ) -> BoxRealtimeFileFuture<'a> {
        Box::pin(async move {
            let id = ProviderFileId::new(alias)
                .map_err(|_| OpenAiRealtimeError::new(OpenAiRealtimeErrorCode::InvalidParameter))?;
            let mapping = self
                .mappings
                .resolve(self.scope.lookup(id), context)
                .await
                .map_err(map_provider_error)?;
            if !mapping.purpose().is_user_data() {
                return Err(OpenAiRealtimeError::new(OpenAiRealtimeErrorCode::NotFound));
            }
            Ok(*mapping.file_reference())
        })
    }
}

/// OpenAI Realtime protocol adapter backed by an injected session runtime.
pub struct OpenAiRealtimeTransport {
    protocol: OpenAiRealtimeProtocol,
    sessions: Arc<dyn RealtimeSessionPort>,
    files: Arc<dyn RealtimeFileAliasResolver>,
}

impl OpenAiRealtimeTransport {
    /// Creates an adapter with explicit protocol, runtime, and file mapping.
    #[must_use]
    pub fn new(
        protocol: OpenAiRealtimeProtocol,
        sessions: Arc<dyn RealtimeSessionPort>,
        files: Arc<dyn RealtimeFileAliasResolver>,
    ) -> Self {
        Self {
            protocol,
            sessions,
            files,
        }
    }

    /// Creates an adapter using the provider-file mapping capability directly.
    #[must_use]
    pub fn with_provider_files(
        protocol: OpenAiRealtimeProtocol,
        sessions: Arc<dyn RealtimeSessionPort>,
        mappings: Arc<dyn ProviderFileMappingPort>,
        scope: ProviderFileScope,
    ) -> Self {
        let files = Arc::new(ProviderRealtimeFileAliasResolver::new(mappings, scope));
        Self::new(protocol, sessions, files)
    }
}

impl HttpUpgradeProtocolAdapter for OpenAiRealtimeTransport {
    fn prepare(&self, query: Option<&str>) -> Result<BoxHttpUpgradeSession, ProtocolFailure> {
        let request = self
            .protocol
            .decode_open_request(query)
            .map_err(|_error| ProtocolFailure::invalid_parameter(Some("model")))?;
        Ok(Box::new(OpenAiRealtimeSession {
            protocol: self.protocol,
            sessions: Arc::clone(&self.sessions),
            files: Arc::clone(&self.files),
            request,
        }))
    }

    fn project_failure(
        &self,
        _identity: &HttpRequestIdentity,
        failure: ProtocolFailure,
    ) -> Result<ProtocolBufferedResponse, ProtocolFailure> {
        let status = match failure {
            ProtocolFailure::Domain(error) => domain_status(error.code()),
            ProtocolFailure::Http(error) => http_status(error.code()),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = serde_json::to_vec(&serde_json::json!({
            "error": {"message": "The Realtime request could not be accepted.", "type": "invalid_request_error"}
        }))
        .map_err(|_| ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal)))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        ProtocolBufferedResponse::new(status, headers, Bytes::from(body))
    }
}

struct OpenAiRealtimeSession {
    protocol: OpenAiRealtimeProtocol,
    sessions: Arc<dyn RealtimeSessionPort>,
    files: Arc<dyn RealtimeFileAliasResolver>,
    request: ariadnion_api_domain::RealtimeSessionOpenRequest,
}

impl HttpUpgradeSession for OpenAiRealtimeSession {
    fn serve(
        self: Box<Self>,
        socket: WebSocket,
        _identity: HttpRequestIdentity,
        context: CoreRequestContext,
    ) -> BoxHttpUpgradeFuture {
        Box::pin(async move { self.drive(socket, context).await })
    }
}

impl OpenAiRealtimeSession {
    async fn drive(self, mut socket: WebSocket, context: CoreRequestContext) {
        let Some(descriptor) = self.open_session(&context).await else {
            return;
        };
        let session_id = descriptor.id().clone();
        let close_watch = RealtimeCloseWatch::spawn(
            Arc::clone(&self.sessions),
            session_id.clone(),
            context.clone(),
        );
        let mut projection = OpenAiRealtimeSessionProjection::new(self.protocol, descriptor);
        let Some(first_frame) = projection.first_frame().ok() else {
            finish_watch(
                close_watch,
                &self.sessions,
                &session_id,
                RealtimeSessionCloseReason::Internal,
                &context,
            )
            .await;
            return;
        };
        if send_frame(&mut socket, Ok(first_frame)).await.is_err() {
            finish_watch(
                close_watch,
                &self.sessions,
                &session_id,
                RealtimeSessionCloseReason::Cancelled,
                &context,
            )
            .await;
            return;
        }
        let reason = self
            .receive_loop(&mut socket, &context, &session_id, &projection)
            .await;
        finish_watch(close_watch, &self.sessions, &session_id, reason, &context).await;
    }

    async fn open_session(
        &self,
        context: &CoreRequestContext,
    ) -> Option<ariadnion_api_domain::RealtimeSessionDescriptor> {
        self.sessions.open(self.request.clone(), context).await.ok()
    }

    async fn receive_loop(
        &self,
        socket: &mut WebSocket,
        context: &CoreRequestContext,
        session_id: &ariadnion_api_domain::RealtimeSessionId,
        projection: &OpenAiRealtimeSessionProjection,
    ) -> RealtimeSessionCloseReason {
        self.receive_frames(socket, context, session_id, projection)
            .await
            .err()
            .unwrap_or(RealtimeSessionCloseReason::Cancelled)
    }

    async fn receive_frames(
        &self,
        socket: &mut WebSocket,
        context: &CoreRequestContext,
        session_id: &ariadnion_api_domain::RealtimeSessionId,
        projection: &OpenAiRealtimeSessionProjection,
    ) -> Result<(), RealtimeSessionCloseReason> {
        loop {
            let frame = next_text_frame(socket, context).await?;
            self.process_frame(socket, context, session_id, projection, &frame)
                .await?;
        }
    }

    async fn process_frame(
        &self,
        socket: &mut WebSocket,
        context: &CoreRequestContext,
        session_id: &ariadnion_api_domain::RealtimeSessionId,
        projection: &OpenAiRealtimeSessionProjection,
        frame: &str,
    ) -> Result<(), RealtimeSessionCloseReason> {
        let Some(decoded) = self.decode_frame(socket, frame).await? else {
            return Ok(());
        };
        let correlation_id = decoded.correlation_id().cloned();
        let Some(event) = self
            .resolve_frame(socket, decoded, correlation_id.clone(), context)
            .await?
        else {
            return Ok(());
        };
        self.submit_frame(
            socket,
            session_id,
            event,
            correlation_id,
            context,
            projection,
        )
        .await
    }

    async fn decode_frame(
        &self,
        socket: &mut WebSocket,
        frame: &str,
    ) -> Result<Option<crate::realtime::OpenAiRealtimeDecodedEvent>, RealtimeSessionCloseReason>
    {
        match self.protocol.decode_client_frame(frame) {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                send_frame(socket, error_frame(&self.protocol, None, error))
                    .await
                    .map_err(|_| RealtimeSessionCloseReason::Internal)?;
                Ok(None)
            }
        }
    }

    async fn resolve_frame(
        &self,
        socket: &mut WebSocket,
        decoded: crate::realtime::OpenAiRealtimeDecodedEvent,
        correlation_id: Option<ariadnion_api_domain::RealtimeClientEventId>,
        context: &CoreRequestContext,
    ) -> Result<Option<ariadnion_api_domain::RealtimeInboundEvent>, RealtimeSessionCloseReason>
    {
        let files = Arc::clone(&self.files);
        let alias_context = context.clone();
        match decoded
            .resolve_file_aliases_async(move |alias| {
                let files = Arc::clone(&files);
                let alias = alias.as_str().to_owned();
                let context = alias_context.clone();
                async move { files.resolve(&alias, &context).await }
            })
            .await
        {
            Ok(event) => Ok(Some(event)),
            Err(error) => {
                send_frame(socket, error_frame(&self.protocol, correlation_id, error))
                    .await
                    .map_err(|_| RealtimeSessionCloseReason::Internal)?;
                Ok(None)
            }
        }
    }

    async fn submit_frame(
        &self,
        socket: &mut WebSocket,
        session_id: &ariadnion_api_domain::RealtimeSessionId,
        event: ariadnion_api_domain::RealtimeInboundEvent,
        correlation_id: Option<ariadnion_api_domain::RealtimeClientEventId>,
        context: &CoreRequestContext,
        projection: &OpenAiRealtimeSessionProjection,
    ) -> Result<(), RealtimeSessionCloseReason> {
        match self.sessions.submit(session_id, event, context).await {
            Ok(()) => drain_events(socket, &self.sessions, session_id, context, projection).await,
            Err(error) => self.reply_submit_error(socket, correlation_id, error).await,
        }
    }

    async fn reply_submit_error(
        &self,
        socket: &mut WebSocket,
        correlation_id: Option<ariadnion_api_domain::RealtimeClientEventId>,
        error: ariadnion_api_domain::ApiDomainError,
    ) -> Result<(), RealtimeSessionCloseReason> {
        let protocol_error = OpenAiRealtimeError::from(error);
        send_frame(
            socket,
            error_frame(&self.protocol, correlation_id, protocol_error),
        )
        .await
        .map_err(|_| RealtimeSessionCloseReason::Internal)?;
        if terminal_error(protocol_error.code()) {
            Err(close_reason(protocol_error_domain_code(
                protocol_error.code(),
            )))
        } else {
            Ok(())
        }
    }
}

async fn finish_watch(
    watch: RealtimeCloseWatch,
    sessions: &Arc<dyn RealtimeSessionPort>,
    id: &ariadnion_api_domain::RealtimeSessionId,
    reason: RealtimeSessionCloseReason,
    context: &CoreRequestContext,
) {
    watch.finish(sessions, id, reason, context).await;
}

async fn next_text_frame(
    socket: &mut WebSocket,
    context: &CoreRequestContext,
) -> Result<String, RealtimeSessionCloseReason> {
    loop {
        check_realtime_context(context)?;
        let Some(message) = receive_message(socket).await? else {
            continue;
        };
        return text_message(message).ok_or(RealtimeSessionCloseReason::ProtocolDesynchronized);
    }
}

fn check_realtime_context(context: &CoreRequestContext) -> Result<(), RealtimeSessionCloseReason> {
    context
        .check_active()
        .map_err(|error| close_reason(ApiDomainError::from(error).code()))
}

async fn receive_message(
    socket: &mut WebSocket,
) -> Result<Option<Message>, RealtimeSessionCloseReason> {
    match tokio::time::timeout(CLOSE_WATCH_INTERVAL, socket.recv()).await {
        Ok(Some(message)) => message
            .map(Some)
            .map_err(|_| RealtimeSessionCloseReason::Internal),
        Ok(None) => Err(RealtimeSessionCloseReason::Cancelled),
        Err(_) => Ok(None),
    }
}

async fn drain_events(
    socket: &mut WebSocket,
    sessions: &Arc<dyn RealtimeSessionPort>,
    session_id: &ariadnion_api_domain::RealtimeSessionId,
    context: &CoreRequestContext,
    projection: &OpenAiRealtimeSessionProjection,
) -> Result<(), RealtimeSessionCloseReason> {
    let first = sessions
        .next_event(session_id, context)
        .await
        .map_err(|error| close_reason(error.code()))?;
    let response_sequence = matches!(first.event(), RealtimeServerEvent::ResponseCreated(_));
    send_runtime_event(socket, projection, &first).await?;
    if response_sequence {
        for _ in 1..MAX_RESPONSE_EVENT_COUNT {
            let event = sessions
                .next_event(session_id, context)
                .await
                .map_err(|error| close_reason(error.code()))?;
            let terminal = matches!(event.event(), RealtimeServerEvent::ResponseDone { .. });
            send_runtime_event(socket, projection, &event).await?;
            if terminal {
                break;
            }
        }
    }
    Ok(())
}

async fn send_runtime_event(
    socket: &mut WebSocket,
    projection: &OpenAiRealtimeSessionProjection,
    event: &ariadnion_api_domain::RealtimeOutboundEvent,
) -> Result<(), RealtimeSessionCloseReason> {
    let frame = projection
        .project_runtime_event(event)
        .map_err(|error| close_reason(protocol_error_domain_code(error.code())))?;
    send_frame(socket, Ok(frame))
        .await
        .map_err(|_| RealtimeSessionCloseReason::Internal)
}

struct RealtimeCloseWatch {
    stop: CancellationToken,
    closed: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl RealtimeCloseWatch {
    fn spawn(
        sessions: Arc<dyn RealtimeSessionPort>,
        id: ariadnion_api_domain::RealtimeSessionId,
        context: CoreRequestContext,
    ) -> Self {
        let stop = CancellationToken::new();
        let closed = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(watch_session_close(
            sessions,
            id,
            context,
            stop.clone(),
            Arc::clone(&closed),
        ));
        Self { stop, closed, task }
    }

    async fn finish(
        self,
        sessions: &Arc<dyn RealtimeSessionPort>,
        id: &ariadnion_api_domain::RealtimeSessionId,
        reason: RealtimeSessionCloseReason,
        context: &CoreRequestContext,
    ) {
        self.stop.cancel();
        let _ = self.task.await;
        close_session_once(sessions, id, reason, context, &self.closed).await;
    }
}

pub(crate) async fn watch_session_close(
    sessions: Arc<dyn RealtimeSessionPort>,
    id: ariadnion_api_domain::RealtimeSessionId,
    context: CoreRequestContext,
    stop: CancellationToken,
    closed: Arc<AtomicBool>,
) {
    loop {
        if stop.is_cancelled() {
            return;
        }
        if let Err(error) = context.check_active() {
            let reason = close_reason(ApiDomainError::from(error).code());
            close_session_once(&sessions, &id, reason, &context, &closed).await;
            return;
        }
        tokio::time::sleep(CLOSE_WATCH_INTERVAL).await;
    }
}

async fn close_session_once(
    sessions: &Arc<dyn RealtimeSessionPort>,
    id: &ariadnion_api_domain::RealtimeSessionId,
    reason: RealtimeSessionCloseReason,
    context: &CoreRequestContext,
    closed: &AtomicBool,
) {
    if closed.swap(true, Ordering::AcqRel) {
        return;
    }
    let cleanup = cleanup_context(context);
    let _ = sessions.close(id, reason, &cleanup).await;
}

pub(crate) fn cleanup_context(context: &CoreRequestContext) -> CoreRequestContext {
    CoreRequestContext::new(
        context.request_id().clone(),
        context.trace_id().clone(),
        context.principal().cloned(),
        None,
        CancellationToken::new(),
    )
}

async fn send_frame(
    socket: &mut WebSocket,
    frame: Result<crate::realtime::OpenAiRealtimeOutboundFrame, OpenAiRealtimeError>,
) -> Result<(), ()> {
    let frame = frame.map_err(|_| ())?;
    socket
        .send(Message::Text(frame.as_str().into()))
        .await
        .map_err(|_| ())
}

fn error_frame(
    protocol: &OpenAiRealtimeProtocol,
    correlation_id: Option<ariadnion_api_domain::RealtimeClientEventId>,
    error: OpenAiRealtimeError,
) -> Result<crate::realtime::OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    protocol.project_server_event(&RealtimeServerEvent::Error {
        correlation_id,
        error: ApiDomainError::new(protocol_error_domain_code(error.code())),
    })
}

fn text_message(message: Message) -> Option<String> {
    match message {
        Message::Text(value) => Some(value.to_string()),
        Message::Close(_) => None,
        _ => None,
    }
}

fn map_provider_error(error: ProviderFilesError) -> OpenAiRealtimeError {
    let code = match error.code() {
        ariadnion_provider_files::ProviderFilesErrorCode::NotFound => {
            OpenAiRealtimeErrorCode::NotFound
        }
        ariadnion_provider_files::ProviderFilesErrorCode::Unavailable => {
            OpenAiRealtimeErrorCode::Unavailable
        }
        ariadnion_provider_files::ProviderFilesErrorCode::Unauthenticated => {
            OpenAiRealtimeErrorCode::InvalidRequest
        }
        ariadnion_provider_files::ProviderFilesErrorCode::Cancelled => {
            OpenAiRealtimeErrorCode::Cancelled
        }
        ariadnion_provider_files::ProviderFilesErrorCode::DeadlineExceeded => {
            OpenAiRealtimeErrorCode::DeadlineExceeded
        }
        _ => OpenAiRealtimeErrorCode::Internal,
    };
    OpenAiRealtimeError::new(code)
}

const fn protocol_error_domain_code(code: OpenAiRealtimeErrorCode) -> ApiDomainErrorCode {
    match code {
        OpenAiRealtimeErrorCode::Conflict => ApiDomainErrorCode::Conflict,
        OpenAiRealtimeErrorCode::Cancelled => ApiDomainErrorCode::Cancelled,
        OpenAiRealtimeErrorCode::DeadlineExceeded => ApiDomainErrorCode::DeadlineExceeded,
        OpenAiRealtimeErrorCode::ResourceExhausted => ApiDomainErrorCode::ResourceExhausted,
        OpenAiRealtimeErrorCode::Unavailable => ApiDomainErrorCode::Unavailable,
        OpenAiRealtimeErrorCode::Internal => ApiDomainErrorCode::Internal,
        _ => ApiDomainErrorCode::InvalidArgument,
    }
}

const fn terminal_error(code: OpenAiRealtimeErrorCode) -> bool {
    matches!(
        code,
        OpenAiRealtimeErrorCode::Cancelled
            | OpenAiRealtimeErrorCode::DeadlineExceeded
            | OpenAiRealtimeErrorCode::ResourceExhausted
            | OpenAiRealtimeErrorCode::Unavailable
            | OpenAiRealtimeErrorCode::Internal
    )
}

const fn close_reason(code: ApiDomainErrorCode) -> RealtimeSessionCloseReason {
    match code {
        ApiDomainErrorCode::Cancelled => RealtimeSessionCloseReason::Cancelled,
        ApiDomainErrorCode::DeadlineExceeded => RealtimeSessionCloseReason::Expired,
        ApiDomainErrorCode::Unavailable => RealtimeSessionCloseReason::Unavailable,
        _ => RealtimeSessionCloseReason::Internal,
    }
}

const fn domain_status(code: ApiDomainErrorCode) -> StatusCode {
    match code {
        ApiDomainErrorCode::Conflict => StatusCode::CONFLICT,
        ApiDomainErrorCode::Unavailable | ApiDomainErrorCode::ResourceExhausted => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::BAD_REQUEST,
    }
}

const fn http_status(code: ApiHttpErrorCode) -> StatusCode {
    match code {
        ApiHttpErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        ApiHttpErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ApiHttpErrorCode::NotFound => StatusCode::NOT_FOUND,
        ApiHttpErrorCode::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        ApiHttpErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    }
}

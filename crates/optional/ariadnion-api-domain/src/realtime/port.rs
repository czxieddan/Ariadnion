// crates/optional/ariadnion-api-domain/src/realtime/port.rs - Runtime-neutral Realtime session port for Ariadnion.
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
//! Lazy runtime-neutral operations for bounded Realtime sessions.

use std::future::Future;
use std::pin::Pin;

use ariadnion_core::RequestContext;

use super::{
    ApiDomainError, RealtimeInboundEvent, RealtimeOutboundEvent, RealtimeSessionCloseReason,
    RealtimeSessionDescriptor, RealtimeSessionId, RealtimeSessionOpenRequest,
};

/// A boxed asynchronous Realtime session operation result.
pub type BoxRealtimeFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Injected lifecycle capability for the initial text-only Realtime session.
///
/// Implementations own session allocation, ordered event processing, queue
/// backpressure, active-response coordination, and deterministic closure. All
/// futures are lazy: construction must not authenticate, allocate a session,
/// poll a WebSocket, resolve a file alias, enqueue an event, or start a provider
/// attempt. On first poll they must authenticate the tenant from RequestContext,
/// check cancellation before deadline, and retain the same context through every
/// externally visible effect.
///
/// The protocol adapter resolves public file aliases before building
/// RealtimeInboundEvent. Consequently, this port receives only opaque
/// FileReference values and must never accept file bytes, paths, URLs,
/// credentials, or account selection state. Runtime implementations must reject
/// inbound or outbound queue saturation as ResourceExhausted, enforce the
/// 60-minute session deadline, and close without fabricating a replacement
/// response after unrecoverable failure.
pub trait RealtimeSessionPort: Send + Sync {
    /// Opens one immutable text-only session.
    ///
    /// The returned descriptor is the sole authority for the session ID and
    /// immutable model/lifetime/output-budget settings. A WebSocket adapter must
    /// emit its session.created frame before forwarding any later event.
    fn open<'a>(
        &'a self,
        request: RealtimeSessionOpenRequest,
        context: &'a RequestContext,
    ) -> BoxRealtimeFuture<'a, Result<RealtimeSessionDescriptor, ApiDomainError>>;

    /// Submits one already decoded, bounded inbound event.
    ///
    /// The implementation applies strict ordering and state rules, including
    /// one active response, text/file-only conversation items, the aggregate
    /// input budget, and queue capacity. A correlated recoverable failure may
    /// later be returned as a protocol-owned error event; a desynchronized or
    /// expired session must be closed deterministically.
    fn submit<'a>(
        &'a self,
        session_id: &'a RealtimeSessionId,
        event: RealtimeInboundEvent,
        context: &'a RequestContext,
    ) -> BoxRealtimeFuture<'a, Result<(), ApiDomainError>>;

    /// Receives the next ordered bounded outbound event.
    ///
    /// The future may wait for one event while honoring cancellation, deadline,
    /// queue backpressure, and the session expiry. It returns Unavailable when
    /// the required runtime capability cannot continue; it never returns audio,
    /// tool, transcription, or unbounded output variants.
    fn next_event<'a>(
        &'a self,
        session_id: &'a RealtimeSessionId,
        context: &'a RequestContext,
    ) -> BoxRealtimeFuture<'a, Result<RealtimeOutboundEvent, ApiDomainError>>;

    /// Closes the exact tenant-scoped session and releases all bounded queues.
    ///
    /// Closing is deterministic for expiry, cancellation, protocol
    /// desynchronization, unavailable capability, and unrecoverable internal
    /// failures. The operation must not issue a new session or response ID.
    fn close<'a>(
        &'a self,
        session_id: &'a RealtimeSessionId,
        reason: RealtimeSessionCloseReason,
        context: &'a RequestContext,
    ) -> BoxRealtimeFuture<'a, Result<(), ApiDomainError>>;
}

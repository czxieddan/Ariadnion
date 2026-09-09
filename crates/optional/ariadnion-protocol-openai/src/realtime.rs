// crates/optional/ariadnion-protocol-openai/src/realtime.rs - OpenAI Realtime protocol projection for Ariadnion.
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
//! Strict typed OpenAI Realtime frame projection for the initial text-only subset.
//!
//! This leaf owns only query and text-frame grammar. A later WebSocket transport
//! integration authenticates the HTTP upgrade, invokes the session port, resolves
//! file aliases through the provider mapping capability, and applies the projected
//! frames to the socket. It must not add audio, tool, image, inline-data, URL, or
//! mutable-model variants around this decoder.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_api_domain::{
    MAX_REALTIME_SESSION_SECONDS, ModelSelector, OutputTokenLimit, RealtimeOutboundEvent,
    RealtimeServerEvent, RealtimeSessionDescriptor, RealtimeSessionLifetime,
    RealtimeSessionOpenRequest,
};

#[path = "realtime/error.rs"]
mod error;
#[path = "realtime/inbound.rs"]
mod inbound;
#[path = "realtime/outbound.rs"]
mod outbound;
#[path = "realtime/query.rs"]
mod query;

pub use error::{OpenAiRealtimeError, OpenAiRealtimeErrorCode};
pub use inbound::{OpenAiRealtimeDecodedEvent, OpenAiRealtimeFileAlias};
pub use outbound::{OpenAiRealtimeOutboundFrame, OpenAiRealtimeServerEventKind};

/// OpenAI-compatible WebSocket route owned by the eventual transport integration.
pub const OPENAI_REALTIME_PATH: &str = "/v1/realtime";

/// Immutable text-only protocol configuration for one selected public profile.
///
/// The default output budget is composition evidence, not an inferred OpenAI or
/// model default. It is captured in every session-open request and used only when
/// a client omits the optional `response` object from `response.create`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenAiRealtimeProtocol {
    default_output_token_limit: OutputTokenLimit,
}

impl OpenAiRealtimeProtocol {
    /// Creates the strict text-only protocol leaf with an explicit typed budget.
    #[must_use]
    pub const fn new(default_output_token_limit: OutputTokenLimit) -> Self {
        Self {
            default_output_token_limit,
        }
    }

    /// Decodes the exact Realtime upgrade query into immutable session settings.
    ///
    /// The query must contain exactly one percent-decoded `model` member and no
    /// other members. Session lifetime and queue limits are the frozen P4 values;
    /// the model remains immutable after this point.
    ///
    /// # Errors
    ///
    /// Returns [`OpenAiRealtimeErrorCode::InvalidRequest`] for every malformed,
    /// missing, duplicate, unsupported, or invalid query shape. This method does
    /// not authenticate, allocate a session, or inspect provider state.
    pub fn decode_open_request(
        &self,
        query: Option<&str>,
    ) -> Result<RealtimeSessionOpenRequest, OpenAiRealtimeError> {
        let model = query::decode_model(query)?;
        let lifetime = RealtimeSessionLifetime::new(MAX_REALTIME_SESSION_SECONDS)
            .map_err(OpenAiRealtimeError::from)?;
        Ok(RealtimeSessionOpenRequest::new(
            model,
            lifetime,
            self.default_output_token_limit,
        ))
    }

    /// Decodes one bounded client JSON text frame without resolving file aliases.
    ///
    /// The returned value preserves a public `input_file.file_id` as a distinct
    /// opaque alias. The caller must use [`OpenAiRealtimeDecodedEvent::resolve_file_aliases`]
    /// before submitting it to `RealtimeSessionPort`, so storage references never
    /// cross the public wire boundary.
    ///
    /// # Errors
    ///
    /// Returns a redacted stable classification for malformed JSON, duplicate or
    /// unknown fields, unsupported event variants, invalid limits, or a frame
    /// exceeding the fixed 256 KiB text-frame budget.
    pub fn decode_client_frame(
        &self,
        frame: &str,
    ) -> Result<OpenAiRealtimeDecodedEvent, OpenAiRealtimeError> {
        inbound::decode_client_frame(frame)
    }

    /// Projects one semantic server event into the sole allowed JSON text frame.
    ///
    /// `RateLimitsUpdated` deliberately fails closed until a session runtime can
    /// supply authoritative rate-limit evidence; a marker alone must not invent
    /// rate-limit values. All other supported domain event variants map to a
    /// finite frame within the shared Realtime frame budget.
    ///
    /// # Errors
    ///
    /// Returns [`OpenAiRealtimeErrorCode::Internal`] for a domain event that
    /// cannot be represented safely by the frozen wire subset or when bounded
    /// frame construction fails.
    pub fn project_server_event(
        &self,
        event: &ariadnion_api_domain::RealtimeServerEvent,
    ) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
        outbound::project_server_event(event)
    }

    /// Validates that a runtime-provided frame exactly matches this protocol leaf.
    ///
    /// The session runtime may retain a bounded `RealtimeTextFrame` to enforce
    /// queue accounting, but it does not own public JSON grammar. An integration
    /// validates every dequeued runtime event here before writing the frame to the
    /// socket, rejecting an internal mismatch before it becomes visible.
    ///
    /// # Errors
    ///
    /// Returns [`OpenAiRealtimeErrorCode::Internal`] for any divergent or
    /// unrepresentable frame.
    pub fn validate_outbound_event(
        &self,
        outbound_event: &ariadnion_api_domain::RealtimeOutboundEvent,
    ) -> Result<(), OpenAiRealtimeError> {
        outbound::validate_outbound_event(outbound_event)
    }
}

/// Per-session frame-order guard for the initial Realtime WebSocket lifecycle.
///
/// A successful transport integration constructs this guard after the session
/// port returns its descriptor, writes [`Self::first_frame`] before polling the
/// port for output, and sends only frames accepted by
/// [`Self::project_runtime_event`]. The guard intentionally contains no socket,
/// task, queue, provider, or authentication state.
#[derive(Clone, Debug)]
pub struct OpenAiRealtimeSessionProjection {
    protocol: OpenAiRealtimeProtocol,
    descriptor: RealtimeSessionDescriptor,
    first_frame_emitted: bool,
}

impl OpenAiRealtimeSessionProjection {
    /// Creates an unopened ordering guard for one already allocated session.
    #[must_use]
    pub const fn new(
        protocol: OpenAiRealtimeProtocol,
        descriptor: RealtimeSessionDescriptor,
    ) -> Self {
        Self {
            protocol,
            descriptor,
            first_frame_emitted: false,
        }
    }

    /// Returns the mandatory first `session.created` server frame exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`OpenAiRealtimeErrorCode::Internal`] if a caller attempts to
    /// emit a second opening frame or the fixed bounded projection cannot be
    /// represented safely.
    pub fn first_frame(&mut self) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
        if self.first_frame_emitted {
            return Err(OpenAiRealtimeError::internal());
        }
        let event = RealtimeServerEvent::SessionCreated(self.descriptor.clone());
        let frame = self.protocol.project_server_event(&event)?;
        self.first_frame_emitted = true;
        Ok(frame)
    }

    /// Validates and canonically projects one runtime event after `session.created`.
    ///
    /// The session port must not enqueue `SessionCreated`: session allocation is
    /// represented exclusively by [`Self::first_frame`]. This prevents a runtime
    /// event from racing the required opening frame or producing a duplicate.
    ///
    /// # Errors
    ///
    /// Returns [`OpenAiRealtimeErrorCode::Internal`] until the opening frame has
    /// been acquired, for a duplicate `SessionCreated`, or for any divergent
    /// runtime frame.
    pub fn project_runtime_event(
        &self,
        outbound_event: &RealtimeOutboundEvent,
    ) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
        if !self.first_frame_emitted
            || matches!(
                outbound_event.event(),
                RealtimeServerEvent::SessionCreated(_)
            )
        {
            return Err(OpenAiRealtimeError::internal());
        }
        self.protocol.validate_outbound_event(outbound_event)?;
        self.protocol.project_server_event(outbound_event.event())
    }
}

fn model_from_wire(value: &str) -> Result<ModelSelector, OpenAiRealtimeError> {
    ModelSelector::new(value).map_err(|_| OpenAiRealtimeError::invalid_request())
}

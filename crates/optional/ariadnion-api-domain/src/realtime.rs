// crates/optional/ariadnion-api-domain/src/realtime.rs - Bounded Realtime session contracts for Ariadnion.
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
//! Bounded, runtime-neutral text-only Realtime session contracts.

use std::fmt::{self, Debug, Formatter};

use crate::error::{ApiDomainError, ApiDomainErrorCode, invalid_argument, limit_exceeded};
use crate::{FileReference, ModelSelector, OutputTokenLimit, TextDelta};

mod port;

pub use port::{BoxRealtimeFuture, RealtimeSessionPort};

/// Maximum Realtime session duration in seconds.
pub const MAX_REALTIME_SESSION_SECONDS: u64 = 60 * 60;
/// Maximum conversation items accepted by one session.
pub const MAX_REALTIME_CONVERSATION_ITEMS: usize = 128;
/// Maximum aggregate UTF-8 bytes accepted as text input by one session.
pub const MAX_REALTIME_ACCEPTED_TEXT_BYTES: usize = 1_048_576;
/// Maximum encoded UTF-8 bytes in one inbound or outbound JSON text frame.
pub const MAX_REALTIME_FRAME_BYTES: usize = 262_144;
/// Maximum inbound events retained by one runtime session queue.
pub const MAX_REALTIME_INBOUND_QUEUE_EVENTS: usize = 16;
/// Maximum outbound events retained by one runtime session queue.
pub const MAX_REALTIME_OUTBOUND_QUEUE_EVENTS: usize = 16;
/// Maximum UTF-8 bytes in a client correlation identifier.
pub const MAX_REALTIME_CLIENT_EVENT_ID_BYTES: usize = 512;
/// Maximum UTF-8 bytes in a runtime-generated session or response identifier.
pub const MAX_REALTIME_RUNTIME_ID_BYTES: usize = 256;
/// Maximum content parts in one accepted conversation item.
pub const MAX_REALTIME_CONTENT_PARTS: usize = 128;

/// An opaque bounded client event correlation value.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RealtimeClientEventId(Box<str>);

impl RealtimeClientEventId {
    /// Validates and copies an optional-wire client correlation value.
    ///
    /// The identifier is opaque to Ariadnion and is never used as a request ID,
    /// storage key, or authorization subject. It must be non-empty, control-free,
    /// and no longer than 512 UTF-8 bytes.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_opaque(value, MAX_REALTIME_CLIENT_EVENT_ID_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the opaque correlation value for the protocol error envelope.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RealtimeClientEventId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealtimeClientEventId")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// A runtime-issued opaque Realtime session identifier.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RealtimeSessionId(Box<str>);

impl RealtimeSessionId {
    /// Validates an opaque runtime session identifier.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_runtime_id(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the runtime identifier only to a trusted session adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RealtimeSessionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealtimeSessionId")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// A runtime-issued opaque Realtime response identifier.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RealtimeResponseId(Box<str>);

impl RealtimeResponseId {
    /// Validates an opaque runtime response identifier.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_runtime_id(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the runtime identifier only to a trusted session adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RealtimeResponseId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealtimeResponseId")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// A checked session lifetime in seconds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealtimeSessionLifetime(u64);

impl RealtimeSessionLifetime {
    /// Validates a positive lifetime no greater than 60 minutes.
    pub const fn new(seconds: u64) -> Result<Self, ApiDomainError> {
        if seconds > MAX_REALTIME_SESSION_SECONDS {
            return Err(limit_exceeded());
        }
        if seconds == 0 {
            return Err(invalid_argument());
        }
        Ok(Self(seconds))
    }

    /// Returns the exact session lifetime in seconds.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

/// A bounded text payload accepted as one Realtime input content part.
#[derive(Clone, Eq, PartialEq)]
pub struct RealtimeInputText(Box<str>);

impl RealtimeInputText {
    /// Validates non-empty, NUL-free text that fits in one JSON frame.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_text(value, MAX_REALTIME_FRAME_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns validated text to a trusted session runtime.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the UTF-8 byte length counted against the session input budget.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.0.len()
    }
}

impl Debug for RealtimeInputText {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealtimeInputText")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// One input part accepted by the text-only Realtime subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealtimeInputContent {
    /// Text supplied directly in the bounded session frame.
    Text(RealtimeInputText),
    /// An already authorized internal file reference without byte, path, or URL data.
    File(FileReference),
}

impl RealtimeInputContent {
    /// Creates a text input part.
    #[must_use]
    pub const fn text(value: RealtimeInputText) -> Self {
        Self::Text(value)
    }

    /// Creates an internal-reference file input part.
    #[must_use]
    pub const fn file(value: FileReference) -> Self {
        Self::File(value)
    }

    const fn text_bytes(&self) -> usize {
        match self {
            Self::Text(value) => value.encoded_bytes(),
            Self::File(_) => 0,
        }
    }
}

/// One user conversation message accepted by the initial Realtime subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealtimeConversationItem {
    content: Box<[RealtimeInputContent]>,
    text_bytes: usize,
}

impl RealtimeConversationItem {
    /// Validates a non-empty bounded sequence of text and internal file inputs.
    pub fn new(content: Vec<RealtimeInputContent>) -> Result<Self, ApiDomainError> {
        if content.is_empty() {
            return Err(invalid_argument());
        }
        if content.len() > MAX_REALTIME_CONTENT_PARTS {
            return Err(limit_exceeded());
        }
        let text_bytes = content.iter().try_fold(0_usize, checked_part_bytes)?;
        if text_bytes > MAX_REALTIME_FRAME_BYTES {
            return Err(limit_exceeded());
        }
        Ok(Self {
            content: content.into_boxed_slice(),
            text_bytes,
        })
    }

    /// Returns accepted text and internal file-reference parts in source order.
    #[must_use]
    pub fn content(&self) -> &[RealtimeInputContent] {
        &self.content
    }

    /// Returns input text bytes counted against the session aggregate limit.
    #[must_use]
    pub const fn text_bytes(&self) -> usize {
        self.text_bytes
    }
}

/// The fixed text-only session update accepted by this P4 subset.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RealtimeSessionUpdate;

impl RealtimeSessionUpdate {
    /// Creates the only accepted session update: realtime type and text output.
    #[must_use]
    pub const fn text_only() -> Self {
        Self
    }
}

/// A request to create one response using the session output budget when omitted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealtimeResponseCreate {
    output_token_limit: Option<OutputTokenLimit>,
}

impl RealtimeResponseCreate {
    /// Creates a text-only response request.
    ///
    /// An absent limit instructs the runtime to use the explicit typed default
    /// captured in the session open request. This type does not invent a model
    /// default.
    #[must_use]
    pub const fn new(output_token_limit: Option<OutputTokenLimit>) -> Self {
        Self { output_token_limit }
    }

    /// Returns the optional request-specific output budget.
    #[must_use]
    pub const fn output_token_limit(&self) -> Option<OutputTokenLimit> {
        self.output_token_limit
    }
}

/// A cancellation request for the sole active response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealtimeResponseCancel {
    response_id: Option<RealtimeResponseId>,
}

impl RealtimeResponseCancel {
    /// Creates a cancellation request with an optional active-response target.
    #[must_use]
    pub const fn new(response_id: Option<RealtimeResponseId>) -> Self {
        Self { response_id }
    }

    /// Returns the optional explicit active-response target.
    #[must_use]
    pub const fn response_id(&self) -> Option<&RealtimeResponseId> {
        self.response_id.as_ref()
    }
}

/// One accepted client operation after strict protocol decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealtimeClientEvent {
    /// Confirms the fixed realtime/text session shape.
    SessionUpdate(RealtimeSessionUpdate),
    /// Adds one user conversation item with text or internal file references.
    ConversationItemCreate(RealtimeConversationItem),
    /// Starts the sole active text response.
    ResponseCreate(RealtimeResponseCreate),
    /// Cancels the sole active response.
    ResponseCancel(RealtimeResponseCancel),
}

/// A bounded JSON text frame retained only while an adapter applies backpressure.
#[derive(Clone, Eq, PartialEq)]
pub struct RealtimeTextFrame(Box<str>);

impl RealtimeTextFrame {
    /// Validates one non-empty, NUL-free JSON text frame within 256 KiB.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_text(value, MAX_REALTIME_FRAME_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the bounded frame bytes to a trusted WebSocket adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RealtimeTextFrame {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealtimeTextFrame")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// One bounded decoded inbound event and its original bounded frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealtimeInboundEvent {
    correlation_id: Option<RealtimeClientEventId>,
    event: RealtimeClientEvent,
    frame: RealtimeTextFrame,
}

impl RealtimeInboundEvent {
    /// Owns a decoded event and its exact bounded JSON frame evidence.
    pub const fn new(
        correlation_id: Option<RealtimeClientEventId>,
        event: RealtimeClientEvent,
        frame: RealtimeTextFrame,
    ) -> Self {
        Self {
            correlation_id,
            event,
            frame,
        }
    }

    /// Returns the optional client correlation ID.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<&RealtimeClientEventId> {
        self.correlation_id.as_ref()
    }

    /// Returns the decoded accepted event.
    #[must_use]
    pub const fn event(&self) -> &RealtimeClientEvent {
        &self.event
    }

    /// Returns the bounded original JSON frame.
    #[must_use]
    pub const fn frame(&self) -> &RealtimeTextFrame {
        &self.frame
    }
}

/// A snapshot of immutable Realtime session settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealtimeSessionOpenRequest {
    model: ModelSelector,
    lifetime: RealtimeSessionLifetime,
    default_output_token_limit: OutputTokenLimit,
}

impl RealtimeSessionOpenRequest {
    /// Creates an immutable text-only session configuration.
    ///
    /// The model is selected before opening and remains immutable for the session.
    /// Queue capacities are fixed to the published bounded constants.
    pub const fn new(
        model: ModelSelector,
        lifetime: RealtimeSessionLifetime,
        default_output_token_limit: OutputTokenLimit,
    ) -> Self {
        Self {
            model,
            lifetime,
            default_output_token_limit,
        }
    }

    /// Returns the immutable model selector.
    #[must_use]
    pub const fn model(&self) -> &ModelSelector {
        &self.model
    }

    /// Returns the checked maximum session lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> RealtimeSessionLifetime {
        self.lifetime
    }

    /// Returns the typed default output budget.
    #[must_use]
    pub const fn default_output_token_limit(&self) -> OutputTokenLimit {
        self.default_output_token_limit
    }

    /// Returns the fixed inbound queue capacity.
    #[must_use]
    pub const fn inbound_queue_limit(&self) -> usize {
        MAX_REALTIME_INBOUND_QUEUE_EVENTS
    }

    /// Returns the fixed outbound queue capacity.
    #[must_use]
    pub const fn outbound_queue_limit(&self) -> usize {
        MAX_REALTIME_OUTBOUND_QUEUE_EVENTS
    }
}

/// One runtime-created Realtime session descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealtimeSessionDescriptor {
    id: RealtimeSessionId,
    request: RealtimeSessionOpenRequest,
}

impl RealtimeSessionDescriptor {
    /// Binds a runtime-issued session ID to immutable open settings.
    #[must_use]
    pub const fn new(id: RealtimeSessionId, request: RealtimeSessionOpenRequest) -> Self {
        Self { id, request }
    }

    /// Returns the runtime-issued session identifier.
    #[must_use]
    pub const fn id(&self) -> &RealtimeSessionId {
        &self.id
    }

    /// Returns the immutable open request.
    #[must_use]
    pub const fn request(&self) -> &RealtimeSessionOpenRequest {
        &self.request
    }
}

/// A reason that deterministically closes a Realtime session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RealtimeSessionCloseReason {
    /// The maximum 60-minute session lifetime elapsed.
    Expired,
    /// The caller cancelled the session context.
    Cancelled,
    /// The peer violated ordered protocol lifecycle invariants.
    ProtocolDesynchronized,
    /// The required session capability became unavailable.
    Unavailable,
    /// An unrecoverable redacted internal failure occurred.
    Internal,
}

/// A terminal reason for the sole active Realtime response.
///
/// This remains separate from the shared complete-response reason because a
/// Realtime response can end through its explicit cancellation operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RealtimeResponseFinishReason {
    /// Generation reached its natural completion point.
    Completed,
    /// Generation reached the configured output token limit.
    OutputLimitReached,
    /// A safety policy stopped generation before ordinary completion.
    ContentFiltered,
    /// The active response was terminated through `response.cancel`.
    Cancelled,
}

/// One allowed outbound event from the initial text-only session lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealtimeServerEvent {
    /// The required first event for a successfully opened session.
    SessionCreated(RealtimeSessionDescriptor),
    /// Confirms the fixed text-only session settings.
    SessionUpdated,
    /// Announces a newly active response.
    ResponseCreated(RealtimeResponseId),
    /// Announces the assistant output item.
    ResponseOutputItemAdded(RealtimeResponseId),
    /// Announces the text content part.
    ResponseContentPartAdded(RealtimeResponseId),
    /// Carries one bounded text delta.
    ResponseOutputTextDelta {
        /// Active response receiving this delta.
        response_id: RealtimeResponseId,
        /// Bounded text output.
        delta: TextDelta,
    },
    /// Ends text output for the active response.
    ResponseOutputTextDone(RealtimeResponseId),
    /// Ends the content part for the active response.
    ResponseContentPartDone(RealtimeResponseId),
    /// Ends the output item for the active response.
    ResponseOutputItemDone(RealtimeResponseId),
    /// Completes or cancels the active response.
    ResponseDone {
        /// Completed response identifier.
        response_id: RealtimeResponseId,
        /// Realtime-specific terminal reason, including explicit cancellation.
        finish_reason: RealtimeResponseFinishReason,
    },
    /// Reports authoritative rate-limit evidence without account credentials.
    RateLimitsUpdated,
    /// Reports one correlated redacted protocol failure while the session remains usable.
    Error {
        /// Client event correlation when the failure is attributable to one event.
        correlation_id: Option<RealtimeClientEventId>,
        /// Stable redacted failure classification.
        error: ApiDomainError,
    },
}

/// A bounded outbound event paired with the exact WebSocket text frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealtimeOutboundEvent {
    event: RealtimeServerEvent,
    frame: RealtimeTextFrame,
}

impl RealtimeOutboundEvent {
    /// Owns an outbound event and its bounded encoded text frame.
    #[must_use]
    pub const fn new(event: RealtimeServerEvent, frame: RealtimeTextFrame) -> Self {
        Self { event, frame }
    }

    /// Returns the semantic server event.
    #[must_use]
    pub const fn event(&self) -> &RealtimeServerEvent {
        &self.event
    }

    /// Returns the bounded encoded text frame.
    #[must_use]
    pub const fn frame(&self) -> &RealtimeTextFrame {
        &self.frame
    }
}

/// Mutable bounded session state for runtime implementations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RealtimeSessionState {
    conversation_items: usize,
    accepted_text_bytes: usize,
    active_response: Option<RealtimeResponseId>,
    closed: bool,
}

impl RealtimeSessionState {
    /// Creates an empty open session state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            conversation_items: 0,
            accepted_text_bytes: 0,
            active_response: None,
            closed: false,
        }
    }

    /// Accepts one bounded user message after protocol validation.
    pub fn accept_conversation_item(
        &mut self,
        item: &RealtimeConversationItem,
    ) -> Result<(), ApiDomainError> {
        self.require_open()?;
        if self.conversation_items >= MAX_REALTIME_CONVERSATION_ITEMS {
            return Err(limit_exceeded());
        }
        let total = self
            .accepted_text_bytes
            .checked_add(item.text_bytes())
            .ok_or_else(limit_exceeded)?;
        if total > MAX_REALTIME_ACCEPTED_TEXT_BYTES {
            return Err(limit_exceeded());
        }
        self.conversation_items += 1;
        self.accepted_text_bytes = total;
        Ok(())
    }

    /// Starts the only active response for this session.
    pub fn start_response(
        &mut self,
        response_id: RealtimeResponseId,
    ) -> Result<(), ApiDomainError> {
        self.require_open()?;
        if self.active_response.is_some() {
            return Err(conflict());
        }
        self.active_response = Some(response_id);
        Ok(())
    }

    /// Resolves cancellation to the current active response.
    ///
    /// Repeating cancellation for that same active response is idempotent. A
    /// different explicit response ID is a conflict and never retargets work.
    pub fn cancel_response(
        &self,
        requested: Option<&RealtimeResponseId>,
    ) -> Result<RealtimeResponseId, ApiDomainError> {
        self.require_open()?;
        let active = self.active_response.as_ref().ok_or_else(conflict)?;
        if requested.is_some_and(|value| value != active) {
            return Err(conflict());
        }
        Ok(active.clone())
    }

    /// Ends the exact active response after its terminal outbound event.
    pub fn finish_response(
        &mut self,
        response_id: &RealtimeResponseId,
    ) -> Result<(), ApiDomainError> {
        self.require_open()?;
        if self.active_response.as_ref() != Some(response_id) {
            return Err(conflict());
        }
        self.active_response = None;
        Ok(())
    }

    /// Marks the session closed so future state transitions fail deterministically.
    pub fn close(&mut self) {
        self.active_response = None;
        self.closed = true;
    }

    /// Returns accepted conversation-item count.
    #[must_use]
    pub const fn conversation_items(&self) -> usize {
        self.conversation_items
    }

    /// Returns aggregate accepted text bytes.
    #[must_use]
    pub const fn accepted_text_bytes(&self) -> usize {
        self.accepted_text_bytes
    }

    /// Returns the sole active response, when present.
    #[must_use]
    pub const fn active_response(&self) -> Option<&RealtimeResponseId> {
        self.active_response.as_ref()
    }

    /// Reports whether the runtime has closed this state.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    fn require_open(&self) -> Result<(), ApiDomainError> {
        if self.closed { Err(conflict()) } else { Ok(()) }
    }
}

fn checked_part_bytes(total: usize, part: &RealtimeInputContent) -> Result<usize, ApiDomainError> {
    total
        .checked_add(part.text_bytes())
        .ok_or_else(limit_exceeded)
}

fn validate_opaque(value: &str, maximum: usize) -> Result<(), ApiDomainError> {
    if value.len() > maximum {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_runtime_id(value: &str) -> Result<(), ApiDomainError> {
    validate_opaque(value, MAX_REALTIME_RUNTIME_ID_BYTES)?;
    if !value.is_ascii() || value.bytes().any(is_invalid_runtime_id_byte) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn is_invalid_runtime_id_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.' | b':')
}

fn validate_text(value: &str, maximum: usize) -> Result<(), ApiDomainError> {
    if value.len() > maximum {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.contains('\0') {
        return Err(invalid_argument());
    }
    Ok(())
}

const fn conflict() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::Conflict)
}

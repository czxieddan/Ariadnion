// crates/optional/ariadnion-protocol-openai/src/realtime/outbound.rs - OpenAI Realtime server frame projection.
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
//! Finite OpenAI Realtime server frames derived only from typed domain events.

use ariadnion_api_domain::{
    ApiDomainError, MAX_REALTIME_ACCEPTED_TEXT_BYTES, MAX_REALTIME_CONVERSATION_ITEMS,
    MAX_REALTIME_FRAME_BYTES, MAX_REALTIME_INBOUND_QUEUE_EVENTS,
    MAX_REALTIME_OUTBOUND_QUEUE_EVENTS, RealtimeOutboundEvent, RealtimeResponseFinishReason,
    RealtimeServerEvent, RealtimeSessionDescriptor, RealtimeTextFrame,
};
use serde::Serialize;

use super::{OpenAiRealtimeError, OpenAiRealtimeErrorCode};

/// The OpenAI event discriminator projected by a bounded outbound frame.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpenAiRealtimeServerEventKind {
    /// The mandatory first frame after a successful session open.
    SessionCreated,
    /// Confirmation of the immutable text-only session update.
    SessionUpdated,
    /// A response became active.
    ResponseCreated,
    /// The assistant output item became visible.
    ResponseOutputItemAdded,
    /// The response text content part became visible.
    ResponseContentPartAdded,
    /// One bounded text delta became visible.
    ResponseOutputTextDelta,
    /// The response text content part finished.
    ResponseOutputTextDone,
    /// The response content part finished.
    ResponseContentPartDone,
    /// The response output item finished.
    ResponseOutputItemDone,
    /// The active response reached a terminal state.
    ResponseDone,
    /// A correlated recoverable protocol error.
    Error,
}

/// A checked finite JSON text frame owned by the OpenAI Realtime protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiRealtimeOutboundFrame {
    kind: OpenAiRealtimeServerEventKind,
    frame: RealtimeTextFrame,
}

impl OpenAiRealtimeOutboundFrame {
    fn new(kind: OpenAiRealtimeServerEventKind, frame: RealtimeTextFrame) -> Self {
        Self { kind, frame }
    }

    /// Returns the exact public event discriminator.
    #[must_use]
    pub const fn kind(&self) -> OpenAiRealtimeServerEventKind {
        self.kind
    }

    /// Borrows the finite JSON text frame for the WebSocket writer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.frame.as_str()
    }

    /// Borrows the checked domain frame used for queue accounting.
    #[must_use]
    pub const fn frame(&self) -> &RealtimeTextFrame {
        &self.frame
    }
}

pub(super) fn project_server_event(
    event: &RealtimeServerEvent,
) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    match event {
        RealtimeServerEvent::SessionCreated(descriptor) => project_session_created(descriptor),
        RealtimeServerEvent::SessionUpdated => project_session_updated(),
        RealtimeServerEvent::RateLimitsUpdated => Err(OpenAiRealtimeError::internal()),
        RealtimeServerEvent::Error {
            correlation_id,
            error,
        } => project_error(correlation_id.as_ref().map(|value| value.as_str()), *error),
        _ => project_response_event(event),
    }
}

pub(super) fn validate_outbound_event(
    outbound_event: &RealtimeOutboundEvent,
) -> Result<(), OpenAiRealtimeError> {
    let expected = project_server_event(outbound_event.event())?;
    if expected.as_str() != outbound_event.frame().as_str() {
        return Err(OpenAiRealtimeError::internal());
    }
    Ok(())
}

fn project_session_created(
    descriptor: &RealtimeSessionDescriptor,
) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    let request = descriptor.request();
    encode(
        OpenAiRealtimeServerEventKind::SessionCreated,
        &SessionCreatedWire {
            event_type: "session.created",
            session: SessionWire {
                id: descriptor.id().as_str(),
                object: "realtime.session",
                session_type: "realtime",
                model: request.model().as_str(),
                output_modalities: ["text"],
                default_max_output_tokens: request.default_output_token_limit().get(),
                limits: SessionLimitsWire {
                    max_duration_seconds: request.lifetime().seconds(),
                    max_conversation_items: MAX_REALTIME_CONVERSATION_ITEMS,
                    max_input_text_bytes: MAX_REALTIME_ACCEPTED_TEXT_BYTES,
                    max_frame_bytes: MAX_REALTIME_FRAME_BYTES,
                    max_inbound_events: MAX_REALTIME_INBOUND_QUEUE_EVENTS,
                    max_outbound_events: MAX_REALTIME_OUTBOUND_QUEUE_EVENTS,
                },
            },
        },
    )
}

fn project_session_updated() -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    encode(
        OpenAiRealtimeServerEventKind::SessionUpdated,
        &SessionUpdatedWire {
            event_type: "session.updated",
            session: TextOnlySessionWire {
                session_type: "realtime",
                output_modalities: ["text"],
            },
        },
    )
}

fn project_error(
    correlation_id: Option<&str>,
    error: ApiDomainError,
) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    let error = OpenAiRealtimeError::from(error);
    let profile = error_profile(error.code());
    encode(
        OpenAiRealtimeServerEventKind::Error,
        &ErrorWire {
            event_type: "error",
            error: ErrorBodyWire {
                message: profile.message,
                error_type: profile.error_type,
                parameter: None,
                code: error.code().as_str(),
                event_id: correlation_id,
            },
        },
    )
}

fn project_response_event(
    event: &RealtimeServerEvent,
) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    match event {
        RealtimeServerEvent::ResponseCreated(response_id) => response_id_frame(
            OpenAiRealtimeServerEventKind::ResponseCreated,
            "response.created",
            response_id.as_str(),
        ),
        RealtimeServerEvent::ResponseOutputItemAdded(response_id) => response_id_frame(
            OpenAiRealtimeServerEventKind::ResponseOutputItemAdded,
            "response.output_item.added",
            response_id.as_str(),
        ),
        RealtimeServerEvent::ResponseContentPartAdded(response_id) => response_id_frame(
            OpenAiRealtimeServerEventKind::ResponseContentPartAdded,
            "response.content_part.added",
            response_id.as_str(),
        ),
        RealtimeServerEvent::ResponseOutputTextDelta { response_id, delta } => encode(
            OpenAiRealtimeServerEventKind::ResponseOutputTextDelta,
            &TextDeltaWire {
                event_type: "response.output_text.delta",
                response_id: response_id.as_str(),
                delta: delta.as_str(),
            },
        ),
        _ => project_response_terminal_event(event),
    }
}

fn project_response_terminal_event(
    event: &RealtimeServerEvent,
) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    match event {
        RealtimeServerEvent::ResponseOutputTextDone(response_id) => response_id_frame(
            OpenAiRealtimeServerEventKind::ResponseOutputTextDone,
            "response.output_text.done",
            response_id.as_str(),
        ),
        RealtimeServerEvent::ResponseContentPartDone(response_id) => response_id_frame(
            OpenAiRealtimeServerEventKind::ResponseContentPartDone,
            "response.content_part.done",
            response_id.as_str(),
        ),
        RealtimeServerEvent::ResponseOutputItemDone(response_id) => response_id_frame(
            OpenAiRealtimeServerEventKind::ResponseOutputItemDone,
            "response.output_item.done",
            response_id.as_str(),
        ),
        RealtimeServerEvent::ResponseDone {
            response_id,
            finish_reason,
        } => project_response_done(response_id.as_str(), *finish_reason),
        _ => Err(OpenAiRealtimeError::internal()),
    }
}

fn response_id_frame(
    kind: OpenAiRealtimeServerEventKind,
    event_type: &'static str,
    response_id: &str,
) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    encode(
        kind,
        &ResponseIdWire {
            event_type,
            response_id,
        },
    )
}

fn project_response_done(
    response_id: &str,
    finish_reason: RealtimeResponseFinishReason,
) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError> {
    let (status, finish_reason) = response_done_status(finish_reason);
    encode(
        OpenAiRealtimeServerEventKind::ResponseDone,
        &ResponseDoneWire {
            event_type: "response.done",
            response_id,
            status,
            finish_reason,
        },
    )
}

fn response_done_status(reason: RealtimeResponseFinishReason) -> (&'static str, &'static str) {
    match reason {
        RealtimeResponseFinishReason::Completed => ("completed", "completed"),
        RealtimeResponseFinishReason::OutputLimitReached => ("incomplete", "max_output_tokens"),
        RealtimeResponseFinishReason::ContentFiltered => ("incomplete", "content_filter"),
        RealtimeResponseFinishReason::Cancelled => ("cancelled", "cancelled"),
    }
}

fn encode<T>(
    kind: OpenAiRealtimeServerEventKind,
    value: &T,
) -> Result<OpenAiRealtimeOutboundFrame, OpenAiRealtimeError>
where
    T: Serialize,
{
    let encoded = serde_json::to_string(value).map_err(|_| OpenAiRealtimeError::internal())?;
    let frame = RealtimeTextFrame::new(&encoded).map_err(OpenAiRealtimeError::from)?;
    Ok(OpenAiRealtimeOutboundFrame::new(kind, frame))
}

fn error_profile(code: OpenAiRealtimeErrorCode) -> ErrorProfile {
    match code {
        OpenAiRealtimeErrorCode::InvalidRequest => INVALID_REQUEST,
        OpenAiRealtimeErrorCode::InvalidParameter => INVALID_PARAMETER,
        OpenAiRealtimeErrorCode::UnsupportedParameter => UNSUPPORTED_PARAMETER,
        OpenAiRealtimeErrorCode::NotFound => NOT_FOUND,
        OpenAiRealtimeErrorCode::Conflict => CONFLICT,
        _ => runtime_error_profile(code),
    }
}

fn runtime_error_profile(code: OpenAiRealtimeErrorCode) -> ErrorProfile {
    match code {
        OpenAiRealtimeErrorCode::Cancelled => CANCELLED,
        OpenAiRealtimeErrorCode::DeadlineExceeded => DEADLINE_EXCEEDED,
        OpenAiRealtimeErrorCode::ResourceExhausted => RATE_LIMITED,
        OpenAiRealtimeErrorCode::Unavailable => SERVICE_UNAVAILABLE,
        OpenAiRealtimeErrorCode::Internal => INTERNAL_ERROR,
        _ => INTERNAL_ERROR,
    }
}

#[derive(Serialize)]
struct SessionCreatedWire<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    session: SessionWire<'a>,
}

#[derive(Serialize)]
struct SessionWire<'a> {
    id: &'a str,
    object: &'static str,
    #[serde(rename = "type")]
    session_type: &'static str,
    model: &'a str,
    output_modalities: [&'static str; 1],
    default_max_output_tokens: u32,
    limits: SessionLimitsWire,
}

#[derive(Serialize)]
struct SessionLimitsWire {
    max_duration_seconds: u64,
    max_conversation_items: usize,
    max_input_text_bytes: usize,
    max_frame_bytes: usize,
    max_inbound_events: usize,
    max_outbound_events: usize,
}

#[derive(Serialize)]
struct SessionUpdatedWire {
    #[serde(rename = "type")]
    event_type: &'static str,
    session: TextOnlySessionWire,
}

#[derive(Serialize)]
struct TextOnlySessionWire {
    #[serde(rename = "type")]
    session_type: &'static str,
    output_modalities: [&'static str; 1],
}

#[derive(Serialize)]
struct ResponseIdWire<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    response_id: &'a str,
}

#[derive(Serialize)]
struct TextDeltaWire<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    response_id: &'a str,
    delta: &'a str,
}

#[derive(Serialize)]
struct ResponseDoneWire<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    response_id: &'a str,
    status: &'static str,
    finish_reason: &'static str,
}

#[derive(Serialize)]
struct ErrorWire<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    error: ErrorBodyWire<'a>,
}

#[derive(Serialize)]
struct ErrorBodyWire<'a> {
    message: &'static str,
    #[serde(rename = "type")]
    error_type: &'static str,
    #[serde(rename = "param")]
    parameter: Option<&'static str>,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
}

#[derive(Clone, Copy)]
struct ErrorProfile {
    message: &'static str,
    error_type: &'static str,
}

const INVALID_REQUEST: ErrorProfile = ErrorProfile {
    message: "The request is invalid.",
    error_type: "invalid_request_error",
};
const INVALID_PARAMETER: ErrorProfile = ErrorProfile {
    message: "A request parameter is invalid.",
    error_type: "invalid_request_error",
};
const UNSUPPORTED_PARAMETER: ErrorProfile = ErrorProfile {
    message: "A request parameter is unsupported.",
    error_type: "invalid_request_error",
};
const NOT_FOUND: ErrorProfile = ErrorProfile {
    message: "The requested resource was not found.",
    error_type: "invalid_request_error",
};
const CONFLICT: ErrorProfile = ErrorProfile {
    message: "The request conflicts with current state.",
    error_type: "invalid_request_error",
};
const CANCELLED: ErrorProfile = ErrorProfile {
    message: "The request was cancelled.",
    error_type: "server_error",
};
const DEADLINE_EXCEEDED: ErrorProfile = ErrorProfile {
    message: "The request deadline elapsed.",
    error_type: "server_error",
};
const RATE_LIMITED: ErrorProfile = ErrorProfile {
    message: "A request resource limit was reached.",
    error_type: "rate_limit_error",
};
const SERVICE_UNAVAILABLE: ErrorProfile = ErrorProfile {
    message: "The requested service is unavailable.",
    error_type: "server_error",
};
const INTERNAL_ERROR: ErrorProfile = ErrorProfile {
    message: "An internal error occurred.",
    error_type: "server_error",
};

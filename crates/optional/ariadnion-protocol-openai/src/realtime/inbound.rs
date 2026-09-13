// crates/optional/ariadnion-protocol-openai/src/realtime/inbound.rs - Strict OpenAI Realtime client frame decoding.
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
//! Duplicate-aware parsing of the frozen text-only client event grammar.

use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};
use std::future::Future;

use ariadnion_api_domain::{
    FileReference, MAX_REALTIME_CONTENT_PARTS, OutputTokenLimit, RealtimeClientEvent,
    RealtimeClientEventId, RealtimeConversationItem, RealtimeInboundEvent, RealtimeInputContent,
    RealtimeInputText, RealtimeResponseCancel, RealtimeResponseCreate, RealtimeResponseId,
    RealtimeSessionUpdate, RealtimeTextFrame,
};
use serde::de::{self, Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};

use super::OpenAiRealtimeError;

const EVENT_FIELDS: &[&str] = &[
    "type",
    "event_id",
    "session",
    "item",
    "response",
    "response_id",
];
const SESSION_FIELDS: &[&str] = &["type", "output_modalities"];
const ITEM_FIELDS: &[&str] = &["type", "role", "content"];
const CONTENT_FIELDS: &[&str] = &["type", "text", "file_id"];
const RESPONSE_FIELDS: &[&str] = &["output_modalities", "max_output_tokens"];
const MAX_OPENAI_REALTIME_FILE_ALIAS_BYTES: usize = 256;

/// A bounded public OpenAI file alias awaiting tenant-scoped resolution.
///
/// This value cannot become a [`FileReference`] by conversion. The eventual
/// WebSocket adapter resolves it through the provider file-mapping capability,
/// verifies the `user_data` purpose, and then calls
/// [`OpenAiRealtimeDecodedEvent::resolve_file_aliases`].
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OpenAiRealtimeFileAlias(Box<str>);

impl OpenAiRealtimeFileAlias {
    /// Validates one public file alias without retaining a path-like value.
    ///
    /// # Errors
    ///
    /// Returns the stable `invalid_parameter` classification for empty,
    /// non-ASCII, forbidden, or oversized aliases.
    pub fn new(value: &str) -> Result<Self, OpenAiRealtimeError> {
        if !valid_file_alias(value) {
            return Err(OpenAiRealtimeError::invalid_parameter());
        }
        Ok(Self(value.into()))
    }

    /// Borrows the public alias for a tenant-scoped mapping lookup.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for OpenAiRealtimeFileAlias {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiRealtimeFileAlias")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// One parsed client frame whose file aliases have not yet crossed into domain state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiRealtimeDecodedEvent {
    correlation_id: Option<RealtimeClientEventId>,
    event: DecodedClientEvent,
    frame: RealtimeTextFrame,
}

impl OpenAiRealtimeDecodedEvent {
    /// Returns the optional client event identifier for error correlation.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<&RealtimeClientEventId> {
        self.correlation_id.as_ref()
    }

    /// Resolves every public file alias before constructing the domain event.
    ///
    /// The resolver is intentionally supplied by the later adapter integration,
    /// which owns provider/account scope and validates `user_data` purpose. It
    /// receives no text, session, credential, or provider selection state.
    ///
    /// # Errors
    ///
    /// Propagates a redacted resolver failure or rejects a conversion that would
    /// violate the bounded domain event contract.
    pub fn resolve_file_aliases<F>(
        self,
        mut resolve: F,
    ) -> Result<RealtimeInboundEvent, OpenAiRealtimeError>
    where
        F: FnMut(&OpenAiRealtimeFileAlias) -> Result<FileReference, OpenAiRealtimeError>,
    {
        let event = self.event.into_domain(&mut resolve)?;
        Ok(RealtimeInboundEvent::new(
            self.correlation_id,
            event,
            self.frame,
        ))
    }

    /// Resolves every public file alias through an asynchronous capability.
    ///
    /// This variant is used by network transports whose provider mapping port
    /// performs authenticated, cancellable I/O. The decoded event remains
    /// detached from internal file references until the resolver succeeds.
    ///
    /// # Errors
    ///
    /// Propagates a redacted resolver failure or rejects a conversion that would
    /// violate the bounded domain event contract.
    pub async fn resolve_file_aliases_async<F, Fut>(
        self,
        mut resolve: F,
    ) -> Result<RealtimeInboundEvent, OpenAiRealtimeError>
    where
        F: FnMut(&OpenAiRealtimeFileAlias) -> Fut,
        Fut: Future<Output = Result<FileReference, OpenAiRealtimeError>>,
    {
        let event = self.event.into_domain_async(&mut resolve).await?;
        Ok(RealtimeInboundEvent::new(
            self.correlation_id,
            event,
            self.frame,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DecodedClientEvent {
    SessionUpdate,
    ConversationItemCreate(Vec<DecodedContentPart>),
    ResponseCreate(Option<OutputTokenLimit>),
    ResponseCancel(Option<RealtimeResponseId>),
}

impl DecodedClientEvent {
    fn into_domain<F>(self, resolve: &mut F) -> Result<RealtimeClientEvent, OpenAiRealtimeError>
    where
        F: FnMut(&OpenAiRealtimeFileAlias) -> Result<FileReference, OpenAiRealtimeError>,
    {
        match self {
            Self::SessionUpdate => Ok(RealtimeClientEvent::SessionUpdate(
                RealtimeSessionUpdate::text_only(),
            )),
            Self::ConversationItemCreate(parts) => {
                let content = parts
                    .into_iter()
                    .map(|part| part.into_domain(resolve))
                    .collect::<Result<Vec<_>, _>>()?;
                let item =
                    RealtimeConversationItem::new(content).map_err(OpenAiRealtimeError::from)?;
                Ok(RealtimeClientEvent::ConversationItemCreate(item))
            }
            Self::ResponseCreate(limit) => Ok(RealtimeClientEvent::ResponseCreate(
                RealtimeResponseCreate::new(limit),
            )),
            Self::ResponseCancel(response_id) => Ok(RealtimeClientEvent::ResponseCancel(
                RealtimeResponseCancel::new(response_id),
            )),
        }
    }

    async fn into_domain_async<F, Fut>(
        self,
        resolve: &mut F,
    ) -> Result<RealtimeClientEvent, OpenAiRealtimeError>
    where
        F: FnMut(&OpenAiRealtimeFileAlias) -> Fut,
        Fut: Future<Output = Result<FileReference, OpenAiRealtimeError>>,
    {
        match self {
            Self::SessionUpdate => Ok(RealtimeClientEvent::SessionUpdate(
                RealtimeSessionUpdate::text_only(),
            )),
            Self::ConversationItemCreate(parts) => {
                let mut content = Vec::with_capacity(parts.len());
                for part in parts {
                    content.push(part.into_domain_async(resolve).await?);
                }
                let item =
                    RealtimeConversationItem::new(content).map_err(OpenAiRealtimeError::from)?;
                Ok(RealtimeClientEvent::ConversationItemCreate(item))
            }
            Self::ResponseCreate(limit) => Ok(RealtimeClientEvent::ResponseCreate(
                RealtimeResponseCreate::new(limit),
            )),
            Self::ResponseCancel(response_id) => Ok(RealtimeClientEvent::ResponseCancel(
                RealtimeResponseCancel::new(response_id),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DecodedContentPart {
    Text(RealtimeInputText),
    File(OpenAiRealtimeFileAlias),
}

impl DecodedContentPart {
    fn into_domain<F>(self, resolve: &mut F) -> Result<RealtimeInputContent, OpenAiRealtimeError>
    where
        F: FnMut(&OpenAiRealtimeFileAlias) -> Result<FileReference, OpenAiRealtimeError>,
    {
        match self {
            Self::Text(text) => Ok(RealtimeInputContent::text(text)),
            Self::File(alias) => resolve(&alias).map(RealtimeInputContent::file),
        }
    }

    async fn into_domain_async<F, Fut>(
        self,
        resolve: &mut F,
    ) -> Result<RealtimeInputContent, OpenAiRealtimeError>
    where
        F: FnMut(&OpenAiRealtimeFileAlias) -> Fut,
        Fut: Future<Output = Result<FileReference, OpenAiRealtimeError>>,
    {
        match self {
            Self::Text(text) => Ok(RealtimeInputContent::text(text)),
            Self::File(alias) => resolve(&alias).await.map(RealtimeInputContent::file),
        }
    }
}

pub(super) fn decode_client_frame(
    frame: &str,
) -> Result<OpenAiRealtimeDecodedEvent, OpenAiRealtimeError> {
    let frame = RealtimeTextFrame::new(frame).map_err(OpenAiRealtimeError::from)?;
    let raw = {
        let mut deserializer = serde_json::Deserializer::from_str(frame.as_str());
        let raw = RawEvent::deserialize(&mut deserializer)
            .map_err(|_| OpenAiRealtimeError::invalid_request())?;
        deserializer
            .end()
            .map_err(|_| OpenAiRealtimeError::invalid_request())?;
        raw
    };
    raw.into_decoded(frame.clone())
}

struct RawEvent<'a> {
    event_type: Cow<'a, str>,
    event_id: Option<Cow<'a, str>>,
    session: Option<RawSession>,
    item: Option<RawItem<'a>>,
    response: Option<RawResponse>,
    response_id: Option<Cow<'a, str>>,
}

impl RawEvent<'_> {
    fn into_decoded(
        self,
        frame: RealtimeTextFrame,
    ) -> Result<OpenAiRealtimeDecodedEvent, OpenAiRealtimeError> {
        let correlation_id = self
            .event_id
            .as_deref()
            .map(RealtimeClientEventId::new)
            .transpose()
            .map_err(OpenAiRealtimeError::from)?;
        let event = self.into_event()?;
        Ok(OpenAiRealtimeDecodedEvent {
            correlation_id,
            event,
            frame,
        })
    }

    fn into_event(self) -> Result<DecodedClientEvent, OpenAiRealtimeError> {
        match self.event_type.as_ref() {
            "session.update" => self.session_update(),
            "conversation.item.create" => self.conversation_item_create(),
            "response.create" => self.response_create(),
            "response.cancel" => self.response_cancel(),
            _ => Err(OpenAiRealtimeError::unsupported_parameter()),
        }
    }

    fn session_update(self) -> Result<DecodedClientEvent, OpenAiRealtimeError> {
        reject_present(
            self.item.is_some() || self.response.is_some() || self.response_id.is_some(),
        )?;
        let session = self
            .session
            .ok_or_else(OpenAiRealtimeError::invalid_request)?;
        session.validate()?;
        Ok(DecodedClientEvent::SessionUpdate)
    }

    fn conversation_item_create(self) -> Result<DecodedClientEvent, OpenAiRealtimeError> {
        reject_present(
            self.session.is_some() || self.response.is_some() || self.response_id.is_some(),
        )?;
        let item = self.item.ok_or_else(OpenAiRealtimeError::invalid_request)?;
        Ok(DecodedClientEvent::ConversationItemCreate(
            item.into_parts()?,
        ))
    }

    fn response_create(self) -> Result<DecodedClientEvent, OpenAiRealtimeError> {
        reject_present(
            self.session.is_some() || self.item.is_some() || self.response_id.is_some(),
        )?;
        let limit = self
            .response
            .map(RawResponse::into_output_limit)
            .transpose()?;
        Ok(DecodedClientEvent::ResponseCreate(limit))
    }

    fn response_cancel(self) -> Result<DecodedClientEvent, OpenAiRealtimeError> {
        reject_present(self.session.is_some() || self.item.is_some() || self.response.is_some())?;
        let response_id = self
            .response_id
            .as_deref()
            .map(RealtimeResponseId::new)
            .transpose()
            .map_err(OpenAiRealtimeError::from)?;
        Ok(DecodedClientEvent::ResponseCancel(response_id))
    }
}

impl<'de> Deserialize<'de> for RawEvent<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(EventVisitor)
    }
}

struct EventVisitor;

impl<'de> Visitor<'de> for EventVisitor {
    type Value = RawEvent<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict OpenAI Realtime client event object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = EventFields::default();
        while let Some(field) = map.next_key::<&str>()? {
            fields.read(field, &mut map)?;
        }
        fields.finish()
    }
}

#[derive(Default)]
struct EventFields<'a> {
    event_type: Option<Cow<'a, str>>,
    event_id: Option<Cow<'a, str>>,
    event_id_seen: bool,
    session: Option<RawSession>,
    item: Option<RawItem<'a>>,
    response: Option<RawResponse>,
    response_seen: bool,
    response_id: Option<Cow<'a, str>>,
    response_id_seen: bool,
}

impl<'de> EventFields<'de> {
    fn read<A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "type" => read_once(&mut self.event_type, "type", map),
            "event_id" => {
                read_once_seen(&mut self.event_id, &mut self.event_id_seen, "event_id", map)
            }
            "session" => read_once(&mut self.session, "session", map),
            "item" => read_once(&mut self.item, "item", map),
            "response" => {
                read_once_seen(&mut self.response, &mut self.response_seen, "response", map)
            }
            "response_id" => read_once_seen(
                &mut self.response_id,
                &mut self.response_id_seen,
                "response_id",
                map,
            ),
            _ => Err(A::Error::unknown_field(field, EVENT_FIELDS)),
        }
    }

    fn finish<E>(self) -> Result<RawEvent<'de>, E>
    where
        E: de::Error,
    {
        Ok(RawEvent {
            event_type: self.event_type.ok_or_else(|| E::missing_field("type"))?,
            event_id: self.event_id,
            session: self.session,
            item: self.item,
            response: self.response,
            response_id: self.response_id,
        })
    }
}

struct RawSession {
    session_type: Box<str>,
    output_modalities: TextOnlyModalities,
}

impl RawSession {
    fn validate(self) -> Result<(), OpenAiRealtimeError> {
        if self.session_type.as_ref() != "realtime" || !self.output_modalities.is_text_only() {
            return Err(OpenAiRealtimeError::unsupported_parameter());
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RawSession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SessionVisitor)
    }
}

struct SessionVisitor;

impl<'de> Visitor<'de> for SessionVisitor {
    type Value = RawSession;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a text-only Realtime session update")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut session_type = None;
        let mut output_modalities = None;
        while let Some(field) = map.next_key::<&str>()? {
            if !read_session_field(field, &mut map, &mut session_type, &mut output_modalities)? {
                return Err(A::Error::unknown_field(field, SESSION_FIELDS));
            }
        }
        Ok(RawSession {
            session_type: session_type.ok_or_else(|| A::Error::missing_field("type"))?,
            output_modalities: output_modalities
                .ok_or_else(|| A::Error::missing_field("output_modalities"))?,
        })
    }
}

struct RawItem<'a> {
    item_type: Cow<'a, str>,
    role: Cow<'a, str>,
    content: RawContents<'a>,
}

impl RawItem<'_> {
    fn into_parts(self) -> Result<Vec<DecodedContentPart>, OpenAiRealtimeError> {
        if self.item_type != "message" || self.role != "user" {
            return Err(OpenAiRealtimeError::unsupported_parameter());
        }
        self.content.into_parts()
    }
}

impl<'de> Deserialize<'de> for RawItem<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ItemVisitor)
    }
}

struct ItemVisitor;

fn read_session_field<'de, A>(
    field: &str,
    map: &mut A,
    session_type: &mut Option<Box<str>>,
    output_modalities: &mut Option<TextOnlyModalities>,
) -> Result<bool, A::Error>
where
    A: MapAccess<'de>,
{
    match field {
        "type" => {
            read_once(session_type, "type", map)?;
            Ok(true)
        }
        "output_modalities" => {
            read_once(output_modalities, "output_modalities", map)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

impl<'de> Visitor<'de> for ItemVisitor {
    type Value = RawItem<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a text-only user Realtime message item")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut item_type = None;
        let mut role = None;
        let mut content = None;
        while let Some(field) = map.next_key::<&str>()? {
            read_item_field(field, &mut map, &mut item_type, &mut role, &mut content)?;
        }
        Ok(RawItem {
            item_type: item_type.ok_or_else(|| A::Error::missing_field("type"))?,
            role: role.ok_or_else(|| A::Error::missing_field("role"))?,
            content: content.ok_or_else(|| A::Error::missing_field("content"))?,
        })
    }
}

fn read_item_field<'de, A>(
    field: &str,
    map: &mut A,
    item_type: &mut Option<Cow<'de, str>>,
    role: &mut Option<Cow<'de, str>>,
    content: &mut Option<RawContents<'de>>,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    match field {
        "type" => {
            read_once(item_type, "type", map)?;
            Ok(())
        }
        "role" => {
            read_once(role, "role", map)?;
            Ok(())
        }
        "content" => {
            read_once(content, "content", map)?;
            Ok(())
        }
        _ => Err(A::Error::unknown_field(field, ITEM_FIELDS)),
    }
}

struct RawContents<'a>(Vec<RawContent<'a>>);

impl RawContents<'_> {
    fn into_parts(self) -> Result<Vec<DecodedContentPart>, OpenAiRealtimeError> {
        self.0
            .into_iter()
            .map(RawContent::into_part)
            .collect::<Result<Vec<_>, _>>()
    }
}

impl<'de> Deserialize<'de> for RawContents<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ContentsVisitor)
    }
}

struct ContentsVisitor;

impl<'de> Visitor<'de> for ContentsVisitor {
    type Value = RawContents<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Realtime text or file content array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut content = Vec::with_capacity(
            sequence
                .size_hint()
                .map_or(0, |value| value.min(MAX_REALTIME_CONTENT_PARTS)),
        );
        while let Some(part) = sequence.next_element()? {
            if content.len() == MAX_REALTIME_CONTENT_PARTS {
                return Err(A::Error::custom("Realtime content part count exceeded"));
            }
            content.push(part);
        }
        Ok(RawContents(content))
    }
}

struct RawContent<'a> {
    content_type: Cow<'a, str>,
    text: Option<Cow<'a, str>>,
    file_id: Option<Cow<'a, str>>,
}

impl RawContent<'_> {
    fn into_part(self) -> Result<DecodedContentPart, OpenAiRealtimeError> {
        match self.content_type.as_ref() {
            "input_text" => self.text_part(),
            "input_file" => self.file_part(),
            _ => Err(OpenAiRealtimeError::unsupported_parameter()),
        }
    }

    fn text_part(self) -> Result<DecodedContentPart, OpenAiRealtimeError> {
        if self.file_id.is_some() {
            return Err(OpenAiRealtimeError::invalid_request());
        }
        let text = self.text.ok_or_else(OpenAiRealtimeError::invalid_request)?;
        let text = RealtimeInputText::new(text.as_ref()).map_err(OpenAiRealtimeError::from)?;
        Ok(DecodedContentPart::Text(text))
    }

    fn file_part(self) -> Result<DecodedContentPart, OpenAiRealtimeError> {
        if self.text.is_some() {
            return Err(OpenAiRealtimeError::invalid_request());
        }
        let file_id = self
            .file_id
            .ok_or_else(OpenAiRealtimeError::invalid_request)?;
        Ok(DecodedContentPart::File(OpenAiRealtimeFileAlias::new(
            file_id.as_ref(),
        )?))
    }
}

impl<'de> Deserialize<'de> for RawContent<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ContentVisitor)
    }
}

struct ContentVisitor;

impl<'de> Visitor<'de> for ContentVisitor {
    type Value = RawContent<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("one strict Realtime input content object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut content_type = None;
        let mut text = None;
        let mut file_id = None;
        while let Some(field) = map.next_key::<&str>()? {
            if !read_content_field(field, &mut map, &mut content_type, &mut text, &mut file_id)? {
                return Err(A::Error::unknown_field(field, CONTENT_FIELDS));
            }
        }
        Ok(RawContent {
            content_type: content_type.ok_or_else(|| A::Error::missing_field("type"))?,
            text,
            file_id,
        })
    }
}

fn read_content_field<'de, A>(
    field: &str,
    map: &mut A,
    content_type: &mut Option<Cow<'de, str>>,
    text: &mut Option<Cow<'de, str>>,
    file_id: &mut Option<Cow<'de, str>>,
) -> Result<bool, A::Error>
where
    A: MapAccess<'de>,
{
    match field {
        "type" => {
            read_once(content_type, "type", map)?;
            Ok(true)
        }
        "text" => {
            read_once(text, "text", map)?;
            Ok(true)
        }
        "file_id" => {
            read_once(file_id, "file_id", map)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

struct RawResponse {
    output_modalities: TextOnlyModalities,
    max_output_tokens: u32,
}

impl RawResponse {
    fn into_output_limit(self) -> Result<OutputTokenLimit, OpenAiRealtimeError> {
        if !self.output_modalities.is_text_only() {
            return Err(OpenAiRealtimeError::unsupported_parameter());
        }
        OutputTokenLimit::new(self.max_output_tokens).map_err(OpenAiRealtimeError::from)
    }
}

impl<'de> Deserialize<'de> for RawResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ResponseVisitor)
    }
}

struct ResponseVisitor;

impl<'de> Visitor<'de> for ResponseVisitor {
    type Value = RawResponse;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a text-only Realtime response override")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output_modalities = None;
        let mut max_output_tokens = None;
        while let Some(field) = map.next_key::<&str>()? {
            if !read_response_field(
                field,
                &mut map,
                &mut output_modalities,
                &mut max_output_tokens,
            )? {
                return Err(A::Error::unknown_field(field, RESPONSE_FIELDS));
            }
        }
        Ok(RawResponse {
            output_modalities: output_modalities
                .ok_or_else(|| A::Error::missing_field("output_modalities"))?,
            max_output_tokens: max_output_tokens
                .ok_or_else(|| A::Error::missing_field("max_output_tokens"))?,
        })
    }
}

fn read_response_field<'de, A>(
    field: &str,
    map: &mut A,
    output_modalities: &mut Option<TextOnlyModalities>,
    max_output_tokens: &mut Option<u32>,
) -> Result<bool, A::Error>
where
    A: MapAccess<'de>,
{
    match field {
        "output_modalities" => {
            read_once(output_modalities, "output_modalities", map)?;
            Ok(true)
        }
        "max_output_tokens" => {
            read_once(max_output_tokens, "max_output_tokens", map)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

struct TextOnlyModalities;

impl TextOnlyModalities {
    const fn is_text_only(&self) -> bool {
        true
    }
}

impl<'de> Deserialize<'de> for TextOnlyModalities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(TextOnlyModalitiesVisitor)
    }
}

struct TextOnlyModalitiesVisitor;

impl<'de> Visitor<'de> for TextOnlyModalitiesVisitor {
    type Value = TextOnlyModalities;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("the exact text-only output modality array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let first = sequence
            .next_element::<Cow<'de, str>>()?
            .ok_or_else(|| A::Error::invalid_length(0, &self))?;
        if first != "text" || sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "only one text output modality is supported",
            ));
        }
        Ok(TextOnlyModalities)
    }
}

fn read_once<'de, A, T>(
    slot: &mut Option<T>,
    field: &'static str,
    map: &mut A,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
    T: Deserialize<'de>,
{
    if slot.is_some() {
        return Err(A::Error::duplicate_field(field));
    }
    *slot = Some(map.next_value()?);
    Ok(())
}

fn read_once_seen<'de, A, T>(
    slot: &mut Option<T>,
    seen: &mut bool,
    field: &'static str,
    map: &mut A,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
    T: Deserialize<'de>,
{
    if *seen {
        return Err(A::Error::duplicate_field(field));
    }
    *slot = Some(map.next_value()?);
    *seen = true;
    Ok(())
}

fn reject_present(present: bool) -> Result<(), OpenAiRealtimeError> {
    if present {
        return Err(OpenAiRealtimeError::invalid_request());
    }
    Ok(())
}

fn valid_file_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPENAI_REALTIME_FILE_ALIAS_BYTES
        && value.is_ascii()
        && value.bytes().all(valid_file_alias_byte)
}

fn valid_file_alias_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
}

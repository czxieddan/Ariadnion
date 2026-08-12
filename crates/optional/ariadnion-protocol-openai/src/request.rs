// crates/optional/ariadnion-protocol-openai/src/request.rs - Strict OpenAI chat request decoding for Ariadnion.
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
//! Duplicate-aware conversion from the accepted OpenAI JSON subset to domain values.

use std::borrow::Cow;
use std::fmt::{self, Formatter};

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, ChatMessage, ChatMessageContent, ChatMessages, ChatRole,
    ChatServiceRequest, MAX_CHAT_MESSAGES, MAX_CHAT_MESSAGES_BYTES, MAX_OUTPUT_TOKENS,
    ModelSelector, OutputTokenLimit, ResponseMode, ServiceContractVersion,
};
use serde::de::{self, Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};

const REQUEST_FIELDS: &[&str] = &["model", "messages", "stream", "stream_options"];
const MESSAGE_FIELDS: &[&str] = &["role", "content"];
const STREAM_OPTION_FIELDS: &[&str] = &["include_usage"];

pub(crate) struct DecodedRequest {
    pub(crate) request: ChatServiceRequest,
    pub(crate) model: Box<str>,
    pub(crate) include_usage: bool,
}

pub(crate) fn decode(bytes: &[u8]) -> Result<DecodedRequest, ApiDomainError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = RawRequest::deserialize(&mut deserializer).map_err(|_| invalid_argument())?;
    deserializer.end().map_err(|_| invalid_argument())?;
    raw.into_domain()
}

struct RawRequest<'a> {
    model: Cow<'a, str>,
    messages: RawMessages<'a>,
    stream: bool,
    stream_options: Option<RawStreamOptions>,
}

impl RawRequest<'_> {
    fn into_domain(self) -> Result<DecodedRequest, ApiDomainError> {
        validate_stream_options(self.stream, self.stream_options.as_ref())?;
        let model = ModelSelector::new(self.model.as_ref())?;
        let projection_model = model.as_str().into();
        let messages = convert_messages(self.messages)?;
        let response_mode = response_mode(self.stream);
        let output_token_limit = OutputTokenLimit::new(MAX_OUTPUT_TOKENS)?;
        let include_usage = self
            .stream_options
            .and_then(|options| options.include_usage)
            .unwrap_or(false);
        Ok(DecodedRequest {
            request: ChatServiceRequest::new(
                ServiceContractVersion::V1,
                model,
                messages,
                output_token_limit,
                response_mode,
                None,
            ),
            model: projection_model,
            include_usage,
        })
    }
}

impl<'de> Deserialize<'de> for RawRequest<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RequestVisitor)
    }
}

struct RequestVisitor;

impl<'de> Visitor<'de> for RequestVisitor {
    type Value = RawRequest<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenAI chat completion request object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = RequestValues::default();
        while let Some(field) = map.next_key::<&str>()? {
            fields.read(field, &mut map)?;
        }
        fields.finish()
    }
}

#[derive(Default)]
struct RequestValues<'a> {
    model: Option<Cow<'a, str>>,
    messages: Option<RawMessages<'a>>,
    stream: Option<Option<bool>>,
    stream_options: Option<RawStreamOptions>,
}

impl<'de> RequestValues<'de> {
    fn read<A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "model" => self.read_model(map),
            "messages" => self.read_messages(map),
            "stream" => self.read_stream(map),
            "stream_options" => self.read_stream_options(map),
            _ => Err(A::Error::unknown_field(field, REQUEST_FIELDS)),
        }
    }

    fn read_model<A>(&mut self, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        reject_duplicate(self.model.is_some(), "model")?;
        self.model = Some(map.next_value()?);
        Ok(())
    }

    fn read_messages<A>(&mut self, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        reject_duplicate(self.messages.is_some(), "messages")?;
        self.messages = Some(map.next_value()?);
        Ok(())
    }

    fn read_stream<A>(&mut self, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        reject_duplicate(self.stream.is_some(), "stream")?;
        self.stream = Some(map.next_value()?);
        Ok(())
    }

    fn read_stream_options<A>(&mut self, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        reject_duplicate(self.stream_options.is_some(), "stream_options")?;
        self.stream_options = Some(map.next_value()?);
        Ok(())
    }

    fn finish<E>(self) -> Result<RawRequest<'de>, E>
    where
        E: de::Error,
    {
        Ok(RawRequest {
            model: self.model.ok_or_else(|| E::missing_field("model"))?,
            messages: self.messages.ok_or_else(|| E::missing_field("messages"))?,
            stream: self.stream.flatten().unwrap_or(false),
            stream_options: self.stream_options,
        })
    }
}

struct RawMessage<'a> {
    role: Cow<'a, str>,
    content: Cow<'a, str>,
}

struct RawMessages<'a>(Vec<RawMessage<'a>>);

impl<'de> Deserialize<'de> for RawMessages<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(MessagesVisitor)
    }
}

struct MessagesVisitor;

impl<'de> Visitor<'de> for MessagesVisitor {
    type Value = RawMessages<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded OpenAI chat message array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = sequence
            .size_hint()
            .map_or(0, |size| size.min(MAX_CHAT_MESSAGES));
        let mut messages = Vec::with_capacity(capacity);
        let mut encoded_bytes = 0usize;
        while let Some(message) = sequence.next_element()? {
            encoded_bytes = checked_raw_message(&message, messages.len(), encoded_bytes)
                .map_err(A::Error::custom)?;
            messages.push(message);
        }
        Ok(RawMessages(messages))
    }
}

impl<'de> Deserialize<'de> for RawMessage<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(MessageVisitor)
    }
}

struct MessageVisitor;

impl<'de> Visitor<'de> for MessageVisitor {
    type Value = RawMessage<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenAI chat message object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        read_message_map(&mut map)
    }
}

#[derive(Default)]
struct MessageValues<'a> {
    role: Option<Cow<'a, str>>,
    content: Option<Cow<'a, str>>,
}

impl<'de> MessageValues<'de> {
    fn read<A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "role" => read_once(&mut self.role, "role", map),
            "content" => read_once(&mut self.content, "content", map),
            _ => Err(A::Error::unknown_field(field, MESSAGE_FIELDS)),
        }
    }

    fn finish<E>(self) -> Result<RawMessage<'de>, E>
    where
        E: de::Error,
    {
        Ok(RawMessage {
            role: self.role.ok_or_else(|| E::missing_field("role"))?,
            content: self.content.ok_or_else(|| E::missing_field("content"))?,
        })
    }
}

#[derive(Default)]
struct StreamOptionValues {
    include_usage: Option<bool>,
}

impl StreamOptionValues {
    fn read<'de, A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "include_usage" => read_once(&mut self.include_usage, "include_usage", map),
            _ => Err(A::Error::unknown_field(field, STREAM_OPTION_FIELDS)),
        }
    }

    const fn finish(self) -> RawStreamOptions {
        RawStreamOptions {
            include_usage: self.include_usage,
        }
    }
}

fn read_message_map<'de, A>(map: &mut A) -> Result<RawMessage<'de>, A::Error>
where
    A: MapAccess<'de>,
{
    let mut fields = MessageValues::default();
    while let Some(field) = map.next_key::<&str>()? {
        fields.read(field, map)?;
    }
    fields.finish()
}

fn read_stream_options_map<'de, A>(map: &mut A) -> Result<RawStreamOptions, A::Error>
where
    A: MapAccess<'de>,
{
    let mut fields = StreamOptionValues::default();
    while let Some(field) = map.next_key::<&str>()? {
        fields.read(field, map)?;
    }
    Ok(fields.finish())
}

fn read_once<'de, A, T>(
    slot: &mut Option<T>,
    name: &'static str,
    map: &mut A,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
    T: Deserialize<'de>,
{
    reject_duplicate(slot.is_some(), name)?;
    *slot = Some(map.next_value()?);
    Ok(())
}

fn reject_duplicate<E>(duplicate: bool, field: &'static str) -> Result<(), E>
where
    E: de::Error,
{
    if duplicate {
        return Err(E::duplicate_field(field));
    }
    Ok(())
}

fn convert_messages(raw: RawMessages<'_>) -> Result<ChatMessages, ApiDomainError> {
    let messages = raw
        .0
        .into_iter()
        .map(convert_message)
        .collect::<Result<Vec<_>, _>>()?;
    ChatMessages::new(messages)
}

fn convert_message(raw: RawMessage<'_>) -> Result<ChatMessage, ApiDomainError> {
    let role = parse_role(raw.role.as_ref())?;
    let content = ChatMessageContent::new(raw.content.as_ref())?;
    Ok(ChatMessage::new(role, content))
}

fn parse_role(value: &str) -> Result<ChatRole, ApiDomainError> {
    match value {
        "developer" => Ok(ChatRole::Developer),
        "system" => Ok(ChatRole::System),
        "user" => Ok(ChatRole::User),
        "assistant" => Ok(ChatRole::Assistant),
        _ => Err(invalid_argument()),
    }
}

fn validate_stream_options(
    stream: bool,
    options: Option<&RawStreamOptions>,
) -> Result<(), ApiDomainError> {
    if options.is_some() && !stream {
        return Err(invalid_argument());
    }
    Ok(())
}

const fn response_mode(stream: bool) -> ResponseMode {
    if stream {
        ResponseMode::Stream
    } else {
        ResponseMode::Complete
    }
}

const fn invalid_argument() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::InvalidArgument)
}

struct RawStreamOptions {
    include_usage: Option<bool>,
}

impl<'de> Deserialize<'de> for RawStreamOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(StreamOptionsVisitor)
    }
}

struct StreamOptionsVisitor;

impl<'de> Visitor<'de> for StreamOptionsVisitor {
    type Value = RawStreamOptions;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenAI stream options object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        read_stream_options_map(&mut map)
    }
}

fn checked_raw_message(
    message: &RawMessage<'_>,
    count: usize,
    encoded_bytes: usize,
) -> Result<usize, &'static str> {
    if count >= MAX_CHAT_MESSAGES {
        return Err("chat message count exceeded");
    }
    let next = encoded_bytes
        .checked_add(message.content.len())
        .ok_or("chat message bytes exceeded")?;
    if next > MAX_CHAT_MESSAGES_BYTES {
        return Err("chat message bytes exceeded");
    }
    Ok(next)
}

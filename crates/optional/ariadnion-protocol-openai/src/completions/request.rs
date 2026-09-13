// crates/optional/ariadnion-protocol-openai/src/completions/request.rs - Strict legacy Completions request decoding.
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
//! Duplicate-aware decoding for the frozen single-string prompt subset.

use std::borrow::Cow;
use std::fmt::{self, Formatter};

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, MAX_OUTPUT_TOKENS, ModelSelector, OutputTokenLimit,
    ResponseMode, ServiceContractVersion, TextInput, TextServiceRequest,
};
use serde::de::{self, Deserialize, Deserializer, Error as _, MapAccess, Visitor};

const REQUEST_FIELDS: &[&str] = &["model", "prompt", "max_tokens", "stream", "stream_options"];
const STREAM_OPTION_FIELDS: &[&str] = &["include_usage"];

pub(crate) struct DecodedRequest {
    pub(crate) request: TextServiceRequest,
    pub(crate) model: Box<str>,
    pub(crate) response_mode: ResponseMode,
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
    prompt: Cow<'a, str>,
    max_tokens: u32,
    stream: bool,
    stream_options: Option<RawStreamOptions>,
}

impl RawRequest<'_> {
    fn into_domain(self) -> Result<DecodedRequest, ApiDomainError> {
        if self.stream_options.is_some() && !self.stream {
            return Err(invalid_argument());
        }
        let model = ModelSelector::new(self.model.as_ref())?;
        let input = TextInput::new(self.prompt.as_ref())?;
        let output_token_limit = OutputTokenLimit::new(self.max_tokens)?;
        let response_mode = if self.stream {
            ResponseMode::Stream
        } else {
            ResponseMode::Complete
        };
        let include_usage = self
            .stream_options
            .and_then(|options| options.include_usage)
            .unwrap_or(false);
        let projection_model = model.as_str().into();
        Ok(DecodedRequest {
            request: TextServiceRequest::new(
                ServiceContractVersion::V1,
                model,
                input,
                output_token_limit,
                response_mode,
                None,
            ),
            model: projection_model,
            response_mode,
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
        formatter.write_str("an OpenAI legacy completion request object")
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
    prompt: Option<Cow<'a, str>>,
    max_tokens: Option<u32>,
    stream: Option<bool>,
    stream_options: Option<RawStreamOptions>,
}

impl<'de> RequestValues<'de> {
    fn read<A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "model" => read_once(&mut self.model, "model", map),
            "prompt" => read_once(&mut self.prompt, "prompt", map),
            "max_tokens" => read_once(&mut self.max_tokens, "max_tokens", map),
            "stream" => read_once(&mut self.stream, "stream", map),
            "stream_options" => read_once(&mut self.stream_options, "stream_options", map),
            _ => Err(A::Error::unknown_field(field, REQUEST_FIELDS)),
        }
    }

    fn finish<E>(self) -> Result<RawRequest<'de>, E>
    where
        E: de::Error,
    {
        Ok(RawRequest {
            model: self.model.ok_or_else(|| E::missing_field("model"))?,
            prompt: self.prompt.ok_or_else(|| E::missing_field("prompt"))?,
            max_tokens: self
                .max_tokens
                .ok_or_else(|| E::missing_field("max_tokens"))?,
            stream: self.stream.unwrap_or(false),
            stream_options: self.stream_options,
        })
    }
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
        formatter.write_str("an OpenAI completion stream options object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut include_usage = None;
        while let Some(field) = map.next_key::<&str>()? {
            match field {
                "include_usage" => read_once(&mut include_usage, "include_usage", &mut map)?,
                _ => return Err(A::Error::unknown_field(field, STREAM_OPTION_FIELDS)),
            }
        }
        Ok(RawStreamOptions { include_usage })
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

const fn invalid_argument() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::InvalidArgument)
}

const _: u32 = MAX_OUTPUT_TOKENS;

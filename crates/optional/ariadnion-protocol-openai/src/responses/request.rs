// crates/optional/ariadnion-protocol-openai/src/responses/request.rs - Strict Responses request decoding.
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
//! Duplicate-aware decoder for the frozen create-only Responses text subset.

use std::borrow::Cow;
use std::fmt::{self, Formatter};

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, IdempotencyKey, ModelSelector, OutputTokenLimit,
    ResponseMode, ServiceContractVersion, TextInput, TextServiceRequest,
};
use serde::de::{self, Deserialize, Deserializer, Error as _, MapAccess, Visitor};

const REQUEST_FIELDS: &[&str] = &["model", "input", "max_output_tokens", "stream"];

pub(crate) struct DecodedRequest {
    pub(crate) request: TextServiceRequest,
    pub(crate) model: Box<str>,
    pub(crate) response_mode: ResponseMode,
}

pub(crate) fn decode(bytes: &[u8]) -> Result<DecodedRequest, ApiDomainError> {
    decode_with_idempotency(bytes, None)
}

pub(crate) fn decode_with_idempotency(
    bytes: &[u8],
    idempotency: Option<IdempotencyKey>,
) -> Result<DecodedRequest, ApiDomainError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = RawRequest::deserialize(&mut deserializer).map_err(|_| invalid_argument())?;
    deserializer.end().map_err(|_| invalid_argument())?;
    raw.into_domain(idempotency)
}

struct RawRequest<'a> {
    model: Cow<'a, str>,
    input: Cow<'a, str>,
    max_output_tokens: u32,
    stream: bool,
}

impl RawRequest<'_> {
    fn into_domain(
        self,
        idempotency: Option<IdempotencyKey>,
    ) -> Result<DecodedRequest, ApiDomainError> {
        let model = ModelSelector::new(self.model.as_ref())?;
        let projection_model = model.as_str().into();
        let input = TextInput::new(self.input.as_ref())?;
        let output_token_limit = OutputTokenLimit::new(self.max_output_tokens)?;
        let response_mode = if self.stream {
            ResponseMode::Stream
        } else {
            ResponseMode::Complete
        };
        Ok(DecodedRequest {
            request: TextServiceRequest::new(
                ServiceContractVersion::V1,
                model,
                input,
                output_token_limit,
                response_mode,
                idempotency,
            ),
            model: projection_model,
            response_mode,
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
        formatter.write_str("an OpenAI Responses create request object")
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
    input: Option<Cow<'a, str>>,
    max_output_tokens: Option<u32>,
    stream: Option<bool>,
    stream_seen: bool,
}

impl<'de> RequestValues<'de> {
    fn read<A>(&mut self, field: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        match field {
            "model" => read_once(&mut self.model, "model", map),
            "input" => read_once(&mut self.input, "input", map),
            "max_output_tokens" => read_once(&mut self.max_output_tokens, "max_output_tokens", map),
            "stream" => {
                reject_duplicate(self.stream_seen, "stream")?;
                self.stream = Some(map.next_value()?);
                self.stream_seen = true;
                Ok(())
            }
            _ => Err(A::Error::unknown_field(field, REQUEST_FIELDS)),
        }
    }

    fn finish<E>(self) -> Result<RawRequest<'de>, E>
    where
        E: de::Error,
    {
        Ok(RawRequest {
            model: self.model.ok_or_else(|| E::missing_field("model"))?,
            input: self.input.ok_or_else(|| E::missing_field("input"))?,
            max_output_tokens: self
                .max_output_tokens
                .ok_or_else(|| E::missing_field("max_output_tokens"))?,
            stream: self.stream.unwrap_or(false),
        })
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
    reject_duplicate(slot.is_some(), field)?;
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

const fn invalid_argument() -> ApiDomainError {
    ApiDomainError::new(ApiDomainErrorCode::InvalidArgument)
}

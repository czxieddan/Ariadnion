// crates/optional/ariadnion-protocol-openai/src/batch.rs - OpenAI Batch protocol adapter.
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
//! OpenAI Batch JSON and JSONL validation helpers.

use std::fmt::{self, Formatter};

use ariadnion_api_domain::{
    ApiBatchError, BatchCompletionWindow, BatchEndpoint, BatchInputFile, BatchRequestLine,
    FileByteLength, FileReference, MAX_BATCH_CUSTOM_ID_BYTES, MAX_BATCH_INPUT_BYTES,
    MAX_BATCH_REQUESTS,
};
use serde::Deserialize;
use serde::de::{Deserializer, Error as _, MapAccess, Visitor};
use serde_json::value::RawValue;

/// Frozen OpenAI Batch route.
pub const OPENAI_BATCH_PATH: &str = "/v1/batches";

const MAX_BATCH_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_BATCH_ENVELOPE_OVERHEAD_BYTES: usize = 1024;
const MAX_BATCH_ENVELOPE_BYTES: usize =
    MAX_BATCH_BODY_BYTES + MAX_BATCH_CUSTOM_ID_BYTES + MAX_BATCH_ENVELOPE_OVERHEAD_BYTES;

/// Strict create request accepted by the Batch profile.
#[derive(Debug)]
pub struct BatchCreateBody<'a> {
    /// Tenant-scoped input file alias.
    pub input_file_id: &'a str,
    /// Relative endpoint targeted by every JSONL line.
    pub endpoint: &'a str,
    /// Completion window, currently only `24h`.
    pub completion_window: &'a str,
}

impl<'de> Deserialize<'de> for BatchCreateBody<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(BatchCreateVisitor)
    }
}

struct BatchCreateVisitor;

impl<'de> Visitor<'de> for BatchCreateVisitor {
    type Value = BatchCreateBody<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenAI Batch create request object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BatchCreateValues::default();
        while let Some(field) = map.next_key::<&str>()? {
            read_create_field(field, &mut values, &mut map)?;
        }
        Ok(BatchCreateBody {
            input_file_id: values
                .input_file_id
                .ok_or_else(|| A::Error::missing_field("input_file_id"))?,
            endpoint: values
                .endpoint
                .ok_or_else(|| A::Error::missing_field("endpoint"))?,
            completion_window: values
                .completion_window
                .ok_or_else(|| A::Error::missing_field("completion_window"))?,
        })
    }
}

fn read_create_field<'de, A>(
    field: &str,
    values: &mut BatchCreateValues<'de>,
    map: &mut A,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    match field {
        "input_file_id" => read_once(&mut values.input_file_id, "input_file_id", map),
        "endpoint" => read_once(&mut values.endpoint, "endpoint", map),
        "completion_window" => read_once(&mut values.completion_window, "completion_window", map),
        _ => Err(A::Error::unknown_field(
            field,
            &["input_file_id", "endpoint", "completion_window"],
        )),
    }
}

#[derive(Default)]
struct BatchCreateValues<'a> {
    input_file_id: Option<&'a str>,
    endpoint: Option<&'a str>,
    completion_window: Option<&'a str>,
}

/// One strict JSONL line shape used before body-specific live-route decoding.
#[derive(Debug)]
struct RawLine<'a> {
    custom_id: &'a str,
    method: &'a str,
    url: &'a str,
    body: &'a RawValue,
}

impl<'de> Deserialize<'de> for RawLine<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawLineVisitor)
    }
}

struct RawLineVisitor;

impl<'de> Visitor<'de> for RawLineVisitor {
    type Value = RawLine<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenAI Batch JSONL request line")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = RawLineValues::default();
        while let Some(field) = map.next_key::<&str>()? {
            read_line_field(field, &mut values, &mut map)?;
        }
        Ok(RawLine {
            custom_id: values
                .custom_id
                .ok_or_else(|| A::Error::missing_field("custom_id"))?,
            method: values
                .method
                .ok_or_else(|| A::Error::missing_field("method"))?,
            url: values.url.ok_or_else(|| A::Error::missing_field("url"))?,
            body: values.body.ok_or_else(|| A::Error::missing_field("body"))?,
        })
    }
}

fn read_line_field<'de, A>(
    field: &str,
    values: &mut RawLineValues<'de>,
    map: &mut A,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    match field {
        "custom_id" => read_once(&mut values.custom_id, "custom_id", map),
        "method" => read_once(&mut values.method, "method", map),
        "url" => read_once(&mut values.url, "url", map),
        "body" => read_once(&mut values.body, "body", map),
        _ => Err(A::Error::unknown_field(
            field,
            &["custom_id", "method", "url", "body"],
        )),
    }
}

#[derive(Default)]
struct RawLineValues<'a> {
    custom_id: Option<&'a str>,
    method: Option<&'a str>,
    url: Option<&'a str>,
    body: Option<&'a RawValue>,
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

/// Validates a Batch JSONL payload and returns the bounded domain summary.
///
/// The caller supplies an already-resolved internal file reference. This function
/// never retains request bodies and deliberately does not execute them.
pub fn validate_jsonl(
    bytes: &[u8],
    reference: FileReference,
    endpoint: BatchEndpoint,
) -> Result<BatchInputFile, ApiBatchError> {
    validate_jsonl_with(bytes, reference, endpoint, |_endpoint, body| {
        let value: serde_json::Value = serde_json::from_str(body).map_err(|_| invalid())?;
        if value.is_object() {
            Ok(())
        } else {
            Err(invalid())
        }
    })
}

/// Validates a Batch JSONL payload and each line body through the owning route
/// decoder. The callback is invoked only after the line envelope has passed
/// duplicate, method, URL, and bounded identifier checks.
pub(crate) fn validate_jsonl_with<F>(
    bytes: &[u8],
    reference: FileReference,
    endpoint: BatchEndpoint,
    mut validate_body: F,
) -> Result<BatchInputFile, ApiBatchError>
where
    F: FnMut(BatchEndpoint, &str) -> Result<(), ApiBatchError>,
{
    validate_input_size(bytes)?;
    let length = FileByteLength::new(bytes.len()).map_err(ApiBatchError::from)?;
    let mut lines = Vec::new();
    let mut segments = bytes.split(|byte| *byte == b'\n').peekable();
    while let Some(raw) = segments.next() {
        let has_newline = segments.peek().is_some();
        if is_terminal_empty(raw, has_newline) {
            break;
        }
        lines.push(parse_bounded_line(
            raw,
            has_newline,
            endpoint,
            &mut validate_body,
            lines.len(),
        )?);
    }
    BatchInputFile::from_lines(reference, length, lines)
}

fn validate_input_size(bytes: &[u8]) -> Result<(), ApiBatchError> {
    if bytes.is_empty() {
        return Err(ApiBatchError::new(
            ariadnion_api_domain::ApiBatchErrorCode::InvalidArgument,
        ));
    }
    if bytes.len() > MAX_BATCH_INPUT_BYTES {
        return Err(ApiBatchError::new(
            ariadnion_api_domain::ApiBatchErrorCode::LimitExceeded,
        ));
    }
    Ok(())
}

fn parse_bounded_line<F>(
    raw: &[u8],
    has_newline: bool,
    endpoint: BatchEndpoint,
    validate_body: &mut F,
    line_count: usize,
) -> Result<BatchRequestLine, ApiBatchError>
where
    F: FnMut(BatchEndpoint, &str) -> Result<(), ApiBatchError>,
{
    if line_count >= MAX_BATCH_REQUESTS {
        return Err(ApiBatchError::new(
            ariadnion_api_domain::ApiBatchErrorCode::LimitExceeded,
        ));
    }
    parse_line(raw, has_newline, endpoint, validate_body)
}

fn parse_line<F>(
    raw: &[u8],
    has_newline: bool,
    endpoint: BatchEndpoint,
    validate_body: &mut F,
) -> Result<BatchRequestLine, ApiBatchError>
where
    F: FnMut(BatchEndpoint, &str) -> Result<(), ApiBatchError>,
{
    let raw = normalize_line(raw, has_newline)?;
    let line = decode_line(raw)?;
    validate_line_bounds(raw, &line)?;
    if line.method != "POST" || line.url != endpoint.as_str() {
        return Err(invalid());
    }
    validate_body(endpoint, line.body.get())?;
    BatchRequestLine::new(line.custom_id, endpoint)
}

fn decode_line(raw: &[u8]) -> Result<RawLine<'_>, ApiBatchError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let line = RawLine::deserialize(&mut deserializer).map_err(|_| invalid())?;
    deserializer.end().map_err(|_| invalid())?;
    Ok(line)
}

const fn is_terminal_empty(raw: &[u8], has_newline: bool) -> bool {
    raw.is_empty() && !has_newline
}

fn normalize_line(raw: &[u8], has_newline: bool) -> Result<&[u8], ApiBatchError> {
    if !has_newline && raw.ends_with(b"\r") {
        return Err(invalid());
    }
    let normalized = raw.strip_suffix(b"\r").unwrap_or(raw);
    if !normalized.ends_with(b"}") {
        return Err(invalid());
    }
    if normalized.is_empty() {
        return Err(invalid());
    }
    Ok(normalized)
}

fn validate_line_bounds(raw: &[u8], line: &RawLine<'_>) -> Result<(), ApiBatchError> {
    if raw.len() > MAX_BATCH_ENVELOPE_BYTES {
        return Err(ApiBatchError::new(
            ariadnion_api_domain::ApiBatchErrorCode::LimitExceeded,
        ));
    }
    validate_custom_id(line.custom_id)?;
    validate_body_size(line.body.get())?;
    Ok(())
}

fn validate_custom_id(value: &str) -> Result<(), ApiBatchError> {
    if value.len() > MAX_BATCH_CUSTOM_ID_BYTES {
        return Err(ApiBatchError::new(
            ariadnion_api_domain::ApiBatchErrorCode::LimitExceeded,
        ));
    }
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}

fn validate_body_size(body: &str) -> Result<(), ApiBatchError> {
    if body.len() > MAX_BATCH_BODY_BYTES {
        return Err(ApiBatchError::new(
            ariadnion_api_domain::ApiBatchErrorCode::LimitExceeded,
        ));
    }
    Ok(())
}

/// Parses a 64-character lowercase hexadecimal file alias into an internal reference.
pub fn parse_file_reference(value: &str) -> Result<FileReference, ApiBatchError> {
    if value.len() != 64 {
        return Err(invalid());
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(FileReference::new(bytes))
}

fn hex(value: u8) -> Result<u8, ApiBatchError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid()),
    }
}

fn invalid() -> ApiBatchError {
    ApiBatchError::new(ariadnion_api_domain::ApiBatchErrorCode::InvalidArgument)
}

/// Parses the three required create members into domain enums.
pub fn parse_create_members(
    endpoint: &str,
    completion_window: &str,
) -> Result<(BatchEndpoint, BatchCompletionWindow), ApiBatchError> {
    Ok((
        BatchEndpoint::parse(endpoint)?,
        BatchCompletionWindow::parse(completion_window)?,
    ))
}

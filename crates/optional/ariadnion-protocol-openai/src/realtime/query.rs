// crates/optional/ariadnion-protocol-openai/src/realtime/query.rs - Exact OpenAI Realtime upgrade query decoding.
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
//! Exact one-member query decoding without a framework-specific extractor.

use ariadnion_api_domain::{MAX_MODEL_SELECTOR_BYTES, ModelSelector};

use super::{OpenAiRealtimeError, model_from_wire};

pub(super) fn decode_model(query: Option<&str>) -> Result<ModelSelector, OpenAiRealtimeError> {
    let member = single_query_member(query)?;
    let (name, value) = split_model_member(member)?;
    validate_model_value(name, value)?;
    let decoded = percent_decode(value)?;
    model_from_wire(&decoded)
}

fn single_query_member(query: Option<&str>) -> Result<&str, OpenAiRealtimeError> {
    let query = query.ok_or_else(OpenAiRealtimeError::invalid_request)?;
    if query.is_empty() {
        return Err(OpenAiRealtimeError::invalid_request());
    }
    let mut members = query.split('&');
    let member = members
        .next()
        .ok_or_else(OpenAiRealtimeError::invalid_request)?;
    if members.next().is_some() {
        return Err(OpenAiRealtimeError::invalid_request());
    }
    Ok(member)
}

fn split_model_member(member: &str) -> Result<(&str, &str), OpenAiRealtimeError> {
    member
        .split_once('=')
        .ok_or_else(OpenAiRealtimeError::invalid_request)
}

fn validate_model_value(name: &str, value: &str) -> Result<(), OpenAiRealtimeError> {
    if name != "model" || value.is_empty() {
        return Err(OpenAiRealtimeError::invalid_request());
    }
    if value.len() > MAX_MODEL_SELECTOR_BYTES.saturating_mul(3) {
        return Err(OpenAiRealtimeError::invalid_request());
    }
    Ok(())
}

fn percent_decode(value: &str) -> Result<String, OpenAiRealtimeError> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = bytes
                .get(index.saturating_add(1))
                .copied()
                .ok_or_else(OpenAiRealtimeError::invalid_request)?;
            let low = bytes
                .get(index.saturating_add(2))
                .copied()
                .ok_or_else(OpenAiRealtimeError::invalid_request)?;
            decoded.push((hex(high)? << 4) | hex(low)?);
            index = index.saturating_add(3);
        } else {
            // URI query percent-decoding preserves a literal plus sign; form
            // encoding's plus-to-space rule does not apply to this upgrade URI.
            decoded.push(byte);
            index = index.saturating_add(1);
        }
    }
    String::from_utf8(decoded).map_err(|_| OpenAiRealtimeError::invalid_request())
}

fn hex(value: u8) -> Result<u8, OpenAiRealtimeError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(OpenAiRealtimeError::invalid_request()),
    }
}

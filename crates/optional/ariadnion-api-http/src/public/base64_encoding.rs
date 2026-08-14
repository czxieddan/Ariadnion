// crates/optional/ariadnion-api-http/src/public/base64_encoding.rs - Bounded Base64 encoding for Ariadnion public HTTP responses.
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
//! Canonical bounded RFC 4648 Base64 encoding with optional cancellation.

use ariadnion_api_domain::ApiDomainError;
use ariadnion_core::RequestContext;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::protocol::ProtocolFailure;
use super::{ApiHttpError, ApiHttpErrorCode, MAX_PUBLIC_BODY_BYTES};

const BASE64_INPUT_CHUNK_BYTES: usize = 12 * 1024;

pub(super) fn encoded_length(input_length: usize) -> Result<usize, ProtocolFailure> {
    base64::encoded_len(input_length, true).ok_or_else(internal_failure)
}

pub(super) fn encode_bounded(input: &[u8]) -> Result<String, ProtocolFailure> {
    encode_bounded_with_context(input, None)
}

pub(super) fn encode_bounded_cancellable(
    input: &[u8],
    context: &RequestContext,
) -> Result<String, ProtocolFailure> {
    encode_bounded_with_context(input, Some(context))
}

fn encode_bounded_with_context(
    input: &[u8],
    context: Option<&RequestContext>,
) -> Result<String, ProtocolFailure> {
    check_context(context)?;
    let output_length = encoded_length(input.len())?;
    if output_length > MAX_PUBLIC_BODY_BYTES {
        return Err(internal_failure());
    }
    let mut output = allocate_encoding(output_length)?;
    encode_chunks(input, &mut output, context)?;
    check_context(context)?;
    String::from_utf8(output).map_err(|_| internal_failure())
}

fn allocate_encoding(length: usize) -> Result<Vec<u8>, ProtocolFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| internal_failure())?;
    output.resize(length, 0);
    Ok(output)
}

fn encode_chunks(
    input: &[u8],
    output: &mut [u8],
    context: Option<&RequestContext>,
) -> Result<(), ProtocolFailure> {
    let mut offset = 0_usize;
    for chunk in input.chunks(BASE64_INPUT_CHUNK_BYTES) {
        check_context(context)?;
        offset = encode_chunk(chunk, output, offset)?;
        check_context(context)?;
    }
    if offset != output.len() {
        return Err(internal_failure());
    }
    Ok(())
}

fn encode_chunk(input: &[u8], output: &mut [u8], offset: usize) -> Result<usize, ProtocolFailure> {
    let encoded_length = encoded_length(input.len())?;
    let end = offset
        .checked_add(encoded_length)
        .ok_or_else(internal_failure)?;
    let target = output.get_mut(offset..end).ok_or_else(internal_failure)?;
    let written = STANDARD
        .encode_slice(input, target)
        .map_err(|_| internal_failure())?;
    if written != encoded_length {
        return Err(internal_failure());
    }
    Ok(end)
}

fn check_context(context: Option<&RequestContext>) -> Result<(), ProtocolFailure> {
    context
        .map(RequestContext::check_active)
        .transpose()
        .map_err(ApiDomainError::from)?;
    Ok(())
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

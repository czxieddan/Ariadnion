// crates/optional/ariadnion-api-stream/src/encode.rs - SSE frame encoding for Ariadnion.
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

use ariadnion_api_domain::{
    ApiDomainError, ApiDomainErrorCode, FinishReason, ServiceContractVersion, TextDelta,
};
use bytes::Bytes;
use serde::Serialize;

use crate::error::{ApiStreamError, ApiStreamErrorCode};

const HEARTBEAT: &[u8] = b": keep-alive\n\n";

#[derive(Serialize)]
struct StartedBody {
    version: u16,
}

#[derive(Serialize)]
struct DeltaBody<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct CompletedBody {
    finish_reason: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    details: EmptyDetails,
    retryable: bool,
}

#[derive(Serialize)]
struct EmptyDetails {}

struct ErrorDescriptor {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

pub(crate) fn started(
    sequence: u64,
    version: ServiceContractVersion,
) -> Result<Bytes, ApiStreamError> {
    let Some(version) = contract_version(version) else {
        return Err(internal_failure());
    };
    json_frame("started", Some(sequence), &StartedBody { version })
}

pub(crate) fn delta(sequence: u64, value: &TextDelta) -> Result<Bytes, ApiStreamError> {
    json_frame(
        "delta",
        Some(sequence),
        &DeltaBody {
            text: value.as_str(),
        },
    )
}

pub(crate) fn completed(
    sequence: u64,
    finish_reason: FinishReason,
) -> Result<Bytes, ApiStreamError> {
    let Some(finish_reason) = finish_reason_name(finish_reason) else {
        return Err(internal_failure());
    };
    json_frame(
        "completed",
        Some(sequence),
        &CompletedBody { finish_reason },
    )
}

pub(crate) fn domain_error(sequence: u64, error: ApiDomainError) -> Bytes {
    let Some(descriptor) = domain_descriptor(error.code()) else {
        return stream_error(Some(sequence), ApiStreamErrorCode::Internal);
    };
    encoded_error(Some(sequence), descriptor)
}

pub(crate) fn stream_error(sequence: Option<u64>, code: ApiStreamErrorCode) -> Bytes {
    encoded_error(sequence, stream_descriptor(code))
}

pub(crate) fn heartbeat() -> Bytes {
    Bytes::from_static(HEARTBEAT)
}

fn json_frame<T: Serialize>(
    event: &'static str,
    sequence: Option<u64>,
    body: &T,
) -> Result<Bytes, ApiStreamError> {
    let json = serde_json::to_string(body).map_err(|_| internal_failure())?;
    Ok(assemble_frame(event, sequence, &json))
}

fn assemble_frame(event: &str, sequence: Option<u64>, json: &str) -> Bytes {
    let id = sequence.map_or_else(String::new, |value| format!("id: {value}\n"));
    Bytes::from(format!("event: {event}\n{id}data: {json}\n\n"))
}

fn encoded_error(sequence: Option<u64>, descriptor: ErrorDescriptor) -> Bytes {
    let body = ErrorBody {
        code: descriptor.code,
        message: descriptor.message,
        details: EmptyDetails {},
        retryable: descriptor.retryable,
    };
    match serde_json::to_string(&body) {
        Ok(json) => assemble_frame("error", sequence, &json),
        Err(_) => internal_error_fallback(sequence),
    }
}

fn internal_error_fallback(sequence: Option<u64>) -> Bytes {
    let json = "{\"code\":\"API_STREAM_INTERNAL\",\"message\":\"The response stream could not be completed.\",\"details\":{},\"retryable\":false}";
    assemble_frame("error", sequence, json)
}

const fn contract_version(version: ServiceContractVersion) -> Option<u16> {
    match version {
        ServiceContractVersion::V1 => Some(1),
        _ => None,
    }
}

const fn finish_reason_name(reason: FinishReason) -> Option<&'static str> {
    match reason {
        FinishReason::Completed => Some("completed"),
        FinishReason::OutputLimitReached => Some("output_limit_reached"),
        _ => None,
    }
}

fn domain_descriptor(code: ApiDomainErrorCode) -> Option<ErrorDescriptor> {
    let message = domain_message(code)?;
    Some(ErrorDescriptor {
        code: code.as_str(),
        message,
        retryable: domain_retryable(code),
    })
}

const fn domain_message(code: ApiDomainErrorCode) -> Option<&'static str> {
    match code {
        ApiDomainErrorCode::InvalidArgument
        | ApiDomainErrorCode::UnsupportedVersion
        | ApiDomainErrorCode::LimitExceeded
        | ApiDomainErrorCode::Conflict => request_domain_message(code),
        ApiDomainErrorCode::Cancelled => Some("The request was cancelled."),
        ApiDomainErrorCode::DeadlineExceeded => Some("The request deadline was exceeded."),
        ApiDomainErrorCode::Unavailable
        | ApiDomainErrorCode::ResourceExhausted
        | ApiDomainErrorCode::Internal => service_domain_message(code),
        _ => None,
    }
}

const fn request_domain_message(code: ApiDomainErrorCode) -> Option<&'static str> {
    match code {
        ApiDomainErrorCode::InvalidArgument => Some("A request value is invalid."),
        ApiDomainErrorCode::UnsupportedVersion => Some("The request version is not supported."),
        ApiDomainErrorCode::LimitExceeded => Some("A request limit was exceeded."),
        ApiDomainErrorCode::Conflict => Some("The request conflicts with current state."),
        _ => None,
    }
}

const fn service_domain_message(code: ApiDomainErrorCode) -> Option<&'static str> {
    match code {
        ApiDomainErrorCode::Unavailable => Some("A required service is unavailable."),
        ApiDomainErrorCode::ResourceExhausted => Some("A request resource was exhausted."),
        ApiDomainErrorCode::Internal => Some("The request could not be completed."),
        _ => None,
    }
}

const fn domain_retryable(code: ApiDomainErrorCode) -> bool {
    matches!(
        code,
        ApiDomainErrorCode::DeadlineExceeded
            | ApiDomainErrorCode::Unavailable
            | ApiDomainErrorCode::ResourceExhausted
    )
}

const fn stream_descriptor(code: ApiStreamErrorCode) -> ErrorDescriptor {
    ErrorDescriptor {
        code: code.as_str(),
        message: stream_message(code),
        retryable: matches!(code, ApiStreamErrorCode::ResourceExhausted),
    }
}

const fn stream_message(code: ApiStreamErrorCode) -> &'static str {
    match code {
        ApiStreamErrorCode::InvalidConfiguration => "The stream configuration is invalid.",
        ApiStreamErrorCode::ResourceExhausted => "Stream capacity is exhausted.",
        ApiStreamErrorCode::InvalidSequence => "The stream event sequence is invalid.",
        ApiStreamErrorCode::InvalidTransition => "The stream event order is invalid.",
        ApiStreamErrorCode::Incomplete => "The response stream ended before completion.",
        ApiStreamErrorCode::Internal => "The response stream could not be completed.",
    }
}

const fn internal_failure() -> ApiStreamError {
    ApiStreamError::new(ApiStreamErrorCode::Internal)
}

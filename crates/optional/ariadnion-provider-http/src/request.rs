// crates/optional/ariadnion-provider-http/src/request.rs - Provider request framing for Ariadnion.
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

//! Private Hyper conversion for one checked fixed-profile request.

use std::fmt::{self, Debug, Formatter};

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_LENGTH, HOST};
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::Full;

use crate::config::ProviderHttpProfile;
use crate::connector::RequestBody;
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};

/// One bounded provider request body for a fixed transport profile.
///
/// Construction validates the byte limit before copying caller data. Formatting
/// never exposes the retained body.
pub struct ProviderHttpRequest {
    body: Box<[u8]>,
    checked_max_body_bytes: usize,
}

impl ProviderHttpRequest {
    /// Copies a request body after validating the profile's hard byte limit.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted limit error before allocation when `body`
    /// exceeds the checked profile boundary.
    pub fn new(profile: &ProviderHttpProfile, body: &[u8]) -> Result<Self, ProviderHttpError> {
        let checked_max_body_bytes = profile.limits().max_request_body_bytes();
        if body.len() > checked_max_body_bytes {
            return Err(request_error(ProviderHttpErrorCode::LimitExceeded));
        }
        Ok(Self {
            body: body.into(),
            checked_max_body_bytes,
        })
    }

    /// Returns the retained request-body byte count without exposing its data.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl Debug for ProviderHttpRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpRequest { redacted }")
    }
}

pub(crate) fn build_request(
    profile: &ProviderHttpProfile,
    request: ProviderHttpRequest,
) -> Result<Request<RequestBody>, ProviderHttpError> {
    validate_request_body(&request, profile)?;
    let host = host_authority(profile);
    let content_length = request.body.len().to_string();
    validate_derived_headers(profile, &host, &content_length)?;
    let method = Method::from_bytes(profile.method().as_str().as_bytes())
        .map_err(|_| request_error(ProviderHttpErrorCode::InvalidHeader))?;
    let uri = profile
        .endpoint()
        .path_and_query()
        .parse::<Uri>()
        .map_err(|_| request_error(ProviderHttpErrorCode::InvalidPathAndQuery))?;
    let mut hyper_request = Request::new(Full::new(Bytes::from(request.body)));
    *hyper_request.method_mut() = method;
    *hyper_request.uri_mut() = uri;
    insert_derived_headers(&mut hyper_request, &host, &content_length)?;
    insert_static_headers(&mut hyper_request, profile)?;
    Ok(hyper_request)
}

fn validate_request_body(
    request: &ProviderHttpRequest,
    profile: &ProviderHttpProfile,
) -> Result<(), ProviderHttpError> {
    let execution_limit = profile.limits().max_request_body_bytes();
    if request.body.len() > request.checked_max_body_bytes || request.body.len() > execution_limit {
        return Err(request_error(ProviderHttpErrorCode::LimitExceeded));
    }
    Ok(())
}

fn validate_derived_headers(
    profile: &ProviderHttpProfile,
    host: &str,
    content_length: &str,
) -> Result<(), ProviderHttpError> {
    let limits = profile.limits();
    let count = profile.headers().len().saturating_add(3);
    let derived_bytes = header_wire_len("host", host)
        .saturating_add(header_wire_len("content-length", content_length))
        .saturating_add(header_wire_len("accept-encoding", "identity"));
    let static_bytes = profile.headers().iter().fold(0_usize, |total, header| {
        total.saturating_add(header.name().len() + header.value().len() + 4)
    });
    if count > limits.max_headers()
        || derived_bytes.saturating_add(static_bytes) > limits.max_header_bytes()
    {
        return Err(request_error(ProviderHttpErrorCode::LimitExceeded));
    }
    Ok(())
}

fn insert_derived_headers(
    request: &mut Request<RequestBody>,
    host: &str,
    content_length: &str,
) -> Result<(), ProviderHttpError> {
    let host = HeaderValue::from_str(host)
        .map_err(|_| request_error(ProviderHttpErrorCode::InvalidHeader))?;
    let content_length = HeaderValue::from_str(content_length)
        .map_err(|_| request_error(ProviderHttpErrorCode::InvalidHeader))?;
    request.headers_mut().insert(HOST, host);
    request.headers_mut().insert(CONTENT_LENGTH, content_length);
    request
        .headers_mut()
        .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    Ok(())
}

fn host_authority(profile: &ProviderHttpProfile) -> String {
    let endpoint = profile.endpoint();
    if endpoint.port() == 443 {
        endpoint.host().as_str().to_owned()
    } else {
        format!("{}:{}", endpoint.host().as_str(), endpoint.port())
    }
}

fn header_wire_len(name: &str, value: &str) -> usize {
    name.len().saturating_add(value.len()).saturating_add(4)
}

fn insert_static_headers(
    request: &mut Request<RequestBody>,
    profile: &ProviderHttpProfile,
) -> Result<(), ProviderHttpError> {
    for header in profile.headers() {
        let name = HeaderName::from_bytes(header.name().as_bytes())
            .map_err(|_| request_error(ProviderHttpErrorCode::InvalidHeader))?;
        let value = HeaderValue::from_str(header.value())
            .map_err(|_| request_error(ProviderHttpErrorCode::InvalidHeader))?;
        request.headers_mut().insert(name, value);
    }
    Ok(())
}

const fn request_error(code: ProviderHttpErrorCode) -> ProviderHttpError {
    ProviderHttpError::with_phase(code, ProviderHttpPhase::RequestHeaders)
}

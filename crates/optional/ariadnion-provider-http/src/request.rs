// crates/optional/ariadnion-provider-http/src/request.rs - Provider request framing for Ariadnion.
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

//! Private Hyper conversion for one checked fixed-profile request.

use std::fmt::{self, Debug, Formatter};
use std::time::SystemTime;

use ariadnion_account_vault::SecretLease;
use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, HOST};
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::Full;
use zeroize::Zeroizing;

use crate::config::{
    MAX_PROVIDER_HTTP_HEADER_NAME_BYTES, MAX_PROVIDER_HTTP_HEADER_VALUE_BYTES, ProviderHttpProfile,
};
use crate::connector::RequestBody;
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};

/// Module identity authorized to consume final provider HTTP credentials.
pub const PROVIDER_HTTP_CREDENTIAL_MODULE: &str = "org.ariadnion.provider.http";

/// Secret purpose accepted by the final provider HTTP credential boundary.
pub const PROVIDER_HTTP_CREDENTIAL_PURPOSE: &str = "provider-request-authentication";

const BEARER_PREFIX: &[u8] = b"Bearer ";

#[derive(Clone, Copy)]
enum CredentialFraming {
    Bearer,
    Raw,
}

impl CredentialFraming {
    const fn prefix(self) -> &'static [u8] {
        match self {
            Self::Bearer => BEARER_PREFIX,
            Self::Raw => b"",
        }
    }

    fn material_is_valid(self, material: &[u8]) -> bool {
        match self {
            Self::Bearer => bearer_material_is_valid(material),
            Self::Raw => credential_material_is_header_safe(material),
        }
    }
}

/// A short-lived vault lease bound to one request-scoped provider header.
///
/// Construction validates the consuming module, secret purpose, current lease
/// interval, header framing, and bounded value length. Plaintext remains owned
/// by the zeroizing vault lease until request framing reaches the final trusted
/// HTTP adapter boundary.
pub struct ProviderHttpCredential {
    header_name: HeaderName,
    framing: CredentialFraming,
    lease: SecretLease,
    value_len: usize,
}

impl ProviderHttpCredential {
    /// Creates an `Authorization: Bearer` credential from an authorized lease.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderHttpErrorCode::CredentialRejected`] when the lease is
    /// expired, bound to another module or purpose, or cannot form one bounded
    /// HTTP header value.
    pub fn bearer(lease: SecretLease) -> Result<Self, ProviderHttpError> {
        Self::new(AUTHORIZATION, CredentialFraming::Bearer, lease)
    }

    /// Creates a request-scoped custom credential header.
    ///
    /// Protocol-owned, connection-specific, proxy, cookie, and authorization
    /// header names are rejected. Use [`Self::bearer`] for bearer authorization.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderHttpErrorCode::CredentialRejected`] when the name is
    /// invalid or reserved, or when the lease fails the final-provider checks.
    pub fn custom_header(name: &str, lease: SecretLease) -> Result<Self, ProviderHttpError> {
        if name.len() > MAX_PROVIDER_HTTP_HEADER_NAME_BYTES {
            return Err(credential_error());
        }
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| credential_error())?;
        if credential_header_is_forbidden(&name) {
            return Err(credential_error());
        }
        Self::new(name, CredentialFraming::Raw, lease)
    }

    /// Returns the normalized header name without exposing credential material.
    #[must_use]
    pub fn header_name(&self) -> &str {
        self.header_name.as_str()
    }

    fn new(
        header_name: HeaderName,
        framing: CredentialFraming,
        lease: SecretLease,
    ) -> Result<Self, ProviderHttpError> {
        validate_credential_scope(&lease)?;
        let material = lease
            .material_at(SystemTime::now())
            .map_err(|_| credential_error())?;
        let value_len = framing
            .prefix()
            .len()
            .checked_add(material.len())
            .ok_or_else(credential_error)?;
        if value_len > MAX_PROVIDER_HTTP_HEADER_VALUE_BYTES
            || !framing.material_is_valid(material.as_bytes())
        {
            return Err(credential_error());
        }
        Ok(Self {
            header_name,
            framing,
            lease,
            value_len,
        })
    }

    fn wire_len(&self) -> usize {
        header_wire_len(self.header_name.as_str(), self.value_len)
    }

    fn into_header(self) -> Result<(HeaderName, HeaderValue), ProviderHttpError> {
        let material = self
            .lease
            .material_at(SystemTime::now())
            .map_err(|_| credential_error())?;
        let mut framed = Zeroizing::new(Vec::with_capacity(self.value_len));
        framed.extend_from_slice(self.framing.prefix());
        framed.extend_from_slice(material.as_bytes());
        let mut value =
            HeaderValue::from_bytes(framed.as_slice()).map_err(|_| credential_error())?;
        value.set_sensitive(true);
        Ok((self.header_name, value))
    }
}

impl Debug for ProviderHttpCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpCredential")
            .field("header_name", &self.header_name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// One bounded provider request body for a fixed transport profile.
///
/// Construction validates the byte limit before copying caller data. Formatting
/// never exposes the retained body.
pub struct ProviderHttpRequest {
    body: Box<[u8]>,
    checked_max_body_bytes: usize,
    credential: Option<ProviderHttpCredential>,
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
            credential: None,
        })
    }

    /// Copies a bounded request body and retains one short-lived credential.
    ///
    /// The credential remains inside its zeroizing lease until the exchange
    /// performs final HTTP request framing. Its scope and validity are checked
    /// again at that boundary.
    ///
    /// # Errors
    ///
    /// Returns the same bounded body error as [`Self::new`]. Credential expiry
    /// during queuing is reported when the exchange frames the request.
    pub fn with_credential(
        profile: &ProviderHttpProfile,
        body: &[u8],
        credential: ProviderHttpCredential,
    ) -> Result<Self, ProviderHttpError> {
        validate_credential_header(profile, &credential)?;
        let mut request = Self::new(profile, body)?;
        request.credential = Some(credential);
        Ok(request)
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
    validate_derived_headers(profile, &request, &host, &content_length)?;
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
    insert_credential_header(&mut hyper_request, request.credential)?;
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
    request: &ProviderHttpRequest,
    host: &str,
    content_length: &str,
) -> Result<(), ProviderHttpError> {
    let limits = profile.limits();
    let credential_count = usize::from(request.credential.is_some());
    let count = profile
        .headers()
        .len()
        .saturating_add(3)
        .saturating_add(credential_count);
    let derived_bytes = header_wire_len("host", host.len())
        .saturating_add(header_wire_len("content-length", content_length.len()))
        .saturating_add(header_wire_len("accept-encoding", "identity".len()));
    let static_bytes = profile.headers().iter().fold(0_usize, |total, header| {
        total.saturating_add(header.name().len() + header.value().len() + 4)
    });
    let credential_bytes = request
        .credential
        .as_ref()
        .map_or(0, ProviderHttpCredential::wire_len);
    if count > limits.max_headers()
        || derived_bytes
            .saturating_add(static_bytes)
            .saturating_add(credential_bytes)
            > limits.max_header_bytes()
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

fn header_wire_len(name: &str, value_len: usize) -> usize {
    name.len().saturating_add(value_len).saturating_add(4)
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

fn insert_credential_header(
    request: &mut Request<RequestBody>,
    credential: Option<ProviderHttpCredential>,
) -> Result<(), ProviderHttpError> {
    if let Some(credential) = credential {
        if request.headers().contains_key(&credential.header_name) {
            return Err(credential_error());
        }
        let (name, value) = credential.into_header()?;
        request.headers_mut().insert(name, value);
    }
    Ok(())
}

fn validate_credential_header(
    profile: &ProviderHttpProfile,
    credential: &ProviderHttpCredential,
) -> Result<(), ProviderHttpError> {
    if profile
        .headers()
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case(credential.header_name()))
    {
        return Err(credential_error());
    }
    Ok(())
}

fn validate_credential_scope(lease: &SecretLease) -> Result<(), ProviderHttpError> {
    if lease.module().as_str() != PROVIDER_HTTP_CREDENTIAL_MODULE
        || lease.reference().purpose().as_str() != PROVIDER_HTTP_CREDENTIAL_PURPOSE
    {
        return Err(credential_error());
    }
    Ok(())
}

fn credential_material_is_header_safe(material: &[u8]) -> bool {
    !material.is_empty()
        && material
            .iter()
            .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte) || *byte >= 0x80)
}

fn bearer_material_is_valid(material: &[u8]) -> bool {
    // RFC 6750 permits padding only after at least one bearer-alphabet byte.
    let content_len = material
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(material.len());
    content_len > 0
        && material[..content_len].iter().all(bearer_alphabet_byte)
        && material[content_len..].iter().all(|byte| *byte == b'=')
}

fn bearer_alphabet_byte(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~+/".contains(byte)
}

fn credential_header_is_forbidden(name: &HeaderName) -> bool {
    const FORBIDDEN: [&str; 13] = [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "host",
        "content-length",
        "accept-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
    ];
    name.as_str().starts_with("proxy-") || FORBIDDEN.contains(&name.as_str())
}

const fn request_error(code: ProviderHttpErrorCode) -> ProviderHttpError {
    ProviderHttpError::with_phase(code, ProviderHttpPhase::RequestHeaders)
}

const fn credential_error() -> ProviderHttpError {
    request_error(ProviderHttpErrorCode::CredentialRejected)
}

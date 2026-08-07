// crates/optional/ariadnion-provider-http/src/response.rs - Pull-driven provider responses for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0

//! Ariadnion-owned response head and single-consumer body access.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use ariadnion_core::RequestContext;
use http::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING};
use http_body_util::BodyExt;
use hyper::body::Incoming;

use crate::config::{ProviderHttpLimits, ProviderHttpMethod, ProviderHttpTimeouts};
use crate::connector::ProviderHttpDirectConnection;
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};
use crate::exchange::ProviderHttpAttemptOwner;
use crate::timeout::run_exchange_phase;

struct ResponseHeader {
    name: Box<str>,
    value: Box<str>,
}

/// An opaque completed clean lease that retains one physical connection.
///
/// This token is not a public send handle. It deliberately exposes no way to
/// redispatch with the completed attempt's evidence. A future crate-internal
/// pool may consume it only while rebinding fresh attempt evidence first.
pub struct ProviderHttpReusableConnection {
    _connection: ProviderHttpDirectConnection,
}

impl ProviderHttpReusableConnection {
    fn new(connection: ProviderHttpDirectConnection) -> Self {
        Self {
            _connection: connection,
        }
    }
}

impl Debug for ProviderHttpReusableConnection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpReusableConnection { redacted }")
    }
}

/// One validated provider response with pull-driven body consumption.
///
/// This value owns the attempt-local cancellation context and physical
/// connection. Dropping it before clean end-of-stream cancels only that child
/// context and immediately discards the connection.
pub struct ProviderHttpResponse {
    status: u16,
    headers: Box<[ResponseHeader]>,
    body: Incoming,
    connection: Option<ProviderHttpDirectConnection>,
    context: RequestContext,
    body_idle: Duration,
    cancellation_poll: Duration,
    complete: bool,
    reusable: bool,
    reuse_allowed: bool,
    declared_length: Option<usize>,
    received_bytes: usize,
    limits: ProviderHttpLimits,
}

impl ProviderHttpResponse {
    pub(crate) fn from_hyper(
        response: http::Response<Incoming>,
        owner: ProviderHttpAttemptOwner,
        timeouts: ProviderHttpTimeouts,
        limits: ProviderHttpLimits,
        method: ProviderHttpMethod,
    ) -> Result<Self, ProviderHttpError> {
        let (parts, body) = response.into_parts();
        validate_status(parts.status.as_u16())?;
        validate_content_encoding(&parts.headers)?;
        validate_transfer_encoding(&parts.headers)?;
        let declared_length =
            expected_body_length(method, declared_content_length(&parts.headers)?);
        validate_declared_length(declared_length, limits)?;
        let headers = copy_headers(&parts.headers, limits)?;
        let reuse_allowed = response_allows_reuse(parts.version, &parts.headers);
        let (connection, context) = owner.into_parts()?;
        Ok(Self {
            status: parts.status.as_u16(),
            headers: headers.into_boxed_slice(),
            body,
            connection: Some(connection),
            context,
            body_idle: timeouts.body_idle(),
            cancellation_poll: timeouts.cancellation_poll(),
            complete: false,
            reusable: false,
            reuse_allowed,
            declared_length,
            received_bytes: 0,
            limits,
        })
    }

    /// Returns the numeric HTTP response status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the first matching response header as checked ASCII text.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_ref())
    }

    /// Consumes a completed response and returns its reusable connection.
    ///
    /// The connection is available only after [`Self::next_chunk`] returned
    /// `None` for a response whose declared and received lengths matched.
    /// Calling this method earlier returns `None`; consuming the incomplete
    /// response then cancels its child context and discards the connection.
    /// Clean extraction does not cancel the child request context.
    #[must_use]
    pub fn into_reusable_connection(mut self) -> Option<ProviderHttpReusableConnection> {
        if !self.reusable {
            return None;
        }
        self.connection
            .take()
            .map(ProviderHttpReusableConnection::new)
    }

    /// Pulls at most one provider body chunk.
    ///
    /// The body is single-consumer because polling requires exclusive access.
    /// Clean end-of-stream returns `None`; transport failures are redacted. Each
    /// pull independently observes parent cancellation, the request deadline,
    /// and the checked body-idle budget.
    ///
    /// # Errors
    ///
    /// Returns a stable response-phase failure for cancellation, deadline or
    /// idle-budget expiry, protocol violations, response limits, or a rejected
    /// Hyper body frame.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProviderHttpError> {
        if self.complete {
            return Ok(None);
        }
        let context = self.context.clone();
        let frame = run_exchange_phase(
            &context,
            self.body_idle,
            self.cancellation_poll,
            self.body.frame(),
        )
        .await;
        match frame {
            Err(code) => Err(self.fail(code)),
            Ok(None) => self.finish_eof(),
            Ok(Some(frame)) => self.accept_frame(frame),
        }
    }

    fn accept_frame(
        &mut self,
        frame: Result<hyper::body::Frame<bytes::Bytes>, hyper::Error>,
    ) -> Result<Option<Vec<u8>>, ProviderHttpError> {
        let data = match frame_data(frame) {
            Ok(data) => data,
            Err(error) => {
                self.abort_attempt();
                return Err(error);
            }
        };
        if let Err(error) = self.retain_chunk(data.len()) {
            self.abort_attempt();
            return Err(error);
        }
        Ok(Some(data.to_vec()))
    }

    fn finish_eof(&mut self) -> Result<Option<Vec<u8>>, ProviderHttpError> {
        self.complete = true;
        match self.validate_eof() {
            Ok(value) => {
                self.reusable = self.reuse_allowed
                    && self
                        .connection
                        .as_ref()
                        .is_some_and(ProviderHttpDirectConnection::is_reusable);
                Ok(value)
            }
            Err(error) => {
                self.abort_attempt();
                Err(error)
            }
        }
    }

    fn fail(&mut self, code: ProviderHttpErrorCode) -> ProviderHttpError {
        self.abort_attempt();
        body_error(code)
    }

    fn abort_attempt(&mut self) {
        self.complete = true;
        self.context.cancellation().cancel();
        let _connection = self.connection.take();
    }

    fn retain_chunk(&mut self, length: usize) -> Result<(), ProviderHttpError> {
        if length > self.limits.max_frame_bytes() {
            self.complete = true;
            return Err(body_error(ProviderHttpErrorCode::ResponseLimit));
        }
        let total = self
            .received_bytes
            .checked_add(length)
            .filter(|total| *total <= self.limits.max_response_body_bytes())
            .ok_or_else(|| body_error(ProviderHttpErrorCode::ResponseLimit))?;
        if self
            .declared_length
            .is_some_and(|declared| total > declared)
        {
            self.complete = true;
            return Err(body_error(ProviderHttpErrorCode::ProtocolViolation));
        }
        self.received_bytes = total;
        Ok(())
    }

    fn validate_eof(&self) -> Result<Option<Vec<u8>>, ProviderHttpError> {
        if self
            .declared_length
            .is_some_and(|declared| declared != self.received_bytes)
        {
            return Err(body_error(ProviderHttpErrorCode::ProtocolViolation));
        }
        Ok(None)
    }
}

fn expected_body_length(method: ProviderHttpMethod, declared: Option<usize>) -> Option<usize> {
    if method == ProviderHttpMethod::Head {
        return None;
    }
    declared
}

fn response_allows_reuse(version: http::Version, headers: &http::HeaderMap) -> bool {
    if has_connection_token(headers, "close") {
        return false;
    }
    match version {
        http::Version::HTTP_11 => true,
        http::Version::HTTP_10 => has_connection_token(headers, "keep-alive"),
        _ => false,
    }
}

fn has_connection_token(headers: &http::HeaderMap, expected: &str) -> bool {
    headers.get_all(CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn frame_data(
    frame: Result<hyper::body::Frame<bytes::Bytes>, hyper::Error>,
) -> Result<bytes::Bytes, ProviderHttpError> {
    let frame = frame.map_err(|_error| body_error(ProviderHttpErrorCode::ResponseBodyFailed))?;
    frame
        .into_data()
        .map_err(|_frame| body_error(ProviderHttpErrorCode::ProtocolViolation))
}

impl Drop for ProviderHttpResponse {
    fn drop(&mut self) {
        if !self.reusable {
            self.abort_attempt();
        }
    }
}

fn copy_headers(
    source: &http::HeaderMap,
    limits: ProviderHttpLimits,
) -> Result<Vec<ResponseHeader>, ProviderHttpError> {
    let mut headers = Vec::with_capacity(source.len().min(limits.max_headers()));
    let mut bytes = 0_usize;
    for (name, value) in source {
        let value = value
            .to_str()
            .map_err(|_| head_error(ProviderHttpErrorCode::ProtocolViolation))?;
        bytes = bytes
            .checked_add(name.as_str().len() + value.len() + 4)
            .filter(|total| *total <= limits.max_header_bytes())
            .ok_or_else(|| head_error(ProviderHttpErrorCode::ResponseLimit))?;
        if headers.len() >= limits.max_headers() {
            return Err(head_error(ProviderHttpErrorCode::ResponseLimit));
        }
        headers.push(ResponseHeader {
            name: name.as_str().into(),
            value: value.into(),
        });
    }
    Ok(headers)
}

fn validate_status(status: u16) -> Result<(), ProviderHttpError> {
    if (300..400).contains(&status) {
        return Err(head_error(ProviderHttpErrorCode::RedirectRejected));
    }
    Ok(())
}

fn validate_content_encoding(headers: &http::HeaderMap) -> Result<(), ProviderHttpError> {
    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    let identity = value
        .to_str()
        .is_ok_and(|value| value.eq_ignore_ascii_case("identity"));
    if !identity || values.next().is_some() {
        return Err(head_error(ProviderHttpErrorCode::ProtocolViolation));
    }
    Ok(())
}

fn validate_transfer_encoding(headers: &http::HeaderMap) -> Result<(), ProviderHttpError> {
    let mut values = headers.get_all(TRANSFER_ENCODING).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    let chunked = value
        .to_str()
        .is_ok_and(|value| value.trim().eq_ignore_ascii_case("chunked"));
    if !chunked || values.next().is_some() || headers.contains_key(CONTENT_LENGTH) {
        return Err(head_error(ProviderHttpErrorCode::ProtocolViolation));
    }
    Ok(())
}

fn declared_content_length(headers: &http::HeaderMap) -> Result<Option<usize>, ProviderHttpError> {
    let value = single_content_length(headers)?;
    value.map(parse_content_length).transpose()
}

fn single_content_length(
    headers: &http::HeaderMap,
) -> Result<Option<&http::HeaderValue>, ProviderHttpError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(head_error(ProviderHttpErrorCode::ProtocolViolation));
    }
    Ok(value)
}

fn parse_content_length(value: &http::HeaderValue) -> Result<usize, ProviderHttpError> {
    let value = value
        .to_str()
        .map_err(|_| head_error(ProviderHttpErrorCode::ProtocolViolation))?;
    validate_decimal_content_length(value)?;
    value
        .parse()
        .map_err(|_| head_error(ProviderHttpErrorCode::ProtocolViolation))
}

fn validate_decimal_content_length(value: &str) -> Result<(), ProviderHttpError> {
    if value.is_empty() {
        return Err(head_error(ProviderHttpErrorCode::ProtocolViolation));
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(head_error(ProviderHttpErrorCode::ProtocolViolation));
    }
    Ok(())
}

fn validate_declared_length(
    declared: Option<usize>,
    limits: ProviderHttpLimits,
) -> Result<(), ProviderHttpError> {
    if declared.is_some_and(|length| length > limits.max_response_body_bytes()) {
        return Err(head_error(ProviderHttpErrorCode::ResponseLimit));
    }
    Ok(())
}

const fn head_error(code: ProviderHttpErrorCode) -> ProviderHttpError {
    ProviderHttpError::with_phase(code, ProviderHttpPhase::ResponseHeaders)
}

const fn body_error(code: ProviderHttpErrorCode) -> ProviderHttpError {
    ProviderHttpError::with_phase(code, ProviderHttpPhase::ResponseBody)
}

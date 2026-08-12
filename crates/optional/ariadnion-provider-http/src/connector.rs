// crates/optional/ariadnion-provider-http/src/connector.rs - Direct provider connection orchestration for Ariadnion.
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

//! Direct numeric TCP, verified TLS, and low-level HTTP/1 connection setup.

use std::fmt::{self, Debug, Display, Formatter};
use std::future::Future;
use std::io;
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Instant;

use ariadnion_core::{OutboundHost, OutboundPolicyPort, OutboundTarget, RequestContext};
use ariadnion_provider_sdk::ProviderAttemptEvidence;
use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_rustls::client::TlsStream;

use crate::authorization::{
    ProviderHttpAuthorizationBoundary, ProviderHttpAuthorizationStamp, ProviderHttpAuthorizedIo,
    ProviderHttpAuthorizedTarget, ProviderHttpConnectionAuthorization,
    ProviderHttpWriteAuthorization, ProviderHttpWriteDenial,
};
use crate::config::{
    ProviderHttpLimits, ProviderHttpProfile, ProviderHttpProxy, ProviderHttpTrust,
};
use crate::dns::{BoundedResolver, ResolutionRecord};
use crate::egress::EgressError;
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};
use crate::proxy;
use crate::timeout::run_with_timeout;
use crate::tls;
use crate::transmission::ProviderTransmissionMarker;

pub(crate) type RequestBody = Full<Bytes>;
type ProviderTcpStream = ProviderHttpAuthorizedIo<TcpStream>;
type ProviderTlsStream = TlsStream<ProviderTcpStream>;

const HTTP1_MAX_BUFFER_BYTES: usize = 16 * 1024;
const GUARDED_READ_CHUNK_BYTES: usize = 1024;

/// An opaque connected numeric TCP socket supplied by a trusted dial adapter.
pub struct ProviderHttpConnectedSocket {
    stream: StdTcpStream,
}

impl ProviderHttpConnectedSocket {
    /// Validates and wraps one already-connected standard TCP stream.
    ///
    /// The stream is switched to nonblocking mode before ownership transfers to
    /// the connector. This API does not perform DNS or outbound authorization.
    ///
    /// # Errors
    ///
    /// Returns a redacted dial error when the stream is not connected or cannot
    /// enter nonblocking mode.
    pub fn from_std(stream: StdTcpStream) -> Result<Self, ProviderHttpDialError> {
        stream
            .peer_addr()
            .map_err(|_| ProviderHttpDialError::unavailable())?;
        stream
            .set_nonblocking(true)
            .map_err(|_| ProviderHttpDialError::unavailable())?;
        Ok(Self { stream })
    }

    fn into_tokio(self) -> Result<TcpStream, ProviderHttpDialError> {
        TcpStream::from_std(self.stream).map_err(|_| ProviderHttpDialError::unavailable())
    }
}

impl Debug for ProviderHttpConnectedSocket {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpConnectedSocket { redacted }")
    }
}

/// A stable redacted numeric TCP dial failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProviderHttpDialError;

impl ProviderHttpDialError {
    /// Creates an unavailable numeric dial result without retaining diagnostics.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self
    }
}

impl Display for ProviderHttpDialError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("provider_http_connect_failed")
    }
}

impl std::error::Error for ProviderHttpDialError {}

/// The owned future returned by a numeric TCP dial adapter.
pub type ProviderHttpDialFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ProviderHttpConnectedSocket, ProviderHttpDialError>> + Send + 'a,
    >,
>;

/// A trusted adapter that dials only the authorized numeric address supplied by the connector.
///
/// The connector authorizes this address before calling the adapter. Production
/// dialing uses that exact address; deterministic test adapters may map the
/// authorized address to local infrastructure without changing authorization.
pub trait ProviderHttpNumericDialer: Send + Sync {
    /// Opens one connection without performing hostname resolution.
    fn dial(&self, approved: SocketAddr) -> ProviderHttpDialFuture<'_>;
}

/// The production Tokio numeric TCP dial adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioNumericDialer;

impl ProviderHttpNumericDialer for TokioNumericDialer {
    fn dial(&self, approved: SocketAddr) -> ProviderHttpDialFuture<'_> {
        Box::pin(async move {
            let stream = TcpStream::connect(approved)
                .await
                .map_err(|_| ProviderHttpDialError::unavailable())?;
            let standard = stream
                .into_std()
                .map_err(|_| ProviderHttpDialError::unavailable())?;
            ProviderHttpConnectedSocket::from_std(standard)
        })
    }
}

/// Direct connector with explicit resolver, policy, and numeric dial ownership.
pub(crate) struct ProviderHttpDirectConnector {
    resolver: Arc<dyn BoundedResolver>,
    policy: Arc<dyn OutboundPolicyPort>,
    dialer: Arc<dyn ProviderHttpNumericDialer>,
}

impl ProviderHttpDirectConnector {
    /// Creates one direct connector from trusted bounded adapters.
    #[must_use]
    pub(crate) fn new(
        resolver: Arc<dyn BoundedResolver>,
        policy: Arc<dyn OutboundPolicyPort>,
        dialer: Arc<dyn ProviderHttpNumericDialer>,
    ) -> Self {
        Self {
            resolver,
            policy,
            dialer,
        }
    }

    /// Resolves, authorizes, dials, verifies TLS, and creates an HTTP/1 connection.
    ///
    /// The returned connection owns both the Hyper sender and running driver.
    /// No request bytes are written by this operation, so every failure leaves
    /// `evidence` at `NotStarted`.
    ///
    /// `evidence` must be pristine and reserved for this physical connection.
    /// Sharing it with another connection or pretransitioning any progress
    /// boundary makes the later first request write fail closed.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted phase failure for cancellation, timeout, DNS,
    /// policy, TCP, proxy CONNECT, TLS, or HTTP/1 setup failure.
    pub(crate) async fn connect(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
    ) -> Result<ProviderHttpDirectConnection, ProviderHttpError> {
        let prepared = self.prepare_tls(profile, context).await?;
        prepared.establish_http1(context, evidence).await
    }

    pub(crate) fn connection_is_current(
        &self,
        connection: &ProviderHttpDirectConnection,
        profile: &ProviderHttpProfile,
    ) -> bool {
        connection.matches_origin(profile)
            && self
                .authorization_guard()
                .is_current(connection.authorization, profile)
    }

    fn authorization_guard(&self) -> ProviderHttpAuthorizationBoundary<'_> {
        ProviderHttpAuthorizationBoundary::new(self.resolver.as_ref(), self.policy.as_ref())
    }

    /// Resolves, authorizes, dials, and verifies TLS without writing HTTP bytes.
    ///
    /// The returned value owns an established TLS stream and a copy of the
    /// checked timeout configuration needed for the subsequent HTTP/1 setup.
    /// It has not armed transmission evidence, so failures before HTTP request
    /// serialization leave an associated attempt at `NotStarted`.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted phase failure for cancellation, timeout, DNS,
    /// policy, TCP, proxy CONNECT, or TLS setup failure.
    pub(crate) async fn prepare_tls(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
    ) -> Result<ProviderHttpPreparedConnection, ProviderHttpError> {
        let origin = self.resolve_origin(profile, context).await?;
        let (socket, authorization) = self.connect_transport(profile, context, origin).await?;
        let authorization_guard = self.authorization_guard();
        authorization_guard.ensure_current(authorization, profile)?;
        let write_denial = socket.denial();
        let timeouts = profile.timeouts();
        let tls_result = run_provider_phase(
            context,
            timeouts.tls_handshake(),
            timeouts.cancellation_poll(),
            ProviderHttpPhase::TlsHandshake,
            ProviderHttpErrorCode::TlsHandshakeFailed,
            tls::connect(socket, profile.endpoint().host(), profile.trust()),
        )
        .await;
        let (mut tls_stream, _tls_version) =
            tls_result.map_err(|error| write_denial.project(error))?;
        tls_stream
            .get_mut()
            .0
            .authorization_mut()
            .set_phase(ProviderHttpPhase::RequestHeaders);
        Ok(ProviderHttpPreparedConnection {
            tls_stream,
            timeouts,
            origin_host: profile.endpoint().host().clone(),
            origin_port: profile.endpoint().port(),
            limits: profile.limits(),
            security_key: ProviderHttpConnectionSecurityKey::from_profile(profile),
            authorization,
            write_denial,
        })
    }

    async fn resolve_origin(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
    ) -> Result<ProviderHttpAuthorizedTarget, ProviderHttpError> {
        let endpoint = profile.endpoint();
        let target =
            OutboundTarget::new(endpoint.host().clone(), endpoint.port()).map_err(|_| {
                phase_error(
                    ProviderHttpErrorCode::ResolutionFailed,
                    ProviderHttpPhase::Resolution,
                )
            })?;
        self.resolve_target(&target, profile, context).await
    }

    async fn resolve_target(
        &self,
        target: &OutboundTarget,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
    ) -> Result<ProviderHttpAuthorizedTarget, ProviderHttpError> {
        check_phase_context(context, ProviderHttpPhase::Resolution)?;
        let revision = self.policy.revision();
        let answers = self
            .resolver
            .resolve_checked_with_limit(
                target.host(),
                context,
                profile.timeouts(),
                profile.limits().max_dns_answers(),
            )
            .await
            .map_err(|error| map_egress_error(error, ProviderHttpPhase::Resolution))?;
        let record = ResolutionRecord::from_resolution(target.clone(), answers, revision)
            .map_err(|error| map_egress_error(error, ProviderHttpPhase::Resolution))?;
        let address = record
            .authorize(
                Instant::now(),
                profile.timeouts().max_resolution_age(),
                self.resolver.as_ref(),
                self.policy.as_ref(),
            )
            .map_err(|error| map_egress_error(error, ProviderHttpPhase::Resolution))?;
        Ok(ProviderHttpAuthorizedTarget {
            address: SocketAddr::new(address, target.port()),
            authorization: ProviderHttpAuthorizationStamp::from_record(&record),
        })
    }

    async fn connect_transport(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
        origin: ProviderHttpAuthorizedTarget,
    ) -> Result<(ProviderTcpStream, ProviderHttpConnectionAuthorization), ProviderHttpError> {
        match profile.proxy().target() {
            Some(proxy_target) => {
                self.connect_proxy_transport(profile, context, origin, proxy_target)
                    .await
            }
            None => {
                self.connect_direct_transport(profile, context, origin)
                    .await
            }
        }
    }

    async fn connect_direct_transport(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
        origin: ProviderHttpAuthorizedTarget,
    ) -> Result<(ProviderTcpStream, ProviderHttpConnectionAuthorization), ProviderHttpError> {
        let authorization = ProviderHttpConnectionAuthorization::direct(origin.authorization);
        let authorization_guard = self.authorization_guard();
        authorization_guard.ensure_current(authorization, profile)?;
        let socket = self.dial(profile, context, origin.address).await?;
        authorization_guard.ensure_current(authorization, profile)?;
        let write_authorization =
            self.write_authorization(authorization, profile, ProviderHttpPhase::TlsHandshake);
        Ok((
            ProviderHttpAuthorizedIo::new(socket, write_authorization),
            authorization,
        ))
    }

    async fn connect_proxy_transport(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
        origin: ProviderHttpAuthorizedTarget,
        proxy_target: &OutboundTarget,
    ) -> Result<(ProviderTcpStream, ProviderHttpConnectionAuthorization), ProviderHttpError> {
        let proxy = self.resolve_target(proxy_target, profile, context).await?;
        let authorization =
            ProviderHttpConnectionAuthorization::proxied(origin.authorization, proxy.authorization);
        let authorization_guard = self.authorization_guard();
        authorization_guard.ensure_current(authorization, profile)?;
        let socket = self.dial(profile, context, proxy.address).await?;
        authorization_guard.ensure_current(authorization, profile)?;
        let write_authorization =
            self.write_authorization(authorization, profile, ProviderHttpPhase::ProxyConnect);
        let socket = ProviderHttpAuthorizedIo::new(socket, write_authorization);
        let write_denial = socket.denial();
        let timeouts = profile.timeouts();
        let tunnel_result = run_provider_phase(
            context,
            timeouts.proxy_connect(),
            timeouts.cancellation_poll(),
            ProviderHttpPhase::ProxyConnect,
            ProviderHttpErrorCode::ProxyConnectFailed,
            proxy::establish_tunnel(socket, origin.address),
        )
        .await;
        let mut socket = tunnel_result.map_err(|error| write_denial.project(error))?;
        socket
            .authorization_mut()
            .set_phase(ProviderHttpPhase::TlsHandshake);
        Ok((socket, authorization))
    }

    fn write_authorization(
        &self,
        authorization: ProviderHttpConnectionAuthorization,
        profile: &ProviderHttpProfile,
        phase: ProviderHttpPhase,
    ) -> ProviderHttpWriteAuthorization {
        ProviderHttpWriteAuthorization::new(
            authorization,
            self.resolver.clone(),
            self.policy.clone(),
            profile.timeouts().max_resolution_age(),
            phase,
        )
    }

    async fn dial(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
        approved: SocketAddr,
    ) -> Result<TcpStream, ProviderHttpError> {
        let timeouts = profile.timeouts();
        let socket = run_provider_phase(
            context,
            timeouts.connect(),
            timeouts.cancellation_poll(),
            ProviderHttpPhase::Connect,
            ProviderHttpErrorCode::ConnectFailed,
            self.dialer.dial(approved),
        )
        .await?;
        socket.into_tokio().map_err(|_| {
            phase_error(
                ProviderHttpErrorCode::ConnectFailed,
                ProviderHttpPhase::Connect,
            )
        })
    }
}

/// An opaque verified TLS connection awaiting low-level HTTP/1 setup.
///
/// This value retains the policy-approved peer, negotiated TLS version, and
/// checked timeouts from TLS preparation. It cannot transmit HTTP request bytes
/// until [`Self::establish_http1`] has completed and armed its evidence marker.
pub(crate) struct ProviderHttpPreparedConnection {
    tls_stream: ProviderTlsStream,
    timeouts: crate::config::ProviderHttpTimeouts,
    origin_host: OutboundHost,
    origin_port: u16,
    limits: ProviderHttpLimits,
    security_key: ProviderHttpConnectionSecurityKey,
    authorization: ProviderHttpConnectionAuthorization,
    write_denial: ProviderHttpWriteDenial,
}

impl ProviderHttpPreparedConnection {
    /// Completes the separately bounded low-level HTTP/1 client handshake.
    ///
    /// This consumes the prepared TLS connection. Cancellation or deadline
    /// expiration before the handshake starts leaves `evidence` at
    /// `NotStarted`; the marker is armed only after successful setup.
    /// The evidence handle must be pristine and exclusive to this physical
    /// connection; otherwise its first request write fails closed.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error for cancellation, deadline expiry,
    /// runtime unavailability, or HTTP/1 handshake failure.
    pub(crate) async fn establish_http1(
        self,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
    ) -> Result<ProviderHttpDirectConnection, ProviderHttpError> {
        let marker = ProviderTransmissionMarker::new(evidence.clone());
        let mut tls_stream = self.tls_stream;
        tls_stream
            .get_mut()
            .0
            .authorization_mut()
            .bind_transmission(marker.clone());
        let response_limit = Arc::new(AtomicBool::new(false));
        let response_protocol = Arc::new(AtomicBool::new(false));
        let response_head_bounds = Arc::new(ResponseHeadBounds::new(self.limits));
        let response_head_guard = Arc::new(Mutex::new(ResponseHeadGuard::new(
            response_head_bounds.clone(),
            response_limit.clone(),
            response_protocol.clone(),
        )));
        let io = TokioIo::new(MarkedTlsStream::new(
            tls_stream,
            marker.clone(),
            response_head_guard.clone(),
        ));
        let mut builder = hyper::client::conn::http1::Builder::new();
        builder.max_headers(ProviderHttpLimits::default().max_headers());
        builder.max_buf_size(HTTP1_MAX_BUFFER_BYTES);
        let (sender, driver) = run_provider_phase(
            context,
            self.timeouts.http1_handshake(),
            self.timeouts.cancellation_poll(),
            ProviderHttpPhase::Http1Handshake,
            ProviderHttpErrorCode::Http1HandshakeFailed,
            builder.handshake::<_, RequestBody>(io),
        )
        .await?;
        marker.arm();
        let driver_finished = Arc::new(AtomicBool::new(false));
        let driver = spawn_driver(driver, marker.clone(), driver_finished.clone());
        let driver_abort = driver.abort_handle();
        Ok(ProviderHttpDirectConnection {
            sender,
            driver: Some(driver),
            driver_abort,
            driver_finished,
            marker,
            origin_host: self.origin_host,
            origin_port: self.origin_port,
            response_limit,
            response_protocol,
            response_head_bounds,
            response_head_guard,
            security_key: self.security_key,
            authorization: self.authorization,
            write_denial: self.write_denial,
        })
    }
}

impl Debug for ProviderHttpPreparedConnection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpPreparedConnection { redacted }")
    }
}

/// One verified direct HTTP/1 connection with retained driver ownership.
pub(crate) struct ProviderHttpDirectConnection {
    sender: SendRequest<RequestBody>,
    driver: Option<JoinHandle<()>>,
    driver_abort: AbortHandle,
    driver_finished: Arc<AtomicBool>,
    marker: ProviderTransmissionMarker,
    origin_host: OutboundHost,
    origin_port: u16,
    response_limit: Arc<AtomicBool>,
    response_protocol: Arc<AtomicBool>,
    response_head_bounds: Arc<ResponseHeadBounds>,
    response_head_guard: Arc<Mutex<ResponseHeadGuard>>,
    security_key: ProviderHttpConnectionSecurityKey,
    authorization: ProviderHttpConnectionAuthorization,
    write_denial: ProviderHttpWriteDenial,
}

impl ProviderHttpDirectConnection {
    pub(crate) fn sender_mut(&mut self) -> &mut SendRequest<RequestBody> {
        &mut self.sender
    }

    pub(crate) fn evidence(&self) -> ProviderAttemptEvidence {
        self.marker.evidence()
    }

    pub(crate) fn rebind_attempt(
        &self,
        evidence: &ProviderAttemptEvidence,
        limits: ProviderHttpLimits,
    ) -> Result<(), ProviderHttpError> {
        self.reset_response_state(limits);
        self.marker
            .rebind(evidence.clone())
            .map_err(|_| evidence_transport_error())?;
        self.write_denial.clear();
        Ok(())
    }

    pub(crate) fn matches_origin(&self, profile: &ProviderHttpProfile) -> bool {
        self.origin_host == *profile.endpoint().host()
            && self.origin_port == profile.endpoint().port()
            && self.security_key.matches(profile)
    }

    pub(crate) fn response_limit_observed(&self) -> bool {
        self.response_limit.load(Ordering::Acquire)
    }

    pub(crate) fn response_protocol_observed(&self) -> bool {
        self.response_protocol.load(Ordering::Acquire)
    }

    pub(crate) fn authorization_error(&self) -> Option<ProviderHttpError> {
        self.write_denial.error()
    }

    pub(crate) fn apply_execution_limits(&self, limits: ProviderHttpLimits) {
        self.response_head_bounds.store(limits);
    }

    pub(crate) fn is_reusable(&self) -> bool {
        !self.driver_is_finished() && !self.sender.is_closed()
    }

    pub(crate) fn abort_driver(&self) {
        self.marker.close();
        self.driver_abort.abort();
    }

    pub(crate) fn driver_is_finished(&self) -> bool {
        self.driver_finished.load(Ordering::Acquire)
    }

    pub(crate) fn take_driver_for_join(&mut self) -> Option<JoinHandle<()>> {
        self.driver.take()
    }

    fn reset_response_state(&self, limits: ProviderHttpLimits) {
        self.response_limit.store(false, Ordering::Release);
        self.response_protocol.store(false, Ordering::Release);
        reset_response_head_guard(&self.response_head_guard, limits);
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ProviderHttpConnectionSecurityKey {
    trust: ProviderHttpTrust,
    proxy: ProviderHttpProxy,
}

impl ProviderHttpConnectionSecurityKey {
    fn from_profile(profile: &ProviderHttpProfile) -> Self {
        Self {
            trust: profile.trust(),
            proxy: profile.proxy().clone(),
        }
    }

    fn matches(&self, profile: &ProviderHttpProfile) -> bool {
        self.trust == profile.trust() && self.proxy == *profile.proxy()
    }
}

impl Drop for ProviderHttpDirectConnection {
    fn drop(&mut self) {
        self.marker.close();
        self.driver_abort.abort();
    }
}

impl Debug for ProviderHttpDirectConnection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpDirectConnection { redacted }")
    }
}

const fn evidence_transport_error() -> ProviderHttpError {
    ProviderHttpError::with_phase(
        ProviderHttpErrorCode::RequestFailed,
        ProviderHttpPhase::RequestHeaders,
    )
}

struct ResponseHeadGuard {
    bounds: Arc<ResponseHeadBounds>,
    header_count: usize,
    header_bytes: usize,
    head_wire_bytes: usize,
    line_bytes: usize,
    previous_was_cr: bool,
    saw_status_line: bool,
    informational_status: bool,
    complete: bool,
    limit_violation: Arc<AtomicBool>,
    protocol_violation: Arc<AtomicBool>,
}

impl ResponseHeadGuard {
    fn new(
        bounds: Arc<ResponseHeadBounds>,
        limit_violation: Arc<AtomicBool>,
        protocol_violation: Arc<AtomicBool>,
    ) -> Self {
        Self {
            bounds,
            header_count: 0,
            header_bytes: 0,
            head_wire_bytes: 0,
            line_bytes: 0,
            previous_was_cr: false,
            saw_status_line: false,
            informational_status: false,
            complete: false,
            limit_violation,
            protocol_violation,
        }
    }

    fn reset(&mut self, limits: ProviderHttpLimits) {
        self.bounds.store(limits);
        self.header_count = 0;
        self.header_bytes = 0;
        self.head_wire_bytes = 0;
        self.line_bytes = 0;
        self.previous_was_cr = false;
        self.saw_status_line = false;
        self.informational_status = false;
        self.complete = false;
    }

    fn observe(&mut self, bytes: &[u8]) -> io::Result<()> {
        for byte in bytes {
            if self.complete {
                break;
            }
            self.observe_byte(*byte)?;
        }
        Ok(())
    }

    fn observe_byte(&mut self, byte: u8) -> io::Result<()> {
        self.charge_wire_byte()?;
        self.observe_status_byte(byte);
        if self.advance_line(byte) {
            self.finish_line()
        } else {
            Ok(())
        }
    }

    fn charge_wire_byte(&mut self) -> io::Result<()> {
        self.head_wire_bytes = self.head_wire_bytes.saturating_add(1);
        self.line_bytes = self.line_bytes.saturating_add(1);
        self.ensure_absolute_head_limit()?;
        self.ensure_current_header_limit()
    }

    fn ensure_absolute_head_limit(&self) -> io::Result<()> {
        if self.head_wire_bytes > HTTP1_MAX_BUFFER_BYTES {
            return self.reject_limit();
        }
        Ok(())
    }

    fn ensure_current_header_limit(&self) -> io::Result<()> {
        if self.current_header_bytes_exceeded() {
            return self.reject_limit();
        }
        Ok(())
    }

    fn advance_line(&mut self, byte: u8) -> bool {
        let ended = self.previous_was_cr && byte == b'\n';
        self.previous_was_cr = byte == b'\r';
        ended
    }

    fn observe_status_byte(&mut self, byte: u8) {
        if !self.saw_status_line && self.line_bytes == 10 {
            self.informational_status = byte == b'1';
        }
    }

    fn current_header_bytes_exceeded(&self) -> bool {
        self.saw_status_line
            && self.line_bytes > 2
            && self
                .header_bytes
                .saturating_add(self.line_bytes)
                .gt(&self.bounds.max_header_bytes())
    }

    fn finish_line(&mut self) -> io::Result<()> {
        let line_bytes = std::mem::take(&mut self.line_bytes);
        if !self.saw_status_line {
            self.saw_status_line = true;
            return self.finish_status_line();
        }
        if line_bytes == 2 {
            self.complete = true;
            return Ok(());
        }
        self.header_count = self.header_count.saturating_add(1);
        self.header_bytes = self.header_bytes.saturating_add(line_bytes);
        if self.header_count > self.bounds.max_headers()
            || self.header_bytes > self.bounds.max_header_bytes()
        {
            return self.reject_limit();
        }
        Ok(())
    }

    fn finish_status_line(&self) -> io::Result<()> {
        if self.informational_status {
            return self.reject_protocol();
        }
        Ok(())
    }

    fn reject_limit<T>(&self) -> io::Result<T> {
        self.limit_violation.store(true, Ordering::Release);
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider response head exceeded its checked boundary",
        ))
    }

    fn reject_protocol<T>(&self) -> io::Result<T> {
        self.protocol_violation.store(true, Ordering::Release);
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider response head violated its checked protocol",
        ))
    }
}

struct ResponseHeadBounds {
    max_headers: AtomicUsize,
    max_header_bytes: AtomicUsize,
}

impl ResponseHeadBounds {
    fn new(limits: ProviderHttpLimits) -> Self {
        Self {
            max_headers: AtomicUsize::new(limits.max_headers()),
            max_header_bytes: AtomicUsize::new(limits.max_header_bytes()),
        }
    }

    fn store(&self, limits: ProviderHttpLimits) {
        self.max_headers
            .store(limits.max_headers(), Ordering::Release);
        self.max_header_bytes
            .store(limits.max_header_bytes(), Ordering::Release);
    }

    fn max_headers(&self) -> usize {
        self.max_headers.load(Ordering::Acquire)
    }

    fn max_header_bytes(&self) -> usize {
        self.max_header_bytes.load(Ordering::Acquire)
    }
}

struct MarkedTlsStream {
    stream: ProviderTlsStream,
    marker: ProviderTransmissionMarker,
    head_guard: Arc<Mutex<ResponseHeadGuard>>,
    scratch: Box<[u8; GUARDED_READ_CHUNK_BYTES]>,
}

impl MarkedTlsStream {
    fn new(
        stream: ProviderTlsStream,
        marker: ProviderTransmissionMarker,
        head_guard: Arc<Mutex<ResponseHeadGuard>>,
    ) -> Self {
        Self {
            stream,
            marker,
            head_guard,
            scratch: Box::new([0_u8; GUARDED_READ_CHUNK_BYTES]),
        }
    }

    fn poll_response_head(
        &mut self,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let capacity = self.scratch.len().min(buffer.remaining());
        if capacity == 0 {
            return Poll::Ready(Ok(()));
        }
        let (result, count) = {
            let mut guarded = ReadBuf::new(&mut self.scratch[..capacity]);
            let result = Pin::new(&mut self.stream).poll_read(context, &mut guarded);
            (result, guarded.filled().len())
        };
        self.finish_guarded_poll(result, count, buffer)
    }

    fn finish_guarded_poll(
        &mut self,
        result: Poll<io::Result<()>>,
        count: usize,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                Poll::Ready(result.and_then(|()| self.forward_response_bytes(count, buffer)))
            }
        }
    }

    fn forward_response_bytes(&mut self, count: usize, buffer: &mut ReadBuf<'_>) -> io::Result<()> {
        if count == 0 {
            return Ok(());
        }
        self.marker.observe_response_bytes()?;
        let bytes = &self.scratch[..count];
        lock_response_head_guard(&self.head_guard).observe(bytes)?;
        buffer.put_slice(bytes);
        Ok(())
    }
}

impl AsyncRead for MarkedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if lock_response_head_guard(&self.head_guard).complete {
            return Pin::new(&mut self.stream).poll_read(context, buffer);
        }
        self.poll_response_head(context, buffer)
    }
}

impl AsyncWrite for MarkedTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write_vectored(context, buffers)
    }
}

fn lock_response_head_guard(guard: &Mutex<ResponseHeadGuard>) -> MutexGuard<'_, ResponseHeadGuard> {
    match guard.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn reset_response_head_guard(guard: &Mutex<ResponseHeadGuard>, limits: ProviderHttpLimits) {
    lock_response_head_guard(guard).reset(limits);
}

struct ProviderDriverCompletion {
    marker: ProviderTransmissionMarker,
    finished: Arc<AtomicBool>,
}

impl Drop for ProviderDriverCompletion {
    fn drop(&mut self) {
        self.marker.close();
        self.finished.store(true, Ordering::Release);
    }
}

fn spawn_driver<F>(
    driver: F,
    marker: ProviderTransmissionMarker,
    finished: Arc<AtomicBool>,
) -> JoinHandle<()>
where
    F: Future<Output = Result<(), hyper::Error>> + Send + 'static,
{
    tokio::spawn(async move {
        let _completion = ProviderDriverCompletion { marker, finished };
        let _result = driver.await;
    })
}

async fn run_provider_phase<T, E, F>(
    context: &RequestContext,
    budget: std::time::Duration,
    cancellation_poll: std::time::Duration,
    phase: ProviderHttpPhase,
    failure: ProviderHttpErrorCode,
    future: F,
) -> Result<T, ProviderHttpError>
where
    F: Future<Output = Result<T, E>>,
{
    let mapped = async { future.await.map_err(|_| EgressError::ResolutionFailed) };
    run_with_timeout(context, budget, cancellation_poll, mapped)
        .await
        .map_err(|error| map_phase_error(error, phase, failure))
}

fn check_phase_context(
    context: &RequestContext,
    phase: ProviderHttpPhase,
) -> Result<(), ProviderHttpError> {
    context.check_active().map_err(|error| {
        let code = if error.code() == ariadnion_core::ErrorCode::Cancelled {
            ProviderHttpErrorCode::Cancelled
        } else {
            ProviderHttpErrorCode::DeadlineExceeded
        };
        phase_error(code, phase)
    })
}

fn map_phase_error(
    error: EgressError,
    phase: ProviderHttpPhase,
    failure: ProviderHttpErrorCode,
) -> ProviderHttpError {
    let code = match error {
        EgressError::Cancelled => ProviderHttpErrorCode::Cancelled,
        EgressError::DeadlineExceeded => ProviderHttpErrorCode::DeadlineExceeded,
        EgressError::RuntimeUnavailable => ProviderHttpErrorCode::RuntimeUnavailable,
        _ => failure,
    };
    phase_error(code, phase)
}

fn map_egress_error(error: EgressError, phase: ProviderHttpPhase) -> ProviderHttpError {
    let code = match error {
        EgressError::Cancelled => ProviderHttpErrorCode::Cancelled,
        EgressError::DeadlineExceeded => ProviderHttpErrorCode::DeadlineExceeded,
        EgressError::RuntimeUnavailable => ProviderHttpErrorCode::RuntimeUnavailable,
        EgressError::PolicyDenied
        | EgressError::PolicyChanged
        | EgressError::StaleResolution
        | EgressError::ForbiddenAddress => ProviderHttpErrorCode::OutboundDenied,
        _ => ProviderHttpErrorCode::ResolutionFailed,
    };
    phase_error(code, phase)
}

const fn phase_error(code: ProviderHttpErrorCode, phase: ProviderHttpPhase) -> ProviderHttpError {
    ProviderHttpError::with_phase(code, phase)
}

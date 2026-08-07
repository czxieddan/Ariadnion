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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
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
use ariadnion_provider_sdk::{
    ProviderAttemptEvidence, ProviderAttemptProgress, ProviderTransmission,
};
use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;

use crate::config::{
    ProviderHttpLimits, ProviderHttpProfile, ProviderHttpProxy, ProviderHttpTrust,
};
use crate::dns::{BoundedResolver, ResolutionRecord};
use crate::egress::EgressError;
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};
use crate::proxy;
use crate::timeout::run_with_timeout;
use crate::tls::{self, ProviderTlsVersion};

pub(crate) type RequestBody = Full<Bytes>;

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
pub struct ProviderHttpDirectConnector {
    resolver: Arc<dyn BoundedResolver>,
    policy: Arc<dyn OutboundPolicyPort>,
    dialer: Arc<dyn ProviderHttpNumericDialer>,
}

impl ProviderHttpDirectConnector {
    /// Creates one direct connector from trusted bounded adapters.
    #[must_use]
    pub fn new(
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
    pub async fn connect(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
    ) -> Result<ProviderHttpDirectConnection, ProviderHttpError> {
        let prepared = self.prepare_tls(profile, context).await?;
        prepared.establish_http1(context, evidence).await
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
    pub async fn prepare_tls(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
    ) -> Result<ProviderHttpPreparedConnection, ProviderHttpError> {
        let origin = self.resolve_origin(profile, context).await?;
        let (socket, approved_peer) = self.connect_transport(profile, context, origin).await?;
        let timeouts = profile.timeouts();
        let (tls_stream, tls_version) = run_provider_phase(
            context,
            timeouts.tls_handshake(),
            timeouts.cancellation_poll(),
            ProviderHttpPhase::TlsHandshake,
            ProviderHttpErrorCode::TlsHandshakeFailed,
            tls::connect(socket, profile.endpoint().host(), profile.trust()),
        )
        .await?;
        Ok(ProviderHttpPreparedConnection {
            tls_stream,
            approved_peer,
            tls_version,
            timeouts,
            origin_host: profile.endpoint().host().clone(),
            origin_port: profile.endpoint().port(),
            limits: profile.limits(),
            security_key: ProviderHttpConnectionSecurityKey::from_profile(profile),
        })
    }

    async fn resolve_origin(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
    ) -> Result<SocketAddr, ProviderHttpError> {
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
    ) -> Result<SocketAddr, ProviderHttpError> {
        check_phase_context(context, ProviderHttpPhase::Resolution)?;
        let revision = self.policy.revision();
        let answers = self
            .resolver
            .resolve_checked(target.host(), context, profile.timeouts())
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
        Ok(SocketAddr::new(address, target.port()))
    }

    async fn connect_transport(
        &self,
        profile: &ProviderHttpProfile,
        context: &RequestContext,
        origin: SocketAddr,
    ) -> Result<(TcpStream, SocketAddr), ProviderHttpError> {
        let Some(proxy_target) = profile.proxy().target() else {
            let socket = self.dial(profile, context, origin).await?;
            return Ok((socket, origin));
        };
        let proxy = self.resolve_target(proxy_target, profile, context).await?;
        let socket = self.dial(profile, context, proxy).await?;
        let timeouts = profile.timeouts();
        let socket = run_provider_phase(
            context,
            timeouts.proxy_connect(),
            timeouts.cancellation_poll(),
            ProviderHttpPhase::ProxyConnect,
            ProviderHttpErrorCode::ProxyConnectFailed,
            proxy::establish_tunnel(socket, origin),
        )
        .await?;
        Ok((socket, proxy))
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
pub struct ProviderHttpPreparedConnection {
    tls_stream: TlsStream<TcpStream>,
    approved_peer: SocketAddr,
    tls_version: ProviderTlsVersion,
    timeouts: crate::config::ProviderHttpTimeouts,
    origin_host: OutboundHost,
    origin_port: u16,
    limits: ProviderHttpLimits,
    security_key: ProviderHttpConnectionSecurityKey,
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
    pub async fn establish_http1(
        self,
        context: &RequestContext,
        evidence: &ProviderAttemptEvidence,
    ) -> Result<ProviderHttpDirectConnection, ProviderHttpError> {
        let marker = ProviderTransmissionMarker::new(evidence.clone());
        let response_limit = Arc::new(AtomicBool::new(false));
        let response_protocol = Arc::new(AtomicBool::new(false));
        let response_head_bounds = Arc::new(ResponseHeadBounds::new(self.limits));
        let io = TokioIo::new(MarkedTlsStream::new(
            self.tls_stream,
            marker.clone(),
            response_head_bounds.clone(),
            response_limit.clone(),
            response_protocol.clone(),
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
        let driver = spawn_driver(driver);
        Ok(ProviderHttpDirectConnection {
            sender,
            driver,
            marker,
            approved_peer: self.approved_peer,
            tls_version: self.tls_version,
            origin_host: self.origin_host,
            origin_port: self.origin_port,
            response_limit,
            response_protocol,
            response_head_bounds,
            security_key: self.security_key,
        })
    }
}

impl Debug for ProviderHttpPreparedConnection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpPreparedConnection { redacted }")
    }
}

/// One verified direct HTTP/1 connection with retained driver ownership.
pub struct ProviderHttpDirectConnection {
    sender: SendRequest<RequestBody>,
    driver: JoinHandle<()>,
    marker: ProviderTransmissionMarker,
    approved_peer: SocketAddr,
    tls_version: ProviderTlsVersion,
    origin_host: OutboundHost,
    origin_port: u16,
    response_limit: Arc<AtomicBool>,
    response_protocol: Arc<AtomicBool>,
    response_head_bounds: Arc<ResponseHeadBounds>,
    security_key: ProviderHttpConnectionSecurityKey,
}

impl ProviderHttpDirectConnection {
    pub(crate) fn sender_mut(&mut self) -> &mut SendRequest<RequestBody> {
        &mut self.sender
    }

    pub(crate) fn evidence(&self) -> ProviderAttemptEvidence {
        self.marker.evidence.clone()
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

    pub(crate) fn apply_execution_limits(&self, limits: ProviderHttpLimits) {
        self.response_head_bounds.store(limits);
    }

    pub(crate) fn is_reusable(&self) -> bool {
        !self.driver.is_finished() && !self.sender.is_closed()
    }

    /// Returns the policy-approved numeric peer selected for the physical connection.
    #[must_use]
    pub const fn approved_peer(&self) -> SocketAddr {
        self.approved_peer
    }

    /// Returns the verified TLS protocol negotiated with the provider.
    #[must_use]
    pub const fn negotiated_tls_version(&self) -> ProviderTlsVersion {
        self.tls_version
    }

    /// Confirms that this value retains the low-level HTTP/1 connection driver.
    #[must_use]
    pub fn owns_http1_driver(&self) -> bool {
        !self.driver.is_finished()
    }

    /// Returns the attempt evidence snapshot owned by this connection marker.
    #[must_use]
    pub fn attempt_progress(&self) -> ProviderAttemptProgress {
        self.marker.evidence.progress()
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
        self.driver.abort();
    }
}

impl Debug for ProviderHttpDirectConnection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderHttpDirectConnection { redacted }")
    }
}

#[derive(Clone)]
struct ProviderTransmissionMarker {
    evidence: ProviderAttemptEvidence,
    lifecycle: Arc<Mutex<ProviderTransmissionLifecycle>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderTransmissionLifecycle {
    Unarmed,
    Idle,
    Claimed,
    Closed,
}

struct ProviderWriteGuard<'a> {
    _lifecycle: MutexGuard<'a, ProviderTransmissionLifecycle>,
}

impl ProviderTransmissionMarker {
    fn new(evidence: ProviderAttemptEvidence) -> Self {
        Self {
            evidence,
            lifecycle: Arc::new(Mutex::new(ProviderTransmissionLifecycle::Unarmed)),
        }
    }

    fn arm(&self) {
        let mut lifecycle = lock_transmission_lifecycle(&self.lifecycle);
        if *lifecycle == ProviderTransmissionLifecycle::Unarmed {
            *lifecycle = ProviderTransmissionLifecycle::Idle;
        }
    }

    /// Acquires the lifecycle before the evidence mutex and retains it through
    /// one synchronous transport poll. No code acquires these locks in reverse
    /// order, and the guard never crosses an await boundary.
    fn write_guard(&self) -> io::Result<ProviderWriteGuard<'_>> {
        let mut lifecycle = lock_transmission_lifecycle(&self.lifecycle);
        match *lifecycle {
            ProviderTransmissionLifecycle::Idle => self.claim(&mut lifecycle)?,
            ProviderTransmissionLifecycle::Claimed => {}
            ProviderTransmissionLifecycle::Unarmed | ProviderTransmissionLifecycle::Closed => {
                return Err(evidence_error());
            }
        }
        Ok(ProviderWriteGuard {
            _lifecycle: lifecycle,
        })
    }

    fn claim(&self, lifecycle: &mut ProviderTransmissionLifecycle) -> io::Result<()> {
        if !pristine_progress(self.evidence.progress()) {
            *lifecycle = ProviderTransmissionLifecycle::Closed;
            return Err(evidence_error());
        }
        if self.evidence.mark_transmission_started().is_err() {
            *lifecycle = ProviderTransmissionLifecycle::Closed;
            return Err(evidence_error());
        }
        if !claimed_progress(self.evidence.progress()) {
            self.close_failed_claim(lifecycle);
            return Err(evidence_error());
        }
        *lifecycle = ProviderTransmissionLifecycle::Claimed;
        Ok(())
    }

    fn close_failed_claim(&self, lifecycle: &mut ProviderTransmissionLifecycle) {
        if self.evidence.progress().transmission() == ProviderTransmission::Started {
            let _result = self.evidence.mark_transmission_unknown();
        }
        *lifecycle = ProviderTransmissionLifecycle::Closed;
    }

    fn close(&self) {
        let mut lifecycle = lock_transmission_lifecycle(&self.lifecycle);
        if *lifecycle == ProviderTransmissionLifecycle::Claimed
            && self.evidence.progress().transmission() == ProviderTransmission::Started
        {
            let _result = self.evidence.mark_transmission_unknown();
        }
        *lifecycle = ProviderTransmissionLifecycle::Closed;
    }

    fn observe_response_bytes(&self) -> io::Result<()> {
        let lifecycle = lock_transmission_lifecycle(&self.lifecycle);
        if *lifecycle != ProviderTransmissionLifecycle::Claimed {
            return Err(evidence_error());
        }
        self.commit_response()?;
        self.mark_upstream_response()
    }

    fn commit_response(&self) -> io::Result<()> {
        match self.evidence.progress().transmission() {
            ProviderTransmission::Started => self
                .evidence
                .mark_request_committed()
                .map_err(|_| evidence_error()),
            ProviderTransmission::Committed => Ok(()),
            ProviderTransmission::NotStarted | ProviderTransmission::Unknown => {
                Err(evidence_error())
            }
            _ => Err(evidence_error()),
        }
    }

    fn mark_upstream_response(&self) -> io::Result<()> {
        if self.evidence.progress().upstream_response_started() {
            return Ok(());
        }
        self.evidence
            .mark_upstream_response_started()
            .map_err(|_| evidence_error())
    }
}

fn pristine_progress(progress: ProviderAttemptProgress) -> bool {
    progress.transmission() == ProviderTransmission::NotStarted
        && !progress.upstream_response_started()
        && !progress.downstream_delivery_started()
}

fn claimed_progress(progress: ProviderAttemptProgress) -> bool {
    progress.transmission() == ProviderTransmission::Started
        && !progress.upstream_response_started()
        && !progress.downstream_delivery_started()
}

fn lock_transmission_lifecycle(
    lifecycle: &Mutex<ProviderTransmissionLifecycle>,
) -> MutexGuard<'_, ProviderTransmissionLifecycle> {
    match lifecycle.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn evidence_error() -> io::Error {
    io::Error::other("provider transmission evidence rejected")
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
    stream: TlsStream<TcpStream>,
    marker: ProviderTransmissionMarker,
    head_guard: ResponseHeadGuard,
    scratch: Box<[u8; GUARDED_READ_CHUNK_BYTES]>,
}

impl MarkedTlsStream {
    fn new(
        stream: TlsStream<TcpStream>,
        marker: ProviderTransmissionMarker,
        bounds: Arc<ResponseHeadBounds>,
        limit_violation: Arc<AtomicBool>,
        protocol_violation: Arc<AtomicBool>,
    ) -> Self {
        Self {
            stream,
            marker,
            head_guard: ResponseHeadGuard::new(bounds, limit_violation, protocol_violation),
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
        self.head_guard.observe(bytes)?;
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
        if self.head_guard.complete {
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
        let marker = self.marker.clone();
        let _write_guard = match marker.write_guard() {
            Ok(guard) => guard,
            Err(error) => return Poll::Ready(Err(error)),
        };
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
        let marker = self.marker.clone();
        let _write_guard = match marker.write_guard() {
            Ok(guard) => guard,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(&mut self.stream).poll_write_vectored(context, buffers)
    }
}

fn spawn_driver<F>(driver: F) -> JoinHandle<()>
where
    F: Future<Output = Result<(), hyper::Error>> + Send + 'static,
{
    tokio::spawn(async move {
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

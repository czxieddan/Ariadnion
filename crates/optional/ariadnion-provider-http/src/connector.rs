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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use ariadnion_core::{OutboundPolicyPort, OutboundTarget, RequestContext};
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

use crate::config::ProviderHttpProfile;
use crate::dns::{BoundedResolver, ResolutionRecord};
use crate::egress::EgressError;
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};
use crate::proxy;
use crate::timeout::run_with_timeout;
use crate::tls::{self, ProviderTlsVersion};

type RequestBody = Full<Bytes>;

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
}

impl ProviderHttpPreparedConnection {
    /// Completes the separately bounded low-level HTTP/1 client handshake.
    ///
    /// This consumes the prepared TLS connection. Cancellation or deadline
    /// expiration before the handshake starts leaves `evidence` at
    /// `NotStarted`; the marker is armed only after successful setup.
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
        let io = TokioIo::new(MarkedTlsStream::new(self.tls_stream, marker.clone()));
        let (sender, driver) = run_provider_phase(
            context,
            self.timeouts.http1_handshake(),
            self.timeouts.cancellation_poll(),
            ProviderHttpPhase::Http1Handshake,
            ProviderHttpErrorCode::Http1HandshakeFailed,
            hyper::client::conn::http1::handshake::<_, RequestBody>(io),
        )
        .await?;
        marker.arm();
        let driver = spawn_driver(driver, marker.clone());
        Ok(ProviderHttpDirectConnection {
            _sender: sender,
            driver,
            marker,
            approved_peer: self.approved_peer,
            tls_version: self.tls_version,
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
    _sender: SendRequest<RequestBody>,
    driver: JoinHandle<()>,
    marker: ProviderTransmissionMarker,
    approved_peer: SocketAddr,
    tls_version: ProviderTlsVersion,
}

impl ProviderHttpDirectConnection {
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

impl Drop for ProviderHttpDirectConnection {
    fn drop(&mut self) {
        self.marker.mark_unknown_if_started();
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
    armed: Arc<AtomicBool>,
}

impl ProviderTransmissionMarker {
    fn new(evidence: ProviderAttemptEvidence) -> Self {
        Self {
            evidence,
            armed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    fn before_write(&self) -> io::Result<()> {
        if !self.armed.load(Ordering::Acquire)
            || self.evidence.progress().transmission() != ProviderTransmission::NotStarted
        {
            return Ok(());
        }
        self.evidence
            .mark_transmission_started()
            .map_err(|_| io::Error::other("provider transmission evidence rejected"))
    }

    fn mark_unknown_if_started(&self) {
        if self.evidence.progress().transmission() == ProviderTransmission::Started {
            let _result = self.evidence.mark_transmission_unknown();
        }
    }
}

struct MarkedTlsStream {
    stream: TlsStream<TcpStream>,
    marker: ProviderTransmissionMarker,
}

impl MarkedTlsStream {
    fn new(stream: TlsStream<TcpStream>, marker: ProviderTransmissionMarker) -> Self {
        Self { stream, marker }
    }
}

impl AsyncRead for MarkedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for MarkedTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let Err(error) = self.marker.before_write() {
            return Poll::Ready(Err(error));
        }
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
        if let Err(error) = self.marker.before_write() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_write_vectored(context, buffers)
    }
}

fn spawn_driver<F>(driver: F, marker: ProviderTransmissionMarker) -> JoinHandle<()>
where
    F: Future<Output = Result<(), hyper::Error>> + Send + 'static,
{
    let driver_marker = marker.clone();
    tokio::spawn(async move {
        let _result = driver.await;
        driver_marker.mark_unknown_if_started();
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

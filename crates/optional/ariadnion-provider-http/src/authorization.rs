// crates/optional/ariadnion-provider-http/src/authorization.rs - Reuse authorization stamps for Ariadnion.
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

//! Fail-closed DNS and policy provenance retained by reusable connections.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ariadnion_core::{OutboundPolicyPort, OutboundPolicyRevision};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::ProviderHttpProfile;
use crate::dns::{BoundedResolver, ResolutionEpoch, ResolutionRecord};
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};
use crate::transmission::ProviderTransmissionMarker;

#[derive(Clone, Copy)]
pub(crate) struct ProviderHttpAuthorizedTarget {
    pub(crate) address: SocketAddr,
    pub(crate) authorization: ProviderHttpAuthorizationStamp,
}

#[derive(Clone, Copy)]
pub(crate) struct ProviderHttpAuthorizationStamp {
    revision: OutboundPolicyRevision,
    epoch: ResolutionEpoch,
    resolved_at: Instant,
}

impl ProviderHttpAuthorizationStamp {
    pub(crate) const fn from_record(record: &ResolutionRecord) -> Self {
        Self {
            revision: record.revision(),
            epoch: record.epoch(),
            resolved_at: record.resolved_at(),
        }
    }

    fn is_current(
        self,
        now: Instant,
        max_age: Duration,
        epoch: ResolutionEpoch,
        revision: OutboundPolicyRevision,
    ) -> bool {
        now >= self.resolved_at
            && now.saturating_duration_since(self.resolved_at) <= max_age
            && self.epoch == epoch
            && self.revision == revision
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProviderHttpConnectionAuthorization {
    origin: ProviderHttpAuthorizationStamp,
    proxy: Option<ProviderHttpAuthorizationStamp>,
}

impl ProviderHttpConnectionAuthorization {
    pub(crate) const fn direct(origin: ProviderHttpAuthorizationStamp) -> Self {
        Self {
            origin,
            proxy: None,
        }
    }

    pub(crate) const fn proxied(
        origin: ProviderHttpAuthorizationStamp,
        proxy: ProviderHttpAuthorizationStamp,
    ) -> Self {
        Self {
            origin,
            proxy: Some(proxy),
        }
    }

    pub(crate) fn is_current(
        self,
        now: Instant,
        max_age: Duration,
        resolver: &dyn BoundedResolver,
        policy: &dyn OutboundPolicyPort,
    ) -> bool {
        let Ok(epoch) = resolver.current_epoch() else {
            return false;
        };
        let revision = policy.revision();
        self.origin.is_current(now, max_age, epoch, revision)
            && self
                .proxy
                .is_none_or(|stamp| stamp.is_current(now, max_age, epoch, revision))
    }
}

pub(crate) struct ProviderHttpAuthorizationBoundary<'a> {
    resolver: &'a dyn BoundedResolver,
    policy: &'a dyn OutboundPolicyPort,
}

impl<'a> ProviderHttpAuthorizationBoundary<'a> {
    pub(crate) const fn new(
        resolver: &'a dyn BoundedResolver,
        policy: &'a dyn OutboundPolicyPort,
    ) -> Self {
        Self { resolver, policy }
    }

    pub(crate) fn is_current(
        &self,
        authorization: ProviderHttpConnectionAuthorization,
        profile: &ProviderHttpProfile,
    ) -> bool {
        authorization.is_current(
            Instant::now(),
            profile.timeouts().max_resolution_age(),
            self.resolver,
            self.policy,
        )
    }

    pub(crate) fn ensure_current(
        &self,
        authorization: ProviderHttpConnectionAuthorization,
        profile: &ProviderHttpProfile,
    ) -> Result<(), ProviderHttpError> {
        if self.is_current(authorization, profile) {
            Ok(())
        } else {
            Err(ProviderHttpError::with_phase(
                ProviderHttpErrorCode::OutboundDenied,
                ProviderHttpPhase::Resolution,
            ))
        }
    }
}

#[derive(Clone)]
pub(crate) struct ProviderHttpWriteDenial {
    error: Arc<Mutex<Option<ProviderHttpError>>>,
}

impl ProviderHttpWriteDenial {
    fn new() -> Self {
        Self {
            error: Arc::new(Mutex::new(None)),
        }
    }

    fn record(&self, error: ProviderHttpError) {
        let mut slot = lock_write_denial(&self.error);
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    pub(crate) fn error(&self) -> Option<ProviderHttpError> {
        *lock_write_denial(&self.error)
    }

    pub(crate) fn project(&self, fallback: ProviderHttpError) -> ProviderHttpError {
        self.error().unwrap_or(fallback)
    }

    pub(crate) fn clear(&self) {
        *lock_write_denial(&self.error) = None;
    }
}

pub(crate) struct ProviderHttpWriteAuthorization {
    authorization: ProviderHttpConnectionAuthorization,
    resolver: Arc<dyn BoundedResolver>,
    policy: Arc<dyn OutboundPolicyPort>,
    max_age: Duration,
    phase: ProviderHttpPhase,
    denial: ProviderHttpWriteDenial,
    marker: Option<ProviderTransmissionMarker>,
}

impl ProviderHttpWriteAuthorization {
    pub(crate) fn new(
        authorization: ProviderHttpConnectionAuthorization,
        resolver: Arc<dyn BoundedResolver>,
        policy: Arc<dyn OutboundPolicyPort>,
        max_age: Duration,
        phase: ProviderHttpPhase,
    ) -> Self {
        Self {
            authorization,
            resolver,
            policy,
            max_age,
            phase,
            denial: ProviderHttpWriteDenial::new(),
            marker: None,
        }
    }

    pub(crate) fn set_phase(&mut self, phase: ProviderHttpPhase) {
        self.phase = phase;
    }

    pub(crate) fn bind_transmission(&mut self, marker: ProviderTransmissionMarker) {
        self.marker = Some(marker);
    }

    pub(crate) fn denial(&self) -> ProviderHttpWriteDenial {
        self.denial.clone()
    }

    fn ensure_current(&self) -> io::Result<()> {
        if self.authorization.is_current(
            Instant::now(),
            self.max_age,
            self.resolver.as_ref(),
            self.policy.as_ref(),
        ) {
            return Ok(());
        }
        let error =
            ProviderHttpError::with_phase(ProviderHttpErrorCode::OutboundDenied, self.phase);
        self.denial.record(error);
        if let Some(marker) = self.marker() {
            marker.close();
        }
        Err(write_denied_error())
    }

    fn marker(&self) -> Option<ProviderTransmissionMarker> {
        self.marker.clone()
    }
}

pub(crate) struct ProviderHttpAuthorizedIo<T> {
    stream: T,
    authorization: ProviderHttpWriteAuthorization,
}

impl<T> ProviderHttpAuthorizedIo<T> {
    pub(crate) const fn new(stream: T, authorization: ProviderHttpWriteAuthorization) -> Self {
        Self {
            stream,
            authorization,
        }
    }

    pub(crate) fn authorization_mut(&mut self) -> &mut ProviderHttpWriteAuthorization {
        &mut self.authorization
    }

    pub(crate) fn denial(&self) -> ProviderHttpWriteDenial {
        self.authorization.denial()
    }
}

impl<T> AsyncRead for ProviderHttpAuthorizedIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl<T> AsyncWrite for ProviderHttpAuthorizedIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.authorization.ensure_current() {
            return Poll::Ready(Err(error));
        }
        let marker = self.authorization.marker();
        let result = poll_scalar_write(&mut self.stream, context, buffer, marker.as_ref());
        finish_marked_write(marker.as_ref(), &result);
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.authorization.ensure_current() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.authorization.ensure_current() {
            return Poll::Ready(Err(error));
        }
        let marker = self.authorization.marker();
        let result = poll_vectored_write(&mut self.stream, context, buffers, marker.as_ref());
        finish_marked_write(marker.as_ref(), &result);
        result
    }
}

fn poll_scalar_write<T>(
    stream: &mut T,
    context: &mut Context<'_>,
    buffer: &[u8],
    marker: Option<&ProviderTransmissionMarker>,
) -> Poll<io::Result<usize>>
where
    T: AsyncWrite + Unpin,
{
    match marker {
        Some(marker) => {
            let _guard = match marker.write_guard() {
                Ok(guard) => guard,
                Err(error) => return Poll::Ready(Err(error)),
            };
            Pin::new(stream).poll_write(context, buffer)
        }
        None => Pin::new(stream).poll_write(context, buffer),
    }
}

fn poll_vectored_write<T>(
    stream: &mut T,
    context: &mut Context<'_>,
    buffers: &[io::IoSlice<'_>],
    marker: Option<&ProviderTransmissionMarker>,
) -> Poll<io::Result<usize>>
where
    T: AsyncWrite + Unpin,
{
    match marker {
        Some(marker) => {
            let _guard = match marker.write_guard() {
                Ok(guard) => guard,
                Err(error) => return Poll::Ready(Err(error)),
            };
            Pin::new(stream).poll_write_vectored(context, buffers)
        }
        None => Pin::new(stream).poll_write_vectored(context, buffers),
    }
}

fn finish_marked_write(
    marker: Option<&ProviderTransmissionMarker>,
    result: &Poll<io::Result<usize>>,
) {
    if let Some(marker) = marker {
        marker.finish_write(result);
    }
}

fn lock_write_denial(
    denial: &Mutex<Option<ProviderHttpError>>,
) -> MutexGuard<'_, Option<ProviderHttpError>> {
    match denial.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn write_denied_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "provider outbound authorization rejected",
    )
}

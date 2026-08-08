// crates/optional/ariadnion-provider-http/src/exchange.rs - Physical provider HTTP exchanges for Ariadnion.
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

//! One-shot request dispatch on an already verified physical connection.

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_provider_sdk::{ProviderAttemptEvidence, ProviderTransmission};

use crate::config::{ProviderHttpLimits, ProviderHttpProfile, ProviderHttpTimeouts};
use crate::connector::{ProviderHttpDirectConnection, RequestBody};
use crate::error::{ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase};
use crate::request::{ProviderHttpRequest, build_request};
use crate::response::ProviderHttpResponse;
use crate::timeout::run_exchange_phase;

/// A crate-owned exchange bound to one verified physical HTTP/1 connection.
pub(crate) struct ProviderHttpExchange {
    connection: Option<ProviderHttpDirectConnection>,
    profile: ProviderHttpProfile,
}

impl ProviderHttpExchange {
    /// Binds a checked profile to an established physical connection.
    ///
    /// Profiles for the same canonical host, port, trust roots, and proxy may
    /// apply different request and response limits. The executing profile is
    /// authoritative for those execution-only limits.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-origin failure when the connection was
    /// established for a different canonical host, port, trust profile, or
    /// proxy boundary.
    pub(crate) fn from_connection(
        connection: ProviderHttpDirectConnection,
        profile: ProviderHttpProfile,
    ) -> Result<Self, ProviderHttpError> {
        if !connection.matches_origin(&profile) {
            return Err(ProviderHttpError::new(ProviderHttpErrorCode::InvalidOrigin));
        }
        connection.apply_execution_limits(profile.limits());
        Ok(Self {
            connection: Some(connection),
            profile,
        })
    }

    /// Sends one fixed-profile request and returns its pull-driven response.
    ///
    /// The request context is checked before sender readiness and dispatch. An
    /// attempt-local child context propagates parent cancellation without ever
    /// cancelling the parent. Dropping an unpolled future leaves this known-idle
    /// exchange untouched. Once polling acquires the connection, dropping the
    /// future aborts that physical connection. This function performs no retry,
    /// redirect, routing, or connection pooling.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted failure for inactive context, request framing,
    /// sender readiness, transport, or response-head conversion failures.
    pub(crate) async fn execute(
        &mut self,
        context: &RequestContext,
        request: ProviderHttpRequest,
    ) -> Result<ProviderHttpResponse, ProviderHttpError> {
        let method = self.profile.method();
        let (mut attempt, request) = self.start_attempt(context, request)?;
        let timeouts = self.profile.timeouts();
        let response = wait_for_response(&mut attempt, request, timeouts).await?;
        accept_response(response, attempt, timeouts, self.profile.limits(), method)
    }

    fn start_attempt(
        &mut self,
        context: &RequestContext,
        request: ProviderHttpRequest,
    ) -> Result<(ProviderHttpAttemptOwner, http::Request<RequestBody>), ProviderHttpError> {
        check_context(context)?;
        let request = build_request(&self.profile, request)?;
        let connection = self
            .connection
            .take()
            .ok_or_else(response_transport_error)?;
        Ok((ProviderHttpAttemptOwner::new(connection, context), request))
    }
}

pub(crate) struct ProviderHttpAttemptOwner {
    connection: Option<ProviderHttpDirectConnection>,
    context: RequestContext,
    cancel_on_drop: bool,
}

impl ProviderHttpAttemptOwner {
    fn new(connection: ProviderHttpDirectConnection, parent: &RequestContext) -> Self {
        Self {
            connection: Some(connection),
            context: child_context(parent),
            cancel_on_drop: true,
        }
    }

    pub(crate) const fn context(&self) -> &RequestContext {
        &self.context
    }

    fn connection_mut(&mut self) -> Result<&mut ProviderHttpDirectConnection, ProviderHttpError> {
        self.connection
            .as_mut()
            .ok_or_else(response_transport_error)
    }

    fn evidence(&self) -> Result<ProviderAttemptEvidence, ProviderHttpError> {
        self.connection
            .as_ref()
            .map(ProviderHttpDirectConnection::evidence)
            .ok_or_else(response_transport_error)
    }

    pub(crate) fn into_parts(
        mut self,
    ) -> Result<(ProviderHttpDirectConnection, RequestContext), ProviderHttpError> {
        let connection = self
            .connection
            .take()
            .ok_or_else(response_transport_error)?;
        let context = self.context.clone();
        self.cancel_on_drop = false;
        Ok((connection, context))
    }
}

impl Drop for ProviderHttpAttemptOwner {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.context.cancellation().cancel();
            let _connection = self.connection.take();
        }
    }
}

async fn dispatch_request(
    connection: &mut ProviderHttpDirectConnection,
    request: http::Request<RequestBody>,
) -> Result<http::Response<hyper::body::Incoming>, ProviderHttpError> {
    if let Err(error) = connection.sender_mut().ready().await {
        return Err(project_dispatch_error(
            connection,
            &error,
            ProviderHttpPhase::RequestHeaders,
        ));
    }
    connection
        .sender_mut()
        .send_request(request)
        .await
        .map_err(|error| {
            project_dispatch_error(connection, &error, ProviderHttpPhase::ResponseHeaders)
        })
}

async fn wait_for_response(
    attempt: &mut ProviderHttpAttemptOwner,
    request: http::Request<RequestBody>,
    timeouts: ProviderHttpTimeouts,
) -> Result<http::Response<hyper::body::Incoming>, ProviderHttpError> {
    let attempt_context = attempt.context().clone();
    let dispatch = dispatch_request(attempt.connection_mut()?, request);
    run_exchange_phase(
        &attempt_context,
        timeouts.response_headers(),
        timeouts.cancellation_poll(),
        dispatch,
    )
    .await
    .map_err(response_phase_error)?
}

fn accept_response(
    response: http::Response<hyper::body::Incoming>,
    attempt: ProviderHttpAttemptOwner,
    timeouts: ProviderHttpTimeouts,
    limits: ProviderHttpLimits,
    method: crate::config::ProviderHttpMethod,
) -> Result<ProviderHttpResponse, ProviderHttpError> {
    let evidence = attempt.evidence()?;
    mark_response_observed(&evidence)?;
    let response = ProviderHttpResponse::from_hyper(response, attempt, timeouts, limits, method)?;
    evidence
        .mark_downstream_delivery_started()
        .map_err(|_| response_transport_error())?;
    Ok(response)
}

fn child_context(parent: &RequestContext) -> RequestContext {
    RequestContext::new(
        parent.request_id().clone(),
        parent.trace_id().clone(),
        parent.principal().cloned(),
        parent.deadline(),
        parent.cancellation().child(),
    )
}

fn check_context(context: &RequestContext) -> Result<(), ProviderHttpError> {
    context.check_active().map_err(|error| {
        let code = if error.code() == ErrorCode::Cancelled {
            ProviderHttpErrorCode::Cancelled
        } else {
            ProviderHttpErrorCode::DeadlineExceeded
        };
        ProviderHttpError::with_phase(code, ProviderHttpPhase::RequestHeaders)
    })
}

fn mark_response_observed(evidence: &ProviderAttemptEvidence) -> Result<(), ProviderHttpError> {
    let progress = evidence.progress();
    if progress.transmission() != ProviderTransmission::Committed
        || !progress.upstream_response_started()
    {
        return Err(response_transport_error());
    }
    Ok(())
}

fn project_dispatch_error(
    connection: &ProviderHttpDirectConnection,
    error: &hyper::Error,
    fallback_phase: ProviderHttpPhase,
) -> ProviderHttpError {
    if connection.response_limit_observed() {
        return ProviderHttpError::with_phase(
            ProviderHttpErrorCode::ResponseLimit,
            ProviderHttpPhase::ResponseHeaders,
        );
    }
    if connection.response_protocol_observed() || error.is_parse() {
        return ProviderHttpError::with_phase(
            ProviderHttpErrorCode::ProtocolViolation,
            ProviderHttpPhase::ResponseHeaders,
        );
    }
    ProviderHttpError::with_phase(ProviderHttpErrorCode::RequestFailed, fallback_phase)
}

const fn response_transport_error() -> ProviderHttpError {
    ProviderHttpError::with_phase(
        ProviderHttpErrorCode::RequestFailed,
        ProviderHttpPhase::ResponseHeaders,
    )
}

const fn response_phase_error(code: ProviderHttpErrorCode) -> ProviderHttpError {
    ProviderHttpError::with_phase(code, ProviderHttpPhase::ResponseHeaders)
}

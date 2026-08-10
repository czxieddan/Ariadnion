// crates/optional/ariadnion-provider-dispatch/src/dispatch.rs - Single-attempt provider coordination for Ariadnion.
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
//
//! Admission and execution of one physical provider attempt.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_api_dispatch::{
    BoxServiceDispatchFuture, ServiceDispatchOutcome, ServiceDispatchPort,
};
use ariadnion_api_domain::{
    ApiDomainError, ChatServiceRequest, ModelSelector, ResponseMode, ServiceRequest,
    ServiceResponse, TextServiceRequest,
};
use ariadnion_core::{AttemptId, RequestContext};
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;
use ariadnion_provider_sdk::{
    ProviderAttempt, ProviderAttemptOutcome, ProviderCapability, ProviderDescriptor,
    ProviderModelId, ProviderPort,
};

use crate::error::{
    internal_error, project_provider_failure, resource_exhausted_error, unavailable_error,
};
use crate::stream::{RelayManager, RelayPermit};

/// Resolves one bounded public model selector to one checked provider model.
pub trait ProviderModelResolverPort: Send + Sync {
    /// Resolves a provider-neutral selector without changing its ownership.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted service error when the selector has no safe
    /// mapping or the resolver cannot complete bounded work.
    fn resolve_model(&self, selector: &ModelSelector) -> Result<ProviderModelId, ApiDomainError>;
}

/// Issues immutable identities for physical provider calls.
pub trait AttemptIdIssuerPort: Send + Sync {
    /// Issues one checked identity for the next admitted physical call.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted service error when an identity cannot be
    /// issued. The dispatcher performs no provider call after this failure.
    fn issue_attempt_id(&self) -> Result<AttemptId, ApiDomainError>;
}

/// Executes one admitted provider attempt without retry or failover.
///
/// The dispatcher holds exactly one resolver, issuer, and provider port. It
/// retains no request body, authentication evidence, or provider diagnostic
/// after the returned future or stream relay completes. Each instance admits
/// at most 64 concurrent blocking relays; excess stream requests fail before
/// attempt identity issuance or provider work. Dropping the dispatcher cancels
/// and joins every retained relay before returning.
pub struct ProviderDispatcher {
    // Rust drops fields in declaration order; relay shutdown must precede the
    // collaborator Arcs that may own provider-side resources.
    relay_manager: RelayManager,
    resolver: Arc<dyn ProviderModelResolverPort>,
    issuer: Arc<dyn AttemptIdIssuerPort>,
    provider: Arc<dyn ProviderPort>,
}

impl ProviderDispatcher {
    /// Creates a dispatcher for exactly one provider implementation.
    ///
    /// The resolver, attempt issuer, and provider are shared for the lifetime
    /// of this dispatcher. A new independent fixed relay budget is created for
    /// the instance; no asynchronous runtime or global registry is required.
    #[must_use]
    pub fn new(
        resolver: Arc<dyn ProviderModelResolverPort>,
        issuer: Arc<dyn AttemptIdIssuerPort>,
        provider: Arc<dyn ProviderPort>,
    ) -> Self {
        Self {
            relay_manager: RelayManager::new(),
            resolver,
            issuer,
            provider,
        }
    }

    async fn dispatch_once(
        &self,
        request: ServiceRequest,
        evidence: &AuthenticatedPrincipalEvidence,
        context: &RequestContext,
    ) -> Result<ServiceDispatchOutcome, ApiDomainError> {
        let PreparedAttempt {
            kind,
            attempt,
            relay_permit,
        } = self.prepare_attempt(request, evidence, context)?;
        let attempt_context = attempt.context().clone();
        self.relay_manager.check_healthy()?;
        let outcome = self.provider.call(attempt).await;
        project_outcome(
            outcome,
            kind,
            &attempt_context,
            relay_permit,
            &self.relay_manager,
        )
    }

    fn prepare_attempt(
        &self,
        request: ServiceRequest,
        evidence: &AuthenticatedPrincipalEvidence,
        context: &RequestContext,
    ) -> Result<PreparedAttempt, ApiDomainError> {
        validate_authenticated_context(evidence, context)?;
        let (kind, mode, model) = self.resolve_admitted_model(&request, context)?;
        context.check_active().map_err(ApiDomainError::from)?;
        let relay_permit = self.reserve_relay(mode)?;
        context.check_active().map_err(ApiDomainError::from)?;
        let attempt_id = self.issue_checked_attempt_id()?;
        context.check_active().map_err(ApiDomainError::from)?;
        let attempt = ProviderAttempt::new(attempt_id, model, request, context);
        Ok(PreparedAttempt {
            kind,
            attempt,
            relay_permit,
        })
    }

    fn issue_checked_attempt_id(&self) -> Result<AttemptId, ApiDomainError> {
        self.relay_manager.check_healthy()?;
        self.issuer.issue_attempt_id()
    }

    fn resolve_admitted_model(
        &self,
        request: &ServiceRequest,
        context: &RequestContext,
    ) -> Result<(ServiceKind, ResponseMode, ProviderModelId), ApiDomainError> {
        let (kind, mode, model) = {
            let admission = RequestAdmission::from_request(request)?;
            let model = self.resolver.resolve_model(admission.selector)?;
            context.check_active().map_err(ApiDomainError::from)?;
            validate_provider(self.provider.descriptor(), admission, &model)?;
            (admission.kind, admission.mode, model)
        };
        Ok((kind, mode, model))
    }

    fn reserve_relay(&self, mode: ResponseMode) -> Result<Option<RelayPermit>, ApiDomainError> {
        match mode {
            ResponseMode::Complete => Ok(None),
            ResponseMode::Stream => self.relay_manager.try_acquire().map(Some),
            _ => Err(internal_error()),
        }
    }
}

impl Debug for ProviderDispatcher {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderDispatcher(<redacted>)")
    }
}

impl ServiceDispatchPort for ProviderDispatcher {
    fn dispatch<'a>(
        &'a self,
        request: ServiceRequest,
        evidence: &'a AuthenticatedPrincipalEvidence,
        context: &'a RequestContext,
    ) -> BoxServiceDispatchFuture<'a, Result<ServiceDispatchOutcome, ApiDomainError>> {
        Box::pin(async move { self.dispatch_once(request, evidence, context).await })
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ServiceKind {
    Text,
    Chat,
}

struct PreparedAttempt {
    kind: ServiceKind,
    attempt: ProviderAttempt,
    relay_permit: Option<RelayPermit>,
}

#[derive(Clone, Copy)]
struct RequestAdmission<'a> {
    kind: ServiceKind,
    selector: &'a ModelSelector,
    mode: ResponseMode,
    bounded_bytes: usize,
}

impl<'a> RequestAdmission<'a> {
    fn from_request(request: &'a ServiceRequest) -> Result<Self, ApiDomainError> {
        match request {
            ServiceRequest::Text(request) => text_admission(request),
            ServiceRequest::Chat(request) => chat_admission(request),
            _ => Err(internal_error()),
        }
    }
}

fn validate_authenticated_context(
    evidence: &AuthenticatedPrincipalEvidence,
    context: &RequestContext,
) -> Result<(), ApiDomainError> {
    context.check_active().map_err(ApiDomainError::from)?;
    let principal = context.principal().ok_or_else(internal_error)?;
    if principal.tenant_id() != evidence.tenant_id()
        || principal.principal_id() != evidence.principal_id()
    {
        return Err(internal_error());
    }
    Ok(())
}

fn text_admission(request: &TextServiceRequest) -> Result<RequestAdmission<'_>, ApiDomainError> {
    let bounded_bytes = checked_byte_sum(&[
        request.model().as_str().len(),
        request.input().as_str().len(),
        idempotency_bytes(request.idempotency_key()),
    ])?;
    Ok(RequestAdmission {
        kind: ServiceKind::Text,
        selector: request.model(),
        mode: request.response_mode(),
        bounded_bytes,
    })
}

fn chat_admission(request: &ChatServiceRequest) -> Result<RequestAdmission<'_>, ApiDomainError> {
    let bounded_bytes = checked_byte_sum(&[
        request.model().as_str().len(),
        request.messages().encoded_bytes(),
        request.messages().len(),
        idempotency_bytes(request.idempotency_key()),
    ])?;
    Ok(RequestAdmission {
        kind: ServiceKind::Chat,
        selector: request.model(),
        mode: request.response_mode(),
        bounded_bytes,
    })
}

fn idempotency_bytes(key: Option<&ariadnion_api_domain::IdempotencyKey>) -> usize {
    key.map_or(0, |value| value.as_str().len())
}

fn checked_byte_sum(values: &[usize]) -> Result<usize, ApiDomainError> {
    let mut total = 0_usize;
    for value in values {
        total = total.checked_add(*value).ok_or_else(internal_error)?;
    }
    Ok(total)
}

fn validate_provider(
    descriptor: &ProviderDescriptor,
    admission: RequestAdmission<'_>,
    model: &ProviderModelId,
) -> Result<(), ApiDomainError> {
    validate_capabilities(descriptor, admission.mode)?;
    let request_bytes = admission
        .bounded_bytes
        .checked_add(model.as_str().len())
        .ok_or_else(resource_exhausted_error)?;
    if request_bytes > descriptor.limits().max_request_bytes() {
        return Err(resource_exhausted_error());
    }
    Ok(())
}

fn validate_capabilities(
    descriptor: &ProviderDescriptor,
    mode: ResponseMode,
) -> Result<(), ApiDomainError> {
    let capabilities = descriptor.capabilities();
    if !capabilities.contains(ProviderCapability::TextGeneration) {
        return Err(unavailable_error());
    }
    if matches!(mode, ResponseMode::Stream)
        && !capabilities.contains(ProviderCapability::TextStreaming)
    {
        return Err(unavailable_error());
    }
    Ok(())
}

fn project_outcome(
    outcome: ProviderAttemptOutcome,
    kind: ServiceKind,
    attempt_context: &RequestContext,
    relay_permit: Option<RelayPermit>,
    relay_manager: &RelayManager,
) -> Result<ServiceDispatchOutcome, ApiDomainError> {
    match (outcome, relay_permit) {
        (ProviderAttemptOutcome::Complete { response, .. }, None) => {
            project_complete_response(kind, response, attempt_context)
        }
        (ProviderAttemptOutcome::Stream { stream, .. }, Some(permit)) => {
            attempt_context
                .check_active()
                .map_err(ApiDomainError::from)?;
            relay_manager
                .start(stream, kind, attempt_context.clone(), permit)
                .map(ServiceDispatchOutcome::Stream)
        }
        (ProviderAttemptOutcome::Failed { failure, .. }, _) => {
            Err(project_provider_failure(failure))
        }
        _ => Err(internal_error()),
    }
}

fn project_complete_response(
    kind: ServiceKind,
    response: ServiceResponse,
    attempt_context: &RequestContext,
) -> Result<ServiceDispatchOutcome, ApiDomainError> {
    attempt_context
        .check_active()
        .map_err(ApiDomainError::from)?;
    if !response_matches(kind, &response) {
        return Err(internal_error());
    }
    Ok(ServiceDispatchOutcome::Complete(response))
}

fn response_matches(kind: ServiceKind, response: &ServiceResponse) -> bool {
    matches!(
        (kind, response),
        (ServiceKind::Text, ServiceResponse::Text(_))
            | (ServiceKind::Chat, ServiceResponse::Chat(_))
    )
}

// crates/optional/ariadnion-routing-coordinator/src/engine/admission.rs - Routing admission projection for Ariadnion.
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
//

use ariadnion_account_budget::{
    BudgetContext, CurrencyCode as BudgetCurrency, Money, ReservationRequest,
};
use ariadnion_model_pricing::PriceQuote;
use ariadnion_rate_limit::{
    AccountLimitId, AccountLimitKey, AdmissionRequest, LimitKey, ModelLimitId, TenantLimitId,
};
use ariadnion_routing_admission::{
    RoutingAdmissionCoordinator, RoutingAdmissionError, RoutingAdmissionErrorCode,
    RoutingAdmissionRequest,
};

use super::CandidateState;
use crate::{
    AdmissionRefusalScope, CandidateExclusion, CoordinationRequest, CoordinatorError,
    CoordinatorErrorCode, bound_exclusions,
};

pub(super) fn admit(
    coordinator: &RoutingAdmissionCoordinator,
    request: &CoordinationRequest,
    selected: &CandidateState<'_>,
    exclusions: &[CandidateExclusion],
) -> Result<ariadnion_routing_admission::RoutingAdmissionLease, CoordinatorError> {
    let quote = selected
        .quote
        .as_ref()
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::PricingUnavailable))?;
    let rate = rate_request(request, selected)?;
    let budget = budget_request(request, selected, quote)?;
    let times = request.admission().times();
    coordinator
        .admit(RoutingAdmissionRequest::new(
            rate,
            budget,
            times.monotonic_now(),
            times.budget_now(),
        ))
        .map_err(|error| map_admission_error(error, exclusions))
}

fn rate_request(
    request: &CoordinationRequest,
    selected: &CandidateState<'_>,
) -> Result<AdmissionRequest, CoordinatorError> {
    let tenant = request.context().tenant_id();
    let tenant_limit = TenantLimitId::parse(tenant.as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let account_limit = AccountLimitId::parse(selected.source.account_id().as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let account_key = LimitKey::Account(AccountLimitKey::new(tenant_limit.clone(), account_limit));
    let rate_keys = vec![
        LimitKey::Tenant(tenant_limit),
        LimitKey::Model(
            ModelLimitId::parse(request.context().model().as_str())
                .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?,
        ),
        account_key,
    ];
    AdmissionRequest::new(rate_keys, request.admission().units())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))
}

fn budget_request(
    request: &CoordinationRequest,
    selected: &CandidateState<'_>,
    quote: &PriceQuote,
) -> Result<ReservationRequest, CoordinatorError> {
    let currency = BudgetCurrency::parse(quote.currency().as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    ReservationRequest::new(
        request.admission().reservation_id().clone(),
        BudgetContext::new(
            request.context().tenant_id().clone(),
            request.admission().group_id().cloned(),
            selected.source.account_id().clone(),
        ),
        Money::new(currency, quote.total().minor_units()),
        request.admission().times().budget_expires_at(),
    )
    .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))
}

fn map_admission_error(
    value: RoutingAdmissionError,
    exclusions: &[CandidateExclusion],
) -> CoordinatorError {
    let mut error =
        CoordinatorError::with_retry_after(admission_error_code(value.code()), value.retry_after());
    error.admission_scope = Some(
        value
            .refusal_scope()
            .unwrap_or(AdmissionRefusalScope::Request),
    );
    let (bounded, truncated) = bound_exclusions(exclusions.to_vec());
    error.exclusions = bounded;
    error.exclusions_truncated = truncated;
    error
}

fn admission_error_code(code: RoutingAdmissionErrorCode) -> CoordinatorErrorCode {
    match code {
        RoutingAdmissionErrorCode::RateLimited => CoordinatorErrorCode::RateLimited,
        RoutingAdmissionErrorCode::ConcurrencyLimited => CoordinatorErrorCode::ConcurrencyLimited,
        RoutingAdmissionErrorCode::BudgetRejected => CoordinatorErrorCode::BudgetRejected,
        RoutingAdmissionErrorCode::TenantMismatch => CoordinatorErrorCode::TenantMismatch,
        RoutingAdmissionErrorCode::InvalidArgument => CoordinatorErrorCode::InvalidArgument,
        _ => CoordinatorErrorCode::AdmissionUnavailable,
    }
}

// crates/optional/ariadnion-routing-coordinator/src/admission_assembly.rs - Admission assembly for Ariadnion routing.
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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ariadnion_account_budget::{BudgetBook, BudgetGeneration, BudgetPolicySnapshot};
use ariadnion_account_pool::{CandidateMetadata, CandidateSnapshot};
use ariadnion_rate_limit::{
    AccountLimitId, AccountLimitKey, AdmissionController, AdmissionPolicySet, ConcurrencyRule,
    LimitDimension, LimitKey, LimitPolicy, MAX_POLICIES, MonotonicTime, TenantLimitId,
};
use ariadnion_routing_admission::RoutingAdmissionCoordinator;

use crate::{CoordinatorError, CoordinatorErrorCode, MAX_CANDIDATES, RoutingCoordinator};

#[derive(Clone)]
pub(super) struct CandidateSnapshotBinding {
    authoritative: Arc<CandidateSnapshot>,
}

impl CandidateSnapshotBinding {
    pub(super) fn new(snapshot: &Arc<CandidateSnapshot>) -> Self {
        Self {
            authoritative: Arc::clone(snapshot),
        }
    }

    pub(super) fn matches(&self, snapshot: &CandidateSnapshot) -> bool {
        self.authoritative.id() == snapshot.id()
            && self.authoritative.version() == snapshot.version()
            && snapshot
                .candidates()
                .iter()
                .all(|candidate| self.contains(candidate))
    }

    fn contains(&self, candidate: &CandidateMetadata) -> bool {
        self.authoritative
            .candidates()
            .binary_search_by(|authoritative| authoritative.id().cmp(candidate.id()))
            .is_ok_and(|index| self.authoritative.candidates()[index] == *candidate)
    }
}

/// Owned inputs for assembling one process-local admission coordinator.
///
/// `configured_policies` may contain only tenant and model dimensions. User and
/// API-key policies are rejected until request admission carries authenticated
/// bindings for those dimensions. Caller-supplied account policies are rejected
/// because account concurrency is derived only from the persisted, secret-free
/// metadata carried by `candidate_snapshot`. The exact snapshot generation is
/// retained by the resulting coordinator. The initial clock seeds rate windows,
/// while `budget` remains the caller-owned budget state moved into the resulting
/// coordinator.
pub struct RoutingAdmissionAssembly {
    configured_policies: Vec<LimitPolicy>,
    candidate_snapshot: Arc<CandidateSnapshot>,
    account_lease_duration: Duration,
    initial_now: MonotonicTime,
    budget: BudgetAssembly,
}

enum BudgetAssembly {
    Legacy(BudgetBook),
    Published {
        snapshot: BudgetPolicySnapshot,
        expected_generation: BudgetGeneration,
    },
}

impl RoutingAdmissionAssembly {
    /// Creates side-effect-free assembly inputs using an explicit initial clock.
    ///
    /// Candidates normally come from one authoritative account-pool snapshot.
    /// Tenant-unbound candidates or candidates without persisted concurrency fail
    /// closed during assembly. Construction performs no validation or allocation
    /// beyond moving the supplied values; validation occurs in
    /// [`build_routing_admission_coordinator`].
    #[must_use]
    pub fn new(
        configured_policies: Vec<LimitPolicy>,
        candidate_snapshot: Arc<CandidateSnapshot>,
        account_lease_duration: Duration,
        initial_now: MonotonicTime,
        budget: BudgetBook,
    ) -> Self {
        Self {
            configured_policies,
            candidate_snapshot,
            account_lease_duration,
            initial_now,
            budget: BudgetAssembly::Legacy(budget),
        }
    }

    /// Creates assembly inputs over one immutable published budget snapshot.
    ///
    /// The expected generation is checked again by
    /// [`build_routing_admission_coordinator`]. A stale or mismatched snapshot
    /// therefore fails before any rate or account policy is allocated. The
    /// snapshot's shared budget ledger is retained by the resulting admission
    /// coordinator; policy state is never reconstructed or copied.
    #[must_use]
    pub fn new_with_budget_snapshot(
        configured_policies: Vec<LimitPolicy>,
        candidate_snapshot: Arc<CandidateSnapshot>,
        account_lease_duration: Duration,
        initial_now: MonotonicTime,
        budget_snapshot: BudgetPolicySnapshot,
        expected_budget_generation: BudgetGeneration,
    ) -> Self {
        Self {
            configured_policies,
            candidate_snapshot,
            account_lease_duration,
            initial_now,
            budget: BudgetAssembly::Published {
                snapshot: budget_snapshot,
                expected_generation: expected_budget_generation,
            },
        }
    }
}

/// Assembles a generation-bound coordinator with durable account concurrency.
///
/// Checks the combined bound before allocation, accepts only configured tenant
/// and model policies, owns the budget book, and performs no I/O. User and API-key
/// policies fail closed because request admission does not yet carry authenticated
/// bindings for those dimensions. Account policies are derived from candidate
/// metadata rather than accepted from the caller. Existing direct construction
/// remains compatible and there is no cancellation boundary. Candidate metadata,
/// policy keys, and budget state are never copied into errors. Request-time
/// coordination fails closed before admission if it receives a pool snapshot with
/// a different identity or version.
///
/// # Errors
///
/// Returns [`CoordinatorErrorCode::InvalidArgument`] for an oversized combined
/// set, a configured user, API-key, or account policy, duplicate configured
/// dimensions, malformed admission identities, or an invalid account lease
/// duration. Returns [`CoordinatorErrorCode::TenantMismatch`] for tenant-unbound
/// account metadata.
/// Returns [`CoordinatorErrorCode::StateUnavailable`] when persisted concurrency
/// is absent, account identities are duplicated, or bounded allocation fails.
pub fn build_routing_admission_coordinator(
    assembly: RoutingAdmissionAssembly,
) -> Result<RoutingCoordinator, CoordinatorError> {
    let RoutingAdmissionAssembly {
        mut configured_policies,
        candidate_snapshot,
        account_lease_duration,
        initial_now,
        budget,
    } = assembly;
    validate_policy_bounds(&configured_policies, candidate_snapshot.candidates().len())?;
    let (budget, budget_generation) = budget.into_shared()?;
    let account_policies = build_account_concurrency_policies(
        candidate_snapshot.candidates(),
        account_lease_duration,
    )?;
    configured_policies
        .try_reserve_exact(account_policies.len())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    configured_policies.extend(account_policies);
    let policies = AdmissionPolicySet::new(configured_policies)
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let rate = AdmissionController::new(policies, initial_now);
    let admission = RoutingAdmissionCoordinator::from_shared_budget(rate, budget);
    Ok(RoutingCoordinator::new_generation_bound(
        admission,
        &candidate_snapshot,
        budget_generation,
    ))
}

fn validate_policy_bounds(
    configured: &[LimitPolicy],
    candidate_count: usize,
) -> Result<(), CoordinatorError> {
    let combined_count = configured
        .len()
        .checked_add(candidate_count)
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    if combined_count > MAX_POLICIES
        || configured.iter().any(|policy| {
            !matches!(
                policy.key().dimension(),
                LimitDimension::Tenant | LimitDimension::Model
            )
        })
    {
        return Err(CoordinatorError::new(CoordinatorErrorCode::InvalidArgument));
    }
    Ok(())
}

impl BudgetAssembly {
    fn into_shared(self) -> Result<(Arc<BudgetBook>, Option<BudgetGeneration>), CoordinatorError> {
        match self {
            Self::Legacy(book) => Ok((Arc::new(book), None)),
            Self::Published {
                snapshot,
                expected_generation,
            } => {
                if snapshot.generation() != expected_generation {
                    return Err(CoordinatorError::new(
                        CoordinatorErrorCode::StateUnavailable,
                    ));
                }
                Ok((snapshot.shared_book(), Some(snapshot.generation())))
            }
        }
    }
}

/// Builds tenant-bound account concurrency policies from authoritative candidates.
///
/// The returned policies contain concurrency limits only. The routing admission
/// builder combines them with configured tenant and model policies. Every
/// candidate must carry the tenant and persisted account bound produced by account
/// import publication; incomplete metadata fails closed.
///
/// # Errors
/// Returns a stable error for oversized input, missing authoritative metadata,
/// duplicate tenant/account identities, malformed admission identities, or an
/// invalid lease duration.
pub fn build_account_concurrency_policies(
    candidates: &[CandidateMetadata],
    lease_duration: Duration,
) -> Result<Vec<LimitPolicy>, CoordinatorError> {
    if candidates.len() > MAX_CANDIDATES {
        return Err(CoordinatorError::new(CoordinatorErrorCode::InvalidArgument));
    }
    let mut policies = BTreeMap::new();
    for candidate in candidates {
        let (key, policy) = account_concurrency_policy(candidate, lease_duration)?;
        if policies.insert(key, policy).is_some() {
            return Err(CoordinatorError::new(
                CoordinatorErrorCode::StateUnavailable,
            ));
        }
    }
    Ok(policies.into_values().collect())
}

fn account_concurrency_policy(
    candidate: &CandidateMetadata,
    lease_duration: Duration,
) -> Result<(LimitKey, LimitPolicy), CoordinatorError> {
    let tenant = candidate
        .tenant_id()
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::TenantMismatch))?;
    let limit = candidate
        .max_concurrency()
        .ok_or_else(|| CoordinatorError::new(CoordinatorErrorCode::StateUnavailable))?;
    let tenant = TenantLimitId::parse(tenant.as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let account = AccountLimitId::parse(candidate.account_id().as_str())
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let key = LimitKey::Account(AccountLimitKey::new(tenant, account));
    let rule = ConcurrencyRule::new(limit, lease_duration)
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    let policy = LimitPolicy::new(key.clone(), None, Some(rule))
        .map_err(|_| CoordinatorError::new(CoordinatorErrorCode::InvalidArgument))?;
    Ok((key, policy))
}

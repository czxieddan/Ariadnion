// crates/optional/ariadnion-account-budget/src/lib.rs - Account budget contracts for Ariadnion.
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
//! Bounded account, group, and tenant budget policies with atomic reservations.
//!
//! [`BudgetBook`] is an in-process domain implementation. Persistence adapters
//! can apply the same commands transactionally while preserving reservation IDs
//! as idempotency keys. Money always carries a validated currency and integer
//! minor units; values from different currencies are never combined.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Mutex;

use ariadnion_account_domain::AccountId;
use ariadnion_core::TenantId;

/// Maximum number of policies in one budget book.
pub const MAX_POLICIES: usize = 4_096;
/// Maximum number of reservation identities retained for replay protection.
pub const MAX_RESERVATIONS: usize = 100_000;
const MAX_ID_BYTES: usize = 128;

/// Stable machine-readable failures returned by budget operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BudgetErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// A fixed collection bound would be exceeded.
    LimitExceeded,
    /// A policy identity is duplicated.
    DuplicatePolicy,
    /// Two policies govern the same scope and currency.
    DuplicateScopeCurrency,
    /// No policy applies to the reservation context and currency.
    NoApplicablePolicy,
    /// A hard budget would be exceeded.
    HardLimitExceeded,
    /// An arithmetic operation would overflow its integer representation.
    ArithmeticOverflow,
    /// A reservation identity was replayed with different immutable input.
    ReplayConflict,
    /// A reservation identity does not exist.
    ReservationNotFound,
    /// A finalized reservation cannot perform the requested transition.
    ReservationFinalized,
    /// A policy identity does not exist.
    PolicyNotFound,
    /// Internal atomic state is unavailable.
    StateUnavailable,
}

impl BudgetErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ACCOUNT_BUDGET_INVALID_ARGUMENT",
            Self::LimitExceeded => "ACCOUNT_BUDGET_LIMIT_EXCEEDED",
            Self::DuplicatePolicy => "ACCOUNT_BUDGET_DUPLICATE_POLICY",
            Self::DuplicateScopeCurrency => "ACCOUNT_BUDGET_DUPLICATE_SCOPE_CURRENCY",
            Self::NoApplicablePolicy => "ACCOUNT_BUDGET_NO_APPLICABLE_POLICY",
            Self::HardLimitExceeded => "ACCOUNT_BUDGET_HARD_LIMIT_EXCEEDED",
            Self::ArithmeticOverflow => "ACCOUNT_BUDGET_ARITHMETIC_OVERFLOW",
            Self::ReplayConflict => "ACCOUNT_BUDGET_REPLAY_CONFLICT",
            Self::ReservationNotFound => "ACCOUNT_BUDGET_RESERVATION_NOT_FOUND",
            Self::ReservationFinalized => "ACCOUNT_BUDGET_RESERVATION_FINALIZED",
            Self::PolicyNotFound => "ACCOUNT_BUDGET_POLICY_NOT_FOUND",
            Self::StateUnavailable => "ACCOUNT_BUDGET_STATE_UNAVAILABLE",
        }
    }
}

/// A redacted budget failure that retains no rejected identity or amount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetError {
    code: BudgetErrorCode,
}

impl BudgetError {
    const fn new(code: BudgetErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> BudgetErrorCode {
        self.code
    }
}

impl Display for BudgetError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for BudgetError {}

macro_rules! bounded_id {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses a non-empty bounded ASCII identity.
            ///
            /// # Errors
            /// Returns [`BudgetErrorCode::InvalidArgument`] when the identity is
            /// empty, exceeds 128 bytes, or contains a disallowed byte.
            pub fn parse(value: &str) -> Result<Self, BudgetError> {
                if !valid_id(value) {
                    return Err(error(BudgetErrorCode::InvalidArgument));
                }
                Ok(Self(value.into()))
            }

            /// Returns the validated identity.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("bytes", &self.as_str().len())
                    .finish_non_exhaustive()
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

bounded_id!(BudgetPolicyId, "A stable budget policy identity.");
bounded_id!(GroupId, "A stable tenant-local account group identity.");
bounded_id!(ReservationId, "A replay-safe budget reservation identity.");

/// A validated three-letter ISO-style currency code.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CurrencyCode(Box<str>);

impl CurrencyCode {
    /// Parses exactly three uppercase ASCII letters.
    ///
    /// # Errors
    /// Returns [`BudgetErrorCode::InvalidArgument`] for malformed codes.
    pub fn parse(value: &str) -> Result<Self, BudgetError> {
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(error(BudgetErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated currency code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for CurrencyCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CurrencyCode")
            .field(&self.0)
            .finish()
    }
}

impl Display for CurrencyCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A non-negative currency amount represented in integer minor units.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Money {
    currency: CurrencyCode,
    minor_units: u64,
}

impl Money {
    /// Creates a currency-safe integer amount.
    #[must_use]
    pub const fn new(currency: CurrencyCode, minor_units: u64) -> Self {
        Self {
            currency,
            minor_units,
        }
    }

    /// Returns the amount currency.
    #[must_use]
    pub const fn currency(&self) -> &CurrencyCode {
        &self.currency
    }

    /// Returns the amount in the currency's minor units.
    #[must_use]
    pub const fn minor_units(&self) -> u64 {
        self.minor_units
    }
}

/// A UTC Unix timestamp measured in whole seconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixTimeSeconds(u64);

impl UnixTimeSeconds {
    /// Creates a timestamp from seconds since the Unix epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The hierarchy level governed by a budget policy.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum BudgetScope {
    /// Every matching account in a tenant.
    Tenant {
        /// The governed tenant.
        tenant_id: TenantId,
    },
    /// Every matching account in a tenant-local group.
    Group {
        /// The governed tenant.
        tenant_id: TenantId,
        /// The governed group.
        group_id: GroupId,
    },
    /// One account in a tenant.
    Account {
        /// The governed tenant.
        tenant_id: TenantId,
        /// The governed account.
        account_id: AccountId,
    },
}

impl BudgetScope {
    /// Creates a tenant-level scope.
    #[must_use]
    pub const fn tenant(tenant_id: TenantId) -> Self {
        Self::Tenant { tenant_id }
    }

    /// Creates a tenant-local group scope.
    #[must_use]
    pub const fn group(tenant_id: TenantId, group_id: GroupId) -> Self {
        Self::Group {
            tenant_id,
            group_id,
        }
    }

    /// Creates a tenant-local account scope.
    #[must_use]
    pub const fn account(tenant_id: TenantId, account_id: AccountId) -> Self {
        Self::Account {
            tenant_id,
            account_id,
        }
    }

    fn matches(&self, context: &BudgetContext) -> bool {
        match self {
            Self::Tenant { tenant_id } => tenant_id == context.tenant_id(),
            Self::Group {
                tenant_id,
                group_id,
            } => tenant_id == context.tenant_id() && context.group_id() == Some(group_id),
            Self::Account {
                tenant_id,
                account_id,
            } => tenant_id == context.tenant_id() && account_id == context.account_id(),
        }
    }
}

/// Whether a policy rejects or only reports limit crossings.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Enforcement {
    /// Reject a reservation that would cross the limit.
    Hard,
    /// Accept a reservation and report that it crosses the limit.
    Soft,
}

/// An immutable budget policy for one scope and currency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetPolicy {
    id: BudgetPolicyId,
    scope: BudgetScope,
    limit: Money,
    enforcement: Enforcement,
}

impl BudgetPolicy {
    /// Creates a bounded policy with a positive limit.
    ///
    /// # Errors
    /// Returns [`BudgetErrorCode::InvalidArgument`] when the limit is zero.
    pub fn new(
        id: BudgetPolicyId,
        scope: BudgetScope,
        limit: Money,
        enforcement: Enforcement,
    ) -> Result<Self, BudgetError> {
        if limit.minor_units() == 0 {
            return Err(error(BudgetErrorCode::InvalidArgument));
        }
        Ok(Self {
            id,
            scope,
            limit,
            enforcement,
        })
    }

    /// Returns the stable policy identity.
    #[must_use]
    pub const fn id(&self) -> &BudgetPolicyId {
        &self.id
    }

    /// Returns the governed scope.
    #[must_use]
    pub const fn scope(&self) -> &BudgetScope {
        &self.scope
    }

    /// Returns the currency-specific limit.
    #[must_use]
    pub const fn limit(&self) -> &Money {
        &self.limit
    }

    /// Returns the policy enforcement behavior.
    #[must_use]
    pub const fn enforcement(&self) -> Enforcement {
        self.enforcement
    }
}

/// Tenant, optional group, and account identities for one charge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetContext {
    tenant_id: TenantId,
    group_id: Option<GroupId>,
    account_id: AccountId,
}

impl BudgetContext {
    /// Creates a validated budget context from typed identities.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        group_id: Option<GroupId>,
        account_id: AccountId,
    ) -> Self {
        Self {
            tenant_id,
            group_id,
            account_id,
        }
    }

    /// Returns the tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the optional group identity.
    #[must_use]
    pub const fn group_id(&self) -> Option<&GroupId> {
        self.group_id.as_ref()
    }

    /// Returns the account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

/// Immutable input used to create or replay a reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationRequest {
    id: ReservationId,
    context: BudgetContext,
    amount: Money,
    expires_at: UnixTimeSeconds,
}

impl ReservationRequest {
    /// Creates a positive reservation request.
    ///
    /// Expiry is compared with the caller-provided current time by
    /// [`BudgetBook::reserve`].
    ///
    /// # Errors
    /// Returns [`BudgetErrorCode::InvalidArgument`] when the amount is zero.
    pub fn new(
        id: ReservationId,
        context: BudgetContext,
        amount: Money,
        expires_at: UnixTimeSeconds,
    ) -> Result<Self, BudgetError> {
        if amount.minor_units() == 0 {
            return Err(error(BudgetErrorCode::InvalidArgument));
        }
        Ok(Self {
            id,
            context,
            amount,
            expires_at,
        })
    }

    /// Returns the reservation identity.
    #[must_use]
    pub const fn id(&self) -> &ReservationId {
        &self.id
    }

    /// Returns the scoped charge context.
    #[must_use]
    pub const fn context(&self) -> &BudgetContext {
        &self.context
    }

    /// Returns the reserved amount.
    #[must_use]
    pub const fn amount(&self) -> &Money {
        &self.amount
    }

    /// Returns the exclusive reservation expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimeSeconds {
        self.expires_at
    }
}

/// The lifecycle state of a retained reservation identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReservationState {
    /// Capacity is reserved but has not been consumed.
    Reserved,
    /// Capacity was converted to committed usage.
    Committed,
    /// Capacity was explicitly released.
    Released,
    /// Capacity was released at or after its expiry.
    Expired,
}

/// Stable result of a reservation or lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationReceipt {
    id: ReservationId,
    state: ReservationState,
    amount: Money,
    expires_at: UnixTimeSeconds,
    applied_policies: Box<[BudgetPolicyId]>,
    soft_limit_breaches: Box<[BudgetPolicyId]>,
}

impl ReservationReceipt {
    /// Returns the reservation identity.
    #[must_use]
    pub const fn id(&self) -> &ReservationId {
        &self.id
    }

    /// Returns the current reservation state.
    #[must_use]
    pub const fn state(&self) -> ReservationState {
        self.state
    }

    /// Returns the currency-safe reservation amount.
    #[must_use]
    pub const fn amount(&self) -> &Money {
        &self.amount
    }

    /// Returns the reservation expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimeSeconds {
        self.expires_at
    }

    /// Returns how many hierarchy policies were reserved atomically.
    #[must_use]
    pub const fn applied_policy_count(&self) -> usize {
        self.applied_policies.len()
    }

    /// Returns the policy identities applied atomically, in stable ID order.
    #[must_use]
    pub const fn applied_policy_ids(&self) -> &[BudgetPolicyId] {
        &self.applied_policies
    }

    /// Returns soft policies whose limits were crossed by the reservation.
    #[must_use]
    pub const fn soft_limit_breaches(&self) -> &[BudgetPolicyId] {
        &self.soft_limit_breaches
    }
}

/// An immutable usage view for one policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetUsage {
    policy_id: BudgetPolicyId,
    limit: Money,
    enforcement: Enforcement,
    reserved_minor_units: u64,
    committed_minor_units: u64,
}

impl BudgetUsage {
    /// Returns the policy identity.
    #[must_use]
    pub const fn policy_id(&self) -> &BudgetPolicyId {
        &self.policy_id
    }

    /// Returns the configured limit and currency.
    #[must_use]
    pub const fn limit(&self) -> &Money {
        &self.limit
    }

    /// Returns whether the limit is hard or soft.
    #[must_use]
    pub const fn enforcement(&self) -> Enforcement {
        self.enforcement
    }

    /// Returns currently reserved minor units.
    #[must_use]
    pub const fn reserved_minor_units(&self) -> u64 {
        self.reserved_minor_units
    }

    /// Returns committed minor units.
    #[must_use]
    pub const fn committed_minor_units(&self) -> u64 {
        self.committed_minor_units
    }
}

/// Summary of one bounded expiry pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiryReport {
    expired_count: usize,
}

impl ExpiryReport {
    /// Returns the number of reservations expired atomically.
    #[must_use]
    pub const fn expired_count(self) -> usize {
        self.expired_count
    }
}

#[derive(Clone, Debug)]
struct PolicyState {
    policy: BudgetPolicy,
    reserved: u64,
    committed: u64,
}

#[derive(Clone, Debug)]
struct ReservationRecord {
    request: ReservationRequest,
    state: ReservationState,
    applied_policies: Box<[BudgetPolicyId]>,
    soft_limit_breaches: Box<[BudgetPolicyId]>,
}

impl ReservationRecord {
    fn receipt(&self) -> ReservationReceipt {
        ReservationReceipt {
            id: self.request.id.clone(),
            state: self.state,
            amount: self.request.amount.clone(),
            expires_at: self.request.expires_at,
            applied_policies: self.applied_policies.clone(),
            soft_limit_breaches: self.soft_limit_breaches.clone(),
        }
    }
}

#[derive(Debug)]
struct BudgetState {
    policies: BTreeMap<BudgetPolicyId, PolicyState>,
    reservations: BTreeMap<ReservationId, ReservationRecord>,
}

/// Atomic in-process budget reservation and usage ledger.
///
/// All applicable account, group, and tenant policies are checked and updated
/// under one lock. Hard-limit failures make no state change. Completed IDs stay
/// retained so retries cannot recreate previously consumed capacity.
#[derive(Debug)]
pub struct BudgetBook {
    state: Mutex<BudgetState>,
}

impl BudgetBook {
    /// Builds a budget book from a bounded immutable policy set.
    ///
    /// # Errors
    /// Returns stable duplicate or bound failures before constructing state.
    pub fn new(policies: Vec<BudgetPolicy>) -> Result<Self, BudgetError> {
        validate_policy_count(policies.len())?;
        let mut identities = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        let mut states = BTreeMap::new();
        for policy in policies {
            validate_unique_policy(&policy, &mut identities, &mut scopes)?;
            states.insert(
                policy.id.clone(),
                PolicyState {
                    policy,
                    reserved: 0,
                    committed: 0,
                },
            );
        }
        Ok(Self {
            state: Mutex::new(BudgetState {
                policies: states,
                reservations: BTreeMap::new(),
            }),
        })
    }

    /// Atomically reserves all applicable hierarchy budgets.
    ///
    /// Replaying byte-equivalent typed input with the same active reservation
    /// identity returns the original receipt without charging twice. Reusing the
    /// identity for different input fails closed.
    ///
    /// # Errors
    /// Returns a stable failure for expired input, replay conflicts, missing
    /// policies, hard-limit crossings, arithmetic overflow, capacity exhaustion,
    /// or poisoned state.
    pub fn reserve(
        &self,
        request: ReservationRequest,
        now: UnixTimeSeconds,
    ) -> Result<ReservationReceipt, BudgetError> {
        let mut state = self.lock_state()?;
        expire_records(&mut state, now)?;
        if let Some(record) = state.reservations.get(request.id()) {
            return replay_reservation(record, &request);
        }
        validate_new_reservation(&state, &request, now)?;
        let policy_ids = applicable_policy_ids(&state, &request)?;
        let soft_breaches = validate_capacity(&state, &policy_ids, request.amount())?;
        reserve_capacity(&mut state, &policy_ids, request.amount().minor_units())?;
        let record = ReservationRecord {
            request,
            state: ReservationState::Reserved,
            applied_policies: policy_ids.into_boxed_slice(),
            soft_limit_breaches: soft_breaches.into_boxed_slice(),
        };
        let receipt = record.receipt();
        state.reservations.insert(receipt.id.clone(), record);
        Ok(receipt)
    }

    /// Converts one active reservation into committed usage atomically.
    ///
    /// Repeating a successful commit returns the same committed receipt.
    ///
    /// # Errors
    /// Returns a stable failure when the ID is absent, finalized differently,
    /// arithmetic invariants fail, or state is unavailable.
    pub fn commit(&self, id: ReservationId) -> Result<ReservationReceipt, BudgetError> {
        self.transition(id, ReservationState::Committed)
    }

    /// Releases one active reservation atomically.
    ///
    /// Repeating a successful release returns the same released receipt.
    ///
    /// # Errors
    /// Returns a stable failure when the ID is absent, finalized differently,
    /// accounting invariants fail, or state is unavailable.
    pub fn release(&self, id: ReservationId) -> Result<ReservationReceipt, BudgetError> {
        self.transition(id, ReservationState::Released)
    }

    /// Expires every active reservation whose deadline is at or before `now`.
    ///
    /// The pass is bounded by [`MAX_RESERVATIONS`] and releases all affected
    /// policy counters under the same atomic lock.
    ///
    /// # Errors
    /// Returns a stable failure if accounting invariants fail or state is unavailable.
    pub fn expire(&self, now: UnixTimeSeconds) -> Result<ExpiryReport, BudgetError> {
        let mut state = self.lock_state()?;
        let count = expire_records(&mut state, now)?;
        Ok(ExpiryReport {
            expired_count: count,
        })
    }

    /// Returns a consistent usage snapshot for one policy.
    ///
    /// # Errors
    /// Returns [`BudgetErrorCode::PolicyNotFound`] for an unknown identity or a
    /// stable state failure if the lock is poisoned.
    pub fn usage(&self, id: BudgetPolicyId) -> Result<BudgetUsage, BudgetError> {
        let state = self.lock_state()?;
        let policy = state
            .policies
            .get(&id)
            .ok_or_else(|| error(BudgetErrorCode::PolicyNotFound))?;
        Ok(BudgetUsage {
            policy_id: policy.policy.id.clone(),
            limit: policy.policy.limit.clone(),
            enforcement: policy.policy.enforcement,
            reserved_minor_units: policy.reserved,
            committed_minor_units: policy.committed,
        })
    }

    fn transition(
        &self,
        id: ReservationId,
        target: ReservationState,
    ) -> Result<ReservationReceipt, BudgetError> {
        let mut state = self.lock_state()?;
        transition_record(&mut state, &id, target)
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, BudgetState>, BudgetError> {
        self.state
            .lock()
            .map_err(|_| error(BudgetErrorCode::StateUnavailable))
    }
}

fn validate_policy_count(count: usize) -> Result<(), BudgetError> {
    if count == 0 {
        return Err(error(BudgetErrorCode::InvalidArgument));
    }
    if count > MAX_POLICIES {
        return Err(error(BudgetErrorCode::LimitExceeded));
    }
    Ok(())
}

fn validate_unique_policy(
    policy: &BudgetPolicy,
    identities: &mut BTreeSet<BudgetPolicyId>,
    scopes: &mut BTreeSet<(BudgetScope, CurrencyCode)>,
) -> Result<(), BudgetError> {
    if !identities.insert(policy.id.clone()) {
        return Err(error(BudgetErrorCode::DuplicatePolicy));
    }
    let key = (policy.scope.clone(), policy.limit.currency.clone());
    if !scopes.insert(key) {
        return Err(error(BudgetErrorCode::DuplicateScopeCurrency));
    }
    Ok(())
}

fn validate_new_reservation(
    state: &BudgetState,
    request: &ReservationRequest,
    now: UnixTimeSeconds,
) -> Result<(), BudgetError> {
    if request.expires_at() <= now {
        return Err(error(BudgetErrorCode::InvalidArgument));
    }
    if state.reservations.len() >= MAX_RESERVATIONS {
        return Err(error(BudgetErrorCode::LimitExceeded));
    }
    Ok(())
}

fn applicable_policy_ids(
    state: &BudgetState,
    request: &ReservationRequest,
) -> Result<Vec<BudgetPolicyId>, BudgetError> {
    let mut ids = Vec::with_capacity(3);
    for policy in state.policies.values() {
        if policy.policy.scope.matches(request.context())
            && policy.policy.limit.currency() == request.amount().currency()
        {
            ids.push(policy.policy.id.clone());
        }
    }
    if ids.is_empty() {
        return Err(error(BudgetErrorCode::NoApplicablePolicy));
    }
    Ok(ids)
}

fn validate_capacity(
    state: &BudgetState,
    policy_ids: &[BudgetPolicyId],
    amount: &Money,
) -> Result<Vec<BudgetPolicyId>, BudgetError> {
    let mut soft_breaches = Vec::new();
    for id in policy_ids {
        let policy = policy_state(state, id)?;
        let projected = projected_usage(policy, amount.minor_units())?;
        if projected <= policy.policy.limit.minor_units() {
            continue;
        }
        match policy.policy.enforcement {
            Enforcement::Hard => return Err(error(BudgetErrorCode::HardLimitExceeded)),
            Enforcement::Soft => soft_breaches.push(id.clone()),
        }
    }
    Ok(soft_breaches)
}

fn projected_usage(policy: &PolicyState, amount: u64) -> Result<u64, BudgetError> {
    policy
        .committed
        .checked_add(policy.reserved)
        .and_then(|usage| usage.checked_add(amount))
        .ok_or_else(|| error(BudgetErrorCode::ArithmeticOverflow))
}

fn reserve_capacity(
    state: &mut BudgetState,
    policy_ids: &[BudgetPolicyId],
    amount: u64,
) -> Result<(), BudgetError> {
    let updates = policy_ids
        .iter()
        .map(|id| {
            let policy = policy_state(state, id)?;
            let reserved = policy
                .reserved
                .checked_add(amount)
                .ok_or_else(|| error(BudgetErrorCode::ArithmeticOverflow))?;
            Ok((id.clone(), reserved))
        })
        .collect::<Result<Vec<_>, BudgetError>>()?;
    for (id, reserved) in updates {
        let policy = policy_state_mut(state, &id)?;
        policy.reserved = reserved;
    }
    Ok(())
}

fn replay_reservation(
    record: &ReservationRecord,
    request: &ReservationRequest,
) -> Result<ReservationReceipt, BudgetError> {
    if &record.request != request {
        return Err(error(BudgetErrorCode::ReplayConflict));
    }
    if record.state != ReservationState::Reserved {
        return Err(error(BudgetErrorCode::ReservationFinalized));
    }
    Ok(record.receipt())
}

fn transition_record(
    state: &mut BudgetState,
    id: &ReservationId,
    target: ReservationState,
) -> Result<ReservationReceipt, BudgetError> {
    let record = state
        .reservations
        .get(id)
        .cloned()
        .ok_or_else(|| error(BudgetErrorCode::ReservationNotFound))?;
    if record.state == target {
        return Ok(record.receipt());
    }
    if record.state != ReservationState::Reserved {
        return Err(error(BudgetErrorCode::ReservationFinalized));
    }
    apply_transition_usage(state, &record, target)?;
    let stored = state
        .reservations
        .get_mut(id)
        .ok_or_else(|| error(BudgetErrorCode::ReservationNotFound))?;
    stored.state = target;
    Ok(stored.receipt())
}

fn apply_transition_usage(
    state: &mut BudgetState,
    record: &ReservationRecord,
    target: ReservationState,
) -> Result<(), BudgetError> {
    let amount = record.request.amount.minor_units();
    let updates = record
        .applied_policies
        .iter()
        .map(|id| {
            let policy = policy_state(state, id)?;
            let reserved = policy
                .reserved
                .checked_sub(amount)
                .ok_or_else(|| error(BudgetErrorCode::ArithmeticOverflow))?;
            let committed = if target == ReservationState::Committed {
                policy
                    .committed
                    .checked_add(amount)
                    .ok_or_else(|| error(BudgetErrorCode::ArithmeticOverflow))?
            } else {
                policy.committed
            };
            Ok((id.clone(), reserved, committed))
        })
        .collect::<Result<Vec<_>, BudgetError>>()?;
    for (id, reserved, committed) in updates {
        let policy = policy_state_mut(state, &id)?;
        policy.reserved = reserved;
        policy.committed = committed;
    }
    Ok(())
}

fn expire_records(state: &mut BudgetState, now: UnixTimeSeconds) -> Result<usize, BudgetError> {
    let expired: Vec<ReservationId> = state
        .reservations
        .values()
        .filter(|record| {
            record.state == ReservationState::Reserved && record.request.expires_at <= now
        })
        .map(|record| record.request.id.clone())
        .collect();
    for id in &expired {
        transition_record(state, id, ReservationState::Expired)?;
    }
    Ok(expired.len())
}

fn policy_state<'a>(
    state: &'a BudgetState,
    id: &BudgetPolicyId,
) -> Result<&'a PolicyState, BudgetError> {
    state
        .policies
        .get(id)
        .ok_or_else(|| error(BudgetErrorCode::PolicyNotFound))
}

fn policy_state_mut<'a>(
    state: &'a mut BudgetState,
    id: &BudgetPolicyId,
) -> Result<&'a mut PolicyState, BudgetError> {
    state
        .policies
        .get_mut(id)
        .ok_or_else(|| error(BudgetErrorCode::PolicyNotFound))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.is_ascii()
        && !value.bytes().any(is_disallowed_id_byte)
}

fn is_disallowed_id_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_' | b':')
}

const fn error(code: BudgetErrorCode) -> BudgetError {
    BudgetError::new(code)
}

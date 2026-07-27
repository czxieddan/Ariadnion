//! Atomic durable persistence for tenant-bound authorization policies.

mod decode;
mod evidence;
mod reconcile;
mod sql;

use std::sync::Arc;
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ariadnion_core::{PrincipalContext, RequestContext, TenantId};
use ariadnion_rbac::{
    AuthorizationPolicy, AuthorizationPolicyCommitReceipt, AuthorizationPolicyEventKind,
    AuthorizationPolicyRepositoryError, AuthorizationPolicyRepositoryErrorCode,
    AuthorizationPolicyRepositoryPort, AuthorizationPolicySnapshot, AuthorizationPolicyTransition,
    AuthorizationScope, PermissionEffect, PolicyVersion,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::LocalSession;

#[cfg(feature = "test-hooks")]
use crate::audit_repository::{AuditReadObserver, AuditReadQuery};
use crate::identity_transaction::run_identity_transaction;
use crate::{AuditSubjectKeyMaterial, RnmdbSessionOwner, SessionOpenOptions};

/// Maximum number of authorization-policy events authenticated by one read.
pub const MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS: u64 = 65_536;

#[cfg(feature = "test-hooks")]
pub(super) struct HistoryTestHooks {
    audit_membership_scans: AtomicU64,
    event_history_decodes: AtomicU64,
    exact_audit_queries: AtomicU64,
    exact_audit_event_decodes: AtomicU64,
    exact_audit_head_queries: AtomicU64,
    exact_audit_head_decodes: AtomicU64,
    exact_audit_chain_queries: AtomicU64,
    exact_audit_chain_decodes: AtomicU64,
    exact_audit_verifications: AtomicU64,
    cancel_next_audit_query: AtomicBool,
    cancel_next_event_history_query: AtomicBool,
    cancel_next_exact_audit_query: AtomicBool,
    cancel_next_exact_audit_head_query: AtomicBool,
    cancel_next_exact_audit_chain_query: AtomicBool,
    cancel_next_exact_outbox_query: AtomicBool,
    event_history_row_limit: AtomicU64,
}

#[cfg(feature = "test-hooks")]
impl HistoryTestHooks {
    const fn new() -> Self {
        Self {
            audit_membership_scans: AtomicU64::new(0),
            event_history_decodes: AtomicU64::new(0),
            exact_audit_queries: AtomicU64::new(0),
            exact_audit_event_decodes: AtomicU64::new(0),
            exact_audit_head_queries: AtomicU64::new(0),
            exact_audit_head_decodes: AtomicU64::new(0),
            exact_audit_chain_queries: AtomicU64::new(0),
            exact_audit_chain_decodes: AtomicU64::new(0),
            exact_audit_verifications: AtomicU64::new(0),
            cancel_next_audit_query: AtomicBool::new(false),
            cancel_next_event_history_query: AtomicBool::new(false),
            cancel_next_exact_audit_query: AtomicBool::new(false),
            cancel_next_exact_audit_head_query: AtomicBool::new(false),
            cancel_next_exact_audit_chain_query: AtomicBool::new(false),
            cancel_next_exact_outbox_query: AtomicBool::new(false),
            event_history_row_limit: AtomicU64::new(MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS),
        }
    }

    fn audit_membership_scan_count(&self) -> u64 {
        self.audit_membership_scans.load(Ordering::Relaxed)
    }

    fn arm_history_cancellation(&self) {
        self.cancel_next_audit_query.store(true, Ordering::Release);
    }

    fn arm_event_history_query_cancellation(&self) {
        self.cancel_next_event_history_query
            .store(true, Ordering::Release);
    }

    fn arm_exact_audit_query_cancellation(&self) {
        self.cancel_next_exact_audit_query
            .store(true, Ordering::Release);
    }

    fn arm_exact_audit_head_query_cancellation(&self) {
        self.cancel_next_exact_audit_head_query
            .store(true, Ordering::Release);
    }

    fn arm_exact_audit_chain_query_cancellation(&self) {
        self.cancel_next_exact_audit_chain_query
            .store(true, Ordering::Release);
    }

    fn arm_exact_outbox_query_cancellation(&self) {
        self.cancel_next_exact_outbox_query
            .store(true, Ordering::Release);
    }

    fn event_history_decode_count(&self) -> u64 {
        self.event_history_decodes.load(Ordering::Relaxed)
    }

    fn exact_audit_query_count(&self) -> u64 {
        self.exact_audit_queries.load(Ordering::Relaxed)
    }

    fn exact_audit_event_decode_count(&self) -> u64 {
        self.exact_audit_event_decodes.load(Ordering::Relaxed)
    }

    fn exact_audit_head_query_count(&self) -> u64 {
        self.exact_audit_head_queries.load(Ordering::Relaxed)
    }

    fn exact_audit_head_decode_count(&self) -> u64 {
        self.exact_audit_head_decodes.load(Ordering::Relaxed)
    }

    fn exact_audit_chain_query_count(&self) -> u64 {
        self.exact_audit_chain_queries.load(Ordering::Relaxed)
    }

    fn exact_audit_chain_decode_count(&self) -> u64 {
        self.exact_audit_chain_decodes.load(Ordering::Relaxed)
    }

    fn exact_audit_verification_count(&self) -> u64 {
        self.exact_audit_verifications.load(Ordering::Relaxed)
    }

    fn event_history_row_limit(&self) -> u64 {
        self.event_history_row_limit
            .load(Ordering::Acquire)
            .min(MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS)
    }

    fn set_event_history_row_limit(&self, maximum: u64) {
        self.event_history_row_limit
            .store(maximum, Ordering::Release);
    }

    fn cancel_after_audit_query_if_armed(&self, context: &RequestContext) {
        if self.cancel_next_audit_query.swap(false, Ordering::AcqRel) {
            let _ = context.cancellation().cancel();
        }
    }

    fn cancel_after_event_history_query_if_armed(&self, context: &RequestContext) {
        if self
            .cancel_next_event_history_query
            .swap(false, Ordering::AcqRel)
        {
            let _ = context.cancellation().cancel();
        }
    }

    fn cancel_after_exact_audit_query_if_armed(&self, context: &RequestContext) {
        if self
            .cancel_next_exact_audit_query
            .swap(false, Ordering::AcqRel)
        {
            let _ = context.cancellation().cancel();
        }
    }

    fn cancel_after_exact_audit_head_query_if_armed(&self, context: &RequestContext) {
        if self
            .cancel_next_exact_audit_head_query
            .swap(false, Ordering::AcqRel)
        {
            let _ = context.cancellation().cancel();
        }
    }

    fn cancel_after_exact_audit_chain_query_if_armed(&self, context: &RequestContext) {
        if self
            .cancel_next_exact_audit_chain_query
            .swap(false, Ordering::AcqRel)
        {
            let _ = context.cancellation().cancel();
        }
    }

    fn cancel_after_exact_outbox_query_if_armed(&self, context: &RequestContext) {
        if self
            .cancel_next_exact_outbox_query
            .swap(false, Ordering::AcqRel)
        {
            let _ = context.cancellation().cancel();
        }
    }

    fn record_event_history_decode(&self) {
        self.event_history_decodes.fetch_add(1, Ordering::Relaxed);
    }

    fn record_exact_audit_query(&self) {
        self.exact_audit_queries.fetch_add(1, Ordering::Relaxed);
    }

    fn record_exact_audit_event_decode(&self) {
        self.exact_audit_event_decodes
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_exact_audit_head_query(&self) {
        self.exact_audit_head_queries
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_exact_audit_head_decode(&self) {
        self.exact_audit_head_decodes
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_exact_audit_chain_query(&self) {
        self.exact_audit_chain_queries
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_exact_audit_chain_decode(&self) {
        self.exact_audit_chain_decodes
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_exact_audit_verification(&self) {
        self.exact_audit_verifications
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_audit_membership_scan(&self) {
        self.audit_membership_scans.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-hooks")]
impl AuditReadObserver for HistoryTestHooks {
    fn before_query(&self, query: AuditReadQuery) {
        match query {
            AuditReadQuery::ExactEvent => self.record_exact_audit_query(),
            AuditReadQuery::Head => self.record_exact_audit_head_query(),
            AuditReadQuery::Chain => self.record_exact_audit_chain_query(),
        }
    }

    fn after_query(&self, query: AuditReadQuery, context: &RequestContext) {
        match query {
            AuditReadQuery::ExactEvent => self.cancel_after_exact_audit_query_if_armed(context),
            AuditReadQuery::Head => self.cancel_after_exact_audit_head_query_if_armed(context),
            AuditReadQuery::Chain => self.cancel_after_exact_audit_chain_query_if_armed(context),
        }
    }

    fn before_decode(&self, query: AuditReadQuery) {
        match query {
            AuditReadQuery::ExactEvent => self.record_exact_audit_event_decode(),
            AuditReadQuery::Head => self.record_exact_audit_head_decode(),
            AuditReadQuery::Chain => self.record_exact_audit_chain_decode(),
        }
    }
}

/// Persists complete authorization-policy snapshots and immutable commit evidence.
pub struct RnmdbAuthorizationPolicyRepository {
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
    #[cfg(feature = "test-hooks")]
    history_test_hooks: HistoryTestHooks,
}

impl RnmdbAuthorizationPolicyRepository {
    /// Opens a repository over a newly created serialized RNMDB session.
    ///
    /// Use this constructor to reconcile a prior indeterminate commit after
    /// discarding the tainted owner and supplying fresh secret material.
    ///
    /// # Errors
    ///
    /// Returns a redacted storage error when the encrypted database cannot be
    /// opened with the supplied validated options.
    pub fn open(
        options: SessionOpenOptions,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Result<Self, StorageError> {
        let session = RnmdbSessionOwner::open(options).map(Arc::new)?;
        Ok(Self::new(session, audit_subject_key))
    }

    /// Creates a repository over one serialized session and audit-subject key.
    ///
    /// A tainted owner remains unusable. Call [`Self::open`] with fresh options
    /// after an indeterminate commit.
    #[must_use]
    pub const fn new(
        session: Arc<RnmdbSessionOwner>,
        audit_subject_key: AuditSubjectKeyMaterial,
    ) -> Self {
        Self {
            session,
            audit_subject_key,
            #[cfg(feature = "test-hooks")]
            history_test_hooks: HistoryTestHooks::new(),
        }
    }

    /// Returns completed audit membership verification attempts for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn audit_membership_scan_count(&self) -> u64 {
        self.history_test_hooks.audit_membership_scan_count()
    }

    /// Arms cancellation after the next history audit query for contract tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_history_cancellation(&self) {
        self.history_test_hooks.arm_history_cancellation();
    }

    /// Overrides the event-history row limit for contract tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_event_history_row_limit(&self, maximum: u64) {
        self.history_test_hooks.set_event_history_row_limit(maximum);
    }

    /// Returns completed event-history decode attempts for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn event_history_decode_count(&self) -> u64 {
        self.history_test_hooks.event_history_decode_count()
    }

    /// Returns exact audit query attempts for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn exact_audit_query_count(&self) -> u64 {
        self.history_test_hooks.exact_audit_query_count()
    }

    /// Returns completed exact audit-event decode attempts for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn exact_audit_event_decode_count(&self) -> u64 {
        self.history_test_hooks.exact_audit_event_decode_count()
    }

    /// Returns exact audit-head query attempts for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn exact_audit_head_query_count(&self) -> u64 {
        self.history_test_hooks.exact_audit_head_query_count()
    }

    /// Returns completed exact audit-head decode attempts for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn exact_audit_head_decode_count(&self) -> u64 {
        self.history_test_hooks.exact_audit_head_decode_count()
    }

    /// Returns exact audit-chain query attempts for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn exact_audit_chain_query_count(&self) -> u64 {
        self.history_test_hooks.exact_audit_chain_query_count()
    }

    /// Returns completed exact audit-chain decode attempts for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn exact_audit_chain_decode_count(&self) -> u64 {
        self.history_test_hooks.exact_audit_chain_decode_count()
    }

    /// Returns completed exact audit semantic verifications for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn exact_audit_verification_count(&self) -> u64 {
        self.history_test_hooks.exact_audit_verification_count()
    }

    /// Arms cancellation after the next event-history query for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_event_history_query_cancellation(&self) {
        self.history_test_hooks
            .arm_event_history_query_cancellation();
    }

    /// Arms cancellation after the next exact audit query for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_exact_audit_query_cancellation(&self) {
        self.history_test_hooks.arm_exact_audit_query_cancellation();
    }

    /// Arms cancellation after the next exact audit-head query for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_exact_audit_head_query_cancellation(&self) {
        self.history_test_hooks
            .arm_exact_audit_head_query_cancellation();
    }

    /// Arms cancellation after the next exact audit-chain query for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_exact_audit_chain_query_cancellation(&self) {
        self.history_test_hooks
            .arm_exact_audit_chain_query_cancellation();
    }

    /// Arms cancellation after the next exact outbox query for tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_exact_outbox_query_cancellation(&self) {
        self.history_test_hooks
            .arm_exact_outbox_query_cancellation();
    }
}

impl AuthorizationPolicyRepositoryPort for RnmdbAuthorizationPolicyRepository {
    fn load(
        &self,
        tenant_id: &TenantId,
        context: &RequestContext,
    ) -> Result<AuthorizationPolicy, AuthorizationPolicyRepositoryError> {
        validate_authenticated_tenant(context, tenant_id).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                load_authenticated_policy(
                    session,
                    tenant_id,
                    context,
                    &self.audit_subject_key,
                    #[cfg(feature = "test-hooks")]
                    &self.history_test_hooks,
                )
                .map(|loaded| loaded.policy)
            })
            .map_err(map_storage_error)
    }

    fn compare_and_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: PolicyVersion,
        transition: &AuthorizationPolicyTransition,
        context: &RequestContext,
    ) -> Result<AuthorizationPolicyCommitReceipt, AuthorizationPolicyRepositoryError> {
        let request = CommitRequest::new(tenant_id, expected_previous_version, transition, context);
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_transaction_session(context, tenant_id, |session| {
                run_identity_transaction(session, context, |session| {
                    commit_in_transaction(
                        session,
                        &request,
                        &self.audit_subject_key,
                        #[cfg(feature = "test-hooks")]
                        &self.history_test_hooks,
                    )
                })
            })
            .map_err(map_storage_error)
    }

    fn reconcile_commit(
        &self,
        tenant_id: &TenantId,
        expected_previous_version: PolicyVersion,
        transition: &AuthorizationPolicyTransition,
        context: &RequestContext,
    ) -> Result<AuthorizationPolicyCommitReceipt, AuthorizationPolicyRepositoryError> {
        let request = CommitRequest::new(tenant_id, expected_previous_version, transition, context);
        validate_commit_request(&request).map_err(map_storage_error)?;
        self.session
            .with_identity_storage_session(context, tenant_id, |session| {
                reconcile::reconcile_commit(
                    session,
                    &request,
                    &self.audit_subject_key,
                    #[cfg(feature = "test-hooks")]
                    &self.history_test_hooks,
                )
            })
            .map_err(map_storage_error)
    }
}

pub(super) struct CommitRequest<'a> {
    pub(super) tenant_id: &'a TenantId,
    pub(super) expected_previous_version: PolicyVersion,
    pub(super) transition: &'a AuthorizationPolicyTransition,
    pub(super) context: &'a RequestContext,
}

impl<'a> CommitRequest<'a> {
    const fn new(
        tenant_id: &'a TenantId,
        expected_previous_version: PolicyVersion,
        transition: &'a AuthorizationPolicyTransition,
        context: &'a RequestContext,
    ) -> Self {
        Self {
            tenant_id,
            expected_previous_version,
            transition,
            context,
        }
    }
}

struct LoadedPolicy {
    policy: AuthorizationPolicy,
    events: Vec<decode::PersistedPolicyEvent>,
}

fn load_authenticated_policy(
    session: &mut LocalSession,
    tenant: &TenantId,
    context: &RequestContext,
    key: &AuditSubjectKeyMaterial,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<LoadedPolicy, StorageError> {
    let maximum_event_history_rows = effective_event_history_row_limit(
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    );
    let loaded = decode::load_policy(
        session,
        tenant,
        maximum_event_history_rows,
        context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    evidence::verify_complete_history(
        session,
        &loaded.events,
        &loaded.policy,
        key,
        context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    Ok(loaded)
}

fn effective_event_history_row_limit(
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> u64 {
    #[cfg(feature = "test-hooks")]
    {
        history_test_hooks.event_history_row_limit()
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS
    }
}

fn commit_in_transaction(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    key: &AuditSubjectKeyMaterial,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<AuthorizationPolicyCommitReceipt, StorageError> {
    validate_commit_request(request)?;
    match request.transition.previous_snapshot() {
        None => persist_publication(session, request)?,
        Some(previous) => persist_replacement(
            session,
            request,
            previous,
            key,
            #[cfg(feature = "test-hooks")]
            history_test_hooks,
        )?,
    }
    let committed_at = trusted_commit_time()?;
    evidence::persist_transition_evidence(session, request, key, committed_at)?;
    Ok(AuthorizationPolicyCommitReceipt::new(
        request.tenant_id.clone(),
        request.transition.policy().version(),
        committed_at,
    ))
}

fn persist_publication(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    ensure_publication_absent(session, request.tenant_id)?;
    sql::insert_header(
        session,
        request.tenant_id,
        request.transition.policy().version(),
    )?;
    persist_snapshot_rows(session, request.transition.policy())?;
    persist_event(session, request)
}

fn ensure_publication_absent(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<(), StorageError> {
    decode::ensure_publication_empty(session, tenant)
}

fn persist_replacement(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
    previous: &AuthorizationPolicySnapshot,
    key: &AuditSubjectKeyMaterial,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<(), StorageError> {
    let durable = load_authenticated_policy(
        session,
        request.tenant_id,
        request.context,
        key,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )
    .map_err(map_replacement_load_error)?;
    if durable.policy.version() != request.expected_previous_version
        || durable.policy.snapshot_state() != *previous
    {
        return Err(sql::conflict());
    }
    sql::update_header(
        session,
        request.tenant_id,
        request.expected_previous_version,
        request.transition.policy().version(),
    )?;
    delete_previous_snapshot(session, request.tenant_id, previous)?;
    persist_snapshot_rows(session, request.transition.policy())?;
    persist_event(session, request)
}

fn map_replacement_load_error(error: StorageError) -> StorageError {
    if error.code() == StorageErrorCode::NotFound {
        sql::conflict()
    } else {
        error
    }
}

fn delete_previous_snapshot(
    session: &mut LocalSession,
    tenant: &TenantId,
    previous: &AuthorizationPolicySnapshot,
) -> Result<(), StorageError> {
    let rules = previous.roles().iter().try_fold(0_usize, |total, role| {
        total
            .checked_add(role.rules().len())
            .ok_or_else(integrity_failure)
    })?;
    sql::delete_snapshot_rows(
        session,
        tenant,
        rules,
        previous.roles().len(),
        previous.assignments().len(),
    )
}

fn persist_snapshot_rows(
    session: &mut LocalSession,
    policy: &AuthorizationPolicy,
) -> Result<(), StorageError> {
    for (role_ordinal, role) in policy.roles().iter().enumerate() {
        sql::insert_role(
            session,
            policy.tenant_id(),
            role_ordinal,
            role.id().as_str(),
        )?;
        for (rule_ordinal, rule) in role.rules().iter().enumerate() {
            sql::insert_rule(
                session,
                policy.tenant_id(),
                role.id().as_str(),
                rule_ordinal,
                rule.permission_id().as_str(),
                effect_label(rule.effect()),
            )?;
        }
    }
    persist_assignment_rows(session, policy)
}

fn persist_assignment_rows(
    session: &mut LocalSession,
    policy: &AuthorizationPolicy,
) -> Result<(), StorageError> {
    for (ordinal, assignment) in policy.assignments().iter().enumerate() {
        let scope = scope_fields(assignment.scope());
        sql::insert_assignment(
            session,
            sql::AssignmentInsert {
                tenant: policy.tenant_id(),
                ordinal,
                assignment_id: assignment.id().as_str(),
                principal_id: assignment.principal_id().as_str(),
                membership_id: assignment.membership_id().as_str(),
                role_id: assignment.role_id().as_str(),
                scope_kind: scope.kind,
                organization_id: scope.organization_id,
                parent_resource_id: scope.parent_resource_id,
                resource_kind: scope.resource_kind,
                resource_id: scope.resource_id,
                expires_at: assignment.expires_at().map(UtcTimestamp::unix_seconds),
            },
        )?;
    }
    Ok(())
}

struct ScopeFields<'a> {
    kind: &'static str,
    organization_id: Option<&'a str>,
    parent_resource_id: Option<&'a str>,
    resource_kind: Option<&'a str>,
    resource_id: Option<&'a str>,
}

fn scope_fields(scope: &AuthorizationScope) -> ScopeFields<'_> {
    match scope {
        AuthorizationScope::Tenant { .. } => ScopeFields::new("tenant"),
        AuthorizationScope::TenantResource {
            resource_kind,
            resource_id,
            ..
        } => ScopeFields {
            kind: "tenant_resource",
            organization_id: None,
            parent_resource_id: None,
            resource_kind: Some(resource_kind.as_str()),
            resource_id: Some(resource_id.as_str()),
        },
        AuthorizationScope::Organization {
            organization_id, ..
        } => ScopeFields {
            kind: "organization",
            organization_id: Some(organization_id.as_str()),
            parent_resource_id: None,
            resource_kind: None,
            resource_id: None,
        },
        AuthorizationScope::Resource {
            organization_id,
            parent_resource_id,
            resource_kind,
            resource_id,
            ..
        } => ScopeFields {
            kind: "resource",
            organization_id: Some(organization_id.as_str()),
            parent_resource_id: parent_resource_id.as_ref().map(|id| id.as_str()),
            resource_kind: Some(resource_kind.as_str()),
            resource_id: Some(resource_id.as_str()),
        },
    }
}

impl ScopeFields<'_> {
    const fn new(kind: &'static str) -> Self {
        Self {
            kind,
            organization_id: None,
            parent_resource_id: None,
            resource_kind: None,
            resource_id: None,
        }
    }
}

fn persist_event(
    session: &mut LocalSession,
    request: &CommitRequest<'_>,
) -> Result<(), StorageError> {
    let event = request.transition.event();
    sql::insert_event(
        session,
        sql::EventInsert {
            tenant: request.tenant_id,
            version: event.version(),
            kind: event_kind_label(event.kind()),
            occurred_at: event.occurred_at().unix_seconds(),
            actor_id: event.actor().as_str(),
            request_id: request.context.request_id().as_str(),
        },
    )
}

pub(super) fn validate_commit_request(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    validate_authenticated_tenant(request.context, request.tenant_id)?;
    let principal = authenticated_principal(request.context)?;
    validate_commit_binding(request, principal)?;
    validate_snapshot_tenant(
        &request.transition.policy().snapshot_state(),
        request.tenant_id,
    )?;
    validate_transition_shape(request)
}

fn validate_commit_binding(
    request: &CommitRequest<'_>,
    principal: &PrincipalContext,
) -> Result<(), StorageError> {
    let policy = request.transition.policy();
    let event = request.transition.event();
    let valid = request.transition.tenant_id() == request.tenant_id
        && policy.tenant_id() == request.tenant_id
        && event.tenant_id() == request.tenant_id
        && event.actor() == principal.principal_id()
        && event.version() == policy.version()
        && request.expected_previous_version == request.transition.expected_previous_version();
    if !valid {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_transition_shape(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    match request.transition.previous_snapshot() {
        None => validate_publication_shape(request),
        Some(previous) => validate_replacement_shape(request, previous),
    }
}

fn validate_publication_shape(request: &CommitRequest<'_>) -> Result<(), StorageError> {
    let valid = request.expected_previous_version == PolicyVersion::initial()
        && request.transition.policy().version() == PolicyVersion::initial()
        && request.transition.event().kind() == AuthorizationPolicyEventKind::Published;
    if !valid {
        return Err(integrity_failure());
    }
    validate_history_capacity(request.transition.policy().version())
}

fn validate_replacement_shape(
    request: &CommitRequest<'_>,
    previous: &AuthorizationPolicySnapshot,
) -> Result<(), StorageError> {
    validate_snapshot_tenant(previous, request.tenant_id)?;
    let next = request
        .expected_previous_version
        .next()
        .map_err(|_| integrity_failure())?;
    let valid = previous.version() == request.expected_previous_version
        && request.transition.policy().version() == next
        && request.transition.event().kind() == AuthorizationPolicyEventKind::Replaced;
    if !valid {
        return Err(integrity_failure());
    }
    validate_history_capacity(next)
}

fn validate_snapshot_tenant(
    snapshot: &AuthorizationPolicySnapshot,
    tenant: &TenantId,
) -> Result<(), StorageError> {
    let roles_match = snapshot
        .roles()
        .iter()
        .all(|role| role.tenant_id() == tenant);
    let assignments_match = snapshot
        .assignments()
        .iter()
        .all(|assignment| assignment.scope().tenant_id() == tenant);
    if snapshot.tenant_id() != tenant || !roles_match || !assignments_match {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_history_capacity(version: PolicyVersion) -> Result<(), StorageError> {
    if version.get() > MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(())
}

pub(super) fn validate_authenticated_tenant(
    context: &RequestContext,
    tenant: &TenantId,
) -> Result<(), StorageError> {
    if authenticated_principal(context)?.tenant_id() != tenant {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn authenticated_principal(
    context: &RequestContext,
) -> Result<&PrincipalContext, StorageError> {
    context.principal().ok_or_else(integrity_failure)
}

fn trusted_commit_time() -> Result<UtcTimestamp, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure())?;
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| integrity_failure())?;
    Ok(UtcTimestamp::from_unix_seconds(seconds))
}

const fn effect_label(effect: PermissionEffect) -> &'static str {
    match effect {
        PermissionEffect::Allow => "allow",
        PermissionEffect::Deny => "deny",
    }
}

pub(super) const fn event_kind_label(kind: AuthorizationPolicyEventKind) -> &'static str {
    match kind {
        AuthorizationPolicyEventKind::Published => "published",
        AuthorizationPolicyEventKind::Replaced => "replaced",
    }
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

pub(super) fn map_fresh_insert_error(error: StorageError) -> StorageError {
    match error.code() {
        StorageErrorCode::Unavailable
        | StorageErrorCode::Cancelled
        | StorageErrorCode::DeadlineExceeded
        | StorageErrorCode::ResourceExhausted => error,
        _ => integrity_failure(),
    }
}

fn map_storage_error(error: StorageError) -> AuthorizationPolicyRepositoryError {
    let code = match error.code() {
        StorageErrorCode::NotFound => AuthorizationPolicyRepositoryErrorCode::NotFound,
        StorageErrorCode::Conflict => AuthorizationPolicyRepositoryErrorCode::Conflict,
        StorageErrorCode::Cancelled => AuthorizationPolicyRepositoryErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => {
            AuthorizationPolicyRepositoryErrorCode::DeadlineExceeded
        }
        StorageErrorCode::ResourceExhausted => {
            AuthorizationPolicyRepositoryErrorCode::ResourceExhausted
        }
        StorageErrorCode::Unavailable => AuthorizationPolicyRepositoryErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => {
            AuthorizationPolicyRepositoryErrorCode::CommitIndeterminate
        }
        _ => AuthorizationPolicyRepositoryErrorCode::IntegrityFailure,
    };
    AuthorizationPolicyRepositoryError::new(code)
}

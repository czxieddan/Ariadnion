// crates/optional/ariadnion-storage-rnmdb/src/rbac_repository/decode.rs - Rust source for Ariadnion.
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
//
//! Strict bounded decoding for authorization-policy snapshots and history.

mod event;

use std::collections::BTreeMap;

use ariadnion_core::{PrincipalId, RequestContext, TenantId};
use ariadnion_organization::{MembershipId, OrganizationId};
use ariadnion_rbac::{
    AssignmentId, AuthorizationPolicy, AuthorizationPolicySnapshot, AuthorizationScope,
    MAX_ASSIGNMENTS, MAX_ROLES, MAX_RULES_PER_ROLE, PermissionEffect, PermissionId, PermissionRule,
    PolicyVersion, ResourceId, ResourceKind, RoleAssignmentSnapshot, RoleDefinitionSnapshot,
    RoleId,
};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use ariadnion_user_domain::UtcTimestamp;
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};

pub(super) use self::event::PersistedPolicyEvent;
#[cfg(feature = "test-hooks")]
use super::HistoryTestHooks;
use super::{LoadedPolicy, MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS, integrity_failure, sql};
use crate::session::check_context;

const VERSION_TEXT_BYTES: usize = 20;

pub(super) fn load_policy(
    session: &mut LocalSession,
    tenant: &TenantId,
    maximum_event_history_rows: u64,
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<LoadedPolicy, StorageError> {
    let version = load_header(session, tenant)?;
    let rules = load_rules(session, tenant)?;
    let roles = load_roles(session, tenant, rules)?;
    let assignments = load_assignments(session, tenant)?;
    let snapshot = AuthorizationPolicySnapshot::new(tenant.clone(), version, roles, assignments);
    let policy = AuthorizationPolicy::from_snapshot(snapshot).map_err(|_| integrity_failure())?;
    let events = load_events(
        session,
        tenant,
        maximum_event_history_rows,
        context,
        #[cfg(feature = "test-hooks")]
        history_test_hooks,
    )?;
    validate_history(&events, version)?;
    Ok(LoadedPolicy { policy, events })
}

pub(super) fn load_header(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<PolicyVersion, StorageError> {
    let batch = rows(sql::load_header(session, tenant)?)?;
    validate_columns(batch.columns(), &header_columns())?;
    match batch.rows() {
        [] => Err(StorageError::new(StorageErrorCode::NotFound)),
        [row] => decode_header(row, tenant),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn ensure_publication_empty(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<(), StorageError> {
    ensure_publication_header_absent(session, tenant)?;
    for table in [
        "identity_rbac_roles",
        "identity_rbac_role_rules",
        "identity_rbac_assignments",
        "identity_rbac_policy_events",
    ] {
        reject_table_residue(session, tenant, table)?;
    }
    reject_outbox_residue(session, tenant)
}

fn ensure_publication_header_absent(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<(), StorageError> {
    match load_header(session, tenant) {
        Ok(_) => Err(sql::conflict()),
        Err(error) if error.code() == StorageErrorCode::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn reject_table_residue(
    session: &mut LocalSession,
    tenant: &TenantId,
    table: &str,
) -> Result<(), StorageError> {
    let batch = rows(sql::load_presence(session, table, tenant)?)?;
    reject_presence(batch)
}

fn reject_outbox_residue(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<(), StorageError> {
    let batch = rows(sql::load_outbox_presence(session, tenant)?)?;
    reject_presence(batch)
}

fn reject_presence(batch: VectorBatch) -> Result<(), StorageError> {
    validate_columns(batch.columns(), &[("tenant_id", SqlType::Text)])?;
    match batch.rows() {
        [] => Ok(()),
        [_] => Err(integrity_failure()),
        _ => Err(integrity_failure()),
    }
}

fn decode_header(row: &Row, tenant: &TenantId) -> Result<PolicyVersion, StorageError> {
    let [SqlValue::Text(found_tenant), SqlValue::Text(version)] = row.values() else {
        return Err(integrity_failure());
    };
    validate_tenant(found_tenant, tenant)?;
    decode_version(version)
}

fn load_rules(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<BTreeMap<String, Vec<PermissionRule>>, StorageError> {
    let batch = rows(sql::load_rules(session, tenant)?)?;
    validate_columns(batch.columns(), &rule_columns())?;
    validate_rule_row_count(batch.rows().len())?;
    let mut rules = BTreeMap::new();
    for row in batch.rows() {
        decode_rule(row, tenant, &mut rules)?;
    }
    Ok(rules)
}

fn validate_rule_row_count(row_count: usize) -> Result<(), StorageError> {
    let maximum = MAX_ROLES
        .checked_mul(MAX_RULES_PER_ROLE)
        .ok_or_else(integrity_failure)?;
    if row_count > maximum {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn decode_rule(
    row: &Row,
    tenant: &TenantId,
    rules: &mut BTreeMap<String, Vec<PermissionRule>>,
) -> Result<(), StorageError> {
    let fields = rule_row_fields(row)?;
    validate_tenant(fields.tenant, tenant)?;
    RoleId::parse(fields.role).map_err(|_| integrity_failure())?;
    let values = rule_slot(rules, fields.role, fields.ordinal)?;
    let permission = PermissionId::parse(fields.permission).map_err(|_| integrity_failure())?;
    let effect = decode_effect(fields.effect)?;
    values.push(PermissionRule::new(permission, effect));
    Ok(())
}

struct RuleRowFields<'a> {
    tenant: &'a str,
    role: &'a str,
    ordinal: i64,
    permission: &'a str,
    effect: &'a str,
}

fn rule_row_fields(row: &Row) -> Result<RuleRowFields<'_>, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Text(role),
        SqlValue::Int64(ordinal),
        SqlValue::Text(permission),
        SqlValue::Text(effect),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(RuleRowFields {
        tenant: found_tenant,
        role,
        ordinal: *ordinal,
        permission,
        effect,
    })
}

fn rule_slot<'a>(
    rules: &'a mut BTreeMap<String, Vec<PermissionRule>>,
    role: &str,
    ordinal: i64,
) -> Result<&'a mut Vec<PermissionRule>, StorageError> {
    let values = rules.entry(role.to_owned()).or_default();
    validate_ordinal(ordinal, values.len())?;
    if values.len() >= MAX_RULES_PER_ROLE {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(values)
}

fn load_roles(
    session: &mut LocalSession,
    tenant: &TenantId,
    mut rules: BTreeMap<String, Vec<PermissionRule>>,
) -> Result<Vec<RoleDefinitionSnapshot>, StorageError> {
    let batch = rows(sql::load_roles(session, tenant)?)?;
    validate_columns(batch.columns(), &role_columns())?;
    validate_role_row_count(batch.rows().len())?;
    let roles = batch
        .rows()
        .iter()
        .enumerate()
        .map(|(ordinal, row)| decode_role(row, tenant, ordinal, &mut rules))
        .collect::<Result<Vec<_>, _>>()?;
    reject_residual_rules(&rules)?;
    Ok(roles)
}

fn validate_role_row_count(row_count: usize) -> Result<(), StorageError> {
    if row_count > MAX_ROLES {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn reject_residual_rules(
    rules: &BTreeMap<String, Vec<PermissionRule>>,
) -> Result<(), StorageError> {
    if !rules.is_empty() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn decode_role(
    row: &Row,
    tenant: &TenantId,
    expected_ordinal: usize,
    rules: &mut BTreeMap<String, Vec<PermissionRule>>,
) -> Result<RoleDefinitionSnapshot, StorageError> {
    let [
        SqlValue::Text(found_tenant),
        SqlValue::Int64(ordinal),
        SqlValue::Text(role),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    validate_tenant(found_tenant, tenant)?;
    validate_ordinal(*ordinal, expected_ordinal)?;
    let role_id = RoleId::parse(role).map_err(|_| integrity_failure())?;
    let role_rules = rules.remove(role).ok_or_else(integrity_failure)?;
    Ok(RoleDefinitionSnapshot::new(
        role_id,
        tenant.clone(),
        role_rules,
    ))
}

fn load_assignments(
    session: &mut LocalSession,
    tenant: &TenantId,
) -> Result<Vec<RoleAssignmentSnapshot>, StorageError> {
    let batch = rows(sql::load_assignments(session, tenant)?)?;
    validate_columns(batch.columns(), &assignment_columns())?;
    if batch.rows().len() > MAX_ASSIGNMENTS {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    batch
        .rows()
        .iter()
        .enumerate()
        .map(|(ordinal, row)| decode_assignment(row, tenant, ordinal))
        .collect()
}

fn decode_assignment(
    row: &Row,
    tenant: &TenantId,
    expected_ordinal: usize,
) -> Result<RoleAssignmentSnapshot, StorageError> {
    let values = AssignmentValues::from_row(row)?;
    validate_tenant(values.tenant, tenant)?;
    validate_ordinal(values.ordinal, expected_ordinal)?;
    let (assignment, principal, membership, role) = decode_assignment_ids(&values)?;
    Ok(RoleAssignmentSnapshot::new(
        assignment,
        principal,
        membership,
        role,
        values.decode_scope(tenant)?,
        values.expires_at.map(UtcTimestamp::from_unix_seconds),
    ))
}

fn decode_assignment_ids(
    values: &AssignmentValues<'_>,
) -> Result<(AssignmentId, PrincipalId, MembershipId, RoleId), StorageError> {
    Ok((
        AssignmentId::parse(values.assignment).map_err(|_| integrity_failure())?,
        PrincipalId::parse(values.principal).map_err(|_| integrity_failure())?,
        MembershipId::parse(values.membership).map_err(|_| integrity_failure())?,
        RoleId::parse(values.role).map_err(|_| integrity_failure())?,
    ))
}

struct AssignmentValues<'a> {
    tenant: &'a str,
    ordinal: i64,
    assignment: &'a str,
    principal: &'a str,
    membership: &'a str,
    role: &'a str,
    scope_kind: &'a str,
    organization: Option<&'a str>,
    parent: Option<&'a str>,
    resource_kind: Option<&'a str>,
    resource: Option<&'a str>,
    expires_at: Option<i64>,
}

impl<'a> AssignmentValues<'a> {
    fn from_row(row: &'a Row) -> Result<Self, StorageError> {
        let [
            SqlValue::Text(tenant),
            SqlValue::Int64(ordinal),
            SqlValue::Text(assignment),
            SqlValue::Text(principal),
            SqlValue::Text(membership),
            SqlValue::Text(role),
            SqlValue::Text(scope_kind),
            organization,
            parent,
            resource_kind,
            resource,
            expires_at,
        ] = row.values()
        else {
            return Err(integrity_failure());
        };
        Ok(Self {
            tenant,
            ordinal: *ordinal,
            assignment,
            principal,
            membership,
            role,
            scope_kind,
            organization: optional_text(organization)?,
            parent: optional_text(parent)?,
            resource_kind: optional_text(resource_kind)?,
            resource: optional_text(resource)?,
            expires_at: optional_i64(expires_at)?,
        })
    }

    fn decode_scope(&self, tenant: &TenantId) -> Result<AuthorizationScope, StorageError> {
        match self.scope_kind {
            "tenant" => self.tenant_scope(tenant),
            "tenant_resource" => self.tenant_resource_scope(tenant),
            "organization" => self.organization_scope(tenant),
            "resource" => self.resource_scope(tenant),
            _ => Err(integrity_failure()),
        }
    }

    fn tenant_scope(&self, tenant: &TenantId) -> Result<AuthorizationScope, StorageError> {
        require_none([
            self.organization,
            self.parent,
            self.resource_kind,
            self.resource,
        ])?;
        Ok(AuthorizationScope::tenant(tenant.clone()))
    }

    fn tenant_resource_scope(&self, tenant: &TenantId) -> Result<AuthorizationScope, StorageError> {
        require_none([self.organization, self.parent])?;
        Ok(AuthorizationScope::tenant_resource(
            tenant.clone(),
            ResourceKind::parse(self.resource_kind.ok_or_else(integrity_failure)?)
                .map_err(|_| integrity_failure())?,
            ResourceId::parse(self.resource.ok_or_else(integrity_failure)?)
                .map_err(|_| integrity_failure())?,
        ))
    }

    fn organization_scope(&self, tenant: &TenantId) -> Result<AuthorizationScope, StorageError> {
        require_none([self.parent, self.resource_kind, self.resource])?;
        let organization = OrganizationId::parse(self.organization.ok_or_else(integrity_failure)?)
            .map_err(|_| integrity_failure())?;
        Ok(AuthorizationScope::organization(
            tenant.clone(),
            organization,
        ))
    }

    fn resource_scope(&self, tenant: &TenantId) -> Result<AuthorizationScope, StorageError> {
        let organization = OrganizationId::parse(self.organization.ok_or_else(integrity_failure)?)
            .map_err(|_| integrity_failure())?;
        let parent = self
            .parent
            .map(ResourceId::parse)
            .transpose()
            .map_err(|_| integrity_failure())?;
        let kind = ResourceKind::parse(self.resource_kind.ok_or_else(integrity_failure)?)
            .map_err(|_| integrity_failure())?;
        let resource = ResourceId::parse(self.resource.ok_or_else(integrity_failure)?)
            .map_err(|_| integrity_failure())?;
        AuthorizationScope::resource(tenant.clone(), organization, parent, kind, resource)
            .map_err(|_| integrity_failure())
    }
}

fn require_none<const N: usize>(values: [Option<&str>; N]) -> Result<(), StorageError> {
    if values.iter().all(Option::is_none) {
        return Ok(());
    }
    Err(integrity_failure())
}

pub(super) fn load_events(
    session: &mut LocalSession,
    tenant: &TenantId,
    maximum_rows: u64,
    context: &RequestContext,
    #[cfg(feature = "test-hooks")] history_test_hooks: &HistoryTestHooks,
) -> Result<Vec<PersistedPolicyEvent>, StorageError> {
    check_context(context)?;
    let output = sql::load_events(session, tenant)?;
    #[cfg(feature = "test-hooks")]
    history_test_hooks.cancel_after_event_history_query_if_armed(context);
    check_context(context)?;
    let batch = rows(output)?;
    validate_columns(batch.columns(), &event::event_columns())?;
    validate_event_row_count(batch.rows().len(), maximum_rows)?;
    #[cfg(feature = "test-hooks")]
    history_test_hooks.record_event_history_decode();
    event::decode_events(batch.rows(), tenant)
}

fn validate_event_row_count(row_count: usize, maximum_rows: u64) -> Result<(), StorageError> {
    let row_count = u64::try_from(row_count).map_err(|_| resource_exhausted())?;
    if row_count > maximum_rows {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn validate_history(
    events: &[PersistedPolicyEvent],
    version: PolicyVersion,
) -> Result<(), StorageError> {
    let expected = expected_history_rows(version)?;
    if events.len() != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

fn expected_history_rows(version: PolicyVersion) -> Result<usize, StorageError> {
    if version.get() > MAX_AUTHORIZATION_POLICY_EVENT_HISTORY_ROWS {
        return Err(resource_exhausted());
    }
    usize::try_from(version.get()).map_err(|_| integrity_failure())
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

pub(super) fn decode_version(value: &str) -> Result<PolicyVersion, StorageError> {
    if value.len() != VERSION_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(integrity_failure());
    }
    let parsed = value.parse::<u64>().map_err(|_| integrity_failure())?;
    let version = PolicyVersion::new(parsed).map_err(|_| integrity_failure())?;
    if sql::encode_version(version) != value {
        return Err(integrity_failure());
    }
    Ok(version)
}

fn decode_effect(value: &str) -> Result<PermissionEffect, StorageError> {
    match value {
        "allow" => Ok(PermissionEffect::Allow),
        "deny" => Ok(PermissionEffect::Deny),
        _ => Err(integrity_failure()),
    }
}

fn validate_tenant(found: &str, tenant: &TenantId) -> Result<(), StorageError> {
    if found != tenant.as_str() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_ordinal(found: i64, expected: usize) -> Result<(), StorageError> {
    if usize::try_from(found).ok() != Some(expected) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn optional_i64(value: &SqlValue) -> Result<Option<i64>, StorageError> {
    match value {
        SqlValue::Int64(value) => Ok(Some(*value)),
        SqlValue::Null => Ok(None),
        _ => Err(integrity_failure()),
    }
}

fn optional_text(value: &SqlValue) -> Result<Option<&str>, StorageError> {
    match value {
        SqlValue::Text(value) => Ok(Some(value)),
        SqlValue::Null => Ok(None),
        _ => Err(integrity_failure()),
    }
}

fn rows(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn validate_columns(
    columns: &[ColumnSchema],
    expected: &[(&str, SqlType)],
) -> Result<(), StorageError> {
    let valid = columns.len() == expected.len()
        && columns.iter().zip(expected).all(|(column, expected)| {
            column.name() == expected.0 && column.data_type() == &expected.1
        });
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn header_columns() -> [(&'static str, SqlType); 2] {
    [("tenant_id", SqlType::Text), ("version", SqlType::Text)]
}

fn role_columns() -> [(&'static str, SqlType); 3] {
    [
        ("tenant_id", SqlType::Text),
        ("role_ordinal", SqlType::Int64),
        ("role_id", SqlType::Text),
    ]
}

fn rule_columns() -> [(&'static str, SqlType); 5] {
    [
        ("tenant_id", SqlType::Text),
        ("role_id", SqlType::Text),
        ("rule_ordinal", SqlType::Int64),
        ("permission_id", SqlType::Text),
        ("effect", SqlType::Text),
    ]
}

fn assignment_columns() -> [(&'static str, SqlType); 12] {
    [
        ("tenant_id", SqlType::Text),
        ("assignment_ordinal", SqlType::Int64),
        ("assignment_id", SqlType::Text),
        ("principal_id", SqlType::Text),
        ("membership_id", SqlType::Text),
        ("role_id", SqlType::Text),
        ("scope_kind", SqlType::Text),
        ("scope_organization_id", SqlType::Text),
        ("scope_parent_resource_id", SqlType::Text),
        ("scope_resource_kind", SqlType::Text),
        ("scope_resource_id", SqlType::Text),
        ("expires_at", SqlType::Int64),
    ]
}

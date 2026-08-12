// crates/optional/ariadnion-storage-rnmdb/src/rbac_repository/evidence/snapshot.rs - Rust source for Ariadnion.
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
//! Incremental canonical hashing for complete authorization-policy snapshots.

use ariadnion_rbac::{
    AuthorizationPolicySnapshot, AuthorizationScope, PermissionEffect, RoleAssignmentSnapshot,
    RoleDefinitionSnapshot,
};
use ariadnion_storage_domain::StorageError;
use ariadnion_user_domain::UtcTimestamp;
use sha2::{Digest, Sha256};

use super::integrity_failure;

const SNAPSHOT_DOMAIN: &[u8] = b"ariadnion.rbac.policy-snapshot.v1";

pub(super) fn snapshot_digest(
    snapshot: &AuthorizationPolicySnapshot,
) -> Result<[u8; 32], StorageError> {
    let mut hasher = SnapshotHasher::new();
    hasher.text(snapshot.tenant_id().as_str())?;
    hasher.u64(snapshot.version().get())?;
    hash_roles(&mut hasher, snapshot.roles())?;
    hash_assignments(&mut hasher, snapshot.assignments())?;
    Ok(hasher.finish())
}

fn hash_roles(
    hasher: &mut SnapshotHasher,
    roles: &[RoleDefinitionSnapshot],
) -> Result<(), StorageError> {
    hasher.len(roles.len())?;
    for role in roles {
        hash_role(hasher, role)?;
    }
    Ok(())
}

fn hash_role(
    hasher: &mut SnapshotHasher,
    role: &RoleDefinitionSnapshot,
) -> Result<(), StorageError> {
    hasher.text(role.id().as_str())?;
    hasher.text(role.tenant_id().as_str())?;
    hasher.len(role.rules().len())?;
    for rule in role.rules() {
        hash_rule(hasher, rule)?;
    }
    Ok(())
}

fn hash_rule(
    hasher: &mut SnapshotHasher,
    rule: &ariadnion_rbac::PermissionRule,
) -> Result<(), StorageError> {
    hasher.text(rule.permission_id().as_str())?;
    hasher.marker(effect_marker(rule.effect()))
}

fn hash_assignments(
    hasher: &mut SnapshotHasher,
    assignments: &[RoleAssignmentSnapshot],
) -> Result<(), StorageError> {
    hasher.len(assignments.len())?;
    for assignment in assignments {
        hash_assignment(hasher, assignment)?;
    }
    Ok(())
}

fn hash_assignment(
    hasher: &mut SnapshotHasher,
    assignment: &RoleAssignmentSnapshot,
) -> Result<(), StorageError> {
    hasher.text(assignment.id().as_str())?;
    hasher.text(assignment.principal_id().as_str())?;
    hasher.text(assignment.membership_id().as_str())?;
    hasher.text(assignment.role_id().as_str())?;
    hash_scope(hasher, assignment.scope())?;
    hasher.optional_i64(assignment.expires_at().map(UtcTimestamp::unix_seconds))
}

fn hash_scope(hasher: &mut SnapshotHasher, scope: &AuthorizationScope) -> Result<(), StorageError> {
    match scope {
        AuthorizationScope::Tenant { tenant_id } => hash_tenant_scope(hasher, tenant_id),
        AuthorizationScope::TenantResource {
            tenant_id,
            resource_kind,
            resource_id,
        } => hash_tenant_resource_scope(hasher, tenant_id, resource_kind, resource_id),
        AuthorizationScope::Organization {
            tenant_id,
            organization_id,
        } => hash_organization_scope(hasher, tenant_id, organization_id),
        AuthorizationScope::Resource {
            tenant_id,
            organization_id,
            parent_resource_id,
            resource_kind,
            resource_id,
        } => hash_resource_scope(
            hasher,
            tenant_id,
            organization_id,
            parent_resource_id.as_ref().map(|id| id.as_str()),
            resource_kind,
            resource_id,
        ),
    }
}

fn hash_tenant_scope(
    hasher: &mut SnapshotHasher,
    tenant: &ariadnion_core::TenantId,
) -> Result<(), StorageError> {
    hasher.marker(0)?;
    hasher.text(tenant.as_str())
}

fn hash_tenant_resource_scope(
    hasher: &mut SnapshotHasher,
    tenant: &ariadnion_core::TenantId,
    kind: &ariadnion_rbac::ResourceKind,
    resource: &ariadnion_rbac::ResourceId,
) -> Result<(), StorageError> {
    hasher.marker(1)?;
    hasher.text(tenant.as_str())?;
    hasher.text(kind.as_str())?;
    hasher.text(resource.as_str())
}

fn hash_organization_scope(
    hasher: &mut SnapshotHasher,
    tenant: &ariadnion_core::TenantId,
    organization: &ariadnion_organization::OrganizationId,
) -> Result<(), StorageError> {
    hasher.marker(2)?;
    hasher.text(tenant.as_str())?;
    hasher.text(organization.as_str())
}

fn hash_resource_scope(
    hasher: &mut SnapshotHasher,
    tenant: &ariadnion_core::TenantId,
    organization: &ariadnion_organization::OrganizationId,
    parent: Option<&str>,
    kind: &ariadnion_rbac::ResourceKind,
    resource: &ariadnion_rbac::ResourceId,
) -> Result<(), StorageError> {
    hasher.marker(3)?;
    hasher.text(tenant.as_str())?;
    hasher.text(organization.as_str())?;
    hasher.optional_text(parent)?;
    hasher.text(kind.as_str())?;
    hasher.text(resource.as_str())
}

struct SnapshotHasher {
    digest: Sha256,
}

impl SnapshotHasher {
    fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(SNAPSHOT_DOMAIN);
        Self { digest }
    }

    fn field(&mut self, value: &[u8]) -> Result<(), StorageError> {
        let length = u64::try_from(value.len()).map_err(|_| integrity_failure())?;
        self.digest.update(length.to_be_bytes());
        self.digest.update(value);
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), StorageError> {
        self.field(value.as_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), StorageError> {
        self.field(&value.to_be_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), StorageError> {
        self.u64(u64::try_from(value).map_err(|_| integrity_failure())?)
    }

    fn marker(&mut self, value: u8) -> Result<(), StorageError> {
        self.field(&[value])
    }

    fn optional_i64(&mut self, value: Option<i64>) -> Result<(), StorageError> {
        match value {
            Some(value) => {
                self.marker(1)?;
                self.field(&value.to_be_bytes())
            }
            None => self.marker(0),
        }
    }

    fn optional_text(&mut self, value: Option<&str>) -> Result<(), StorageError> {
        match value {
            Some(value) => {
                self.marker(1)?;
                self.text(value)
            }
            None => self.marker(0),
        }
    }

    fn finish(self) -> [u8; 32] {
        self.digest.finalize().into()
    }
}

const fn effect_marker(effect: PermissionEffect) -> u8 {
    match effect {
        PermissionEffect::Allow => 0,
        PermissionEffect::Deny => 1,
    }
}

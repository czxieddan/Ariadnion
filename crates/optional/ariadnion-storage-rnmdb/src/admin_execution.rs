// crates/optional/ariadnion-storage-rnmdb/src/admin_execution.rs - Rust source for Ariadnion.
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
//! Typed administration-execution capability owned by RNMDB storage.

use std::sync::Arc;

use ariadnion_api_admin::{AdminCommandExecutor, AdminExecutionPort};
use ariadnion_core::{
    CancellationToken, CapabilityId, CapabilityProvider, CoreError, ModuleId, ModuleVersion,
    PortHandle, PortKey, PortSlot,
};

use crate::{
    AuditSubjectKeyMaterial, RnmdbAdminCommandRepository, RnmdbAuthenticatedPrincipalValidator,
    RnmdbAuthoritativePolicyPort, RnmdbSessionOwner,
};

pub(super) const ADMIN_EXECUTION_CAPABILITY_ID: &str = "org.ariadnion.admin.execution";
const ADMIN_EXECUTION_PORT_NAME: &str = "org.ariadnion.admin.execution.port";
const PRIMARY_PROVIDER_PRIORITY: u16 = 0;

/// One lifecycle-owned typed slot for the durable administration executor.
#[derive(Clone)]
pub(super) struct AdminExecutionCapability {
    slot: Arc<PortSlot<dyn AdminExecutionPort>>,
}

impl AdminExecutionCapability {
    /// Creates an empty typed slot without publishing a provider.
    pub(super) fn new() -> Result<Self, CoreError> {
        let key = PortKey::new(ADMIN_EXECUTION_PORT_NAME)?;
        Ok(Self {
            slot: Arc::new(PortSlot::new(key)),
        })
    }

    /// Resolves the current generation only after successful publication.
    pub(super) fn resolve(&self) -> Result<PortHandle<dyn AdminExecutionPort>, CoreError> {
        self.slot.resolve()
    }

    /// Constructs and publishes the sole executor over the live storage owner.
    pub(super) fn publish(
        &self,
        session: Arc<RnmdbSessionOwner>,
        audit_subject_key: AuditSubjectKeyMaterial,
        cancellation: CancellationToken,
    ) -> Result<(), CoreError> {
        let executor = build_executor(session, audit_subject_key);
        let _published = self
            .slot
            .register(PRIMARY_PROVIDER_PRIORITY, executor, cancellation)?;
        Ok(())
    }

    /// Invalidates every resolved generation before storage shutdown begins.
    pub(super) fn invalidate(&self) -> Result<(), CoreError> {
        self.slot.invalidate().map(|_generation| ())
    }
}

pub(super) fn admin_execution_provider(
    module_id: &ModuleId,
    version: ModuleVersion,
) -> Result<CapabilityProvider, CoreError> {
    Ok(CapabilityProvider::new(
        CapabilityId::parse(ADMIN_EXECUTION_CAPABILITY_ID)?,
        version,
        module_id.clone(),
    ))
}

fn build_executor(
    session: Arc<RnmdbSessionOwner>,
    audit_subject_key: AuditSubjectKeyMaterial,
) -> Arc<dyn AdminExecutionPort> {
    let policy_key = duplicate_audit_subject_key(&audit_subject_key);
    let authenticated_principals = RnmdbAuthenticatedPrincipalValidator::new(session.clone());
    let policies = RnmdbAuthoritativePolicyPort::new(session.clone(), policy_key);
    let repository = RnmdbAdminCommandRepository::new(session, audit_subject_key);
    Arc::new(AdminCommandExecutor::new(
        authenticated_principals,
        policies,
        repository,
    ))
}

fn duplicate_audit_subject_key(
    audit_subject_key: &AuditSubjectKeyMaterial,
) -> AuditSubjectKeyMaterial {
    AuditSubjectKeyMaterial::new(*audit_subject_key.as_bytes())
}

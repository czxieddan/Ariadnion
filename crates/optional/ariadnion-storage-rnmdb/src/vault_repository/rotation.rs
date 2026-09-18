// crates/optional/ariadnion-storage-rnmdb/src/vault_repository/rotation.rs - Durable credential rotations.
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
//! Bounded worker orchestration for durable credential-rotation journals.

mod codec;

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ariadnion_account_vault::{
    BoxVaultFuture, CredentialRotationPort, MAX_ROTATION_ID_BYTES, RotationMutationId,
    RotationMutationReceipt, RotationMutationRequest, RotationSnapshot, VaultError, VaultErrorCode,
};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_rbac::migrations::IDENTITY_RUNTIME_ROLE;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_security::ColumnKeyMaterial;
use zeroize::Zeroizing;

use super::worker::VaultWorker;
use super::{VaultKeyCustody, error, map_storage_error};
use crate::RnmdbSessionOwner;
use crate::identity_transaction::run_identity_transaction;
use crate::session::ColumnEncryptionTarget;

const PREVIOUS_PATH_TARGET: ColumnEncryptionTarget = ColumnEncryptionTarget::new(
    "public",
    "account_vault_rotation_journals",
    "previous_secret_path",
);
const NEXT_PATH_TARGET: ColumnEncryptionTarget = ColumnEncryptionTarget::new(
    "public",
    "account_vault_rotation_journals",
    "next_secret_path",
);

/// Operation class evaluated by the caller-injected rotation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultRotationAccess {
    /// Apply one durable state transition.
    Mutate,
    /// Reconcile an earlier mutation identity.
    Reconcile,
    /// Load a reconstructed rotation journal.
    Load,
}

/// Immutable authenticated inputs presented to rotation authorization policy.
pub struct VaultRotationAuthorizationRequest<'a> {
    /// Full request context, including authenticated actor and cancellation.
    pub context: &'a RequestContext,
    /// Exact tenant derived from the authenticated principal.
    pub tenant: &'a TenantId,
    /// Opaque rotation identity being accessed.
    pub rotation_id: Option<&'a str>,
    /// Requested durable operation.
    pub access: VaultRotationAccess,
}

/// Fail-closed policy boundary for durable credential rotation.
pub trait VaultRotationAccessPolicy: Send + Sync {
    /// Authorizes one current operation without granting future transitions.
    ///
    /// # Errors
    /// Uncertainty must return a redacted denial or availability error.
    fn authorize(&self, request: VaultRotationAuthorizationRequest<'_>) -> Result<(), VaultError>;
}

/// Clock boundary used for overlap enforcement and durable receipt publication.
pub trait VaultRotationClock: Send + Sync {
    /// Returns the current UTC time representable at microsecond precision.
    fn now(&self) -> SystemTime;
}

/// Production UTC clock truncated to the RNMDB microsecond representation.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemVaultRotationClock;

impl VaultRotationClock for SystemVaultRotationClock {
    fn now(&self) -> SystemTime {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_micros())
            .unwrap_or_default();
        let bounded = u64::try_from(micros).unwrap_or(u64::MAX);
        UNIX_EPOCH + Duration::from_micros(bounded)
    }
}

/// Single-consumption encrypted-path and mutation-fingerprint keys.
pub struct VaultRotationKeyMaterial {
    path: Zeroizing<[u8; 32]>,
    fingerprint: Zeroizing<[u8; 32]>,
}

impl VaultRotationKeyMaterial {
    /// Takes ownership of exact 256-bit path and mutation-fingerprint keys.
    ///
    /// The caller must supply independently derived keys from protected external
    /// custody. The path key must be recoverable across repository restarts so
    /// encrypted locators remain readable. The fingerprint key must remain stable
    /// while exact replay of existing mutation identities is required. Managed
    /// replacement requires re-encryption or a versioned fingerprint migration
    /// before constructing the repository with new material.
    #[must_use]
    pub fn new(path: [u8; 32], fingerprint: [u8; 32]) -> Self {
        Self {
            path: Zeroizing::new(path),
            fingerprint: Zeroizing::new(fingerprint),
        }
    }
}

impl Debug for VaultRotationKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultRotationKeyMaterial(<redacted>)")
    }
}

struct RotationEnvironment {
    policy: Arc<dyn VaultRotationAccessPolicy>,
    custody: Arc<dyn VaultKeyCustody>,
    clock: Arc<dyn VaultRotationClock>,
    fingerprint: Zeroizing<[u8; 32]>,
}

/// Durable tenant-scoped credential-rotation repository.
///
/// Blocking embedded database work runs on one bounded vault worker. Every
/// mutation is reauthorized immediately before transaction entry, records an
/// immutable keyed request fingerprint, compares the expected revision, and
/// publishes the journal and replay receipt in the same durable transaction.
pub struct RnmdbCredentialRotationRepository {
    session: Arc<RnmdbSessionOwner>,
    worker: VaultWorker,
    environment: Arc<RotationEnvironment>,
}

impl RnmdbCredentialRotationRepository {
    /// Configures encrypted rotation paths and starts the bounded worker.
    ///
    /// # Errors
    /// Returns a redacted error when context validation, key installation, or
    /// worker startup fails. A partially configured owner must be discarded.
    pub fn new(
        session: Arc<RnmdbSessionOwner>,
        keys: VaultRotationKeyMaterial,
        policy: Arc<dyn VaultRotationAccessPolicy>,
        custody: Arc<dyn VaultKeyCustody>,
        clock: Arc<dyn VaultRotationClock>,
        context: &RequestContext,
    ) -> Result<Self, VaultError> {
        context.check_active().map_err(VaultError::from)?;
        require_separate_keys(&keys)?;
        let worker = VaultWorker::start(session.clone())?;
        configure_rotation_paths(&session, &keys.path, context).inspect_err(|_| {
            session.quarantine_after_worker_panic();
        })?;
        Ok(Self {
            session,
            worker,
            environment: Arc::new(RotationEnvironment {
                policy,
                custody,
                clock,
                fingerprint: keys.fingerprint,
            }),
        })
    }

    /// Returns the serialized embedded owner used by the repository worker.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }

    fn submit<T: Send + 'static>(
        &self,
        rotation_id: Option<&str>,
        access: VaultRotationAccess,
        context: &RequestContext,
        action: impl FnOnce(
            &RnmdbSessionOwner,
            &RotationEnvironment,
            TenantId,
            RequestContext,
        ) -> Result<T, VaultError>
        + Send
        + 'static,
    ) -> BoxVaultFuture<'_, T> {
        let tenant = match authorize(
            self.environment.policy.as_ref(),
            rotation_id,
            access,
            context,
        ) {
            Ok(tenant) => tenant,
            Err(error) => return Box::pin(std::future::ready(Err(error))),
        };
        let cancellation = context.cancellation().child();
        let owned_context = RequestContext::new(
            context.request_id().clone(),
            context.trace_id().clone(),
            context.principal().cloned(),
            context.deadline(),
            cancellation.clone(),
        );
        let environment = self.environment.clone();
        let rotation_id = rotation_id.map(str::to_owned);
        self.worker.submit(cancellation, move |owner| {
            authorize(
                environment.policy.as_ref(),
                rotation_id.as_deref(),
                access,
                &owned_context,
            )?;
            action(owner, &environment, tenant, owned_context)
        })
    }
}

impl Debug for RnmdbCredentialRotationRepository {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbCredentialRotationRepository")
            .field("instance", self.session.instance())
            .finish_non_exhaustive()
    }
}

impl CredentialRotationPort for RnmdbCredentialRotationRepository {
    fn mutate<'a>(
        &'a self,
        request: RotationMutationRequest,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, RotationMutationReceipt> {
        let rotation_id = request.rotation_id().to_owned();
        self.submit(
            Some(&rotation_id),
            VaultRotationAccess::Mutate,
            context,
            move |owner, environment, tenant, context| {
                let now = environment.clock.now();
                context.check_active().map_err(VaultError::from)?;
                let mut boundary_error = None;
                let result = owner.with_identity_transaction_session(&context, &tenant, |local| {
                    run_identity_transaction(local, &context, |local| {
                        let receipt = codec::mutate(
                            local,
                            &tenant,
                            &request,
                            now,
                            &environment.fingerprint,
                            environment.custody.as_ref(),
                        )?;
                        record_authorization_boundary(
                            environment.policy.as_ref(),
                            request.rotation_id(),
                            &tenant,
                            &context,
                            &mut boundary_error,
                        )?;
                        Ok(receipt)
                    })
                });
                project_mutation_result(result, boundary_error)
            },
        )
    }

    fn reconcile<'a>(
        &'a self,
        mutation_id: &'a RotationMutationId,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, Option<RotationMutationReceipt>> {
        let mutation_id = mutation_id.clone();
        self.submit(
            None,
            VaultRotationAccess::Reconcile,
            context,
            move |owner, environment, tenant, context| {
                owner
                    .with_identity_storage_session(&context, &tenant, |local| {
                        codec::load_mutation(
                            local,
                            &tenant,
                            &mutation_id,
                            environment.custody.as_ref(),
                        )
                    })
                    .map_err(map_storage_error)
            },
        )
    }

    fn load<'a>(
        &'a self,
        rotation_id: &'a str,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, Option<RotationSnapshot>> {
        if !valid_rotation_id(rotation_id) {
            return Box::pin(std::future::ready(Err(error(
                VaultErrorCode::InvalidArgument,
            ))));
        }
        let rotation_id = rotation_id.to_owned();
        let authorized_rotation_id = rotation_id.clone();
        self.submit(
            Some(&authorized_rotation_id),
            VaultRotationAccess::Load,
            context,
            move |owner, environment, tenant, context| {
                owner
                    .with_identity_storage_session(&context, &tenant, |local| {
                        codec::load_snapshot(
                            local,
                            &tenant,
                            &rotation_id,
                            environment.custody.as_ref(),
                        )
                    })
                    .map_err(map_storage_error)
            },
        )
    }
}

fn valid_rotation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ROTATION_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn require_separate_keys(keys: &VaultRotationKeyMaterial) -> Result<(), VaultError> {
    if keys.path.as_ref() == keys.fingerprint.as_ref() {
        return Err(error(VaultErrorCode::InvalidArgument));
    }
    Ok(())
}

fn configure_rotation_paths(
    owner: &RnmdbSessionOwner,
    key: &[u8; 32],
    context: &RequestContext,
) -> Result<(), VaultError> {
    configure_path(owner, PREVIOUS_PATH_TARGET, key, context)?;
    configure_path(owner, NEXT_PATH_TARGET, key, context)
}

fn configure_path(
    owner: &RnmdbSessionOwner,
    target: ColumnEncryptionTarget,
    key: &[u8; 32],
    context: &RequestContext,
) -> Result<(), VaultError> {
    owner
        .configure_column_encryption_once(
            target,
            ColumnKeyMaterial::from_bytes(*key),
            Some(IDENTITY_RUNTIME_ROLE),
            context,
        )
        .map_err(map_storage_error)
}

fn authorize(
    policy: &dyn VaultRotationAccessPolicy,
    rotation_id: Option<&str>,
    access: VaultRotationAccess,
    context: &RequestContext,
) -> Result<TenantId, VaultError> {
    context.check_active().map_err(VaultError::from)?;
    let tenant = context
        .principal()
        .map(|principal| principal.tenant_id())
        .ok_or_else(|| error(VaultErrorCode::Unauthenticated))?;
    policy.authorize(VaultRotationAuthorizationRequest {
        context,
        tenant,
        rotation_id,
        access,
    })?;
    context.check_active().map_err(VaultError::from)?;
    Ok(tenant.clone())
}

fn record_authorization_boundary(
    policy: &dyn VaultRotationAccessPolicy,
    rotation_id: &str,
    tenant: &TenantId,
    context: &RequestContext,
    boundary_error: &mut Option<VaultError>,
) -> Result<(), StorageError> {
    let decision = authorize(
        policy,
        Some(rotation_id),
        VaultRotationAccess::Mutate,
        context,
    )
    .and_then(|current| {
        if &current == tenant {
            Ok(())
        } else {
            Err(error(VaultErrorCode::PermissionDenied))
        }
    });
    decision.map_err(|error| {
        *boundary_error = Some(error);
        StorageError::new(StorageErrorCode::InvalidArgument)
    })
}

fn project_mutation_result<T>(
    result: Result<T, StorageError>,
    boundary_error: Option<VaultError>,
) -> Result<T, VaultError> {
    match (result, boundary_error) {
        (Err(storage), Some(error)) if storage.code() == StorageErrorCode::InvalidArgument => {
            Err(error)
        }
        (result, _) => result.map_err(map_storage_error),
    }
}

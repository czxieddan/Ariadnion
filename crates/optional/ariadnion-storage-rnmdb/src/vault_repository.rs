// crates/optional/ariadnion-storage-rnmdb/src/vault_repository.rs - Encrypted vault adapter for Ariadnion.
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
//! Tenant-scoped encrypted vault persistence and explicit custody boundaries.

mod codec;
mod custody;
mod rotation;
mod sql;
mod worker;

pub use custody::{MAX_VAULT_CUSTODY_KEYS, RnmdbVaultKeyCustody, VaultCustodyKey};
pub use rotation::{
    RnmdbCredentialRotationRepository, SystemVaultRotationClock, VaultRotationAccess,
    VaultRotationAccessPolicy, VaultRotationAuthorizationRequest, VaultRotationClock,
    VaultRotationKeyMaterial,
};

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_account_vault::{
    BoxVaultFuture, EncryptedSecretEnvelope, SecretLease, SecretLeaseId, SecretMaterial,
    SecretReadRequest, SecretRef, SecretRevokeReceipt, SecretStoreReceipt, SecretStoreRequest,
    VaultError, VaultErrorCode, VaultMutationReceipt, VaultPort, VaultRevokeRequest,
};
use ariadnion_core::{ModuleId, RequestContext, TenantId};
use ariadnion_rbac::migrations::IDENTITY_RUNTIME_ROLE;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_security::ColumnKeyMaterial;
use zeroize::Zeroizing;

use crate::RnmdbSessionOwner;
use crate::identity_transaction::run_identity_transaction;
use crate::session::ColumnEncryptionTarget;

/// The operation being authorized by the caller-injected vault policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultOperation {
    /// Issue one short plaintext lease.
    Read,
    /// Store one authenticated ciphertext envelope.
    Store,
    /// Revoke one immutable secret version.
    Revoke,
    /// Recover durable mutation evidence.
    Reconcile,
}

/// Immutable tenant, actor, module, and purpose inputs for vault policy.
///
/// A read always provides its final consumer module. Mutation authorization
/// remains actor- and reference-bound and does not invent a consumer module.
pub struct VaultAuthorizationRequest<'a> {
    /// Authenticated request context, including actor and cancellation.
    pub context: &'a RequestContext,
    /// Exact tenant taken from the authenticated principal.
    pub tenant: &'a TenantId,
    /// Exact purpose-bound secret identity.
    pub reference: &'a SecretRef,
    /// Final consumer identity, present only for reads.
    pub module: Option<&'a ModuleId>,
    /// Requested operation.
    pub operation: VaultOperation,
}

/// Explicit fail-closed policy boundary for every vault operation.
///
/// Implementations must authorize the authenticated actor, tenant, provider,
/// exact reference purpose, and read module against an authoritative policy.
/// Returning success grants only this operation, never subsequent operations.
pub trait VaultAccessPolicy: Send + Sync {
    /// Authorizes one operation without logging paths or secret material.
    ///
    /// # Errors
    /// Return a redacted denial or availability error; uncertainty fails closed.
    fn authorize(&self, request: VaultAuthorizationRequest<'_>) -> Result<(), VaultError>;
}

/// External cryptography and key-custody boundary.
///
/// Key bytes are never persisted or supplied to this repository. Implementations
/// must use a reviewed authenticated-encryption primitive, bind tenant and all
/// reference fields as authenticated data, enforce key-version lifecycle, and
/// return owned zeroizing plaintext only after authentication succeeds.
pub trait VaultKeyCustody: Send + Sync {
    /// Computes a stable keyed 256-bit locator digest for this tenant/reference.
    ///
    /// This must use a custody-owned secret lookup key, not an unkeyed path hash,
    /// so persistent indexes do not expose dictionary-testable secret locators.
    fn reference_digest(
        &self,
        tenant: &TenantId,
        reference: &SecretRef,
    ) -> Result<[u8; 32], VaultError>;

    /// Authenticates and decrypts a bounded envelope using custody-owned keys.
    ///
    /// # Errors
    /// Unknown, retired, or unavailable keys fail closed. Authentication failures
    /// return an integrity error without retaining ciphertext, plaintext, or keys.
    fn decrypt(
        &self,
        tenant: &TenantId,
        reference: &SecretRef,
        envelope: &EncryptedSecretEnvelope,
    ) -> Result<SecretMaterial, VaultError>;

    /// Computes a keyed, domain-separated digest for immutable mutation input.
    ///
    /// The payload is a bounded envelope digest or explicit revoke reason;
    /// only store and revoke operations are valid. The default fails closed.
    fn mutation_fingerprint(
        &self,
        _tenant: &TenantId,
        _reference: &SecretRef,
        _operation: VaultOperation,
        _payload: &[u8],
    ) -> Result<[u8; 32], VaultError> {
        Err(error(VaultErrorCode::Unavailable))
    }
}

/// Single-consumption RNMDB column keys; no wrapping or envelope keys are stored.
///
/// The path key configures both encrypted reference-path columns. The nonce and
/// ciphertext keys configure their dedicated envelope columns. RNMDB owns key
/// copies for the embedded session lifetime; this set zeroizes on drop.
pub struct VaultColumnKeySet {
    path: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 32]>,
    ciphertext: Zeroizing<[u8; 32]>,
}

impl VaultColumnKeySet {
    /// Takes ownership of three exact 256-bit column keys from external custody.
    #[must_use]
    pub fn new(path: [u8; 32], nonce: [u8; 32], ciphertext: [u8; 32]) -> Self {
        Self {
            path: Zeroizing::new(path),
            nonce: Zeroizing::new(nonce),
            ciphertext: Zeroizing::new(ciphertext),
        }
    }

    fn configure(
        &self,
        owner: &RnmdbSessionOwner,
        context: &RequestContext,
    ) -> Result<(), VaultError> {
        configure(
            owner,
            "account_vault_secrets",
            "secret_path",
            &self.path,
            context,
        )?;
        configure(
            owner,
            "account_vault_mutations",
            "secret_path",
            &self.path,
            context,
        )?;
        configure(
            owner,
            "account_vault_secrets",
            "nonce_hex",
            &self.nonce,
            context,
        )?;
        configure(
            owner,
            "account_vault_secrets",
            "ciphertext_hex",
            &self.ciphertext,
            context,
        )
    }
}

impl Debug for VaultColumnKeySet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultColumnKeySet(<redacted>)")
    }
}

/// Durable encrypted vault adapter with one bounded blocking worker.
///
/// No plaintext is returned before a tenant-scoped access event is durably
/// committed. Writes bind replay evidence to the authenticated request ID and
/// exact reference; ambiguous commits require reopening a quarantined session
/// and reconciling with the same request ID and reference. Revocation blocks
/// new leases, while already issued leases retain their bounded expiry.
pub struct RnmdbVaultRepository {
    session: Arc<RnmdbSessionOwner>,
    policy: Arc<dyn VaultAccessPolicy>,
    custody: Arc<dyn VaultKeyCustody>,
    worker: worker::VaultWorker,
}

impl RnmdbVaultRepository {
    /// Configures encrypted columns and starts a bounded dedicated worker.
    ///
    /// # Errors
    /// Context, key configuration, or worker failures return redacted errors.
    /// A partially configured owner must be discarded, never retried with keys
    /// that could differ from the already installed session keys.
    pub fn new(
        session: Arc<RnmdbSessionOwner>,
        columns: VaultColumnKeySet,
        policy: Arc<dyn VaultAccessPolicy>,
        custody: Arc<dyn VaultKeyCustody>,
        context: &RequestContext,
    ) -> Result<Self, VaultError> {
        context.check_active().map_err(VaultError::from)?;
        let worker = worker::VaultWorker::start(session.clone())?;
        columns.configure(&session, context).inspect_err(|_| {
            // A partial installation cannot be retried with unknown key state.
            session.quarantine_after_worker_panic();
        })?;
        Ok(Self {
            session,
            policy,
            custody,
            worker,
        })
    }

    /// Returns the serialized embedded owner for shutdown coordination.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }

    fn submit<T: Send + 'static>(
        &self,
        reference: &SecretRef,
        module: Option<&ModuleId>,
        operation: VaultOperation,
        context: &RequestContext,
        action: impl FnOnce(
            &RnmdbSessionOwner,
            &TenantId,
            &RequestContext,
            &dyn VaultKeyCustody,
        ) -> Result<T, VaultError>
        + Send
        + 'static,
    ) -> BoxVaultFuture<'_, T> {
        let admission = authorize(self.policy.as_ref(), reference, module, operation, context);
        let tenant = match admission {
            Ok(tenant) => tenant,
            Err(error) => return Box::pin(std::future::ready(Err(error))),
        };
        let cancellation = context.cancellation().child();
        let context = RequestContext::new(
            context.request_id().clone(),
            context.trace_id().clone(),
            context.principal().cloned(),
            context.deadline(),
            cancellation.clone(),
        );
        let custody = self.custody.clone();
        let policy = self.policy.clone();
        let reference = reference.clone();
        let module = module.cloned();
        self.worker.submit(cancellation, move |owner| {
            authorize(
                policy.as_ref(),
                &reference,
                module.as_ref(),
                operation,
                &context,
            )?;
            action(owner, &tenant, &context, custody.as_ref())
        })
    }
}

impl Debug for RnmdbVaultRepository {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbVaultRepository")
            .field("instance", self.session.instance())
            .finish_non_exhaustive()
    }
}

impl VaultPort for RnmdbVaultRepository {
    fn read<'a>(
        &'a self,
        request: SecretReadRequest,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, SecretLease> {
        let reference = request.reference().clone();
        let module = request.module().clone();
        self.submit(
            &reference,
            Some(&module),
            VaultOperation::Read,
            context,
            move |owner, tenant, context, custody| {
                let digest = custody.reference_digest(tenant, request.reference())?;
                owner
                    .with_identity_transaction_session(context, tenant, |local| {
                        run_identity_transaction(local, context, |local| {
                            codec::read(local, tenant, &request, &digest, context, custody)
                        })
                    })
                    .map_err(map_storage_error)
            },
        )
    }

    fn store<'a>(
        &'a self,
        request: SecretStoreRequest,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, SecretStoreReceipt> {
        let reference = request.reference().clone();
        self.submit(
            &reference,
            None,
            VaultOperation::Store,
            context,
            move |owner, tenant, context, custody| {
                let digest = custody.reference_digest(tenant, request.reference())?;
                owner
                    .with_identity_transaction_session(context, tenant, |local| {
                        run_identity_transaction(local, context, |local| {
                            codec::store(local, tenant, &request, &digest, context, custody)
                        })
                    })
                    .map_err(map_storage_error)
            },
        )
    }

    fn revoke<'a>(
        &'a self,
        request: VaultRevokeRequest,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, SecretRevokeReceipt> {
        let reference = request.reference().clone();
        self.submit(
            &reference,
            None,
            VaultOperation::Revoke,
            context,
            move |owner, tenant, context, custody| {
                let digest = custody.reference_digest(tenant, request.reference())?;
                owner
                    .with_identity_transaction_session(context, tenant, |local| {
                        run_identity_transaction(local, context, |local| {
                            codec::revoke(local, tenant, &request, &digest, context, custody)
                        })
                    })
                    .map_err(map_storage_error)
            },
        )
    }

    fn reconcile<'a>(
        &'a self,
        reference: SecretRef,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, Option<VaultMutationReceipt>> {
        let locator = reference.clone();
        self.submit(
            &locator,
            None,
            VaultOperation::Reconcile,
            context,
            move |owner, tenant, context, custody| {
                let digest = custody.reference_digest(tenant, &reference)?;
                owner
                    .with_identity_storage_session(context, tenant, |local| {
                        codec::reconcile(local, tenant, &reference, &digest, context)
                    })
                    .map_err(map_storage_error)
            },
        )
    }

    fn new_lease_id(&self) -> Result<SecretLeaseId, VaultError> {
        new_lease_id()
    }
}

fn configure(
    owner: &RnmdbSessionOwner,
    table: &'static str,
    column: &'static str,
    key: &[u8; 32],
    context: &RequestContext,
) -> Result<(), VaultError> {
    owner
        .configure_column_encryption_once(
            ColumnEncryptionTarget::new("public", table, column),
            ColumnKeyMaterial::from_bytes(*key),
            Some(IDENTITY_RUNTIME_ROLE),
            context,
        )
        .map_err(map_storage_error)
}

fn authorize(
    policy: &dyn VaultAccessPolicy,
    reference: &SecretRef,
    module: Option<&ModuleId>,
    operation: VaultOperation,
    context: &RequestContext,
) -> Result<TenantId, VaultError> {
    context.check_active().map_err(VaultError::from)?;
    let tenant = context
        .principal()
        .map(|principal| principal.tenant_id())
        .ok_or_else(|| error(VaultErrorCode::Unauthenticated))?;
    policy.authorize(VaultAuthorizationRequest {
        context,
        tenant,
        reference,
        module,
        operation,
    })?;
    context.check_active().map_err(VaultError::from)?;
    Ok(tenant.clone())
}

fn new_lease_id() -> Result<SecretLeaseId, VaultError> {
    let mut bytes = Zeroizing::new([0_u8; SecretLeaseId::BYTE_LENGTH]);
    getrandom::fill(bytes.as_mut()).map_err(|_| error(VaultErrorCode::Unavailable))?;
    Ok(SecretLeaseId::new(*bytes))
}

fn map_storage_error(value: StorageError) -> VaultError {
    let code = match value.code() {
        StorageErrorCode::InvalidArgument => VaultErrorCode::InvalidArgument,
        StorageErrorCode::Conflict => VaultErrorCode::Conflict,
        StorageErrorCode::Cancelled => VaultErrorCode::Cancelled,
        StorageErrorCode::DeadlineExceeded => VaultErrorCode::DeadlineExceeded,
        StorageErrorCode::ResourceExhausted => VaultErrorCode::ResourceExhausted,
        code => adapter_storage_code(code),
    };
    error(code)
}

fn adapter_storage_code(code: StorageErrorCode) -> VaultErrorCode {
    match code {
        StorageErrorCode::Unavailable | StorageErrorCode::MigrationRequired => {
            VaultErrorCode::Unavailable
        }
        StorageErrorCode::CommitIndeterminate => VaultErrorCode::CommitIndeterminate,
        StorageErrorCode::NotFound => VaultErrorCode::NotFound,
        _ => VaultErrorCode::IntegrityFailure,
    }
}

pub(super) const fn error(code: VaultErrorCode) -> VaultError {
    VaultError::new(code)
}

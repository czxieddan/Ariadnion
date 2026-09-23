// crates/optional/ariadnion-storage-rnmdb/src/account_proxy_repository.rs - Durable tenant proxy snapshots for Ariadnion.
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
//! Complete generation-checked proxy snapshots on the shared embedded session.

mod codec;
mod sql;

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_account_proxy::{
    MAX_PROFILES, ProxyExecutionSnapshot, ProxyGeneration, ProxyPersistenceError,
    ProxyPersistenceErrorCode, ProxyPublishReceipt, ProxyPublishRequest, ProxySnapshotStore,
};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_rbac::migrations::IDENTITY_RUNTIME_ROLE;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;
use rnmdb_security::ColumnKeyMaterial;
use rnmdb_types::SqlValue;
use zeroize::Zeroizing;

use crate::RnmdbSessionOwner;
use crate::identity_transaction::{require_active_identity_transaction, run_identity_transaction};
use crate::session::{ColumnEncryptionTarget, check_context};

/// Externally managed key for the encrypted proxy authentication path column.
///
/// Bytes are zeroized on drop and never persisted by Ariadnion. The same key
/// must be supplied when reopening the database; RNMDB owns its session copy.
pub struct AccountProxySecretPathKeyMaterial(Zeroizing<[u8; 32]>);

impl AccountProxySecretPathKeyMaterial {
    /// Takes ownership of exactly 32 externally managed key bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn into_upstream_key(self) -> ColumnKeyMaterial {
        ColumnKeyMaterial::from_bytes(*self.0)
    }
}

impl Debug for AccountProxySecretPathKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountProxySecretPathKeyMaterial(<redacted>)")
    }
}

/// One access to a tenant's durable proxy snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountProxyAccess {
    /// Reads the complete current snapshot.
    Load,
    /// Replaces the complete current snapshot.
    Publish,
}

/// Trusted fail-closed authorization for proxy persistence.
///
/// Authentication alone is not permission. Implementations must evaluate the
/// context's principal and tenant against current policy. Decisions are checked
/// before storage access and again before commit, while the session lock is held.
/// They must not reenter the session owner or a proxy publication book, or
/// acquire those locks in reverse order. Policy must remain valid through commit.
pub trait AccountProxyAuthorizationPort: Send + Sync {
    /// Authorizes this access or returns a redacted denial.
    ///
    /// # Errors
    /// Return `Unavailable` when authorization cannot be established. No
    /// rejected data or credentials may be included in the error.
    fn authorize(
        &self,
        access: AccountProxyAccess,
        context: &RequestContext,
    ) -> Result<(), ProxyPersistenceError>;
}

/// Shared-session owner of tenant-bound durable proxy store views.
///
/// This synchronous adapter must run on a blocking worker, not an async executor
/// thread. It does not create another RNMDB session, connection, or worker queue.
/// Reads and complete replacements hold the existing session lock through one
/// transaction. At most `MAX_PROFILES` profiles are accepted or reconstructed.
pub struct RnmdbAccountProxyRepository {
    session: Arc<RnmdbSessionOwner>,
    authorization: Arc<dyn AccountProxyAuthorizationPort>,
}

impl RnmdbAccountProxyRepository {
    /// Configures encrypted authentication paths once on the shared session.
    ///
    /// Install schema 27 first. Keys remain outside the database and must be
    /// reinjected after reopen. This constructor grants column decryption only
    /// to the existing tenant-scoped runtime role, not arbitrary caller roles.
    ///
    /// # Errors
    /// Fails closed on inactive or anonymous context, missing schema, repeated
    /// configuration, unavailable storage, or failed encryption setup.
    pub fn new(
        session: Arc<RnmdbSessionOwner>,
        key: AccountProxySecretPathKeyMaterial,
        authorization: Arc<dyn AccountProxyAuthorizationPort>,
        context: &RequestContext,
    ) -> Result<Self, ProxyPersistenceError> {
        admitted_tenant(context)?;
        session
            .configure_column_encryption_once(
                ColumnEncryptionTarget::new("public", "account_proxy_profiles", "auth_path"),
                key.into_upstream_key(),
                Some(IDENTITY_RUNTIME_ROLE),
                context,
            )
            .map_err(map_storage)?;
        Ok(Self {
            session,
            authorization,
        })
    }

    /// Binds the context-free domain port to an authenticated request tenant.
    ///
    /// No caller-supplied tenant override is accepted. The borrowed context
    /// keeps cancellation and deadline checks live through each operation.
    /// Authorization is evaluated on each call, not cached by this binding.
    ///
    /// # Errors
    /// Returns `Unavailable` for an inactive or anonymous context.
    pub fn bind<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> Result<RnmdbProxySnapshotStore<'a>, ProxyPersistenceError> {
        Ok(RnmdbProxySnapshotStore {
            repository: self,
            tenant: admitted_tenant(context)?,
            context,
        })
    }
}

impl Debug for RnmdbAccountProxyRepository {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbAccountProxyRepository")
            .field("instance", self.session.instance())
            .finish_non_exhaustive()
    }
}

/// A request- and tenant-bound view implementing the durable domain port.
///
/// Operations are synchronous and check cancellation/deadlines before access,
/// between profiles, and before commit. Since the domain port has no interruption
/// error variants, these failures map to `Unavailable`. An indeterminate commit
/// quarantines the shared owner: reopen with the same keys and load the actual
/// snapshot before deciding whether to retry. Never blindly republish on timeout.
/// A pristine tenant with no header or profiles starts at generation one, empty.
pub struct RnmdbProxySnapshotStore<'a> {
    repository: &'a RnmdbAccountProxyRepository,
    context: &'a RequestContext,
    tenant: TenantId,
}

impl ProxySnapshotStore for RnmdbProxySnapshotStore<'_> {
    fn load(&self) -> Result<ProxyExecutionSnapshot, ProxyPersistenceError> {
        self.execute(AccountProxyAccess::Load, |local| {
            load_snapshot(local, &self.tenant, self.context).map(|(_, snapshot)| snapshot)
        })
    }

    fn publish(
        &self,
        request: &ProxyPublishRequest,
    ) -> Result<ProxyPublishReceipt, ProxyPersistenceError> {
        self.execute(AccountProxyAccess::Publish, |local| {
            publish_snapshot(local, &self.tenant, self.context, request)
        })
    }
}

impl RnmdbProxySnapshotStore<'_> {
    fn execute<T>(
        &self,
        access: AccountProxyAccess,
        operation: impl FnOnce(&mut LocalSession) -> Result<T, StorageError>,
    ) -> Result<T, ProxyPersistenceError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.authorize(access).map_err(map_storage)?;
            self.repository
                .session
                .with_identity_transaction_session(self.context, &self.tenant, |local| {
                    run_identity_transaction(local, self.context, |local| {
                        let value = operation(local)?;
                        self.authorize(access)?;
                        Ok(value)
                    })
                })
                .map_err(map_storage)
        }));
        match result {
            Ok(result) => result,
            Err(_) => {
                self.repository.session.quarantine_after_worker_panic();
                Err(unavailable())
            }
        }
    }

    fn authorize(&self, access: AccountProxyAccess) -> Result<(), StorageError> {
        check_context(self.context)?;
        let decision = self
            .repository
            .authorization
            .authorize(access, self.context);
        check_context(self.context)?;
        decision.map_err(|_| StorageError::new(StorageErrorCode::Unavailable))
    }
}

fn admitted_tenant(context: &RequestContext) -> Result<TenantId, ProxyPersistenceError> {
    check_context(context).map_err(map_storage)?;
    context
        .principal()
        .map(|principal| principal.tenant_id().clone())
        .ok_or_else(unavailable)
}

fn map_storage(error: StorageError) -> ProxyPersistenceError {
    let code = match error.code() {
        StorageErrorCode::Conflict => ProxyPersistenceErrorCode::Conflict,
        StorageErrorCode::IntegrityFailure
        | StorageErrorCode::Internal
        | StorageErrorCode::InvalidArgument => ProxyPersistenceErrorCode::Corrupt,
        _ => ProxyPersistenceErrorCode::Unavailable,
    };
    ProxyPersistenceError::new(code)
}

const fn unavailable() -> ProxyPersistenceError {
    ProxyPersistenceError::new(ProxyPersistenceErrorCode::Unavailable)
}

struct SnapshotHeader {
    generation: ProxyGeneration,
    count: usize,
}

fn load_header(
    local: &mut LocalSession,
    tenant: &TenantId,
) -> Result<Option<SnapshotHeader>, StorageError> {
    let batch = sql::query(
        local,
        format!(
            "SELECT tenant_id, generation, profile_count FROM account_proxy_generations WHERE tenant_id = {} LIMIT 2;",
            sql::quote(tenant.as_str()).as_str(),
        ),
    )?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_header(row.values(), tenant).map(Some),
        _ => Err(sql::integrity()),
    }
}

fn decode_header(values: &[SqlValue], tenant: &TenantId) -> Result<SnapshotHeader, StorageError> {
    let values: &[SqlValue; 3] = values.try_into().map_err(|_| sql::integrity())?;
    sql::require_tenant(&values[0], tenant.as_str())?;
    let generation =
        ProxyGeneration::new(sql::version(&values[1])?).map_err(|_| sql::integrity())?;
    let count = usize::try_from(sql::integer(&values[2])?).map_err(|_| sql::integrity())?;
    require_header_bounds(generation, count)?;
    Ok(SnapshotHeader { generation, count })
}

fn require_header_bounds(generation: ProxyGeneration, count: usize) -> Result<(), StorageError> {
    if count > MAX_PROFILES || generation == ProxyGeneration::initial() {
        return Err(sql::integrity());
    }
    Ok(())
}

fn load_snapshot(
    local: &mut LocalSession,
    tenant: &TenantId,
    context: &RequestContext,
) -> Result<(bool, ProxyExecutionSnapshot), StorageError> {
    require_active_identity_transaction(local)?;
    let stored = load_header(local, tenant)?;
    let exists = stored.is_some();
    let header = stored.unwrap_or(SnapshotHeader {
        generation: ProxyGeneration::initial(),
        count: 0,
    });
    let batch = sql::query(
        local,
        format!(
            "SELECT {} FROM account_proxy_profiles WHERE tenant_id = {} ORDER BY profile_id LIMIT {};",
            codec::COLUMNS,
            sql::quote(tenant.as_str()).as_str(),
            MAX_PROFILES + 1,
        ),
    )?;
    if batch.rows().len() != header.count {
        return Err(sql::integrity());
    }
    Ok((
        exists,
        decode_snapshot(batch.rows(), &header, tenant, context)?,
    ))
}

fn decode_snapshot(
    rows: &[Row],
    header: &SnapshotHeader,
    tenant: &TenantId,
    context: &RequestContext,
) -> Result<ProxyExecutionSnapshot, StorageError> {
    let mut profiles = Vec::with_capacity(header.count);
    for row in rows {
        check_context(context)?;
        profiles.push(codec::decode(row, tenant, header.generation)?);
    }
    ProxyExecutionSnapshot::new(header.generation, profiles).map_err(|_| sql::integrity())
}

fn publish_snapshot(
    local: &mut LocalSession,
    tenant: &TenantId,
    context: &RequestContext,
    request: &ProxyPublishRequest,
) -> Result<ProxyPublishReceipt, StorageError> {
    let (exists, previous) = load_snapshot(local, tenant, context)?;
    require_successor(&previous, request)?;
    replace_profiles(local, tenant, context, &previous, request.snapshot())?;
    persist_header(local, tenant, exists, request)?;
    Ok(ProxyPublishReceipt::committed(
        request.snapshot().generation(),
    ))
}

fn replace_profiles(
    local: &mut LocalSession,
    tenant: &TenantId,
    context: &RequestContext,
    previous: &ProxyExecutionSnapshot,
    next: &ProxyExecutionSnapshot,
) -> Result<(), StorageError> {
    let delete = Zeroizing::new(format!(
        "DELETE FROM account_proxy_profiles WHERE tenant_id = {};",
        sql::quote(tenant.as_str()).as_str(),
    ));
    sql::require_affected(sql::execute(local, delete)?, previous.profiles().len())?;
    for profile in next.profiles() {
        check_context(context)?;
        sql::require_affected(
            sql::execute(local, codec::insert(tenant, next.generation(), profile)?)?,
            1,
        )?;
    }
    Ok(())
}

fn require_successor(
    previous: &ProxyExecutionSnapshot,
    request: &ProxyPublishRequest,
) -> Result<(), StorageError> {
    if previous.generation() != request.expected_generation() {
        return Err(sql::conflict());
    }
    let next = previous.generation().next().map_err(|_| sql::conflict())?;
    if request.snapshot().generation() != next {
        return Err(sql::conflict());
    }
    Ok(())
}

fn persist_header(
    local: &mut LocalSession,
    tenant: &TenantId,
    exists: bool,
    request: &ProxyPublishRequest,
) -> Result<(), StorageError> {
    let next = request.snapshot();
    let statement = if exists {
        format!(
            "UPDATE account_proxy_generations SET generation = '{}', profile_count = {} WHERE tenant_id = {} AND generation = '{}';",
            next.generation().get(),
            next.profiles().len(),
            sql::quote(tenant.as_str()).as_str(),
            request.expected_generation().get(),
        )
    } else {
        format!(
            "INSERT INTO account_proxy_generations (tenant_id, generation, profile_count) VALUES ({}, '{}', {});",
            sql::quote(tenant.as_str()).as_str(),
            next.generation().get(),
            next.profiles().len(),
        )
    };
    sql::require_affected(sql::execute(local, Zeroizing::new(statement))?, 1)
}

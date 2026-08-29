// crates/optional/ariadnion-storage-rnmdb/src/file_catalog_repository.rs - Rust source for Ariadnion.
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
//! Bounded asynchronous access to the durable file metadata catalog.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, BoxFileFuture, FileCatalogPort, FileCatalogRecord,
    FileDeleteReconciliation, FileDeleteRequest, FileDescriptor, FileListPage, FileListRequest,
    FileReference, FileUploadReconciliation, FileUploadRequest,
};
use ariadnion_core::{PrincipalContext, RequestContext};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::RnmdbSessionOwner;

mod evidence;
mod sql;
mod worker;

#[cfg(feature = "test-hooks")]
pub use worker::FileCatalogWorkerPause;

const MAX_COMMITMENT_KEYS: usize = 16;
const WORK_QUEUE_CAPACITY: usize = 32;

/// Stable secret material for keyed idempotency lookup derivation.
///
/// This key must remain unchanged for the lifetime of one database. Changing it
/// would change persisted lookup identities and break durable replay detection.
pub struct FileCatalogLookupKeyMaterial {
    bytes: [u8; 32],
}

impl FileCatalogLookupKeyMaterial {
    /// Takes ownership of exactly 32 secret bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Debug for FileCatalogLookupKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileCatalogLookupKeyMaterial(<redacted>)")
    }
}

impl Zeroize for FileCatalogLookupKeyMaterial {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for FileCatalogLookupKeyMaterial {}

impl Drop for FileCatalogLookupKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// One positive version safely represented by the catalog's signed `INT64` column.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FileCatalogCommitmentKeyVersion(i64);

impl FileCatalogCommitmentKeyVersion {
    /// Validates one positive signed key version.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::InvalidArgument`] when `value` is not positive.
    pub const fn new(value: i64) -> Result<Self, ApiFilesError> {
        if value <= 0 {
            return Err(api_error(ApiFilesErrorCode::InvalidArgument));
        }
        Ok(Self(value))
    }

    /// Returns the positive signed value stored in RNMDB.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// One versioned 32-byte commitment key cleared when dropped.
pub struct FileCatalogCommitmentKeyMaterial {
    version: FileCatalogCommitmentKeyVersion,
    bytes: [u8; 32],
}

impl FileCatalogCommitmentKeyMaterial {
    /// Takes ownership of one validated version and exactly 32 secret bytes.
    #[must_use]
    pub const fn new(version: FileCatalogCommitmentKeyVersion, bytes: [u8; 32]) -> Self {
        Self { version, bytes }
    }

    /// Returns this key's persisted version.
    #[must_use]
    pub const fn version(&self) -> FileCatalogCommitmentKeyVersion {
        self.version
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Debug for FileCatalogCommitmentKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileCatalogCommitmentKeyMaterial")
            .field("version", &self.version)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Zeroize for FileCatalogCommitmentKeyMaterial {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for FileCatalogCommitmentKeyMaterial {}

impl Drop for FileCatalogCommitmentKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A bounded version-indexed key set with exactly one active version.
pub struct FileCatalogCommitmentKeys {
    active: FileCatalogCommitmentKeyVersion,
    materials: Box<[FileCatalogCommitmentKeyMaterial]>,
}

impl FileCatalogCommitmentKeys {
    /// Validates at most 16 unique versions and one present active version.
    ///
    /// Historical materials must remain present while persisted operations or
    /// authenticated cursors may still name their versions.
    ///
    /// # Errors
    ///
    /// Returns a bounded argument error for an empty, oversized, duplicate, or
    /// active-version-missing collection.
    pub fn new(
        active: FileCatalogCommitmentKeyVersion,
        mut materials: Vec<FileCatalogCommitmentKeyMaterial>,
    ) -> Result<Self, ApiFilesError> {
        validate_key_count(materials.len())?;
        materials.sort_by_key(FileCatalogCommitmentKeyMaterial::version);
        validate_key_versions(active, &materials)?;
        Ok(Self {
            active,
            materials: materials.into_boxed_slice(),
        })
    }

    /// Returns the version used for new commitments and cursors.
    #[must_use]
    pub const fn active_version(&self) -> FileCatalogCommitmentKeyVersion {
        self.active
    }

    fn active(&self) -> Result<&FileCatalogCommitmentKeyMaterial, ApiFilesError> {
        self.material(self.active)
            .ok_or_else(|| api_error(ApiFilesErrorCode::Internal))
    }

    fn material(
        &self,
        version: FileCatalogCommitmentKeyVersion,
    ) -> Option<&FileCatalogCommitmentKeyMaterial> {
        self.materials
            .binary_search_by_key(&version, FileCatalogCommitmentKeyMaterial::version)
            .ok()
            .and_then(|index| self.materials.get(index))
    }
}

impl Debug for FileCatalogCommitmentKeys {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileCatalogCommitmentKeys")
            .field("active_version", &self.active)
            .field("version_count", &self.materials.len())
            .finish()
    }
}

fn validate_key_count(count: usize) -> Result<(), ApiFilesError> {
    if count == 0 {
        return Err(api_error(ApiFilesErrorCode::InvalidArgument));
    }
    if count > MAX_COMMITMENT_KEYS {
        return Err(api_error(ApiFilesErrorCode::LimitExceeded));
    }
    Ok(())
}

fn validate_key_versions(
    active: FileCatalogCommitmentKeyVersion,
    materials: &[FileCatalogCommitmentKeyMaterial],
) -> Result<(), ApiFilesError> {
    if materials
        .windows(2)
        .any(|pair| pair[0].version() == pair[1].version())
        || !materials
            .iter()
            .any(|material| material.version() == active)
    {
        return Err(api_error(ApiFilesErrorCode::InvalidArgument));
    }
    Ok(())
}

struct CatalogSecrets {
    lookup: FileCatalogLookupKeyMaterial,
    commitments: FileCatalogCommitmentKeys,
    database_probe: sql::CatalogDatabaseBoundaryProbe,
}

/// RNMDB-backed metadata catalog with one bounded serialized worker.
pub struct RnmdbFileCatalogRepository {
    session: Arc<RnmdbSessionOwner>,
    secrets: Arc<CatalogSecrets>,
    worker: worker::CatalogWorker,
}

impl RnmdbFileCatalogRepository {
    /// Creates one repository whose bounded worker starts on the first future poll.
    pub fn new(
        session: Arc<RnmdbSessionOwner>,
        lookup: FileCatalogLookupKeyMaterial,
        commitments: FileCatalogCommitmentKeys,
    ) -> Result<Self, ApiFilesError> {
        Self::start(session, lookup, commitments, WORK_QUEUE_CAPACITY)
    }

    /// Arms one caught result-waker clone panic on the current polling thread.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::Conflict`] when an injection is already armed.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_result_waker_clone_panic(&self) -> Result<(), ApiFilesError> {
        self.worker.inject_next_result_waker_clone_panic()
    }

    /// Cancels the next catalog operation immediately after its first database boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::Conflict`] when an injection is already armed.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_cancel_after_next_database_boundary(&self) -> Result<(), ApiFilesError> {
        if !self.secrets.database_probe.arm_child_cancellation() {
            return Err(api_error(ApiFilesErrorCode::Conflict));
        }
        Ok(())
    }

    /// Returns the number of catalog mutation statements attempted by this repository.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn database_mutation_attempt_count(&self) -> u64 {
        self.secrets.database_probe.mutation_attempt_count()
    }

    /// Creates one repository with an exact worker queue capacity for contracts.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::InvalidArgument`] when `capacity` is zero.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn new_with_test_worker_capacity(
        session: Arc<RnmdbSessionOwner>,
        lookup: FileCatalogLookupKeyMaterial,
        commitments: FileCatalogCommitmentKeys,
        capacity: usize,
    ) -> Result<Self, ApiFilesError> {
        if capacity == 0 {
            return Err(api_error(ApiFilesErrorCode::InvalidArgument));
        }
        Self::start(session, lookup, commitments, capacity)
    }

    /// Pauses the next admitted worker job immediately before execution.
    ///
    /// # Errors
    ///
    /// Returns [`ApiFilesErrorCode::Conflict`] when a pause is already armed.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn pause_next_worker_job(&self) -> Result<FileCatalogWorkerPause, ApiFilesError> {
        self.worker.pause_next_job()
    }

    fn start(
        session: Arc<RnmdbSessionOwner>,
        lookup: FileCatalogLookupKeyMaterial,
        commitments: FileCatalogCommitmentKeys,
        capacity: usize,
    ) -> Result<Self, ApiFilesError> {
        let secrets = Arc::new(CatalogSecrets {
            lookup,
            commitments,
            database_probe: sql::CatalogDatabaseBoundaryProbe::new(),
        });
        let worker = worker::CatalogWorker::new(session.clone(), secrets.clone(), capacity);
        Ok(Self {
            session,
            secrets,
            worker,
        })
    }

    async fn execute<T, F>(&self, context: RequestContext, operation: F) -> Result<T, ApiFilesError>
    where
        T: Send + 'static,
        F: FnOnce(
                &Arc<RnmdbSessionOwner>,
                &CatalogSecrets,
                &RequestContext,
            ) -> Result<T, ApiFilesError>
            + Send
            + 'static,
    {
        self.worker.execute(context, operation).await
    }
}

impl Debug for RnmdbFileCatalogRepository {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbFileCatalogRepository")
            .field("instance", self.session.instance())
            .field("commitment_keys", &self.secrets.commitments)
            .field("worker_started", &self.worker.started())
            .finish()
    }
}

impl FileCatalogPort for RnmdbFileCatalogRepository {
    fn publish<'a>(
        &'a self,
        record: &'a FileCatalogRecord,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>> {
        Box::pin(async move {
            require_record_owner(record, context)?;
            let owned = operation_context(context)?;
            let record = record.clone();
            self.execute(owned, move |session, secrets, worker_context| {
                require_record_owner(&record, worker_context)?;
                publish_record(session, secrets, &record, worker_context)
            })
            .await
        })
    }

    fn reconcile_publish<'a>(
        &'a self,
        request: &'a FileUploadRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileUploadReconciliation, ApiFilesError>> {
        Box::pin(async move {
            require_authenticated(context)?;
            let owned = operation_context(context)?;
            let request = request.clone();
            self.execute(owned, move |session, secrets, worker_context| {
                let owner = require_authenticated(worker_context)?;
                reconcile_published_record(session, secrets, &owner, &request, worker_context)
            })
            .await
        })
    }

    fn metadata<'a>(
        &'a self,
        reference: &'a FileReference,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDescriptor, ApiFilesError>> {
        Box::pin(async move {
            require_authenticated(context)?;
            let owned = operation_context(context)?;
            let reference = *reference;
            self.execute(owned, move |session, secrets, worker_context| {
                let owner = require_authenticated(worker_context)?;
                metadata_record(session, secrets, &owner, &reference, worker_context)
            })
            .await
        })
    }

    fn list<'a>(
        &'a self,
        request: FileListRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileListPage, ApiFilesError>> {
        Box::pin(async move {
            require_authenticated(context)?;
            let owned = operation_context(context)?;
            self.execute(owned, move |session, secrets, worker_context| {
                let owner = require_authenticated(worker_context)?;
                list_records(session, secrets, &owner, &request, worker_context)
            })
            .await
        })
    }

    fn delete<'a>(
        &'a self,
        request: &'a FileDeleteRequest,
        expected_descriptor: &'a FileDescriptor,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>> {
        Box::pin(async move {
            require_authenticated(context)?;
            let owned = operation_context(context)?;
            let request = request.clone();
            let expected = expected_descriptor.clone();
            self.execute(owned, move |session, secrets, worker_context| {
                let owner = require_authenticated(worker_context)?;
                delete_record(
                    session,
                    secrets,
                    &owner,
                    &request,
                    &expected,
                    worker_context,
                )
            })
            .await
        })
    }

    fn reconcile_delete<'a>(
        &'a self,
        request: &'a FileDeleteRequest,
        expected_descriptor: &'a FileDescriptor,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDeleteReconciliation, ApiFilesError>> {
        Box::pin(async move {
            require_authenticated(context)?;
            let owned = operation_context(context)?;
            let request = request.clone();
            let expected = expected_descriptor.clone();
            self.execute(owned, move |session, secrets, worker_context| {
                let owner = require_authenticated(worker_context)?;
                reconcile_deleted_record(
                    session,
                    secrets,
                    &owner,
                    &request,
                    &expected,
                    worker_context,
                )
            })
            .await
        })
    }
}

fn publish_record(
    session: &Arc<RnmdbSessionOwner>,
    secrets: &CatalogSecrets,
    record: &FileCatalogRecord,
    context: &RequestContext,
) -> Result<(), ApiFilesError> {
    let lookup = evidence::derive_lookup(
        &secrets.lookup,
        record.owner(),
        evidence::PUBLISH_KIND,
        record.request().idempotency_key().as_str(),
    )?;
    session
        .with_files_transaction_session(context, record.tenant_id(), |database| {
            sql::run_transaction(database, context, &secrets.database_probe, |database| {
                publish_in_transaction(database, secrets, record, &lookup)
            })
        })
        .map_err(map_storage_error)
}

fn publish_in_transaction(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    record: &FileCatalogRecord,
    lookup: &[u8; 32],
) -> Result<(), StorageError> {
    let existing = sql::load_operation(database, record.owner(), evidence::PUBLISH_KIND, lookup)?;
    if let Some(existing) = existing {
        return resolve_publish_replay(database, secrets, record, &existing);
    }
    let active = secrets
        .commitments
        .active()
        .map_err(|_| integrity_failure())?;
    let commitment = evidence::derive_publish_commitment(
        record.owner(),
        record.request(),
        record.descriptor(),
        active,
    )
    .map_err(|_| integrity_failure())?;
    sql::insert_entry(database, record)?;
    sql::insert_operation(
        database,
        record.owner(),
        evidence::PUBLISH_KIND,
        lookup,
        &commitment,
        record.descriptor().reference(),
        active.version(),
    )
}

fn resolve_publish_replay(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    record: &FileCatalogRecord,
    existing: &sql::OperationEvidence,
) -> Result<(), StorageError> {
    validate_publish_replay_evidence(secrets, record, existing)?;
    validate_replayed_descriptor(
        database,
        record.owner(),
        record.descriptor().reference(),
        record.descriptor(),
    )?;
    Ok(())
}

fn validate_publish_replay_evidence(
    secrets: &CatalogSecrets,
    record: &FileCatalogRecord,
    existing: &sql::OperationEvidence,
) -> Result<(), StorageError> {
    let key = evidence::commitment_key_for_version(&secrets.commitments, existing.key_version)?;
    if !evidence::verify_publish_commitment(
        record.owner(),
        record.request(),
        record.descriptor(),
        key,
        &existing.commitment,
    )? {
        return Err(conflict());
    }
    if &existing.reference != record.descriptor().reference() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_replayed_descriptor(
    database: &mut sql::CatalogDatabase<'_>,
    owner: &PrincipalContext,
    reference: &FileReference,
    expected: &FileDescriptor,
) -> Result<(), StorageError> {
    let descriptor = sql::load_entry(database, owner, reference)?.ok_or_else(integrity_failure)?;
    if &descriptor != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

fn reconcile_published_record(
    session: &Arc<RnmdbSessionOwner>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileUploadRequest,
    context: &RequestContext,
) -> Result<FileUploadReconciliation, ApiFilesError> {
    let lookup = evidence::derive_lookup(
        &secrets.lookup,
        owner,
        evidence::PUBLISH_KIND,
        request.idempotency_key().as_str(),
    )?;
    session
        .with_files_storage_session(context, owner.tenant_id(), |database| {
            let mut database =
                sql::CatalogDatabase::new(database, context, &secrets.database_probe);
            reconcile_publish_from_session(&mut database, secrets, owner, request, &lookup)
        })
        .map_err(map_storage_error)
}

fn reconcile_publish_from_session(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileUploadRequest,
    lookup: &[u8; 32],
) -> Result<FileUploadReconciliation, StorageError> {
    let Some(operation) = sql::load_operation(database, owner, evidence::PUBLISH_KIND, lookup)?
    else {
        return Ok(FileUploadReconciliation::NotCommitted);
    };
    let descriptor = reconcile_publish_operation(database, secrets, owner, request, &operation)?;
    Ok(FileUploadReconciliation::Committed(descriptor))
}

fn reconcile_publish_operation(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileUploadRequest,
    operation: &sql::OperationEvidence,
) -> Result<FileDescriptor, StorageError> {
    let descriptor =
        sql::load_entry(database, owner, &operation.reference)?.ok_or_else(integrity_failure)?;
    let key = evidence::commitment_key_for_version(&secrets.commitments, operation.key_version)?;
    if !evidence::verify_publish_commitment(
        owner,
        request,
        &descriptor,
        key,
        &operation.commitment,
    )? {
        return Err(integrity_failure());
    }
    Ok(descriptor)
}

fn metadata_record(
    session: &Arc<RnmdbSessionOwner>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    reference: &FileReference,
    context: &RequestContext,
) -> Result<FileDescriptor, ApiFilesError> {
    let result = session.with_files_storage_session(context, owner.tenant_id(), |database| {
        let mut database = sql::CatalogDatabase::new(database, context, &secrets.database_probe);
        sql::load_visible_entry(&mut database, &secrets.commitments, owner, reference)
    });
    result
        .map_err(map_storage_error)?
        .ok_or_else(|| api_error(ApiFilesErrorCode::NotFound))
}

fn list_records(
    session: &Arc<RnmdbSessionOwner>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileListRequest,
    context: &RequestContext,
) -> Result<FileListPage, ApiFilesError> {
    let after = request
        .cursor()
        .map(|cursor| evidence::verify_cursor(&secrets.commitments, owner, cursor))
        .transpose()?;
    let limit = request.limit();
    let query_limit = limit
        .get()
        .checked_add(1)
        .ok_or_else(|| api_error(ApiFilesErrorCode::Internal))?;
    let mut files = session
        .with_files_storage_session(context, owner.tenant_id(), |database| {
            let mut database =
                sql::CatalogDatabase::new(database, context, &secrets.database_probe);
            let files = sql::list_visible_entries(
                &mut database,
                &secrets.commitments,
                owner,
                after.as_ref(),
                query_limit,
            )?;
            let through = list_validation_upper_bound(&files, limit.get());
            sql::validate_list_tombstones(
                &mut database,
                &secrets.commitments,
                owner,
                after.as_ref(),
                through,
            )?;
            Ok(files)
        })
        .map_err(map_storage_error)?;
    let next_cursor = next_list_cursor(&mut files, limit.get(), secrets, owner)?;
    FileListPage::new(files, next_cursor, limit)
}

fn list_validation_upper_bound(
    files: &[FileDescriptor],
    requested_limit: usize,
) -> Option<&FileReference> {
    if files.len() <= requested_limit {
        return None;
    }
    files.last().map(FileDescriptor::reference)
}

fn next_list_cursor(
    files: &mut Vec<FileDescriptor>,
    limit: usize,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
) -> Result<Option<ariadnion_api_files::FileListCursor>, ApiFilesError> {
    if files.len() <= limit {
        return Ok(None);
    }
    let _extra = files.pop();
    let reference = files
        .last()
        .map(FileDescriptor::reference)
        .ok_or_else(|| api_error(ApiFilesErrorCode::IntegrityFailure))?;
    evidence::issue_cursor(&secrets.commitments, owner, reference).map(Some)
}

fn delete_record(
    session: &Arc<RnmdbSessionOwner>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    expected: &FileDescriptor,
    context: &RequestContext,
) -> Result<(), ApiFilesError> {
    let lookup = evidence::derive_lookup(
        &secrets.lookup,
        owner,
        evidence::DELETE_KIND,
        request.idempotency_key().as_str(),
    )?;
    session
        .with_files_transaction_session(context, owner.tenant_id(), |database| {
            sql::run_transaction(database, context, &secrets.database_probe, |database| {
                delete_in_transaction(database, secrets, owner, request, expected, &lookup)
            })
        })
        .map_err(map_storage_error)
}

fn delete_in_transaction(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    expected: &FileDescriptor,
    lookup: &[u8; 32],
) -> Result<(), StorageError> {
    let existing = sql::load_operation(database, owner, evidence::DELETE_KIND, lookup)?;
    if let Some(existing) = existing {
        return resolve_delete_replay(database, secrets, owner, request, expected, &existing);
    }
    create_delete_operation(database, secrets, owner, request, expected, lookup)
}

fn create_delete_operation(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    expected: &FileDescriptor,
    lookup: &[u8; 32],
) -> Result<(), StorageError> {
    let descriptor =
        sql::load_visible_entry(database, &secrets.commitments, owner, request.reference())?
            .ok_or_else(not_found_storage)?;
    if &descriptor != expected || expected.reference() != request.reference() {
        return Err(conflict());
    }
    let active = secrets
        .commitments
        .active()
        .map_err(|_| integrity_failure())?;
    let commitment = evidence::derive_delete_commitment(owner, request, expected, active)
        .map_err(|_| integrity_failure())?;
    sql::insert_operation(
        database,
        owner,
        evidence::DELETE_KIND,
        lookup,
        &commitment,
        request.reference(),
        active.version(),
    )
}

fn resolve_delete_replay(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    expected: &FileDescriptor,
    existing: &sql::OperationEvidence,
) -> Result<(), StorageError> {
    validate_delete_replay_evidence(secrets, owner, request, expected, existing)?;
    validate_replayed_descriptor(database, owner, &existing.reference, expected)?;
    Ok(())
}

fn validate_delete_replay_evidence(
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    expected: &FileDescriptor,
    existing: &sql::OperationEvidence,
) -> Result<(), StorageError> {
    let key = evidence::commitment_key_for_version(&secrets.commitments, existing.key_version)?;
    if !evidence::verify_delete_commitment(owner, request, expected, key, &existing.commitment)? {
        return Err(conflict());
    }
    if &existing.reference != request.reference() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn reconcile_deleted_record(
    session: &Arc<RnmdbSessionOwner>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    expected: &FileDescriptor,
    context: &RequestContext,
) -> Result<FileDeleteReconciliation, ApiFilesError> {
    let lookup = evidence::derive_lookup(
        &secrets.lookup,
        owner,
        evidence::DELETE_KIND,
        request.idempotency_key().as_str(),
    )?;
    session
        .with_files_storage_session(context, owner.tenant_id(), |database| {
            let mut database =
                sql::CatalogDatabase::new(database, context, &secrets.database_probe);
            reconcile_delete_from_session(&mut database, secrets, owner, request, expected, &lookup)
        })
        .map_err(map_storage_error)
}

fn reconcile_delete_from_session(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    expected: &FileDescriptor,
    lookup: &[u8; 32],
) -> Result<FileDeleteReconciliation, StorageError> {
    let Some(operation) = sql::load_operation(database, owner, evidence::DELETE_KIND, lookup)?
    else {
        return Ok(FileDeleteReconciliation::NotDeleted);
    };
    reconcile_delete_operation(database, secrets, owner, request, expected, &operation)?;
    Ok(FileDeleteReconciliation::Deleted)
}

fn reconcile_delete_operation(
    database: &mut sql::CatalogDatabase<'_>,
    secrets: &CatalogSecrets,
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    expected: &FileDescriptor,
    operation: &sql::OperationEvidence,
) -> Result<(), StorageError> {
    let key = evidence::commitment_key_for_version(&secrets.commitments, operation.key_version)?;
    if !evidence::verify_delete_commitment(owner, request, expected, key, &operation.commitment)?
        || &operation.reference != request.reference()
    {
        return Err(integrity_failure());
    }
    validate_replayed_descriptor(database, owner, &operation.reference, expected)
}

const fn not_found_storage() -> StorageError {
    StorageError::new(StorageErrorCode::NotFound)
}

fn map_storage_error(error: StorageError) -> ApiFilesError {
    api_error(map_storage_error_code(error.code()))
}

const fn map_storage_error_code(code: StorageErrorCode) -> ApiFilesErrorCode {
    match code {
        StorageErrorCode::InvalidArgument => ApiFilesErrorCode::IntegrityFailure,
        StorageErrorCode::NotFound => ApiFilesErrorCode::NotFound,
        StorageErrorCode::Conflict => ApiFilesErrorCode::Conflict,
        StorageErrorCode::DeadlineExceeded => ApiFilesErrorCode::DeadlineExceeded,
        StorageErrorCode::Cancelled => ApiFilesErrorCode::Cancelled,
        remaining => map_storage_durability_error_code(remaining),
    }
}

const fn map_storage_durability_error_code(code: StorageErrorCode) -> ApiFilesErrorCode {
    match code {
        StorageErrorCode::ResourceExhausted => ApiFilesErrorCode::ResourceExhausted,
        StorageErrorCode::Unavailable => ApiFilesErrorCode::Unavailable,
        StorageErrorCode::CommitIndeterminate => ApiFilesErrorCode::CommitIndeterminate,
        _ => ApiFilesErrorCode::IntegrityFailure,
    }
}

const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

fn operation_context(context: &RequestContext) -> Result<RequestContext, ApiFilesError> {
    context.check_active().map_err(ApiFilesError::from)?;
    Ok(RequestContext::new(
        context.request_id().clone(),
        context.trace_id().clone(),
        context.principal().cloned(),
        context.deadline(),
        context.cancellation().child(),
    ))
}

fn require_record_owner(
    record: &FileCatalogRecord,
    context: &RequestContext,
) -> Result<PrincipalContext, ApiFilesError> {
    let owner = require_authenticated(context)?;
    if &owner != record.owner() {
        return Err(api_error(ApiFilesErrorCode::IntegrityFailure));
    }
    Ok(owner)
}

fn require_authenticated(context: &RequestContext) -> Result<PrincipalContext, ApiFilesError> {
    context
        .principal()
        .cloned()
        .ok_or_else(|| api_error(ApiFilesErrorCode::Unauthenticated))
}

const fn api_error(code: ApiFilesErrorCode) -> ApiFilesError {
    ApiFilesError::new(code)
}

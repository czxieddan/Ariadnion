//! Verified RNMDB backup creation behind trusted path and key resolution.

use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::io::ErrorKind as IoErrorKind;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::SystemTime;

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_backup::{
    BackupCreateRequest, BackupFileVersion, BackupIntegrityProof, BackupKeyVersionId,
    BackupPageCount, BackupPort, BackupSha256Digest, BackupSourceSnapshot, BackupTargetId,
    BackupVerificationEvidence,
};
use ariadnion_storage_domain::{SchemaVersion, StorageError, StorageErrorCode, StorageInstanceId};

use crate::file_integrity::digest_location;
use crate::location::StorageFileLocation;
use crate::maintenance::{BackupSummary, RnmdbMaintenance, VerificationSummary};
use crate::session::PageKeyMaterial;

/// Resolves trusted RNMDB backup resources without exposing paths or keys.
///
/// Implementations own the mapping from logical identities to validated file
/// locations. They must keep the source quiescent and the resolved target
/// namespace exclusive for the complete [`BackupPort::create_verified_backup`]
/// call. Each key request must return newly owned material for the exact source
/// and requested key version; returning shared mutable key storage is invalid.
pub trait RnmdbBackupEnvironment: Send + Sync {
    /// Returns durable evidence for an exact completed request, when present.
    ///
    /// Implementations must return `Conflict` or integrity failure when the
    /// backup identity is already bound to different inputs.
    fn completed_evidence(
        &self,
        request: &BackupCreateRequest,
        context: &RequestContext,
    ) -> Result<Option<BackupVerificationEvidence>, StorageError>;

    /// Resolves the immutable source instance to its validated file location.
    ///
    /// # Errors
    ///
    /// Returns a stable storage error when the instance is unavailable or the
    /// request no longer permits resolution.
    fn resolve_source(
        &self,
        source: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<StorageFileLocation, StorageError>;

    /// Resolves an unused logical backup target to a validated file location.
    ///
    /// The target namespace must remain exclusively owned by this operation
    /// until the adapter returns, including during failure cleanup.
    ///
    /// # Errors
    ///
    /// Returns a stable storage error when the target cannot be resolved or the
    /// request no longer permits resolution.
    fn resolve_target(
        &self,
        target: &BackupTargetId,
        context: &RequestContext,
    ) -> Result<StorageFileLocation, StorageError>;

    /// Reports the application schema version in the quiescent source.
    ///
    /// # Errors
    ///
    /// Returns a stable storage error when authoritative schema evidence is not
    /// available for the exact source snapshot.
    fn source_schema_version(
        &self,
        source: &StorageInstanceId,
        context: &RequestContext,
    ) -> Result<SchemaVersion, StorageError>;

    /// Supplies fresh page-key material for one authentication attempt.
    ///
    /// The returned value must correspond to both `source` and `key_version`.
    /// The adapter consumes it once and clears its owned bytes on drop.
    ///
    /// # Errors
    ///
    /// Returns a stable storage error when the key version is unavailable,
    /// unauthorized, retired, or cannot be delivered before the deadline.
    fn fresh_page_key(
        &self,
        source: &StorageInstanceId,
        key_version: &BackupKeyVersionId,
        context: &RequestContext,
    ) -> Result<PageKeyMaterial, StorageError>;

    /// Persists completed evidence as the idempotent replay authority.
    ///
    /// An error must not leave evidence visible as durable. A successful call
    /// must make the exact evidence observable through `completed_evidence`.
    fn persist_completed_evidence(
        &self,
        evidence: &BackupVerificationEvidence,
        context: &RequestContext,
    ) -> Result<(), StorageError>;
}

/// Creates authenticated RNMDB backups through one serialized maintenance gate.
///
/// Concurrent calls on one adapter fail with a retryable unavailable result
/// instead of waiting beyond their request deadline. A poisoned gate fails
/// closed. The environment must provide the namespace exclusivity documented
/// by [`RnmdbBackupEnvironment`].
pub struct RnmdbBackupAdapter {
    environment: Arc<dyn RnmdbBackupEnvironment>,
    maintenance: Mutex<()>,
}

impl RnmdbBackupAdapter {
    /// Creates an adapter backed by one trusted resolver and key environment.
    #[must_use]
    pub fn new(environment: Arc<dyn RnmdbBackupEnvironment>) -> Self {
        Self {
            environment,
            maintenance: Mutex::new(()),
        }
    }

    fn resolve_locations(
        &self,
        request: &BackupCreateRequest,
        context: &RequestContext,
    ) -> Result<(StorageFileLocation, StorageFileLocation), StorageError> {
        let source = self.environment.resolve_source(request.source(), context)?;
        require_source_binding(request, &source)?;
        let target = self.environment.resolve_target(request.target(), context)?;
        require_distinct_locations(&source, &target)?;
        require_missing_target(&target)?;
        Ok((source, target))
    }

    fn create_evidence(
        &self,
        request: &BackupCreateRequest,
        source: &StorageFileLocation,
        target: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<BackupVerificationEvidence, StorageError> {
        let source_verification = self.authenticate(request, source, context)?;
        let schema_version = self
            .environment
            .source_schema_version(request.source(), context)?;
        check_context(context)?;

        let copy = RnmdbMaintenance::backup(source, target, context)?;
        let created_at = SystemTime::now();
        let target_verification = self.authenticate(request, target, context)?;
        validate_copy(&source_verification, &copy, &target_verification)?;

        let digest = BackupSha256Digest::new(digest_location(
            target,
            target_verification.file_len_bytes(),
            context,
        )?);
        let verified_at = SystemTime::now();
        build_evidence(
            request,
            schema_version,
            source_verification,
            digest,
            created_at,
            verified_at,
        )
    }

    fn authenticate(
        &self,
        request: &BackupCreateRequest,
        location: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<VerificationSummary, StorageError> {
        let key =
            self.environment
                .fresh_page_key(request.source(), request.key_version(), context)?;
        let verification = RnmdbMaintenance::verify(location, key, context)?;
        require_authenticated(&verification)?;
        Ok(verification)
    }

    fn completed_replay(
        &self,
        request: &BackupCreateRequest,
        context: &RequestContext,
    ) -> Result<Option<BackupVerificationEvidence>, StorageError> {
        let Some(evidence) = self.environment.completed_evidence(request, context)? else {
            return Ok(None);
        };
        evidence.validate_for(request)?;
        Ok(Some(evidence))
    }

    fn create_and_persist(
        &self,
        request: &BackupCreateRequest,
        source: &StorageFileLocation,
        target: &StorageFileLocation,
        context: &RequestContext,
    ) -> Result<BackupVerificationEvidence, StorageError> {
        let evidence = self.create_evidence(request, source, target, context)?;
        self.environment
            .persist_completed_evidence(&evidence, context)?;
        Ok(evidence)
    }
}

impl Debug for RnmdbBackupAdapter {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbBackupAdapter")
            .field("environment", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BackupPort for RnmdbBackupAdapter {
    fn create_verified_backup(
        &self,
        request: &BackupCreateRequest,
        context: &RequestContext,
    ) -> Result<BackupVerificationEvidence, StorageError> {
        check_context(context)?;
        let _maintenance = lock_maintenance(&self.maintenance)?;
        check_context(context)?;
        if let Some(evidence) = self.completed_replay(request, context)? {
            return Ok(evidence);
        }
        let (source, target) = self.resolve_locations(request, context)?;
        let result = self.create_and_persist(request, &source, &target, context);
        finish_or_remove_incomplete(result, &target)
    }
}

fn build_evidence(
    request: &BackupCreateRequest,
    schema_version: SchemaVersion,
    source: VerificationSummary,
    digest: BackupSha256Digest,
    created_at: SystemTime,
    verified_at: SystemTime,
) -> Result<BackupVerificationEvidence, StorageError> {
    let file_version = BackupFileVersion::new(u32::from(source.format_version()))
        .map_err(|_| integrity_failure())?;
    let page_count = BackupPageCount::new(source.present_page_records())?;
    let snapshot = BackupSourceSnapshot::new(
        request.source().clone(),
        file_version,
        schema_version,
        page_count,
    );
    let proof = BackupIntegrityProof::new(
        digest,
        request.key_version().clone(),
        created_at,
        verified_at,
    )?;
    let evidence = BackupVerificationEvidence::new(
        request.backup_id().clone(),
        request.target().clone(),
        snapshot,
        proof,
    )?;
    evidence.validate_for(request)?;
    Ok(evidence)
}

fn validate_copy(
    source: &VerificationSummary,
    copy: &BackupSummary,
    target: &VerificationSummary,
) -> Result<(), StorageError> {
    let bytes_match = source.file_len_bytes() == copy.bytes_copied()
        && target.file_len_bytes() == copy.bytes_copied();
    let pages_match = source.present_page_records() == copy.present_page_records()
        && target.present_page_records() == copy.present_page_records();
    let slots_match = source.page_record_slots() == copy.page_record_slots()
        && target.page_record_slots() == copy.page_record_slots();
    let format_matches = source.format_version() == target.format_version();
    if !(bytes_match && pages_match && slots_match && format_matches) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn finish_or_remove_incomplete<T>(
    result: Result<T, StorageError>,
    target: &StorageFileLocation,
) -> Result<T, StorageError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            remove_incomplete_target(target)?;
            Err(error)
        }
    }
}

fn remove_incomplete_target(target: &StorageFileLocation) -> Result<(), StorageError> {
    match fs::remove_file(target.path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == IoErrorKind::NotFound => Ok(()),
        Err(_) => Err(unavailable()),
    }
}

fn require_missing_target(target: &StorageFileLocation) -> Result<(), StorageError> {
    match fs::symlink_metadata(target.path()) {
        Ok(_) => Err(StorageError::new(StorageErrorCode::Conflict)),
        Err(error) if error.kind() == IoErrorKind::NotFound => Ok(()),
        Err(_) => Err(unavailable()),
    }
}

fn require_source_binding(
    request: &BackupCreateRequest,
    source: &StorageFileLocation,
) -> Result<(), StorageError> {
    if request.source() != source.instance() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn require_distinct_locations(
    source: &StorageFileLocation,
    target: &StorageFileLocation,
) -> Result<(), StorageError> {
    if source.path() == target.path() {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn require_authenticated(verification: &VerificationSummary) -> Result<(), StorageError> {
    if !verification.is_valid() || !verification.encryption_authenticated() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn lock_maintenance(gate: &Mutex<()>) -> Result<MutexGuard<'_, ()>, StorageError> {
    match gate.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => Err(unavailable()),
        Err(TryLockError::Poisoned(_)) => Err(internal()),
    }
}

fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => StorageError::new(StorageErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => StorageError::new(StorageErrorCode::DeadlineExceeded),
        _ => internal(),
    })
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn unavailable() -> StorageError {
    StorageError::new(StorageErrorCode::Unavailable)
}

const fn internal() -> StorageError {
    StorageError::new(StorageErrorCode::Internal)
}

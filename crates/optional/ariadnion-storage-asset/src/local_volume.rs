// crates/optional/ariadnion-storage-asset/src/local_volume.rs - Rust source for Ariadnion.
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
//! Durable filesystem operations for tenant-bound content-addressed assets.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use ariadnion_core::{RequestContext, TenantId};
#[cfg(windows)]
use cap_fs_ext::OpenOptionsMaybeDirExt;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
#[cfg(unix)]
use cap_std::fs::OpenOptionsExt;
use cap_std::fs::{Dir, File, Metadata, OpenOptions};
use sha2::{Digest, Sha256};

use crate::manifest::{
    CommittedRecord, StageRecord, decode_committed_record, decode_stage_record,
    encode_committed_record, encode_consumed_marker, encode_stage_record, is_consumed_marker,
    tenant_path_digest,
};
use crate::{
    AssetByteLength, AssetCommitReceipt, AssetCommitStatus, AssetDescriptor, AssetDigest, AssetKey,
    AssetQuarantineReason, AssetQuarantineReceipt, AssetStageRequest, AssetStageToken,
    LocalVolumeAssetStoragePort, StagedAsset, StorageError, StorageErrorCode,
};

mod helpers;
mod intent;
use helpers::*;

const BUFFER_SIZE: usize = 64 * 1024;
const MAX_RECORD_BYTES: u64 = 4 * 1024;
const FAULT_CONSUME_MARKER: u16 = 1;
const FAULT_QUARANTINE_RENAME: u16 = 2;
const FAULT_PUBLICATION_PARENT_SYNC: u16 = 4;
const FAULT_DESCRIPTOR_PARENT_SYNC: u16 = 32;
const STAGE_ENTRY_NAMES: [&str; 8] = [
    "content",
    "manifest",
    "descriptor",
    "consumed",
    "reason",
    "publish-content",
    "publish-intent",
    "quarantine-intent",
];

/// Supplies cryptographically secure opaque stage tokens to a local volume.
///
/// The filesystem adapter deliberately receives this capability from its
/// composition boundary. Implementations must use an operating-system CSPRNG;
/// counters, clocks, request identifiers, and content digests are forbidden.
pub trait StageTokenIssuer: Send + Sync {
    /// Issues one fresh opaque token.
    fn issue(&self) -> Result<AssetStageToken, StorageError>;
}

/// A tenant-bound local content-addressed asset volume.
pub struct LocalVolume {
    root: PathBuf,
    root_dir: Dir,
    issuer: Arc<dyn StageTokenIssuer>,
    operation_gate: Mutex<()>,
    #[cfg(feature = "test-hooks")]
    faults: AtomicU16,
    #[cfg(feature = "test-hooks")]
    quarantine_visibility_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(feature = "test-hooks")]
    stage_retire_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(feature = "test-hooks")]
    quarantine_post_rename_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(feature = "test-hooks")]
    quarantine_recovery_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
}

impl std::fmt::Debug for LocalVolume {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalVolume")
            .field("root", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl LocalVolume {
    /// Opens or creates a local volume beneath `root`.
    ///
    /// The process uses ambient authority only once to open the caller-selected
    /// root. All later operations are rooted in that directory handle, use
    /// no-follow traversal, and accept only fixed generated path components.
    pub fn new(
        root: impl AsRef<Path>,
        issuer: Arc<dyn StageTokenIssuer>,
    ) -> Result<Self, StorageError> {
        let root = prepare_root(root.as_ref())?;
        let root_dir = Dir::open_ambient_dir(&root, ambient_authority()).map_err(map_io)?;
        let volume = Self {
            root,
            root_dir,
            issuer,
            operation_gate: Mutex::new(()),
            #[cfg(feature = "test-hooks")]
            faults: AtomicU16::new(0),
            #[cfg(feature = "test-hooks")]
            quarantine_visibility_barrier: Mutex::new(None),
            #[cfg(feature = "test-hooks")]
            stage_retire_barrier: Mutex::new(None),
            #[cfg(feature = "test-hooks")]
            quarantine_post_rename_barrier: Mutex::new(None),
            #[cfg(feature = "test-hooks")]
            quarantine_recovery_barrier: Mutex::new(None),
        };
        volume.initialize_layout()?;
        Ok(volume)
    }

    #[cfg(feature = "test-hooks")]
    fn arm_fault(&self, fault: u16) -> Result<(), StorageError> {
        match self
            .faults
            .compare_exchange(0, fault, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(_) => Err(StorageError::new(StorageErrorCode::Conflict)),
        }
    }

    #[cfg(feature = "test-hooks")]
    fn take_fault(&self, fault: u16) -> bool {
        self.faults
            .compare_exchange(fault, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[cfg(not(feature = "test-hooks"))]
    fn take_fault(&self, _fault: u16) -> bool {
        false
    }

    fn maybe_fail_fault(&self, fault: u16) -> Result<(), StorageError> {
        if self.take_fault(fault) {
            return Err(StorageError::new(StorageErrorCode::Unavailable));
        }
        Ok(())
    }

    fn initialize_layout(&self) -> Result<(), StorageError> {
        let paths = [
            "staging",
            "committed",
            "descriptors",
            "quarantine",
            "staging/.locks",
            "staging/.consumed",
            "staging/.recovery",
            "committed/sha256",
            "quarantine/recovery",
        ];
        for path in paths {
            self.ensure_dir(Path::new(path), None)?;
        }
        self.sync_relative(Path::new("."))
    }

    fn stage_dir(&self, token: &AssetStageToken) -> PathBuf {
        self.root.join("staging").join(token_name(token))
    }

    fn quarantine_dir(&self, token: &AssetStageToken) -> PathBuf {
        self.root.join("quarantine").join(token_name(token))
    }

    fn stage_lock_path(&self, token: &AssetStageToken) -> PathBuf {
        self.root
            .join("staging")
            .join(".locks")
            .join(token_name(token))
    }

    fn content_path(&self, digest: AssetDigest) -> PathBuf {
        let encoded = hex(digest.as_bytes());
        self.root
            .join("committed")
            .join("sha256")
            .join(&encoded[..2])
            .join(encoded)
    }

    fn descriptor_path(&self, key: &AssetKey) -> PathBuf {
        self.root
            .join("descriptors")
            .join(hex(&tenant_path_digest(key.tenant_id())))
            .join(hex(key.digest().as_bytes()))
    }

    fn stage_content_path(&self, token: &AssetStageToken) -> PathBuf {
        self.stage_dir(token).join("content")
    }

    fn stage_manifest_path(&self, token: &AssetStageToken) -> PathBuf {
        self.stage_dir(token).join("manifest")
    }

    fn stage_consumed_path(&self, token: &AssetStageToken) -> PathBuf {
        self.stage_dir(token).join("consumed")
    }

    fn consumed_tombstone_path(&self, token: &AssetStageToken) -> PathBuf {
        self.root
            .join("staging")
            .join(".consumed")
            .join(token_name(token))
    }

    fn stage_reason_path(&self, token: &AssetStageToken) -> PathBuf {
        self.stage_dir(token).join("reason")
    }

    fn stage_publish_path(&self, token: &AssetStageToken) -> PathBuf {
        self.stage_dir(token).join("publish-content")
    }

    fn stage_publish_intent_path(&self, token: &AssetStageToken) -> PathBuf {
        self.stage_dir(token).join("publish-intent")
    }

    fn stage_quarantine_intent_path(&self, token: &AssetStageToken) -> PathBuf {
        self.stage_dir(token).join("quarantine-intent")
    }

    fn recovery_marker_path(&self, token: &AssetStageToken) -> PathBuf {
        self.root
            .join("staging")
            .join(".recovery")
            .join(token_name(token))
    }

    fn failed_stage_target(&self, token: &AssetStageToken) -> PathBuf {
        self.root
            .join("quarantine")
            .join("recovery")
            .join(token_name(token))
    }

    fn check_owner(&self, tenant: &TenantId, context: &RequestContext) -> Result<(), StorageError> {
        check_active(context)?;
        let Some(principal) = context.principal() else {
            return Err(integrity_failure());
        };
        if principal.tenant_id() != tenant {
            return Err(StorageError::new(StorageErrorCode::NotFound));
        }
        Ok(())
    }

    fn create_stage_directory(
        &self,
        token: &AssetStageToken,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.validate_dir(Path::new("staging"), context)?;
        let lock = self.create_file(&self.stage_lock_path(token), context)?;
        drop(lock);
        if let Err(error) = self.ensure_dir(&self.relative(&self.stage_dir(token))?, Some(context))
        {
            let _ = self.remove_file(&self.stage_lock_path(token));
            return Err(error);
        }
        self.sync_relative(Path::new("staging/.locks"))?;
        self.sync_relative(Path::new("staging"))
    }

    fn load_stage<'a>(
        &self,
        staged: &'a StagedAsset,
        context: &RequestContext,
    ) -> Result<StageLease<'a>, StorageError> {
        let lock = self.open_stage_lock(staged)?;
        self.reject_consumed_stage(staged, context)?;
        let record = self.read_stage_record(staged, context)?;
        self.validate_stage_content(staged, &record, context)?;
        Ok(StageLease {
            lock,
            staged,
            record,
        })
    }

    fn read_stage_record(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<StageRecord, StorageError> {
        self.read_stage_record_at(&self.stage_dir(staged.token()), staged, context)
    }

    fn read_stage_record_at(
        &self,
        base: &Path,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<StageRecord, StorageError> {
        let path = base.join("manifest");
        let (mut manifest, metadata) = self
            .open_managed_file(&path, false, context)
            .map_err(map_missing_stage)?;
        let bytes = read_bounded(&mut manifest, &metadata, MAX_RECORD_BYTES, context)?;
        decode_stage_record(&bytes, staged)
    }

    fn validate_stage_content(
        &self,
        staged: &StagedAsset,
        record: &StageRecord,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.validate_content_at(&self.stage_dir(staged.token()), &record.descriptor, context)
    }

    fn validate_content_at(
        &self,
        base: &Path,
        descriptor: &AssetDescriptor,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let content = base.join("content");
        let metadata = self
            .managed_regular_metadata(&content, context)
            .map_err(map_missing_stage)?;
        ensure_exact_length(&metadata, descriptor.byte_length())
    }

    fn reject_consumed_stage(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.reject_marker(
            &self.consumed_tombstone_path(staged.token()),
            staged,
            context,
        )?;
        self.reject_marker(&self.stage_consumed_path(staged.token()), staged, context)
    }

    fn reject_marker(
        &self,
        marker: &Path,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        match self.open_managed_file(marker, false, context) {
            Ok((mut file, metadata)) => {
                let bytes = read_bounded(&mut file, &metadata, MAX_RECORD_BYTES, context)?;
                if is_consumed_marker(&bytes, staged.token(), staged.descriptor()) {
                    return Err(integrity_failure());
                }
                Err(integrity_failure())
            }
            Err(error) if error.code() == StorageErrorCode::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn reject_quarantine_claim(
        &self,
        token: &AssetStageToken,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        match self.open_managed_file(&self.stage_reason_path(token), false, context) {
            Ok(_) => Err(integrity_failure()),
            Err(error) if error.code() == StorageErrorCode::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn load_committed_for_key(
        &self,
        key: &AssetKey,
        context: &RequestContext,
    ) -> Result<CommittedRecord, StorageError> {
        let path = self.descriptor_path(key);
        let (mut file, metadata) = self.open_managed_file(&path, false, context)?;
        let bytes = read_bounded(&mut file, &metadata, MAX_RECORD_BYTES, context)?;
        decode_committed_record(&bytes, key)
    }

    fn load_optional_committed(
        &self,
        key: &AssetKey,
        context: &RequestContext,
    ) -> Result<Option<CommittedRecord>, StorageError> {
        match self.load_committed_for_key(key, context) {
            Ok(record) => Ok(Some(record)),
            Err(error) if error.code() == StorageErrorCode::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn verify_content(
        &self,
        descriptor: &AssetDescriptor,
        destination: Option<&mut dyn Write>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let path = self.content_path(descriptor.digest());
        self.verify_file(&path, descriptor, destination, context)
            .map_err(map_missing_stage)
    }

    fn verify_stage_content(
        &self,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let path = self.stage_content_path(lease.staged.token());
        self.verify_file(&path, &lease.record.descriptor, None, context)
            .map_err(map_missing_stage)
    }

    fn verify_file(
        &self,
        path: &Path,
        descriptor: &AssetDescriptor,
        mut destination: Option<&mut dyn Write>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let (mut file, metadata) = self.open_managed_file(path, false, context)?;
        ensure_exact_length(&metadata, descriptor.byte_length())?;
        let digest = stream_file(
            &mut file,
            descriptor.byte_length(),
            &mut destination,
            context,
        )?;
        ensure_digest(digest, descriptor.digest())
    }

    fn install_content(
        &self,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let descriptor = &lease.record.descriptor;
        let target = self.content_path(descriptor.digest());
        let parent = self.ensure_content_parent(descriptor.digest(), context)?;
        let pending = self.prepare_content(lease, context)?;
        self.publish_content_file(&pending, &target, context)?;
        self.finish_content_install(lease, &pending, &parent)?;
        self.verify_file(&target, descriptor, None, context)
            .map_err(map_missing_stage)
    }

    fn publish_content_file(
        &self,
        pending: &Path,
        target: &Path,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        self.hard_link(pending, target, context)
    }

    fn finish_content_install(
        &self,
        lease: &StageLease<'_>,
        pending: &Path,
        parent: &Path,
    ) -> Result<(), StorageError> {
        self.remove_file(pending)?;
        let stage = self.relative(&self.stage_dir(lease.staged.token()))?;
        self.sync_relative(&stage)?;
        self.sync_content_publication_parents(parent)
    }

    fn sync_content_publication_parents(&self, parent: &Path) -> Result<(), StorageError> {
        self.maybe_fail_fault(FAULT_PUBLICATION_PARENT_SYNC)
            .map_err(commit_indeterminate)?;
        self.sync_relative(parent).map_err(commit_indeterminate)?;
        self.sync_relative(Path::new("committed/sha256"))
            .map_err(commit_indeterminate)
    }

    fn prepare_content(
        &self,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<PathBuf, StorageError> {
        let pending = self.stage_publish_path(lease.staged.token());
        self.create_or_reuse_pending(&pending, lease, context)?;
        Ok(pending)
    }

    fn create_or_reuse_pending(
        &self,
        pending: &Path,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        match self.create_file(pending, context) {
            Ok(destination) => self.copy_pending_or_remove(pending, lease, destination, context),
            Err(error) if error.code() == StorageErrorCode::Conflict => {
                self.verify_file(pending, &lease.record.descriptor, None, context)
            }
            Err(error) => Err(error),
        }
    }

    fn copy_pending_or_remove(
        &self,
        pending: &Path,
        lease: &StageLease<'_>,
        mut destination: File,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        match self.copy_stage_to_pending(lease, &mut destination, context) {
            Ok(()) => Ok(()),
            Err(error) => {
                drop(destination);
                let _ = self.remove_file(pending);
                Err(error)
            }
        }
    }

    fn copy_stage_to_pending(
        &self,
        lease: &StageLease<'_>,
        destination: &mut File,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let source = self.stage_content_path(lease.staged.token());
        let (mut source, metadata) = self
            .open_managed_file(&source, false, context)
            .map_err(map_missing_stage)?;
        ensure_exact_length(&metadata, lease.record.descriptor.byte_length())?;
        let digest = stream_file(
            &mut source,
            lease.record.descriptor.byte_length(),
            &mut Some(destination as &mut dyn Write),
            context,
        )?;
        ensure_digest(digest, lease.record.descriptor.digest())?;
        destination.sync_all().map_err(map_io)?;
        check_active(context)
    }

    fn publish_descriptor(
        &self,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        let descriptor = &lease.record.descriptor;
        let pending = self.prepare_descriptor(lease, context)?;
        let target = self.descriptor_path(descriptor.key());
        let parent = self.ensure_descriptor_parent(descriptor.key(), context)?;
        let created = self.publish_descriptor_file(&pending, &target, &parent, context)?;
        if created {
            return Ok(true);
        }
        self.reconcile_existing_descriptor(descriptor, context)
    }

    fn publish_descriptor_file(
        &self,
        pending: &Path,
        target: &Path,
        parent: &Path,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        let created = self.hard_link(pending, target, context)?;
        self.remove_descriptor_pending(pending, created)?;
        self.sync_descriptor_publication_parents(parent)?;
        Ok(created)
    }

    fn sync_descriptor_publication_parents(&self, parent: &Path) -> Result<(), StorageError> {
        self.maybe_fail_fault(FAULT_DESCRIPTOR_PARENT_SYNC)
            .map_err(commit_indeterminate)?;
        self.sync_relative(parent).map_err(commit_indeterminate)?;
        self.sync_relative(Path::new("descriptors"))
            .map_err(commit_indeterminate)
    }

    fn sync_existing_publication(
        &self,
        descriptor: &AssetDescriptor,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let content_parent = self.ensure_content_parent(descriptor.digest(), context)?;
        self.sync_content_publication_parents(&content_parent)?;
        let descriptor_parent = self.ensure_descriptor_parent(descriptor.key(), context)?;
        self.sync_descriptor_publication_parents(&descriptor_parent)
    }

    fn remove_descriptor_pending(&self, pending: &Path, created: bool) -> Result<(), StorageError> {
        self.remove_file(pending).map_err(|error| {
            if created {
                commit_indeterminate(error)
            } else {
                error
            }
        })
    }

    fn reconcile_existing_descriptor(
        &self,
        descriptor: &AssetDescriptor,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        let existing = self.load_committed_for_key(descriptor.key(), context)?;
        if existing.descriptor != *descriptor {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        self.verify_content(&existing.descriptor, None, context)?;
        Ok(false)
    }

    fn consume_stage(
        &self,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let marker = encode_consumed_marker(lease.staged.token(), &lease.record.descriptor);
        self.write_or_reuse_file(
            &self.consumed_tombstone_path(lease.staged.token()),
            &marker,
            context,
        )?;
        self.sync_relative(Path::new("staging/.consumed"))?;
        self.maybe_fail_fault(FAULT_CONSUME_MARKER)?;
        self.write_or_reuse_file(
            &self.stage_consumed_path(lease.staged.token()),
            &marker,
            context,
        )?;
        self.sync_relative(&self.relative(&self.stage_dir(lease.staged.token()))?)
    }

    fn prepare_descriptor(
        &self,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<PathBuf, StorageError> {
        let path = self.stage_dir(lease.staged.token()).join("descriptor");
        let bytes = encode_committed_record(&lease.record.descriptor);
        self.write_or_reuse_file(&path, &bytes, context)?;
        Ok(path)
    }

    fn ensure_content_parent(
        &self,
        digest: AssetDigest,
        context: &RequestContext,
    ) -> Result<PathBuf, StorageError> {
        let encoded = hex(digest.as_bytes());
        let path = Path::new("committed/sha256").join(&encoded[..2]);
        self.ensure_dir(path, Some(context))
    }

    fn ensure_descriptor_parent(
        &self,
        key: &AssetKey,
        context: &RequestContext,
    ) -> Result<PathBuf, StorageError> {
        let path = Path::new("descriptors").join(hex(&tenant_path_digest(key.tenant_id())));
        self.ensure_dir(path, Some(context))
    }

    fn retire_stage(&self, lease: &StageLease<'_>) -> Result<(), StorageError> {
        let token = lease.staged.token();
        let stage = self.stage_dir(token);
        for entry in STAGE_ENTRY_NAMES {
            self.remove_if_present(&stage.join(entry))?;
        }
        self.remove_dir(&stage).map_err(commit_indeterminate)?;
        self.pause_after_stage_retire()?;
        self.remove_file(&self.stage_lock_path(token))
            .map_err(commit_indeterminate)?;
        self.sync_relative(Path::new("staging"))
            .map_err(commit_indeterminate)?;
        self.sync_relative(Path::new("staging/.locks"))
            .map_err(commit_indeterminate)
    }

    #[cfg(feature = "test-hooks")]
    fn pause_after_stage_retire(&self) -> Result<(), StorageError> {
        let barrier = self
            .stage_retire_barrier
            .lock()
            .map_err(|_| internal_failure())?
            .take();
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
        Ok(())
    }

    #[cfg(not(feature = "test-hooks"))]
    const fn pause_after_stage_retire(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn discard_stage(&self, token: &AssetStageToken) -> Result<(), StorageError> {
        let stage = self.stage_dir(token);
        for entry in STAGE_ENTRY_NAMES {
            self.remove_if_present(&stage.join(entry))?;
        }
        self.remove_if_present(&stage)?;
        self.remove_if_present(&self.stage_lock_path(token))?;
        self.sync_relative(Path::new("staging"))?;
        self.sync_relative(Path::new("staging/.locks"))
    }

    fn stage_created(
        &self,
        token: AssetStageToken,
        request: AssetStageRequest,
        source: &mut dyn Read,
        context: &RequestContext,
    ) -> Result<StagedAsset, (AssetStageToken, StorageError)> {
        match self.write_stage(&token, request, source, context) {
            Ok(descriptor) => Ok(StagedAsset::new(token, descriptor)),
            Err(error) => Err((token, error)),
        }
    }

    fn write_stage(
        &self,
        token: &AssetStageToken,
        request: AssetStageRequest,
        source: &mut dyn Read,
        context: &RequestContext,
    ) -> Result<AssetDescriptor, StorageError> {
        let content_path = self.stage_content_path(token);
        let descriptor = self.write_stage_content(&content_path, request, source, context)?;
        let manifest = encode_stage_record(token, &descriptor);
        if let Err(error) =
            self.create_and_write(&self.stage_manifest_path(token), &manifest, context)
        {
            let _ = self.remove_file(&content_path);
            return Err(error);
        }
        self.sync_relative(&self.relative(&self.stage_dir(token))?)?;
        Ok(descriptor)
    }

    fn finish_failed_stage<T>(
        &self,
        token: &AssetStageToken,
        error: StorageError,
    ) -> Result<T, StorageError> {
        let cleanup = self.discard_stage(token);
        if cleanup.is_err() && self.isolate_failed_stage(token).is_err() {
            return Err(commit_indeterminate_result());
        }
        Err(error)
    }

    fn commit_leased(
        &self,
        lease: StageLease<'_>,
        existing: Option<CommittedRecord>,
        context: &RequestContext,
    ) -> Result<AssetCommitReceipt, StorageError> {
        self.verify_stage_content(&lease, context)?;
        match existing {
            Some(existing) => self.finish_existing_commit(lease, existing, context),
            None => self.finish_new_commit(lease, context),
        }
    }

    fn finish_new_commit(
        &self,
        lease: StageLease<'_>,
        context: &RequestContext,
    ) -> Result<AssetCommitReceipt, StorageError> {
        self.prepare_publish_intent(&lease, context)?;
        self.install_content(&lease, context)?;
        let created = self.publish_descriptor(&lease, context)?;
        self.maybe_fail_fault(intent::FAULT_POST_DESCRIPTOR_VISIBILITY)
            .map_err(commit_indeterminate)?;
        let descriptor = lease.record.descriptor.clone();
        self.consume_stage(&lease, context)
            .map_err(|_| commit_indeterminate_result())?;
        let _ = self.retire_stage(&lease);
        let _ = lease.unlock();
        drop(lease);
        let status = if created {
            AssetCommitStatus::Stored
        } else {
            AssetCommitStatus::AlreadyStored
        };
        Ok(AssetCommitReceipt::new(descriptor, status))
    }

    fn finish_existing_commit(
        &self,
        lease: StageLease<'_>,
        existing: CommittedRecord,
        context: &RequestContext,
    ) -> Result<AssetCommitReceipt, StorageError> {
        if existing.descriptor != lease.record.descriptor {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        self.verify_content(&existing.descriptor, None, context)?;
        self.prepare_publish_intent(&lease, context)?;
        self.sync_existing_publication(&existing.descriptor, context)?;
        let descriptor = existing.descriptor;
        self.consume_stage(&lease, context)
            .map_err(|_| commit_indeterminate_result())?;
        let _ = self.retire_stage(&lease);
        let _ = lease.unlock();
        drop(lease);
        Ok(AssetCommitReceipt::new(
            descriptor,
            AssetCommitStatus::AlreadyStored,
        ))
    }

    fn write_stage_content(
        &self,
        path: &Path,
        request: AssetStageRequest,
        source: &mut dyn Read,
        context: &RequestContext,
    ) -> Result<AssetDescriptor, StorageError> {
        let mut file = self.create_file(path, context)?;
        let result = self.copy_declared_bytes(&mut file, source, request.byte_length(), context);
        let digest = match result {
            Ok(digest) => digest,
            Err(error) => {
                drop(file);
                let _ = self.remove_file(path);
                return Err(error);
            }
        };
        if let Err(error) = ensure_source_exhausted(source, context)
            .and_then(|()| file.sync_all().map_err(map_io))
            .and_then(|()| check_active(context))
            .and_then(|()| ensure_expected_digest(request.expected_digest(), digest))
        {
            drop(file);
            let _ = self.remove_file(path);
            return Err(error);
        }
        Ok(AssetDescriptor::new(
            AssetKey::new(request.tenant_id().clone(), digest),
            request.media_type().clone(),
            request.byte_length(),
        ))
    }

    fn copy_declared_bytes(
        &self,
        destination: &mut File,
        source: &mut dyn Read,
        length: AssetByteLength,
        context: &RequestContext,
    ) -> Result<AssetDigest, StorageError> {
        let mut hasher = Sha256::new();
        let mut remaining = length.get();
        let mut buffer = [0_u8; BUFFER_SIZE];
        while remaining > 0 {
            let read = read_chunk(source, &mut buffer, remaining, context)?;
            write_chunk(destination, &buffer[..read], context)?;
            hasher.update(&buffer[..read]);
            remaining -= read as u64;
        }
        Ok(AssetDigest::new(hasher.finalize().into()))
    }

    fn create_and_write(
        &self,
        path: &Path,
        bytes: &[u8],
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let mut file = self.create_file(path, context)?;
        if let Err(error) = write_and_sync(&mut file, bytes, context) {
            drop(file);
            let _ = self.remove_file(path);
            return Err(error);
        }
        Ok(())
    }

    fn write_or_reuse_file(
        &self,
        path: &Path,
        bytes: &[u8],
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        match self.create_and_write(path, bytes, context) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == StorageErrorCode::Conflict => {
                let (mut file, metadata) = self.open_managed_file(path, false, context)?;
                let current = read_bounded(&mut file, &metadata, MAX_RECORD_BYTES, context)?;
                if current == bytes {
                    Ok(())
                } else {
                    Err(integrity_failure())
                }
            }
            Err(error) => Err(error),
        }
    }

    fn prepare_rooted_path(&self, path: &Path) -> Result<(Dir, OsString), StorageError> {
        let relative = self.relative(path)?;
        let mut components = valid_components(&relative)?;
        let name = components.pop().ok_or_else(internal_failure)?;
        let parent = self.open_components(&components)?;
        Ok((parent, name))
    }

    fn open_components(&self, components: &[OsString]) -> Result<Dir, StorageError> {
        let mut directory = self.root_dir.try_clone().map_err(map_io)?;
        for component in components {
            directory = directory.open_dir_nofollow(component).map_err(map_io)?;
        }
        Ok(directory)
    }

    fn relative(&self, path: &Path) -> Result<PathBuf, StorageError> {
        path.strip_prefix(&self.root)
            .map(Path::to_path_buf)
            .map_err(|_| integrity_failure())
    }

    fn open_file(
        &self,
        path: &Path,
        writable: bool,
        create_new: bool,
    ) -> Result<(File, Metadata), StorageError> {
        let (parent, name) = self.prepare_rooted_path(path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(writable).create_new(create_new);
        options.follow(FollowSymlinks::No);
        #[cfg(unix)]
        options.mode(0o600);
        let file = self.open_candidate(&parent, &name, &options)?;
        self.validate_open_file(file)
    }

    fn open_candidate(
        &self,
        parent: &Dir,
        name: &OsString,
        options: &OpenOptions,
    ) -> Result<File, StorageError> {
        match parent.open_with(name, options) {
            Ok(file) => Ok(file),
            Err(error) => match parent.symlink_metadata(name) {
                Ok(metadata) if metadata.file_type().is_symlink() => Err(integrity_failure()),
                _ => Err(map_io(error)),
            },
        }
    }

    fn validate_open_file(&self, file: File) -> Result<(File, Metadata), StorageError> {
        let metadata = file.metadata().map_err(map_io)?;
        validate_regular_metadata(&metadata)?;
        Ok((file, metadata))
    }

    fn open_managed_file(
        &self,
        path: &Path,
        writable: bool,
        context: &RequestContext,
    ) -> Result<(File, Metadata), StorageError> {
        check_active(context)?;
        let output = self.open_file(path, writable, false)?;
        check_active(context)?;
        Ok(output)
    }

    fn managed_regular_metadata(
        &self,
        path: &Path,
        context: &RequestContext,
    ) -> Result<Metadata, StorageError> {
        check_active(context)?;
        let (parent, name) = self.prepare_rooted_path(path)?;
        let metadata = parent.symlink_metadata(name).map_err(map_io)?;
        validate_regular_metadata(&metadata)?;
        check_active(context)?;
        Ok(metadata)
    }

    fn ensure_dir(
        &self,
        relative: impl AsRef<Path>,
        context: Option<&RequestContext>,
    ) -> Result<PathBuf, StorageError> {
        check_optional_context(context)?;
        let relative = relative.as_ref().to_path_buf();
        let components = valid_components(&relative)?;
        if components.is_empty() {
            return Ok(relative);
        }
        for index in 0..components.len() {
            self.ensure_component(&components[..index], &components[index], context)?;
        }
        Ok(relative)
    }

    fn ensure_component(
        &self,
        parent_components: &[OsString],
        name: &OsString,
        context: Option<&RequestContext>,
    ) -> Result<(), StorageError> {
        let parent = self.open_components(parent_components)?;
        self.create_component(&parent, name)?;
        self.sync_parent_components(parent_components)?;
        check_optional_context(context)
    }

    fn create_component(&self, parent: &Dir, name: &OsString) -> Result<(), StorageError> {
        let builder = private_dir_builder();
        match parent.create_dir_with(name, &builder) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(map_io(error)),
        }
        parent.open_dir_nofollow(name).map_err(map_io)?;
        Ok(())
    }

    fn validate_dir(&self, relative: &Path, context: &RequestContext) -> Result<(), StorageError> {
        check_active(context)?;
        self.open_components(&valid_components(relative)?)?;
        check_active(context)
    }

    fn create_file(&self, path: &Path, context: &RequestContext) -> Result<File, StorageError> {
        check_active(context)?;
        let (file, _) = self.open_file(path, true, true)?;
        check_active(context)?;
        Ok(file)
    }

    fn remove_file(&self, path: &Path) -> Result<(), StorageError> {
        let (parent, name) = self.prepare_rooted_path(path)?;
        parent.remove_file(name).map_err(map_io)
    }

    fn remove_dir(&self, path: &Path) -> Result<(), StorageError> {
        let (parent, name) = self.prepare_rooted_path(path)?;
        parent.remove_dir(name).map_err(map_io)
    }

    fn remove_if_present(&self, path: &Path) -> Result<(), StorageError> {
        let (parent, name) = self.prepare_rooted_path(path)?;
        match parent.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(map_io(error)),
            Ok(metadata) if metadata.is_dir() => parent.remove_dir(&name).map_err(map_io),
            Ok(_) => parent.remove_file(&name).map_err(map_io),
        }
    }

    fn hard_link(
        &self,
        source: &Path,
        target: &Path,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        check_active(context)?;
        let (source_parent, source_name) = self.prepare_rooted_path(source)?;
        let (target_parent, target_name) = self.prepare_rooted_path(target)?;
        match source_parent.hard_link(&source_name, &target_parent, &target_name) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(map_io(error)),
        }
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        let (source_parent, source_name) = self.prepare_rooted_path(source)?;
        let (target_parent, target_name) = self.prepare_rooted_path(target)?;
        source_parent
            .rename(&source_name, &target_parent, &target_name)
            .map_err(map_io)
    }

    fn sync_relative(&self, relative: &Path) -> Result<(), StorageError> {
        self.sync_components(&valid_components(relative)?)
    }

    fn sync_parent_components(&self, components: &[OsString]) -> Result<(), StorageError> {
        self.sync_components(components)
    }

    fn sync_components(&self, components: &[OsString]) -> Result<(), StorageError> {
        let directory = self.open_sync_components(components)?;
        directory.into_std_file().sync_all().map_err(map_io)
    }

    #[cfg(windows)]
    fn open_sync_components(&self, components: &[OsString]) -> Result<Dir, StorageError> {
        let (parent_components, name) = match components.split_last() {
            Some((name, parent_components)) => (parent_components, name.as_os_str()),
            None => (&[][..], std::ffi::OsStr::new(".")),
        };
        let parent = self.open_components(parent_components)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .maybe_dir(true)
            .follow(FollowSymlinks::No);
        let directory = parent.open_with(name, &options).map_err(map_io)?.into_std();
        let metadata = directory.metadata().map_err(map_io)?;
        validate_sync_directory(&metadata)?;
        Ok(Dir::from_std_file(directory))
    }

    #[cfg(not(windows))]
    fn open_sync_components(&self, components: &[OsString]) -> Result<Dir, StorageError> {
        self.open_components(components)
    }
}

impl LocalVolumeAssetStoragePort for LocalVolume {
    fn stage(
        &self,
        request: AssetStageRequest,
        source: &mut dyn Read,
        context: &RequestContext,
    ) -> Result<StagedAsset, StorageError> {
        let _operation = acquire_operation(&self.operation_gate)?;
        self.check_owner(request.tenant_id(), context)?;
        let token = self.issuer.issue()?;
        self.create_stage_directory(&token, context)?;
        match self.stage_created(token, request, source, context) {
            Ok(staged) => Ok(staged),
            Err((token, error)) => self.finish_failed_stage(&token, error),
        }
    }

    fn commit(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<AssetCommitReceipt, StorageError> {
        self.commit_request(staged, context)
    }

    fn quarantine(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<AssetQuarantineReceipt, StorageError> {
        self.quarantine_request(staged, reason, context)
    }

    fn metadata(
        &self,
        key: &AssetKey,
        context: &RequestContext,
    ) -> Result<Option<AssetDescriptor>, StorageError> {
        let _operation = acquire_operation(&self.operation_gate)?;
        self.check_owner(key.tenant_id(), context)?;
        let Some(record) = self.load_optional_committed(key, context)? else {
            return Ok(None);
        };
        self.verify_content(&record.descriptor, None, context)?;
        Ok(Some(record.descriptor))
    }

    fn read_into(
        &self,
        key: &AssetKey,
        destination: &mut dyn Write,
        context: &RequestContext,
    ) -> Result<AssetDescriptor, StorageError> {
        let _operation = acquire_operation(&self.operation_gate)?;
        self.check_owner(key.tenant_id(), context)?;
        let descriptor = self.load_committed_for_key(key, context)?.descriptor;
        self.verify_content(&descriptor, Some(destination), context)?;
        Ok(descriptor)
    }
}

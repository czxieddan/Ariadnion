// crates/optional/ariadnion-storage-asset/src/local_volume/intent.rs - Rust source for Ariadnion.
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

#[cfg(feature = "test-hooks")]
use std::io::Read;
use std::io::{self, Write};
use std::path::Path;

use ariadnion_core::RequestContext;

use crate::manifest::{
    decode_publish_intent, decode_quarantine_intent, encode_publish_intent,
    encode_quarantine_intent, encode_recovery_marker, is_consumed_marker,
};
use crate::{
    AssetCommitReceipt, AssetQuarantineReason, AssetQuarantineReceipt, AssetStageToken,
    StagedAsset, StorageError, StorageErrorCode,
};

use super::{
    LocalVolume, MAX_RECORD_BYTES, StageLease, acquire_operation, check_active,
    commit_indeterminate, commit_indeterminate_result, encode_consumed_marker, integrity_failure,
    map_io, read_bounded, reason_name, valid_components, verify_marker_reader,
};

pub(super) const FAULT_POST_DESCRIPTOR_VISIBILITY: u16 = 8;
const FAULT_QUARANTINE_CLAIM_SYNC: u16 = 16;
const FAULT_QUARANTINE_RECOVERY_SYNC: u16 = 64;
const FAULT_QUARANTINE_SOURCE_PARENT_SYNC: u16 = 128;
const QUARANTINE_PARENT_SYNC_ORDER: [&str; 2] = ["quarantine", "staging"];
const FAILED_STAGE_PARENT_SYNC_ORDER: [&str; 2] = ["quarantine/recovery", "staging"];

impl LocalVolume {
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_consume_marker_failure(&self) -> Result<(), StorageError> {
        self.arm_fault(super::FAULT_CONSUME_MARKER)
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_quarantine_rename_failure(&self) -> Result<(), StorageError> {
        self.arm_fault(super::FAULT_QUARANTINE_RENAME)
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_publication_parent_sync_failure(&self) -> Result<(), StorageError> {
        self.arm_fault(super::FAULT_PUBLICATION_PARENT_SYNC)
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_descriptor_parent_sync_failure(&self) -> Result<(), StorageError> {
        self.arm_fault(super::FAULT_DESCRIPTOR_PARENT_SYNC)
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn pause_next_stage_retire_for_test(
        &self,
        barrier: std::sync::Arc<std::sync::Barrier>,
    ) -> Result<(), StorageError> {
        let mut slot = self
            .stage_retire_barrier
            .lock()
            .map_err(|_| super::internal_failure())?;
        if slot.is_some() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        *slot = Some(barrier);
        Ok(())
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn pause_next_quarantine_after_rename_for_test(
        &self,
        barrier: std::sync::Arc<std::sync::Barrier>,
    ) -> Result<(), StorageError> {
        let mut slot = self
            .quarantine_post_rename_barrier
            .lock()
            .map_err(|_| super::internal_failure())?;
        if slot.is_some() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        *slot = Some(barrier);
        Ok(())
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn pause_next_quarantine_recovery_before_lock_removal_for_test(
        &self,
        barrier: std::sync::Arc<std::sync::Barrier>,
    ) -> Result<(), StorageError> {
        let mut slot = self
            .quarantine_recovery_barrier
            .lock()
            .map_err(|_| super::internal_failure())?;
        if slot.is_some() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        *slot = Some(barrier);
        Ok(())
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_post_descriptor_visibility_failure(&self) -> Result<(), StorageError> {
        self.arm_fault(FAULT_POST_DESCRIPTOR_VISIBILITY)
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_quarantine_claim_sync_failure(&self) -> Result<(), StorageError> {
        self.arm_fault(FAULT_QUARANTINE_CLAIM_SYNC)
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_quarantine_recovery_sync_failure(&self) -> Result<(), StorageError> {
        self.arm_fault(FAULT_QUARANTINE_RECOVERY_SYNC)
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn inject_next_quarantine_source_parent_sync_failure(&self) -> Result<(), StorageError> {
        self.arm_fault(FAULT_QUARANTINE_SOURCE_PARENT_SYNC)
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub const fn quarantine_parent_sync_order_for_test() -> [&'static str; 2] {
        QUARANTINE_PARENT_SYNC_ORDER
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub const fn failed_stage_parent_sync_order_for_test() -> [&'static str; 2] {
        FAILED_STAGE_PARENT_SYNC_ORDER
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn pause_next_quarantine_after_visibility_check(
        &self,
        barrier: std::sync::Arc<std::sync::Barrier>,
    ) -> Result<(), StorageError> {
        let mut slot = self
            .quarantine_visibility_barrier
            .lock()
            .map_err(|_| super::internal_failure())?;
        if slot.is_some() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        *slot = Some(barrier);
        Ok(())
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn verify_marker_reader_for_test(
        source: &mut dyn Read,
        expected: &[u8],
    ) -> Result<(), StorageError> {
        verify_marker_reader(source, expected)
    }

    pub(super) fn commit_request(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<AssetCommitReceipt, StorageError> {
        let _operation = acquire_operation(&self.operation_gate)?;
        self.check_owner(staged.descriptor().tenant_id(), context)?;
        self.commit_after_reconciliation(staged, context)
    }

    fn commit_after_reconciliation(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<AssetCommitReceipt, StorageError> {
        if let Some(receipt) = self.reconcile_publish_intent(staged, context)? {
            return Ok(receipt);
        }
        let lease = self.load_stage(staged, context)?;
        self.reject_quarantine_claim(staged.token(), context)?;
        let existing = self.load_optional_committed(staged.descriptor().key(), context)?;
        self.commit_leased(lease, existing, context)
    }

    pub(super) fn quarantine_request(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<AssetQuarantineReceipt, StorageError> {
        let _operation = acquire_operation(&self.operation_gate)?;
        self.check_owner(staged.descriptor().tenant_id(), context)?;
        self.quarantine_after_reconciliation(staged, reason, context)
    }

    fn quarantine_after_reconciliation(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<AssetQuarantineReceipt, StorageError> {
        if self.publish_lineage_is_visible(staged, context)? {
            return Err(commit_indeterminate_result());
        }
        self.pause_after_quarantine_visibility_check()?;
        if let Some(receipt) = self.reconcile_quarantine_intent(staged, reason, context)? {
            return Ok(receipt);
        }
        self.quarantine_new_stage(staged, reason, context)
    }

    #[cfg(feature = "test-hooks")]
    fn pause_after_quarantine_visibility_check(&self) -> Result<(), StorageError> {
        let barrier = self
            .quarantine_visibility_barrier
            .lock()
            .map_err(|_| super::internal_failure())?
            .take();
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
        Ok(())
    }

    #[cfg(feature = "test-hooks")]
    fn pause_after_quarantine_rename(&self) -> Result<(), StorageError> {
        let barrier = self
            .quarantine_post_rename_barrier
            .lock()
            .map_err(|_| super::internal_failure())?
            .take();
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
        Ok(())
    }

    #[cfg(feature = "test-hooks")]
    fn pause_before_quarantine_recovery_lock_removal(&self) -> Result<(), StorageError> {
        let barrier = self
            .quarantine_recovery_barrier
            .lock()
            .map_err(|_| super::internal_failure())?
            .take();
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
        Ok(())
    }

    #[cfg(not(feature = "test-hooks"))]
    fn pause_after_quarantine_visibility_check(&self) -> Result<(), StorageError> {
        Ok(())
    }

    #[cfg(not(feature = "test-hooks"))]
    const fn pause_after_quarantine_rename(&self) -> Result<(), StorageError> {
        Ok(())
    }

    #[cfg(not(feature = "test-hooks"))]
    const fn pause_before_quarantine_recovery_lock_removal(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn publish_lineage_is_visible(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        if !self.valid_publish_intent_exists(staged, context)? {
            return Ok(false);
        }
        self.matching_committed_content_is_visible(staged, context)
    }

    fn matching_committed_content_is_visible(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        let Some(existing) = self.load_optional_committed(staged.descriptor().key(), context)?
        else {
            return Ok(false);
        };
        self.validate_visible_publish(&existing.descriptor, staged, context)?;
        Ok(true)
    }

    fn validate_visible_publish(
        &self,
        descriptor: &crate::AssetDescriptor,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        if descriptor != staged.descriptor() {
            return Err(integrity_failure());
        }
        self.verify_content(descriptor, None, context).map(|_| ())
    }

    fn valid_publish_intent_exists(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        let paths = [
            self.stage_publish_intent_path(staged.token()),
            self.quarantine_dir(staged.token()).join("publish-intent"),
        ];
        for path in paths {
            let Some(bytes) = self.read_optional_marker(&path, context)? else {
                continue;
            };
            decode_publish_intent(&bytes, staged)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn quarantine_new_stage(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<AssetQuarantineReceipt, StorageError> {
        let lease = self.load_stage(staged, context)?;
        self.reject_visible_publish_for_quarantine(staged, context)?;
        let target = self.quarantine_dir(staged.token());
        let descriptor = lease.record.descriptor.clone();
        self.ensure_quarantine_target_absent(&target)?;
        self.prepare_quarantine_intent(staged, reason, context)?;
        self.prepare_quarantine_claim(staged, &descriptor, reason, context)?;
        self.move_to_quarantine(staged, reason, &target, &lease, context)?;
        Ok(AssetQuarantineReceipt::new(descriptor, reason))
    }

    fn ensure_quarantine_target_absent(&self, target: &Path) -> Result<(), StorageError> {
        let quarantine = self.open_components(&valid_components(Path::new("quarantine"))?)?;
        let (_, target_name) = self.prepare_rooted_path(target)?;
        match quarantine.symlink_metadata(&target_name) {
            Ok(_) => Err(StorageError::new(StorageErrorCode::Conflict)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(map_io(error)),
        }
    }

    fn prepare_quarantine_claim(
        &self,
        staged: &StagedAsset,
        descriptor: &crate::AssetDescriptor,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.write_or_reuse_file(
            &self.stage_reason_path(staged.token()),
            reason_name(reason).as_bytes(),
            context,
        )?;
        self.maybe_fail_fault(FAULT_QUARANTINE_CLAIM_SYNC)?;
        self.sync_relative(&self.relative(&self.stage_dir(staged.token()))?)?;
        let marker = encode_consumed_marker(staged.token(), descriptor);
        self.write_or_reuse_file(
            &self.consumed_tombstone_path(staged.token()),
            &marker,
            context,
        )?;
        self.sync_relative(Path::new("staging/.consumed"))?;
        check_active(context)
    }

    fn move_to_quarantine(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        target: &Path,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        check_active(context)?;
        self.rename(&self.stage_dir(staged.token()), target)
            .map_err(commit_indeterminate)?;
        self.maybe_fail_fault(super::FAULT_QUARANTINE_RENAME)
            .map_err(commit_indeterminate)?;
        self.pause_after_quarantine_rename()
            .map_err(commit_indeterminate)?;
        self.sync_quarantine_move_parents()?;
        self.validate_quarantine_record(target, staged, reason, context)
            .map_err(|_| commit_indeterminate_result())?;
        let _ = lease.unlock();
        let _ = self.remove_file(&self.stage_lock_path(staged.token()));
        let _ = self.sync_relative(Path::new("staging/.locks"));
        Ok(())
    }

    pub(super) fn read_optional_marker(
        &self,
        path: &Path,
        context: &RequestContext,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        match self.open_managed_file(path, false, context) {
            Ok((mut file, metadata)) => {
                read_bounded(&mut file, &metadata, MAX_RECORD_BYTES, context).map(Some)
            }
            Err(error) if error.code() == StorageErrorCode::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn consumed_marker_exists(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        let paths = [
            self.consumed_tombstone_path(staged.token()),
            self.stage_consumed_path(staged.token()),
        ];
        let mut found = false;
        for path in paths {
            let Some(bytes) = self.read_optional_marker(&path, context)? else {
                continue;
            };
            if !is_consumed_marker(&bytes, staged.token(), staged.descriptor()) {
                return Err(integrity_failure());
            }
            found = true;
        }
        Ok(found)
    }

    fn consumed_tombstone_exists(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        let Some(bytes) =
            self.read_optional_marker(&self.consumed_tombstone_path(staged.token()), context)?
        else {
            return Ok(false);
        };
        if !is_consumed_marker(&bytes, staged.token(), staged.descriptor()) {
            return Err(integrity_failure());
        }
        Ok(true)
    }

    pub(super) fn reconcile_publish_intent(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<Option<AssetCommitReceipt>, StorageError> {
        if !self.publish_intent_ready(staged, context)? {
            return Ok(None);
        }
        self.reconcile_published_stage(staged, context).map(Some)
    }

    fn publish_intent_ready(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        let path = self.stage_publish_intent_path(staged.token());
        let Some(bytes) = self.read_optional_marker(&path, context)? else {
            return Ok(false);
        };
        decode_publish_intent(&bytes, staged)?;
        self.consumed_marker_exists(staged, context)
    }

    fn reconcile_published_stage(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<AssetCommitReceipt, StorageError> {
        let lock = self.open_stage_lock(staged)?;
        let record = self.read_stage_record(staged, context)?;
        self.validate_stage_content(staged, &record, context)?;
        let existing = self.load_matching_committed(staged, &record, context)?;
        let lease = StageLease {
            lock,
            staged,
            record,
        };
        self.finish_existing_commit(lease, existing, context)
    }

    fn load_matching_committed(
        &self,
        staged: &StagedAsset,
        record: &super::StageRecord,
        context: &RequestContext,
    ) -> Result<super::CommittedRecord, StorageError> {
        let Some(existing) = self.load_optional_committed(staged.descriptor().key(), context)?
        else {
            return Err(commit_indeterminate_result());
        };
        if existing.descriptor != record.descriptor {
            return Err(integrity_failure());
        }
        Ok(existing)
    }

    pub(super) fn prepare_publish_intent(
        &self,
        lease: &StageLease<'_>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let bytes = encode_publish_intent(lease.staged.token(), &lease.record.descriptor);
        self.write_or_reuse_file(
            &self.stage_publish_intent_path(lease.staged.token()),
            &bytes,
            context,
        )?;
        self.sync_relative(&self.relative(&self.stage_dir(lease.staged.token()))?)?;
        check_active(context)
    }

    pub(super) fn reconcile_quarantine_intent(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<Option<AssetQuarantineReceipt>, StorageError> {
        if self.quarantine_target_intent_present(staged, context)? {
            return self.reconcile_quarantine_target(staged, reason, context);
        }
        let path = self.stage_quarantine_intent_path(staged.token());
        let Some(bytes) = self.read_optional_marker(&path, context)? else {
            return Ok(None);
        };
        decode_quarantine_intent(&bytes, staged, reason)?;
        self.reconcile_staged_quarantine(staged, reason, context)
    }

    fn quarantine_target_intent_present(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        Ok(self
            .read_optional_marker(
                &self
                    .quarantine_dir(staged.token())
                    .join("quarantine-intent"),
                context,
            )?
            .is_some())
    }

    fn reconcile_staged_quarantine(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<Option<AssetQuarantineReceipt>, StorageError> {
        if let Some(receipt) = self.reconcile_quarantine_target(staged, reason, context)? {
            return Ok(Some(receipt));
        }
        if !self.consumed_tombstone_exists(staged, context)? {
            return Ok(None);
        }
        self.move_consumed_stage_to_quarantine(staged, reason, context)
            .map(Some)
    }

    fn move_consumed_stage_to_quarantine(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<AssetQuarantineReceipt, StorageError> {
        let lease = self.prepare_consumed_quarantine_lease(staged, context)?;
        let target = self.quarantine_dir(staged.token());
        self.ensure_quarantine_target_absent(&target)?;
        self.move_to_quarantine(staged, reason, &target, &lease, context)?;
        Ok(AssetQuarantineReceipt::new(
            staged.descriptor().clone(),
            reason,
        ))
    }

    fn prepare_consumed_quarantine_lease<'a>(
        &'a self,
        staged: &'a StagedAsset,
        context: &RequestContext,
    ) -> Result<StageLease<'a>, StorageError> {
        let lock = self.open_stage_lock(staged)?;
        let record = self.read_stage_record(staged, context)?;
        self.validate_stage_content(staged, &record, context)?;
        let lease = StageLease {
            lock,
            staged,
            record,
        };
        self.reject_visible_publish_for_quarantine(staged, context)?;
        Ok(lease)
    }

    fn reject_visible_publish_for_quarantine(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        if self.publish_lineage_is_visible(staged, context)? {
            return Err(commit_indeterminate_result());
        }
        Ok(())
    }

    fn reconcile_quarantine_target(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<Option<AssetQuarantineReceipt>, StorageError> {
        let target = self.quarantine_dir(staged.token());
        let lock = self.open_stage_lock_if_present(staged)?;
        let Some(record) = self.load_quarantine_record(&target, staged, reason, context)? else {
            drop(lock);
            return Ok(None);
        };
        self.finish_quarantine_recovery(staged, lock.as_ref(), context)?;
        drop(lock);
        Ok(Some(AssetQuarantineReceipt::new(record.descriptor, reason)))
    }

    fn load_quarantine_record(
        &self,
        target: &Path,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<Option<super::StageRecord>, StorageError> {
        if !self.quarantine_manifest_exists(target, context)? {
            return Ok(None);
        }
        self.validate_quarantine_record(target, staged, reason, context)
            .map(Some)
    }

    fn quarantine_manifest_exists(
        &self,
        target: &Path,
        context: &RequestContext,
    ) -> Result<bool, StorageError> {
        match self.managed_regular_metadata(&target.join("manifest"), context) {
            Ok(_) => Ok(true),
            Err(error) if error.code() == StorageErrorCode::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn validate_quarantine_record(
        &self,
        target: &Path,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<super::StageRecord, StorageError> {
        self.validate_quarantine_markers(target, staged, reason, context)?;
        let record = self.read_stage_record_at(target, staged, context)?;
        self.validate_content_at(target, &record.descriptor, context)?;
        self.require_consumed_for_quarantine(staged, context)?;
        Ok(record)
    }

    fn validate_quarantine_markers(
        &self,
        target: &Path,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let intent = self
            .read_optional_marker(&target.join("quarantine-intent"), context)?
            .ok_or_else(integrity_failure)?;
        decode_quarantine_intent(&intent, staged, reason)?;
        let stored_reason = self
            .read_optional_marker(&target.join("reason"), context)?
            .ok_or_else(integrity_failure)?;
        if stored_reason != reason_name(reason).as_bytes() {
            return Err(integrity_failure());
        }
        Ok(())
    }

    fn require_consumed_for_quarantine(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        if !self.consumed_tombstone_exists(staged, context)? {
            return Err(integrity_failure());
        }
        Ok(())
    }

    fn finish_quarantine_recovery(
        &self,
        staged: &StagedAsset,
        lock: Option<&std::fs::File>,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.sync_quarantine_recovery_parents()?;
        if lock.is_some() {
            self.pause_before_quarantine_recovery_lock_removal()?;
            self.remove_if_present(&self.stage_lock_path(staged.token()))?;
        }
        self.sync_relative(Path::new("staging/.locks"))
            .map_err(commit_indeterminate)?;
        check_active(context)
    }

    fn sync_quarantine_move_parents(&self) -> Result<(), StorageError> {
        self.sync_relative(Path::new(QUARANTINE_PARENT_SYNC_ORDER[0]))
            .map_err(commit_indeterminate)?;
        self.sync_relative(Path::new(QUARANTINE_PARENT_SYNC_ORDER[1]))
            .map_err(commit_indeterminate)
    }

    fn sync_quarantine_recovery_parents(&self) -> Result<(), StorageError> {
        self.maybe_fail_fault(FAULT_QUARANTINE_RECOVERY_SYNC)
            .map_err(commit_indeterminate)?;
        self.sync_relative(Path::new(QUARANTINE_PARENT_SYNC_ORDER[0]))
            .map_err(commit_indeterminate)?;
        self.maybe_fail_fault(FAULT_QUARANTINE_SOURCE_PARENT_SYNC)
            .map_err(commit_indeterminate)?;
        self.sync_relative(Path::new(QUARANTINE_PARENT_SYNC_ORDER[1]))
            .map_err(commit_indeterminate)
    }

    pub(super) fn prepare_quarantine_intent(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let bytes = encode_quarantine_intent(staged.token(), staged.descriptor(), reason);
        self.write_or_reuse_file(
            &self.stage_quarantine_intent_path(staged.token()),
            &bytes,
            context,
        )?;
        self.sync_relative(&self.relative(&self.stage_dir(staged.token()))?)?;
        check_active(context)
    }

    pub(super) fn isolate_failed_stage(&self, token: &AssetStageToken) -> Result<(), StorageError> {
        let marker = self.recovery_marker_path(token);
        let marker_bytes = encode_recovery_marker(token);
        self.write_unchecked_or_reuse(&marker, &marker_bytes)?;
        self.sync_relative(Path::new("staging/.recovery"))?;
        self.ensure_dir(Path::new("quarantine/recovery"), None)?;
        let source = self.stage_dir(token);
        let target = self.failed_stage_target(token);
        self.rename_or_accept_missing(&source, &target)?;
        self.sync_failed_stage_rename_parents()?;
        self.remove_if_present(&self.stage_lock_path(token))?;
        self.sync_relative(Path::new("staging/.locks"))
    }

    fn sync_failed_stage_rename_parents(&self) -> Result<(), StorageError> {
        self.sync_relative(Path::new(FAILED_STAGE_PARENT_SYNC_ORDER[0]))?;
        self.sync_relative(Path::new(FAILED_STAGE_PARENT_SYNC_ORDER[1]))
    }

    fn rename_or_accept_missing(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        match self.rename(source, target) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == StorageErrorCode::NotFound => {
                self.accept_missing_source(source, error)
            }
            Err(error) if error.code() == StorageErrorCode::Conflict => {
                self.accept_existing_target(source, target, error)
            }
            Err(error) => Err(error),
        }
    }

    fn accept_missing_source(
        &self,
        source: &Path,
        error: StorageError,
    ) -> Result<(), StorageError> {
        if self.directory_exists(source)? {
            Err(error)
        } else {
            Ok(())
        }
    }

    fn accept_existing_target(
        &self,
        source: &Path,
        target: &Path,
        error: StorageError,
    ) -> Result<(), StorageError> {
        if self.directory_exists(target)? && !self.directory_exists(source)? {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn directory_exists(&self, path: &Path) -> Result<bool, StorageError> {
        let relative = self.relative(path)?;
        let components = super::valid_components(&relative)?;
        self.directory_exists_components(&components)
    }

    fn directory_exists_components(
        &self,
        components: &[std::ffi::OsString],
    ) -> Result<bool, StorageError> {
        if components.is_empty() {
            return Ok(true);
        }
        let name = self.directory_name(components)?;
        let parent = self.open_components(&components[..components.len() - 1])?;
        self.directory_metadata_exists(&parent, name)
    }

    fn directory_name(
        &self,
        components: &[std::ffi::OsString],
    ) -> Result<std::ffi::OsString, StorageError> {
        components
            .last()
            .cloned()
            .ok_or_else(super::internal_failure)
    }

    fn directory_metadata_exists(
        &self,
        parent: &cap_std::fs::Dir,
        name: std::ffi::OsString,
    ) -> Result<bool, StorageError> {
        match parent.symlink_metadata(name) {
            Ok(metadata) => Ok(metadata.is_dir() && !metadata.file_type().is_symlink()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(super::map_io(error)),
        }
    }

    fn write_unchecked_or_reuse(&self, path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
        match self.open_file(path, true, true) {
            Ok((mut file, _)) => {
                file.write_all(bytes).map_err(super::map_io)?;
                file.sync_all().map_err(super::map_io)
            }
            Err(error) if error.code() == StorageErrorCode::Conflict => {
                self.verify_existing_marker(path, bytes)
            }
            Err(error) => Err(error),
        }
    }

    fn verify_existing_marker(&self, path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
        let (mut file, metadata) = self.open_file(path, false, false)?;
        if metadata.len() > MAX_RECORD_BYTES {
            return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
        }
        verify_marker_reader(&mut file, bytes)
    }
}

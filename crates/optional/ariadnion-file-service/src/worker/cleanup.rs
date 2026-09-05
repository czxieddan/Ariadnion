// crates/optional/ariadnion-file-service/src/worker/cleanup.rs - Retained-stage cleanup jobs.
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

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use ariadnion_core::{CancellationToken, RequestContext};
use ariadnion_storage_asset::{
    AssetDescriptor, AssetQuarantineReason, AssetQuarantineReceipt, LocalVolumeAssetStoragePort,
    StagedAsset,
};

use super::{
    ApiFilesError, JobCell, WorkerJob, WorkerPhase, WorkerShared, fail_worker, internal_error,
    lock_worker, project_storage_error, unavailable_error,
};

/// A staged asset bound to the worker reservation that created it.
pub(crate) struct OperationGuard {
    shared: Arc<WorkerShared>,
    reservation: u64,
    staged: Option<StagedAsset>,
    cleanup: Option<RequestContext>,
    armed: bool,
}

impl OperationGuard {
    /// Returns verified staged metadata without exposing the opaque stage token.
    pub(crate) fn descriptor(&self) -> Result<&AssetDescriptor, ApiFilesError> {
        self.staged
            .as_ref()
            .map(StagedAsset::descriptor)
            .ok_or_else(internal_error)
    }

    pub(super) fn new(
        shared: Arc<WorkerShared>,
        reservation: u64,
        staged: StagedAsset,
        context: &RequestContext,
    ) -> Self {
        Self::from_retained(shared, reservation, staged, cleanup_context(context))
    }

    pub(super) fn from_retained(
        shared: Arc<WorkerShared>,
        reservation: u64,
        staged: StagedAsset,
        cleanup: RequestContext,
    ) -> Self {
        Self {
            shared,
            reservation,
            staged: Some(staged),
            cleanup: Some(cleanup),
            armed: true,
        }
    }

    pub(super) fn into_staged_with_cleanup(
        mut self,
        expected: &Arc<WorkerShared>,
    ) -> Result<(u64, StagedAsset, RequestContext), ApiFilesError> {
        if !Arc::ptr_eq(&self.shared, expected) {
            return Err(internal_error());
        }
        let Some(staged) = self.staged.take() else {
            return Err(internal_error());
        };
        let Some(cleanup) = self.cleanup.take() else {
            self.armed = false;
            contain_unresolved_stage(&self.shared, Some(staged));
            fail_worker(&self.shared);
            return Err(internal_error());
        };
        self.armed = false;
        Ok((self.reservation, staged, cleanup))
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let staged = self.staged.take();
        let cleanup = self.cleanup.take();
        retire_retained_stage(&self.shared, self.reservation, staged, cleanup);
    }
}

fn retire_retained_stage(
    shared: &Arc<WorkerShared>,
    reservation: u64,
    staged: Option<StagedAsset>,
    cleanup: Option<RequestContext>,
) {
    let outcome = match (staged, cleanup) {
        (Some(staged), Some(cleanup)) => enqueue_abandoned(shared, reservation, staged, cleanup),
        (Some(staged), None) => Err(staged),
        (None, _) => {
            fail_worker(shared);
            return;
        }
    };
    if let Err(staged) = outcome {
        contain_unresolved_stage(shared, Some(staged));
        fail_worker(shared);
    }
}

pub(super) fn cleanup_context(source: &RequestContext) -> RequestContext {
    RequestContext::new(
        source.request_id().clone(),
        source.trace_id().clone(),
        source.principal().cloned(),
        None,
        CancellationToken::new(),
    )
}

/// Retains the only unresolved opaque stage after the worker has failed closed.
///
/// The worker has one active reservation, so a failed state can retain at most one
/// inaccessible capability. It is neither a retry queue nor a recovery claim: no
/// storage operation is attempted after the handoff.
pub(super) fn contain_unresolved_stage(shared: &Arc<WorkerShared>, staged: Option<StagedAsset>) {
    let Some(staged) = staged else {
        return;
    };
    let (mut state, poisoned) = super::lock_recover(&shared.state);
    if poisoned {
        shared.state.clear_poison();
    }
    if state.unresolved_stage.is_none() {
        state.unresolved_stage = Some(staged);
        return;
    }
    drop(state);
    // A single worker reservation cannot own two unresolved stages. Keep the
    // pre-existing private capability and fail closed if that invariant is broken.
    fail_worker(shared);
}

/// Contains a stage when commit failed before invoking storage and no worker remains.
pub(super) fn contain_pre_call_commit_stage(
    shared: &Arc<WorkerShared>,
    staged: Option<StagedAsset>,
) {
    contain_unresolved_stage(shared, staged);
}

/// Contains a stage after storage commit may have crossed an unknown durable boundary.
pub(super) fn contain_inflight_commit_stage(
    shared: &Arc<WorkerShared>,
    staged: Option<StagedAsset>,
) {
    contain_unresolved_stage(shared, staged);
}

/// Moves a retryable private stage into the worker's existing retained slot.
pub(super) fn abandon_retained_stage(
    shared: &Arc<WorkerShared>,
    reservation: u64,
    staged: &mut Option<StagedAsset>,
    cleanup: &mut Option<RequestContext>,
) -> bool {
    let Some(staged) = staged.take() else {
        return false;
    };
    let Some(cleanup) = cleanup.take() else {
        contain_unresolved_stage(shared, Some(staged));
        fail_worker(shared);
        return false;
    };
    match enqueue_abandoned(shared, reservation, staged, cleanup) {
        Ok(()) => true,
        Err(staged) => {
            contain_unresolved_stage(shared, Some(staged));
            fail_worker(shared);
            false
        }
    }
}

/// A one-shot best-effort quarantine submitted by a dropped operation guard.
pub(super) struct AbandonedJob {
    staged: Option<StagedAsset>,
    context: RequestContext,
    shared: Arc<WorkerShared>,
}

impl AbandonedJob {
    fn new(staged: StagedAsset, context: RequestContext, shared: Arc<WorkerShared>) -> Self {
        Self {
            staged: Some(staged),
            context,
            shared,
        }
    }

    fn quarantine(
        &self,
        assets: &dyn LocalVolumeAssetStoragePort,
        staged: &StagedAsset,
    ) -> Result<(), ()> {
        catch_unwind(AssertUnwindSafe(|| {
            assets.quarantine(staged, AssetQuarantineReason::Abandoned, &self.context)
        }))
        .map_err(|_| ())?
        .map(|_| ())
        .map_err(|_| ())
    }
}

impl WorkerJob for AbandonedJob {
    fn execute(
        &mut self,
        assets: &dyn LocalVolumeAssetStoragePort,
        shared: &Arc<WorkerShared>,
        reservation: u64,
    ) {
        let Some(staged) = self.staged.as_ref() else {
            fail_worker(shared);
            return;
        };
        if self.quarantine(assets, staged).is_err() {
            contain_unresolved_stage(shared, self.staged.take());
            fail_worker(shared);
            return;
        }
        self.staged.take();
        if !release_running_reservation(shared, reservation) {
            fail_worker(shared);
        }
    }

    fn fail(&mut self, _error: ApiFilesError) {
        contain_unresolved_stage(&self.shared, self.staged.take());
    }

    fn cancellation(&self) -> CancellationToken {
        self.context.cancellation()
    }
}

/// A synchronously admitted explicit quarantine operation with detached observation.
pub(super) struct QuarantineJob {
    cell: Arc<JobCell<AssetQuarantineReceipt>>,
    context: RequestContext,
    staged: Option<StagedAsset>,
    reason: AssetQuarantineReason,
    shared: Arc<WorkerShared>,
}

impl QuarantineJob {
    pub(super) fn new(
        cell: Arc<JobCell<AssetQuarantineReceipt>>,
        context: RequestContext,
        staged: StagedAsset,
        reason: AssetQuarantineReason,
        shared: Arc<WorkerShared>,
    ) -> Self {
        Self {
            cell,
            context,
            staged: Some(staged),
            reason,
            shared,
        }
    }

    fn run(
        &self,
        assets: &dyn LocalVolumeAssetStoragePort,
    ) -> Result<AssetQuarantineReceipt, ApiFilesError> {
        self.context.check_active().map_err(ApiFilesError::from)?;
        let Some(staged) = self.staged.as_ref() else {
            return Err(internal_error());
        };
        catch_unwind(AssertUnwindSafe(|| {
            assets.quarantine(staged, self.reason, &self.context)
        }))
        .map_err(|_| internal_error())?
        .map_err(project_storage_error)
    }
}

impl WorkerJob for QuarantineJob {
    fn execute(
        &mut self,
        assets: &dyn LocalVolumeAssetStoragePort,
        shared: &Arc<WorkerShared>,
        reservation: u64,
    ) {
        match self.run(assets) {
            Ok(receipt) => {
                self.staged.take();
                let accepting = release_running_reservation(shared, reservation);
                self.cell.complete(if accepting {
                    Ok(receipt)
                } else {
                    Err(unavailable_error())
                });
            }
            Err(error) => {
                contain_unresolved_stage(shared, self.staged.take());
                fail_worker(shared);
                self.cell.complete(Err(error));
            }
        }
    }

    fn fail(&mut self, error: ApiFilesError) {
        contain_unresolved_stage(&self.shared, self.staged.take());
        self.cell.complete(Err(error));
    }

    fn cancellation(&self) -> CancellationToken {
        self.context.cancellation()
    }
}

/// Atomically installs one abandoned cleanup job in a retained worker slot.
pub(super) fn enqueue_abandoned(
    shared: &Arc<WorkerShared>,
    reservation: u64,
    staged: StagedAsset,
    context: RequestContext,
) -> Result<(), StagedAsset> {
    let (mut state, poisoned) = super::lock_recover(&shared.state);
    if poisoned {
        shared.state.clear_poison();
        drop(state);
        super::fail_worker(shared);
        return Err(staged);
    }
    let available = state.phase == WorkerPhase::Assigned
        && state.reservation == Some(reservation)
        && state.job.is_none();
    if !available {
        drop(state);
        return Err(staged);
    }
    state.active_cancellation = Some(context.cancellation());
    state.job = Some(Box::new(AbandonedJob::new(staged, context, shared.clone())));
    drop(state);
    shared.changed.notify_one();
    Ok(())
}

pub(super) fn retain_running_reservation(shared: &Arc<WorkerShared>, reservation: u64) -> bool {
    let (mut state, poisoned) = lock_worker(shared);
    if poisoned {
        return false;
    }
    if state.phase != WorkerPhase::Running || state.reservation != Some(reservation) {
        return false;
    }
    state.phase = WorkerPhase::Assigned;
    state.active_cancellation = None;
    true
}

pub(super) fn release_running_reservation(shared: &Arc<WorkerShared>, reservation: u64) -> bool {
    let (mut state, poisoned) = lock_worker(shared);
    if poisoned || state.reservation != Some(reservation) {
        return false;
    }
    state.reservation = None;
    state.active_cancellation = None;
    let accepting = state.phase == WorkerPhase::Running;
    if accepting {
        state.phase = WorkerPhase::Idle;
    }
    drop(state);
    shared.changed.notify_all();
    accepting
}

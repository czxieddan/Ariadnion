// crates/optional/ariadnion-file-service/src/service/upload.rs - Upload coordination for Ariadnion.
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

use std::future::{Future, poll_fn};
use std::io::Read;
use std::pin::Pin;
use std::task::Poll;

use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, BoxFileFuture, FileCatalogRecord, FileDescriptor, FileDigest,
    FileUploadReconciliation, FileUploadRequest, FileUploadSource, FileUploadSpecification,
};
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext};
use ariadnion_storage_asset::{
    AssetDescriptor, AssetDigest, AssetKey, AssetMediaType, AssetQuarantineReason,
    AssetStageRequest,
};

use super::{DurableFileService, require_authenticated_active};
use crate::pipe::{PipeAbortHandle, PipeAsyncSender, upload_pipe};
use crate::worker::{CommitDisposition, OperationGuard};

struct PreparedPublication {
    request: FileUploadRequest,
    staged: AssetDescriptor,
    descriptor: FileDescriptor,
    record: FileCatalogRecord,
}

struct PrivateStage {
    guard: OperationGuard,
    descriptor: AssetDescriptor,
}

enum StageFeedStep {
    Continue,
    Complete,
}

enum StageFeedError {
    Selected(ApiFilesError),
    Sender(ApiFilesError),
}

enum StageTransition {
    Worker(Result<OperationGuard, ApiFilesError>),
    EarlySuccess(OperationGuard),
    Feed(Result<StageFeedStep, StageFeedError>),
}

enum StageAdvance {
    Continue,
    Terminal(Box<Result<OperationGuard, ApiFilesError>>),
}

impl DurableFileService {
    /// Lazily stages, verifies, commits, and publishes one upload.
    ///
    /// Authentication and active-context checks occur before any source,
    /// dependency, worker, issuer, catalog, or storage work. The borrowed
    /// source remains on the caller side of the asynchronous pipe.
    pub fn upload<'a>(
        &'a self,
        request: FileUploadRequest,
        source: &'a mut dyn FileUploadSource,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDescriptor, ApiFilesError>> {
        Box::pin(async move { upload_operation(self, request, source, context).await })
    }

    /// Lazily reconciles an upload whose catalog publication outcome was unknown.
    ///
    /// Reconciliation uses authoritative catalog evidence and verifies the
    /// corresponding physical asset without issuing references or publishing.
    pub fn reconcile_upload<'a>(
        &'a self,
        request: &'a FileUploadRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileUploadReconciliation, ApiFilesError>> {
        Box::pin(async move { reconcile_upload_operation(self, request, context).await })
    }
}

async fn upload_operation(
    service: &DurableFileService,
    request: FileUploadRequest,
    source: &mut dyn FileUploadSource,
    context: &RequestContext,
) -> Result<FileDescriptor, ApiFilesError> {
    let owner = require_authenticated_active(context)?;
    let stage_request = asset_stage_request(owner, request.specification())?;
    let stage = validated_stage(
        service,
        source,
        context,
        owner,
        request.specification(),
        stage_request,
    )
    .await?;
    let observed_digest = FileDigest::new(*stage.descriptor.digest().as_bytes());
    let replay = service
        .catalog
        .resolve_upload_replay(&request, &observed_digest, context)
        .await;
    route_initial_replay(service, request, context, owner, stage, replay).await
}

async fn validated_stage(
    service: &DurableFileService,
    source: &mut dyn FileUploadSource,
    context: &RequestContext,
    owner: &PrincipalContext,
    specification: &FileUploadSpecification,
    stage_request: AssetStageRequest,
) -> Result<PrivateStage, ApiFilesError> {
    let (mut sender, mut stage_future, abort, ready_guard) =
        admit_stage(service, stage_request, context).await?;
    if let Some(guard) = ready_guard {
        return quarantine_primary(
            &service.worker,
            guard,
            AssetQuarantineReason::Abandoned,
            context,
            Err(ApiFilesError::new(ApiFilesErrorCode::Internal)),
        )
        .await;
    }
    let stage_guard = feed_stage(
        service,
        &mut sender,
        &mut stage_future,
        abort,
        source,
        context,
    )
    .await?;
    let staged = stage_guard
        .descriptor()
        .map_err(|_| integrity_error())?
        .clone();
    if !matches_asset(owner, specification, &staged) {
        return quarantine_primary(
            &service.worker,
            stage_guard,
            AssetQuarantineReason::IntegrityFailure,
            context,
            Err(integrity_error()),
        )
        .await;
    }
    Ok(PrivateStage {
        guard: stage_guard,
        descriptor: staged,
    })
}

async fn route_initial_replay(
    service: &DurableFileService,
    request: FileUploadRequest,
    context: &RequestContext,
    owner: &PrincipalContext,
    stage: PrivateStage,
    replay: Result<FileUploadReconciliation, ApiFilesError>,
) -> Result<FileDescriptor, ApiFilesError> {
    match replay {
        Ok(FileUploadReconciliation::Committed(original)) => {
            exact_replay(
                service,
                owner,
                context,
                stage.guard,
                stage.descriptor,
                original,
            )
            .await
        }
        Ok(FileUploadReconciliation::NotCommitted) => {
            prepare_new_upload(
                service,
                request,
                context,
                owner,
                stage.guard,
                stage.descriptor,
            )
            .await
        }
        Err(error) => {
            quarantine_primary(
                &service.worker,
                stage.guard,
                AssetQuarantineReason::Abandoned,
                context,
                Err(error),
            )
            .await
        }
    }
}

async fn admit_stage(
    service: &DurableFileService,
    request: AssetStageRequest,
    context: &RequestContext,
) -> Result<
    (
        PipeAsyncSender,
        Pin<Box<impl Future<Output = Result<OperationGuard, ApiFilesError>>>>,
        PipeAbortHandle,
        Option<OperationGuard>,
    ),
    ApiFilesError,
> {
    let (sender, reader, abort) = upload_pipe(context.clone());
    let mut stage_future = Box::pin(service.worker.submit_stage(
        request,
        Box::new(reader) as Box<dyn Read + Send>,
        context,
    ));
    if let Some(result) = poll_admission(&mut stage_future).await {
        result.map(|guard| (sender, stage_future, abort, Some(guard)))
    } else {
        Ok((sender, stage_future, abort, None))
    }
}

async fn feed_stage<F>(
    service: &DurableFileService,
    sender: &mut PipeAsyncSender,
    stage_future: &mut Pin<Box<F>>,
    abort: PipeAbortHandle,
    source: &mut dyn FileUploadSource,
    context: &RequestContext,
) -> Result<OperationGuard, ApiFilesError>
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    loop {
        match advance_stage(service, sender, stage_future, &abort, source, context).await {
            StageAdvance::Continue => {}
            StageAdvance::Terminal(result) => return *result,
        }
    }
}

async fn advance_stage<F>(
    service: &DurableFileService,
    sender: &mut PipeAsyncSender,
    stage_future: &mut Pin<Box<F>>,
    abort: &PipeAbortHandle,
    source: &mut dyn FileUploadSource,
    context: &RequestContext,
) -> StageAdvance
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    match poll_stage_and_feed(sender, stage_future, source, context).await {
        StageTransition::Worker(result) => StageAdvance::Terminal(Box::new(result)),
        StageTransition::EarlySuccess(guard) => StageAdvance::Terminal(Box::new(
            quarantine_primary(
                &service.worker,
                guard,
                AssetQuarantineReason::Abandoned,
                context,
                Err(ApiFilesError::new(ApiFilesErrorCode::Internal)),
            )
            .await,
        )),
        StageTransition::Feed(Ok(StageFeedStep::Continue)) => StageAdvance::Continue,
        StageTransition::Feed(Ok(StageFeedStep::Complete)) => {
            StageAdvance::Terminal(Box::new(stage_future.await))
        }
        StageTransition::Feed(Err(error)) => StageAdvance::Terminal(Box::new(
            resolve_feed_failure(service, stage_future, abort, context, error).await,
        )),
    }
}

async fn poll_stage_and_feed<F>(
    sender: &mut PipeAsyncSender,
    stage_future: &mut Pin<Box<F>>,
    source: &mut dyn FileUploadSource,
    context: &RequestContext,
) -> StageTransition
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    let mut feed = Box::pin(feed_one(sender, source, context));
    poll_fn(|task| match feed.as_mut().poll(task) {
        Poll::Ready(result @ Err(_)) => Poll::Ready(StageTransition::Feed(result)),
        Poll::Ready(Ok(StageFeedStep::Complete)) => {
            Poll::Ready(StageTransition::Feed(Ok(StageFeedStep::Complete)))
        }
        Poll::Ready(Ok(StageFeedStep::Continue)) => {
            poll_worker_after_feed_progress(stage_future, task)
        }
        Poll::Pending => poll_worker_after_pending_feed(stage_future, task),
    })
    .await
}

fn poll_worker_after_feed_progress<F>(
    stage_future: &mut Pin<Box<F>>,
    task: &mut std::task::Context<'_>,
) -> Poll<StageTransition>
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    match poll_worker_transition(stage_future, task) {
        Poll::Ready(transition) => Poll::Ready(transition),
        Poll::Pending => Poll::Ready(StageTransition::Feed(Ok(StageFeedStep::Continue))),
    }
}

fn poll_worker_after_pending_feed<F>(
    stage_future: &mut Pin<Box<F>>,
    task: &mut std::task::Context<'_>,
) -> Poll<StageTransition>
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    poll_worker_transition(stage_future, task)
}

fn poll_worker_transition<F>(
    stage_future: &mut Pin<Box<F>>,
    task: &mut std::task::Context<'_>,
) -> Poll<StageTransition>
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    match stage_future.as_mut().poll(task) {
        Poll::Ready(Ok(guard)) => Poll::Ready(StageTransition::EarlySuccess(guard)),
        Poll::Ready(Err(error)) => Poll::Ready(StageTransition::Worker(Err(error))),
        Poll::Pending => Poll::Pending,
    }
}

async fn feed_one(
    sender: &mut PipeAsyncSender,
    source: &mut dyn FileUploadSource,
    context: &RequestContext,
) -> Result<StageFeedStep, StageFeedError> {
    match source.next_chunk(context).await {
        Ok(Some(chunk)) => sender
            .offer(chunk, context)
            .await
            .map(|()| StageFeedStep::Continue)
            .map_err(StageFeedError::Sender),
        Ok(None) => sender
            .finish(context)
            .await
            .map(|()| StageFeedStep::Complete)
            .map_err(StageFeedError::Sender),
        Err(error) => Err(StageFeedError::Selected(error)),
    }
}

async fn resolve_feed_failure<F>(
    service: &DurableFileService,
    stage_future: &mut Pin<Box<F>>,
    abort: &PipeAbortHandle,
    context: &RequestContext,
    failure: StageFeedError,
) -> Result<OperationGuard, ApiFilesError>
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    match failure {
        StageFeedError::Selected(error) => {
            selected_stage_failure(service, stage_future, abort, context, error).await
        }
        StageFeedError::Sender(error) => {
            sender_failure(service, stage_future, abort, context, error).await
        }
    }
}

async fn sender_failure<F>(
    service: &DurableFileService,
    stage_future: &mut Pin<Box<F>>,
    abort: &PipeAbortHandle,
    context: &RequestContext,
    error: ApiFilesError,
) -> Result<OperationGuard, ApiFilesError>
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    if abort.io_fault_observed() {
        return selected_stage_failure(service, stage_future, abort, context, error).await;
    }
    match poll_stage_once(stage_future).await {
        Some(Ok(guard)) => {
            quarantine_primary(
                &service.worker,
                guard,
                AssetQuarantineReason::Abandoned,
                context,
                Err(error),
            )
            .await
        }
        Some(Err(worker_error)) => Err(worker_error),
        None => selected_stage_failure(service, stage_future, abort, context, error).await,
    }
}

async fn selected_stage_failure<F>(
    service: &DurableFileService,
    stage_future: &mut Pin<Box<F>>,
    abort: &PipeAbortHandle,
    context: &RequestContext,
    error: ApiFilesError,
) -> Result<OperationGuard, ApiFilesError>
where
    F: Future<Output = Result<OperationGuard, ApiFilesError>>,
{
    abort.abort_io_fault();
    match stage_future.await {
        Ok(guard) => {
            quarantine_primary(
                &service.worker,
                guard,
                AssetQuarantineReason::Abandoned,
                context,
                Err(error),
            )
            .await
        }
        Err(_) => Err(error),
    }
}

async fn exact_replay(
    service: &DurableFileService,
    owner: &PrincipalContext,
    context: &RequestContext,
    guard: OperationGuard,
    staged: AssetDescriptor,
    original: FileDescriptor,
) -> Result<FileDescriptor, ApiFilesError> {
    if !matches_file_asset(owner, &original, &staged) {
        return quarantine_primary(
            &service.worker,
            guard,
            AssetQuarantineReason::Abandoned,
            context,
            Err(integrity_error()),
        )
        .await;
    }
    let key = asset_key(owner, &original);
    let verification = service
        .worker
        .submit_reserved_metadata(guard, key, context)
        .await?;
    let (guard, result) = verification.into_parts();
    let primary = match result {
        Ok(Some(descriptor)) if descriptor == staged => Ok(original),
        Ok(Some(_)) | Ok(None) => Err(integrity_error()),
        Err(error) => Err(promote_visible_not_found(error)),
    };
    quarantine_primary(
        &service.worker,
        guard,
        AssetQuarantineReason::Abandoned,
        context,
        primary,
    )
    .await
}

async fn prepare_new_upload(
    service: &DurableFileService,
    request: FileUploadRequest,
    context: &RequestContext,
    owner: &PrincipalContext,
    guard: OperationGuard,
    staged: AssetDescriptor,
) -> Result<FileDescriptor, ApiFilesError> {
    let issued = service.issuer.issue_reference(context).await;
    let (guard, reference) = retain_stage_result(service, guard, context, issued).await?;
    let descriptor = FileDescriptor::new(
        reference,
        request.specification().display_name().clone(),
        request.specification().media_type().clone(),
        request.specification().byte_length(),
        FileDigest::new(*staged.digest().as_bytes()),
    );
    let record =
        FileCatalogRecord::from_authenticated_context(context, request.clone(), descriptor.clone());
    let (guard, record) = retain_stage_result(service, guard, context, record).await?;
    let guard = active_stage(service, guard, context).await?;
    let prepared = PreparedPublication {
        request,
        staged,
        descriptor,
        record,
    };
    commit_and_publish(service, context, owner, guard, prepared).await
}

async fn retain_stage_result<T>(
    service: &DurableFileService,
    guard: OperationGuard,
    context: &RequestContext,
    result: Result<T, ApiFilesError>,
) -> Result<(OperationGuard, T), ApiFilesError> {
    match result {
        Ok(value) => Ok((guard, value)),
        Err(error) => {
            quarantine_primary(
                &service.worker,
                guard,
                AssetQuarantineReason::Abandoned,
                context,
                Err(error),
            )
            .await
        }
    }
}

async fn active_stage(
    service: &DurableFileService,
    guard: OperationGuard,
    context: &RequestContext,
) -> Result<OperationGuard, ApiFilesError> {
    match context.check_active() {
        Ok(()) => Ok(guard),
        Err(error) => {
            quarantine_primary(
                &service.worker,
                guard,
                AssetQuarantineReason::Abandoned,
                context,
                Err(error.into()),
            )
            .await
        }
    }
}

async fn commit_and_publish(
    service: &DurableFileService,
    context: &RequestContext,
    owner: &PrincipalContext,
    guard: OperationGuard,
    prepared: PreparedPublication,
) -> Result<FileDescriptor, ApiFilesError> {
    let committed = commit_stage(service, guard, context).await?;
    validate_committed_receipt(owner, &prepared, committed.descriptor())?;
    context.check_active()?;
    publish_prepared(service, context, owner, prepared).await
}

async fn commit_stage(
    service: &DurableFileService,
    guard: OperationGuard,
    context: &RequestContext,
) -> Result<ariadnion_storage_asset::AssetCommitReceipt, ApiFilesError> {
    match service.worker.submit_commit(guard, context).await {
        Ok(CommitDisposition::Committed(receipt)) => Ok(receipt),
        Ok(CommitDisposition::Determinate { guard, error }) => {
            quarantine_primary(
                &service.worker,
                guard,
                AssetQuarantineReason::Abandoned,
                context,
                Err(error),
            )
            .await
        }
        Ok(CommitDisposition::Indeterminate(error)) | Err(error) => Err(error),
    }
}

fn validate_committed_receipt(
    owner: &PrincipalContext,
    prepared: &PreparedPublication,
    committed: &AssetDescriptor,
) -> Result<(), ApiFilesError> {
    if committed != &prepared.staged || !matches_file_asset(owner, &prepared.descriptor, committed)
    {
        return Err(integrity_error());
    }
    Ok(())
}

async fn publish_prepared(
    service: &DurableFileService,
    context: &RequestContext,
    owner: &PrincipalContext,
    prepared: PreparedPublication,
) -> Result<FileDescriptor, ApiFilesError> {
    match service.catalog.publish(&prepared.record, context).await {
        Ok(()) => Ok(prepared.descriptor),
        Err(error) if error.code() == ApiFilesErrorCode::Conflict => {
            resolve_publish_conflict(
                service,
                prepared.request,
                context,
                owner,
                prepared.descriptor,
            )
            .await
        }
        Err(error) => Err(error),
    }
}

async fn resolve_publish_conflict(
    service: &DurableFileService,
    request: FileUploadRequest,
    context: &RequestContext,
    owner: &PrincipalContext,
    descriptor: FileDescriptor,
) -> Result<FileDescriptor, ApiFilesError> {
    let observed = descriptor.digest().to_owned();
    match service
        .catalog
        .resolve_upload_replay(&request, &observed, context)
        .await
    {
        Ok(FileUploadReconciliation::Committed(original)) => {
            verify_conflict_replay(service, context, owner, descriptor, original).await
        }
        Ok(FileUploadReconciliation::NotCommitted) => Err(conflict_error()),
        Err(error) => Err(error),
    }
}

async fn verify_conflict_replay(
    service: &DurableFileService,
    context: &RequestContext,
    owner: &PrincipalContext,
    generated: FileDescriptor,
    original: FileDescriptor,
) -> Result<FileDescriptor, ApiFilesError> {
    if !matches_file_descriptors(&original, &generated) {
        return Err(integrity_error());
    }
    let key = asset_key(owner, &original);
    let physical = service.worker.submit_metadata(key, context).await;
    verify_visible_metadata(physical, owner, &original)?;
    Ok(original)
}

fn verify_visible_metadata(
    result: Result<Option<AssetDescriptor>, ApiFilesError>,
    owner: &PrincipalContext,
    descriptor: &FileDescriptor,
) -> Result<(), ApiFilesError> {
    match result {
        Ok(Some(physical)) if matches_file_asset(owner, descriptor, &physical) => Ok(()),
        Ok(Some(_)) | Ok(None) => Err(integrity_error()),
        Err(error) => Err(promote_visible_not_found(error)),
    }
}

async fn reconcile_upload_operation(
    service: &DurableFileService,
    request: &FileUploadRequest,
    context: &RequestContext,
) -> Result<FileUploadReconciliation, ApiFilesError> {
    let owner = require_authenticated_active(context)?;
    let reconciliation = service.catalog.reconcile_publish(request, context).await?;
    verify_reconciliation(service, context, owner, reconciliation).await
}

async fn verify_reconciliation(
    service: &DurableFileService,
    context: &RequestContext,
    owner: &PrincipalContext,
    reconciliation: FileUploadReconciliation,
) -> Result<FileUploadReconciliation, ApiFilesError> {
    match reconciliation {
        FileUploadReconciliation::NotCommitted => Ok(FileUploadReconciliation::NotCommitted),
        FileUploadReconciliation::Committed(descriptor) => {
            verify_committed_reconciliation(service, context, owner, descriptor).await
        }
    }
}

async fn verify_committed_reconciliation(
    service: &DurableFileService,
    context: &RequestContext,
    owner: &PrincipalContext,
    descriptor: FileDescriptor,
) -> Result<FileUploadReconciliation, ApiFilesError> {
    let key = asset_key(owner, &descriptor);
    let physical = service.worker.submit_metadata(key.clone(), context).await;
    verify_visible_metadata(physical, owner, &descriptor)?;
    let read = service
        .worker
        .submit_read(key, Box::new(std::io::sink()), context)
        .await
        .map_err(promote_visible_not_found)?;
    require_matching_asset(owner, &descriptor, &read)?;
    Ok(FileUploadReconciliation::Committed(descriptor))
}

fn require_matching_asset(
    owner: &PrincipalContext,
    descriptor: &FileDescriptor,
    asset: &AssetDescriptor,
) -> Result<(), ApiFilesError> {
    if !matches_file_asset(owner, descriptor, asset) {
        return Err(integrity_error());
    }
    Ok(())
}

async fn quarantine_primary<T>(
    worker: &crate::worker::TransferWorker,
    guard: OperationGuard,
    reason: AssetQuarantineReason,
    caller_context: &RequestContext,
    primary: Result<T, ApiFilesError>,
) -> Result<T, ApiFilesError> {
    let cleanup = cleanup_context(caller_context);
    let _ = worker.submit_quarantine(guard, reason, &cleanup).await;
    primary
}

fn cleanup_context(context: &RequestContext) -> RequestContext {
    RequestContext::new(
        context.request_id().clone(),
        context.trace_id().clone(),
        context.principal().cloned(),
        None,
        CancellationToken::new(),
    )
}

fn asset_stage_request(
    owner: &PrincipalContext,
    specification: &FileUploadSpecification,
) -> Result<AssetStageRequest, ApiFilesError> {
    let media_type = AssetMediaType::parse(specification.media_type().as_str())
        .map_err(|_| integrity_error())?;
    let byte_length =
        ariadnion_storage_asset::AssetByteLength::new(specification.byte_length().get() as u64)
            .map_err(|_| integrity_error())?;
    let expected_digest = specification
        .expected_digest()
        .map(|digest| AssetDigest::new(*digest.as_bytes()));
    Ok(AssetStageRequest::new(
        owner.tenant_id().clone(),
        media_type,
        byte_length,
        expected_digest,
    ))
}

fn asset_key(owner: &PrincipalContext, descriptor: &FileDescriptor) -> AssetKey {
    AssetKey::new(
        owner.tenant_id().clone(),
        AssetDigest::new(*descriptor.digest().as_bytes()),
    )
}

fn matches_asset(
    owner: &PrincipalContext,
    specification: &FileUploadSpecification,
    descriptor: &AssetDescriptor,
) -> bool {
    descriptor.tenant_id() == owner.tenant_id()
        && descriptor.media_type().as_str() == specification.media_type().as_str()
        && descriptor.byte_length().get() == specification.byte_length().get() as u64
        && specification
            .expected_digest()
            .is_none_or(|digest| descriptor.digest().as_bytes() == digest.as_bytes())
}

fn matches_file_descriptors(left: &FileDescriptor, right: &FileDescriptor) -> bool {
    left.digest() == right.digest()
        && left.media_type() == right.media_type()
        && left.byte_length() == right.byte_length()
}

fn matches_file_asset(
    owner: &PrincipalContext,
    descriptor: &FileDescriptor,
    asset: &AssetDescriptor,
) -> bool {
    asset.tenant_id() == owner.tenant_id()
        && asset.digest().as_bytes() == descriptor.digest().as_bytes()
        && asset.media_type().as_str() == descriptor.media_type().as_str()
        && asset.byte_length().get() == descriptor.byte_length().get() as u64
}

fn promote_visible_not_found(error: ApiFilesError) -> ApiFilesError {
    if error.code() == ApiFilesErrorCode::NotFound {
        integrity_error()
    } else {
        error
    }
}

fn integrity_error() -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure)
}

fn conflict_error() -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::Conflict)
}

async fn poll_admission<T, F>(future: &mut Pin<Box<F>>) -> Option<Result<T, ApiFilesError>>
where
    F: Future<Output = Result<T, ApiFilesError>>,
{
    poll_stage_once(future).await
}

async fn poll_stage_once<T, F>(future: &mut Pin<Box<F>>) -> Option<Result<T, ApiFilesError>>
where
    F: Future<Output = Result<T, ApiFilesError>>,
{
    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Ready(result) => Poll::Ready(Some(result)),
        Poll::Pending => Poll::Ready(None),
    })
    .await
}

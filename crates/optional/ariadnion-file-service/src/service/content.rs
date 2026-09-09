// crates/optional/ariadnion-file-service/src/service/content.rs - Durable file content streaming.
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
use std::pin::Pin;
use std::task::{Context, Poll};

use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, BoxFileFuture, FileDescriptor, FileDownloadSink,
    FileReference,
};
use ariadnion_core::{PrincipalContext, RequestContext};
use ariadnion_storage_asset::{AssetDescriptor, AssetDigest, AssetKey};

use super::{DurableFileService, require_authenticated_active};
use crate::pipe::{PipeAbortHandle, PipeAsyncReceiver, PipeReceivedChunk, download_pipe};

struct WorkerState<F> {
    future: Option<Pin<Box<F>>>,
    result: Option<Result<AssetDescriptor, ApiFilesError>>,
}

struct Verification<'a> {
    owner: &'a PrincipalContext,
    visible: &'a FileDescriptor,
}

struct DeliveryState<'a, F> {
    receiver: &'a mut PipeAsyncReceiver,
    abort: &'a PipeAbortHandle,
    worker: &'a mut WorkerState<F>,
    worker_result: Option<Result<AssetDescriptor, ApiFilesError>>,
    receiver_eof: bool,
    verification: Verification<'a>,
    sink: &'a mut dyn FileDownloadSink,
    context: &'a RequestContext,
}

enum DeliveryError {
    Worker(ApiFilesError),
    Receiver(ApiFilesError),
}

impl<F> WorkerState<F> {
    fn new(future: F) -> Self {
        Self {
            future: Some(Box::pin(future)),
            result: None,
        }
    }

    fn poll(&mut self, task: &mut Context<'_>)
    where
        F: Future<Output = Result<AssetDescriptor, ApiFilesError>>,
    {
        let Some(future) = self.future.as_mut() else {
            return;
        };
        if let Poll::Ready(result) = future.as_mut().poll(task) {
            self.result = Some(result);
            self.future = None;
        }
    }
}

impl DurableFileService {
    /// Lazily streams one visible file through an acknowledged bounded pipe.
    ///
    /// Authentication, metadata lookup, worker admission, receiver polling,
    /// sink delivery, descriptor verification, and finalization all occur only
    /// after the returned future is first polled. The worker result is observed
    /// exactly once and is arbitrated jointly with receiver progress so a
    /// terminal worker failure cannot be hidden by an open pipe.
    pub fn content<'a>(
        &'a self,
        reference: &'a FileReference,
        sink: &'a mut dyn FileDownloadSink,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDescriptor, ApiFilesError>> {
        Box::pin(async move { content_operation(self, reference, sink, context).await })
    }
}

async fn content_operation(
    service: &DurableFileService,
    reference: &FileReference,
    sink: &mut dyn FileDownloadSink,
    context: &RequestContext,
) -> Result<FileDescriptor, ApiFilesError> {
    let owner = require_authenticated_active(context)?;
    let visible = service.catalog.metadata(reference, context).await?;
    let key = asset_key(owner, &visible);
    let (writer, mut receiver, abort) = download_pipe(context.clone());
    let mut worker = WorkerState::new(service.worker.submit_streaming_read(key, writer, context));

    let admission = poll_worker_admission(&mut worker).await;
    if let Some(Err(error)) = admission.as_ref() {
        abort.abort();
        return Err(project_worker_error(*error));
    }
    DeliveryState {
        receiver: &mut receiver,
        abort: &abort,
        worker: &mut worker,
        worker_result: admission,
        receiver_eof: false,
        verification: Verification {
            owner,
            visible: &visible,
        },
        sink,
        context,
    }
    .run()
    .await
}

async fn poll_worker_admission(
    worker: &mut WorkerState<impl Future<Output = Result<AssetDescriptor, ApiFilesError>>>,
) -> Option<Result<AssetDescriptor, ApiFilesError>> {
    poll_fn(|task| {
        worker.poll(task);
        Poll::Ready(worker.result.take())
    })
    .await
}

impl<F> DeliveryState<'_, F>
where
    F: Future<Output = Result<AssetDescriptor, ApiFilesError>>,
{
    async fn run(&mut self) -> Result<FileDescriptor, ApiFilesError> {
        loop {
            if let Some(result) = self.progress().await? {
                return Ok(result);
            }
        }
    }

    async fn progress(&mut self) -> Result<Option<FileDescriptor>, ApiFilesError> {
        self.take_worker_result();
        if let Some(error) = worker_error(&self.worker_result) {
            self.abort.abort();
            return Err(error);
        }
        match self.next().await {
            Ok(Some(receipt)) => {
                deliver_chunk(self.receiver, self.abort, self.sink, self.context, receipt).await?;
                Ok(None)
            }
            Ok(None) => self.complete().await.map(Some),
            Err(error) => Err(self.resolve(error)),
        }
    }

    fn take_worker_result(&mut self) {
        if self.worker_result.is_none() {
            self.worker_result = self.worker.result.take();
        }
    }

    async fn next(&mut self) -> Result<Option<PipeReceivedChunk>, DeliveryError> {
        receive_with_worker(
            self.receiver,
            self.worker,
            &mut self.receiver_eof,
            &mut self.worker_result,
            self.context,
        )
        .await
    }

    fn resolve(&self, error: DeliveryError) -> ApiFilesError {
        match error {
            DeliveryError::Worker(error) => {
                self.abort.abort();
                error
            }
            DeliveryError::Receiver(error) => {
                self.abort.abort_io_fault();
                error
            }
        }
    }

    async fn complete(&mut self) -> Result<FileDescriptor, ApiFilesError> {
        let Some(descriptor) = self.worker_result.take().and_then(Result::ok) else {
            self.abort.abort_io_fault();
            return Err(integrity_error());
        };
        verify_descriptor(
            self.verification.owner,
            self.verification.visible,
            &descriptor,
        )
        .inspect_err(|_| self.abort.abort_io_fault())?;
        self.context
            .check_active()
            .map_err(ApiFilesError::from)
            .inspect_err(|_| self.abort.abort_io_fault())?;
        finish_sink(self.sink, self.context)
            .await
            .map(|()| self.verification.visible.clone())
            .inspect_err(|_| self.abort.abort_io_fault())
    }
}

async fn receive_with_worker(
    receiver: &mut PipeAsyncReceiver,
    worker: &mut WorkerState<impl Future<Output = Result<AssetDescriptor, ApiFilesError>>>,
    receiver_eof: &mut bool,
    worker_result: &mut Option<Result<AssetDescriptor, ApiFilesError>>,
    context: &RequestContext,
) -> Result<Option<PipeReceivedChunk>, DeliveryError> {
    if *receiver_eof {
        return wait_for_worker(worker, worker_result, context)
            .await
            .map(|()| None);
    }

    let mut receive = Box::pin(receiver.receive(context));
    poll_fn(|task| {
        poll_receive_progress(
            &mut receive,
            worker,
            receiver_eof,
            worker_result,
            context,
            task,
        )
    })
    .await
}

fn poll_receive_progress<F>(
    receive: &mut Pin<Box<F>>,
    worker: &mut WorkerState<impl Future<Output = Result<AssetDescriptor, ApiFilesError>>>,
    receiver_eof: &mut bool,
    worker_result: &mut Option<Result<AssetDescriptor, ApiFilesError>>,
    context: &RequestContext,
    task: &mut Context<'_>,
) -> Poll<Result<Option<PipeReceivedChunk>, DeliveryError>>
where
    F: Future<Output = Result<Option<PipeReceivedChunk>, ApiFilesError>>,
{
    if let Err(error) = context.check_active() {
        return Poll::Ready(Err(DeliveryError::Receiver(error.into())));
    }
    poll_worker_result(worker, worker_result, task);
    if let Some(error) = worker_error(worker_result) {
        return Poll::Ready(Err(DeliveryError::Worker(error)));
    }
    if *receiver_eof {
        return receiver_eof_progress(worker_result);
    }
    poll_open_receiver(receive, receiver_eof, worker, worker_result, task)
}

fn poll_open_receiver<F>(
    receive: &mut Pin<Box<F>>,
    receiver_eof: &mut bool,
    worker: &mut WorkerState<impl Future<Output = Result<AssetDescriptor, ApiFilesError>>>,
    worker_result: &mut Option<Result<AssetDescriptor, ApiFilesError>>,
    task: &mut Context<'_>,
) -> Poll<Result<Option<PipeReceivedChunk>, DeliveryError>>
where
    F: Future<Output = Result<Option<PipeReceivedChunk>, ApiFilesError>>,
{
    match poll_receiver(receive, receiver_eof, task) {
        Poll::Ready(Ok(None)) => receiver_eof_after_poll(worker, worker_result, task),
        Poll::Ready(Err(DeliveryError::Receiver(error))) => {
            resolve_receiver_error(error, worker, worker_result, task)
        }
        polled => polled,
    }
}

fn receiver_eof_progress(
    worker_result: &Option<Result<AssetDescriptor, ApiFilesError>>,
) -> Poll<Result<Option<PipeReceivedChunk>, DeliveryError>> {
    if worker_result.is_some() {
        Poll::Ready(Ok(None))
    } else {
        Poll::Pending
    }
}

fn receiver_eof_after_poll<F>(
    worker: &mut WorkerState<F>,
    worker_result: &mut Option<Result<AssetDescriptor, ApiFilesError>>,
    task: &mut Context<'_>,
) -> Poll<Result<Option<PipeReceivedChunk>, DeliveryError>>
where
    F: Future<Output = Result<AssetDescriptor, ApiFilesError>>,
{
    poll_worker_result(worker, worker_result, task);
    if let Some(error) = worker_error(worker_result) {
        Poll::Ready(Err(DeliveryError::Worker(error)))
    } else {
        receiver_eof_progress(worker_result)
    }
}

fn poll_worker_result(
    worker: &mut WorkerState<impl Future<Output = Result<AssetDescriptor, ApiFilesError>>>,
    worker_result: &mut Option<Result<AssetDescriptor, ApiFilesError>>,
    task: &mut Context<'_>,
) {
    worker.poll(task);
    if let Some(result) = worker.result.take() {
        *worker_result = Some(result);
    }
}

fn worker_error(
    worker_result: &Option<Result<AssetDescriptor, ApiFilesError>>,
) -> Option<ApiFilesError> {
    match worker_result.as_ref() {
        Some(Err(error)) => Some(project_worker_error(*error)),
        _ => None,
    }
}

fn poll_receiver<F>(
    receive: &mut Pin<Box<F>>,
    receiver_eof: &mut bool,
    task: &mut Context<'_>,
) -> Poll<Result<Option<PipeReceivedChunk>, DeliveryError>>
where
    F: Future<Output = Result<Option<PipeReceivedChunk>, ApiFilesError>>,
{
    if *receiver_eof {
        return Poll::Pending;
    }
    match receive.as_mut().poll(task) {
        Poll::Ready(Ok(Some(receipt))) => Poll::Ready(Ok(Some(receipt))),
        Poll::Ready(Ok(None)) => {
            *receiver_eof = true;
            Poll::Ready(Ok(None))
        }
        Poll::Ready(Err(error)) => Poll::Ready(Err(DeliveryError::Receiver(error))),
        Poll::Pending => Poll::Pending,
    }
}

fn resolve_receiver_error(
    error: ApiFilesError,
    worker: &mut WorkerState<impl Future<Output = Result<AssetDescriptor, ApiFilesError>>>,
    worker_result: &mut Option<Result<AssetDescriptor, ApiFilesError>>,
    task: &mut Context<'_>,
) -> Poll<Result<Option<PipeReceivedChunk>, DeliveryError>> {
    poll_worker_result(worker, worker_result, task);
    if let Some(Err(worker_error)) = worker_result.as_ref() {
        return Poll::Ready(Err(DeliveryError::Worker(project_worker_error(
            *worker_error,
        ))));
    }
    Poll::Ready(Err(DeliveryError::Receiver(error)))
}

async fn wait_for_worker(
    worker: &mut WorkerState<impl Future<Output = Result<AssetDescriptor, ApiFilesError>>>,
    worker_result: &mut Option<Result<AssetDescriptor, ApiFilesError>>,
    context: &RequestContext,
) -> Result<(), DeliveryError> {
    poll_fn(|task| {
        if let Err(error) = context.check_active() {
            return Poll::Ready(Err(DeliveryError::Receiver(error.into())));
        }
        worker.poll(task);
        if let Some(result) = worker.result.take() {
            *worker_result = Some(result);
        }
        match worker_result.as_ref() {
            Some(Ok(_)) => Poll::Ready(Ok(())),
            Some(Err(error)) => {
                Poll::Ready(Err(DeliveryError::Worker(project_worker_error(*error))))
            }
            None => Poll::Pending,
        }
    })
    .await
}

async fn finish_sink<'a>(
    sink: &'a mut dyn FileDownloadSink,
    context: &'a RequestContext,
) -> Result<(), ApiFilesError> {
    context.check_active().map_err(ApiFilesError::from)?;
    let mut finish = sink.finish(context);
    let result = poll_fn(|task| {
        if let Err(error) = context.check_active() {
            return Poll::Ready(Err(ApiFilesError::from(error)));
        }
        finish.as_mut().poll(task)
    })
    .await?;
    context.check_active().map_err(ApiFilesError::from)?;
    Ok(result)
}

async fn deliver_chunk(
    receiver: &mut PipeAsyncReceiver,
    abort: &PipeAbortHandle,
    sink: &mut dyn FileDownloadSink,
    context: &RequestContext,
    receipt: PipeReceivedChunk,
) -> Result<(), ApiFilesError> {
    let sequence = receipt.sequence();
    let chunk = receipt.into_chunk();
    if let Err(error) = sink.write_chunk(chunk, context).await {
        abort.abort_io_fault();
        return Err(error);
    }
    receiver
        .acknowledge(sequence)
        .inspect_err(|_| abort.abort_io_fault())
}

fn asset_key(owner: &PrincipalContext, descriptor: &FileDescriptor) -> AssetKey {
    AssetKey::new(
        owner.tenant_id().clone(),
        AssetDigest::new(*descriptor.digest().as_bytes()),
    )
}

fn verify_descriptor(
    owner: &PrincipalContext,
    visible: &FileDescriptor,
    observed: &AssetDescriptor,
) -> Result<(), ApiFilesError> {
    if observed.tenant_id() != owner.tenant_id()
        || observed.media_type().as_str() != visible.media_type().as_str()
        || observed.byte_length().get() != visible.byte_length().get() as u64
        || observed.digest().as_bytes() != visible.digest().as_bytes()
    {
        return Err(integrity_error());
    }
    Ok(())
}

fn project_worker_error(error: ApiFilesError) -> ApiFilesError {
    if error.code() == ApiFilesErrorCode::NotFound {
        integrity_error()
    } else {
        error
    }
}

fn integrity_error() -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::IntegrityFailure)
}

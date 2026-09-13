// crates/optional/ariadnion-api-domain/src/batch/port.rs - Batch operation port for Ariadnion.
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
//! The runtime-neutral durable Batch operation port.

use std::future::Future;
use std::pin::Pin;

use ariadnion_core::RequestContext;

use super::{
    ApiBatchError, BatchCancelRequest, BatchCreateRequest, BatchListLimit, BatchListRequest,
    BatchOperation, BatchOperationId, integrity_failure, limit_exceeded,
};

/// A boxed asynchronous Batch operation result.
pub type BoxBatchFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bounded cursor page of Batch operation projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPage {
    data: Box<[BatchOperation]>,
    first_id: Option<BatchOperationId>,
    last_id: Option<BatchOperationId>,
    has_more: bool,
}

impl BatchPage {
    /// Creates a list page and derives its first and last IDs from the data.
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` when data exceeds the requested limit and
    /// `IntegrityFailure` when an empty page claims a following page.
    pub fn new(
        data: Vec<BatchOperation>,
        limit: BatchListLimit,
        has_more: bool,
    ) -> Result<Self, ApiBatchError> {
        if data.len() > limit.get() {
            return Err(limit_exceeded());
        }
        if data.is_empty() && has_more {
            return Err(integrity_failure());
        }
        let first_id = data.first().map(|operation| operation.id().clone());
        let last_id = data.last().map(|operation| operation.id().clone());
        Ok(Self {
            data: data.into_boxed_slice(),
            first_id,
            last_id,
            has_more,
        })
    }

    /// Returns the ordered operation projections.
    #[must_use]
    pub fn data(&self) -> &[BatchOperation] {
        &self.data
    }

    /// Returns the first operation identity, when the page is non-empty.
    #[must_use]
    pub const fn first_id(&self) -> Option<&BatchOperationId> {
        self.first_id.as_ref()
    }

    /// Returns the last operation identity, when the page is non-empty.
    #[must_use]
    pub const fn last_id(&self) -> Option<&BatchOperationId> {
        self.last_id.as_ref()
    }

    /// Returns whether another page follows.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

/// Injected durable Batch lifecycle capability owned by a later operations phase.
///
/// Implementations must authenticate the tenant from [`RequestContext`] before
/// authoritative lookup or mutation, check cancellation before deadline, and
/// preserve cancellation/deadline results until the durable boundary is known.
/// Every returned future is lazy: constructing it performs no I/O, allocation of
/// unbounded state, file reads, operation-ID issuance, or queue insertion. P4
/// adapters may validate and project protocol data, but must not execute JSONL
/// bodies or simulate durable progress in memory. An absent implementation must
/// project [`super::ApiBatchErrorCode::Unavailable`] rather than fabricate a
/// queued Batch.
pub trait BatchOperationPort: Send + Sync {
    /// Creates one durable Batch operation from a validated file summary.
    ///
    /// The operation port owns durable IDs, lifecycle persistence, restart
    /// recovery, output/error file production, and expiry. File values in the
    /// request and result are internal [`super::FileReference`] values only.
    fn create<'a>(
        &'a self,
        request: BatchCreateRequest,
        context: &'a RequestContext,
    ) -> BoxBatchFuture<'a, Result<BatchOperation, ApiBatchError>>;

    /// Retrieves one tenant-scoped durable Batch operation.
    ///
    /// Unknown or foreign IDs must return `NotFound` without revealing which
    /// scope check failed.
    fn retrieve<'a>(
        &'a self,
        operation_id: &'a BatchOperationId,
        context: &'a RequestContext,
    ) -> BoxBatchFuture<'a, Result<BatchOperation, ApiBatchError>>;

    /// Lists a bounded tenant-scoped page of durable Batch operations.
    fn list<'a>(
        &'a self,
        request: &'a BatchListRequest,
        context: &'a RequestContext,
    ) -> BoxBatchFuture<'a, Result<BatchPage, ApiBatchError>>;

    /// Requests cancellation of one durable Batch operation.
    ///
    /// Cancellation is idempotent only for the addressed operation and must not
    /// create a replacement operation or claim a second input file.
    fn cancel<'a>(
        &'a self,
        request: BatchCancelRequest,
        context: &'a RequestContext,
    ) -> BoxBatchFuture<'a, Result<BatchOperation, ApiBatchError>>;
}

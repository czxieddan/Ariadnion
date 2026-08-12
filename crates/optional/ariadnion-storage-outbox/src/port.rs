// crates/optional/ariadnion-storage-outbox/src/port.rs - Rust source for Ariadnion.
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
use std::time::SystemTime;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, TransactionPort};

use crate::{EnqueueStatus, NewOutboxMessage, OutboxLease, OutboxLeaseRequest, OutboxLeaseToken};

/// Persists and leases outbox messages through explicit transactions.
pub trait OutboxPort: Send + Sync {
    /// Enqueues a message in the caller's existing business transaction.
    ///
    /// Implementations must verify that the request tenant equals the message
    /// tenant and use `(tenant_id, idempotency_key)` as the idempotent boundary.
    fn enqueue(
        &self,
        transaction: &mut dyn TransactionPort,
        message: NewOutboxMessage,
        context: &RequestContext,
    ) -> Result<EnqueueStatus, StorageError>;

    /// Claims a bounded deterministic batch in one short transaction.
    ///
    /// Only pending messages whose availability time has arrived and expired
    /// leases may be claimed. Returned lease tokens must be unguessable and
    /// scoped to the exact worker, event, attempt, and expiry.
    fn claim(
        &self,
        transaction: &mut dyn TransactionPort,
        request: &OutboxLeaseRequest,
        now: SystemTime,
        context: &RequestContext,
    ) -> Result<Vec<OutboxLease>, StorageError>;

    /// Marks one currently owned lease delivered exactly once.
    fn mark_delivered(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        delivered_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Releases a transient failure for a bounded future retry time.
    fn release_for_retry(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        available_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError>;

    /// Moves one currently owned lease to a permanent dead-letter state.
    fn dead_letter(
        &self,
        transaction: &mut dyn TransactionPort,
        token: &OutboxLeaseToken,
        failed_at: SystemTime,
        context: &RequestContext,
    ) -> Result<(), StorageError>;
}

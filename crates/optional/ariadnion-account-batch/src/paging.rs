// crates/optional/ariadnion-account-batch/src/paging.rs - Stable batch outcome paging.
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

//! Stable, bounded reads of durable terminal item evidence.

use crate::execution::BatchItemOutcome;
use crate::{BatchError, BatchErrorCode, BatchIdentity, BatchItemOrdinal, BatchRevision, error};
use std::num::NonZeroU16;

/// Maximum terminal outcomes returned by one page.
pub const MAX_OUTCOME_PAGE_ITEMS: u16 = 1 << 10;

/// Typed cursor positioned after one immutable plan ordinal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutcomeCursor(BatchItemOrdinal);

impl OutcomeCursor {
    /// Creates a cursor positioned after an outcome ordinal.
    #[must_use]
    pub const fn after(ordinal: BatchItemOrdinal) -> Self {
        Self(ordinal)
    }

    /// Returns the last ordinal delivered before this cursor.
    #[must_use]
    pub const fn ordinal(self) -> BatchItemOrdinal {
        self.0
    }
}

/// Bounded maximum outcomes returned by one read.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutcomePageLimit(NonZeroU16);

impl OutcomePageLimit {
    /// Creates a non-zero page limit within the fixed maximum.
    ///
    /// # Errors
    /// Returns a stable argument or resource-limit error.
    pub fn new(value: u16) -> Result<Self, BatchError> {
        let Some(value) = NonZeroU16::new(value) else {
            return Err(error(BatchErrorCode::InvalidArgument));
        };
        if value.get() > MAX_OUTCOME_PAGE_ITEMS {
            return Err(error(BatchErrorCode::ResourceLimitExceeded));
        }
        Ok(Self(value))
    }

    /// Returns the bounded page size.
    #[must_use]
    pub const fn get(self) -> NonZeroU16 {
        self.0
    }
}

/// Tenant-scoped request for one stable outcome page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomePageRequest {
    identity: BatchIdentity,
    expected_revision: BatchRevision,
    after: Option<OutcomeCursor>,
    limit: OutcomePageLimit,
    total_items: u32,
}

impl OutcomePageRequest {
    /// Creates a stable ordered outcome-page request.
    #[must_use]
    pub const fn new(
        identity: BatchIdentity,
        expected_revision: BatchRevision,
        total_items: u32,
        after: Option<OutcomeCursor>,
        limit: OutcomePageLimit,
    ) -> Self {
        Self {
            identity,
            expected_revision,
            after,
            limit,
            total_items,
        }
    }

    /// Creates an outcome request bound to the immutable batch item count.
    #[must_use]
    pub const fn for_batch(
        identity: BatchIdentity,
        expected_revision: BatchRevision,
        total_items: u32,
        after: Option<OutcomeCursor>,
        limit: OutcomePageLimit,
    ) -> Self {
        Self::new(identity, expected_revision, total_items, after, limit)
    }

    /// Returns the tenant-scoped durable batch identity.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        &self.identity
    }

    /// Returns the durable revision that defines this outcome snapshot.
    #[must_use]
    pub const fn expected_revision(&self) -> BatchRevision {
        self.expected_revision
    }

    /// Returns the exclusive cursor when continuing a page sequence.
    #[must_use]
    pub const fn after(&self) -> Option<OutcomeCursor> {
        self.after
    }

    /// Returns the bounded page size.
    #[must_use]
    pub const fn limit(&self) -> OutcomePageLimit {
        self.limit
    }

    /// Returns the immutable number of items in the batch plan.
    #[must_use]
    pub const fn total_items(&self) -> u32 {
        self.total_items
    }
}

/// Constructor-validated page of durable terminal item evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomePage {
    identity: BatchIdentity,
    revision: BatchRevision,
    outcomes: Box<[BatchItemOutcome]>,
    next_cursor: Option<OutcomeCursor>,
}

impl OutcomePage {
    /// Creates a bounded, identity-checked, ordinal-ordered outcome page.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::InvalidPage`] for an oversized, empty
    /// continuation, cross-scoped, or non-increasing page.
    pub fn new(
        request: &OutcomePageRequest,
        outcomes: Vec<BatchItemOutcome>,
        has_more: bool,
    ) -> Result<Self, BatchError> {
        validate_page_size(request.limit, outcomes.len(), has_more)?;
        validate_page_order(request, &outcomes)?;
        let next_cursor = if has_more {
            outcomes
                .last()
                .map(|outcome| OutcomeCursor::after(outcome.ordinal()))
        } else {
            None
        };
        Ok(Self {
            identity: request.identity.clone(),
            revision: request.expected_revision,
            outcomes: outcomes.into_boxed_slice(),
            next_cursor,
        })
    }

    /// Returns the tenant-scoped durable batch identity for this page.
    #[must_use]
    pub const fn identity(&self) -> &BatchIdentity {
        &self.identity
    }

    /// Returns the durable revision shared by every page in this snapshot.
    #[must_use]
    pub const fn revision(&self) -> BatchRevision {
        self.revision
    }

    /// Returns the durable outcome evidence in immutable plan order.
    #[must_use]
    pub const fn outcomes(&self) -> &[BatchItemOutcome] {
        &self.outcomes
    }

    /// Returns the exclusive cursor for the next page when more evidence exists.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<OutcomeCursor> {
        self.next_cursor
    }
}

fn validate_page_size(
    limit: OutcomePageLimit,
    length: usize,
    has_more: bool,
) -> Result<(), BatchError> {
    if length > usize::from(limit.get().get()) {
        return Err(error(BatchErrorCode::InvalidPage));
    }
    if has_more && length == 0 {
        return Err(error(BatchErrorCode::InvalidPage));
    }
    Ok(())
}

fn validate_page_order(
    request: &OutcomePageRequest,
    outcomes: &[BatchItemOutcome],
) -> Result<(), BatchError> {
    if request.total_items == 0 || request.total_items as usize > crate::MAX_BATCH_ITEMS {
        return Err(error(BatchErrorCode::InvalidPage));
    }
    let mut previous = request.after.map(OutcomeCursor::ordinal);
    for outcome in outcomes {
        if outcome.identity() != &request.identity {
            return Err(error(BatchErrorCode::InvalidPage));
        }
        if previous.is_some_and(|ordinal| outcome.ordinal() <= ordinal) {
            return Err(error(BatchErrorCode::InvalidPage));
        }
        if request.total_items.le(&outcome.ordinal().get()) {
            return Err(error(BatchErrorCode::InvalidPage));
        }
        previous = Some(outcome.ordinal());
    }
    Ok(())
}

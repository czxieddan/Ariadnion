// crates/optional/ariadnion-api-domain/src/batch/timestamps.rs - Batch lifecycle timestamp contracts.
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
//! Bounded lifecycle timestamp values for Batch operations.

use std::time::SystemTime;

use super::{ApiBatchError, ApiBatchErrorCode};

/// Validated lifecycle timestamps associated with one Batch operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchTimestamps {
    created_at: SystemTime,
    in_progress_at: Option<SystemTime>,
    expires_at: Option<SystemTime>,
    finalizing_at: Option<SystemTime>,
    completed_at: Option<SystemTime>,
    failed_at: Option<SystemTime>,
    expired_at: Option<SystemTime>,
    cancelling_at: Option<SystemTime>,
    cancelled_at: Option<SystemTime>,
}

/// Optional lifecycle transitions supplied when constructing [`BatchTimestamps`].
///
/// The value groups the optional timestamps so the public constructor remains
/// bounded and callers cannot accidentally reorder lifecycle evidence. Each
/// timestamp is validated against the operation creation time by
/// [`BatchTimestamps::new`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BatchTimestampTransitions {
    in_progress_at: Option<SystemTime>,
    expires_at: Option<SystemTime>,
    finalizing_at: Option<SystemTime>,
    completed_at: Option<SystemTime>,
    failed_at: Option<SystemTime>,
    expired_at: Option<SystemTime>,
    cancelling_at: Option<SystemTime>,
    cancelled_at: Option<SystemTime>,
}

impl BatchTimestampTransitions {
    /// Creates an empty transition set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            in_progress_at: None,
            expires_at: None,
            finalizing_at: None,
            completed_at: None,
            failed_at: None,
            expired_at: None,
            cancelling_at: None,
            cancelled_at: None,
        }
    }

    /// Sets the transition-to-in-progress timestamp.
    #[must_use]
    pub const fn with_in_progress_at(mut self, value: Option<SystemTime>) -> Self {
        self.in_progress_at = value;
        self
    }

    /// Sets the completion-window expiry timestamp.
    #[must_use]
    pub const fn with_expires_at(mut self, value: Option<SystemTime>) -> Self {
        self.expires_at = value;
        self
    }

    /// Sets the transition-to-finalizing timestamp.
    #[must_use]
    pub const fn with_finalizing_at(mut self, value: Option<SystemTime>) -> Self {
        self.finalizing_at = value;
        self
    }

    /// Sets the successful completion timestamp.
    #[must_use]
    pub const fn with_completed_at(mut self, value: Option<SystemTime>) -> Self {
        self.completed_at = value;
        self
    }

    /// Sets the failure timestamp.
    #[must_use]
    pub const fn with_failed_at(mut self, value: Option<SystemTime>) -> Self {
        self.failed_at = value;
        self
    }

    /// Sets the expiry transition timestamp.
    #[must_use]
    pub const fn with_expired_at(mut self, value: Option<SystemTime>) -> Self {
        self.expired_at = value;
        self
    }

    /// Sets the cancellation-request timestamp.
    #[must_use]
    pub const fn with_cancelling_at(mut self, value: Option<SystemTime>) -> Self {
        self.cancelling_at = value;
        self
    }

    /// Sets the cancellation-completed timestamp.
    #[must_use]
    pub const fn with_cancelled_at(mut self, value: Option<SystemTime>) -> Self {
        self.cancelled_at = value;
        self
    }
}

impl BatchTimestamps {
    /// Creates timestamps whose optional values cannot precede creation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` when any supplied timestamp precedes `created_at`.
    pub fn new(
        created_at: SystemTime,
        transitions: BatchTimestampTransitions,
    ) -> Result<Self, ApiBatchError> {
        validate_timestamp_order(
            created_at,
            [
                transitions.in_progress_at,
                transitions.expires_at,
                transitions.finalizing_at,
                transitions.completed_at,
                transitions.failed_at,
                transitions.expired_at,
                transitions.cancelling_at,
                transitions.cancelled_at,
            ],
        )?;
        Ok(Self {
            created_at,
            in_progress_at: transitions.in_progress_at,
            expires_at: transitions.expires_at,
            finalizing_at: transitions.finalizing_at,
            completed_at: transitions.completed_at,
            failed_at: transitions.failed_at,
            expired_at: transitions.expired_at,
            cancelling_at: transitions.cancelling_at,
            cancelled_at: transitions.cancelled_at,
        })
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(self) -> SystemTime {
        self.created_at
    }

    /// Returns the transition-to-in-progress timestamp.
    #[must_use]
    pub const fn in_progress_at(self) -> Option<SystemTime> {
        self.in_progress_at
    }

    /// Returns the completion-window expiry timestamp.
    #[must_use]
    pub const fn expires_at(self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Returns the finalizing transition timestamp.
    #[must_use]
    pub const fn finalizing_at(self) -> Option<SystemTime> {
        self.finalizing_at
    }

    /// Returns the successful completion timestamp.
    #[must_use]
    pub const fn completed_at(self) -> Option<SystemTime> {
        self.completed_at
    }

    /// Returns the failure timestamp.
    #[must_use]
    pub const fn failed_at(self) -> Option<SystemTime> {
        self.failed_at
    }

    /// Returns the expiry transition timestamp.
    #[must_use]
    pub const fn expired_at(self) -> Option<SystemTime> {
        self.expired_at
    }

    /// Returns the cancellation-request timestamp.
    #[must_use]
    pub const fn cancelling_at(self) -> Option<SystemTime> {
        self.cancelling_at
    }

    /// Returns the cancellation-completed timestamp.
    #[must_use]
    pub const fn cancelled_at(self) -> Option<SystemTime> {
        self.cancelled_at
    }
}

fn validate_timestamp_order(
    created_at: SystemTime,
    values: [Option<SystemTime>; 8],
) -> Result<(), ApiBatchError> {
    if values.iter().flatten().any(|value| *value < created_at) {
        return Err(ApiBatchError::new(ApiBatchErrorCode::InvalidArgument));
    }
    Ok(())
}

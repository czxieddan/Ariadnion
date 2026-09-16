// crates/optional/ariadnion-account-batch/src/lifecycle.rs - Account batch lifecycle contracts for Ariadnion.
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

//! Coherent account-batch lifecycle and terminal transition rules.

use super::{BatchError, BatchErrorCode, UtcSeconds, error};

/// Coarse batch lifecycle with explicit terminal detail.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchLifecycle {
    /// The immutable plan is durable but no item has started.
    Planned,
    /// One or more items may be claimed or executing.
    Running,
    /// Cancellation is durable and no new item may be claimed.
    Cancelling,
    /// No further state or item-outcome mutation is permitted.
    Terminal(BatchTerminalState),
}

impl BatchLifecycle {
    /// Starts a planned batch before its deadline.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::DeadlineExceeded`] at or after the deadline and
    /// [`BatchErrorCode::InvalidTransition`] from any state other than planned.
    pub fn start(self, now: UtcSeconds, deadline: UtcSeconds) -> Result<Self, BatchError> {
        if now >= deadline {
            return Err(error(BatchErrorCode::DeadlineExceeded));
        }
        match self {
            Self::Planned => Ok(Self::Running),
            _ => Err(error(BatchErrorCode::InvalidTransition)),
        }
    }

    /// Requests cancellation with exact terminal replay.
    ///
    /// Planned work becomes terminal immediately, running work enters the
    /// cancelling state, and repeated cancelling or cancelled requests preserve
    /// state.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::InvalidTransition`] when another terminal
    /// result is already durable.
    pub const fn request_cancellation(self) -> Result<Self, BatchError> {
        match self {
            Self::Planned => Ok(Self::Terminal(BatchTerminalState::Cancelled)),
            Self::Running => Ok(Self::Cancelling),
            Self::Cancelling | Self::Terminal(BatchTerminalState::Cancelled) => Ok(self),
            Self::Terminal(_) => Err(error(BatchErrorCode::InvalidTransition)),
        }
    }

    /// Moves running or cancelling work to coherent terminal detail.
    ///
    /// Running work may complete or fail. Cancellation must first enter
    /// [`Self::Cancelling`] before it becomes cancelled. Already claimed work
    /// may finish while cancelling; terminal progress validation still requires
    /// every item to be complete for a successful or completed-with-failures
    /// result. Deadline termination is produced only by [`Self::expire`]. Exact
    /// terminal replay is idempotent.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::InvalidTransition`] for contradictory state.
    pub fn finish(self, terminal: BatchTerminalState) -> Result<Self, BatchError> {
        match self {
            Self::Running => finish_running(terminal),
            Self::Cancelling => finish_cancelling(terminal),
            Self::Terminal(existing) if existing == terminal => Ok(self),
            Self::Planned | Self::Terminal(_) => Err(error(BatchErrorCode::InvalidTransition)),
        }
    }

    /// Expires non-terminal work at or after its deadline.
    ///
    /// # Errors
    /// Returns [`BatchErrorCode::InvalidTransition`] before the deadline.
    pub fn expire(self, now: UtcSeconds, deadline: UtcSeconds) -> Result<Self, BatchError> {
        if now < deadline {
            return Err(error(BatchErrorCode::InvalidTransition));
        }
        match self {
            Self::Terminal(BatchTerminalState::DeadlineExceeded) => Ok(self),
            Self::Terminal(_) => Err(error(BatchErrorCode::InvalidTransition)),
            Self::Planned | Self::Running | Self::Cancelling => {
                Ok(Self::Terminal(BatchTerminalState::DeadlineExceeded))
            }
        }
    }
}

fn finish_running(terminal: BatchTerminalState) -> Result<BatchLifecycle, BatchError> {
    match terminal {
        BatchTerminalState::Succeeded
        | BatchTerminalState::CompletedWithFailures
        | BatchTerminalState::Failed => Ok(BatchLifecycle::Terminal(terminal)),
        BatchTerminalState::Cancelled | BatchTerminalState::DeadlineExceeded => {
            Err(error(BatchErrorCode::InvalidTransition))
        }
    }
}

fn finish_cancelling(terminal: BatchTerminalState) -> Result<BatchLifecycle, BatchError> {
    match terminal {
        BatchTerminalState::Cancelled
        | BatchTerminalState::Failed
        | BatchTerminalState::Succeeded
        | BatchTerminalState::CompletedWithFailures => Ok(BatchLifecycle::Terminal(terminal)),
        BatchTerminalState::DeadlineExceeded => Err(error(BatchErrorCode::InvalidTransition)),
    }
}

/// Immutable terminal detail for an account batch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchTerminalState {
    /// Every item produced a successful outcome for the selected intent.
    Succeeded,
    /// All items are terminal and at least one was rejected.
    CompletedWithFailures,
    /// Cancellation stopped remaining work.
    Cancelled,
    /// The absolute deadline stopped remaining work.
    DeadlineExceeded,
    /// A durable adapter failure prevented safe continuation.
    Failed,
}

/// Version-checked durable batch lifecycle mutation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchTransition {
    /// Move a planned batch to running before its deadline.
    Start,
    /// Persist cancellation before preventing new claims.
    RequestCancellation,
    /// Expire work whose deadline has been reached.
    Expire,
    /// Persist coherent terminal completion detail.
    Finish(BatchTerminalState),
}

impl BatchTransition {
    /// Validates transition timing against the immutable batch deadline.
    ///
    /// Start and cancellation must be observed before the deadline. Expiry is
    /// valid only at or after it; finish timing remains adapter-specific because
    /// an item may complete at any instant before terminal publication.
    pub fn validate_observed_at(
        self,
        observed_at: UtcSeconds,
        deadline: UtcSeconds,
    ) -> Result<(), BatchError> {
        let valid = match self {
            Self::Start | Self::RequestCancellation => observed_at < deadline,
            Self::Expire => observed_at >= deadline,
            Self::Finish(_) => true,
        };
        if valid {
            Ok(())
        } else {
            Err(error(BatchErrorCode::DeadlineExceeded))
        }
    }
}

// crates/optional/ariadnion-api-domain/src/stream.rs - Service stream contracts for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Bounded payload events for service response streams.

use std::fmt::{self, Debug, Formatter};

use crate::error::{ApiDomainError, invalid_argument, limit_exceeded};
use crate::request::ServiceContractVersion;
use crate::response::FinishReason;

/// Maximum encoded size of one text delta in UTF-8 bytes.
pub const MAX_TEXT_DELTA_BYTES: usize = 65_536;

/// A bounded nonempty text delta whose diagnostics never expose its content.
#[derive(Clone, Eq, PartialEq)]
pub struct TextDelta(Box<str>);

impl TextDelta {
    /// Validates and copies a text delta.
    ///
    /// Deltas must contain between 1 and 65,536 UTF-8 bytes and must not
    /// contain a NUL character.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] when the byte limit
    /// is exceeded and [`crate::ApiDomainErrorCode::InvalidArgument`] for an
    /// empty value or NUL.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_text_delta(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated delta to a trusted stream adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for TextDelta {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TextDelta")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A payload event produced by a text service stream.
///
/// Stream ordering, terminal-state enforcement, backpressure, and cancellation
/// belong to the stream port and its lifecycle envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TextStreamEvent {
    /// Announces the service contract used by subsequent payload events.
    Started {
        /// Service contract version used by this stream.
        version: ServiceContractVersion,
    },
    /// Carries one bounded increment of generated text.
    Delta(TextDelta),
    /// Reports normal stream completion without retaining accumulated output.
    Completed {
        /// Reason generation ended.
        finish_reason: FinishReason,
    },
    /// Reports a terminal redacted service failure.
    Failed(ApiDomainError),
}

/// A transport-neutral service stream payload event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServiceStreamEvent {
    /// An event from a text service stream.
    Text(TextStreamEvent),
}

fn validate_text_delta(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_TEXT_DELTA_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.contains('\0') {
        return Err(invalid_argument());
    }
    Ok(())
}

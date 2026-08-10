// crates/optional/ariadnion-api-domain/src/usage.rs - Token usage contracts for Ariadnion.
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
//! Checked provider-neutral token usage values.

use crate::error::{ApiDomainError, limit_exceeded};

/// Checked input, output, and total token counts for one service result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TokenUsage {
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
}

impl TokenUsage {
    /// Builds usage from input and output counts with a checked total.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] when the sum cannot
    /// be represented as `u64`.
    pub fn new(input_tokens: u64, output_tokens: u64) -> Result<Self, ApiDomainError> {
        let total_tokens = input_tokens
            .checked_add(output_tokens)
            .ok_or_else(limit_exceeded)?;
        Ok(Self {
            input_tokens,
            output_tokens,
            total_tokens,
        })
    }

    /// Returns tokens consumed from service input.
    #[must_use]
    pub const fn input_tokens(self) -> u64 {
        self.input_tokens
    }

    /// Returns tokens generated in service output.
    #[must_use]
    pub const fn output_tokens(self) -> u64 {
        self.output_tokens
    }

    /// Returns the checked sum of input and output tokens.
    #[must_use]
    pub const fn total_tokens(self) -> u64 {
        self.total_tokens
    }
}

// crates/optional/ariadnion-provider-mock/src/chunk.rs - Rust source for Ariadnion.
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
//! UTF-8-safe deterministic chunking for mock text and chat output.

use ariadnion_api_domain::TextDelta;
use ariadnion_provider_sdk::{ProviderFailure, ProviderFailureClass};

use crate::MAX_MOCK_STREAM_DELTA_BYTES;

pub(crate) fn for_each_delta(
    prefix: &str,
    content: &str,
    scalar_limit: usize,
    mut emit: impl FnMut(TextDelta) -> Result<(), ProviderFailure>,
) -> Result<(), ProviderFailure> {
    let mut chunk = String::with_capacity(MAX_MOCK_STREAM_DELTA_BYTES);
    for character in prefix.chars().chain(content.chars()).take(scalar_limit) {
        if next_character_exceeds(&chunk, character) {
            flush(&mut chunk, &mut emit)?;
        }
        chunk.push(character);
    }
    flush(&mut chunk, &mut emit)
}

fn next_character_exceeds(chunk: &str, character: char) -> bool {
    !chunk.is_empty()
        && chunk
            .len()
            .checked_add(character.len_utf8())
            .is_none_or(|bytes| bytes > MAX_MOCK_STREAM_DELTA_BYTES)
}

fn flush(
    chunk: &mut String,
    emit: &mut impl FnMut(TextDelta) -> Result<(), ProviderFailure>,
) -> Result<(), ProviderFailure> {
    if chunk.is_empty() {
        return Ok(());
    }
    let delta = TextDelta::new(chunk).map_err(|_| response_limit())?;
    emit(delta)?;
    chunk.clear();
    Ok(())
}

const fn response_limit() -> ProviderFailure {
    ProviderFailure::new(ProviderFailureClass::ResponseLimit)
}

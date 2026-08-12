// crates/optional/ariadnion-api-domain/src/request/debug.rs - Redacted request diagnostics for Ariadnion.
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
//! Redacted diagnostics for bounded service request values.

use std::fmt::{self, Debug, Formatter};

use super::{
    ChatServiceRequest, EmbeddingServiceRequest, IdempotencyKey, ImageServiceRequest, TextInput,
    TextServiceRequest,
};

impl Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyKey")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Debug for TextInput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TextInput")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Debug for TextServiceRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TextServiceRequest")
            .field("version", &self.version)
            .field("model", &self.model)
            .field("input", &self.input)
            .field("output_token_limit", &self.output_token_limit)
            .field("response_mode", &self.response_mode)
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

impl Debug for ChatServiceRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatServiceRequest")
            .field("version", &self.version)
            .field("model", &self.model)
            .field("messages", &self.messages)
            .field("output_token_limit", &self.output_token_limit)
            .field("response_mode", &self.response_mode)
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

impl Debug for EmbeddingServiceRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddingServiceRequest")
            .field("version", &self.version)
            .field("model", &self.model)
            .field("inputs", &self.inputs)
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

impl Debug for ImageServiceRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageServiceRequest")
            .field("version", &self.version)
            .field("model", &self.model)
            .field("prompt", &self.prompt)
            .field("output_specification", &self.output_specification)
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

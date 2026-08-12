// crates/optional/ariadnion-api-domain/src/lib.rs - Rust source for Ariadnion.
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
//! Transport-neutral public service contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod chat;
mod embedding;
mod error;
mod request;
mod response;
mod stream;
mod usage;

pub use chat::{
    ChatMessage, ChatMessageContent, ChatMessages, ChatRole, MAX_CHAT_MESSAGE_CONTENT_BYTES,
    MAX_CHAT_MESSAGES, MAX_CHAT_MESSAGES_BYTES,
};
pub use embedding::{
    EmbeddingInput, EmbeddingInputs, EmbeddingVector, EmbeddingVectors, MAX_EMBEDDING_DIMENSIONS,
    MAX_EMBEDDING_INPUT_BYTES, MAX_EMBEDDING_INPUTS, MAX_EMBEDDING_INPUTS_BYTES,
    MAX_EMBEDDING_SCALARS, MAX_EMBEDDING_VECTORS,
};
pub use error::{ApiDomainError, ApiDomainErrorCode};
pub use request::{
    ChatServiceRequest, EmbeddingServiceRequest, IdempotencyKey, MAX_IDEMPOTENCY_KEY_BYTES,
    MAX_MODEL_SELECTOR_BYTES, MAX_OUTPUT_TOKENS, MAX_TEXT_INPUT_BYTES, ModelSelector,
    OutputTokenLimit, ResponseMode, ServiceContractVersion, ServiceRequest, ServiceRequestVersion,
    TextInput, TextServiceRequest,
};
pub use response::{
    ChatServiceResponse, EmbeddingServiceResponse, FinishReason, MAX_TEXT_OUTPUT_BYTES,
    ServiceResponse, TextOutput, TextServiceResponse,
};
pub use stream::{
    ChatStreamEvent, MAX_TEXT_DELTA_BYTES, ServiceStreamEvent, TextDelta, TextStreamEvent,
};
pub use usage::TokenUsage;

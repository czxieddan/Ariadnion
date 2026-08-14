// crates/optional/ariadnion-api-domain/src/response.rs - Complete service response contracts for Ariadnion.
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
//! Bounded values for complete service responses.

use crate::audio::GeneratedAudio;
use crate::embedding::EmbeddingVectors;
use crate::error::{ApiDomainError, invalid_argument, limit_exceeded};
use crate::image::GeneratedImages;
use crate::request::ServiceContractVersion;
use crate::usage::TokenUsage;

mod debug;

/// Maximum encoded size of a complete text output in UTF-8 bytes.
pub const MAX_TEXT_OUTPUT_BYTES: usize = 16_777_216;

/// Bounded complete text output whose diagnostics never expose its content.
#[derive(Clone, Eq, PartialEq)]
pub struct TextOutput(Box<str>);

impl TextOutput {
    /// Validates and copies complete text output.
    ///
    /// Empty output is valid. Output must not exceed 16 MiB of UTF-8 bytes or
    /// contain a NUL character.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] when the byte limit
    /// is exceeded and [`crate::ApiDomainErrorCode::InvalidArgument`] for NUL.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_text_output(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated output to a trusted service adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reason generation ended for a complete or streamed response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FinishReason {
    /// Generation reached its natural completion point.
    Completed,
    /// Generation reached its configured output limit.
    OutputLimitReached,
    /// A safety policy stopped generation before ordinary completion.
    ContentFiltered,
}

/// A complete response from a text service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextServiceResponse {
    version: ServiceContractVersion,
    output: TextOutput,
    finish_reason: FinishReason,
}

impl TextServiceResponse {
    /// Creates a complete text response from validated domain values.
    #[must_use]
    pub const fn new(
        version: ServiceContractVersion,
        output: TextOutput,
        finish_reason: FinishReason,
    ) -> Self {
        Self {
            version,
            output,
            finish_reason,
        }
    }

    /// Returns the service contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns the validated complete output.
    #[must_use]
    pub const fn output(&self) -> &TextOutput {
        &self.output
    }

    /// Returns why generation ended.
    #[must_use]
    pub const fn finish_reason(&self) -> FinishReason {
        self.finish_reason
    }
}

/// A complete response from a role-preserving chat service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatServiceResponse {
    version: ServiceContractVersion,
    output: TextOutput,
    finish_reason: FinishReason,
    usage: TokenUsage,
}

impl ChatServiceResponse {
    /// Creates a complete chat response from validated domain values.
    #[must_use]
    pub const fn new(
        version: ServiceContractVersion,
        output: TextOutput,
        finish_reason: FinishReason,
        usage: TokenUsage,
    ) -> Self {
        Self {
            version,
            output,
            finish_reason,
            usage,
        }
    }

    /// Returns the service contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns the validated assistant output.
    #[must_use]
    pub const fn output(&self) -> &TextOutput {
        &self.output
    }

    /// Returns why generation ended.
    #[must_use]
    pub const fn finish_reason(&self) -> FinishReason {
        self.finish_reason
    }

    /// Returns checked token usage for the completed result.
    #[must_use]
    pub const fn usage(&self) -> TokenUsage {
        self.usage
    }
}

/// A complete response from an embedding service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddingServiceResponse {
    version: ServiceContractVersion,
    vectors: EmbeddingVectors,
    usage: TokenUsage,
}

impl EmbeddingServiceResponse {
    /// Creates a complete embedding response with input-only token usage.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] when usage
    /// reports generated output tokens. Embeddings consume input tokens but do
    /// not generate text tokens.
    pub fn new(
        version: ServiceContractVersion,
        vectors: EmbeddingVectors,
        usage: TokenUsage,
    ) -> Result<Self, ApiDomainError> {
        if usage.output_tokens() != 0 {
            return Err(invalid_argument());
        }
        Ok(Self {
            version,
            vectors,
            usage,
        })
    }

    /// Returns the service contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns ordered vectors correlated to the request inputs.
    #[must_use]
    pub const fn vectors(&self) -> &EmbeddingVectors {
        &self.vectors
    }

    /// Returns checked input-only token usage.
    #[must_use]
    pub const fn usage(&self) -> TokenUsage {
        self.usage
    }
}

/// A complete response from an image-generation service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageServiceResponse {
    version: ServiceContractVersion,
    images: GeneratedImages,
}

impl ImageServiceResponse {
    /// Creates a complete image response from validated generated images.
    #[must_use]
    pub const fn new(version: ServiceContractVersion, images: GeneratedImages) -> Self {
        Self { version, images }
    }

    /// Returns the service contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns ordered generated images correlated to the request count.
    #[must_use]
    pub const fn images(&self) -> &GeneratedImages {
        &self.images
    }
}

/// A complete response from an audio-synthesis service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudioServiceResponse {
    version: ServiceContractVersion,
    audio: GeneratedAudio,
}

impl AudioServiceResponse {
    /// Creates a complete audio response from validated generated audio.
    #[must_use]
    pub const fn new(version: ServiceContractVersion, audio: GeneratedAudio) -> Self {
        Self { version, audio }
    }

    /// Returns the service contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns the validated complete audio output.
    #[must_use]
    pub const fn audio(&self) -> &GeneratedAudio {
        &self.audio
    }
}

/// A complete transport-neutral service response.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServiceResponse {
    /// A complete bounded text response.
    Text(TextServiceResponse),
    /// A complete bounded chat response.
    Chat(ChatServiceResponse),
    /// A complete ordered embedding response.
    Embedding(EmbeddingServiceResponse),
    /// A complete ordered image-generation response.
    Image(ImageServiceResponse),
    /// A complete bounded audio-synthesis response.
    Audio(AudioServiceResponse),
}

fn validate_text_output(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_TEXT_OUTPUT_BYTES {
        return Err(limit_exceeded());
    }
    if value.contains('\0') {
        return Err(invalid_argument());
    }
    Ok(())
}

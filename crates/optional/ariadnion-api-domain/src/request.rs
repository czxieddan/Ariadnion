// crates/optional/ariadnion-api-domain/src/request.rs - Service request contracts for Ariadnion.
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
//! Bounded, transport-neutral service request values.

mod debug;

use crate::chat::ChatMessages;
use crate::embedding::EmbeddingInputs;
use crate::error::{ApiDomainError, ApiDomainErrorCode, invalid_argument, limit_exceeded};
use crate::image::{ImageCount, ImageDimensions, ImageMediaType, ImagePrompt};

/// Maximum encoded size of a model selector in UTF-8 bytes.
pub const MAX_MODEL_SELECTOR_BYTES: usize = 256;
/// Maximum encoded size of an idempotency key in bytes.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
/// Maximum encoded size of a text input in UTF-8 bytes.
pub const MAX_TEXT_INPUT_BYTES: usize = 1_048_576;
/// Maximum number of output tokens a text request may ask for.
pub const MAX_OUTPUT_TOKENS: u32 = 1_048_576;

/// Version of the transport-neutral service contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ServiceContractVersion {
    /// The initial service contract.
    V1,
}

impl ServiceContractVersion {
    /// Parses the numeric representation of a service contract version.
    ///
    /// # Errors
    ///
    /// Returns [`ApiDomainErrorCode::UnsupportedVersion`] for every value other
    /// than `1`.
    pub const fn parse(value: u16) -> Result<Self, ApiDomainError> {
        if value == 1 {
            Ok(Self::V1)
        } else {
            Err(ApiDomainError::new(ApiDomainErrorCode::UnsupportedVersion))
        }
    }
}

/// Backward-compatible name for the service contract version used by requests.
pub type ServiceRequestVersion = ServiceContractVersion;

/// A bounded model selector independent of provider-specific model types.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelSelector(Box<str>);

impl ModelSelector {
    /// Validates and copies a model selector.
    ///
    /// Selectors must contain between 1 and 256 UTF-8 bytes. Leading or
    /// trailing whitespace and Unicode control characters are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ApiDomainErrorCode::InvalidArgument`] for invalid syntax and
    /// [`ApiDomainErrorCode::LimitExceeded`] when the byte bound is exceeded.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_model_selector(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated selector.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded idempotency key whose diagnostics never expose key material.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(Box<str>);

impl IdempotencyKey {
    /// Validates and copies an idempotency key.
    ///
    /// Keys must contain between 1 and 128 visible ASCII bytes. Spaces,
    /// control bytes, and non-ASCII text are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ApiDomainErrorCode::InvalidArgument`] for invalid syntax and
    /// [`ApiDomainErrorCode::LimitExceeded`] when the byte bound is exceeded.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_idempotency_key(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated key to a trusted idempotency adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded service input whose diagnostics never expose input text.
#[derive(Clone, Eq, PartialEq)]
pub struct TextInput(Box<str>);

impl TextInput {
    /// Validates and copies text service input.
    ///
    /// Input must contain between 1 and 1,048,576 UTF-8 bytes and must not
    /// contain a NUL character. Other Unicode text, including newlines, is
    /// preserved without normalization.
    ///
    /// # Errors
    ///
    /// Returns [`ApiDomainErrorCode::InvalidArgument`] for an empty value or
    /// NUL and [`ApiDomainErrorCode::LimitExceeded`] when the byte bound is
    /// exceeded.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_text_input(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated text to a trusted service implementation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated hard limit for generated output tokens.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutputTokenLimit(u32);

impl OutputTokenLimit {
    /// Validates an output token limit.
    ///
    /// # Errors
    ///
    /// Returns [`ApiDomainErrorCode::InvalidArgument`] for zero and
    /// [`ApiDomainErrorCode::LimitExceeded`] above 1,048,576 tokens.
    pub const fn new(value: u32) -> Result<Self, ApiDomainError> {
        if value == 0 {
            return Err(invalid_argument());
        }
        if value > MAX_OUTPUT_TOKENS {
            return Err(limit_exceeded());
        }
        Ok(Self(value))
    }

    /// Returns the validated token count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Delivery mode requested for a service response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ResponseMode {
    /// Deliver one complete response after generation finishes.
    Complete,
    /// Deliver response events incrementally through a separate stream port.
    Stream,
}

/// Complete-only output requirements for one image-generation request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImageOutputSpecification {
    count: ImageCount,
    dimensions: ImageDimensions,
    media_type: ImageMediaType,
}

impl ImageOutputSpecification {
    /// Creates output requirements from already validated image values.
    #[must_use]
    pub const fn new(
        count: ImageCount,
        dimensions: ImageDimensions,
        media_type: ImageMediaType,
    ) -> Self {
        Self {
            count,
            dimensions,
            media_type,
        }
    }

    /// Returns the requested number of generated images.
    #[must_use]
    pub const fn count(self) -> ImageCount {
        self.count
    }

    /// Returns the requested dimensions for each generated image.
    #[must_use]
    pub const fn dimensions(self) -> ImageDimensions {
        self.dimensions
    }

    /// Returns the requested encoded media type.
    #[must_use]
    pub const fn media_type(self) -> ImageMediaType {
        self.media_type
    }
}

/// A fully validated request for a text service.
#[derive(Clone, Eq, PartialEq)]
pub struct TextServiceRequest {
    version: ServiceContractVersion,
    model: ModelSelector,
    input: TextInput,
    output_token_limit: OutputTokenLimit,
    response_mode: ResponseMode,
    idempotency_key: Option<IdempotencyKey>,
}

impl TextServiceRequest {
    /// Creates a text service request from already validated domain values.
    ///
    /// Transport and caller context remain separate concerns. This value does
    /// not carry request identifiers, principals, deadlines, cancellation
    /// handles, trace state, or protocol metadata.
    #[must_use]
    pub const fn new(
        version: ServiceContractVersion,
        model: ModelSelector,
        input: TextInput,
        output_token_limit: OutputTokenLimit,
        response_mode: ResponseMode,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Self {
        Self {
            version,
            model,
            input,
            output_token_limit,
            response_mode,
            idempotency_key,
        }
    }

    /// Returns the request contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns the provider-independent model selector.
    #[must_use]
    pub const fn model(&self) -> &ModelSelector {
        &self.model
    }

    /// Returns the validated text input.
    #[must_use]
    pub const fn input(&self) -> &TextInput {
        &self.input
    }

    /// Returns the requested maximum output token count.
    #[must_use]
    pub const fn output_token_limit(&self) -> OutputTokenLimit {
        self.output_token_limit
    }

    /// Returns the requested response delivery mode.
    #[must_use]
    pub const fn response_mode(&self) -> ResponseMode {
        self.response_mode
    }

    /// Returns the optional idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

/// A fully validated request for a role-preserving chat service.
#[derive(Clone, Eq, PartialEq)]
pub struct ChatServiceRequest {
    version: ServiceContractVersion,
    model: ModelSelector,
    messages: ChatMessages,
    output_token_limit: OutputTokenLimit,
    response_mode: ResponseMode,
    idempotency_key: Option<IdempotencyKey>,
}

impl ChatServiceRequest {
    /// Creates a chat request from validated, transport-neutral domain values.
    ///
    /// Protocol stream options, request identifiers, principals, deadlines,
    /// cancellation handles, and trace state remain outside this value.
    #[must_use]
    pub const fn new(
        version: ServiceContractVersion,
        model: ModelSelector,
        messages: ChatMessages,
        output_token_limit: OutputTokenLimit,
        response_mode: ResponseMode,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Self {
        Self {
            version,
            model,
            messages,
            output_token_limit,
            response_mode,
            idempotency_key,
        }
    }

    /// Returns the request contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns the provider-independent model selector.
    #[must_use]
    pub const fn model(&self) -> &ModelSelector {
        &self.model
    }

    /// Returns the ordered chat history.
    #[must_use]
    pub const fn messages(&self) -> &ChatMessages {
        &self.messages
    }

    /// Returns the requested maximum output token count.
    #[must_use]
    pub const fn output_token_limit(&self) -> OutputTokenLimit {
        self.output_token_limit
    }

    /// Returns the requested response delivery mode.
    #[must_use]
    pub const fn response_mode(&self) -> ResponseMode {
        self.response_mode
    }

    /// Returns the optional idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

/// A fully validated request for non-streaming embedding generation.
#[derive(Clone, Eq, PartialEq)]
pub struct EmbeddingServiceRequest {
    version: ServiceContractVersion,
    model: ModelSelector,
    inputs: EmbeddingInputs,
    idempotency_key: Option<IdempotencyKey>,
}

impl EmbeddingServiceRequest {
    /// Creates an embedding request from validated, transport-neutral values.
    ///
    /// Embedding responses are complete-only. Request identifiers, principals,
    /// deadlines, cancellation handles, trace state, provider dimensions, and
    /// protocol encoding options remain outside this value.
    #[must_use]
    pub const fn new(
        version: ServiceContractVersion,
        model: ModelSelector,
        inputs: EmbeddingInputs,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Self {
        Self {
            version,
            model,
            inputs,
            idempotency_key,
        }
    }

    /// Returns the request contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns the provider-independent model selector.
    #[must_use]
    pub const fn model(&self) -> &ModelSelector {
        &self.model
    }

    /// Returns the ordered embedding inputs.
    #[must_use]
    pub const fn inputs(&self) -> &EmbeddingInputs {
        &self.inputs
    }

    /// Returns the optional idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

/// A fully validated request for complete-only image generation.
#[derive(Clone, Eq, PartialEq)]
pub struct ImageServiceRequest {
    version: ServiceContractVersion,
    model: ModelSelector,
    prompt: ImagePrompt,
    output_specification: ImageOutputSpecification,
    idempotency_key: Option<IdempotencyKey>,
}

impl ImageServiceRequest {
    /// Creates an image request from validated, transport-neutral values.
    ///
    /// Provider quality controls, style controls, seeds, response encodings,
    /// request identifiers, principals, deadlines, cancellation handles, and
    /// trace state remain outside this value.
    #[must_use]
    pub const fn new(
        version: ServiceContractVersion,
        model: ModelSelector,
        prompt: ImagePrompt,
        output_specification: ImageOutputSpecification,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Self {
        Self {
            version,
            model,
            prompt,
            output_specification,
            idempotency_key,
        }
    }

    /// Returns the request contract version.
    #[must_use]
    pub const fn version(&self) -> ServiceContractVersion {
        self.version
    }

    /// Returns the provider-independent model selector.
    #[must_use]
    pub const fn model(&self) -> &ModelSelector {
        &self.model
    }

    /// Returns the validated image prompt.
    #[must_use]
    pub const fn prompt(&self) -> &ImagePrompt {
        &self.prompt
    }

    /// Returns the complete-only output requirements.
    #[must_use]
    pub const fn output_specification(&self) -> ImageOutputSpecification {
        self.output_specification
    }

    /// Returns the optional idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

/// A transport-neutral service request accepted by the public service layer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServiceRequest {
    /// A bounded text generation request.
    Text(TextServiceRequest),
    /// A bounded role-preserving chat request.
    Chat(ChatServiceRequest),
    /// An ordered complete-only embedding request.
    Embedding(EmbeddingServiceRequest),
    /// A bounded complete-only image-generation request.
    Image(ImageServiceRequest),
}

fn validate_model_selector(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_MODEL_SELECTOR_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.trim() != value {
        return Err(invalid_argument());
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), ApiDomainError> {
    if value.is_empty() {
        return Err(invalid_argument());
    }
    if value.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(limit_exceeded());
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_text_input(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_TEXT_INPUT_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.contains('\0') {
        return Err(invalid_argument());
    }
    Ok(())
}

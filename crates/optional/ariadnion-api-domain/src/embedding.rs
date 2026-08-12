// crates/optional/ariadnion-api-domain/src/embedding.rs - Bounded embedding values for Ariadnion.
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
//! Bounded, provider-neutral embedding inputs and vectors.

use std::fmt::{self, Debug, Formatter};

use crate::error::{ApiDomainError, invalid_argument, limit_exceeded};

/// Maximum encoded size of one embedding input in UTF-8 bytes.
pub const MAX_EMBEDDING_INPUT_BYTES: usize = 1_048_576;
/// Maximum number of inputs in one embedding request.
pub const MAX_EMBEDDING_INPUTS: usize = 128;
/// Maximum aggregate encoded input size in one embedding request.
pub const MAX_EMBEDDING_INPUTS_BYTES: usize = 1_048_576;
/// Maximum number of scalar dimensions in one embedding vector.
pub const MAX_EMBEDDING_DIMENSIONS: usize = 65_536;
/// Maximum number of vectors in one embedding response.
pub const MAX_EMBEDDING_VECTORS: usize = 128;
/// Maximum aggregate scalar count in one embedding response.
pub const MAX_EMBEDDING_SCALARS: usize = 1_048_576;

/// One bounded embedding input whose diagnostics never expose its text.
#[derive(Clone, Eq, PartialEq)]
pub struct EmbeddingInput(Box<str>);

impl EmbeddingInput {
    /// Validates and copies one embedding input.
    ///
    /// Input must contain between 1 and 1,048,576 UTF-8 bytes and must not
    /// contain NUL. Other Unicode text is preserved without normalization.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] when the byte limit
    /// is exceeded and [`crate::ApiDomainErrorCode::InvalidArgument`] for empty
    /// input or NUL.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_input(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated text to a trusted embedding adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for EmbeddingInput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddingInput")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// An ordered, non-empty, bounded batch of embedding inputs.
#[derive(Clone, Eq, PartialEq)]
pub struct EmbeddingInputs {
    values: Box<[EmbeddingInput]>,
    total_bytes: usize,
}

impl EmbeddingInputs {
    /// Validates and owns one ordered input batch.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for an empty
    /// batch and [`crate::ApiDomainErrorCode::LimitExceeded`] when the item,
    /// aggregate-byte, or checked-arithmetic bound is exceeded.
    pub fn new(values: Vec<EmbeddingInput>) -> Result<Self, ApiDomainError> {
        validate_input_count(values.len())?;
        let total_bytes = checked_input_bytes(&values)?;
        Ok(Self {
            values: values.into_boxed_slice(),
            total_bytes,
        })
    }

    /// Returns the ordered inputs.
    #[must_use]
    pub fn as_slice(&self) -> &[EmbeddingInput] {
        &self.values
    }

    /// Returns the number of inputs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Reports whether the batch is empty.
    ///
    /// Validated instances always return `false`; this method supports generic
    /// collection-style callers without weakening construction invariants.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the checked aggregate UTF-8 byte count.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

impl Debug for EmbeddingInputs {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddingInputs")
            .field("count", &self.values.len())
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

/// One bounded embedding vector containing only finite scalars.
#[derive(Clone, PartialEq)]
pub struct EmbeddingVector(Box<[f32]>);

// Private construction rejects NaN and both infinities, and immutable access
// preserves that invariant, so equality is reflexive for every valid instance.
impl Eq for EmbeddingVector {}

impl EmbeddingVector {
    /// Validates and owns one embedding vector.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for an empty
    /// vector or any non-finite scalar and
    /// [`crate::ApiDomainErrorCode::LimitExceeded`] above 65,536 dimensions.
    pub fn new(values: Vec<f32>) -> Result<Self, ApiDomainError> {
        validate_vector(&values)?;
        Ok(Self(values.into_boxed_slice()))
    }

    /// Returns the validated scalars to a trusted embedding adapter.
    #[must_use]
    pub fn as_slice(&self) -> &[f32] {
        &self.0
    }

    /// Returns the vector dimension.
    #[must_use]
    pub const fn dimensions(&self) -> usize {
        self.0.len()
    }
}

impl Debug for EmbeddingVector {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddingVector")
            .field("dimensions", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// An ordered, shape-consistent, bounded batch of embedding vectors.
#[derive(Clone, Eq, PartialEq)]
pub struct EmbeddingVectors {
    values: Box<[EmbeddingVector]>,
    dimensions: usize,
    total_scalars: usize,
}

impl EmbeddingVectors {
    /// Validates and owns vectors for a known number of inputs.
    ///
    /// `expected_count` binds provider output cardinality to the corresponding
    /// request. `expected_dimensions` binds every vector to the selected model's
    /// declared non-zero output dimension.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for an empty
    /// batch, count mismatch, or inconsistent dimensions. Returns
    /// [`crate::ApiDomainErrorCode::LimitExceeded`] when a count, aggregate
    /// scalar, or checked-arithmetic bound is exceeded.
    pub fn new(
        values: Vec<EmbeddingVector>,
        expected_count: usize,
        expected_dimensions: usize,
    ) -> Result<Self, ApiDomainError> {
        validate_vector_count(values.len(), expected_count)?;
        validate_expected_dimensions(expected_dimensions)?;
        let total_scalars = checked_scalar_count(values.len(), expected_dimensions)?;
        validate_dimensions(&values, expected_dimensions)?;
        Ok(Self {
            values: values.into_boxed_slice(),
            dimensions: expected_dimensions,
            total_scalars,
        })
    }

    /// Returns the ordered vectors.
    #[must_use]
    pub fn as_slice(&self) -> &[EmbeddingVector] {
        &self.values
    }

    /// Returns the number of vectors.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Reports whether the batch is empty.
    ///
    /// Validated instances always return `false`; this method supports generic
    /// collection-style callers without weakening construction invariants.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the shared vector dimension.
    #[must_use]
    pub const fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// Returns the checked aggregate scalar count.
    #[must_use]
    pub const fn total_scalars(&self) -> usize {
        self.total_scalars
    }
}

impl Debug for EmbeddingVectors {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddingVectors")
            .field("count", &self.values.len())
            .field("dimensions", &self.dimensions)
            .field("total_scalars", &self.total_scalars)
            .finish_non_exhaustive()
    }
}

fn validate_input(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_EMBEDDING_INPUT_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.contains('\0') {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_input_count(count: usize) -> Result<(), ApiDomainError> {
    if count > MAX_EMBEDDING_INPUTS {
        return Err(limit_exceeded());
    }
    if count == 0 {
        return Err(invalid_argument());
    }
    Ok(())
}

fn checked_input_bytes(values: &[EmbeddingInput]) -> Result<usize, ApiDomainError> {
    let total = values.iter().try_fold(0_usize, |total, input| {
        total.checked_add(input.0.len()).ok_or_else(limit_exceeded)
    })?;
    if total > MAX_EMBEDDING_INPUTS_BYTES {
        return Err(limit_exceeded());
    }
    Ok(total)
}

fn validate_vector(values: &[f32]) -> Result<(), ApiDomainError> {
    if values.len() > MAX_EMBEDDING_DIMENSIONS {
        return Err(limit_exceeded());
    }
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_vector_count(count: usize, expected_count: usize) -> Result<(), ApiDomainError> {
    if count > MAX_EMBEDDING_VECTORS || expected_count > MAX_EMBEDDING_VECTORS {
        return Err(limit_exceeded());
    }
    if count == 0 || count != expected_count {
        return Err(invalid_argument());
    }
    Ok(())
}

fn checked_scalar_count(count: usize, dimensions: usize) -> Result<usize, ApiDomainError> {
    let total = count.checked_mul(dimensions).ok_or_else(limit_exceeded)?;
    if total > MAX_EMBEDDING_SCALARS {
        return Err(limit_exceeded());
    }
    Ok(total)
}

fn validate_expected_dimensions(dimensions: usize) -> Result<(), ApiDomainError> {
    if dimensions > MAX_EMBEDDING_DIMENSIONS {
        return Err(limit_exceeded());
    }
    if dimensions == 0 {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_dimensions(
    values: &[EmbeddingVector],
    expected_dimensions: usize,
) -> Result<(), ApiDomainError> {
    if values
        .iter()
        .any(|vector| vector.dimensions() != expected_dimensions)
    {
        return Err(invalid_argument());
    }
    Ok(())
}

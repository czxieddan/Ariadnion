// crates/optional/ariadnion-api-domain/src/image.rs - Bounded image values for Ariadnion.
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
//! Bounded, provider-neutral image prompts and generated image values.

use std::fmt::{self, Debug, Formatter};

use crate::error::{ApiDomainError, invalid_argument, limit_exceeded};

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const JPEG_SIGNATURE: &[u8; 3] = b"\xff\xd8\xff";
const WEBP_RIFF_SIGNATURE: &[u8; 4] = b"RIFF";
const WEBP_FORMAT_SIGNATURE: &[u8; 4] = b"WEBP";

/// Maximum encoded size of one image prompt in UTF-8 bytes.
pub const MAX_IMAGE_PROMPT_BYTES: usize = 262_144;
/// Maximum number of images requested or returned in one operation.
pub const MAX_GENERATED_IMAGES: usize = 8;
/// Maximum width or height of one generated image in pixels.
pub const MAX_IMAGE_EDGE: usize = 8_192;
/// Maximum checked pixel count of one generated image.
pub const MAX_IMAGE_PIXELS: usize = 16_777_216;
/// Maximum encoded size of one generated image.
pub const MAX_GENERATED_IMAGE_BYTES: usize = 8_388_608;
/// Maximum aggregate encoded size of one generated image batch.
pub const MAX_GENERATED_IMAGES_BYTES: usize = 33_554_432;

/// One bounded image-generation prompt whose diagnostics never expose its text.
#[derive(Clone, Eq, PartialEq)]
pub struct ImagePrompt(Box<str>);

impl ImagePrompt {
    /// Validates and copies one image prompt.
    ///
    /// Input must contain between 1 and 262,144 UTF-8 bytes and must not contain
    /// NUL. Other Unicode text is preserved without normalization.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] above the byte limit
    /// and [`crate::ApiDomainErrorCode::InvalidArgument`] for empty input or NUL.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_prompt(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated prompt to a trusted image adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the prompt's encoded UTF-8 byte count.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.0.len()
    }
}

impl Debug for ImagePrompt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImagePrompt")
            .field("encoded_bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

/// A checked non-zero number of generated images.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImageCount(usize);

impl ImageCount {
    /// Validates a requested or expected image count.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for zero and
    /// [`crate::ApiDomainErrorCode::LimitExceeded`] above eight images.
    pub const fn new(value: usize) -> Result<Self, ApiDomainError> {
        if value > MAX_GENERATED_IMAGES {
            return Err(limit_exceeded());
        }
        if value == 0 {
            return Err(invalid_argument());
        }
        Ok(Self(value))
    }

    /// Returns the validated count.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Checked pixel dimensions for one generated image.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImageDimensions {
    width: usize,
    height: usize,
    pixels: usize,
}

impl ImageDimensions {
    /// Validates image width, height, and checked pixel count.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] when either edge,
    /// checked multiplication, or total pixel count exceeds its hard limit.
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for a zero edge.
    pub fn new(width: usize, height: usize) -> Result<Self, ApiDomainError> {
        validate_edges(width, height)?;
        let Some(pixels) = width.checked_mul(height) else {
            return Err(limit_exceeded());
        };
        if pixels > MAX_IMAGE_PIXELS {
            return Err(limit_exceeded());
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    /// Returns the validated width in pixels.
    #[must_use]
    pub const fn width(self) -> usize {
        self.width
    }

    /// Returns the validated height in pixels.
    #[must_use]
    pub const fn height(self) -> usize {
        self.height
    }

    /// Returns the checked total pixel count.
    #[must_use]
    pub const fn pixels(self) -> usize {
        self.pixels
    }
}

/// Supported encoded formats for provider-neutral generated images.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ImageMediaType {
    /// Portable Network Graphics.
    Png,
    /// JPEG image data.
    Jpeg,
    /// WebP image data.
    WebP,
}

impl ImageMediaType {
    /// Returns the stable Internet media type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::WebP => "image/webp",
        }
    }

    fn matches_signature(self, bytes: &[u8]) -> bool {
        match self {
            Self::Png => bytes.starts_with(PNG_SIGNATURE),
            Self::Jpeg => bytes.starts_with(JPEG_SIGNATURE),
            Self::WebP => webp_signature_matches(bytes),
        }
    }
}

/// One bounded encoded image whose diagnostics never expose image bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedImage {
    media_type: ImageMediaType,
    dimensions: ImageDimensions,
    bytes: Box<[u8]>,
}

impl GeneratedImage {
    /// Validates and owns one encoded generated image.
    ///
    /// The media type must match the fixed container signature. Full image
    /// decoding belongs to a later trusted media adapter and is not inferred
    /// from caller-controlled metadata.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] above 8 MiB and
    /// [`crate::ApiDomainErrorCode::InvalidArgument`] for empty data or a
    /// mismatched fixed container signature.
    pub fn new(
        media_type: ImageMediaType,
        dimensions: ImageDimensions,
        bytes: Vec<u8>,
    ) -> Result<Self, ApiDomainError> {
        validate_encoded_image(media_type, &bytes)?;
        Ok(Self {
            media_type,
            dimensions,
            bytes: bytes.into_boxed_slice(),
        })
    }

    /// Returns the validated encoded media type.
    #[must_use]
    pub const fn media_type(&self) -> ImageMediaType {
        self.media_type
    }

    /// Returns the validated image dimensions.
    #[must_use]
    pub const fn dimensions(&self) -> ImageDimensions {
        self.dimensions
    }

    /// Returns the encoded bytes to a trusted image adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the encoded byte count.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.bytes.len()
    }
}

impl Debug for GeneratedImage {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedImage")
            .field("media_type", &self.media_type.as_str())
            .field("width", &self.dimensions.width())
            .field("height", &self.dimensions.height())
            .field("encoded_bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

/// An ordered, non-empty, bounded batch of generated images.
#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedImages {
    values: Box<[GeneratedImage]>,
    total_bytes: usize,
}

impl GeneratedImages {
    /// Validates and owns images for a known requested count.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for an empty batch
    /// or count mismatch. Returns [`crate::ApiDomainErrorCode::LimitExceeded`]
    /// when the actual count, checked byte sum, or 32 MiB aggregate bound is
    /// exceeded.
    pub fn new(
        values: Vec<GeneratedImage>,
        expected_count: ImageCount,
    ) -> Result<Self, ApiDomainError> {
        validate_image_count(values.len(), expected_count.get())?;
        let total_bytes = checked_image_bytes(&values)?;
        Ok(Self {
            values: values.into_boxed_slice(),
            total_bytes,
        })
    }

    /// Returns the ordered generated images.
    #[must_use]
    pub fn as_slice(&self) -> &[GeneratedImage] {
        &self.values
    }

    /// Returns the generated image count.
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

    /// Returns the checked aggregate encoded byte count.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

impl Debug for GeneratedImages {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedImages")
            .field("count", &self.values.len())
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

const fn validate_edges(width: usize, height: usize) -> Result<(), ApiDomainError> {
    if width > MAX_IMAGE_EDGE || height > MAX_IMAGE_EDGE {
        return Err(limit_exceeded());
    }
    if width == 0 || height == 0 {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_prompt(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_IMAGE_PROMPT_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.contains('\0') {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_encoded_image(media_type: ImageMediaType, bytes: &[u8]) -> Result<(), ApiDomainError> {
    if bytes.len() > MAX_GENERATED_IMAGE_BYTES {
        return Err(limit_exceeded());
    }
    if bytes.is_empty() || !media_type.matches_signature(bytes) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn webp_signature_matches(bytes: &[u8]) -> bool {
    bytes.starts_with(WEBP_RIFF_SIGNATURE)
        && bytes
            .get(8..12)
            .is_some_and(|signature| signature == WEBP_FORMAT_SIGNATURE)
}

const fn validate_image_count(count: usize, expected: usize) -> Result<(), ApiDomainError> {
    if count > MAX_GENERATED_IMAGES {
        return Err(limit_exceeded());
    }
    if count == 0 || count != expected {
        return Err(invalid_argument());
    }
    Ok(())
}

fn checked_image_bytes(values: &[GeneratedImage]) -> Result<usize, ApiDomainError> {
    let total = values.iter().try_fold(0_usize, |total, image| {
        total
            .checked_add(image.encoded_bytes())
            .ok_or_else(limit_exceeded)
    })?;
    if total > MAX_GENERATED_IMAGES_BYTES {
        return Err(limit_exceeded());
    }
    Ok(total)
}

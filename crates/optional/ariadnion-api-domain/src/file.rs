// crates/optional/ariadnion-api-domain/src/file.rs - Bounded file values for Ariadnion.
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
//! Bounded, transport-neutral file references and metadata.

use std::fmt::{self, Debug, Formatter};

use crate::error::{ApiDomainError, invalid_argument, limit_exceeded};

const MEDIA_TOKEN_PUNCTUATION: &[u8] = b"!#$%&'+-.^_`|~";

/// Maximum encoded size of one file display name in UTF-8 bytes.
pub const MAX_FILE_DISPLAY_NAME_BYTES: usize = 255;
/// Maximum encoded size of one normalized file media type in ASCII bytes.
pub const MAX_FILE_MEDIA_TYPE_BYTES: usize = 127;
/// Maximum exact byte length of one file.
pub const MAX_FILE_BYTES: usize = 536_870_912;

/// One opaque fixed-width reference issued by a trusted file service.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FileReference([u8; Self::BYTE_LENGTH]);

impl FileReference {
    /// Exact width of a file reference in bytes.
    pub const BYTE_LENGTH: usize = 32;

    /// Creates a reference from exactly 32 opaque bytes issued by a trusted service.
    #[must_use]
    pub const fn new(value: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(value)
    }

    /// Returns the opaque reference bytes to a trusted file adapter.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

impl Debug for FileReference {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileReference")
            .finish_non_exhaustive()
    }
}

/// One validated file name intended only for display and download metadata.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FileDisplayName(Box<str>);

impl FileDisplayName {
    /// Validates and copies one file display name.
    ///
    /// The value must contain 1 to 255 UTF-8 bytes. Control characters, `/`,
    /// and `\` are rejected so the value cannot be interpreted as a path.
    /// Unicode text is otherwise preserved without normalization.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] above the byte limit.
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for empty input or
    /// a forbidden character.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_display_name(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated display name to a trusted file adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the display name's encoded UTF-8 byte count.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.0.len()
    }
}

impl Debug for FileDisplayName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileDisplayName")
            .field("encoded_bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

/// One concrete normalized Internet media type for file metadata.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FileMediaType(Box<str>);

impl FileMediaType {
    /// Validates, normalizes, and owns one concrete media type.
    ///
    /// Input must contain exactly one `type/subtype` pair using the RFC token
    /// character grammar except `*`, which is rejected everywhere to prohibit
    /// wildcard notation. Parameters are rejected. ASCII letters are normalized
    /// to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] above 127 bytes.
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for empty input,
    /// non-ASCII input, wildcards, parameters, or malformed token syntax.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_media_type(value)?;
        Ok(Self(value.to_ascii_lowercase().into_boxed_str()))
    }

    /// Returns the validated lowercase media type to a trusted file adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the normalized media type's ASCII byte count.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.0.len()
    }
}

impl Debug for FileMediaType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileMediaType")
            .field("encoded_bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

/// One checked, non-zero exact file length in bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileByteLength(usize);

impl FileByteLength {
    /// Validates an exact file length.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for zero and
    /// [`crate::ApiDomainErrorCode::LimitExceeded`] above 512 MiB.
    pub const fn new(value: usize) -> Result<Self, ApiDomainError> {
        if value > MAX_FILE_BYTES {
            return Err(limit_exceeded());
        }
        if value == 0 {
            return Err(invalid_argument());
        }
        Ok(Self(value))
    }

    /// Returns the validated exact byte length.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// One exact SHA-256 digest supplied or verified at a trusted file boundary.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FileDigest([u8; Self::BYTE_LENGTH]);

impl FileDigest {
    /// Exact width of a SHA-256 digest in bytes.
    pub const BYTE_LENGTH: usize = 32;

    /// Creates a digest from exactly 32 SHA-256 bytes.
    #[must_use]
    pub const fn new(value: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(value)
    }

    /// Returns the digest bytes to a trusted file adapter.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

impl Debug for FileDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FileDigest").finish_non_exhaustive()
    }
}

/// Complete validated metadata required before accepting a file upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileUploadSpecification {
    display_name: FileDisplayName,
    media_type: FileMediaType,
    byte_length: FileByteLength,
    expected_digest: Option<FileDigest>,
}

impl FileUploadSpecification {
    /// Owns validated upload metadata without changing any component value.
    #[must_use]
    pub fn new(
        display_name: FileDisplayName,
        media_type: FileMediaType,
        byte_length: FileByteLength,
        expected_digest: Option<FileDigest>,
    ) -> Self {
        Self {
            display_name,
            media_type,
            byte_length,
            expected_digest,
        }
    }

    /// Returns the validated display name.
    #[must_use]
    pub const fn display_name(&self) -> &FileDisplayName {
        &self.display_name
    }

    /// Returns the validated normalized media type.
    #[must_use]
    pub const fn media_type(&self) -> &FileMediaType {
        &self.media_type
    }

    /// Returns the declared exact byte length.
    #[must_use]
    pub const fn byte_length(&self) -> FileByteLength {
        self.byte_length
    }

    /// Returns the optional caller-supplied expected SHA-256 digest.
    #[must_use]
    pub const fn expected_digest(&self) -> Option<&FileDigest> {
        self.expected_digest.as_ref()
    }
}

/// Complete metadata for one file whose bytes were verified by a trusted service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDescriptor {
    reference: FileReference,
    display_name: FileDisplayName,
    media_type: FileMediaType,
    byte_length: FileByteLength,
    digest: FileDigest,
}

impl FileDescriptor {
    /// Owns one verified file reference and its validated immutable metadata.
    #[must_use]
    pub fn new(
        reference: FileReference,
        display_name: FileDisplayName,
        media_type: FileMediaType,
        byte_length: FileByteLength,
        digest: FileDigest,
    ) -> Self {
        Self {
            reference,
            display_name,
            media_type,
            byte_length,
            digest,
        }
    }

    /// Returns the opaque service-issued file reference.
    #[must_use]
    pub const fn reference(&self) -> &FileReference {
        &self.reference
    }

    /// Returns the validated display name.
    #[must_use]
    pub const fn display_name(&self) -> &FileDisplayName {
        &self.display_name
    }

    /// Returns the validated normalized media type.
    #[must_use]
    pub const fn media_type(&self) -> &FileMediaType {
        &self.media_type
    }

    /// Returns the verified exact byte length.
    #[must_use]
    pub const fn byte_length(&self) -> FileByteLength {
        self.byte_length
    }

    /// Returns the verified SHA-256 digest.
    #[must_use]
    pub const fn digest(&self) -> &FileDigest {
        &self.digest
    }
}

fn validate_display_name(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_FILE_DISPLAY_NAME_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.chars().any(forbidden_display_name_character) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn forbidden_display_name_character(character: char) -> bool {
    character.is_control() || matches!(character, '/' | '\\')
}

fn validate_media_type(value: &str) -> Result<(), ApiDomainError> {
    validate_media_type_length(value)?;
    let (top_level, subtype) = split_media_type(value)?;
    validate_media_type_tokens(top_level, subtype)
}

fn validate_media_type_length(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_FILE_MEDIA_TYPE_BYTES {
        return Err(limit_exceeded());
    }
    Ok(())
}

fn split_media_type(value: &str) -> Result<(&str, &str), ApiDomainError> {
    let Some((top_level, subtype)) = value.split_once('/') else {
        return Err(invalid_argument());
    };
    if subtype.contains('/') {
        return Err(invalid_argument());
    }
    Ok((top_level, subtype))
}

fn validate_media_type_tokens(top_level: &str, subtype: &str) -> Result<(), ApiDomainError> {
    if !is_concrete_media_token(top_level) || !is_concrete_media_token(subtype) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn is_concrete_media_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_media_token_byte)
}

fn is_media_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || MEDIA_TOKEN_PUNCTUATION.contains(&byte)
}

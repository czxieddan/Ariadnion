// crates/optional/ariadnion-api-domain/src/audio.rs - Provider-neutral audio values for Ariadnion.
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
//! Bounded provider-neutral audio synthesis values.

use std::fmt::{self, Debug, Formatter};

use crate::error::{ApiDomainError, invalid_argument, limit_exceeded};

mod generated;

pub use generated::{GeneratedAudio, MAX_AUDIO_DURATION_MILLIS, MAX_GENERATED_AUDIO_BYTES};

/// Maximum encoded size of one synthesis input in UTF-8 bytes.
pub const MAX_AUDIO_TEXT_BYTES: usize = 262_144;
/// Maximum encoded size of one provider-neutral voice selector.
pub const MAX_AUDIO_VOICE_SELECTOR_BYTES: usize = 128;

/// One bounded audio synthesis input whose diagnostics never expose its text.
#[derive(Clone, Eq, PartialEq)]
pub struct AudioText(Box<str>);

impl AudioText {
    /// Validates and copies one synthesis input.
    ///
    /// Input must contain between 1 and 262,144 UTF-8 bytes and must not contain
    /// NUL. Other Unicode text is preserved without normalization.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] above the byte limit
    /// and [`crate::ApiDomainErrorCode::InvalidArgument`] for empty input or NUL.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_audio_text(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated text to a trusted audio adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the encoded UTF-8 byte count.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.0.len()
    }
}

impl Debug for AudioText {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AudioText")
            .field("encoded_bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

/// One bounded provider-neutral voice selector.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AudioVoiceSelector(Box<str>);

impl AudioVoiceSelector {
    /// Validates and copies one voice selector.
    ///
    /// The selector must contain only ASCII graphic bytes and cannot exceed 128
    /// bytes. Provider-specific voice mapping belongs outside this value.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] above the byte limit
    /// and [`crate::ApiDomainErrorCode::InvalidArgument`] for invalid syntax.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_voice_selector(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated selector to a trusted routing or provider adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the encoded selector byte count.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.0.len()
    }
}

impl Debug for AudioVoiceSelector {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AudioVoiceSelector")
            .field("encoded_bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

/// Supported provider-neutral PCM sample rates.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AudioSampleRate {
    /// 8 kHz narrowband audio.
    Hz8000,
    /// 16 kHz wideband audio.
    Hz16000,
    /// 24 kHz synthesis audio.
    Hz24000,
    /// 48 kHz full-band audio.
    Hz48000,
}

impl AudioSampleRate {
    /// Returns the sample rate in hertz.
    #[must_use]
    pub const fn as_hz(self) -> u32 {
        match self {
            Self::Hz8000 => 8_000,
            Self::Hz16000 => 16_000,
            Self::Hz24000 => 24_000,
            Self::Hz48000 => 48_000,
        }
    }
}

/// Supported provider-neutral audio channel counts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AudioChannelCount {
    /// One interleaved channel.
    Mono,
    /// Two interleaved channels.
    Stereo,
}

impl AudioChannelCount {
    /// Returns the channel count used by PCM container metadata.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Mono => 1,
            Self::Stereo => 2,
        }
    }
}

/// Supported encoded formats for provider-neutral generated audio.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AudioMediaType {
    /// Canonical little-endian RIFF/WAVE with 16-bit integer PCM samples.
    WavPcm16,
}

impl AudioMediaType {
    /// Returns the stable Internet media type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WavPcm16 => "audio/wav",
        }
    }
}

/// Complete-only output requirements for one audio-synthesis request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AudioOutputSpecification {
    media_type: AudioMediaType,
    sample_rate: AudioSampleRate,
    channel_count: AudioChannelCount,
}

impl AudioOutputSpecification {
    /// Creates output requirements from already validated audio values.
    #[must_use]
    pub const fn new(
        media_type: AudioMediaType,
        sample_rate: AudioSampleRate,
        channel_count: AudioChannelCount,
    ) -> Self {
        Self {
            media_type,
            sample_rate,
            channel_count,
        }
    }

    /// Returns the requested encoded media type.
    #[must_use]
    pub const fn media_type(self) -> AudioMediaType {
        self.media_type
    }

    /// Returns the requested PCM sample rate.
    #[must_use]
    pub const fn sample_rate(self) -> AudioSampleRate {
        self.sample_rate
    }

    /// Returns the requested channel count.
    #[must_use]
    pub const fn channel_count(self) -> AudioChannelCount {
        self.channel_count
    }
}

fn validate_audio_text(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_AUDIO_TEXT_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || value.contains('\0') {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_voice_selector(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_AUDIO_VOICE_SELECTOR_BYTES {
        return Err(limit_exceeded());
    }
    if value.is_empty() || !value.is_ascii() {
        return Err(invalid_argument());
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid_argument());
    }
    Ok(())
}

// crates/optional/ariadnion-api-domain/src/audio/generated.rs - Canonical generated audio values for Ariadnion.
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
//! Bounded canonical generated audio values.

use std::fmt::{self, Debug, Formatter};

use crate::error::{ApiDomainError, invalid_argument, limit_exceeded};

use super::{AudioChannelCount, AudioMediaType, AudioSampleRate};

const WAV_HEADER_BYTES: usize = 44;
const PCM_FORMAT_CODE: u16 = 1;
const PCM_BITS_PER_SAMPLE: u16 = 16;
const PCM_BYTES_PER_SAMPLE: u16 = PCM_BITS_PER_SAMPLE / 8;

/// Maximum encoded size of one generated audio response.
pub const MAX_GENERATED_AUDIO_BYTES: usize = 16_777_216;
/// Maximum duration of one generated audio response in milliseconds.
pub const MAX_AUDIO_DURATION_MILLIS: u64 = 600_000;

/// One bounded canonical audio response whose diagnostics never expose bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedAudio {
    media_type: AudioMediaType,
    sample_rate: AudioSampleRate,
    channel_count: AudioChannelCount,
    duration_millis: u64,
    bytes: Box<[u8]>,
}

impl GeneratedAudio {
    /// Validates and owns one canonical PCM WAV response.
    ///
    /// The first audio slice accepts exactly one 44-byte canonical RIFF/WAVE
    /// layout with PCM16 metadata followed by one non-empty, frame-aligned data
    /// region. The header must agree with the supplied sample rate and channels.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] above 16 MiB, above
    /// 600 seconds, or on checked arithmetic overflow. Returns
    /// [`crate::ApiDomainErrorCode::InvalidArgument`] for malformed or
    /// inconsistent container data.
    pub fn new(
        media_type: AudioMediaType,
        sample_rate: AudioSampleRate,
        channel_count: AudioChannelCount,
        bytes: Vec<u8>,
    ) -> Result<Self, ApiDomainError> {
        if bytes.len() > MAX_GENERATED_AUDIO_BYTES {
            return Err(limit_exceeded());
        }
        bind_canonical_wav_media_type(media_type);
        let header = parse_wav_header(&bytes)?;
        validate_pcm_header(header)?;
        validate_wav_lengths(header, bytes.len())?;
        validate_requested_layout(header, sample_rate, channel_count)?;
        let duration_millis = checked_duration_millis(header)?;
        Ok(Self {
            media_type,
            sample_rate,
            channel_count,
            duration_millis,
            bytes: bytes.into_boxed_slice(),
        })
    }

    /// Returns the validated encoded media type.
    #[must_use]
    pub const fn media_type(&self) -> AudioMediaType {
        self.media_type
    }

    /// Returns the validated sample rate.
    #[must_use]
    pub const fn sample_rate(&self) -> AudioSampleRate {
        self.sample_rate
    }

    /// Returns the validated channel count.
    #[must_use]
    pub const fn channel_count(&self) -> AudioChannelCount {
        self.channel_count
    }

    /// Returns the checked rounded-up duration in milliseconds.
    #[must_use]
    pub const fn duration_millis(&self) -> u64 {
        self.duration_millis
    }

    /// Returns the encoded byte count.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.bytes.len()
    }

    /// Returns validated encoded bytes to a trusted transport adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn bind_canonical_wav_media_type(media_type: AudioMediaType) {
    match media_type {
        AudioMediaType::WavPcm16 => {}
    }
}

impl Debug for GeneratedAudio {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedAudio")
            .field("media_type", &self.media_type.as_str())
            .field("sample_rate_hz", &self.sample_rate.as_hz())
            .field("channels", &self.channel_count.as_u16())
            .field("duration_millis", &self.duration_millis)
            .field("encoded_bytes", &self.encoded_bytes())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct WavHeader {
    riff_bytes: u32,
    format_bytes: u32,
    format_code: u16,
    channels: u16,
    sample_rate: u32,
    byte_rate: u32,
    block_align: u16,
    bits_per_sample: u16,
    data_bytes: u32,
}

fn parse_wav_header(bytes: &[u8]) -> Result<WavHeader, ApiDomainError> {
    if bytes.len() < WAV_HEADER_BYTES {
        return Err(invalid_argument());
    }
    validate_chunk_identifiers(bytes)?;
    Ok(WavHeader {
        riff_bytes: read_u32(bytes, 4),
        format_bytes: read_u32(bytes, 16),
        format_code: read_u16(bytes, 20),
        channels: read_u16(bytes, 22),
        sample_rate: read_u32(bytes, 24),
        byte_rate: read_u32(bytes, 28),
        block_align: read_u16(bytes, 32),
        bits_per_sample: read_u16(bytes, 34),
        data_bytes: read_u32(bytes, 40),
    })
}

fn validate_chunk_identifiers(bytes: &[u8]) -> Result<(), ApiDomainError> {
    if !has_canonical_chunk_identifiers(bytes) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn has_canonical_chunk_identifiers(bytes: &[u8]) -> bool {
    &bytes[0..4] == b"RIFF"
        && &bytes[8..12] == b"WAVE"
        && &bytes[12..16] == b"fmt "
        && &bytes[36..40] == b"data"
}

fn validate_pcm_header(header: WavHeader) -> Result<(), ApiDomainError> {
    if !has_canonical_pcm_header(header) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn has_canonical_pcm_header(header: WavHeader) -> bool {
    header.format_bytes == 16
        && header.format_code == PCM_FORMAT_CODE
        && header.bits_per_sample == PCM_BITS_PER_SAMPLE
        && header.data_bytes != 0
}

fn validate_wav_lengths(header: WavHeader, encoded_bytes: usize) -> Result<(), ApiDomainError> {
    let (expected_riff, expected_data) = expected_wav_lengths(encoded_bytes)?;
    if !has_canonical_wav_lengths(header, expected_riff, expected_data) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn expected_wav_lengths(encoded_bytes: usize) -> Result<(u32, u32), ApiDomainError> {
    let riff_bytes = u32::try_from(encoded_bytes - 8).map_err(|_| limit_exceeded())?;
    let data_bytes =
        u32::try_from(encoded_bytes - WAV_HEADER_BYTES).map_err(|_| limit_exceeded())?;
    Ok((riff_bytes, data_bytes))
}

fn has_canonical_wav_lengths(header: WavHeader, expected_riff: u32, expected_data: u32) -> bool {
    let block_align = u32::from(header.block_align);
    header.riff_bytes == expected_riff
        && header.data_bytes == expected_data
        && block_align != 0
        && header.data_bytes.is_multiple_of(block_align)
}

fn validate_requested_layout(
    header: WavHeader,
    sample_rate: AudioSampleRate,
    channel_count: AudioChannelCount,
) -> Result<(), ApiDomainError> {
    let expected_channels = channel_count.as_u16();
    let expected_block_align = expected_channels * PCM_BYTES_PER_SAMPLE;
    let expected_byte_rate = sample_rate
        .as_hz()
        .checked_mul(u32::from(expected_block_align))
        .ok_or_else(limit_exceeded)?;
    if header.sample_rate != sample_rate.as_hz() || header.channels != expected_channels {
        return Err(invalid_argument());
    }
    if header.block_align != expected_block_align || header.byte_rate != expected_byte_rate {
        return Err(invalid_argument());
    }
    Ok(())
}

fn checked_duration_millis(header: WavHeader) -> Result<u64, ApiDomainError> {
    let frames = u64::from(header.data_bytes) / u64::from(header.block_align);
    let sample_rate = u64::from(header.sample_rate);
    let scaled = frames.checked_mul(1_000).ok_or_else(limit_exceeded)?;
    let rounded = scaled
        .checked_add(sample_rate - 1)
        .ok_or_else(limit_exceeded)?;
    let duration_millis = rounded / sample_rate;
    if duration_millis > MAX_AUDIO_DURATION_MILLIS {
        return Err(limit_exceeded());
    }
    Ok(duration_millis)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

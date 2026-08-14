// crates/optional/ariadnion-provider-mock/src/audio.rs - Deterministic mock audio for Ariadnion.
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
//! Bounded canonical PCM WAV generated from validated request values.

use ariadnion_api_domain::{
    AudioChannelCount, AudioMediaType, AudioSampleRate, AudioServiceRequest, AudioServiceResponse,
    GeneratedAudio,
};
use ariadnion_core::RequestContext;
use ariadnion_provider_sdk::{ProviderFailure, ProviderFailureClass};

use crate::provider::check_context;

const WAV_HEADER_BYTES: usize = 44;
const PCM_FORMAT_CODE: u16 = 1;
const PCM_BITS_PER_SAMPLE: u16 = 16;
const PCM_BYTES_PER_SAMPLE: u16 = PCM_BITS_PER_SAMPLE / 8;
const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME: u64 = 1_099_511_628_211;
const SAMPLE_ORDINAL_STEP: u64 = 0x9e37_79b9_7f4a_7c15;
const FINGERPRINT_SEPARATOR: &[u8; 1] = b"\xff";
const FINGERPRINT_DOMAIN: &[u8] = b"ariadnion-mock-audio-v1";

pub(crate) fn plan_audio(
    request: &AudioServiceRequest,
    context: &RequestContext,
) -> Result<AudioServiceResponse, ProviderFailure> {
    let specification = request.output_specification();
    let frame_count = specification.sample_rate().as_hz();
    let fingerprint = request_fingerprint(request);
    let bytes = encode_audio(
        specification.media_type(),
        specification.sample_rate(),
        specification.channel_count(),
        frame_count,
        fingerprint,
        context,
    )?;
    let audio = GeneratedAudio::new(
        specification.media_type(),
        specification.sample_rate(),
        specification.channel_count(),
        bytes,
    )
    .map_err(|_| internal_failure())?;
    Ok(AudioServiceResponse::new(request.version(), audio))
}

fn request_fingerprint(request: &AudioServiceRequest) -> u64 {
    let fingerprint = fingerprint_bytes(FNV_OFFSET, FINGERPRINT_DOMAIN);
    let fingerprint = fingerprint_bytes(fingerprint, FINGERPRINT_SEPARATOR);
    let fingerprint = fingerprint_bytes(fingerprint, request.input().as_str().as_bytes());
    let fingerprint = fingerprint_bytes(fingerprint, FINGERPRINT_SEPARATOR);
    fingerprint_bytes(fingerprint, request.voice().as_str().as_bytes())
}

fn fingerprint_bytes(mut fingerprint: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        fingerprint ^= u64::from(*byte);
        fingerprint = fingerprint.wrapping_mul(FNV_PRIME);
    }
    fingerprint
}

fn encode_audio(
    media_type: AudioMediaType,
    sample_rate: AudioSampleRate,
    channel_count: AudioChannelCount,
    frame_count: u32,
    fingerprint: u64,
    context: &RequestContext,
) -> Result<Vec<u8>, ProviderFailure> {
    match media_type {
        AudioMediaType::WavPcm16 => encode_pcm_wav(
            sample_rate,
            channel_count,
            frame_count,
            fingerprint,
            context,
        ),
    }
}

fn encode_pcm_wav(
    sample_rate: AudioSampleRate,
    channel_count: AudioChannelCount,
    frame_count: u32,
    fingerprint: u64,
    context: &RequestContext,
) -> Result<Vec<u8>, ProviderFailure> {
    let layout = wav_layout(sample_rate, channel_count, frame_count)?;
    let mut bytes = Vec::with_capacity(layout.total_bytes);
    append_wav_header(&mut bytes, sample_rate, channel_count, layout);
    append_samples(&mut bytes, frame_count, channel_count, fingerprint, context)?;
    if bytes.len() != layout.total_bytes {
        return Err(internal_failure());
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
struct WavLayout {
    block_align: u16,
    byte_rate: u32,
    data_bytes: u32,
    total_bytes: usize,
}

fn wav_layout(
    sample_rate: AudioSampleRate,
    channel_count: AudioChannelCount,
    frame_count: u32,
) -> Result<WavLayout, ProviderFailure> {
    let block_align = channel_count
        .as_u16()
        .checked_mul(PCM_BYTES_PER_SAMPLE)
        .ok_or_else(response_limit)?;
    let byte_rate = sample_rate
        .as_hz()
        .checked_mul(u32::from(block_align))
        .ok_or_else(response_limit)?;
    let data_bytes = frame_count
        .checked_mul(u32::from(block_align))
        .ok_or_else(response_limit)?;
    let total_bytes = WAV_HEADER_BYTES
        .checked_add(usize::try_from(data_bytes).map_err(|_| response_limit())?)
        .ok_or_else(response_limit)?;
    Ok(WavLayout {
        block_align,
        byte_rate,
        data_bytes,
        total_bytes,
    })
}

fn append_wav_header(
    bytes: &mut Vec<u8>,
    sample_rate: AudioSampleRate,
    channel_count: AudioChannelCount,
    layout: WavLayout,
) {
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&(layout.data_bytes + 36).to_le_bytes());
    bytes.extend_from_slice(b"WAVE");
    bytes.extend_from_slice(b"fmt ");
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    bytes.extend_from_slice(&PCM_FORMAT_CODE.to_le_bytes());
    bytes.extend_from_slice(&channel_count.as_u16().to_le_bytes());
    bytes.extend_from_slice(&sample_rate.as_hz().to_le_bytes());
    bytes.extend_from_slice(&layout.byte_rate.to_le_bytes());
    bytes.extend_from_slice(&layout.block_align.to_le_bytes());
    bytes.extend_from_slice(&PCM_BITS_PER_SAMPLE.to_le_bytes());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&layout.data_bytes.to_le_bytes());
}

fn append_samples(
    bytes: &mut Vec<u8>,
    frame_count: u32,
    channel_count: AudioChannelCount,
    fingerprint: u64,
    context: &RequestContext,
) -> Result<(), ProviderFailure> {
    for frame in 0..frame_count {
        check_context(context)?;
        for channel in 0..channel_count.as_u16() {
            let sample = sample_for_ordinal(fingerprint, frame, channel, channel_count)?;
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
    }
    Ok(())
}

fn sample_for_ordinal(
    fingerprint: u64,
    frame: u32,
    channel: u16,
    channel_count: AudioChannelCount,
) -> Result<i16, ProviderFailure> {
    let ordinal = u64::from(frame)
        .checked_mul(u64::from(channel_count.as_u16()))
        .and_then(|value| value.checked_add(u64::from(channel)))
        .ok_or_else(response_limit)?;
    let value = fingerprint.wrapping_add(ordinal.wrapping_mul(SAMPLE_ORDINAL_STEP));
    let high = u16::try_from(splitmix64(value) >> 48).map_err(|_| internal_failure())?;
    let centered = i32::from(high) - 32_768;
    i16::try_from(centered / 4).map_err(|_| internal_failure())
}

fn splitmix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

const fn response_limit() -> ProviderFailure {
    ProviderFailure::new(ProviderFailureClass::ResponseLimit)
}

const fn internal_failure() -> ProviderFailure {
    ProviderFailure::new(ProviderFailureClass::Internal)
}

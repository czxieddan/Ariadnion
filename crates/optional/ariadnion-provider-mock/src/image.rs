// crates/optional/ariadnion-provider-mock/src/image.rs - Deterministic mock images for Ariadnion.
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
//! Small standard image containers generated without raster-sized allocation.

use ariadnion_api_domain::{
    GeneratedImage, GeneratedImages, ImageDimensions, ImageMediaType, ImageServiceRequest,
    ImageServiceResponse,
};
use ariadnion_provider_sdk::{ProviderFailure, ProviderFailureClass};

const METADATA_VERSION: u8 = 1;
const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME: u64 = 1_099_511_628_211;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const PNG_CHUNK_IHDR: &[u8; 4] = b"IHDR";
const PNG_CHUNK_PLTE: &[u8; 4] = b"PLTE";
const PNG_CHUNK_METADATA: &[u8; 4] = b"arID";
const PNG_CHUNK_IDAT: &[u8; 4] = b"IDAT";
const PNG_CHUNK_IEND: &[u8; 4] = b"IEND";
const PNG_CRC_POLYNOMIAL: u32 = 0xedb8_8320;
const ADLER_MODULUS: usize = 65_521;
const JPEG_BLOCK_EDGE: usize = 8;
const WEBP_ALPHA_USED: u32 = 1 << 28;

const LENGTH_BASES: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

pub(crate) fn plan_image(
    request: &ImageServiceRequest,
) -> Result<ImageServiceResponse, ProviderFailure> {
    let specification = request.output_specification();
    let fingerprint = prompt_fingerprint(request.prompt().as_str());
    let count = specification.count();
    let mut images = Vec::with_capacity(count.get());
    for ordinal in 0..count.get() {
        let ordinal = u8::try_from(ordinal).map_err(|_| internal_failure())?;
        let metadata = image_metadata(fingerprint, ordinal);
        let bytes = encode_image(
            specification.media_type(),
            specification.dimensions(),
            &metadata,
        )?;
        let image = GeneratedImage::new(
            specification.media_type(),
            specification.dimensions(),
            bytes,
        )
        .map_err(|_| internal_failure())?;
        images.push(image);
    }
    let images = GeneratedImages::new(images, count).map_err(|_| internal_failure())?;
    Ok(ImageServiceResponse::new(request.version(), images))
}

fn encode_image(
    media_type: ImageMediaType,
    dimensions: ImageDimensions,
    metadata: &[u8; 10],
) -> Result<Vec<u8>, ProviderFailure> {
    match media_type {
        ImageMediaType::Png => encode_png(dimensions, metadata),
        ImageMediaType::Jpeg => encode_jpeg(dimensions, metadata),
        ImageMediaType::WebP => encode_webp(dimensions, metadata),
    }
}

fn prompt_fingerprint(prompt: &str) -> u64 {
    let mut fingerprint = FNV_OFFSET;
    for byte in prompt.bytes() {
        fingerprint ^= u64::from(byte);
        fingerprint = fingerprint.wrapping_mul(FNV_PRIME);
    }
    fingerprint
}

fn image_metadata(fingerprint: u64, ordinal: u8) -> [u8; 10] {
    let mut metadata = [0_u8; 10];
    metadata[0] = METADATA_VERSION;
    metadata[1] = ordinal;
    metadata[2..].copy_from_slice(&fingerprint.to_be_bytes());
    metadata
}

fn encode_png(
    dimensions: ImageDimensions,
    metadata: &[u8; 10],
) -> Result<Vec<u8>, ProviderFailure> {
    let raw_bytes = png_raw_bytes(dimensions)?;
    let zlib = encode_png_zlib(raw_bytes)?;
    let ihdr = png_header(dimensions)?;
    assemble_png(&ihdr, metadata, &zlib)
}

fn encode_png_zlib(raw_bytes: usize) -> Result<Vec<u8>, ProviderFailure> {
    let deflate = deflate_zeroes(raw_bytes)?;
    let mut zlib = Vec::with_capacity(deflate.len() + 6);
    zlib.extend_from_slice(&[0x78, 0x01]);
    zlib.extend_from_slice(&deflate);
    zlib.extend_from_slice(&adler32_zeroes(raw_bytes)?.to_be_bytes());
    Ok(zlib)
}

fn png_header(dimensions: ImageDimensions) -> Result<[u8; 13], ProviderFailure> {
    let mut ihdr = [0_u8; 13];
    ihdr[..4].copy_from_slice(&dimension_u32(dimensions.width())?.to_be_bytes());
    ihdr[4..8].copy_from_slice(&dimension_u32(dimensions.height())?.to_be_bytes());
    ihdr[8..].copy_from_slice(&[1, 3, 0, 0, 0]);
    Ok(ihdr)
}

fn assemble_png(
    ihdr: &[u8; 13],
    metadata: &[u8; 10],
    zlib: &[u8],
) -> Result<Vec<u8>, ProviderFailure> {
    let palette = [metadata[2] ^ metadata[1], metadata[5], metadata[9]];

    let mut output = Vec::with_capacity(zlib.len() + 82);
    output.extend_from_slice(PNG_SIGNATURE);
    append_png_chunk(&mut output, PNG_CHUNK_IHDR, ihdr)?;
    append_png_chunk(&mut output, PNG_CHUNK_PLTE, &palette)?;
    append_png_chunk(&mut output, PNG_CHUNK_METADATA, metadata)?;
    append_png_chunk(&mut output, PNG_CHUNK_IDAT, zlib)?;
    append_png_chunk(&mut output, PNG_CHUNK_IEND, &[])?;
    Ok(output)
}

fn png_raw_bytes(dimensions: ImageDimensions) -> Result<usize, ProviderFailure> {
    let row_bytes = dimensions
        .width()
        .div_ceil(8)
        .checked_add(1)
        .ok_or_else(internal_failure)?;
    row_bytes
        .checked_mul(dimensions.height())
        .ok_or_else(internal_failure)
}

fn deflate_zeroes(length: usize) -> Result<Vec<u8>, ProviderFailure> {
    let mut writer = BitWriter::new();
    writer.write_bits(1, 1);
    writer.write_bits(1, 2);
    write_fixed_symbol(&mut writer, 0)?;
    let remaining = length.checked_sub(1).ok_or_else(internal_failure)?;
    let remaining = write_full_zero_runs(&mut writer, remaining)?;
    write_zero_tail(&mut writer, remaining)?;
    write_fixed_symbol(&mut writer, 256)?;
    Ok(writer.finish())
}

fn write_full_zero_runs(
    writer: &mut BitWriter,
    mut remaining: usize,
) -> Result<usize, ProviderFailure> {
    while remaining >= 258 {
        write_zero_run(writer, 258)?;
        remaining -= 258;
    }
    Ok(remaining)
}

fn write_zero_tail(writer: &mut BitWriter, remaining: usize) -> Result<(), ProviderFailure> {
    if remaining >= 3 {
        write_zero_run(writer, remaining)
    } else {
        write_zero_literals(writer, remaining)
    }
}

fn write_zero_literals(writer: &mut BitWriter, remaining: usize) -> Result<(), ProviderFailure> {
    for _ in 0..remaining {
        write_fixed_symbol(writer, 0)?;
    }
    Ok(())
}

fn write_zero_run(writer: &mut BitWriter, length: usize) -> Result<(), ProviderFailure> {
    let (symbol, extra_bits, extra_value) = length_encoding(length)?;
    write_fixed_symbol(writer, symbol)?;
    writer.write_bits(extra_value, extra_bits);
    writer.write_bits(0, 5);
    Ok(())
}

fn length_encoding(length: usize) -> Result<(u16, u8, u32), ProviderFailure> {
    if !(3..=258).contains(&length) {
        return Err(internal_failure());
    }
    let mut index = 0;
    for (candidate, base) in LENGTH_BASES.iter().enumerate().skip(1) {
        if *base > length {
            break;
        }
        index = candidate;
    }
    let symbol = 257_u16
        .checked_add(u16::try_from(index).map_err(|_| internal_failure())?)
        .ok_or_else(internal_failure)?;
    let extra_value =
        u32::try_from(length - LENGTH_BASES[index]).map_err(|_| internal_failure())?;
    Ok((symbol, LENGTH_EXTRA_BITS[index], extra_value))
}

fn write_fixed_symbol(writer: &mut BitWriter, symbol: u16) -> Result<(), ProviderFailure> {
    let (canonical, width) = match symbol {
        0..=143 => (0x30_u16 + symbol, 8),
        144..=255 => (0x190_u16 + symbol - 144, 9),
        256..=279 => (symbol - 256, 7),
        280..=287 => (0xc0_u16 + symbol - 280, 8),
        _ => return Err(internal_failure()),
    };
    writer.write_bits(reverse_low_bits(canonical, width), width);
    Ok(())
}

fn reverse_low_bits(mut value: u16, width: u8) -> u32 {
    let mut reversed = 0_u32;
    for _ in 0..width {
        reversed = (reversed << 1) | u32::from(value & 1);
        value >>= 1;
    }
    reversed
}

fn append_png_chunk(
    output: &mut Vec<u8>,
    chunk_type: &[u8; 4],
    data: &[u8],
) -> Result<(), ProviderFailure> {
    let length = u32::try_from(data.len()).map_err(|_| internal_failure())?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(chunk_type);
    output.extend_from_slice(data);
    output.extend_from_slice(&png_crc(chunk_type, data).to_be_bytes());
    Ok(())
}

fn png_crc(chunk_type: &[u8; 4], data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in chunk_type.iter().chain(data) {
        crc = png_crc_byte(crc, *byte);
    }
    !crc
}

fn png_crc_byte(mut crc: u32, byte: u8) -> u32 {
    crc ^= u32::from(byte);
    for _ in 0..8 {
        let mask = 0_u32.wrapping_sub(crc & 1);
        crc = (crc >> 1) ^ (PNG_CRC_POLYNOMIAL & mask);
    }
    crc
}

fn adler32_zeroes(length: usize) -> Result<u32, ProviderFailure> {
    let remainder = u32::try_from(length % ADLER_MODULUS).map_err(|_| internal_failure())?;
    Ok((remainder << 16) | 1)
}

fn encode_jpeg(
    dimensions: ImageDimensions,
    metadata: &[u8; 10],
) -> Result<Vec<u8>, ProviderFailure> {
    let width = dimension_u16(dimensions.width())?;
    let height = dimension_u16(dimensions.height())?;
    let blocks = jpeg_blocks(dimensions)?;
    let mut output = Vec::with_capacity(168 + blocks.div_ceil(4));
    output.extend_from_slice(&[0xff, 0xd8]);
    append_jpeg_app0(&mut output);
    append_jpeg_comment(&mut output, metadata)?;
    append_jpeg_quantization(&mut output);
    append_jpeg_frame(&mut output, width, height);
    append_jpeg_huffman(&mut output);
    append_jpeg_scan(&mut output);
    append_jpeg_entropy(&mut output, blocks)?;
    output.extend_from_slice(&[0xff, 0xd9]);
    Ok(output)
}

fn append_jpeg_app0(output: &mut Vec<u8>) {
    output.extend_from_slice(&[
        0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0,
    ]);
}

fn append_jpeg_comment(output: &mut Vec<u8>, metadata: &[u8; 10]) -> Result<(), ProviderFailure> {
    let length = u16::try_from(metadata.len() + 2).map_err(|_| internal_failure())?;
    output.extend_from_slice(&[0xff, 0xfe]);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(metadata);
    Ok(())
}

fn append_jpeg_quantization(output: &mut Vec<u8>) {
    output.extend_from_slice(&[0xff, 0xdb, 0x00, 0x43, 0x00]);
    output.extend_from_slice(&[1; 64]);
}

fn append_jpeg_frame(output: &mut Vec<u8>, width: u16, height: u16) {
    output.extend_from_slice(&[0xff, 0xc0, 0x00, 0x0b, 8]);
    output.extend_from_slice(&height.to_be_bytes());
    output.extend_from_slice(&width.to_be_bytes());
    output.extend_from_slice(&[1, 1, 0x11, 0]);
}

fn append_jpeg_huffman(output: &mut Vec<u8>) {
    output.extend_from_slice(&[0xff, 0xc4, 0x00, 0x26, 0x00]);
    output.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    output.push(0);
    output.push(0x10);
    output.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    output.push(0);
}

fn append_jpeg_scan(output: &mut Vec<u8>) {
    output.extend_from_slice(&[0xff, 0xda, 0x00, 0x08, 1, 1, 0, 0, 63, 0]);
}

fn append_jpeg_entropy(output: &mut Vec<u8>, blocks: usize) -> Result<(), ProviderFailure> {
    let full_bytes = blocks / 4;
    let length = output
        .len()
        .checked_add(full_bytes)
        .ok_or_else(internal_failure)?;
    output.resize(length, 0);
    match blocks % 4 {
        0 => {}
        1 => output.push(0x3f),
        2 => output.push(0x0f),
        3 => output.push(0x03),
        _ => return Err(internal_failure()),
    }
    Ok(())
}

fn jpeg_blocks(dimensions: ImageDimensions) -> Result<usize, ProviderFailure> {
    dimensions
        .width()
        .div_ceil(JPEG_BLOCK_EDGE)
        .checked_mul(dimensions.height().div_ceil(JPEG_BLOCK_EDGE))
        .ok_or_else(internal_failure)
}

fn encode_webp(
    dimensions: ImageDimensions,
    metadata: &[u8; 10],
) -> Result<Vec<u8>, ProviderFailure> {
    let width = dimension_u32(dimensions.width())?;
    let height = dimension_u32(dimensions.height())?;
    let packed = width
        .checked_sub(1)
        .and_then(|value| value.checked_add((height - 1) << 14))
        .and_then(|value| value.checked_add(WEBP_ALPHA_USED))
        .ok_or_else(internal_failure)?;
    let mut output = Vec::with_capacity(46);
    output.extend_from_slice(b"RIFF");
    output.extend_from_slice(&38_u32.to_le_bytes());
    output.extend_from_slice(b"WEBPVP8L");
    output.extend_from_slice(&8_u32.to_le_bytes());
    output.push(0x2f);
    output.extend_from_slice(&packed.to_le_bytes());
    output.extend_from_slice(&[0x88, 0x88, 0x08]);
    output.extend_from_slice(b"ARID");
    output.extend_from_slice(&10_u32.to_le_bytes());
    output.extend_from_slice(metadata);
    Ok(output)
}

fn dimension_u16(value: usize) -> Result<u16, ProviderFailure> {
    u16::try_from(value).map_err(|_| internal_failure())
}

fn dimension_u32(value: usize) -> Result<u32, ProviderFailure> {
    u32::try_from(value).map_err(|_| internal_failure())
}

const fn internal_failure() -> ProviderFailure {
    ProviderFailure::new(ProviderFailureClass::Internal)
}

struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    used: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current: 0,
            used: 0,
        }
    }

    fn write_bits(&mut self, mut value: u32, count: u8) {
        for _ in 0..count {
            self.current |= ((value & 1) as u8) << self.used;
            self.used += 1;
            value >>= 1;
            if self.used == 8 {
                self.bytes.push(self.current);
                self.current = 0;
                self.used = 0;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.used != 0 {
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

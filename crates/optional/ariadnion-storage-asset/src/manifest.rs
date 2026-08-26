// crates/optional/ariadnion-storage-asset/src/manifest.rs - Rust source for Ariadnion.
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
//! Canonical private records for restart-safe local-volume state.

use std::io::Cursor;

use ariadnion_core::TenantId;
use sha2::{Digest, Sha256};

use crate::{
    AssetByteLength, AssetDescriptor, AssetDigest, AssetKey, AssetMediaType, AssetQuarantineReason,
    AssetStageToken, StagedAsset, StorageError, StorageErrorCode,
};

const STAGE_MAGIC: &[u8; 5] = b"ARSM2";
const COMMITTED_MAGIC: &[u8; 5] = b"ARCD2";
const CONSUMED_MAGIC: &[u8; 5] = b"ARSC1";
const PUBLISH_INTENT_MAGIC: &[u8; 5] = b"ARPI1";
const QUARANTINE_INTENT_MAGIC: &[u8; 5] = b"ARQI1";
const TOKEN_DOMAIN: &[u8] = b"ariadnion-local-volume-token-v1";
const TENANT_DOMAIN: &[u8] = b"ariadnion-local-volume-tenant-v1";
const MAX_MEDIA_BYTES: usize = AssetMediaType::MAX_BYTES;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct StageRecord {
    pub(crate) descriptor: AssetDescriptor,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CommittedRecord {
    pub(crate) descriptor: AssetDescriptor,
}

pub(crate) fn encode_stage_record(
    token: &AssetStageToken,
    descriptor: &AssetDescriptor,
) -> Vec<u8> {
    let mut bytes = STAGE_MAGIC.to_vec();
    bytes.extend_from_slice(&token_digest(token));
    encode_descriptor_commitments(&mut bytes, descriptor);
    bytes
}

pub(crate) fn decode_stage_record(
    bytes: &[u8],
    staged: &StagedAsset,
) -> Result<StageRecord, StorageError> {
    let mut cursor = Cursor::new(bytes);
    require_magic(&mut cursor, STAGE_MAGIC)?;
    let stored_token = read_array::<32>(&mut cursor)?;
    ensure_token_matches(stored_token, staged.token())?;
    let descriptor = decode_descriptor_commitments(&mut cursor, staged.descriptor().key())?;
    ensure_consumed(&cursor, bytes)?;
    ensure_descriptor_matches(&descriptor, staged.descriptor())?;
    Ok(StageRecord { descriptor })
}

pub(crate) fn encode_consumed_marker(
    token: &AssetStageToken,
    descriptor: &AssetDescriptor,
) -> Vec<u8> {
    let mut bytes = CONSUMED_MAGIC.to_vec();
    bytes.extend_from_slice(&token_digest(token));
    bytes.extend_from_slice(&descriptor.digest().as_bytes()[..]);
    bytes
}

pub(crate) fn is_consumed_marker(
    bytes: &[u8],
    token: &AssetStageToken,
    descriptor: &AssetDescriptor,
) -> bool {
    let mut expected = CONSUMED_MAGIC.to_vec();
    expected.extend_from_slice(&token_digest(token));
    expected.extend_from_slice(descriptor.digest().as_bytes());
    bytes == expected
}

pub(crate) fn encode_publish_intent(
    token: &AssetStageToken,
    descriptor: &AssetDescriptor,
) -> Vec<u8> {
    encode_intent(PUBLISH_INTENT_MAGIC, token, descriptor, None)
}

pub(crate) fn decode_publish_intent(
    bytes: &[u8],
    staged: &StagedAsset,
) -> Result<(), StorageError> {
    decode_intent(bytes, PUBLISH_INTENT_MAGIC, staged, None, false).map(|_| ())
}

pub(crate) fn encode_quarantine_intent(
    token: &AssetStageToken,
    descriptor: &AssetDescriptor,
    reason: AssetQuarantineReason,
) -> Vec<u8> {
    encode_intent(
        QUARANTINE_INTENT_MAGIC,
        token,
        descriptor,
        Some(reason_code(reason)),
    )
}

pub(crate) fn decode_quarantine_intent(
    bytes: &[u8],
    staged: &StagedAsset,
    reason: AssetQuarantineReason,
) -> Result<(), StorageError> {
    decode_intent(
        bytes,
        QUARANTINE_INTENT_MAGIC,
        staged,
        Some(reason_code(reason)),
        true,
    )
    .map(|_| ())
}

pub(crate) fn encode_recovery_marker(token: &AssetStageToken) -> Vec<u8> {
    let mut bytes = b"ARSR1".to_vec();
    bytes.extend_from_slice(&token_digest(token));
    bytes
}

pub(crate) fn encode_committed_record(descriptor: &AssetDescriptor) -> Vec<u8> {
    let mut bytes = COMMITTED_MAGIC.to_vec();
    encode_descriptor_commitments(&mut bytes, descriptor);
    bytes
}

pub(crate) fn decode_committed_record(
    bytes: &[u8],
    key: &AssetKey,
) -> Result<CommittedRecord, StorageError> {
    let mut cursor = Cursor::new(bytes);
    require_magic(&mut cursor, COMMITTED_MAGIC)?;
    let descriptor = decode_descriptor_commitments(&mut cursor, key)?;
    ensure_consumed(&cursor, bytes)?;
    Ok(CommittedRecord { descriptor })
}

pub(crate) fn tenant_path_digest(tenant: &TenantId) -> [u8; 32] {
    domain_digest(TENANT_DOMAIN, tenant.as_str().as_bytes())
}

fn token_digest(token: &AssetStageToken) -> [u8; 32] {
    domain_digest(TOKEN_DOMAIN, token.as_bytes())
}

fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u16).to_be_bytes());
    hasher.update(domain);
    hasher.update((value.len() as u16).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

fn encode_descriptor_commitments(output: &mut Vec<u8>, descriptor: &AssetDescriptor) {
    output.extend_from_slice(&tenant_path_digest(descriptor.tenant_id()));
    output.extend_from_slice(descriptor.digest().as_bytes());
    output.extend_from_slice(&descriptor.byte_length().get().to_be_bytes());
    let media = descriptor.media_type().as_str().as_bytes();
    output.extend_from_slice(&(media.len() as u16).to_be_bytes());
    output.extend_from_slice(media);
}

fn encode_intent(
    magic: &[u8; 5],
    token: &AssetStageToken,
    descriptor: &AssetDescriptor,
    reason: Option<u8>,
) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(&token_digest(token));
    encode_descriptor_commitments(&mut bytes, descriptor);
    if let Some(reason) = reason {
        bytes.push(reason);
    }
    bytes
}

fn decode_intent(
    bytes: &[u8],
    magic: &[u8; 5],
    staged: &StagedAsset,
    expected_reason: Option<u8>,
    read_reason: bool,
) -> Result<Option<u8>, StorageError> {
    let mut cursor = Cursor::new(bytes);
    require_magic(&mut cursor, magic)?;
    decode_intent_identity(&mut cursor, staged)?;
    let reason = decode_intent_reason(&mut cursor, read_reason, expected_reason)?;
    ensure_consumed(&cursor, bytes)?;
    Ok(reason)
}

fn decode_intent_identity(
    cursor: &mut Cursor<&[u8]>,
    staged: &StagedAsset,
) -> Result<(), StorageError> {
    let stored_token = read_array::<32>(cursor)?;
    ensure_token_matches(stored_token, staged.token())?;
    let descriptor = decode_descriptor_commitments(cursor, staged.descriptor().key())?;
    ensure_descriptor_matches(&descriptor, staged.descriptor())
}

fn decode_intent_reason(
    cursor: &mut Cursor<&[u8]>,
    read_reason: bool,
    expected_reason: Option<u8>,
) -> Result<Option<u8>, StorageError> {
    let reason = if read_reason {
        Some(read_array::<1>(cursor)?[0])
    } else {
        None
    };
    if reason != expected_reason {
        return Err(integrity_failure());
    }
    Ok(reason)
}

fn reason_code(reason: AssetQuarantineReason) -> u8 {
    match reason {
        AssetQuarantineReason::IntegrityFailure => 1,
        AssetQuarantineReason::PolicyRejected => 2,
        AssetQuarantineReason::InspectionRequired => 3,
        AssetQuarantineReason::Abandoned => 4,
    }
}

fn decode_descriptor_commitments(
    cursor: &mut Cursor<&[u8]>,
    key: &AssetKey,
) -> Result<AssetDescriptor, StorageError> {
    let tenant = read_array::<32>(cursor)?;
    let digest = AssetDigest::new(read_array(cursor)?);
    ensure_key_matches(tenant, digest, key)?;
    let length = decode_byte_length(cursor)?;
    let media = decode_media_type(cursor)?;
    Ok(AssetDescriptor::new(key.clone(), media, length))
}

fn ensure_token_matches(stored: [u8; 32], token: &AssetStageToken) -> Result<(), StorageError> {
    if stored != token_digest(token) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn ensure_descriptor_matches(
    actual: &AssetDescriptor,
    expected: &AssetDescriptor,
) -> Result<(), StorageError> {
    if actual != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

fn ensure_key_matches(
    tenant: [u8; 32],
    digest: AssetDigest,
    key: &AssetKey,
) -> Result<(), StorageError> {
    if tenant != tenant_path_digest(key.tenant_id()) || digest != key.digest() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn decode_byte_length(cursor: &mut Cursor<&[u8]>) -> Result<AssetByteLength, StorageError> {
    let value = u64::from_be_bytes(read_array(cursor)?);
    AssetByteLength::new(value).map_err(|_| integrity_failure())
}

fn decode_media_type(cursor: &mut Cursor<&[u8]>) -> Result<AssetMediaType, StorageError> {
    let value = read_text(cursor, MAX_MEDIA_BYTES)?;
    AssetMediaType::parse(&value).map_err(|_| integrity_failure())
}

fn require_magic(cursor: &mut Cursor<&[u8]>, magic: &[u8]) -> Result<(), StorageError> {
    if read_exact(cursor, magic.len())? != magic {
        return Err(integrity_failure());
    }
    Ok(())
}

fn ensure_consumed(cursor: &Cursor<&[u8]>, bytes: &[u8]) -> Result<(), StorageError> {
    if cursor.position() as usize != bytes.len() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn read_text(cursor: &mut Cursor<&[u8]>, maximum: usize) -> Result<String, StorageError> {
    let length = u16::from_be_bytes(read_array(cursor)?) as usize;
    if length == 0 || length > maximum {
        return Err(integrity_failure());
    }
    let bytes = read_exact(cursor, length)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| integrity_failure())
}

fn read_array<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], StorageError> {
    let bytes = read_exact(cursor, N)?;
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn read_exact<'a>(cursor: &mut Cursor<&'a [u8]>, length: usize) -> Result<&'a [u8], StorageError> {
    let start = cursor.position() as usize;
    let end = start.checked_add(length).ok_or_else(integrity_failure)?;
    if end > cursor.get_ref().len() {
        return Err(integrity_failure());
    }
    cursor.set_position(end as u64);
    Ok(&cursor.get_ref()[start..end])
}

fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

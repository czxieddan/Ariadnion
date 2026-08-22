// crates/optional/ariadnion-storage-rnmdb/src/file_catalog_repository/evidence.rs - Rust source for Ariadnion.
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
//! Domain-separated durable file-catalog evidence.

use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, FileDeleteRequest, FileDescriptor, FileDigest,
    FileListCursor, FileReference, FileUploadRequest,
};
use ariadnion_core::PrincipalContext;
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{
    FileCatalogCommitmentKeyMaterial, FileCatalogCommitmentKeyVersion, FileCatalogCommitmentKeys,
    FileCatalogLookupKeyMaterial, api_error,
};

pub(super) const PUBLISH_KIND: &str = "publish";
pub(super) const DELETE_KIND: &str = "delete";
pub(super) const COMMITTED_OUTCOME: &str = "committed";

const LOOKUP_DOMAIN: &[u8] = b"ariadnion-files-idempotency-lookup-v1";
const COMMITMENT_DOMAIN: &[u8] = b"ariadnion-files-request-commitment-v1";
const CURSOR_DOMAIN: &[u8] = b"ariadnion-files-list-cursor-v1";
const CURSOR_FORMAT_VERSION: u8 = 1;
const CURSOR_PREFIX_BYTES: usize = 1 + 8 + FileReference::BYTE_LENGTH;
const CURSOR_TAG_BYTES: usize = 32;
const CURSOR_BYTES: usize = CURSOR_PREFIX_BYTES + CURSOR_TAG_BYTES;
const HEX_32_LENGTH: usize = 64;

type HmacSha256 = Hmac<Sha256>;

pub(super) fn derive_lookup(
    key: &FileCatalogLookupKeyMaterial,
    owner: &PrincipalContext,
    kind: &str,
    idempotency_key: &str,
) -> Result<[u8; 32], ApiFilesError> {
    let mut mac = new_mac(key.as_bytes())?;
    mac.update(LOOKUP_DOMAIN);
    update_mac_field(&mut mac, owner.tenant_id().as_str().as_bytes())?;
    update_mac_field(&mut mac, owner.principal_id().as_str().as_bytes())?;
    update_mac_field(&mut mac, kind.as_bytes())?;
    update_mac_field(&mut mac, idempotency_key.as_bytes())?;
    Ok(mac.finalize().into_bytes().into())
}

pub(super) fn derive_publish_commitment(
    owner: &PrincipalContext,
    request: &FileUploadRequest,
    descriptor: &FileDescriptor,
    key: &FileCatalogCommitmentKeyMaterial,
) -> Result<[u8; 32], ApiFilesError> {
    Ok(publish_commitment_mac(owner, request, descriptor, key)?
        .finalize()
        .into_bytes()
        .into())
}

pub(super) fn verify_publish_commitment(
    owner: &PrincipalContext,
    request: &FileUploadRequest,
    descriptor: &FileDescriptor,
    key: &FileCatalogCommitmentKeyMaterial,
    actual: &[u8; 32],
) -> Result<bool, StorageError> {
    let mac =
        publish_commitment_mac(owner, request, descriptor, key).map_err(|_| integrity_failure())?;
    Ok(mac.verify_slice(actual).is_ok())
}

pub(super) fn derive_delete_commitment(
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    descriptor: &FileDescriptor,
    key: &FileCatalogCommitmentKeyMaterial,
) -> Result<[u8; 32], ApiFilesError> {
    Ok(delete_commitment_mac(owner, request, descriptor, key)?
        .finalize()
        .into_bytes()
        .into())
}

pub(super) fn verify_delete_commitment(
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    descriptor: &FileDescriptor,
    key: &FileCatalogCommitmentKeyMaterial,
    actual: &[u8; 32],
) -> Result<bool, StorageError> {
    let mac =
        delete_commitment_mac(owner, request, descriptor, key).map_err(|_| integrity_failure())?;
    Ok(mac.verify_slice(actual).is_ok())
}

pub(super) fn commitment_key_for_version(
    keys: &FileCatalogCommitmentKeys,
    version: i64,
) -> Result<&FileCatalogCommitmentKeyMaterial, StorageError> {
    let version = FileCatalogCommitmentKeyVersion::new(version).map_err(|_| integrity_failure())?;
    keys.material(version).ok_or_else(integrity_failure)
}

pub(super) fn issue_cursor(
    keys: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    reference: &FileReference,
) -> Result<FileListCursor, ApiFilesError> {
    let key = keys.active()?;
    let version =
        u64::try_from(key.version().get()).map_err(|_| api_error(ApiFilesErrorCode::Internal))?;
    let mut bytes = [0_u8; CURSOR_BYTES];
    bytes[0] = CURSOR_FORMAT_VERSION;
    bytes[1..9].copy_from_slice(&version.to_be_bytes());
    bytes[9..CURSOR_PREFIX_BYTES].copy_from_slice(reference.as_bytes());
    let tag = cursor_tag(key, owner, &bytes[..CURSOR_PREFIX_BYTES])?;
    bytes[CURSOR_PREFIX_BYTES..].copy_from_slice(&tag);
    FileListCursor::new(&bytes)
}

pub(super) fn verify_cursor(
    keys: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    cursor: &FileListCursor,
) -> Result<FileReference, ApiFilesError> {
    let bytes = cursor.as_bytes();
    let Some((prefix, tag)) = split_cursor(bytes) else {
        return Err(not_found());
    };
    let key = cursor_key(keys, prefix)?;
    let mac = cursor_mac(key, owner, prefix)?;
    if mac.verify_slice(tag).is_err() {
        return Err(not_found());
    }
    let mut reference = [0_u8; FileReference::BYTE_LENGTH];
    reference.copy_from_slice(&prefix[9..CURSOR_PREFIX_BYTES]);
    Ok(FileReference::new(reference))
}

pub(super) fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(HEX_32_LENGTH);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn decode_fixed_hex(value: &str) -> Result<[u8; 32], StorageError> {
    if value.len() != HEX_32_LENGTH {
        return Err(integrity_failure());
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn publish_commitment_mac(
    owner: &PrincipalContext,
    request: &FileUploadRequest,
    descriptor: &FileDescriptor,
    key: &FileCatalogCommitmentKeyMaterial,
) -> Result<HmacSha256, ApiFilesError> {
    let specification = request.specification();
    let mut mac = commitment_mac(key, owner, PUBLISH_KIND, request.idempotency_key().as_str())?;
    update_mac_field(&mut mac, specification.display_name().as_str().as_bytes())?;
    update_mac_field(&mut mac, specification.media_type().as_str().as_bytes())?;
    update_usize_field(&mut mac, specification.byte_length().get())?;
    update_optional_digest(&mut mac, specification.expected_digest())?;
    update_descriptor(&mut mac, descriptor)?;
    Ok(mac)
}

fn delete_commitment_mac(
    owner: &PrincipalContext,
    request: &FileDeleteRequest,
    descriptor: &FileDescriptor,
    key: &FileCatalogCommitmentKeyMaterial,
) -> Result<HmacSha256, ApiFilesError> {
    let mut mac = commitment_mac(key, owner, DELETE_KIND, request.idempotency_key().as_str())?;
    update_mac_field(&mut mac, request.reference().as_bytes())?;
    update_descriptor(&mut mac, descriptor)?;
    Ok(mac)
}

fn commitment_mac(
    key: &FileCatalogCommitmentKeyMaterial,
    owner: &PrincipalContext,
    kind: &str,
    idempotency_key: &str,
) -> Result<HmacSha256, ApiFilesError> {
    let mut mac = new_mac(key.as_bytes())?;
    mac.update(COMMITMENT_DOMAIN);
    update_mac_field(&mut mac, &key.version().get().to_be_bytes())?;
    update_mac_field(&mut mac, owner.tenant_id().as_str().as_bytes())?;
    update_mac_field(&mut mac, owner.principal_id().as_str().as_bytes())?;
    update_mac_field(&mut mac, kind.as_bytes())?;
    update_mac_field(&mut mac, idempotency_key.as_bytes())?;
    Ok(mac)
}

fn update_optional_digest(
    mac: &mut HmacSha256,
    digest: Option<&FileDigest>,
) -> Result<(), ApiFilesError> {
    match digest {
        Some(digest) => {
            update_mac_field(mac, &[1])?;
            update_mac_field(mac, digest.as_bytes())
        }
        None => update_mac_field(mac, &[0]),
    }
}

fn update_descriptor(
    mac: &mut HmacSha256,
    descriptor: &FileDescriptor,
) -> Result<(), ApiFilesError> {
    update_mac_field(mac, descriptor.reference().as_bytes())?;
    update_mac_field(mac, descriptor.display_name().as_str().as_bytes())?;
    update_mac_field(mac, descriptor.media_type().as_str().as_bytes())?;
    update_usize_field(mac, descriptor.byte_length().get())?;
    update_mac_field(mac, descriptor.digest().as_bytes())
}

fn update_usize_field(mac: &mut HmacSha256, value: usize) -> Result<(), ApiFilesError> {
    let value = u64::try_from(value).map_err(|_| api_error(ApiFilesErrorCode::Internal))?;
    update_mac_field(mac, &value.to_be_bytes())
}

fn cursor_tag(
    key: &FileCatalogCommitmentKeyMaterial,
    owner: &PrincipalContext,
    prefix: &[u8],
) -> Result<[u8; CURSOR_TAG_BYTES], ApiFilesError> {
    Ok(cursor_mac(key, owner, prefix)?
        .finalize()
        .into_bytes()
        .into())
}

fn cursor_mac(
    key: &FileCatalogCommitmentKeyMaterial,
    owner: &PrincipalContext,
    prefix: &[u8],
) -> Result<HmacSha256, ApiFilesError> {
    let mut mac = new_mac(key.as_bytes())?;
    mac.update(CURSOR_DOMAIN);
    update_mac_field(&mut mac, owner.tenant_id().as_str().as_bytes())?;
    update_mac_field(&mut mac, owner.principal_id().as_str().as_bytes())?;
    update_mac_field(&mut mac, prefix)?;
    Ok(mac)
}

fn split_cursor(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.len() != CURSOR_BYTES || bytes.first().copied() != Some(CURSOR_FORMAT_VERSION) {
        return None;
    }
    Some(bytes.split_at(CURSOR_PREFIX_BYTES))
}

fn cursor_key<'a>(
    keys: &'a FileCatalogCommitmentKeys,
    prefix: &[u8],
) -> Result<&'a FileCatalogCommitmentKeyMaterial, ApiFilesError> {
    let version_bytes: [u8; 8] = prefix[1..9].try_into().map_err(|_| not_found())?;
    let version = u64::from_be_bytes(version_bytes);
    let version = i64::try_from(version).map_err(|_| not_found())?;
    let version = FileCatalogCommitmentKeyVersion::new(version).map_err(|_| not_found())?;
    keys.material(version).ok_or_else(not_found)
}

fn new_mac(key: &[u8; 32]) -> Result<HmacSha256, ApiFilesError> {
    HmacSha256::new_from_slice(key).map_err(|_| api_error(ApiFilesErrorCode::Internal))
}

fn update_mac_field(mac: &mut HmacSha256, value: &[u8]) -> Result<(), ApiFilesError> {
    let length =
        u64::try_from(value.len()).map_err(|_| api_error(ApiFilesErrorCode::ResourceExhausted))?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn hex_nibble(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(integrity_failure()),
    }
}

const fn not_found() -> ApiFilesError {
    api_error(ApiFilesErrorCode::NotFound)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

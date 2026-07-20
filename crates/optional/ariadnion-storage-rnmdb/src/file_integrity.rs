//! Bounded streaming integrity helpers for validated RNMDB locations.

use std::fs::File;
use std::io::Read;

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::StorageFileLocation;

const DIGEST_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) fn digest_location(
    location: &StorageFileLocation,
    expected_bytes: u64,
    context: &RequestContext,
) -> Result<[u8; 32], StorageError> {
    check_context(context)?;
    let file = File::open(location.path()).map_err(|_| unavailable())?;
    let maximum_bytes = expected_bytes
        .checked_add(1)
        .ok_or_else(resource_exhausted)?;
    let mut reader = file.take(maximum_bytes);
    let (digest, total) = hash_reader(&mut reader, context)?;
    if total != expected_bytes {
        return Err(integrity_failure());
    }
    Ok(digest)
}

fn hash_reader(
    reader: &mut impl Read,
    context: &RequestContext,
) -> Result<([u8; 32], u64), StorageError> {
    let mut buffer = Zeroizing::new([0_u8; DIGEST_BUFFER_BYTES]);
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    loop {
        check_context(context)?;
        let count = reader.read(&mut buffer[..]).map_err(|_| unavailable())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total = add_read_bytes(total, count)?;
    }
    check_context(context)?;
    Ok((hasher.finalize().into(), total))
}

fn add_read_bytes(total: u64, count: usize) -> Result<u64, StorageError> {
    let count = u64::try_from(count).map_err(|_| resource_exhausted())?;
    total.checked_add(count).ok_or_else(resource_exhausted)
}

fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => StorageError::new(StorageErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => StorageError::new(StorageErrorCode::DeadlineExceeded),
        _ => internal(),
    })
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

const fn unavailable() -> StorageError {
    StorageError::new(StorageErrorCode::Unavailable)
}

const fn internal() -> StorageError {
    StorageError::new(StorageErrorCode::Internal)
}

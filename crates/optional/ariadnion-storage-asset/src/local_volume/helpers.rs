// crates/optional/ariadnion-storage-asset/src/local_volume/helpers.rs - Rust source for Ariadnion.
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

use std::ffi::OsString;
use std::fs::{self, File as StdFile, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
#[cfg(feature = "test-hooks")]
use std::sync::LazyLock;
use std::sync::{Mutex, MutexGuard, TryLockError as MutexTryLockError};

use ariadnion_core::{ErrorCode, RequestContext};
#[cfg(windows)]
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::ambient_authority;
#[cfg(unix)]
use cap_std::fs::DirBuilderExt;
#[cfg(windows)]
use cap_std::fs::OpenOptions;
use cap_std::fs::{Dir, DirBuilder, File, Metadata};
use sha2::{Digest, Sha256};

use crate::manifest::StageRecord;
use crate::{
    AssetByteLength, AssetDigest, AssetQuarantineReason, AssetStageToken, StagedAsset,
    StorageError, StorageErrorCode,
};

use super::BUFFER_SIZE;

pub(super) struct StageLease<'a> {
    pub(super) lock: StdFile,
    pub(super) staged: &'a StagedAsset,
    pub(super) record: StageRecord,
}

impl StageLease<'_> {
    pub(super) fn unlock(&self) -> Result<(), StorageError> {
        self.lock.unlock().map_err(map_io)
    }
}

impl super::LocalVolume {
    pub(super) fn open_stage_lock(&self, staged: &StagedAsset) -> Result<StdFile, StorageError> {
        self.open_stage_lock_if_present(staged)?
            .ok_or_else(integrity_failure)
    }

    pub(super) fn open_stage_lock_if_present(
        &self,
        staged: &StagedAsset,
    ) -> Result<Option<StdFile>, StorageError> {
        let file = match self.open_file(&self.stage_lock_path(staged.token()), true, false) {
            Ok((file, _)) => file,
            Err(error) if error.code() == StorageErrorCode::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let lock = file.into_std();
        lock_stage(&lock)?;
        Ok(Some(lock))
    }
}

pub(super) fn check_optional_context(context: Option<&RequestContext>) -> Result<(), StorageError> {
    if let Some(context) = context {
        check_active(context)?;
    }
    Ok(())
}

#[cfg(feature = "test-hooks")]
static ROOT_PARENT_SYNC_FAILURE: LazyLock<Mutex<Option<(PathBuf, usize)>>> =
    LazyLock::new(|| Mutex::new(None));

#[cfg(feature = "test-hooks")]
impl super::LocalVolume {
    #[doc(hidden)]
    pub fn inject_root_parent_sync_failure_for_test(
        root: impl AsRef<Path>,
        sync_ordinal: usize,
    ) -> Result<(), StorageError> {
        if sync_ordinal == 0 {
            return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
        }
        let root = std::path::absolute(root.as_ref()).map_err(map_io)?;
        let mut fault = ROOT_PARENT_SYNC_FAILURE
            .lock()
            .map_err(|_| internal_failure())?;
        if fault.is_some() {
            return Err(StorageError::new(StorageErrorCode::Conflict));
        }
        *fault = Some((root, sync_ordinal));
        Ok(())
    }

    #[cfg(windows)]
    #[doc(hidden)]
    pub fn sync_relative_for_test(&self, relative: &Path) -> Result<(), StorageError> {
        let _operation = super::acquire_operation(&self.operation_gate)?;
        self.sync_relative(relative)
    }
}

#[cfg(feature = "test-hooks")]
fn maybe_fail_root_parent_sync(root: &Path) -> Result<(), StorageError> {
    let mut fault = ROOT_PARENT_SYNC_FAILURE
        .lock()
        .map_err(|_| internal_failure())?;
    let Some((target, remaining)) = fault.as_mut() else {
        return Ok(());
    };
    if target != root {
        return Ok(());
    }
    if *remaining > 1 {
        *remaining -= 1;
        return Ok(());
    }
    *fault = None;
    Err(StorageError::new(StorageErrorCode::Unavailable))
}

#[cfg(not(feature = "test-hooks"))]
fn maybe_fail_root_parent_sync(_root: &Path) -> Result<(), StorageError> {
    Ok(())
}

pub(super) fn prepare_root(path: &Path) -> Result<PathBuf, StorageError> {
    let absolute = std::path::absolute(path).map_err(map_io)?;
    ensure_root_exists(&absolute)?;
    canonicalize_root(&absolute)
}

fn ensure_root_exists(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_std_directory(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_root_path(path)?,
        Err(error) => return Err(map_io(error)),
    }
    Ok(())
}

fn create_root_path(path: &Path) -> Result<(), StorageError> {
    let (existing, missing) = split_root_path(path)?;
    let parent = Dir::open_ambient_dir(existing, ambient_authority()).map_err(map_io)?;
    let final_directory = create_missing_root_components(parent, path, &missing)?;
    validate_root_directory(&final_directory)
}

fn split_root_path(path: &Path) -> Result<(PathBuf, Vec<OsString>), StorageError> {
    let mut cursor = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match probe_root_path(&cursor)? {
            RootPathProbe::Existing(existing) => {
                missing.reverse();
                return Ok((existing, missing));
            }
            RootPathProbe::Missing(name, parent) => {
                missing.push(name);
                cursor = parent;
            }
        }
    }
}

enum RootPathProbe {
    Existing(PathBuf),
    Missing(OsString, PathBuf),
}

fn probe_root_path(path: &Path) -> Result<RootPathProbe, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_std_directory(&metadata)?;
            Ok(RootPathProbe::Existing(path.to_path_buf()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or_else(integrity_failure)?;
            let parent = path.parent().ok_or_else(integrity_failure)?;
            Ok(RootPathProbe::Missing(
                name.to_os_string(),
                parent.to_path_buf(),
            ))
        }
        Err(error) => Err(map_io(error)),
    }
}

fn create_missing_root_components(
    mut parent: Dir,
    path: &Path,
    missing: &[OsString],
) -> Result<Dir, StorageError> {
    let builder = private_dir_builder();
    for name in missing {
        let child = create_root_component(&parent, name, &builder)?;
        sync_new_root_parent(&parent, path)?;
        parent = child;
    }
    Ok(parent)
}

fn create_root_component(
    parent: &Dir,
    name: &OsString,
    builder: &DirBuilder,
) -> Result<Dir, StorageError> {
    match parent.create_dir_with(name, builder) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(map_io(error)),
    }
    parent.open_dir_nofollow(name).map_err(map_io)
}

fn sync_new_root_parent(parent: &Dir, path: &Path) -> Result<(), StorageError> {
    sync_directory_handle(parent)?;
    maybe_fail_root_parent_sync(path)
}

fn validate_root_directory(directory: &Dir) -> Result<(), StorageError> {
    let metadata = directory.metadata(".").map_err(map_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn sync_directory_handle(directory: &Dir) -> Result<(), StorageError> {
    #[cfg(windows)]
    {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .maybe_dir(true)
            .follow(FollowSymlinks::No);
        let file = directory
            .open_with(".", &options)
            .map_err(map_io)?
            .into_std();
        validate_sync_directory(&file.metadata().map_err(map_io)?)?;
        file.sync_all().map_err(map_io)
    }
    #[cfg(not(windows))]
    {
        directory
            .try_clone()
            .map_err(map_io)?
            .into_std_file()
            .sync_all()
            .map_err(map_io)
    }
}

fn canonicalize_root(path: &Path) -> Result<PathBuf, StorageError> {
    let canonical = fs::canonicalize(path).map_err(map_io)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(map_io)?;
    validate_std_directory(&metadata)?;
    Ok(canonical)
}

pub(super) fn private_dir_builder() -> DirBuilder {
    let mut builder = DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    builder.mode(0o700);
    builder
}

pub(super) fn valid_components(path: &Path) -> Result<Vec<OsString>, StorageError> {
    let mut output = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => output.push(name.to_os_string()),
            Component::CurDir if output.is_empty() => {}
            _ => return Err(integrity_failure()),
        }
    }
    Ok(output)
}

pub(super) fn validate_std_directory(metadata: &fs::Metadata) -> Result<(), StorageError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(integrity_failure());
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn validate_sync_directory(metadata: &fs::Metadata) -> Result<(), StorageError> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn validate_regular_metadata(metadata: &Metadata) -> Result<(), StorageError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn read_chunk(
    source: &mut dyn Read,
    buffer: &mut [u8; BUFFER_SIZE],
    remaining: u64,
    context: &RequestContext,
) -> Result<usize, StorageError> {
    check_active(context)?;
    let amount = remaining.min(BUFFER_SIZE as u64) as usize;
    let read = source.read(&mut buffer[..amount]).map_err(map_io)?;
    check_active(context)?;
    if read == 0 {
        return Err(integrity_failure());
    }
    Ok(read)
}

pub(super) fn write_chunk(
    destination: &mut dyn Write,
    bytes: &[u8],
    context: &RequestContext,
) -> Result<(), StorageError> {
    check_active(context)?;
    destination.write_all(bytes).map_err(map_io)?;
    check_active(context)
}

pub(super) fn ensure_source_exhausted(
    source: &mut dyn Read,
    context: &RequestContext,
) -> Result<(), StorageError> {
    check_active(context)?;
    let mut extra = [0_u8; 1];
    let read = source.read(&mut extra).map_err(map_io)?;
    check_active(context)?;
    if read != 0 {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn write_and_sync(
    file: &mut File,
    bytes: &[u8],
    context: &RequestContext,
) -> Result<(), StorageError> {
    check_active(context)?;
    file.write_all(bytes).map_err(map_io)?;
    check_active(context)?;
    file.sync_all().map_err(map_io)?;
    check_active(context)
}

pub(super) fn read_bounded(
    file: &mut File,
    metadata: &Metadata,
    maximum: u64,
    context: &RequestContext,
) -> Result<Vec<u8>, StorageError> {
    ensure_record_size(metadata, maximum)?;
    let length = usize::try_from(metadata.len())
        .map_err(|_| StorageError::new(StorageErrorCode::ResourceExhausted))?;
    let bytes = read_record_payload(file, length, context)?;
    ensure_no_extra_bytes(file)?;
    check_active(context)?;
    Ok(bytes)
}

pub(super) fn verify_marker_reader(
    source: &mut dyn Read,
    expected: &[u8],
) -> Result<(), StorageError> {
    let mut current = vec![0_u8; expected.len()];
    read_exact_marker(source, &mut current)?;
    if current != expected {
        return Err(integrity_failure());
    }
    reject_marker_growth(source)
}

fn read_exact_marker(source: &mut dyn Read, current: &mut [u8]) -> Result<(), StorageError> {
    match source.read_exact(current) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(integrity_failure()),
        Err(error) => Err(map_io(error)),
    }
}

fn reject_marker_growth(source: &mut dyn Read) -> Result<(), StorageError> {
    let mut extra = [0_u8; 1];
    if source.read(&mut extra).map_err(map_io)? != 0 {
        return Err(integrity_failure());
    }
    Ok(())
}

fn read_record_payload(
    file: &mut File,
    length: usize,
    context: &RequestContext,
) -> Result<Vec<u8>, StorageError> {
    file.seek(SeekFrom::Start(0)).map_err(map_io)?;
    let mut bytes = vec![0_u8; length];
    check_active(context)?;
    file.read_exact(&mut bytes).map_err(map_io)?;
    check_active(context)?;
    Ok(bytes)
}

fn ensure_record_size(metadata: &Metadata, maximum: u64) -> Result<(), StorageError> {
    if metadata.len() > maximum {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn ensure_no_extra_bytes(file: &mut File) -> Result<(), StorageError> {
    let mut extra = [0_u8; 1];
    if file.read(&mut extra).map_err(map_io)? != 0 {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn stream_file(
    file: &mut File,
    length: AssetByteLength,
    destination: &mut Option<&mut dyn Write>,
    context: &RequestContext,
) -> Result<AssetDigest, StorageError> {
    let mut hasher = Sha256::new();
    let mut remaining = length.get();
    let mut buffer = [0_u8; BUFFER_SIZE];
    while remaining > 0 {
        let read = read_chunk(file, &mut buffer, remaining, context)?;
        hasher.update(&buffer[..read]);
        if let Some(writer) = destination.as_deref_mut() {
            write_chunk(writer, &buffer[..read], context)?;
        }
        remaining -= read as u64;
    }
    ensure_source_exhausted(file, context)?;
    Ok(AssetDigest::new(hasher.finalize().into()))
}

pub(super) fn lock_stage(file: &StdFile) -> Result<(), StorageError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(StorageError::new(StorageErrorCode::Conflict)),
        Err(TryLockError::Error(error)) => Err(map_io(error)),
    }
}

pub(super) fn ensure_exact_length(
    metadata: &Metadata,
    length: AssetByteLength,
) -> Result<(), StorageError> {
    if metadata.len() != length.get() {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn ensure_digest(
    actual: AssetDigest,
    expected: AssetDigest,
) -> Result<(), StorageError> {
    if actual != expected {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn ensure_expected_digest(
    expected: Option<AssetDigest>,
    actual: AssetDigest,
) -> Result<(), StorageError> {
    if expected.is_some_and(|expected| expected != actual) {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(super) fn check_active(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => StorageError::new(StorageErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => StorageError::new(StorageErrorCode::DeadlineExceeded),
        _ => internal_failure(),
    })
}

pub(super) fn acquire_operation(gate: &Mutex<()>) -> Result<MutexGuard<'_, ()>, StorageError> {
    match gate.try_lock() {
        Ok(guard) => Ok(guard),
        Err(MutexTryLockError::WouldBlock) => {
            Err(StorageError::new(StorageErrorCode::ResourceExhausted))
        }
        Err(MutexTryLockError::Poisoned(_)) => Err(internal_failure()),
    }
}

pub(super) fn map_io(error: io::Error) -> StorageError {
    match error.kind() {
        io::ErrorKind::NotFound => StorageError::new(StorageErrorCode::NotFound),
        io::ErrorKind::AlreadyExists => StorageError::new(StorageErrorCode::Conflict),
        io::ErrorKind::PermissionDenied => StorageError::new(StorageErrorCode::Unavailable),
        _ => StorageError::new(StorageErrorCode::Unavailable),
    }
}

pub(super) fn map_missing_stage(error: StorageError) -> StorageError {
    if error.code() == StorageErrorCode::NotFound {
        integrity_failure()
    } else {
        error
    }
}

pub(super) fn commit_indeterminate(_error: StorageError) -> StorageError {
    StorageError::new(StorageErrorCode::CommitIndeterminate)
}

pub(super) fn commit_indeterminate_result() -> StorageError {
    StorageError::new(StorageErrorCode::CommitIndeterminate)
}

pub(super) fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

pub(super) fn internal_failure() -> StorageError {
    StorageError::new(StorageErrorCode::Internal)
}

pub(super) fn reason_name(reason: AssetQuarantineReason) -> &'static str {
    match reason {
        AssetQuarantineReason::IntegrityFailure => "integrity-failure",
        AssetQuarantineReason::PolicyRejected => "policy-rejected",
        AssetQuarantineReason::InspectionRequired => "inspection-required",
        AssetQuarantineReason::Abandoned => "abandoned",
    }
}

pub(super) fn token_name(token: &AssetStageToken) -> String {
    let mut hasher = Sha256::new();
    let domain = b"ariadnion-local-volume-token-v1";
    hasher.update((domain.len() as u16).to_be_bytes());
    hasher.update(domain);
    hasher.update((token.as_bytes().len() as u16).to_be_bytes());
    hasher.update(token.as_bytes());
    hex(&hasher.finalize())
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        output.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    output
}

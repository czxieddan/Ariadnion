//! Redacted storage-file locations confined to a configured data root.

use std::fmt::{self, Debug, Formatter};
use std::path::{Component, Path, PathBuf};

use ariadnion_storage_domain::{StorageError, StorageErrorCode, StorageInstanceId};

/// A validated RNMDB file location whose path is never exposed publicly.
#[derive(Clone, Eq, PartialEq)]
pub struct StorageFileLocation {
    instance: StorageInstanceId,
    path: PathBuf,
}

impl StorageFileLocation {
    /// Places an instance file below an absolute, traversal-free data root.
    pub fn new(
        data_root: impl Into<PathBuf>,
        instance: StorageInstanceId,
    ) -> Result<Self, StorageError> {
        let data_root = data_root.into();
        if !valid_data_root(&data_root) {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        let path = data_root.join(format!("{}.rnmdb", instance.as_str()));
        Ok(Self { instance, path })
    }

    /// Returns the safe instance identity.
    #[must_use]
    pub const fn instance(&self) -> &StorageInstanceId {
        &self.instance
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Debug for StorageFileLocation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageFileLocation")
            .field("instance", &self.instance)
            .field("path", &"<redacted>")
            .finish()
    }
}

fn valid_data_root(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

// crates/optional/ariadnion-storage-rnmdb/src/location.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
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

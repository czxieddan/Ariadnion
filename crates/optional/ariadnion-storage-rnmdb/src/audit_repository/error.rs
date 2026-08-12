// crates/optional/ariadnion-storage-rnmdb/src/audit_repository/error.rs - Rust source for Ariadnion.
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
//! Stable storage error projection for identity audit persistence.

use ariadnion_audit_domain::AuditError;
use ariadnion_audit_store::{AuditStoreError, AuditStoreErrorCode};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};

pub(super) fn map_domain_error(_error: AuditError) -> StorageError {
    integrity_failure()
}

pub(super) fn map_store_error(error: AuditStoreError) -> StorageError {
    let code = match error.code() {
        AuditStoreErrorCode::EmptyRange | AuditStoreErrorCode::IncompleteRange => {
            StorageErrorCode::NotFound
        }
        AuditStoreErrorCode::ResourceLimitExceeded => StorageErrorCode::ResourceExhausted,
        _ => StorageErrorCode::IntegrityFailure,
    };
    StorageError::new(code)
}

pub(super) const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

pub(super) const fn not_found() -> StorageError {
    StorageError::new(StorageErrorCode::NotFound)
}

pub(super) const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

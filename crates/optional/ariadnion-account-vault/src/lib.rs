// crates/optional/ariadnion-account-vault/src/lib.rs - Secret vault contracts for Ariadnion.
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
//! Tenant- and purpose-bound contracts for encrypted account secret storage.
//!
//! The crate deliberately stops at a typed vault boundary. A storage adapter
//! owns the reviewed encryption primitive, key custody, durable transaction,
//! and audit implementation. The domain contract never persists or displays
//! plaintext secret material.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod port;
mod secret;

pub use error::{VaultError, VaultErrorCode};
pub use port::{
    BoxVaultFuture, SecretReadRequest, SecretRevokeReceipt, SecretStoreReceipt, SecretStoreRequest,
    VaultPort, VaultRevokeReason, VaultRevokeRequest,
};
pub use secret::{
    ENVELOPE_NONCE_BYTES, EncryptedSecretEnvelope, MAX_CIPHERTEXT_BYTES, MAX_LEASE_LIFETIME,
    MAX_SECRET_BYTES, SecretLease, SecretLeaseId, SecretLeaseLifetime, SecretMaterial,
    VaultKeyVersion,
};

pub use ariadnion_account_domain::{
    AccountId, SecretPath, SecretProvider, SecretPurpose, SecretRef, SecretVersion,
};

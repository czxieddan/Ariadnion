// crates/optional/ariadnion-storage-rnmdb/src/vault_repository/custody.rs - Concrete RNMDB vault key custody for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Concrete externally provisioned custody using RNMDB authenticated encryption.

use std::fmt::{self, Debug, Formatter};
use std::time::SystemTime;

use ariadnion_account_vault::{
    ENVELOPE_NONCE_BYTES, EncryptedSecretEnvelope, SecretMaterial, SecretRef, VaultError,
    VaultErrorCode, VaultKeyVersion,
};
use ariadnion_core::TenantId;
use hmac::{Hmac, Mac};
use rnmdb_common::ids::RelationId;
use rnmdb_security::{ColumnKeyMaterial, decrypt_column_value, encrypt_column_value};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{VaultKeyCustody, VaultOperation, error, sql};

/// Binary maximum for keys supplied in one immutable custody snapshot.
pub const MAX_VAULT_CUSTODY_KEYS: usize = 1 << 8;
const MAX_MUTATION_PAYLOAD_BYTES: usize = 1 << 7;

/// One externally provisioned tenant key with an explicit UTC lifecycle.
///
/// Raw bytes remain in zeroizing memory and are never persisted, logged, or
/// exposed by this API. At retirement, both encryption and decryption fail
/// closed; overlap windows must be explicitly provisioned by key custody.
pub struct VaultCustodyKey {
    tenant: TenantId,
    version: VaultKeyVersion,
    activated_at: SystemTime,
    retired_at: Option<SystemTime>,
    bytes: Zeroizing<[u8; 32]>,
}

impl VaultCustodyKey {
    /// Creates one lifecycle-bound key from external custody material.
    ///
    /// # Errors
    /// Rejects a retirement that is not strictly later than activation.
    pub fn new(
        tenant: TenantId,
        version: VaultKeyVersion,
        activated_at: SystemTime,
        retired_at: Option<SystemTime>,
        bytes: [u8; 32],
    ) -> Result<Self, VaultError> {
        let bytes = Zeroizing::new(bytes);
        if retired_at.is_some_and(|retired| retired <= activated_at) {
            return Err(error(VaultErrorCode::InvalidArgument));
        }
        Ok(Self {
            tenant,
            version,
            activated_at,
            retired_at,
            bytes,
        })
    }

    fn active_at(&self, now: SystemTime) -> bool {
        self.activated_at <= now && self.retired_at.is_none_or(|retired| now < retired)
    }
}

impl Debug for VaultCustodyKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultCustodyKey")
            .field("version", &self.version)
            .field("activated_at", &self.activated_at)
            .field("retired_at", &self.retired_at)
            .finish_non_exhaustive()
    }
}

/// Immutable externally provisioned key custody backed by RNMDB's AEAD API.
///
/// The supplied relation identity is an explicit stable cryptographic namespace,
/// not a fabricated permission or runtime role. Associated data binds the tenant,
/// provider, path, version, purpose, key version, and 24-byte envelope nonce.
/// RNMDB's authenticated column envelope contains its own fresh encryption
/// nonce; the outer nonce is independently random and authenticated.
///
/// Replace the custody snapshot through the composition boundary when external
/// key state changes. This adapter never discovers, creates, or persists keys.
/// The lookup key must remain stable across envelope-key rotations; changing it
/// requires an explicit new-target index migration, not a live key replacement.
pub struct RnmdbVaultKeyCustody {
    namespace: RelationId,
    lookup_key: Zeroizing<[u8; 32]>,
    keys: Box<[VaultCustodyKey]>,
}

impl RnmdbVaultKeyCustody {
    /// Validates a bounded, duplicate-free externally provisioned key snapshot.
    ///
    /// # Errors
    /// Rejects empty, oversized, or duplicate tenant/version snapshots.
    pub fn new(
        namespace: RelationId,
        lookup_key: [u8; 32],
        mut keys: Vec<VaultCustodyKey>,
    ) -> Result<Self, VaultError> {
        let lookup_key = Zeroizing::new(lookup_key);
        if keys.is_empty() || keys.len() > MAX_VAULT_CUSTODY_KEYS {
            return Err(error(VaultErrorCode::InvalidArgument));
        }
        keys.sort_by(|left, right| {
            (&left.tenant, left.version).cmp(&(&right.tenant, right.version))
        });
        if keys
            .windows(2)
            .any(|pair| pair[0].tenant == pair[1].tenant && pair[0].version == pair[1].version)
        {
            return Err(error(VaultErrorCode::Conflict));
        }
        Ok(Self {
            namespace,
            lookup_key,
            keys: keys.into_boxed_slice(),
        })
    }

    /// Encrypts one bounded plaintext using an active externally supplied key.
    ///
    /// This blocking cryptographic API belongs on a dedicated worker. The
    /// plaintext input must already be zeroizing and is never retained.
    ///
    /// # Errors
    /// Tenant/key lifecycle, randomness, or authentication setup fails closed.
    pub fn encrypt(
        &self,
        tenant: &TenantId,
        reference: &SecretRef,
        version: VaultKeyVersion,
        material: &SecretMaterial,
    ) -> Result<EncryptedSecretEnvelope, VaultError> {
        let key = self.key(tenant, version)?;
        let mut nonce = Zeroizing::new([0_u8; ENVELOPE_NONCE_BYTES]);
        getrandom::fill(nonce.as_mut()).map_err(|_| error(VaultErrorCode::Unavailable))?;
        let aad = self.associated_data(tenant, reference, version, &nonce)?;
        let key_material = ColumnKeyMaterial::from_bytes(*key.bytes);
        let encrypted = seal(&key_material, self.namespace, &aad, material)?;
        require_active_key(key)?;
        EncryptedSecretEnvelope::new(version, *nonce, &encrypted)
    }

    fn key(
        &self,
        tenant: &TenantId,
        version: VaultKeyVersion,
    ) -> Result<&VaultCustodyKey, VaultError> {
        let found = self
            .keys
            .binary_search_by(|key| (&key.tenant, key.version).cmp(&(tenant, version)))
            .ok()
            .and_then(|index| self.keys.get(index))
            .ok_or_else(|| error(VaultErrorCode::Unavailable))?;
        if !found.active_at(SystemTime::now()) {
            return Err(error(VaultErrorCode::Unavailable));
        }
        Ok(found)
    }

    fn associated_data(
        &self,
        tenant: &TenantId,
        reference: &SecretRef,
        version: VaultKeyVersion,
        nonce: &[u8; ENVELOPE_NONCE_BYTES],
    ) -> Result<String, VaultError> {
        let mut mac = self.reference_mac(tenant, reference, b"ariadnion.vault.aead.v1")?;
        frame(&mut mac, &version.get().to_be_bytes());
        frame(&mut mac, nonce);
        Ok(format!(
            "ariadnion_vault_{}",
            sql::hex(&mac.finalize().into_bytes())
        ))
    }

    fn reference_mac(
        &self,
        tenant: &TenantId,
        reference: &SecretRef,
        domain: &[u8],
    ) -> Result<Hmac<Sha256>, VaultError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.lookup_key.as_ref())
            .map_err(|_| error(VaultErrorCode::IntegrityFailure))?;
        frame(&mut mac, domain);
        frame(&mut mac, tenant.as_str().as_bytes());
        frame(&mut mac, reference.provider().as_str().as_bytes());
        frame(&mut mac, reference.path().as_str().as_bytes());
        frame(&mut mac, &reference.version().get().to_be_bytes());
        frame(&mut mac, reference.purpose().as_str().as_bytes());
        Ok(mac)
    }
}

impl VaultKeyCustody for RnmdbVaultKeyCustody {
    fn mutation_fingerprint(
        &self,
        tenant: &TenantId,
        reference: &SecretRef,
        operation: VaultOperation,
        payload: &[u8],
    ) -> Result<[u8; 32], VaultError> {
        require_mutation_payload(payload)?;
        let domain: &[u8] = match operation {
            VaultOperation::Store => b"ariadnion.vault.store-mutation.v1",
            VaultOperation::Revoke => b"ariadnion.vault.revoke-mutation.v1",
            _ => return Err(error(VaultErrorCode::InvalidArgument)),
        };
        let mut mac = self.reference_mac(tenant, reference, domain)?;
        frame(&mut mac, payload);
        Ok(mac.finalize().into_bytes().into())
    }

    fn reference_digest(
        &self,
        tenant: &TenantId,
        reference: &SecretRef,
    ) -> Result<[u8; 32], VaultError> {
        let mac = self.reference_mac(tenant, reference, b"ariadnion.vault.locator.v1")?;
        Ok(mac.finalize().into_bytes().into())
    }

    fn decrypt(
        &self,
        tenant: &TenantId,
        reference: &SecretRef,
        envelope: &EncryptedSecretEnvelope,
    ) -> Result<SecretMaterial, VaultError> {
        let key = self.key(tenant, envelope.key_version())?;
        let aad =
            self.associated_data(tenant, reference, envelope.key_version(), envelope.nonce())?;
        let key_material = ColumnKeyMaterial::from_bytes(*key.bytes);
        let plaintext = Zeroizing::new(
            decrypt_column_value(&key_material, self.namespace, &aad, envelope.ciphertext())
                .map_err(|_| error(VaultErrorCode::IntegrityFailure))?,
        );
        if !key.active_at(SystemTime::now()) {
            return Err(error(VaultErrorCode::Unavailable));
        }
        SecretMaterial::from_bytes(&plaintext)
    }
}

impl Debug for RnmdbVaultKeyCustody {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbVaultKeyCustody")
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

fn frame(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(bytes);
}

fn require_active_key(key: &VaultCustodyKey) -> Result<(), VaultError> {
    if !key.active_at(SystemTime::now()) {
        return Err(error(VaultErrorCode::Unavailable));
    }
    Ok(())
}

fn require_mutation_payload(payload: &[u8]) -> Result<(), VaultError> {
    if payload.is_empty() || payload.len() > MAX_MUTATION_PAYLOAD_BYTES {
        return Err(error(VaultErrorCode::InvalidArgument));
    }
    Ok(())
}

fn seal(
    key: &ColumnKeyMaterial,
    namespace: RelationId,
    aad: &str,
    material: &SecretMaterial,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    // Upstream's OS entropy API can unwind on failure. Containment provides no
    // deterministic nonce fallback and never turns an entropy failure into data.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        encrypt_column_value(key, namespace, aad, material.as_bytes())
    }))
    .map_err(|_| error(VaultErrorCode::Unavailable))?;
    result
        .map(Zeroizing::new)
        .map_err(|_| error(VaultErrorCode::IntegrityFailure))
}

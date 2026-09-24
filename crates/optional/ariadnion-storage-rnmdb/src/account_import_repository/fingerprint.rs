// crates/optional/ariadnion-storage-rnmdb/src/account_import_repository/fingerprint.rs - Account import replay fingerprints for Ariadnion.
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
//! Versioned HMAC identities for exact account-import replay.

use ariadnion_account_domain::AccountUtcTimestamp;
use ariadnion_account_import::{ConflictStrategy, DurablePublishRequest, ImportEntry};
use ariadnion_core::TenantId;
use ariadnion_storage_domain::StorageError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::sql;

const LEGACY_DOMAIN: &[u8] = b"ariadnion.account-import.publish-intent.hmac-sha256.v2";
const CONFIGURED_DOMAIN: &[u8] = b"ariadnion.account-import.publish-intent.hmac-sha256.v3";
const ROUTING_DOMAIN: &[u8] = b"ariadnion.account-import.publish-intent.hmac-sha256.v4";
const EFFECTIVE_WINDOW_DOMAIN: &[u8] = b"ariadnion.account-import.publish-intent.hmac-sha256.v5";
const CONFIGURATION_MODE_DOMAIN: &[u8] = b"ariadnion.account-import.publish-intent.hmac-sha256.v6";
const PROVISIONING_POLICY: &[u8] = b"minimal-provisioning-v1";
const REPLACEMENT_POLICY: &[u8] = b"advance-config-and-account-versions-preserve-status-v1";
const INITIAL_VERSION: u64 = 1;
const INITIAL_MAX_CONCURRENCY: u32 = 1;
const INITIAL_STATUS: &str = "provisioning";

pub(super) fn request(
    tenant: &TenantId,
    request: &DurablePublishRequest,
    key: &[u8],
) -> Result<Zeroizing<String>, StorageError> {
    let mut hash = Hmac::<Sha256>::new_from_slice(key).map_err(|_| sql::integrity())?;
    let shape = fingerprint_shape(request.intent().entries());
    push_frame(&mut hash, shape.domain());
    push_frame(&mut hash, tenant.as_str().as_bytes());
    push_frame(&mut hash, request.mutation_id().as_str().as_bytes());
    let intent = request.intent();
    push_frame(&mut hash, &intent.expected_generation().get().to_be_bytes());
    push_frame(&mut hash, strategy_label(intent.strategy()).as_bytes());
    push_frame(&mut hash, PROVISIONING_POLICY);
    push_frame(&mut hash, REPLACEMENT_POLICY);
    let count = u64::try_from(intent.entries().len()).map_err(|_| sql::exhausted())?;
    push_frame(&mut hash, &count.to_be_bytes());
    for entry in intent.entries() {
        fingerprint_entry(&mut hash, entry, shape);
    }
    Ok(Zeroizing::new(bytes_hex(&hash.finalize().into_bytes())))
}

#[derive(Clone, Copy)]
enum FingerprintShape {
    LegacyV2,
    ConfiguredV3,
    RoutingV4,
    EffectiveWindowV5,
    ConfigurationModeV6,
}

impl FingerprintShape {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::LegacyV2 => LEGACY_DOMAIN,
            Self::ConfiguredV3 => CONFIGURED_DOMAIN,
            Self::RoutingV4 => ROUTING_DOMAIN,
            Self::EffectiveWindowV5 => EFFECTIVE_WINDOW_DOMAIN,
            Self::ConfigurationModeV6 => CONFIGURATION_MODE_DOMAIN,
        }
    }
}

fn fingerprint_shape(entries: &[ImportEntry]) -> FingerprintShape {
    if requires_configuration_mode(entries) {
        FingerprintShape::ConfigurationModeV6
    } else if entries.iter().any(has_effective_window) {
        FingerprintShape::EffectiveWindowV5
    } else if entries.iter().any(has_nondefault_routing) {
        FingerprintShape::RoutingV4
    } else if entries.iter().any(ImportEntry::has_explicit_configuration) {
        FingerprintShape::ConfiguredV3
    } else {
        FingerprintShape::LegacyV2
    }
}

fn requires_configuration_mode(entries: &[ImportEntry]) -> bool {
    // Equal-valued explicit entries could be legacy entries in an old receipt.
    // Both forms must leave the old domain; otherwise a mode-changing replay
    // could still authenticate against an ambiguous V3-V5 fingerprint.
    entries.len() > 1
        && entries.iter().any(ImportEntry::has_explicit_configuration)
        && entries.iter().any(has_legacy_entry_values)
}

fn has_legacy_entry_values(entry: &ImportEntry) -> bool {
    has_legacy_metadata(entry) && has_legacy_configuration(entry)
}

fn has_legacy_metadata(entry: &ImportEntry) -> bool {
    entry.provider_label() == entry.provider_id().as_str()
        && entry.account_label() == entry.account_id().as_str()
        && entry.external_account_id().is_none()
}

fn has_legacy_configuration(entry: &ImportEntry) -> bool {
    entry.config_version().get() == INITIAL_VERSION
        && entry.default_model().is_none()
        && entry.max_concurrency().get() == INITIAL_MAX_CONCURRENCY
        && !has_nondefault_routing(entry)
        && !has_effective_window(entry)
}

fn has_effective_window(entry: &ImportEntry) -> bool {
    entry.effective_window() != Default::default()
}

fn has_nondefault_routing(entry: &ImportEntry) -> bool {
    entry.routing_priority() != Default::default() || entry.routing_weight() != Default::default()
}

fn fingerprint_entry(hash: &mut Hmac<Sha256>, entry: &ImportEntry, shape: FingerprintShape) {
    match shape {
        FingerprintShape::LegacyV2 => fingerprint_legacy_entry(hash, entry),
        FingerprintShape::ConfiguredV3 => fingerprint_configured_entry(hash, entry),
        FingerprintShape::RoutingV4 => fingerprint_routing_entry(hash, entry),
        FingerprintShape::EffectiveWindowV5 => fingerprint_effective_window_entry(hash, entry),
        FingerprintShape::ConfigurationModeV6 => fingerprint_configuration_mode_entry(hash, entry),
    }
}

fn fingerprint_configuration_mode_entry(hash: &mut Hmac<Sha256>, entry: &ImportEntry) {
    push_frame(hash, &[u8::from(entry.has_explicit_configuration())]);
    fingerprint_effective_window_entry(hash, entry);
}

fn fingerprint_effective_window_entry(hash: &mut Hmac<Sha256>, entry: &ImportEntry) {
    fingerprint_routing_entry(hash, entry);
    let window = entry.effective_window();
    push_optional_timestamp(hash, window.effective_start());
    push_optional_timestamp(hash, window.effective_end());
}

fn fingerprint_routing_entry(hash: &mut Hmac<Sha256>, entry: &ImportEntry) {
    fingerprint_configured_entry(hash, entry);
    push_frame(hash, &entry.routing_priority().get().to_be_bytes());
    push_frame(hash, &entry.routing_weight().get().to_be_bytes());
}

fn fingerprint_configured_entry(hash: &mut Hmac<Sha256>, entry: &ImportEntry) {
    let secret = entry.secret_ref();
    push_frame(hash, entry.account_id().as_str().as_bytes());
    push_frame(hash, entry.provider_id().as_str().as_bytes());
    push_frame(hash, entry.provider_label().as_bytes());
    push_frame(hash, entry.account_label().as_bytes());
    push_optional_text(
        hash,
        entry.external_account_id().map(|value| value.as_str()),
    );
    push_frame(hash, &entry.config_version().get().to_be_bytes());
    push_frame(hash, secret.provider().as_str().as_bytes());
    push_frame(hash, secret.path().as_str().as_bytes());
    push_frame(hash, &secret.version().get().to_be_bytes());
    push_frame(hash, secret.purpose().as_str().as_bytes());
    push_frame(hash, &entry.credential_digest().as_bytes());
    push_optional_text(hash, entry.default_model().map(|value| value.as_str()));
    push_frame(hash, &entry.max_concurrency().get().to_be_bytes());
    push_frame(hash, &INITIAL_VERSION.to_be_bytes());
    push_frame(hash, INITIAL_STATUS.as_bytes());
}

fn fingerprint_legacy_entry(hash: &mut Hmac<Sha256>, entry: &ImportEntry) {
    let secret = entry.secret_ref();
    push_frame(hash, entry.account_id().as_str().as_bytes());
    push_frame(hash, entry.provider_id().as_str().as_bytes());
    push_frame(hash, entry.provider_id().as_str().as_bytes());
    push_frame(hash, entry.account_id().as_str().as_bytes());
    push_frame(hash, b"external-account-id:none");
    push_frame(hash, &INITIAL_VERSION.to_be_bytes());
    push_frame(hash, secret.provider().as_str().as_bytes());
    push_frame(hash, secret.path().as_str().as_bytes());
    push_frame(hash, &secret.version().get().to_be_bytes());
    push_frame(hash, secret.purpose().as_str().as_bytes());
    push_frame(hash, &entry.credential_digest().as_bytes());
    push_frame(hash, b"default-model:none");
    push_frame(hash, &INITIAL_MAX_CONCURRENCY.to_be_bytes());
    push_frame(hash, &INITIAL_VERSION.to_be_bytes());
    push_frame(hash, INITIAL_STATUS.as_bytes());
}

fn push_optional_timestamp(hash: &mut Hmac<Sha256>, value: Option<AccountUtcTimestamp>) {
    match value {
        Some(value) => {
            push_frame(hash, b"some");
            push_frame(hash, &value.unix_seconds().to_be_bytes());
        }
        None => push_frame(hash, b"none"),
    }
}

fn push_optional_text(hash: &mut Hmac<Sha256>, value: Option<&str>) {
    match value {
        Some(value) => {
            push_frame(hash, b"some");
            push_frame(hash, value.as_bytes());
        }
        None => push_frame(hash, b"none"),
    }
}

fn push_frame(hash: &mut Hmac<Sha256>, value: &[u8]) {
    hash.update(&(value.len() as u64).to_be_bytes());
    hash.update(value);
}

const fn strategy_label(strategy: ConflictStrategy) -> &'static str {
    match strategy {
        ConflictStrategy::Reject => "reject",
        ConflictStrategy::SkipExisting => "skip-existing",
        ConflictStrategy::ReplaceExisting => "replace-existing",
    }
}

pub(super) fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

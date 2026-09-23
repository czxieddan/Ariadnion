// crates/optional/ariadnion-storage-rnmdb/src/account_proxy_repository/codec.rs - Durable proxy profile codec for Ariadnion.
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
//! Strict reconstruction and bounded serialization of metadata-only profiles.

use ariadnion_account_domain::{
    SecretPath, SecretProvider, SecretPurpose, SecretRef, SecretVersion,
};
use ariadnion_account_proxy::{
    AccountProxyProfile, ConnectivityPolicy, EgressEndpoint, MAX_REGION_BYTES, MAX_REGIONS,
    ProxyGeneration, ProxyProfileId, ProxyScheme, RegionConstraint,
};
use ariadnion_core::TenantId;
use ariadnion_storage_domain::StorageError;
use rnmdb_executor::vector::Row;
use rnmdb_types::SqlValue;
use zeroize::Zeroizing;

use super::sql::{self, integrity};

pub(super) const COLUMNS: &str = "tenant_id, profile_id, generation, scheme, host, port, auth_provider, auth_path, auth_version, auth_purpose, region_policy, connect_timeout_ms, request_timeout_ms, max_connections, max_redirects";
const MAX_REGION_POLICY_BYTES: usize = MAX_REGIONS * (MAX_REGION_BYTES + 1) + 6;

pub(super) fn decode(
    row: &Row,
    tenant: &TenantId,
    generation: ProxyGeneration,
) -> Result<AccountProxyProfile, StorageError> {
    let values: &[SqlValue; 15] = row.values().try_into().map_err(|_| integrity())?;
    require_identity(values, tenant, generation)?;
    decode_profile(values)
}

fn decode_profile(values: &[SqlValue; 15]) -> Result<AccountProxyProfile, StorageError> {
    let id = ProxyProfileId::parse(sql::text(&values[1])?).map_err(|_| integrity())?;
    let endpoint = decode_endpoint(&values[3..6])?;
    let authentication = decode_authentication(&values[6..10])?;
    let regions = decode_regions(sql::text(&values[10])?)?;
    let connectivity = decode_connectivity(&values[11..15])?;
    AccountProxyProfile::new(id, endpoint, authentication, regions, connectivity)
        .map_err(|_| integrity())
}

fn require_identity(
    values: &[SqlValue; 15],
    tenant: &TenantId,
    generation: ProxyGeneration,
) -> Result<(), StorageError> {
    sql::require_tenant(&values[0], tenant.as_str())?;
    if sql::version(&values[2])? != generation.get() {
        return Err(integrity());
    }
    Ok(())
}

fn decode_endpoint(values: &[SqlValue]) -> Result<EgressEndpoint, StorageError> {
    let scheme = sql::text(&values[0])?;
    if scheme == "direct" {
        sql::require_nulls(&values[1..])?;
        return Ok(EgressEndpoint::Direct);
    }
    decode_proxy_endpoint(scheme, &values[1], &values[2])
}

fn decode_proxy_endpoint(
    scheme: &str,
    host: &SqlValue,
    port: &SqlValue,
) -> Result<EgressEndpoint, StorageError> {
    let scheme = ProxyScheme::parse(scheme).map_err(|_| integrity())?;
    let port = u16::try_from(sql::integer(port)?).map_err(|_| integrity())?;
    EgressEndpoint::proxy(scheme, sql::text(host)?, port).map_err(|_| integrity())
}

fn decode_authentication(values: &[SqlValue]) -> Result<Option<SecretRef>, StorageError> {
    if matches!(values[0], SqlValue::Null) {
        sql::require_nulls(values)?;
        return Ok(None);
    }
    decode_secret_reference(values).map(Some)
}

fn decode_secret_reference(values: &[SqlValue]) -> Result<SecretRef, StorageError> {
    let provider = SecretProvider::parse(sql::text(&values[0])?).map_err(|_| integrity())?;
    let path = decode_secret_path(&values[1])?;
    let version = SecretVersion::new(sql::version(&values[2])?).map_err(|_| integrity())?;
    let purpose = SecretPurpose::parse(sql::text(&values[3])?).map_err(|_| integrity())?;
    Ok(SecretRef::new(provider, path, version, purpose))
}

fn decode_secret_path(value: &SqlValue) -> Result<SecretPath, StorageError> {
    SecretPath::parse(sql::text(value)?).map_err(|_| integrity())
}

fn decode_connectivity(values: &[SqlValue]) -> Result<ConnectivityPolicy, StorageError> {
    let connect = decode_number(&values[0])?;
    let request = decode_number(&values[1])?;
    let connections = decode_number(&values[2])?;
    let redirects = decode_number(&values[3])?;
    ConnectivityPolicy::new(connect, request, connections, redirects).map_err(|_| integrity())
}

fn decode_number<T: TryFrom<i64>>(value: &SqlValue) -> Result<T, StorageError> {
    T::try_from(sql::integer(value)?).map_err(|_| integrity())
}

fn decode_regions(value: &str) -> Result<RegionConstraint, StorageError> {
    if value.len() > MAX_REGION_POLICY_BYTES {
        return Err(integrity());
    }
    decode_region_policy(value)
}

fn decode_region_policy(value: &str) -> Result<RegionConstraint, StorageError> {
    match value.split_once(':') {
        None if value == "any" => Ok(RegionConstraint::Any),
        Some(("allow", list)) => {
            RegionConstraint::allowlist(bounded_regions(list)?).map_err(|_| integrity())
        }
        Some(("deny", list)) => {
            RegionConstraint::denylist(bounded_regions(list)?).map_err(|_| integrity())
        }
        _ => Err(integrity()),
    }
}

fn bounded_regions(list: &str) -> Result<Vec<&str>, StorageError> {
    let values: Vec<_> = list.split(',').take(MAX_REGIONS + 1).collect();
    if values.len() > MAX_REGIONS {
        return Err(integrity());
    }
    Ok(values)
}

pub(super) fn insert(
    tenant: &TenantId,
    generation: ProxyGeneration,
    profile: &AccountProxyProfile,
) -> Result<Zeroizing<String>, StorageError> {
    let endpoint = encode_endpoint(profile.endpoint())?;
    let authentication = encode_authentication(profile.authentication());
    let regions = encode_regions(profile.regions())?;
    let connectivity = profile.connectivity();
    Ok(Zeroizing::new(format!(
        "INSERT INTO account_proxy_profiles ({COLUMNS}) VALUES ({}, {}, '{}', {endpoint}, {}, {}, {}, {}, {}, {});",
        sql::quote(tenant.as_str()).as_str(),
        sql::quote(profile.id().as_str()).as_str(),
        generation.get(),
        authentication.as_str(),
        sql::quote(&regions).as_str(),
        connectivity.connect_timeout_ms(),
        connectivity.request_timeout_ms(),
        connectivity.max_connections(),
        connectivity.max_redirects(),
    )))
}

fn encode_endpoint(endpoint: &EgressEndpoint) -> Result<String, StorageError> {
    match endpoint {
        EgressEndpoint::Direct => Ok("'direct', NULL, NULL".to_owned()),
        EgressEndpoint::Proxy { scheme, host, port } => {
            EgressEndpoint::proxy(*scheme, host, port.get()).map_err(|_| integrity())?;
            Ok(format!(
                "'{}', {}, {}",
                scheme_label(*scheme),
                sql::quote(host).as_str(),
                port,
            ))
        }
    }
}

fn scheme_label(scheme: ProxyScheme) -> &'static str {
    match scheme {
        ProxyScheme::Http => "http",
        ProxyScheme::Https => "https",
        ProxyScheme::Socks5 => "socks5",
    }
}

fn encode_authentication(reference: Option<&SecretRef>) -> Zeroizing<String> {
    match reference {
        None => Zeroizing::new("NULL, NULL, NULL, NULL".to_owned()),
        Some(reference) => Zeroizing::new(format!(
            "{}, {}, '{}', {}",
            sql::quote(reference.provider().as_str()).as_str(),
            sql::quote(reference.path().as_str()).as_str(),
            reference.version().get(),
            sql::quote(reference.purpose().as_str()).as_str(),
        )),
    }
}

fn encode_regions(regions: &RegionConstraint) -> Result<String, StorageError> {
    match regions {
        RegionConstraint::Any => Ok("any".to_owned()),
        RegionConstraint::Allowlist(values) => encode_region_list("allow", values),
        RegionConstraint::Denylist(values) => encode_region_list("deny", values),
    }
}

fn encode_region_list(prefix: &str, values: &[Box<str>]) -> Result<String, StorageError> {
    // Public enum variants can bypass the domain constructors.
    if values.len() > MAX_REGIONS {
        return Err(integrity());
    }
    if values.iter().any(|value| value.len() > MAX_REGION_BYTES) {
        return Err(integrity());
    }
    let encoded = format!("{prefix}:{}", values.join(","));
    let decoded = decode_regions(&encoded)?;
    require_canonical_regions(&decoded, values)?;
    Ok(encoded)
}

fn require_canonical_regions(
    decoded: &RegionConstraint,
    expected: &[Box<str>],
) -> Result<(), StorageError> {
    let actual = match decoded {
        RegionConstraint::Allowlist(values) | RegionConstraint::Denylist(values) => values,
        RegionConstraint::Any => return Err(integrity()),
    };
    if actual.as_ref() != expected {
        return Err(integrity());
    }
    Ok(())
}

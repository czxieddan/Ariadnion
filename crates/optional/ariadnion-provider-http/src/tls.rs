// crates/optional/ariadnion-provider-http/src/tls.rs - Verified provider TLS policy for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0

//! Explicit TLS policy and peer verification for provider connections.

use std::sync::Arc;

use ariadnion_core::OutboundHost;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, NoKeyLog, ProtocolVersion, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::config::ProviderHttpTrust;
use crate::error::{ProviderHttpError, ProviderHttpErrorCode};

/// The verified TLS protocol negotiated for one provider connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderTlsVersion {
    /// TLS 1.3.
    Tls13,
    /// TLS 1.2 compatibility using rustls safe cipher suites.
    Tls12,
}

pub(crate) async fn connect(
    stream: TcpStream,
    host: &OutboundHost,
    trust: ProviderHttpTrust,
) -> Result<(TlsStream<TcpStream>, ProviderTlsVersion), ProviderHttpError> {
    let server_name = ServerName::try_from(host.as_str().to_owned()).map_err(tls_failure)?;
    let connector = TlsConnector::from(build_client_config(trust)?);
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(tls_failure)?;
    let version = negotiated_version(&stream)?;
    Ok((stream, version))
}

fn build_client_config(trust: ProviderHttpTrust) -> Result<Arc<ClientConfig>, ProviderHttpError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(tls_failure)?;
    let mut config = builder
        .with_root_certificates(root_store(&trust)?)
        .with_no_client_auth();
    config.enable_sni = true;
    config.enable_early_data = false;
    config.enable_secret_extraction = false;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.key_log = Arc::new(NoKeyLog);
    Ok(Arc::new(config))
}

fn root_store(trust: &ProviderHttpTrust) -> Result<RootCertStore, ProviderHttpError> {
    let Some(roots) = trust.explicit_roots() else {
        return Ok(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
    };
    let mut store = RootCertStore::empty();
    for root in roots {
        store
            .add(CertificateDer::from(root.as_ref()))
            .map_err(tls_failure)?;
    }
    Ok(store)
}

fn negotiated_version(
    stream: &TlsStream<TcpStream>,
) -> Result<ProviderTlsVersion, ProviderHttpError> {
    match stream.get_ref().1.protocol_version() {
        Some(ProtocolVersion::TLSv1_3) => Ok(ProviderTlsVersion::Tls13),
        Some(ProtocolVersion::TLSv1_2) => Ok(ProviderTlsVersion::Tls12),
        _ => Err(tls_failure(())),
    }
}

fn tls_failure<T>(_source: T) -> ProviderHttpError {
    ProviderHttpError::new(ProviderHttpErrorCode::TlsHandshakeFailed)
}

// crates/optional/ariadnion-provider-http/src/lib.rs - Provider HTTP transport for Ariadnion.
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
//
//! Provider-neutral bounded HTTPS transport contracts and implementation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod connector;
mod dns;
mod egress;
mod endpoint;
mod error;
mod exchange;
mod proxy;
mod request;
mod response;
mod timeout;
mod tls;

pub use config::{
    MAX_PROVIDER_HTTP_EXPLICIT_ROOTS, MAX_PROVIDER_HTTP_HEADER_NAME_BYTES,
    MAX_PROVIDER_HTTP_HEADER_VALUE_BYTES, MAX_PROVIDER_HTTP_PATH_AND_QUERY_BYTES,
    MAX_PROVIDER_HTTP_ROOT_DER_BYTES, ProviderHttpHeader, ProviderHttpLimits, ProviderHttpMethod,
    ProviderHttpPool, ProviderHttpProfile, ProviderHttpProfileBuilder, ProviderHttpProxy,
    ProviderHttpTimeouts, ProviderHttpTrust,
};
pub use connector::{
    ProviderHttpConnectedSocket, ProviderHttpDialError, ProviderHttpDialFuture,
    ProviderHttpDirectConnection, ProviderHttpDirectConnector, ProviderHttpNumericDialer,
    ProviderHttpPreparedConnection, TokioNumericDialer,
};
pub use dns::{
    AddressClass, BoundedResolver, ResolutionEpoch, ResolutionRecord, ResolvedAddresses,
    TokioSystemResolver, classify_address, resolve_bounded,
};
pub use egress::{EgressError, wait_for};
pub use endpoint::ProviderHttpEndpoint;
pub use error::{
    ProviderHttpError, ProviderHttpErrorCode, ProviderHttpPhase, ProviderHttpProfileError,
    ProviderHttpProfileErrorCode,
};
pub use exchange::ProviderHttpExchange;
pub use request::ProviderHttpRequest;
pub use response::{ProviderHttpResponse, ProviderHttpReusableConnection};
pub use timeout::bounded_timeout;
pub use tls::ProviderTlsVersion;

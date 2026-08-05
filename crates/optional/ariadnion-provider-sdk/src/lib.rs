// crates/optional/ariadnion-provider-sdk/src/lib.rs - Provider SDK contracts for Ariadnion.
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
//! Runtime-neutral provider capability and execution contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod attempt;
mod contract;
mod error;

pub use attempt::{
    AttemptProgressError, AttemptProgressErrorCode, ProviderAttempt, ProviderAttemptEvidence,
    ProviderAttemptProgress, ProviderTransmission,
};
pub use contract::{
    MAX_PROVIDER_DELTA_BYTES, MAX_PROVIDER_REQUEST_BYTES, MAX_PROVIDER_STREAM_BYTES,
    MAX_PROVIDER_STREAM_EVENTS, ProviderCapabilities, ProviderCapability, ProviderContractError,
    ProviderContractErrorCode, ProviderDescriptor, ProviderId, ProviderLimits, ProviderModelId,
};
pub use error::{
    MAX_PROVIDER_RETRY_AFTER, ProviderFailure, ProviderFailureClass, ProviderRetryAdvice,
};

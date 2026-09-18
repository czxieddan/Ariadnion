// crates/optional/ariadnion-routing-runtime/src/error_code.rs - Stable runtime error codes.
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

use crate::RoutingRuntimeErrorCode;

impl RoutingRuntimeErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        if let Some(code) = request_error_code(self) {
            return code;
        }
        if let Some(code) = state_error_code(self) {
            return code;
        }
        if let Some(code) = adapter_error_code(self) {
            return code;
        }
        execution_error_code(self)
    }
}

const fn request_error_code(code: RoutingRuntimeErrorCode) -> Option<&'static str> {
    match code {
        RoutingRuntimeErrorCode::InvalidArgument => Some("ROUTING_RUNTIME_INVALID_ARGUMENT"),
        RoutingRuntimeErrorCode::DuplicateAttempt => Some("ROUTING_RUNTIME_DUPLICATE_ATTEMPT"),
        RoutingRuntimeErrorCode::Unauthenticated => Some("ROUTING_RUNTIME_UNAUTHENTICATED"),
        RoutingRuntimeErrorCode::TenantMismatch => Some("ROUTING_RUNTIME_TENANT_MISMATCH"),
        RoutingRuntimeErrorCode::Cancelled => Some("ROUTING_RUNTIME_CANCELLED"),
        RoutingRuntimeErrorCode::DeadlineExceeded => Some("ROUTING_RUNTIME_DEADLINE_EXCEEDED"),
        _ => None,
    }
}

const fn state_error_code(code: RoutingRuntimeErrorCode) -> Option<&'static str> {
    match code {
        RoutingRuntimeErrorCode::ProjectionUnavailable => {
            Some("ROUTING_RUNTIME_PROJECTION_UNAVAILABLE")
        }
        RoutingRuntimeErrorCode::PoolUnavailable => Some("ROUTING_RUNTIME_POOL_UNAVAILABLE"),
        RoutingRuntimeErrorCode::ModelUnavailable => Some("ROUTING_RUNTIME_MODEL_UNAVAILABLE"),
        RoutingRuntimeErrorCode::MonotonicClockUnavailable => {
            Some("ROUTING_RUNTIME_MONOTONIC_CLOCK_UNAVAILABLE")
        }
        RoutingRuntimeErrorCode::CoordinationFailed => Some("ROUTING_RUNTIME_COORDINATION_FAILED"),
        _ => None,
    }
}

const fn adapter_error_code(code: RoutingRuntimeErrorCode) -> Option<&'static str> {
    match code {
        RoutingRuntimeErrorCode::CredentialUnavailable => {
            Some("ROUTING_RUNTIME_CREDENTIAL_UNAVAILABLE")
        }
        RoutingRuntimeErrorCode::CredentialMismatch => Some("ROUTING_RUNTIME_CREDENTIAL_MISMATCH"),
        RoutingRuntimeErrorCode::VaultUnavailable => Some("ROUTING_RUNTIME_VAULT_UNAVAILABLE"),
        _ => None,
    }
}

const fn execution_error_code(code: RoutingRuntimeErrorCode) -> &'static str {
    match code {
        RoutingRuntimeErrorCode::InvalidLease => "ROUTING_RUNTIME_INVALID_LEASE",
        RoutingRuntimeErrorCode::InvalidExecutionOutcome => {
            "ROUTING_RUNTIME_INVALID_EXECUTION_OUTCOME"
        }
        RoutingRuntimeErrorCode::AdmissionFinalizeFailed => {
            "ROUTING_RUNTIME_ADMISSION_FINALIZE_FAILED"
        }
        RoutingRuntimeErrorCode::AttemptsExhausted => "ROUTING_RUNTIME_ATTEMPTS_EXHAUSTED",
        RoutingRuntimeErrorCode::InvariantViolation => "ROUTING_RUNTIME_INVARIANT_VIOLATION",
        _ => "ROUTING_RUNTIME_INVARIANT_VIOLATION",
    }
}

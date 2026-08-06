// crates/optional/ariadnion-provider-http/src/timeout.rs - Provider timeout helpers for Ariadnion.
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

use std::time::{Duration, SystemTime};

use ariadnion_core::RequestContext;

use crate::egress::EgressError;

/// Returns the smaller phase budget and request deadline remainder.
pub fn bounded_timeout(
    context: &RequestContext,
    phase: Duration,
    now: SystemTime,
) -> Result<Duration, EgressError> {
    context.check_active_at(now).map_err(|error| {
        if error.code() == ariadnion_core::ErrorCode::Cancelled {
            EgressError::Cancelled
        } else {
            EgressError::DeadlineExceeded
        }
    })?;
    let remainder = context
        .deadline()
        .and_then(|deadline| deadline.duration_since(now).ok());
    Ok(remainder.map_or(phase, |value| phase.min(value)))
}

// crates/optional/ariadnion-organization/src/model/transfer_validation.rs - Rust source for Ariadnion.
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
//! Validation of short-lived ownership-transfer evidence.

use crate::error::{OrganizationError, OrganizationErrorCode, error};

use super::OwnershipTransferEvidenceInput;

const MAX_TRANSFER_LIFETIME_SECONDS: i64 = 900;

pub(super) fn validate_transfer_evidence_input(
    input: &OwnershipTransferEvidenceInput,
) -> Result<(), OrganizationError> {
    validate_transfer_principals(input)?;
    if input.initiating_owner_id == input.recipient_id {
        return Err(error(OrganizationErrorCode::TransferEvidenceInvalid));
    }
    let reauthentication = input
        .recipient_reauthentication
        .authenticated_at()
        .unix_seconds();
    let not_before = input.not_before.unix_seconds();
    let expires_at = input.expires_at.unix_seconds();
    let delay = not_before.checked_sub(reauthentication);
    let lifetime = expires_at.checked_sub(not_before);
    if delay.is_none_or(|seconds| seconds <= 0) || !valid_transfer_lifetime(lifetime) {
        return Err(error(OrganizationErrorCode::TransferEvidenceInvalid));
    }
    Ok(())
}

fn validate_transfer_principals(
    input: &OwnershipTransferEvidenceInput,
) -> Result<(), OrganizationError> {
    let initiator_tenant_matches =
        input.initiating_user.principal().tenant_id() == &input.tenant_id;
    let recipient_tenant_matches = input
        .recipient_reauthentication
        .authenticated_user()
        .principal()
        .tenant_id()
        == &input.tenant_id;
    let approver_tenant_matches = input.approving_principal.tenant_id() == &input.tenant_id;
    if !initiator_tenant_matches || !recipient_tenant_matches || !approver_tenant_matches {
        return Err(error(OrganizationErrorCode::TransferOrganizationMismatch));
    }
    if input.initiating_user.principal().principal_id() == input.approving_principal.principal_id()
    {
        return Err(error(OrganizationErrorCode::TransferApproverConflict));
    }
    Ok(())
}

fn valid_transfer_lifetime(lifetime: Option<i64>) -> bool {
    lifetime.is_some_and(|seconds| seconds > 0 && seconds <= MAX_TRANSFER_LIFETIME_SECONDS)
}

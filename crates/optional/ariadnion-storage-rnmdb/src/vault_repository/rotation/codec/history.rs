// crates/optional/ariadnion-storage-rnmdb/src/vault_repository/rotation/codec/history.rs - Rotation receipt history validation.
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
//! Reachability validation for durable rotation mutation receipts.

use ariadnion_account_vault::{
    RotationMutationReceipt, RotationPhase, RotationRevision, RotationSnapshot,
};

const PREPARED_HISTORY: &[RotationPhase] = &[RotationPhase::Prepared];
const STORED_HISTORY: &[RotationPhase] =
    &[RotationPhase::Prepared, RotationPhase::NewVersionStored];
const ACTIVE_HISTORY: &[RotationPhase] = &[
    RotationPhase::Prepared,
    RotationPhase::NewVersionStored,
    RotationPhase::Active,
];
const COMPLETED_HISTORY: &[RotationPhase] = &[
    RotationPhase::Prepared,
    RotationPhase::NewVersionStored,
    RotationPhase::Active,
    RotationPhase::Completed,
];
const STORED_COMPENSATION_HISTORY: &[RotationPhase] = &[
    RotationPhase::Prepared,
    RotationPhase::NewVersionStored,
    RotationPhase::Compensating,
];
const ACTIVE_COMPENSATION_HISTORY: &[RotationPhase] = &[
    RotationPhase::Prepared,
    RotationPhase::NewVersionStored,
    RotationPhase::Active,
    RotationPhase::Compensating,
];
const STORED_FAILURE_HISTORY: &[RotationPhase] = &[
    RotationPhase::Prepared,
    RotationPhase::NewVersionStored,
    RotationPhase::Compensating,
    RotationPhase::Failed,
];
const ACTIVE_FAILURE_HISTORY: &[RotationPhase] = &[
    RotationPhase::Prepared,
    RotationPhase::NewVersionStored,
    RotationPhase::Active,
    RotationPhase::Compensating,
    RotationPhase::Failed,
];

pub(super) fn receipt_matches_snapshot(
    snapshot: &RotationSnapshot,
    receipt: &RotationMutationReceipt,
) -> bool {
    let Some(index) = receipt
        .revision()
        .get()
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    history_for_snapshot(snapshot)
        .and_then(|history| history.get(index))
        .is_some_and(|phase| *phase == receipt.phase())
        && receipt_time_matches_snapshot(snapshot, receipt)
}

fn receipt_time_matches_snapshot(
    snapshot: &RotationSnapshot,
    receipt: &RotationMutationReceipt,
) -> bool {
    match receipt.revision().cmp(&snapshot.revision()) {
        std::cmp::Ordering::Less => receipt.committed_at() <= snapshot.updated_at(),
        std::cmp::Ordering::Equal => receipt.committed_at() == snapshot.updated_at(),
        std::cmp::Ordering::Greater => false,
    }
}

fn history_for_snapshot(snapshot: &RotationSnapshot) -> Option<&'static [RotationPhase]> {
    match snapshot.journal().phase() {
        RotationPhase::Prepared => Some(PREPARED_HISTORY),
        RotationPhase::NewVersionStored => Some(STORED_HISTORY),
        RotationPhase::Active => Some(ACTIVE_HISTORY),
        RotationPhase::Completed => Some(COMPLETED_HISTORY),
        RotationPhase::Compensating => compensating_history(snapshot.revision()),
        RotationPhase::Failed => failed_history(snapshot.revision()),
    }
}

fn compensating_history(revision: RotationRevision) -> Option<&'static [RotationPhase]> {
    match revision.get() {
        3 => Some(STORED_COMPENSATION_HISTORY),
        4 => Some(ACTIVE_COMPENSATION_HISTORY),
        _ => None,
    }
}

fn failed_history(revision: RotationRevision) -> Option<&'static [RotationPhase]> {
    match revision.get() {
        4 => Some(STORED_FAILURE_HISTORY),
        5 => Some(ACTIVE_FAILURE_HISTORY),
        _ => None,
    }
}

// crates/optional/ariadnion-account-budget/src/reservation.rs - Atomic budget reservation creation for Ariadnion.
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

use crate::{
    BudgetBook, BudgetError, BudgetErrorCode, BudgetState, ReservationReceipt, ReservationRecord,
    ReservationRequest, ReservationState, UnixTimeSeconds, applicable_policy_ids, error,
    expire_records, replay_reservation, reserve_capacity, validate_capacity,
    validate_new_reservation,
};

impl BudgetBook {
    /// Atomically reserves all applicable hierarchy budgets.
    ///
    /// Replaying byte-equivalent typed input with the same active reservation
    /// identity returns the original receipt without charging twice. Reusing the
    /// identity for different input fails closed. Independent execution leases
    /// must use [`Self::reserve_fresh`] instead of treating replay as new ownership.
    ///
    /// # Errors
    /// Returns a stable failure for expired input, replay conflicts, missing
    /// policies, hard-limit crossings, arithmetic overflow, capacity exhaustion,
    /// or poisoned state.
    pub fn reserve(
        &self,
        request: ReservationRequest,
        now: UnixTimeSeconds,
    ) -> Result<ReservationReceipt, BudgetError> {
        let mut state = self.lock_state()?;
        expire_records(&mut state, now)?;
        if let Some(record) = state.reservations.get(request.id()) {
            return replay_reservation(record, &request);
        }
        insert_reservation(&mut state, request, now)
    }

    /// Atomically reserves capacity only for a previously unseen identity.
    ///
    /// Use this operation when success grants a new execution lease. Every
    /// retained identity is rejected, including reserved, committed, released,
    /// and expired records. A duplicate failure leaves the ledger unchanged;
    /// it does not expire, refund, or otherwise finalize the original record.
    /// The identity check, capacity validation, and insertion share one ledger
    /// lock, including across independently constructed consumers of this book.
    ///
    /// This synchronous operation performs no I/O and has no cancellation point.
    /// It preserves [`Self::reserve`]'s replay-compatible behavior for callers
    /// that already own the reservation lifecycle.
    ///
    /// # Errors
    /// Returns [`BudgetErrorCode::ReplayConflict`] for any previously used
    /// identity, regardless of its state or payload. New identities receive the
    /// same validation, capacity, arithmetic, and state errors as [`Self::reserve`].
    pub fn reserve_fresh(
        &self,
        request: ReservationRequest,
        now: UnixTimeSeconds,
    ) -> Result<ReservationReceipt, BudgetError> {
        let mut state = self.lock_state()?;
        if state.reservations.contains_key(request.id()) {
            return Err(error(BudgetErrorCode::ReplayConflict));
        }
        expire_records(&mut state, now)?;
        insert_reservation(&mut state, request, now)
    }
}

// Both callers hold the ledger lock and have established that the ID is absent.
fn insert_reservation(
    state: &mut BudgetState,
    request: ReservationRequest,
    now: UnixTimeSeconds,
) -> Result<ReservationReceipt, BudgetError> {
    validate_new_reservation(state, &request, now)?;
    let policy_ids = applicable_policy_ids(state, &request)?;
    let soft_breaches = validate_capacity(state, &policy_ids, request.amount())?;
    reserve_capacity(state, &policy_ids, request.amount().minor_units())?;
    let record = ReservationRecord {
        request,
        state: ReservationState::Reserved,
        applied_policies: policy_ids.into_boxed_slice(),
        soft_limit_breaches: soft_breaches.into_boxed_slice(),
    };
    let receipt = record.receipt();
    state.reservations.insert(receipt.id.clone(), record);
    Ok(receipt)
}

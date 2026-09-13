// crates/optional/ariadnion-account-vault/src/rotation.rs - Credential rotation state machine.
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
//! Generation-safe credential rotation sequencing.
//!
//! The state machine coordinates durable receipts around an external vault
//! adapter. It never accepts or stores plaintext. A successful rotation writes
//! and verifies the new version, activates it for a bounded overlap window,
//! then revokes the previous version. Failures expose only a typed compensation
//! request for the new version.

use std::fmt::{self, Debug, Formatter};
use std::time::{Duration, SystemTime};

use ariadnion_account_domain::{AccountId, SecretRef};

use crate::{
    SecretRevokeReceipt, SecretStoreReceipt, VaultError, VaultErrorCode, VaultRevokeReason,
    VaultRevokeRequest,
};

/// Maximum overlap allowed between active credential versions.
pub const MAX_ROTATION_OVERLAP: Duration = Duration::from_secs(86_400);
/// Maximum byte length of a rotation operation identifier.
pub const MAX_ROTATION_ID_BYTES: usize = 128;

/// Bounded overlap interval used during a credential rotation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RotationWindow(Duration);

impl RotationWindow {
    /// Validates a positive overlap interval no longer than one day.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::InvalidArgument`] for zero and
    /// [`VaultErrorCode::LimitExceeded`] above [`MAX_ROTATION_OVERLAP`].
    pub fn new(value: Duration) -> Result<Self, VaultError> {
        if value.is_zero() {
            return Err(VaultError::new(VaultErrorCode::InvalidArgument));
        }
        if value > MAX_ROTATION_OVERLAP {
            return Err(VaultError::new(VaultErrorCode::LimitExceeded));
        }
        Ok(Self(value))
    }

    /// Returns the bounded overlap duration.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// Immutable plan binding the old and new secret versions for one account.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialRotationPlan {
    account_id: AccountId,
    rotation_id: Box<str>,
    previous: SecretRef,
    next: SecretRef,
    overlap: RotationWindow,
}

impl CredentialRotationPlan {
    /// Creates a rotation plan for two versions of the same secret locator.
    ///
    /// The next version must be greater than the previous version. Provider,
    /// path, and purpose must remain unchanged so a rotation cannot silently
    /// switch tenants or secret classes.
    ///
    /// # Errors
    /// Returns a redacted [`VaultErrorCode::InvalidArgument`] for malformed
    /// operation identifiers, a [`VaultErrorCode::Conflict`] for mismatched
    /// locators or non-advancing versions, and the window validation error.
    pub fn new(
        account_id: AccountId,
        rotation_id: &str,
        previous: SecretRef,
        next: SecretRef,
        overlap: RotationWindow,
    ) -> Result<Self, VaultError> {
        if !valid_rotation_id(rotation_id) {
            return Err(VaultError::new(VaultErrorCode::InvalidArgument));
        }
        if !same_locator(&previous, &next) || next.version() <= previous.version() {
            return Err(VaultError::new(VaultErrorCode::Conflict));
        }
        Ok(Self {
            account_id,
            rotation_id: rotation_id.into(),
            previous,
            next,
            overlap,
        })
    }

    /// Returns the account bound to this rotation.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the operation identifier.
    #[must_use]
    pub fn rotation_id(&self) -> &str {
        &self.rotation_id
    }

    /// Returns the previous active secret reference.
    #[must_use]
    pub const fn previous(&self) -> &SecretRef {
        &self.previous
    }

    /// Returns the new secret reference.
    #[must_use]
    pub const fn next(&self) -> &SecretRef {
        &self.next
    }

    /// Returns the configured overlap window.
    #[must_use]
    pub const fn overlap(&self) -> RotationWindow {
        self.overlap
    }
}

impl Debug for CredentialRotationPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRotationPlan")
            .field("account_id", &"<redacted>")
            .field("rotation_id", &"<redacted>")
            .field("previous", &self.previous)
            .field("next", &self.next)
            .field("overlap", &self.overlap)
            .finish()
    }
}

/// Durable phase of one credential rotation operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RotationPhase {
    /// The plan exists but the new version has not been durably stored.
    Prepared,
    /// The new version has a durable store receipt.
    NewVersionStored,
    /// The new version is active and the old version remains in the overlap window.
    Active,
    /// The old version was revoked after the overlap window.
    Completed,
    /// A failure requires revoking the new version as compensation.
    Compensating,
    /// Compensation completed and the rotation did not activate.
    Failed,
}

/// In-memory journal of durable rotation receipts and state transitions.
#[derive(Clone, Eq, PartialEq)]
pub struct RotationJournal {
    plan: CredentialRotationPlan,
    phase: RotationPhase,
    new_receipt: Option<SecretStoreReceipt>,
    activated_at: Option<SystemTime>,
    overlap_expires_at: Option<SystemTime>,
    old_revoke_receipt: Option<SecretRevokeReceipt>,
    compensation_receipt: Option<SecretRevokeReceipt>,
}

impl RotationJournal {
    /// Creates a journal in the prepared phase.
    #[must_use]
    pub fn new(plan: CredentialRotationPlan) -> Self {
        Self {
            plan,
            phase: RotationPhase::Prepared,
            new_receipt: None,
            activated_at: None,
            overlap_expires_at: None,
            old_revoke_receipt: None,
            compensation_receipt: None,
        }
    }

    /// Returns the immutable rotation plan.
    #[must_use]
    pub const fn plan(&self) -> &CredentialRotationPlan {
        &self.plan
    }

    /// Returns the current durable phase.
    #[must_use]
    pub const fn phase(&self) -> RotationPhase {
        self.phase
    }

    /// Returns the new-version store receipt, when durable storage succeeded.
    #[must_use]
    pub fn new_receipt(&self) -> Option<SecretStoreReceipt> {
        self.new_receipt.clone()
    }

    /// Returns the activation time, when the new version became active.
    #[must_use]
    pub const fn activated_at(&self) -> Option<SystemTime> {
        self.activated_at
    }

    /// Returns when the old version may be revoked.
    #[must_use]
    pub const fn overlap_expires_at(&self) -> Option<SystemTime> {
        self.overlap_expires_at
    }

    /// Records a durable store receipt for exactly the planned new version.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::Conflict`] when the phase, locator, version, or
    /// receipt time does not match the plan or observed time.
    pub fn record_new_version(
        &mut self,
        receipt: SecretStoreReceipt,
        now: SystemTime,
    ) -> Result<(), VaultError> {
        ensure_phase(self.phase, RotationPhase::Prepared)?;
        if receipt.reference() != self.plan.next()
            || receipt.version() != self.plan.next().version()
            || receipt.committed_at() > now
        {
            return Err(VaultError::new(VaultErrorCode::Conflict));
        }
        self.new_receipt = Some(receipt);
        self.phase = RotationPhase::NewVersionStored;
        Ok(())
    }

    /// Activates the new version and starts the bounded overlap window.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::Conflict`] when the new version was not stored
    /// and [`VaultErrorCode::InvalidArgument`] if the system time cannot
    /// represent the overlap expiry.
    pub fn activate(&mut self, activated_at: SystemTime) -> Result<(), VaultError> {
        ensure_phase(self.phase, RotationPhase::NewVersionStored)?;
        let committed_at = self
            .new_receipt
            .as_ref()
            .map(SecretStoreReceipt::committed_at)
            .ok_or_else(|| VaultError::new(VaultErrorCode::Conflict))?;
        if activated_at < committed_at {
            return Err(VaultError::new(VaultErrorCode::Conflict));
        }
        let overlap_expires_at = activated_at
            .checked_add(self.plan.overlap().duration())
            .ok_or_else(|| VaultError::new(VaultErrorCode::InvalidArgument))?;
        self.activated_at = Some(activated_at);
        self.overlap_expires_at = Some(overlap_expires_at);
        self.phase = RotationPhase::Active;
        Ok(())
    }

    /// Records revocation of the previous version after the overlap expires.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::Conflict`] for an early call, a mismatched
    /// receipt, or a receipt committed before the overlap expires.
    pub fn revoke_previous(
        &mut self,
        receipt: SecretRevokeReceipt,
        now: SystemTime,
    ) -> Result<(), VaultError> {
        ensure_phase(self.phase, RotationPhase::Active)?;
        let overlap_expires_at = self
            .overlap_expires_at
            .ok_or_else(|| VaultError::new(VaultErrorCode::Conflict))?;
        validate_previous_revoke(&self.plan, &receipt, now, overlap_expires_at)?;
        self.old_revoke_receipt = Some(receipt);
        self.phase = RotationPhase::Completed;
        Ok(())
    }

    /// Starts failure compensation by requesting revocation of the new version.
    ///
    /// Prepared, completed, failed, and already-compensating journals return
    /// `Ok(None)` because no new version needs another revoke request.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::Conflict`] only if the journal invariants are
    /// inconsistent with the active phase.
    pub fn begin_compensation(&mut self) -> Result<Option<VaultRevokeRequest>, VaultError> {
        match self.phase {
            RotationPhase::NewVersionStored | RotationPhase::Active => {
                self.phase = RotationPhase::Compensating;
                Ok(Some(VaultRevokeRequest::new(
                    self.plan.next().clone(),
                    VaultRevokeReason::RotationFailure,
                )))
            }
            RotationPhase::Prepared
            | RotationPhase::Completed
            | RotationPhase::Compensating
            | RotationPhase::Failed => Ok(None),
        }
    }

    /// Records durable compensation of the new version and marks the rotation failed.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::Conflict`] for an invalid phase, locator,
    /// version, or future receipt time.
    pub fn record_compensation(
        &mut self,
        receipt: SecretRevokeReceipt,
        now: SystemTime,
    ) -> Result<(), VaultError> {
        ensure_phase(self.phase, RotationPhase::Compensating)?;
        if receipt.reference() != self.plan.next()
            || receipt.version() != self.plan.next().version()
            || receipt.committed_at() > now
        {
            return Err(VaultError::new(VaultErrorCode::Conflict));
        }
        self.compensation_receipt = Some(receipt);
        self.phase = RotationPhase::Failed;
        Ok(())
    }
}

impl Debug for RotationJournal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationJournal")
            .field("plan", &self.plan)
            .field("phase", &self.phase)
            .field("new_receipt", &self.new_receipt)
            .field("activated_at", &self.activated_at)
            .field("overlap_expires_at", &self.overlap_expires_at)
            .field("old_revoke_receipt", &self.old_revoke_receipt)
            .field("compensation_receipt", &self.compensation_receipt)
            .finish()
    }
}

fn ensure_phase(actual: RotationPhase, expected: RotationPhase) -> Result<(), VaultError> {
    if actual != expected {
        return Err(VaultError::new(VaultErrorCode::Conflict));
    }
    Ok(())
}

fn validate_previous_revoke(
    plan: &CredentialRotationPlan,
    receipt: &SecretRevokeReceipt,
    now: SystemTime,
    overlap_expires_at: SystemTime,
) -> Result<(), VaultError> {
    if now < overlap_expires_at
        || receipt.reference() != plan.previous()
        || receipt.version() != plan.previous().version()
        || receipt.committed_at() < overlap_expires_at
        || receipt.committed_at() > now
    {
        return Err(VaultError::new(VaultErrorCode::Conflict));
    }
    Ok(())
}

fn same_locator(previous: &SecretRef, next: &SecretRef) -> bool {
    previous.provider() == next.provider()
        && previous.path() == next.path()
        && previous.purpose() == next.purpose()
}

fn valid_rotation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ROTATION_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

// crates/optional/ariadnion-account-vault/src/rotation_port.rs - Durable rotation port contracts.
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
//! Authenticated durable persistence contracts for credential rotation.

use std::fmt::{self, Debug, Formatter};
use std::time::SystemTime;

use ariadnion_core::RequestContext;

use crate::{
    BoxVaultFuture, CredentialRotationPlan, MAX_ROTATION_ID_BYTES, RotationJournal, RotationPhase,
    SecretRevokeReceipt, SecretStoreReceipt, VaultError, VaultErrorCode,
};

/// Maximum byte length of a caller-stable rotation mutation identifier.
pub const MAX_ROTATION_MUTATION_ID_BYTES: usize = 128;

/// Caller-stable identity used for exact mutation replay and reconciliation.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RotationMutationId(Box<str>);

impl RotationMutationId {
    /// Parses a bounded printable ASCII mutation identity.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::InvalidArgument`] when the value is empty,
    /// non-ASCII, contains whitespace or control bytes, or exceeds the bound.
    pub fn parse(value: &str) -> Result<Self, VaultError> {
        if !valid_identity(value, MAX_ROTATION_MUTATION_ID_BYTES) {
            return Err(VaultError::new(VaultErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated mutation identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RotationMutationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RotationMutationId(<redacted>)")
    }
}

/// Monotonic durable revision of one credential rotation journal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RotationRevision(u64);

impl RotationRevision {
    /// Revision expected before the first prepared journal is inserted.
    pub const ZERO: Self = Self(0);

    /// Creates a revision from its exact non-negative durable value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances the revision without wrapping.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::LimitExceeded`] at `u64::MAX`.
    pub fn checked_next(self) -> Result<Self, VaultError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| VaultError::new(VaultErrorCode::LimitExceeded))
    }
}

/// One immutable state transition requested against a durable rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotationTransition {
    /// Creates a new prepared journal from an immutable plan.
    Prepare(CredentialRotationPlan),
    /// Records the durable vault store receipt for the planned new version.
    RecordNewVersion(SecretStoreReceipt),
    /// Activates the new version at the supplied UTC instant.
    Activate(SystemTime),
    /// Records durable revocation of the old version after overlap expiry.
    Complete(SecretRevokeReceipt),
    /// Marks the stored or active new version as requiring compensation.
    BeginCompensation,
    /// Records durable revocation of the new version and marks the rotation failed.
    RecordCompensation(SecretRevokeReceipt),
}

impl RotationTransition {
    /// Returns a stable, non-sensitive transition label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Prepare(_) => "prepare",
            Self::RecordNewVersion(_) => "record-new-version",
            Self::Activate(_) => "activate",
            Self::Complete(_) => "complete",
            Self::BeginCompensation => "begin-compensation",
            Self::RecordCompensation(_) => "record-compensation",
        }
    }
}

/// One exact, revision-checked durable rotation mutation.
#[derive(Clone, Eq, PartialEq)]
pub struct RotationMutationRequest {
    mutation_id: RotationMutationId,
    rotation_id: Box<str>,
    expected_revision: RotationRevision,
    transition: RotationTransition,
}

impl RotationMutationRequest {
    /// Creates the initial mutation for a prepared rotation plan.
    ///
    /// # Errors
    /// Returns a stable validation error when the plan rotation identity is invalid.
    pub fn prepare(
        mutation_id: RotationMutationId,
        plan: CredentialRotationPlan,
    ) -> Result<Self, VaultError> {
        Self::new(
            mutation_id,
            plan.rotation_id(),
            RotationRevision::ZERO,
            RotationTransition::Prepare(plan.clone()),
        )
    }

    /// Creates a mutation that records a durable new-version store receipt.
    ///
    /// # Errors
    /// Returns a stable validation error when the rotation identity is invalid.
    pub fn record_new_version(
        mutation_id: RotationMutationId,
        rotation_id: &str,
        expected_revision: RotationRevision,
        receipt: SecretStoreReceipt,
    ) -> Result<Self, VaultError> {
        Self::new(
            mutation_id,
            rotation_id,
            expected_revision,
            RotationTransition::RecordNewVersion(receipt),
        )
    }

    /// Creates a mutation that activates the stored new version.
    ///
    /// # Errors
    /// Returns a stable validation error when the rotation identity is invalid.
    pub fn activate(
        mutation_id: RotationMutationId,
        rotation_id: &str,
        expected_revision: RotationRevision,
        activated_at: SystemTime,
    ) -> Result<Self, VaultError> {
        Self::new(
            mutation_id,
            rotation_id,
            expected_revision,
            RotationTransition::Activate(activated_at),
        )
    }

    /// Creates a mutation that completes old-version revocation.
    ///
    /// # Errors
    /// Returns a stable validation error when the rotation identity is invalid.
    pub fn complete(
        mutation_id: RotationMutationId,
        rotation_id: &str,
        expected_revision: RotationRevision,
        receipt: SecretRevokeReceipt,
    ) -> Result<Self, VaultError> {
        Self::new(
            mutation_id,
            rotation_id,
            expected_revision,
            RotationTransition::Complete(receipt),
        )
    }

    /// Creates a mutation that enters the compensating phase.
    ///
    /// # Errors
    /// Returns a stable validation error when the rotation identity is invalid.
    pub fn begin_compensation(
        mutation_id: RotationMutationId,
        rotation_id: &str,
        expected_revision: RotationRevision,
    ) -> Result<Self, VaultError> {
        Self::new(
            mutation_id,
            rotation_id,
            expected_revision,
            RotationTransition::BeginCompensation,
        )
    }

    /// Creates a mutation that records compensation and marks the rotation failed.
    ///
    /// # Errors
    /// Returns a stable validation error when the rotation identity is invalid.
    pub fn record_compensation(
        mutation_id: RotationMutationId,
        rotation_id: &str,
        expected_revision: RotationRevision,
        receipt: SecretRevokeReceipt,
    ) -> Result<Self, VaultError> {
        Self::new(
            mutation_id,
            rotation_id,
            expected_revision,
            RotationTransition::RecordCompensation(receipt),
        )
    }

    fn new(
        mutation_id: RotationMutationId,
        rotation_id: &str,
        expected_revision: RotationRevision,
        transition: RotationTransition,
    ) -> Result<Self, VaultError> {
        if !valid_identity(rotation_id, MAX_ROTATION_ID_BYTES) {
            return Err(VaultError::new(VaultErrorCode::InvalidArgument));
        }
        Ok(Self {
            mutation_id,
            rotation_id: rotation_id.into(),
            expected_revision,
            transition,
        })
    }

    /// Returns the caller-stable mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &RotationMutationId {
        &self.mutation_id
    }

    /// Returns the exact durable rotation identity.
    #[must_use]
    pub fn rotation_id(&self) -> &str {
        &self.rotation_id
    }

    /// Returns the revision that must exist before this mutation.
    #[must_use]
    pub const fn expected_revision(&self) -> RotationRevision {
        self.expected_revision
    }

    /// Returns the requested state transition.
    #[must_use]
    pub const fn transition(&self) -> &RotationTransition {
        &self.transition
    }
}

impl Debug for RotationMutationRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationMutationRequest")
            .field("mutation_id", &"<redacted>")
            .field("rotation_id", &"<redacted>")
            .field("expected_revision", &self.expected_revision)
            .field("transition", &self.transition.as_str())
            .finish()
    }
}

/// Durable result of one exact rotation mutation.
#[derive(Clone, Eq, PartialEq)]
pub struct RotationMutationReceipt {
    mutation_id: RotationMutationId,
    rotation_id: Box<str>,
    prior_revision: RotationRevision,
    revision: RotationRevision,
    phase: RotationPhase,
    committed_at: SystemTime,
}

impl RotationMutationReceipt {
    /// Creates a receipt after durable commit or authoritative reconciliation.
    ///
    /// # Errors
    /// Returns [`VaultErrorCode::InvalidArgument`] when the rotation identity is
    /// invalid or the committed revision is not exactly one greater than the
    /// prior revision.
    pub fn new(
        mutation_id: RotationMutationId,
        rotation_id: &str,
        prior_revision: RotationRevision,
        revision: RotationRevision,
        phase: RotationPhase,
        committed_at: SystemTime,
    ) -> Result<Self, VaultError> {
        let expected_revision = prior_revision.get().checked_add(1);
        if !valid_identity(rotation_id, MAX_ROTATION_ID_BYTES)
            || expected_revision != Some(revision.get())
        {
            return Err(VaultError::new(VaultErrorCode::InvalidArgument));
        }
        Ok(Self {
            mutation_id,
            rotation_id: rotation_id.into(),
            prior_revision,
            revision,
            phase,
            committed_at,
        })
    }

    /// Returns the mutation identity that produced this receipt.
    #[must_use]
    pub const fn mutation_id(&self) -> &RotationMutationId {
        &self.mutation_id
    }

    /// Returns the affected rotation identity.
    #[must_use]
    pub fn rotation_id(&self) -> &str {
        &self.rotation_id
    }

    /// Returns the revision observed before the mutation.
    #[must_use]
    pub const fn prior_revision(&self) -> RotationRevision {
        self.prior_revision
    }

    /// Returns the revision committed by the mutation.
    #[must_use]
    pub const fn revision(&self) -> RotationRevision {
        self.revision
    }

    /// Returns the phase committed by the mutation.
    #[must_use]
    pub const fn phase(&self) -> RotationPhase {
        self.phase
    }

    /// Returns the adapter-observed UTC publication time.
    #[must_use]
    pub const fn committed_at(&self) -> SystemTime {
        self.committed_at
    }
}

impl Debug for RotationMutationReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationMutationReceipt")
            .field("mutation_id", &"<redacted>")
            .field("rotation_id", &"<redacted>")
            .field("prior_revision", &self.prior_revision)
            .field("revision", &self.revision)
            .field("phase", &self.phase)
            .field("committed_at", &self.committed_at)
            .finish()
    }
}

/// Reconstructed durable rotation journal and its monotonic revision.
#[derive(Clone, Eq, PartialEq)]
pub struct RotationSnapshot {
    journal: RotationJournal,
    revision: RotationRevision,
    updated_at: SystemTime,
}

impl RotationSnapshot {
    /// Creates a snapshot after all persisted invariants have been verified.
    #[must_use]
    pub const fn new(
        journal: RotationJournal,
        revision: RotationRevision,
        updated_at: SystemTime,
    ) -> Self {
        Self {
            journal,
            revision,
            updated_at,
        }
    }

    /// Returns the reconstructed domain journal.
    #[must_use]
    pub const fn journal(&self) -> &RotationJournal {
        &self.journal
    }

    /// Returns the durable journal revision.
    #[must_use]
    pub const fn revision(&self) -> RotationRevision {
        self.revision
    }

    /// Returns when the current revision was durably published.
    #[must_use]
    pub const fn updated_at(&self) -> SystemTime {
        self.updated_at
    }
}

impl Debug for RotationSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationSnapshot")
            .field("phase", &self.journal.phase())
            .field("revision", &self.revision)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

/// Authenticated durable credential-rotation persistence boundary.
pub trait CredentialRotationPort: Send + Sync {
    /// Applies one exact revision-checked state transition atomically.
    ///
    /// Exact replay of the same mutation identity and payload returns the
    /// original receipt. Reusing an identity with changed input or a stale
    /// expected revision returns [`VaultErrorCode::Conflict`]. An ambiguous
    /// commit returns [`VaultErrorCode::CommitIndeterminate`] and requires
    /// [`Self::reconcile`] after reopening the durable adapter.
    ///
    /// # Errors
    /// Returns stable authentication, authorization, cancellation, deadline,
    /// conflict, resource, availability, or commit-indeterminate errors without
    /// exposing credential locators or persistence details.
    fn mutate<'a>(
        &'a self,
        request: RotationMutationRequest,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, RotationMutationReceipt>;

    /// Reconciles one caller-stable mutation identity after an ambiguous commit.
    ///
    /// # Errors
    /// Returns stable authentication, authorization, cancellation, deadline,
    /// availability, or integrity errors. A missing tenant-scoped mutation is
    /// returned as `Ok(None)` and does not disclose another tenant's evidence.
    fn reconcile<'a>(
        &'a self,
        mutation_id: &'a RotationMutationId,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, Option<RotationMutationReceipt>>;

    /// Loads and reconstructs one tenant-scoped durable rotation journal.
    ///
    /// # Errors
    /// Returns stable validation, authentication, authorization, cancellation,
    /// deadline, availability, or integrity errors. A missing tenant-scoped
    /// rotation is returned as `Ok(None)`.
    fn load<'a>(
        &'a self,
        rotation_id: &'a str,
        context: &'a RequestContext,
    ) -> BoxVaultFuture<'a, Option<RotationSnapshot>>;
}

fn valid_identity(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.is_ascii()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

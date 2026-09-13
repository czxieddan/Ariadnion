// crates/optional/ariadnion-account-import/src/lib.rs - Account import contracts for Ariadnion.
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
//! Bounded, secret-free account import validation and publication intents.
//!
//! This crate stops before encryption or signature verification. Importers pass
//! only typed [`SecretRef`] values and opaque digests. A coordinator performs a
//! deterministic dry run and local generation sequencing, leaving cryptographic
//! custody and durable snapshot publication to a later adapter such as the
//! account-pool boundary.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::RwLock;

pub use ariadnion_account_domain::{AccountId, ProviderId, SecretRef};

/// Maximum entries accepted by one import batch.
pub const MAX_IMPORT_ENTRIES: usize = 100_000;
/// Maximum bytes accepted when parsing a hexadecimal digest.
pub const DIGEST_HEX_BYTES: usize = 64;
const CURRENT_SCHEMA_VERSION: u16 = 1;

/// Stable machine-readable account-import failures.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ImportErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// The import schema version is not supported.
    UnsupportedSchemaVersion,
    /// The import contains more entries than the bounded capacity.
    TooManyEntries,
    /// An account identity occurs more than once in one batch.
    DuplicateEntry,
    /// An entry conflicts with an existing account under the selected strategy.
    Conflict,
    /// A publication intent was created for an old coordinator generation.
    GenerationConflict,
    /// The coordinator generation cannot advance without wrapping.
    GenerationExhausted,
    /// Internal state could not be read or updated.
    StateUnavailable,
}

impl ImportErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        const CODES: [&str; 8] = [
            "ACCOUNT_IMPORT_INVALID_ARGUMENT",
            "ACCOUNT_IMPORT_UNSUPPORTED_SCHEMA_VERSION",
            "ACCOUNT_IMPORT_TOO_MANY_ENTRIES",
            "ACCOUNT_IMPORT_DUPLICATE_ENTRY",
            "ACCOUNT_IMPORT_CONFLICT",
            "ACCOUNT_IMPORT_GENERATION_CONFLICT",
            "ACCOUNT_IMPORT_GENERATION_EXHAUSTED",
            "ACCOUNT_IMPORT_STATE_UNAVAILABLE",
        ];
        CODES[self as usize]
    }
}

impl Display for ImportErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted account-import failure carrying no rejected input or secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportError {
    code: ImportErrorCode,
}

impl ImportError {
    const fn new(code: ImportErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ImportErrorCode {
        self.code
    }
}

impl Display for ImportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ImportError {}

/// Version of the structured import schema.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImportSchemaVersion(u16);

impl ImportSchemaVersion {
    /// Returns the schema version implemented by this crate.
    #[must_use]
    pub const fn current() -> Self {
        Self(CURRENT_SCHEMA_VERSION)
    }

    /// Creates an explicit schema version for compatibility checks.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric schema version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    const fn supported(self) -> bool {
        self.0 == CURRENT_SCHEMA_VERSION
    }
}

/// Monotonic generation used for optimistic atomic publication.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImportGeneration(u64);

impl ImportGeneration {
    /// Returns the generation before any successful publication.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Creates a generation reconstructed from durable state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, ImportError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| ImportError::new(ImportErrorCode::GenerationExhausted))
    }
}

/// A fixed-size opaque digest supplied by an upstream integrity layer.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueDigest([u8; 32]);

impl OpaqueDigest {
    /// Creates a digest from its already-authenticated bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 64 hexadecimal characters without performing cryptography.
    ///
    /// # Errors
    /// Returns [`ImportErrorCode::InvalidArgument`] for malformed input.
    pub fn parse_hex(value: &str) -> Result<Self, ImportError> {
        if value.len() != DIGEST_HEX_BYTES || !value.is_ascii() {
            return Err(ImportError::new(ImportErrorCode::InvalidArgument));
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(chunk[0])?;
            let low = hex_nibble(chunk[1])?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Debug for OpaqueDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueDigest(<redacted>)")
    }
}

impl Display for OpaqueDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// How an import handles an account already present in the target set.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConflictStrategy {
    /// Reject the complete operation when any existing account is encountered.
    Reject,
    /// Leave existing accounts untouched and import only new accounts.
    SkipExisting,
    /// Include existing accounts in the replacement set.
    ReplaceExisting,
}

/// One structured account record containing references but no plaintext secret.
#[derive(Clone, Eq, PartialEq)]
pub struct ImportEntry {
    account_id: AccountId,
    provider_id: ProviderId,
    secret_ref: SecretRef,
    credential_digest: OpaqueDigest,
}

/// Compatibility alias for callers that name entries as account-import records.
pub type AccountImportEntry = ImportEntry;

impl ImportEntry {
    /// Creates an entry from validated identities, a secret reference, and an opaque digest.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        provider_id: ProviderId,
        secret_ref: SecretRef,
        credential_digest: OpaqueDigest,
    ) -> Self {
        Self {
            account_id,
            provider_id,
            secret_ref,
            credential_digest,
        }
    }

    /// Returns the account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the external secret reference.
    #[must_use]
    pub const fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Returns the opaque credential digest.
    #[must_use]
    pub const fn credential_digest(&self) -> OpaqueDigest {
        self.credential_digest
    }
}

impl Debug for ImportEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportEntry")
            .field("account_id", &self.account_id)
            .field("provider_id", &self.provider_id)
            .field("secret_ref", &self.secret_ref)
            .field("credential_digest", &self.credential_digest)
            .finish()
    }
}

/// A bounded structured batch awaiting validation and publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBatch {
    schema_version: ImportSchemaVersion,
    entries: Box<[ImportEntry]>,
}

/// Compatibility alias for the structured account-import batch.
pub type AccountImportBatch = ImportBatch;

impl ImportBatch {
    /// Creates a batch without retaining plaintext credentials.
    ///
    /// Cross-entry uniqueness and schema compatibility are checked during dry run.
    ///
    /// # Errors
    /// Returns [`ImportErrorCode::TooManyEntries`] when the bound is exceeded.
    pub fn new(
        schema_version: ImportSchemaVersion,
        entries: Vec<ImportEntry>,
    ) -> Result<Self, ImportError> {
        if entries.len() > MAX_IMPORT_ENTRIES {
            return Err(ImportError::new(ImportErrorCode::TooManyEntries));
        }
        Ok(Self {
            schema_version,
            entries: entries.into_boxed_slice(),
        })
    }

    /// Returns the declared schema version.
    #[must_use]
    pub const fn schema_version(&self) -> ImportSchemaVersion {
        self.schema_version
    }

    /// Returns entries in source order.
    #[must_use]
    pub fn entries(&self) -> &[ImportEntry] {
        &self.entries
    }
}

/// Deterministic result of validating one batch against an existing account set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DryRunReport {
    total_count: usize,
    selected_count: usize,
    skipped_count: usize,
    conflict_count: usize,
    strategy: ConflictStrategy,
}

/// Compatibility alias for the dry-run report type.
pub type ImportDryRunReport = DryRunReport;

impl DryRunReport {
    /// Returns the total source entry count.
    #[must_use]
    pub const fn total_count(self) -> usize {
        self.total_count
    }

    /// Returns the number of entries selected for publication.
    #[must_use]
    pub const fn selected_count(self) -> usize {
        self.selected_count
    }

    /// Returns the number of existing entries skipped by policy.
    #[must_use]
    pub const fn skipped_count(self) -> usize {
        self.skipped_count
    }

    /// Returns the number of conflicts observed by policy.
    #[must_use]
    pub const fn conflict_count(self) -> usize {
        self.conflict_count
    }

    /// Returns the strategy used for this report.
    #[must_use]
    pub const fn strategy(self) -> ConflictStrategy {
        self.strategy
    }
}

/// Immutable, generation-bound intent for an atomic publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishIntent {
    expected_generation: ImportGeneration,
    strategy: ConflictStrategy,
    entries: Box<[ImportEntry]>,
}

/// Compatibility alias for the atomic publication intent.
pub type AtomicPublishIntent = PublishIntent;

impl PublishIntent {
    /// Returns the generation that must still be current to publish this intent.
    #[must_use]
    pub const fn expected_generation(&self) -> ImportGeneration {
        self.expected_generation
    }

    /// Returns the conflict strategy used to produce this intent.
    #[must_use]
    pub const fn strategy(&self) -> ConflictStrategy {
        self.strategy
    }

    /// Returns the selected secret-free entries.
    #[must_use]
    pub fn entries(&self) -> &[ImportEntry] {
        &self.entries
    }
}

/// Receipt returned after an intent is accepted by the in-memory coordinator.
///
/// This receipt is deliberately non-durable. It only advances the coordinator's
/// local optimistic generation and must never be used as evidence of a durable
/// account snapshot commit. Durable generation ownership belongs to the storage
/// adapter that consumes the intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishReceipt {
    generation: ImportGeneration,
    published_count: usize,
}

impl PublishReceipt {
    /// Returns the generation assigned by publication.
    #[must_use]
    pub const fn generation(self) -> ImportGeneration {
        self.generation
    }

    /// Returns the number of entries accepted by publication.
    #[must_use]
    pub const fn published_count(self) -> usize {
        self.published_count
    }

}

#[derive(Debug)]
struct CoordinatorState {
    generation: ImportGeneration,
}

/// Coordinator for deterministic dry runs and local generation sequencing.
///
/// The coordinator does not access storage and does not prove durable success.
/// A durable adapter must consume the immutable [`PublishIntent`] and own its
/// generation compare-and-swap, transaction, and reconciliation behavior.
#[derive(Debug)]
pub struct ImportCoordinator {
    state: RwLock<CoordinatorState>,
}

impl Default for ImportCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ImportCoordinator {
    /// Creates an empty coordinator at generation zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(CoordinatorState {
                generation: ImportGeneration::initial(),
            }),
        }
    }

    /// Performs a bounded dry run without changing coordinator state.
    ///
    /// # Errors
    /// Returns a stable schema, duplicate, conflict, or state error.
    pub fn dry_run(
        &self,
        batch: &ImportBatch,
        existing: &[AccountId],
        strategy: ConflictStrategy,
    ) -> Result<DryRunReport, ImportError> {
        let existing_set = existing_accounts(existing)?;
        let (selected, skipped, conflicts) = classify_entries(batch, &existing_set, strategy)?;
        Ok(DryRunReport {
            total_count: batch.entries.len(),
            selected_count: selected,
            skipped_count: skipped,
            conflict_count: conflicts,
            strategy,
        })
    }

    /// Creates an immutable intent bound to the current generation.
    ///
    /// # Errors
    /// Returns validation or state errors without mutating publication state.
    pub fn prepare(
        &self,
        batch: &ImportBatch,
        existing: &[AccountId],
        strategy: ConflictStrategy,
    ) -> Result<PublishIntent, ImportError> {
        let existing_set = existing_accounts(existing)?;
        let entries = select_entries(batch, &existing_set, strategy)?;
        let generation = self.generation()?;
        Ok(PublishIntent {
            expected_generation: generation,
            strategy,
            entries: entries.into_boxed_slice(),
        })
    }

    /// Atomically accepts an intent in coordinator memory if its expected generation is current.
    ///
    /// This advances only the coordinator's local generation. It is not a
    /// durable commit and must not be used as one.
    ///
    /// # Errors
    /// Returns [`ImportErrorCode::GenerationConflict`] for stale intents and a
    /// stable state or overflow error for other failures.
    pub fn accept_intent(&self, intent: PublishIntent) -> Result<PublishReceipt, ImportError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| ImportError::new(ImportErrorCode::StateUnavailable))?;
        if state.generation != intent.expected_generation {
            return Err(ImportError::new(ImportErrorCode::GenerationConflict));
        }
        let generation = state.generation.next()?;
        state.generation = generation;
        Ok(PublishReceipt {
            generation,
            published_count: intent.entries.len(),
        })
    }

    /// Backward-compatible alias for [`Self::accept_intent`].
    ///
    /// The returned receipt is explicitly non-durable. Durable publication is
    /// owned by the adapter that consumes the intent.
    pub fn publish(&self, intent: PublishIntent) -> Result<PublishReceipt, ImportError> {
        self.accept_intent(intent)
    }

    /// Returns the current coordinator generation.
    ///
    /// # Errors
    /// Returns [`ImportErrorCode::StateUnavailable`] if the state lock is poisoned.
    pub fn generation(&self) -> Result<ImportGeneration, ImportError> {
        self.state
            .read()
            .map(|state| state.generation)
            .map_err(|_| ImportError::new(ImportErrorCode::StateUnavailable))
    }
}

fn classify_entries(
    batch: &ImportBatch,
    existing: &BTreeSet<AccountId>,
    strategy: ConflictStrategy,
) -> Result<(usize, usize, usize), ImportError> {
    validate_batch(batch)?;
    let mut selected = 0;
    let mut skipped = 0;
    let mut conflicts = 0;
    for entry in &batch.entries {
        if existing.contains(entry.account_id()) {
            conflicts += 1;
            match strategy {
                ConflictStrategy::Reject => {
                    return Err(ImportError::new(ImportErrorCode::Conflict));
                }
                ConflictStrategy::SkipExisting => skipped += 1,
                ConflictStrategy::ReplaceExisting => selected += 1,
            }
        } else {
            selected += 1;
        }
    }
    Ok((selected, skipped, conflicts))
}

fn select_entries(
    batch: &ImportBatch,
    existing: &BTreeSet<AccountId>,
    strategy: ConflictStrategy,
) -> Result<Vec<ImportEntry>, ImportError> {
    classify_entries(batch, existing, strategy)?;
    let mut selected = Vec::with_capacity(batch.entries.len());
    for entry in &batch.entries {
        if existing.contains(entry.account_id()) && strategy == ConflictStrategy::SkipExisting {
            continue;
        }
        selected.push(entry.clone());
    }
    Ok(selected)
}

fn validate_batch(batch: &ImportBatch) -> Result<(), ImportError> {
    if !batch.schema_version.supported() {
        return Err(ImportError::new(ImportErrorCode::UnsupportedSchemaVersion));
    }
    let mut ids = BTreeSet::new();
    for entry in &batch.entries {
        if !ids.insert(entry.account_id()) {
            return Err(ImportError::new(ImportErrorCode::DuplicateEntry));
        }
    }
    Ok(())
}

fn existing_accounts(existing: &[AccountId]) -> Result<BTreeSet<AccountId>, ImportError> {
    if existing.len() > MAX_IMPORT_ENTRIES {
        return Err(ImportError::new(ImportErrorCode::TooManyEntries));
    }
    let mut ids = BTreeSet::new();
    for id in existing {
        if !ids.insert(id.clone()) {
            return Err(ImportError::new(ImportErrorCode::DuplicateEntry));
        }
    }
    Ok(ids)
}

fn hex_nibble(value: u8) -> Result<u8, ImportError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ImportError::new(ImportErrorCode::InvalidArgument)),
    }
}

// crates/optional/ariadnion-account-import/src/port.rs - Durable account import ports for Ariadnion.
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
//! Tenant-scoped durable publication and reconciliation contracts.

use std::fmt::{self, Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use ariadnion_core::RequestContext;

use crate::{ImportGeneration, MAX_IMPORT_ENTRIES, PublishIntent};

/// Maximum bytes in one caller-stable import mutation identity.
pub const MAX_IMPORT_MUTATION_ID_BYTES: usize = 1 << 7;

/// A boxed, sendable durable import operation future.
pub type BoxImportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ImportPortError>> + Send + 'a>>;

/// Stable failures returned by a durable account import adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ImportPortErrorCode {
    /// A mutation identity or receipt field is malformed.
    InvalidArgument,
    /// The request has no authenticated tenant.
    Unauthenticated,
    /// The authenticated principal cannot publish account configuration.
    PermissionDenied,
    /// The mutation identity or expected generation conflicts with durable state.
    Conflict,
    /// Cancellation won before a new durable effect began.
    Cancelled,
    /// The absolute deadline won before a new durable effect began.
    DeadlineExceeded,
    /// A bounded adapter resource cannot accept more work.
    ResourceExhausted,
    /// The durable account store is temporarily unavailable.
    Unavailable,
    /// A commit outcome is ambiguous and requires reconciliation.
    CommitIndeterminate,
    /// Durable state failed structural or integrity validation.
    CorruptState,
}

impl ImportPortErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        if let Some(code) = request_error_code(self) {
            return code;
        }
        if let Some(code) = execution_error_code(self) {
            return code;
        }
        adapter_error_code(self)
    }
}

const fn request_error_code(code: ImportPortErrorCode) -> Option<&'static str> {
    match code {
        ImportPortErrorCode::InvalidArgument => Some("ACCOUNT_IMPORT_PORT_INVALID_ARGUMENT"),
        ImportPortErrorCode::Unauthenticated => Some("ACCOUNT_IMPORT_PORT_UNAUTHENTICATED"),
        ImportPortErrorCode::PermissionDenied => Some("ACCOUNT_IMPORT_PORT_PERMISSION_DENIED"),
        ImportPortErrorCode::Conflict => Some("ACCOUNT_IMPORT_PORT_CONFLICT"),
        _ => None,
    }
}

const fn execution_error_code(code: ImportPortErrorCode) -> Option<&'static str> {
    match code {
        ImportPortErrorCode::Cancelled => Some("ACCOUNT_IMPORT_PORT_CANCELLED"),
        ImportPortErrorCode::DeadlineExceeded => Some("ACCOUNT_IMPORT_PORT_DEADLINE_EXCEEDED"),
        ImportPortErrorCode::ResourceExhausted => Some("ACCOUNT_IMPORT_PORT_RESOURCE_EXHAUSTED"),
        _ => None,
    }
}

const fn adapter_error_code(code: ImportPortErrorCode) -> &'static str {
    match code {
        ImportPortErrorCode::Unavailable => "ACCOUNT_IMPORT_PORT_UNAVAILABLE",
        ImportPortErrorCode::CommitIndeterminate => "ACCOUNT_IMPORT_PORT_COMMIT_INDETERMINATE",
        ImportPortErrorCode::CorruptState => "ACCOUNT_IMPORT_PORT_CORRUPT_STATE",
        _ => "ACCOUNT_IMPORT_PORT_CORRUPT_STATE",
    }
}

/// A redacted durable import failure containing no tenant or account data.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ImportPortError {
    code: ImportPortErrorCode,
}

impl ImportPortError {
    /// Creates a redacted adapter failure.
    #[must_use]
    pub const fn new(code: ImportPortErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ImportPortErrorCode {
        self.code
    }

    /// Reports whether callers must reconcile instead of replaying the mutation.
    #[must_use]
    pub const fn requires_reconciliation(self) -> bool {
        matches!(self.code, ImportPortErrorCode::CommitIndeterminate)
    }
}

impl Debug for ImportPortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "ImportPortError({})", self.code.as_str())
    }
}

impl Display for ImportPortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ImportPortError {}

/// A tenant-local, caller-stable identity for one durable publication attempt.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImportMutationId(Box<str>);

impl ImportMutationId {
    /// Parses a non-empty bounded ASCII mutation identity.
    ///
    /// The first byte must be alphanumeric. Remaining bytes may also contain
    /// `.`, `-`, `_`, or `:`. Reconciliation must reuse the exact same value.
    ///
    /// # Errors
    ///
    /// Returns [`ImportPortErrorCode::InvalidArgument`] for malformed input.
    pub fn parse(value: &str) -> Result<Self, ImportPortError> {
        if !valid_mutation_id(value) {
            return Err(ImportPortError::new(ImportPortErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ImportMutationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ImportMutationId")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for ImportMutationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One immutable publication intent bound to its durable mutation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePublishRequest {
    mutation_id: ImportMutationId,
    intent: PublishIntent,
}

impl DurablePublishRequest {
    /// Binds a caller-stable mutation identity to one validated intent.
    #[must_use]
    pub const fn new(mutation_id: ImportMutationId, intent: PublishIntent) -> Self {
        Self {
            mutation_id,
            intent,
        }
    }

    /// Returns the tenant-local mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> &ImportMutationId {
        &self.mutation_id
    }

    /// Returns the immutable generation-bound publication intent.
    #[must_use]
    pub const fn intent(&self) -> &PublishIntent {
        &self.intent
    }

    /// Consumes the request into its durable identity and immutable intent.
    #[must_use]
    pub fn into_parts(self) -> (ImportMutationId, PublishIntent) {
        (self.mutation_id, self.intent)
    }
}

/// Durable evidence for one committed account publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePublishReceipt {
    mutation_id: ImportMutationId,
    generation: ImportGeneration,
    published_count: usize,
    committed_at: SystemTime,
}

impl DurablePublishReceipt {
    /// Creates a receipt only after the adapter confirms durable commit.
    ///
    /// # Errors
    ///
    /// Returns [`ImportPortErrorCode::InvalidArgument`] for generation zero or
    /// an entry count above [`MAX_IMPORT_ENTRIES`].
    pub fn new(
        mutation_id: ImportMutationId,
        generation: ImportGeneration,
        published_count: usize,
        committed_at: SystemTime,
    ) -> Result<Self, ImportPortError> {
        if generation == ImportGeneration::initial() || published_count > MAX_IMPORT_ENTRIES {
            return Err(ImportPortError::new(ImportPortErrorCode::InvalidArgument));
        }
        Ok(Self {
            mutation_id,
            generation,
            published_count,
            committed_at,
        })
    }

    /// Returns the mutation identity used for reconciliation.
    #[must_use]
    pub const fn mutation_id(&self) -> &ImportMutationId {
        &self.mutation_id
    }

    /// Returns the committed durable generation.
    #[must_use]
    pub const fn generation(&self) -> ImportGeneration {
        self.generation
    }

    /// Returns the number of entries applied by the transaction.
    #[must_use]
    pub const fn published_count(&self) -> usize {
        self.published_count
    }

    /// Returns the adapter-reported UTC commit time.
    #[must_use]
    pub const fn committed_at(&self) -> SystemTime {
        self.committed_at
    }
}

/// Durable, tenant-scoped account import publication port.
///
/// Implementations authenticate the tenant from [`RequestContext`], compare the
/// intent generation and mutation identity inside one transaction, and persist
/// the resulting account state, generation, request fingerprint, and receipt
/// atomically. A repeated mutation identity is idempotent only when its original
/// request fingerprint matches. [`ImportPortErrorCode::CommitIndeterminate`]
/// requires [`Self::reconcile`]; callers must not invent a new mutation identity.
pub trait AccountImportPort: Send + Sync {
    /// Atomically publishes one validated account import intent.
    fn publish<'a>(
        &'a self,
        request: DurablePublishRequest,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, DurablePublishReceipt>;

    /// Reconciles one prior mutation without replaying its account effects.
    fn reconcile<'a>(
        &'a self,
        mutation_id: &'a ImportMutationId,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, Option<DurablePublishReceipt>>;

    /// Loads the tenant's authoritative durable import generation.
    fn generation<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxImportFuture<'a, ImportGeneration>;
}

fn valid_mutation_id(value: &str) -> bool {
    let Some(first) = value.as_bytes().first() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.len() <= MAX_IMPORT_MUTATION_ID_BYTES
        && value.bytes().all(valid_mutation_id_byte)
}

fn valid_mutation_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

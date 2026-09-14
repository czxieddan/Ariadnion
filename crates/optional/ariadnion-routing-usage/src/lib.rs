// crates/optional/ariadnion-routing-usage/src/lib.rs - Provider-attempt usage confirmation contracts for Ariadnion.
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
//! Provider-attempt usage confirmation contracts.
//!
//! The crate binds a bounded provider usage report to one tenant, account,
//! request, and attempt. A stable confirmation identity provides the
//! idempotency key for later durable ingestion. Receipts retain the immutable
//! input so equal replays return the same outcome, divergent replays conflict,
//! and ambiguous outcomes remain reconciliation-only. No transport, storage,
//! clock, credential, or metering side effect is implemented here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

pub use ariadnion_account_domain::AccountId;
pub use ariadnion_core::{AttemptId, RequestId, TenantId};

/// Maximum UTF-8 bytes accepted by an opaque identifier.
pub const MAX_IDENTIFIER_BYTES: usize = 128;
/// Maximum integer value accepted for one usage dimension.
pub const MAX_USAGE_AMOUNT: u64 = 1_u64 << 50;
/// Maximum distinct dimensions in one provider usage report.
pub const MAX_USAGE_DIMENSIONS: usize = 8;

/// Stable machine-readable usage confirmation errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum UsageConfirmationErrorCode {
    /// An opaque identifier is empty, malformed, or oversized.
    InvalidIdentifier,
    /// A usage amount exceeds its fixed upper bound.
    UsageOutOfRange,
    /// A usage report contains no dimensions.
    UsageReportEmpty,
    /// A usage report exceeds the fixed dimension count.
    TooManyDimensions,
    /// A usage report repeats one dimension.
    DuplicateDimension,
    /// A receipt was compared with a different confirmation identity.
    ReceiptMismatch,
    /// One confirmation identity was replayed with different immutable input.
    ReplayConflict,
    /// The durable confirmation boundary is unavailable.
    PortUnavailable,
}

impl UsageConfirmationErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidIdentifier => "ROUTING_USAGE_INVALID_IDENTIFIER",
            Self::UsageOutOfRange => "ROUTING_USAGE_AMOUNT_OUT_OF_RANGE",
            Self::UsageReportEmpty => "ROUTING_USAGE_REPORT_EMPTY",
            Self::TooManyDimensions => "ROUTING_USAGE_TOO_MANY_DIMENSIONS",
            Self::DuplicateDimension => "ROUTING_USAGE_DUPLICATE_DIMENSION",
            Self::ReceiptMismatch | Self::ReplayConflict | Self::PortUnavailable => {
                replay_error_code(self)
            }
        }
    }
}

impl fmt::Display for UsageConfirmationErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted usage confirmation error containing only a stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsageConfirmationError {
    code: UsageConfirmationErrorCode,
}

impl UsageConfirmationError {
    /// Creates an error for adapters implementing the confirmation port.
    #[must_use]
    pub const fn from_code(code: UsageConfirmationErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> UsageConfirmationErrorCode {
        self.code
    }
}

impl fmt::Display for UsageConfirmationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for UsageConfirmationError {}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BoundedIdentifier(Box<str>);

impl BoundedIdentifier {
    fn parse(value: &str) -> Result<Self, UsageConfirmationError> {
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(error(UsageConfirmationErrorCode::InvalidIdentifier));
        }
        Ok(Self(value.into()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

macro_rules! define_identifier {
    ($name:ident, $purpose:literal) => {
        #[doc = $purpose]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(BoundedIdentifier);

        impl $name {
            /// Parses a visible ASCII identifier within the fixed byte bound.
            ///
            /// # Errors
            /// Returns [`UsageConfirmationErrorCode::InvalidIdentifier`] for
            /// empty, non-ASCII, control-containing, whitespace-containing, or
            /// oversized values.
            pub fn parse(value: &str) -> Result<Self, UsageConfirmationError> {
                BoundedIdentifier::parse(value).map(Self)
            }

            /// Returns the validated identifier for typed port implementations.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"<redacted>")
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("<redacted>")
            }
        }
    };
}

define_identifier!(
    MeteringReceiptId,
    "A bounded receipt identifier returned by durable metering ingestion."
);
define_identifier!(
    ReconciliationId,
    "A bounded identifier for resolving an ambiguous confirmation."
);

/// Stable idempotency identity for one provider-attempt usage report.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UsageConfirmationId {
    tenant: TenantId,
    account: AccountId,
    request: RequestId,
    attempt: AttemptId,
}

impl UsageConfirmationId {
    /// Binds the tenant, provider account, request, and provider attempt.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        account: AccountId,
        request: RequestId,
        attempt: AttemptId,
    ) -> Self {
        Self {
            tenant,
            account,
            request,
            attempt,
        }
    }

    /// Returns the bound tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the bound provider account.
    #[must_use]
    pub const fn account(&self) -> &AccountId {
        &self.account
    }

    /// Returns the bound request.
    #[must_use]
    pub const fn request(&self) -> &RequestId {
        &self.request
    }

    /// Returns the bound provider attempt.
    #[must_use]
    pub const fn attempt(&self) -> &AttemptId {
        &self.attempt
    }
}

impl fmt::Debug for UsageConfirmationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UsageConfirmationId")
            .field("binding", &"<redacted>")
            .finish()
    }
}

/// Provider-reported integer usage dimensions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum UsageDimension {
    /// Text or multimodal input tokens charged by the provider.
    InputTokens,
    /// Generated output tokens charged by the provider.
    OutputTokens,
    /// Input tokens served from a provider cache.
    CachedInputTokens,
    /// Provider-defined audio input units.
    AudioInputUnits,
    /// Provider-defined audio output units.
    AudioOutputUnits,
    /// Provider-defined image units.
    ImageUnits,
    /// Provider request units.
    RequestUnits,
    /// Provider tool invocation units.
    ToolCalls,
}

/// Bounded non-negative integer quantity for one usage dimension.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UsageAmount(u64);

impl UsageAmount {
    /// Creates a bounded usage quantity without floating-point conversion.
    ///
    /// # Errors
    /// Returns [`UsageConfirmationErrorCode::UsageOutOfRange`] when `value`
    /// exceeds [`MAX_USAGE_AMOUNT`]. Zero is valid for explicit provider fields.
    pub fn new(value: u64) -> Result<Self, UsageConfirmationError> {
        if value > MAX_USAGE_AMOUNT {
            return Err(error(UsageConfirmationErrorCode::UsageOutOfRange));
        }
        Ok(Self(value))
    }

    /// Returns the integer quantity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One typed dimension and its bounded integer quantity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UsageEntry {
    dimension: UsageDimension,
    amount: UsageAmount,
}

impl UsageEntry {
    /// Creates one usage entry.
    #[must_use]
    pub const fn new(dimension: UsageDimension, amount: UsageAmount) -> Self {
        Self { dimension, amount }
    }

    /// Returns the provider usage dimension.
    #[must_use]
    pub const fn dimension(self) -> UsageDimension {
        self.dimension
    }

    /// Returns the bounded integer quantity.
    #[must_use]
    pub const fn amount(self) -> UsageAmount {
        self.amount
    }
}

/// Canonical, bounded provider usage report.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UsageReport {
    entries: Box<[UsageEntry]>,
}

impl UsageReport {
    /// Validates and canonicalizes a provider usage report by dimension.
    ///
    /// Input ordering does not affect equality or replay behavior. Dimensions
    /// must be unique and the report must remain within the fixed count bound.
    ///
    /// # Errors
    /// Returns a stable error for empty, oversized, or duplicate reports.
    pub fn new(mut entries: Vec<UsageEntry>) -> Result<Self, UsageConfirmationError> {
        validate_report_size(entries.len())?;
        entries.sort_unstable_by_key(|entry| entry.dimension());
        if entries
            .windows(2)
            .any(|pair| pair[0].dimension() == pair[1].dimension())
        {
            return Err(error(UsageConfirmationErrorCode::DuplicateDimension));
        }
        Ok(Self {
            entries: entries.into_boxed_slice(),
        })
    }

    /// Returns entries in canonical dimension order.
    #[must_use]
    pub fn entries(&self) -> &[UsageEntry] {
        &self.entries
    }
}

/// Immutable provider usage input for one bound attempt.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProviderUsageConfirmation {
    identity: UsageConfirmationId,
    usage: UsageReport,
}

impl ProviderUsageConfirmation {
    /// Creates an immutable confirmation from validated identity and usage.
    #[must_use]
    pub const fn new(identity: UsageConfirmationId, usage: UsageReport) -> Self {
        Self { identity, usage }
    }

    /// Returns the stable idempotency identity.
    #[must_use]
    pub const fn identity(&self) -> &UsageConfirmationId {
        &self.identity
    }

    /// Returns the canonical provider usage report.
    #[must_use]
    pub const fn usage(&self) -> &UsageReport {
        &self.usage
    }
}

impl fmt::Debug for ProviderUsageConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderUsageConfirmation")
            .field("identity", &"<redacted>")
            .field("usage", &self.usage)
            .finish()
    }
}

/// Durable metering acknowledgement for a confirmed usage input.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfirmedUsageReceipt {
    confirmation: ProviderUsageConfirmation,
    metering_receipt: MeteringReceiptId,
}

impl ConfirmedUsageReceipt {
    /// Creates a confirmed receipt returned by durable ingestion.
    #[must_use]
    pub const fn new(
        confirmation: ProviderUsageConfirmation,
        metering_receipt: MeteringReceiptId,
    ) -> Self {
        Self {
            confirmation,
            metering_receipt,
        }
    }

    /// Returns the immutable input acknowledged by this receipt.
    #[must_use]
    pub const fn confirmation(&self) -> &ProviderUsageConfirmation {
        &self.confirmation
    }

    /// Returns the durable metering receipt identifier.
    #[must_use]
    pub const fn metering_receipt(&self) -> &MeteringReceiptId {
        &self.metering_receipt
    }
}

impl fmt::Debug for ConfirmedUsageReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedUsageReceipt")
            .field("confirmation", &self.confirmation)
            .field("metering_receipt", &"<redacted>")
            .finish()
    }
}

/// Reconciliation-only receipt for an outcome whose side effect is uncertain.
#[derive(Clone, Eq, PartialEq)]
pub struct AmbiguousUsageReceipt {
    confirmation: ProviderUsageConfirmation,
    reconciliation: ReconciliationId,
}

impl AmbiguousUsageReceipt {
    /// Creates a receipt that forbids normal confirmation retries.
    #[must_use]
    pub const fn new(
        confirmation: ProviderUsageConfirmation,
        reconciliation: ReconciliationId,
    ) -> Self {
        Self {
            confirmation,
            reconciliation,
        }
    }

    /// Returns the immutable input whose outcome must be reconciled.
    #[must_use]
    pub const fn confirmation(&self) -> &ProviderUsageConfirmation {
        &self.confirmation
    }

    /// Returns the reconciliation identifier.
    #[must_use]
    pub const fn reconciliation(&self) -> &ReconciliationId {
        &self.reconciliation
    }
}

impl fmt::Debug for AmbiguousUsageReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmbiguousUsageReceipt")
            .field("confirmation", &self.confirmation)
            .field("reconciliation", &"<redacted>")
            .finish()
    }
}

/// Typed outcome returned by durable usage ingestion or reconciliation.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum UsageConfirmationReceipt {
    /// The provider-attempt usage is durably confirmed.
    Confirmed(ConfirmedUsageReceipt),
    /// The outcome is uncertain and only reconciliation is permitted.
    Ambiguous(AmbiguousUsageReceipt),
}

impl UsageConfirmationReceipt {
    /// Replays an immutable input against this receipt.
    ///
    /// Equal input returns an equal receipt without authorizing another
    /// metering submission. The same idempotency identity with different usage
    /// fails as a conflict. A different identity is a receipt lookup mismatch.
    /// Ambiguous receipts remain ambiguous and must be passed to
    /// [`UsageConfirmationPort::reconcile`].
    ///
    /// # Errors
    /// Returns [`UsageConfirmationErrorCode::ReplayConflict`] for divergent
    /// input with the same identity, or
    /// [`UsageConfirmationErrorCode::ReceiptMismatch`] for another identity.
    pub fn replay(
        &self,
        input: &ProviderUsageConfirmation,
    ) -> Result<Self, UsageConfirmationError> {
        let existing = self.confirmation();
        if existing.identity() != input.identity() {
            return Err(error(UsageConfirmationErrorCode::ReceiptMismatch));
        }
        if existing != input {
            return Err(error(UsageConfirmationErrorCode::ReplayConflict));
        }
        Ok(self.clone())
    }

    /// Returns the immutable input recorded by either receipt outcome.
    #[must_use]
    pub const fn confirmation(&self) -> &ProviderUsageConfirmation {
        match self {
            Self::Confirmed(receipt) => receipt.confirmation(),
            Self::Ambiguous(receipt) => receipt.confirmation(),
        }
    }

    /// Returns the ambiguous receipt when reconciliation is required.
    #[must_use]
    pub const fn ambiguous(&self) -> Option<&AmbiguousUsageReceipt> {
        match self {
            Self::Confirmed(_) => None,
            Self::Ambiguous(receipt) => Some(receipt),
        }
    }

    /// Returns the confirmed receipt when durable ingestion succeeded.
    #[must_use]
    pub const fn confirmed(&self) -> Option<&ConfirmedUsageReceipt> {
        match self {
            Self::Confirmed(receipt) => Some(receipt),
            Self::Ambiguous(_) => None,
        }
    }
}

impl fmt::Debug for UsageConfirmationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Confirmed(receipt) => formatter.debug_tuple("Confirmed").field(receipt).finish(),
            Self::Ambiguous(receipt) => formatter.debug_tuple("Ambiguous").field(receipt).finish(),
        }
    }
}

/// Typed port for later P8 durable usage ingestion.
///
/// Implementations must atomically deduplicate [`UsageConfirmationId`]. Equal
/// immutable input must return the original receipt, while divergent input for
/// the same identity must return [`UsageConfirmationErrorCode::ReplayConflict`].
/// If a call may have applied its external metering side effect but cannot
/// prove the result, it must return an [`UsageConfirmationReceipt::Ambiguous`]
/// receipt. Callers must pass that receipt to [`Self::reconcile`] and must not
/// call [`Self::confirm`] again for the same identity.
///
/// The domain port is synchronous and does not define transport, storage,
/// deadlines, or cancellation. Adapters must check cancellation before an
/// external side effect and preserve the stable identity across retries.
pub trait UsageConfirmationPort: Send + Sync {
    /// Confirms provider usage or returns the existing deterministic receipt.
    ///
    /// # Errors
    /// Returns a stable redacted error when validation, deduplication, or the
    /// adapter boundary cannot complete safely.
    fn confirm(
        &self,
        input: &ProviderUsageConfirmation,
    ) -> Result<UsageConfirmationReceipt, UsageConfirmationError>;

    /// Resolves an ambiguous outcome without issuing a blind new submission.
    ///
    /// # Errors
    /// Returns a stable redacted error when the reconciliation lookup cannot
    /// establish a safe outcome.
    fn reconcile(
        &self,
        receipt: &AmbiguousUsageReceipt,
    ) -> Result<UsageConfirmationReceipt, UsageConfirmationError>;
}

fn validate_report_size(count: usize) -> Result<(), UsageConfirmationError> {
    if count == 0 {
        return Err(error(UsageConfirmationErrorCode::UsageReportEmpty));
    }
    if count > MAX_USAGE_DIMENSIONS {
        return Err(error(UsageConfirmationErrorCode::TooManyDimensions));
    }
    Ok(())
}

const fn error(code: UsageConfirmationErrorCode) -> UsageConfirmationError {
    UsageConfirmationError::from_code(code)
}

const fn replay_error_code(code: UsageConfirmationErrorCode) -> &'static str {
    match code {
        UsageConfirmationErrorCode::ReceiptMismatch => "ROUTING_USAGE_RECEIPT_MISMATCH",
        UsageConfirmationErrorCode::ReplayConflict => "ROUTING_USAGE_REPLAY_CONFLICT",
        UsageConfirmationErrorCode::PortUnavailable => "ROUTING_USAGE_PORT_UNAVAILABLE",
        _ => "ROUTING_USAGE_INVALID_ERROR_CODE",
    }
}

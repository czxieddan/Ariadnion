// crates/optional/ariadnion-model-pricing/src/lib.rs - Versioned model pricing contracts for Ariadnion.
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
//! Immutable, provider-neutral pricing schedules with checked integer arithmetic.
//!
//! A catalog is validated once and then shared as a deterministic snapshot. It
//! contains no transport, persistence, clock, or provider-specific behavior.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

/// Maximum byte length of a model identity.
pub const MAX_MODEL_ID_BYTES: usize = 128;
/// Maximum schedules in one immutable catalog.
pub const MAX_SCHEDULES: usize = 4_096;
/// Maximum dimensions in one schedule.
pub const MAX_DIMENSIONS: usize = 8;
/// Maximum minor-unit price accepted by the domain.
pub const MAX_MINOR_UNITS: u64 = 9_000_000_000_000_000_000;

/// Stable machine-readable pricing failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(usize)]
pub enum ModelPricingErrorCode {
    /// An argument is empty, malformed, or outside its bound.
    InvalidArgument,
    /// A fixed collection bound was exceeded.
    LimitExceeded,
    /// A dimension occurs more than once in one schedule.
    DuplicateDimension,
    /// Two schedules overlap for a model, currency, and dimension.
    OverlappingWindow,
    /// A schedule identity is repeated.
    DuplicateSchedule,
    /// No matching schedule or dimension exists.
    NotFound,
    /// A checked arithmetic operation exceeded the supported range.
    Overflow,
    /// A non-zero version could not advance without wrapping.
    VersionExhausted,
}

impl ModelPricingErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument
            | Self::LimitExceeded
            | Self::DuplicateDimension
            | Self::OverlappingWindow => self.as_str_core(),
            Self::DuplicateSchedule | Self::NotFound | Self::Overflow | Self::VersionExhausted => {
                self.as_str_extended()
            }
        }
    }

    const fn as_str_core(self) -> &'static str {
        match self {
            Self::InvalidArgument => "MODEL_PRICING_INVALID_ARGUMENT",
            Self::LimitExceeded => "MODEL_PRICING_LIMIT_EXCEEDED",
            Self::DuplicateDimension => "MODEL_PRICING_DUPLICATE_DIMENSION",
            Self::OverlappingWindow => "MODEL_PRICING_OVERLAPPING_WINDOW",
            _ => "MODEL_PRICING_INVALID_ARGUMENT",
        }
    }

    const fn as_str_extended(self) -> &'static str {
        match self {
            Self::DuplicateSchedule => "MODEL_PRICING_DUPLICATE_SCHEDULE",
            Self::NotFound => "MODEL_PRICING_NOT_FOUND",
            Self::Overflow => "MODEL_PRICING_OVERFLOW",
            Self::VersionExhausted => "MODEL_PRICING_VERSION_EXHAUSTED",
            _ => "MODEL_PRICING_INVALID_ARGUMENT",
        }
    }
}

impl fmt::Display for ModelPricingErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted pricing failure retaining only its stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelPricingError {
    code: ModelPricingErrorCode,
}

impl ModelPricingError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ModelPricingErrorCode {
        self.code
    }
}

impl fmt::Display for ModelPricingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ModelPricingError {}

/// A validated ISO-4217-style uppercase currency identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
    /// Parses a three-letter uppercase currency code.
    ///
    /// # Errors
    /// Returns [`ModelPricingErrorCode::InvalidArgument`] for any other shape.
    pub fn parse(value: &str) -> Result<Self, ModelPricingError> {
        let bytes = value.as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_uppercase) {
            return Err(error(ModelPricingErrorCode::InvalidArgument));
        }
        Ok(Self([bytes[0], bytes[1], bytes[2]]))
    }

    /// Returns the uppercase currency code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match std::str::from_utf8(&self.0) {
            Ok(value) => value,
            Err(_) => "???",
        }
    }
}

impl fmt::Debug for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CurrencyCode")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A non-zero monotonically increasing pricing version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PricingVersion(NonZeroU64);

impl PricingVersion {
    /// Returns the first publishable version.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero version.
    ///
    /// # Errors
    /// Returns [`ModelPricingErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, ModelPricingError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(ModelPricingErrorCode::InvalidArgument))
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Advances the version without wrapping.
    ///
    /// # Errors
    /// Returns [`ModelPricingErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, ModelPricingError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(ModelPricingErrorCode::VersionExhausted))
    }
}

/// A half-open UTC timestamp window `[start, end)`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EffectiveWindow {
    start: u64,
    end: Option<u64>,
}

impl EffectiveWindow {
    /// Creates a window with an optional exclusive end timestamp.
    ///
    /// # Errors
    /// Returns [`ModelPricingErrorCode::InvalidArgument`] when `end` is not
    /// greater than `start`.
    pub fn new(start: u64, end: Option<u64>) -> Result<Self, ModelPricingError> {
        if end.is_some_and(|value| value <= start) {
            return Err(error(ModelPricingErrorCode::InvalidArgument));
        }
        Ok(Self { start, end })
    }

    /// Returns the inclusive start timestamp.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the exclusive end timestamp, if bounded.
    #[must_use]
    pub const fn end(self) -> Option<u64> {
        self.end
    }

    fn contains(self, timestamp: u64) -> bool {
        timestamp >= self.start && self.end.is_none_or(|end| timestamp < end)
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end.unwrap_or(u64::MAX) && other.start < self.end.unwrap_or(u64::MAX)
    }
}

/// The provider-neutral usage dimension being charged.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PriceDimension {
    /// Input tokens.
    InputTokens,
    /// Output tokens.
    OutputTokens,
    /// Cached input tokens.
    CachedInputTokens,
    /// Media input units.
    MediaInput,
    /// Tool calls.
    ToolCalls,
}

/// A bounded non-negative integer amount in the schedule currency's minor unit.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PriceMinorUnits(u64);

impl PriceMinorUnits {
    /// Creates a bounded minor-unit amount.
    ///
    /// # Errors
    /// Returns [`ModelPricingErrorCode::Overflow`] above the supported bound.
    pub const fn new(value: u64) -> Result<Self, ModelPricingError> {
        if value > MAX_MINOR_UNITS {
            Err(error(ModelPricingErrorCode::Overflow))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the integer minor-unit value.
    #[must_use]
    pub const fn minor_units(self) -> u64 {
        self.0
    }

    fn checked_mul(self, quantity: u64) -> Result<Self, ModelPricingError> {
        self.0
            .checked_mul(quantity)
            .filter(|value| *value <= MAX_MINOR_UNITS)
            .map(Self)
            .ok_or_else(|| error(ModelPricingErrorCode::Overflow))
    }
}

/// One immutable price for one usage dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriceEntry {
    dimension: PriceDimension,
    price: PriceMinorUnits,
}

impl PriceEntry {
    /// Returns the charged dimension.
    #[must_use]
    pub const fn dimension(self) -> PriceDimension {
        self.dimension
    }

    /// Returns the price per unit in minor currency units.
    #[must_use]
    pub const fn price(self) -> PriceMinorUnits {
        self.price
    }
}

/// A validated versioned schedule for one model and effective window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelPricingSchedule {
    model_id: Box<str>,
    currency: CurrencyCode,
    version: PricingVersion,
    window: EffectiveWindow,
    entries: Arc<[PriceEntry]>,
}

impl ModelPricingSchedule {
    /// Builds and freezes a schedule with deterministic dimension ordering.
    ///
    /// # Errors
    /// Returns a stable error for malformed identities, too many entries, or
    /// duplicate dimensions.
    pub fn new<I>(
        model_id: &str,
        currency: CurrencyCode,
        version: PricingVersion,
        window: EffectiveWindow,
        entries: I,
    ) -> Result<Self, ModelPricingError>
    where
        I: IntoIterator<Item = (PriceDimension, PriceMinorUnits)>,
    {
        if !valid_model_id(model_id) {
            return Err(error(ModelPricingErrorCode::InvalidArgument));
        }
        let mut entries = entries
            .into_iter()
            .map(|(dimension, price)| PriceEntry { dimension, price })
            .collect::<Vec<_>>();
        if entries.is_empty() || entries.len() > MAX_DIMENSIONS {
            return Err(error(ModelPricingErrorCode::LimitExceeded));
        }
        entries.sort_unstable_by_key(|entry| entry.dimension);
        if entries
            .windows(2)
            .any(|pair| pair[0].dimension == pair[1].dimension)
        {
            return Err(error(ModelPricingErrorCode::DuplicateDimension));
        }
        Ok(Self {
            model_id: model_id.into(),
            currency,
            version,
            window,
            entries: Arc::from(entries.into_boxed_slice()),
        })
    }

    /// Returns the provider-neutral model identity.
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Returns the schedule currency.
    #[must_use]
    pub const fn currency(&self) -> &CurrencyCode {
        &self.currency
    }

    /// Returns the immutable schedule version.
    #[must_use]
    pub const fn version(&self) -> PricingVersion {
        self.version
    }

    /// Returns the effective time window.
    #[must_use]
    pub const fn window(&self) -> EffectiveWindow {
        self.window
    }

    /// Returns entries in stable dimension order.
    #[must_use]
    pub fn entries(&self) -> &[PriceEntry] {
        &self.entries
    }

    fn price_for(&self, dimension: PriceDimension) -> Option<PriceMinorUnits> {
        self.entries
            .binary_search_by_key(&dimension, |entry| entry.dimension)
            .ok()
            .map(|index| self.entries[index].price)
    }
}

/// A charged quote carrying the schedule identity and checked total.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceQuote {
    currency: CurrencyCode,
    version: PricingVersion,
    dimension: PriceDimension,
    price: PriceMinorUnits,
    quantity: u64,
    total: PriceMinorUnits,
}

impl PriceQuote {
    /// Returns the quote currency.
    #[must_use]
    pub const fn currency(&self) -> &CurrencyCode {
        &self.currency
    }

    /// Returns the schedule version used.
    #[must_use]
    pub const fn version(&self) -> PricingVersion {
        self.version
    }

    /// Returns the charged dimension.
    #[must_use]
    pub const fn dimension(&self) -> PriceDimension {
        self.dimension
    }

    /// Returns the unit price.
    #[must_use]
    pub const fn price(&self) -> PriceMinorUnits {
        self.price
    }

    /// Returns the requested quantity.
    #[must_use]
    pub const fn quantity(&self) -> u64 {
        self.quantity
    }

    /// Returns the checked total charge.
    #[must_use]
    pub const fn total(&self) -> PriceMinorUnits {
        self.total
    }
}

/// An immutable deterministic collection of pricing schedules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PricingCatalog {
    schedules: Arc<[ModelPricingSchedule]>,
}

impl PricingCatalog {
    /// Validates and freezes schedules in canonical order.
    ///
    /// Schedules may coexist when windows differ. Overlap is rejected whenever
    /// a model and dimension would be ambiguous, including across currencies.
    ///
    /// # Errors
    /// Returns a stable bounded, duplicate, or overlap error.
    pub fn new<I>(schedules: I) -> Result<Self, ModelPricingError>
    where
        I: IntoIterator<Item = ModelPricingSchedule>,
    {
        let mut schedules = schedules.into_iter().collect::<Vec<_>>();
        if schedules.is_empty() || schedules.len() > MAX_SCHEDULES {
            return Err(error(ModelPricingErrorCode::LimitExceeded));
        }
        schedules.sort_unstable_by(|left, right| {
            left.model_id
                .cmp(&right.model_id)
                .then_with(|| left.currency.cmp(&right.currency))
                .then_with(|| left.window.start.cmp(&right.window.start))
                .then_with(|| left.version.cmp(&right.version))
        });
        validate_schedule_conflicts(&schedules)?;
        Ok(Self {
            schedules: Arc::from(schedules.into_boxed_slice()),
        })
    }

    /// Returns schedules in deterministic model, currency, and start order.
    #[must_use]
    pub fn schedules(&self) -> &[ModelPricingSchedule] {
        &self.schedules
    }

    /// Quotes one dimension at a UTC timestamp and quantity.
    ///
    /// # Errors
    /// Returns [`ModelPricingErrorCode::NotFound`] when no schedule or
    /// dimension applies, or [`ModelPricingErrorCode::Overflow`] on total cost.
    pub fn quote_at(
        &self,
        model_id: &str,
        dimension: PriceDimension,
        timestamp: u64,
        quantity: u64,
    ) -> Result<PriceQuote, ModelPricingError> {
        let schedule = self
            .schedules
            .iter()
            .find(|schedule| {
                schedule.model_id.as_ref() == model_id
                    && schedule.window.contains(timestamp)
                    && schedule.price_for(dimension).is_some()
            })
            .ok_or_else(|| error(ModelPricingErrorCode::NotFound))?;
        let price = schedule
            .price_for(dimension)
            .ok_or_else(|| error(ModelPricingErrorCode::NotFound))?;
        let total = price.checked_mul(quantity)?;
        Ok(PriceQuote {
            currency: schedule.currency.clone(),
            version: schedule.version,
            dimension,
            price,
            quantity,
            total,
        })
    }
}

fn validate_schedule_conflicts(
    schedules: &[ModelPricingSchedule],
) -> Result<(), ModelPricingError> {
    for (index, schedule) in schedules.iter().enumerate() {
        if let Some(code) = schedules
            .iter()
            .skip(index + 1)
            .find_map(|other| schedule_pair_error(schedule, other))
        {
            return Err(error(code));
        }
    }
    Ok(())
}

fn schedule_pair_error(
    left: &ModelPricingSchedule,
    right: &ModelPricingSchedule,
) -> Option<ModelPricingErrorCode> {
    if left.model_id != right.model_id {
        return None;
    }
    if left.version == right.version && left.window == right.window {
        return Some(ModelPricingErrorCode::DuplicateSchedule);
    }
    if left.window.overlaps(right.window) && shares_dimension(left, right) {
        return Some(ModelPricingErrorCode::OverlappingWindow);
    }
    None
}

fn shares_dimension(left: &ModelPricingSchedule, right: &ModelPricingSchedule) -> bool {
    left.entries
        .iter()
        .any(|entry| right.price_for(entry.dimension).is_some())
}

fn valid_model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MODEL_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

const fn error(code: ModelPricingErrorCode) -> ModelPricingError {
    ModelPricingError { code }
}

//! Ariadnion-owned bounded values at the RNMDB type boundary.

use std::ops::RangeInclusive;

use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_types::{SqlJson, SqlTimestamp, SqlUuid, SqlValue};

const UUID_BYTES: usize = 16;
const MIN_CURRENCY_BYTES: usize = 3;
const MAX_CURRENCY_BYTES: usize = 12;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const UTC_MICROS_RANGE: RangeInclusive<i64> =
    UtcTimestampMicros::MIN_EPOCH_MICROS..=UtcTimestampMicros::MAX_EPOCH_MICROS;

/// A non-nil 128-bit storage identity represented in network byte order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageUuid([u8; UUID_BYTES]);

impl StorageUuid {
    /// Validates a non-nil UUID byte sequence.
    pub fn new(bytes: [u8; UUID_BYTES]) -> Result<Self, StorageError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid_argument());
        }
        Ok(Self(bytes))
    }

    /// Returns the UUID bytes in network byte order.
    #[must_use]
    pub const fn bytes(self) -> [u8; UUID_BYTES] {
        self.0
    }

    /// Converts this value to the explicit RNMDB UUID adapter type.
    #[must_use]
    pub fn to_sql_uuid(self) -> SqlUuid {
        SqlUuid::from_bytes(self.0)
    }

    /// Converts this value to an RNMDB UUID SQL value.
    #[must_use]
    pub fn to_sql_value(self) -> SqlValue {
        SqlValue::Uuid(self.to_sql_uuid())
    }

    /// Validates an RNMDB UUID adapter value at the Ariadnion boundary.
    pub fn try_from_sql_uuid(value: SqlUuid) -> Result<Self, StorageError> {
        Self::new(value.as_bytes())
    }

    /// Decodes an RNMDB SQL value only when it contains a non-nil UUID.
    pub fn try_from_sql_value(value: &SqlValue) -> Result<Self, StorageError> {
        match value {
            SqlValue::Uuid(value) => Self::try_from_sql_uuid(*value),
            _ => Err(invalid_argument()),
        }
    }
}

/// A UTC timestamp stored as signed microseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcTimestampMicros(i64);

impl UtcTimestampMicros {
    /// Earliest supported UTC instant, `0001-01-01T00:00:00Z`.
    pub const MIN_EPOCH_MICROS: i64 = -62_135_596_800_000_000;
    /// Latest supported UTC instant, `9999-12-31T23:59:59.999999Z`.
    pub const MAX_EPOCH_MICROS: i64 = 253_402_300_799_999_999;

    /// Validates UTC microseconds within the supported civil-time range.
    pub fn new(epoch_micros: i64) -> Result<Self, StorageError> {
        if !UTC_MICROS_RANGE.contains(&epoch_micros) {
            return Err(invalid_argument());
        }
        Ok(Self(epoch_micros))
    }

    /// Returns signed microseconds since the Unix epoch.
    #[must_use]
    pub const fn epoch_micros(self) -> i64 {
        self.0
    }

    /// Converts this value to the explicit RNMDB timestamp adapter type.
    #[must_use]
    pub fn to_sql_timestamp(self) -> SqlTimestamp {
        SqlTimestamp::from_epoch_micros(self.0)
    }

    /// Converts this value to an RNMDB timestamp SQL value.
    #[must_use]
    pub fn to_sql_value(self) -> SqlValue {
        SqlValue::Timestamp(self.to_sql_timestamp())
    }

    /// Validates an RNMDB timestamp adapter value at the Ariadnion boundary.
    pub fn try_from_sql_timestamp(value: SqlTimestamp) -> Result<Self, StorageError> {
        Self::new(value.epoch_micros())
    }

    /// Decodes an RNMDB SQL value only when it contains a bounded timestamp.
    pub fn try_from_sql_value(value: &SqlValue) -> Result<Self, StorageError> {
        match value {
            SqlValue::Timestamp(value) => Self::try_from_sql_timestamp(*value),
            _ => Err(invalid_argument()),
        }
    }
}

/// A bounded uppercase ASCII currency or billing-unit code.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CurrencyCode(Box<str>);

impl CurrencyCode {
    /// Maximum encoded currency length in bytes.
    pub const MAX_BYTES: usize = MAX_CURRENCY_BYTES;

    /// Parses three to twelve uppercase ASCII letters or digits.
    ///
    /// The first byte must be an uppercase letter. Inputs exceeding the byte
    /// bound return [`StorageErrorCode::ResourceExhausted`]; malformed bounded
    /// inputs return [`StorageErrorCode::InvalidArgument`].
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        validate_currency_bound(value)?;
        if !valid_currency_text(value) {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated currency code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An integer amount paired with its explicit currency or billing unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoneyValue {
    currency: CurrencyCode,
    minor_units: i64,
}

impl MoneyValue {
    /// Creates an amount from validated currency and signed minor units.
    #[must_use]
    pub const fn new(currency: CurrencyCode, minor_units: i64) -> Self {
        Self {
            currency,
            minor_units,
        }
    }

    /// Returns the currency or billing unit.
    #[must_use]
    pub const fn currency(&self) -> &CurrencyCode {
        &self.currency
    }

    /// Returns the signed amount in the currency's smallest unit.
    #[must_use]
    pub const fn minor_units(&self) -> i64 {
        self.minor_units
    }

    /// Converts this amount to RNMDB `INT64` and `TEXT` column values.
    #[must_use]
    pub fn to_sql_values(&self) -> (SqlValue, SqlValue) {
        (
            SqlValue::Int64(self.minor_units),
            SqlValue::Text(self.currency.as_str().into()),
        )
    }

    /// Decodes RNMDB `INT64` minor units and a bounded `TEXT` currency.
    ///
    /// Float and other numeric variants are rejected to keep money arithmetic
    /// integer-only across the storage boundary.
    pub fn try_from_sql_values(
        minor_units: &SqlValue,
        currency: &SqlValue,
    ) -> Result<Self, StorageError> {
        let SqlValue::Int64(minor_units) = minor_units else {
            return Err(invalid_argument());
        };
        let SqlValue::Text(currency) = currency else {
            return Err(invalid_argument());
        };
        CurrencyCode::parse(currency).map(|currency| Self::new(currency, *minor_units))
    }
}

/// Bounded JSON text normalized by the reviewed RNMDB JSON codec.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NormalizedJson(Box<str>);

impl NormalizedJson {
    /// Maximum accepted UTF-8 JSON length in bytes.
    pub const MAX_BYTES: usize = MAX_JSON_BYTES;

    /// Parses, validates, and normalizes a bounded JSON document.
    ///
    /// Invalid JSON maps to [`StorageErrorCode::InvalidArgument`] without
    /// retaining the upstream error text. Callers remain responsible for
    /// validating application-specific schemas before persistence.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        validate_json_bound(value)?;
        let normalized = SqlJson::parse_str(value).map_err(|_| invalid_argument())?;
        validate_json_bound(normalized.as_str())?;
        Ok(Self(normalized.as_str().into()))
    }

    /// Returns normalized JSON text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }

    /// Converts normalized text to the explicit RNMDB JSON adapter type.
    ///
    /// A failure indicates an internal invariant violation and is projected as
    /// [`StorageErrorCode::Internal`] without exposing upstream diagnostics.
    pub fn to_sql_json(&self) -> Result<SqlJson, StorageError> {
        SqlJson::parse_str(self.text()).map_err(|_| internal_error())
    }

    /// Converts normalized text to an RNMDB JSON SQL value.
    pub fn to_sql_value(&self) -> Result<SqlValue, StorageError> {
        self.to_sql_json().map(SqlValue::Json)
    }

    /// Imports a bounded normalized RNMDB JSON adapter value.
    pub fn try_from_sql_json(value: &SqlJson) -> Result<Self, StorageError> {
        validate_json_bound(value.as_str())?;
        Ok(Self(value.as_str().into()))
    }

    /// Decodes an RNMDB SQL value only when it contains bounded JSON.
    pub fn try_from_sql_value(value: &SqlValue) -> Result<Self, StorageError> {
        match value {
            SqlValue::Json(value) => Self::try_from_sql_json(value),
            _ => Err(invalid_argument()),
        }
    }
}

fn validate_currency_bound(value: &str) -> Result<(), StorageError> {
    if value.len() > MAX_CURRENCY_BYTES {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn valid_currency_text(value: &str) -> bool {
    let valid_length = value.len() >= MIN_CURRENCY_BYTES;
    let valid_first = value.as_bytes().first().is_some_and(u8::is_ascii_uppercase);
    let valid_rest = value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
    valid_length && valid_first && valid_rest
}

fn validate_json_bound(value: &str) -> Result<(), StorageError> {
    if value.len() > MAX_JSON_BYTES {
        return Err(resource_exhausted());
    }
    Ok(())
}

const fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

const fn internal_error() -> StorageError {
    StorageError::new(StorageErrorCode::Internal)
}

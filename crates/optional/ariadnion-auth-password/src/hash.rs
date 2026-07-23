//! Bounded Argon2id hashing and progressive parameter upgrades.

use std::fmt::{self, Debug, Formatter};

use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;

use crate::{PasswordError, PasswordErrorCode, PasswordSecret};

const MIN_MEMORY_KIB: u32 = 19_456;
const MAX_MEMORY_KIB: u32 = 1_048_576;
const MIN_ITERATIONS: u32 = 1;
const MAX_ITERATIONS: u32 = 10;
const MIN_LANES: u32 = 1;
const MAX_LANES: u32 = 16;
const HASH_OUTPUT_BYTES: usize = 32;
const SALT_BYTES: usize = 16;

/// Validated Argon2id resource parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2idParameters {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl Argon2idParameters {
    /// Creates parameters within the supported resource envelope.
    ///
    /// Memory is measured in kibibytes and must be between 19,456 and
    /// 1,048,576 inclusive. Iterations must be between 1 and 10 inclusive,
    /// and lanes must be between 1 and 16 inclusive.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidHashParameters`] when any value is
    /// outside its supported range.
    pub fn new(memory_kib: u32, iterations: u32, lanes: u32) -> Result<Self, PasswordError> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory_kib)
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
            || !(MIN_LANES..=MAX_LANES).contains(&lanes)
        {
            return Err(invalid_parameters());
        }
        Ok(Self {
            memory_kib,
            iterations,
            lanes,
        })
    }

    /// Returns the memory cost in kibibytes.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Returns the iteration count.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Returns the lane count.
    #[must_use]
    pub const fn lanes(self) -> u32 {
        self.lanes
    }

    const fn fits_within(self, maximum: Self) -> bool {
        self.memory_kib <= maximum.memory_kib
            && self.iterations <= maximum.iterations
            && self.lanes <= maximum.lanes
    }

    fn argon2_params(self) -> Result<Params, PasswordError> {
        Params::new(
            self.memory_kib,
            self.iterations,
            self.lanes,
            Some(HASH_OUTPUT_BYTES),
        )
        .map_err(|_| hash_operation_failed())
    }
}

/// A caller-provided fixed-width password salt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PasswordSalt([u8; SALT_BYTES]);

impl PasswordSalt {
    /// Owns exactly 16 bytes supplied by the caller's secure random source.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SALT_BYTES]) -> Self {
        Self(bytes)
    }
}

/// An owned, structurally validated Argon2id PHC record.
#[derive(Clone, Eq, PartialEq)]
pub struct PasswordHashRecord(Box<str>);

impl PasswordHashRecord {
    /// Maximum accepted PHC record length in bytes.
    pub const MAX_BYTES: usize = 512;

    /// Parses and owns a supported Argon2id version 19 PHC record.
    ///
    /// The record must contain exactly the `m`, `t`, and `p` parameters, a
    /// 16-byte salt, and a 32-byte hash output. This function performs no
    /// password hashing.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidHashRecord`] when the record is too
    /// long, malformed, unsupported, or outside the absolute parameter bounds.
    pub fn parse(value: &str) -> Result<Self, PasswordError> {
        validate_record(value)?;
        Ok(Self(value.into()))
    }

    /// Borrows the validated PHC representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the fixed password-hash algorithm identifier.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        "argon2id"
    }

    /// Returns the Argon2 version encoded by every accepted record.
    #[must_use]
    pub const fn algorithm_version(&self) -> u32 {
        19
    }

    /// Revalidates and returns the resource parameters encoded in the record.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidHashRecord`] if the owned record no
    /// longer satisfies its construction invariant.
    pub fn parameters(&self) -> Result<Argon2idParameters, PasswordError> {
        parse_record(self.as_str()).map(|record| record.parameters)
    }
}

impl Debug for PasswordHashRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let _record = &self.0;
        formatter.write_str("PasswordHashRecord(<redacted>)")
    }
}

/// The result of checking a password against a supported hash record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordVerification {
    /// The supplied password does not match the record.
    Invalid,
    /// The password matches and the record uses the current parameters.
    ValidCurrent,
    /// The password matches but the record should be replaced after login.
    ValidNeedsRehash,
}

/// A bounded Argon2id hashing and verification engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2idEngine {
    current: Argon2idParameters,
    maximum_verify: Argon2idParameters,
}

impl Argon2idEngine {
    /// Creates an engine with current hashing and maximum verification costs.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidHashParameters`] when any current
    /// cost exceeds its corresponding verification maximum.
    pub fn new(
        current: Argon2idParameters,
        maximum_verify: Argon2idParameters,
    ) -> Result<Self, PasswordError> {
        if !current.fits_within(maximum_verify) {
            return Err(invalid_parameters());
        }
        Ok(Self {
            current,
            maximum_verify,
        })
    }

    /// Hashes a password into an Argon2id version 19 PHC record.
    ///
    /// This synchronous operation is CPU- and memory-intensive. Async callers
    /// must run it on a bounded blocking pool and propagate cancellation and
    /// deadlines at the adapter boundary.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error if the cryptographic operation fails.
    pub fn hash(
        &self,
        secret: &PasswordSecret,
        salt: PasswordSalt,
    ) -> Result<PasswordHashRecord, PasswordError> {
        let context = argon2_context(self.current)?;
        let encoded_salt = SaltString::encode_b64(&salt.0).map_err(|_| hash_operation_failed())?;
        let hash = context
            .hash_password(secret.bytes(), encoded_salt.as_salt())
            .map_err(|_| hash_operation_failed())?;
        PasswordHashRecord::parse(&hash.to_string()).map_err(|_| hash_operation_failed())
    }

    /// Verifies a password after structural and resource-budget validation.
    ///
    /// This synchronous operation is CPU- and memory-intensive. Async callers
    /// must run it on a bounded blocking pool and propagate cancellation and
    /// deadlines at the adapter boundary. A password mismatch returns
    /// [`PasswordVerification::Invalid`] rather than an error.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when the record is malformed, exceeds
    /// the verification budget, or the cryptographic operation fails.
    pub fn verify(
        &self,
        secret: &PasswordSecret,
        record: &PasswordHashRecord,
    ) -> Result<PasswordVerification, PasswordError> {
        let parsed = parse_record(record.as_str())?;
        if !parsed.parameters.fits_within(self.maximum_verify) {
            return Err(verification_budget_exceeded());
        }
        let mut computed = [0u8; HASH_OUTPUT_BYTES];
        argon2_context(parsed.parameters)?
            .hash_password_into(secret.bytes(), &parsed.salt, &mut computed)
            .map_err(|_| hash_operation_failed())?;
        Ok(classify_verification(
            bool::from(computed.ct_eq(&parsed.output)),
            parsed.parameters,
            self.current,
        ))
    }
}

struct ParsedRecord {
    parameters: Argon2idParameters,
    salt: [u8; SALT_BYTES],
    output: [u8; HASH_OUTPUT_BYTES],
}

fn validate_record(value: &str) -> Result<(), PasswordError> {
    let _parsed = parse_record(value)?;
    Ok(())
}

fn parse_record(value: &str) -> Result<ParsedRecord, PasswordError> {
    validate_record_length(value)?;
    let hash = PasswordHash::new(value).map_err(|_| invalid_record())?;
    validate_identity(&hash)?;
    Ok(ParsedRecord {
        parameters: parse_parameters(&hash)?,
        salt: decode_salt(&hash)?,
        output: copy_output(&hash)?,
    })
}

fn validate_record_length(value: &str) -> Result<(), PasswordError> {
    if value.len() > PasswordHashRecord::MAX_BYTES {
        return Err(invalid_record());
    }
    Ok(())
}

fn validate_identity(hash: &PasswordHash<'_>) -> Result<(), PasswordError> {
    if hash.algorithm.as_str() != "argon2id" || hash.version != Some(19) {
        return Err(invalid_record());
    }
    Ok(())
}

fn parse_parameters(hash: &PasswordHash<'_>) -> Result<Argon2idParameters, PasswordError> {
    if hash.params.iter().count() != 3 {
        return Err(invalid_record());
    }
    let memory_kib = hash.params.get_decimal("m").ok_or_else(invalid_record)?;
    let iterations = hash.params.get_decimal("t").ok_or_else(invalid_record)?;
    let lanes = hash.params.get_decimal("p").ok_or_else(invalid_record)?;
    Argon2idParameters::new(memory_kib, iterations, lanes).map_err(|_| invalid_record())
}

fn decode_salt(hash: &PasswordHash<'_>) -> Result<[u8; SALT_BYTES], PasswordError> {
    let encoded = hash.salt.ok_or_else(invalid_record)?;
    let mut salt = [0u8; SALT_BYTES];
    let decoded = encoded
        .decode_b64(&mut salt)
        .map_err(|_| invalid_record())?;
    if decoded.len() != SALT_BYTES {
        return Err(invalid_record());
    }
    Ok(salt)
}

fn copy_output(hash: &PasswordHash<'_>) -> Result<[u8; HASH_OUTPUT_BYTES], PasswordError> {
    let encoded = hash.hash.ok_or_else(invalid_record)?;
    if encoded.len() != HASH_OUTPUT_BYTES {
        return Err(invalid_record());
    }
    let mut output = [0u8; HASH_OUTPUT_BYTES];
    output.copy_from_slice(encoded.as_bytes());
    Ok(output)
}

fn argon2_context(parameters: Argon2idParameters) -> Result<Argon2<'static>, PasswordError> {
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        parameters.argon2_params()?,
    ))
}

fn classify_verification(
    matches: bool,
    record: Argon2idParameters,
    current: Argon2idParameters,
) -> PasswordVerification {
    if !matches {
        PasswordVerification::Invalid
    } else if record == current {
        PasswordVerification::ValidCurrent
    } else {
        PasswordVerification::ValidNeedsRehash
    }
}

const fn invalid_parameters() -> PasswordError {
    PasswordError::new(PasswordErrorCode::InvalidHashParameters)
}

const fn invalid_record() -> PasswordError {
    PasswordError::new(PasswordErrorCode::InvalidHashRecord)
}

const fn verification_budget_exceeded() -> PasswordError {
    PasswordError::new(PasswordErrorCode::HashVerificationBudgetExceeded)
}

const fn hash_operation_failed() -> PasswordError {
    PasswordError::new(PasswordErrorCode::HashOperationFailed)
}

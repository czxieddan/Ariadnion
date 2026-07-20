//! Bounded plaintext password ownership with zeroization on drop.

use std::fmt::{self, Debug, Formatter};

use zeroize::Zeroizing;

use crate::{PasswordError, PasswordErrorCode};

/// Validated scalar and byte bounds for password admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordLimits {
    min_scalars: u16,
    max_scalars: u16,
    max_bytes: u16,
}

impl PasswordLimits {
    /// Creates coherent password bounds.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidLimits`] when the minimum is zero,
    /// the minimum exceeds the scalar maximum, or the scalar maximum exceeds
    /// the byte maximum.
    pub fn new(min_scalars: u16, max_scalars: u16, max_bytes: u16) -> Result<Self, PasswordError> {
        if min_scalars == 0 || min_scalars > max_scalars || max_scalars > max_bytes {
            return Err(PasswordError::new(PasswordErrorCode::InvalidLimits));
        }
        Ok(Self {
            min_scalars,
            max_scalars,
            max_bytes,
        })
    }
}

/// An owned plaintext password whose allocation is zeroized on drop.
pub struct PasswordSecret(Zeroizing<Vec<u8>>);

impl PasswordSecret {
    /// Validates and owns a plaintext password.
    ///
    /// Byte length is checked before Unicode scalar counting and before the
    /// plaintext allocation is cloned. Unicode input is not normalized.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when the input is empty, violates the
    /// supplied limits, or contains a NUL scalar.
    pub fn parse(value: &str, limits: PasswordLimits) -> Result<Self, PasswordError> {
        validate_byte_length(value, limits)?;
        validate_scalars(value, limits)?;
        Ok(Self(Zeroizing::new(value.as_bytes().to_vec())))
    }
}

fn validate_byte_length(value: &str, limits: PasswordLimits) -> Result<(), PasswordError> {
    if value.is_empty() {
        return Err(PasswordError::new(PasswordErrorCode::Empty));
    }
    if value.len() > usize::from(limits.max_bytes) {
        return Err(PasswordError::new(PasswordErrorCode::TooManyBytes));
    }
    Ok(())
}

fn validate_scalars(value: &str, limits: PasswordLimits) -> Result<(), PasswordError> {
    if value.contains('\0') {
        return Err(PasswordError::new(PasswordErrorCode::ContainsNul));
    }
    let scalar_count = value.chars().count();
    if scalar_count < usize::from(limits.min_scalars) {
        return Err(PasswordError::new(PasswordErrorCode::TooShort));
    }
    if scalar_count > usize::from(limits.max_scalars) {
        return Err(PasswordError::new(PasswordErrorCode::TooManyScalars));
    }
    Ok(())
}

impl Debug for PasswordSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let _secret_allocation = &self.0;
        formatter.write_str("PasswordSecret(<redacted>)")
    }
}

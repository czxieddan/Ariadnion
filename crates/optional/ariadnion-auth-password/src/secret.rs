// crates/optional/ariadnion-auth-password/src/secret.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
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
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
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

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_slice()
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

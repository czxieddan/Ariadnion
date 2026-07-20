//! Stable redacted password-domain errors.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

const ERROR_CODES: [&str; 6] = [
    "PASSWORD_INVALID_LIMITS",
    "PASSWORD_EMPTY",
    "PASSWORD_TOO_SHORT",
    "PASSWORD_TOO_MANY_BYTES",
    "PASSWORD_TOO_MANY_SCALARS",
    "PASSWORD_CONTAINS_NUL",
];

/// A stable machine-readable password failure code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum PasswordErrorCode {
    /// The configured scalar or byte bounds are inconsistent.
    InvalidLimits = 0,
    /// The supplied password is empty.
    Empty = 1,
    /// The supplied password has fewer Unicode scalars than required.
    TooShort = 2,
    /// The supplied password exceeds the byte budget.
    TooManyBytes = 3,
    /// The supplied password exceeds the Unicode scalar budget.
    TooManyScalars = 4,
    /// The supplied password contains a NUL scalar.
    ContainsNul = 5,
}

impl PasswordErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        ERROR_CODES[self as usize]
    }
}

/// A redacted password admission error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordError {
    code: PasswordErrorCode,
}

impl PasswordError {
    pub(crate) const fn new(code: PasswordErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> PasswordErrorCode {
        self.code
    }
}

impl Display for PasswordError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for PasswordError {}

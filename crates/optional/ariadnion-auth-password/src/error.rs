//! Stable redacted password-domain errors.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

const ERROR_CODES: [&str; 29] = [
    "PASSWORD_INVALID_LIMITS",
    "PASSWORD_EMPTY",
    "PASSWORD_TOO_SHORT",
    "PASSWORD_TOO_MANY_BYTES",
    "PASSWORD_TOO_MANY_SCALARS",
    "PASSWORD_CONTAINS_NUL",
    "PASSWORD_EXPLICITLY_DENIED",
    "PASSWORD_COMPROMISED",
    "PASSWORD_BREACH_CHECK_UNAVAILABLE",
    "PASSWORD_BREACH_ASSESSMENT_MISMATCH",
    "PASSWORD_TOO_MANY_DENIED_FINGERPRINTS",
    "PASSWORD_DUPLICATE_DENIED_FINGERPRINT",
    "PASSWORD_INVALID_BREACH_SOURCE_VERSION",
    "PASSWORD_INVALID_HASH_PARAMETERS",
    "PASSWORD_INVALID_HASH_RECORD",
    "PASSWORD_HASH_VERIFICATION_BUDGET_EXCEEDED",
    "PASSWORD_HASH_OPERATION_FAILED",
    "PASSWORD_INVALID_RESET_ARGUMENT",
    "PASSWORD_INVALID_RESET_LIFETIME",
    "PASSWORD_INVALID_RESET_EVIDENCE",
    "PASSWORD_INVALID_RESET_TIME",
    "PASSWORD_RESET_VERSION_CONFLICT",
    "PASSWORD_RESET_VERSION_EXHAUSTED",
    "PASSWORD_RESET_ALREADY_CONSUMED",
    "PASSWORD_RESET_REVOKED",
    "PASSWORD_RESET_EXPIRED",
    "PASSWORD_RESET_NOT_YET_EXPIRED",
    "PASSWORD_INVALID_CREDENTIAL_ARGUMENT",
    "PASSWORD_CREDENTIAL_VERSION_EXHAUSTED",
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
    /// The supplied password matches an explicitly denied fingerprint.
    ExplicitlyDenied = 6,
    /// The supplied password is known to be compromised.
    Compromised = 7,
    /// The required breach check did not produce a security decision.
    BreachCheckUnavailable = 8,
    /// The breach assessment belongs to a different password fingerprint.
    BreachAssessmentMismatch = 9,
    /// The policy contains more denied fingerprints than the supported bound.
    TooManyDeniedFingerprints = 10,
    /// The policy contains the same denied fingerprint more than once.
    DuplicateDeniedFingerprint = 11,
    /// The breach source version is empty, non-ASCII, or too long.
    InvalidBreachSourceVersion = 12,
    /// The configured Argon2id parameters violate the supported bounds.
    InvalidHashParameters = 13,
    /// The supplied password hash record is malformed or unsupported.
    InvalidHashRecord = 14,
    /// The password hash record requests work beyond the verification budget.
    HashVerificationBudgetExceeded = 15,
    /// The cryptographic hashing operation failed without exposing internals.
    HashOperationFailed = 16,
    /// A password-reset identifier, version, token, or bounded input is invalid.
    InvalidResetArgument = 17,
    /// A password-reset validity window is empty, reversed, too long, or unrepresentable.
    InvalidResetLifetime = 18,
    /// Password-reset subject or token evidence does not match the aggregate.
    InvalidResetEvidence = 19,
    /// A password-reset command occurred before the trusted issuance time.
    InvalidResetTime = 20,
    /// The caller supplied a stale optimistic password-reset version.
    ResetVersionConflict = 21,
    /// The password-reset version cannot advance beyond `u64::MAX`.
    ResetVersionExhausted = 22,
    /// A consumed password reset rejected another lifecycle command.
    ResetAlreadyConsumed = 23,
    /// A revoked password reset rejected another lifecycle command.
    ResetRevoked = 24,
    /// A password reset expired or reached its exclusive expiry boundary.
    ResetExpired = 25,
    /// Expiry was requested before the password-reset expiry boundary.
    ResetNotYetExpired = 26,
    /// A credential identity, version, policy version, or hash record is invalid.
    InvalidCredentialArgument = 27,
    /// The password-credential version cannot advance beyond `u64::MAX`.
    CredentialVersionExhausted = 28,
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

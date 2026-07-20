//! Bounded password denylist and breach-assessment decisions.

use std::fmt::{self, Debug, Formatter};

use sha2::{Digest, Sha256};

use crate::{PasswordError, PasswordErrorCode, PasswordLimits, PasswordSecret};

/// A redacted SHA-256 fingerprint of validated password bytes.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PasswordFingerprint([u8; 32]);

impl PasswordFingerprint {
    /// Computes the SHA-256 fingerprint of an owned validated password.
    #[must_use]
    pub fn from_secret(secret: &PasswordSecret) -> Self {
        Self(Sha256::digest(secret.bytes()).into())
    }
}

impl Debug for PasswordFingerprint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordFingerprint(<sha256>)")
    }
}

/// The fail-closed result of an external password breach check.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BreachStatus {
    /// The checked password was not present in the breach source.
    NotCompromised,
    /// The checked password was present in the breach source.
    Compromised,
    /// The breach source could not provide a trustworthy decision.
    Unavailable,
}

/// A bounded breach result tied to one exact password fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BreachAssessment {
    fingerprint: PasswordFingerprint,
    status: BreachStatus,
    source_version: Box<str>,
}

impl BreachAssessment {
    /// Maximum accepted breach-source version length in ASCII bytes.
    pub const MAX_SOURCE_VERSION_BYTES: usize = 128;

    /// Creates a fingerprint-bound breach result from a versioned source.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::InvalidBreachSourceVersion`] when the
    /// source version is empty, non-ASCII, or longer than 128 bytes.
    pub fn new(
        fingerprint: PasswordFingerprint,
        status: BreachStatus,
        source_version: &str,
    ) -> Result<Self, PasswordError> {
        validate_source_version(source_version)?;
        Ok(Self {
            fingerprint,
            status,
            source_version: source_version.into(),
        })
    }
}

/// Validated password limits and a bounded sorted fingerprint denylist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordPolicy {
    limits: PasswordLimits,
    denied: Vec<PasswordFingerprint>,
}

impl PasswordPolicy {
    /// Maximum number of unique fingerprints accepted by one policy.
    pub const MAX_DENIED_FINGERPRINTS: usize = 4_096;

    /// Creates a bounded policy and canonicalizes its denylist ordering.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordErrorCode::TooManyDeniedFingerprints`] above the
    /// 4,096-entry limit, or [`PasswordErrorCode::DuplicateDeniedFingerprint`]
    /// when any fingerprint occurs more than once.
    pub fn new(
        limits: PasswordLimits,
        mut denied: Vec<PasswordFingerprint>,
    ) -> Result<Self, PasswordError> {
        if denied.len() > Self::MAX_DENIED_FINGERPRINTS {
            return Err(PasswordError::new(
                PasswordErrorCode::TooManyDeniedFingerprints,
            ));
        }
        denied.sort_unstable();
        if denied.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PasswordError::new(
                PasswordErrorCode::DuplicateDeniedFingerprint,
            ));
        }
        Ok(Self { limits, denied })
    }
}

/// Admits a password only after policy and fingerprint-bound breach checks.
///
/// The password is validated before hashing. Assessment equality is evaluated
/// in constant time, and unavailable breach checks fail closed.
///
/// # Errors
///
/// Returns a stable redacted error when the plaintext violates its limits, the
/// assessment belongs to another password, the fingerprint is denied, or the
/// breach result is not safe for admission.
pub fn admit_password(
    value: &str,
    policy: &PasswordPolicy,
    assessment: &BreachAssessment,
) -> Result<PasswordSecret, PasswordError> {
    let secret = PasswordSecret::parse(value, policy.limits)?;
    let fingerprint = PasswordFingerprint::from_secret(&secret);
    require_assessment_binding(fingerprint, assessment.fingerprint)?;
    require_not_denied(fingerprint, &policy.denied)?;
    require_not_compromised(assessment.status)?;
    Ok(secret)
}

fn validate_source_version(source_version: &str) -> Result<(), PasswordError> {
    if source_version.is_empty()
        || source_version.len() > BreachAssessment::MAX_SOURCE_VERSION_BYTES
        || !source_version.is_ascii()
    {
        return Err(PasswordError::new(
            PasswordErrorCode::InvalidBreachSourceVersion,
        ));
    }
    Ok(())
}

fn require_assessment_binding(
    actual: PasswordFingerprint,
    assessed: PasswordFingerprint,
) -> Result<(), PasswordError> {
    if !constant_time_digest_eq(actual.0, assessed.0) {
        return Err(PasswordError::new(
            PasswordErrorCode::BreachAssessmentMismatch,
        ));
    }
    Ok(())
}

fn require_not_denied(
    fingerprint: PasswordFingerprint,
    denied: &[PasswordFingerprint],
) -> Result<(), PasswordError> {
    if denied.binary_search(&fingerprint).is_ok() {
        return Err(PasswordError::new(PasswordErrorCode::ExplicitlyDenied));
    }
    Ok(())
}

fn require_not_compromised(status: BreachStatus) -> Result<(), PasswordError> {
    match status {
        BreachStatus::NotCompromised => Ok(()),
        BreachStatus::Compromised => Err(PasswordError::new(PasswordErrorCode::Compromised)),
        BreachStatus::Unavailable => Err(PasswordError::new(
            PasswordErrorCode::BreachCheckUnavailable,
        )),
    }
}

fn constant_time_digest_eq(left: [u8; 32], right: [u8; 32]) -> bool {
    left.into_iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

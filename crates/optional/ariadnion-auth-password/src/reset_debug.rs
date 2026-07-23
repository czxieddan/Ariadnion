//! Redacted formatters for password-reset identity and digest values.

use std::fmt::{self, Debug, Formatter};

use crate::reset::{PasswordHashRecordDigest, PasswordResetId, PasswordResetTokenDigest};

impl Debug for PasswordResetId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordResetId(<opaque>)")
    }
}

impl Debug for PasswordResetTokenDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordResetTokenDigest(<sha256>)")
    }
}

impl Debug for PasswordHashRecordDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHashRecordDigest(<sha256>)")
    }
}

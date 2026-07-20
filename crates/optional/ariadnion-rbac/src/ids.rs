//! Bounded authorization identities and policy versions.

use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU64;

use crate::error::{AuthorizationError, AuthorizationErrorCode, error};

const MAX_ID_BYTES: usize = 128;

macro_rules! bounded_id {
    ($name:ident, $documentation:literal, $debug_name:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses a non-empty ASCII identity of at most 128 bytes.
            ///
            /// # Errors
            /// Returns [`AuthorizationErrorCode::InvalidArgument`] without
            /// retaining or formatting the rejected value.
            pub fn parse(value: &str) -> Result<Self, AuthorizationError> {
                if !valid_id(value) {
                    return Err(error(AuthorizationErrorCode::InvalidArgument));
                }
                Ok(Self(value.into()))
            }

            /// Returns the validated identity.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($debug_name, "(<opaque>)"))
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

bounded_id!(
    AssignmentId,
    "A bounded role-assignment identity.",
    "AssignmentId"
);
bounded_id!(
    DecisionId,
    "A bounded authorization-decision identity.",
    "DecisionId"
);
bounded_id!(
    PermissionId,
    "A bounded permission identity.",
    "PermissionId"
);
bounded_id!(
    ResourceId,
    "A bounded protected-resource identity.",
    "ResourceId"
);
bounded_id!(
    ResourceKind,
    "A bounded protected-resource kind.",
    "ResourceKind"
);
bounded_id!(RoleId, "A bounded authorization-role identity.", "RoleId");

/// A non-zero immutable authorization policy version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolicyVersion(NonZeroU64);

impl PolicyVersion {
    /// Returns the first policy version.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero policy version.
    ///
    /// # Errors
    /// Returns [`AuthorizationErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, AuthorizationError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(AuthorizationErrorCode::InvalidArgument))
    }

    /// Returns the numeric policy version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(is_id_byte)
}

fn is_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

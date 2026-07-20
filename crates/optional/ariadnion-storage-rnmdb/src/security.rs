//! Fail-closed column-key injection for managed encrypted columns.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, StorageInstanceId};
use rnmdb_security::ColumnKeyMaterial as UpstreamColumnKeyMaterial;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::RnmdbSessionOwner;
use crate::session::ColumnEncryptionTarget;

const SECRET_LOCATOR_TARGET: ColumnEncryptionTarget =
    ColumnEncryptionTarget::new("public", "platform_secret_references", "locator");

/// Single-consumption key input for encrypted secret-reference locators.
///
/// Ariadnion-owned bytes are zeroized on drop. RNMDB retains its own key copy
/// for the lifetime of the local session, so the key must be reinjected after
/// every reopen and the session must remain within the secret-bearing module.
pub struct SecretLocatorKeyMaterial {
    bytes: [u8; 32],
}

impl SecretLocatorKeyMaterial {
    /// Takes ownership of exactly 32 key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    fn into_upstream_key(self) -> UpstreamColumnKeyMaterial {
        UpstreamColumnKeyMaterial::from_bytes(self.bytes)
    }
}

impl Debug for SecretLocatorKeyMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretLocatorKeyMaterial(<redacted>)")
    }
}

impl Zeroize for SecretLocatorKeyMaterial {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SecretLocatorKeyMaterial {}

impl Drop for SecretLocatorKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Configures managed column encryption on one serialized RNMDB session.
pub struct RnmdbColumnSecurity {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbColumnSecurity {
    /// Creates a column-security adapter for one isolated session.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Returns the storage instance protected by this adapter.
    #[must_use]
    pub fn instance(&self) -> &StorageInstanceId {
        self.session.instance()
    }

    /// Injects the locator column key once for the current session lifetime.
    ///
    /// Repeated injection returns a conflict instead of silently replacing a
    /// live key. Missing schema, an unencrypted column, cancellation, and
    /// upstream security failures map to stable storage errors.
    pub fn configure_secret_locator(
        &self,
        key: SecretLocatorKeyMaterial,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        self.session.configure_column_encryption_once(
            SECRET_LOCATOR_TARGET,
            key.into_upstream_key(),
            context,
        )
    }
}

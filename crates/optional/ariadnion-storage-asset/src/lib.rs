//! Database-independent contracts for content-addressed local asset storage.
//!
//! The contracts expose tenant-scoped asset identities and opaque staging
//! capabilities. Local-volume paths, hashing implementations, and filesystem
//! operations remain private to adapters.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Read, Write};
use std::num::NonZeroU64;

use ariadnion_core::{RequestContext, TenantId};
pub use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A SHA-256 digest used as an immutable asset content address.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssetDigest([u8; 32]);

impl AssetDigest {
    /// The exact number of bytes in a SHA-256 digest.
    pub const BYTE_LENGTH: usize = 32;

    /// Creates a digest from exactly 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

impl Display for AssetDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Debug for AssetDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "AssetDigest({self})")
    }
}

/// A validated concrete media type without parameters.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssetMediaType(Box<str>);

impl AssetMediaType {
    /// The maximum encoded length of a media type.
    pub const MAX_BYTES: usize = 255;

    /// Parses and normalizes an ASCII `type/subtype` value.
    ///
    /// Wildcards, parameters, whitespace, controls, and values longer than
    /// 255 bytes are rejected with [`StorageErrorCode::InvalidArgument`].
    /// Type and subtype tokens are normalized to ASCII lowercase.
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        validate_media_type_bounds(value)?;
        validate_media_type_shape(value)?;
        Ok(Self(value.to_ascii_lowercase().into()))
    }

    /// Returns the normalized media type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AssetMediaType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AssetMediaType")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for AssetMediaType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A non-zero asset size constrained by the platform hard limit.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssetByteLength(NonZeroU64);

impl AssetByteLength {
    /// The largest asset accepted by this contract, in bytes.
    pub const MAX_BYTES: u64 = 1_099_511_627_776;

    /// Creates a length from 1 byte through 1 TiB.
    pub fn new(value: u64) -> Result<Self, StorageError> {
        let Some(value) = NonZeroU64::new(value) else {
            return Err(invalid_argument());
        };
        if value.get() > Self::MAX_BYTES {
            return Err(invalid_argument());
        }
        Ok(Self(value))
    }

    /// Returns the number of bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A tenant-scoped content address that never contains a storage path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssetKey {
    tenant_id: TenantId,
    digest: AssetDigest,
}

impl AssetKey {
    /// Creates a tenant-scoped content address.
    #[must_use]
    pub const fn new(tenant_id: TenantId, digest: AssetDigest) -> Self {
        Self { tenant_id, digest }
    }

    /// Returns the tenant that owns the asset.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the SHA-256 content address.
    #[must_use]
    pub const fn digest(&self) -> AssetDigest {
        self.digest
    }
}

/// Immutable metadata for one tenant-owned committed asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetDescriptor {
    key: AssetKey,
    media_type: AssetMediaType,
    byte_length: AssetByteLength,
}

impl AssetDescriptor {
    /// Creates immutable metadata from already validated values.
    #[must_use]
    pub const fn new(
        key: AssetKey,
        media_type: AssetMediaType,
        byte_length: AssetByteLength,
    ) -> Self {
        Self {
            key,
            media_type,
            byte_length,
        }
    }

    /// Returns the tenant-scoped content address.
    #[must_use]
    pub const fn key(&self) -> &AssetKey {
        &self.key
    }

    /// Returns the owning tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.key.tenant_id()
    }

    /// Returns the SHA-256 content address.
    #[must_use]
    pub const fn digest(&self) -> AssetDigest {
        self.key.digest()
    }

    /// Returns the normalized media type.
    #[must_use]
    pub const fn media_type(&self) -> &AssetMediaType {
        &self.media_type
    }

    /// Returns the exact non-zero content length.
    #[must_use]
    pub const fn byte_length(&self) -> AssetByteLength {
        self.byte_length
    }
}

/// Validated metadata supplied before an asset stream is staged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetStageRequest {
    tenant_id: TenantId,
    media_type: AssetMediaType,
    byte_length: AssetByteLength,
    expected_digest: Option<AssetDigest>,
}

impl AssetStageRequest {
    /// Creates a staging request with an optional expected digest.
    ///
    /// Supplying an expected digest lets the adapter reject content that does
    /// not match an upstream content address. Omitting it lets the adapter
    /// derive the address while streaming the source once.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        media_type: AssetMediaType,
        byte_length: AssetByteLength,
        expected_digest: Option<AssetDigest>,
    ) -> Self {
        Self {
            tenant_id,
            media_type,
            byte_length,
            expected_digest,
        }
    }

    /// Returns the tenant that will own the asset.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the normalized media type.
    #[must_use]
    pub const fn media_type(&self) -> &AssetMediaType {
        &self.media_type
    }

    /// Returns the declared exact content length.
    #[must_use]
    pub const fn byte_length(&self) -> AssetByteLength {
        self.byte_length
    }

    /// Returns the expected digest when one was supplied.
    #[must_use]
    pub const fn expected_digest(&self) -> Option<AssetDigest> {
        self.expected_digest
    }
}

/// An opaque staging capability generated by a storage adapter.
///
/// The fixed bytes are an adapter-defined nonce, never a relative or absolute
/// filesystem path. Adapters must treat caller-supplied values as untrusted.
#[derive(Eq, Hash, PartialEq)]
pub struct AssetStageToken([u8; 32]);

impl AssetStageToken {
    /// The exact number of opaque token bytes.
    pub const BYTE_LENGTH: usize = 32;

    /// Creates an opaque token from adapter-generated bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque token bytes for adapter lookup.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

impl Debug for AssetStageToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AssetStageToken(<redacted>)")
    }
}

impl Zeroize for AssetStageToken {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for AssetStageToken {}

impl Drop for AssetStageToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A verified asset held outside the committed content-addressed namespace.
#[derive(Debug, Eq, PartialEq)]
pub struct StagedAsset {
    token: AssetStageToken,
    descriptor: AssetDescriptor,
}

impl StagedAsset {
    /// Creates a verified staging handle for an adapter-owned nonce.
    #[must_use]
    pub const fn new(token: AssetStageToken, descriptor: AssetDescriptor) -> Self {
        Self { token, descriptor }
    }

    /// Returns the opaque staging capability.
    #[must_use]
    pub const fn token(&self) -> &AssetStageToken {
        &self.token
    }

    /// Returns metadata derived and verified during staging.
    #[must_use]
    pub const fn descriptor(&self) -> &AssetDescriptor {
        &self.descriptor
    }
}

/// The durable result of promoting a staged asset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetCommitStatus {
    /// New committed content was made visible atomically.
    Stored,
    /// Identical committed content and metadata were already visible.
    AlreadyStored,
}

/// Evidence that a staged asset reached a durable committed state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetCommitReceipt {
    descriptor: AssetDescriptor,
    status: AssetCommitStatus,
}

impl AssetCommitReceipt {
    /// Creates a receipt after the adapter confirms durable promotion.
    #[must_use]
    pub const fn new(descriptor: AssetDescriptor, status: AssetCommitStatus) -> Self {
        Self { descriptor, status }
    }

    /// Returns the committed descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &AssetDescriptor {
        &self.descriptor
    }

    /// Returns whether promotion stored new content or found an exact match.
    #[must_use]
    pub const fn status(&self) -> AssetCommitStatus {
        self.status
    }
}

/// A stable reason for isolating staged bytes from the committed namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AssetQuarantineReason {
    /// The bytes failed digest, length, or decoder integrity validation.
    IntegrityFailure,
    /// A configured content or tenant policy rejected the asset.
    PolicyRejected,
    /// A security scanner requires the bytes to remain isolated.
    InspectionRequired,
    /// The caller abandoned a valid stage before commit.
    Abandoned,
}

/// Evidence that staged bytes were isolated without revealing their location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetQuarantineReceipt {
    descriptor: AssetDescriptor,
    reason: AssetQuarantineReason,
}

impl AssetQuarantineReceipt {
    /// Creates a receipt after the adapter confirms isolation.
    #[must_use]
    pub const fn new(descriptor: AssetDescriptor, reason: AssetQuarantineReason) -> Self {
        Self { descriptor, reason }
    }

    /// Returns metadata for the isolated content.
    #[must_use]
    pub const fn descriptor(&self) -> &AssetDescriptor {
        &self.descriptor
    }

    /// Returns the stable quarantine reason.
    #[must_use]
    pub const fn reason(&self) -> AssetQuarantineReason {
        self.reason
    }
}

/// Streams tenant-owned assets through an adapter-managed local volume.
///
/// Implementations must reject a tenant mismatch between the authenticated
/// request context and every request, key, or staged descriptor. They must
/// check cancellation and deadlines between bounded I/O chunks, keep staging
/// and quarantine namespaces inaccessible to reads, and never project local
/// paths through return values, errors, logs, or diagnostics.
pub trait LocalVolumeAssetStoragePort: Send + Sync {
    /// Streams a source into an isolated staging object.
    ///
    /// The adapter must read exactly the declared byte length, calculate the
    /// SHA-256 digest while streaming, and compare an expected digest when it
    /// is present. A short, long, mismatched, cancelled, or failed source must
    /// never become readable; partial bytes must be quarantined or removed
    /// before a redacted [`StorageError`] is returned.
    fn stage(
        &self,
        request: AssetStageRequest,
        source: &mut dyn Read,
        context: &RequestContext,
    ) -> Result<StagedAsset, StorageError>;

    /// Atomically promotes verified staged bytes to their content address.
    ///
    /// The operation is idempotent for an exact existing descriptor. Existing
    /// content with different length or media metadata must return
    /// [`StorageErrorCode::Conflict`]. A transient failure must leave the stage
    /// retryable unless durable promotion has already completed.
    fn commit(
        &self,
        staged: &StagedAsset,
        context: &RequestContext,
    ) -> Result<AssetCommitReceipt, StorageError>;

    /// Moves a verified stage into an unreadable quarantine namespace.
    ///
    /// A successful call permanently invalidates the staging capability for
    /// commit. The adapter must retain no caller-controlled path component.
    fn quarantine(
        &self,
        staged: &StagedAsset,
        reason: AssetQuarantineReason,
        context: &RequestContext,
    ) -> Result<AssetQuarantineReceipt, StorageError>;

    /// Finds immutable metadata for one committed tenant-scoped address.
    fn metadata(
        &self,
        key: &AssetKey,
        context: &RequestContext,
    ) -> Result<Option<AssetDescriptor>, StorageError>;

    /// Streams committed bytes into a caller-provided destination.
    ///
    /// Implementations must use bounded buffers and verify the stored length
    /// and digest. The caller must discard destination bytes if this method
    /// returns an error because a failing writer or late integrity check can
    /// leave a partial stream. Successful completion returns the descriptor
    /// that was validated for the streamed bytes.
    fn read_into(
        &self,
        key: &AssetKey,
        destination: &mut dyn Write,
        context: &RequestContext,
    ) -> Result<AssetDescriptor, StorageError>;
}

fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

fn validate_media_type_bounds(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > AssetMediaType::MAX_BYTES {
        return Err(invalid_argument());
    }
    if !value.is_ascii() {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_media_type_shape(value: &str) -> Result<(), StorageError> {
    let Some((type_name, subtype)) = value.split_once('/') else {
        return Err(invalid_argument());
    };
    if subtype.contains('/') {
        return Err(invalid_argument());
    }
    validate_media_token(type_name)?;
    validate_media_token(subtype)
}

fn validate_media_token(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.bytes().any(is_invalid_media_token_byte) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn is_invalid_media_token_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric()
        && !matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

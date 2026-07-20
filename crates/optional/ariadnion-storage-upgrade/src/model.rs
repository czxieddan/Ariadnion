use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU32;

use ariadnion_storage_domain::{SchemaVersion, StorageError, StorageErrorCode, StorageInstanceId};

const MAX_IDENTIFIER_BYTES: usize = 128;

/// Maximum ordered operations in one immutable upgrade plan.
pub const MAX_UPGRADE_STEPS: usize = 256;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BoundedIdentifier(Box<str>);

impl BoundedIdentifier {
    fn parse(value: &str) -> Result<Self, StorageError> {
        if !valid_identifier(value) {
            return Err(invalid_argument());
        }
        Ok(Self(value.into()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(BoundedIdentifier);

        impl $name {
            /// Parses a non-empty path-free ASCII identity of at most 128 bytes.
            /// # Errors
            /// Returns [`StorageErrorCode::InvalidArgument`] for invalid input.
            pub fn parse(value: &str) -> Result<Self, StorageError> {
                BoundedIdentifier::parse(value).map(Self)
            }

            /// Returns the validated identity.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

macro_rules! ref_accessor {
    ($name:ident, $field:ident, $type:ty, $documentation:literal) => {
        #[doc = $documentation]
        #[must_use]
        pub const fn $name(&self) -> &$type {
            &self.$field
        }
    };
}

macro_rules! copy_accessor {
    ($name:ident, $field:ident, $type:ty, $documentation:literal) => {
        #[doc = $documentation]
        #[must_use]
        pub const fn $name(&self) -> $type {
            self.$field
        }
    };
}

bounded_identifier!(
    KeyVersionId,
    "Bounded public key-version identity, never key material."
);
bounded_identifier!(
    SwitchAuthorizationId,
    "Bounded audit reference for one consumed switch authorization."
);

/// An exact SHA-256 digest used to bind typed immutable evidence.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Sha256Digest(
    /// Exact digest bytes.
    pub [u8; 32],
);

impl Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(<sha256>)")
    }
}

/// Non-zero database-format version independent of any storage engine type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DatabaseFormatVersion(NonZeroU32);

impl DatabaseFormatVersion {
    /// Creates a non-zero format version.
    /// # Errors
    /// Returns [`StorageErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u32) -> Result<Self, StorageError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or_else(invalid_argument)
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Exact database format, application schema, and public key-version state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageVersionState {
    /// Database-format version.
    pub format: DatabaseFormatVersion,
    /// Application-schema version.
    pub schema: SchemaVersion,
    /// Public key-version identity.
    pub key_version: KeyVersionId,
}

/// Authenticated immutable facts about the source instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeSource {
    /// Immutable source identity.
    pub instance: StorageInstanceId,
    /// Authenticated digest of the source bytes.
    pub digest: Sha256Digest,
    /// Exact source version and key state.
    pub state: StorageVersionState,
}

/// One explicitly supported forward transition for a typed version domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportedVersionWindow<V> {
    from: V,
    to: V,
    definition_digest: Sha256Digest,
}

impl<V: Copy> SupportedVersionWindow<V> {
    copy_accessor!(from, from, V, "Returns the only accepted source version.");
    copy_accessor!(to, to, V, "Returns the only accepted target version.");
    copy_accessor!(
        definition_digest,
        definition_digest,
        Sha256Digest,
        "Returns the digest of the immutable transition definition."
    );
}

impl SupportedVersionWindow<DatabaseFormatVersion> {
    /// Creates the immediate supported format successor without unknown leaps.
    /// # Errors
    /// Returns [`StorageErrorCode::MigrationRequired`] unless `to` follows `from`.
    pub fn new(
        from: DatabaseFormatVersion,
        to: DatabaseFormatVersion,
        definition_digest: Sha256Digest,
    ) -> Result<Self, StorageError> {
        let supported = from.get().checked_add(1) == Some(to.get());
        create_supported_window(from, to, definition_digest, supported)
    }
}

impl SupportedVersionWindow<SchemaVersion> {
    /// Creates the immediate supported schema successor without unknown leaps.
    /// # Errors
    /// Returns [`StorageErrorCode::MigrationRequired`] unless `to` follows `from`.
    pub fn new(
        from: SchemaVersion,
        to: SchemaVersion,
        definition_digest: Sha256Digest,
    ) -> Result<Self, StorageError> {
        let supported = from.get().checked_add(1) == Some(to.get());
        create_supported_window(from, to, definition_digest, supported)
    }
}

/// Exact supported database-format version window.
pub type DatabaseFormatWindow = SupportedVersionWindow<DatabaseFormatVersion>;

/// Exact supported application-schema version window.
pub type ApplicationSchemaWindow = SupportedVersionWindow<SchemaVersion>;

/// Immutable transition between two distinct public key-version identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRotationStep {
    from: KeyVersionId,
    to: KeyVersionId,
    definition_digest: Sha256Digest,
}

impl KeyRotationStep {
    /// Creates an exact key transition and rejects current-key reuse.
    /// # Errors
    /// Returns [`StorageErrorCode::MigrationRequired`] when both versions match.
    pub fn new(
        from: KeyVersionId,
        to: KeyVersionId,
        definition_digest: Sha256Digest,
    ) -> Result<Self, StorageError> {
        if from == to {
            return Err(migration_required());
        }
        Ok(Self {
            from,
            to,
            definition_digest,
        })
    }

    ref_accessor!(
        from,
        from,
        KeyVersionId,
        "Returns the source key-version identity."
    );
    ref_accessor!(
        to,
        to,
        KeyVersionId,
        "Returns the target key-version identity."
    );
    copy_accessor!(
        definition_digest,
        definition_digest,
        Sha256Digest,
        "Returns the digest of the immutable rotation definition."
    );
}

/// One typed immutable operation in an upgrade plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpgradeStep {
    /// An exact database-format window.
    DatabaseFormat(DatabaseFormatWindow),
    /// An exact application-schema window.
    ApplicationSchema(ApplicationSchemaWindow),
    /// An exact key-rotation operation.
    KeyRotation(KeyRotationStep),
}

/// Bounded immutable plan for creating one exact new target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradePlan {
    source: UpgradeSource,
    target: StorageInstanceId,
    target_state: StorageVersionState,
    steps: Vec<UpgradeStep>,
    digest: Sha256Digest,
}

impl UpgradePlan {
    /// Creates a distinct, forward-only, gap-free, phase-ordered plan.
    ///
    /// The trusted composition planner owns the versioned canonical encoding.
    /// `digest` must be its authenticated SHA-256 over every supplied field and
    /// ordered step. This crate binds but does not compute that digest; switch
    /// authorization also compares the complete immutable plan for equality.
    ///
    /// # Errors
    /// Downgrades, missing exact windows, unknown leaps, wrong ordering, empty
    /// plans, and oversized plans return `MigrationRequired`, `InvalidArgument`,
    /// `Conflict`, or `ResourceExhausted` as appropriate.
    pub fn new(
        source: UpgradeSource,
        target: StorageInstanceId,
        target_state: StorageVersionState,
        steps: Vec<UpgradeStep>,
        digest: Sha256Digest,
    ) -> Result<Self, StorageError> {
        validate_identities(&source.instance, &target)?;
        validate_forward_state(&source.state, &target_state)?;
        validate_steps(&source.state, &target_state, &steps)?;
        Ok(Self {
            source,
            target,
            target_state,
            steps,
            digest,
        })
    }

    ref_accessor!(
        source,
        source,
        UpgradeSource,
        "Returns the authenticated source."
    );
    ref_accessor!(
        target,
        target,
        StorageInstanceId,
        "Returns the new target identity."
    );
    ref_accessor!(
        target_state,
        target_state,
        StorageVersionState,
        "Returns the exact required target state."
    );

    /// Returns operations in immutable execution order.
    #[must_use]
    pub fn steps(&self) -> &[UpgradeStep] {
        &self.steps
    }

    copy_accessor!(
        digest,
        digest,
        Sha256Digest,
        "Returns the planner-authenticated digest of the complete canonical plan."
    );
}

fn validate_identities(
    source: &StorageInstanceId,
    target: &StorageInstanceId,
) -> Result<(), StorageError> {
    if source == target {
        return Err(conflict());
    }
    Ok(())
}

fn validate_forward_state(
    source: &StorageVersionState,
    target: &StorageVersionState,
) -> Result<(), StorageError> {
    if target.format < source.format || target.schema < source.schema {
        return Err(migration_required());
    }
    if source == target {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_steps(
    source: &StorageVersionState,
    target: &StorageVersionState,
    steps: &[UpgradeStep],
) -> Result<(), StorageError> {
    validate_step_count(steps)?;
    let state = replay_steps(source, steps)?;
    validate_replayed_state(&state, target)
}

fn validate_step_count(steps: &[UpgradeStep]) -> Result<(), StorageError> {
    if steps.is_empty() {
        return Err(invalid_argument());
    }
    if steps.len() > MAX_UPGRADE_STEPS {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn replay_steps(
    source: &StorageVersionState,
    steps: &[UpgradeStep],
) -> Result<StorageVersionState, StorageError> {
    let mut state = source.clone();
    let mut previous = None;
    for step in steps {
        let phase = step_phase(step);
        validate_step_order(previous, phase)?;
        apply_step(&mut state, step)?;
        previous = Some(phase);
    }
    Ok(state)
}

fn validate_replayed_state(
    actual: &StorageVersionState,
    expected: &StorageVersionState,
) -> Result<(), StorageError> {
    if actual != expected {
        return Err(migration_required());
    }
    Ok(())
}

fn create_supported_window<V>(
    from: V,
    to: V,
    definition_digest: Sha256Digest,
    supported: bool,
) -> Result<SupportedVersionWindow<V>, StorageError> {
    if !supported {
        return Err(migration_required());
    }
    Ok(SupportedVersionWindow {
        from,
        to,
        definition_digest,
    })
}

fn validate_step_order(previous: Option<u8>, current: u8) -> Result<(), StorageError> {
    if previous.is_some_and(|phase| phase > current) {
        return Err(migration_required());
    }
    Ok(())
}

fn apply_step(state: &mut StorageVersionState, step: &UpgradeStep) -> Result<(), StorageError> {
    match step {
        UpgradeStep::DatabaseFormat(window) => apply_format(state, *window),
        UpgradeStep::ApplicationSchema(window) => apply_schema(state, *window),
        UpgradeStep::KeyRotation(rotation) => apply_key(state, rotation),
    }
}

fn step_phase(step: &UpgradeStep) -> u8 {
    match step {
        UpgradeStep::DatabaseFormat(_) => 0,
        UpgradeStep::ApplicationSchema(_) => 1,
        UpgradeStep::KeyRotation(_) => 2,
    }
}

fn apply_format(
    state: &mut StorageVersionState,
    window: DatabaseFormatWindow,
) -> Result<(), StorageError> {
    if state.format != window.from() {
        return Err(migration_required());
    }
    state.format = window.to();
    Ok(())
}

fn apply_schema(
    state: &mut StorageVersionState,
    window: ApplicationSchemaWindow,
) -> Result<(), StorageError> {
    if state.schema != window.from() {
        return Err(migration_required());
    }
    state.schema = window.to();
    Ok(())
}

fn apply_key(state: &mut StorageVersionState, step: &KeyRotationStep) -> Result<(), StorageError> {
    if &state.key_version != step.from() {
        return Err(migration_required());
    }
    state.key_version = step.to().clone();
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

macro_rules! storage_error {
    ($name:ident, $code:ident) => {
        pub(crate) const fn $name() -> StorageError {
            StorageError::new(StorageErrorCode::$code)
        }
    };
}

storage_error!(invalid_argument, InvalidArgument);
storage_error!(conflict, Conflict);
storage_error!(resource_exhausted, ResourceExhausted);
storage_error!(integrity_failure, IntegrityFailure);
storage_error!(migration_required, MigrationRequired);

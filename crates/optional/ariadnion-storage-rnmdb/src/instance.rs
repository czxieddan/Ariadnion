//! Bounded RNMDB instance profiles and conflict-safe registration.

use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt::{self, Debug, Formatter};
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use ariadnion_storage_domain::{StorageError, StorageErrorCode, StorageInstanceId};
use rnmdb_common::{
    ErrorKind, RnovError,
    ids::{DatabaseId, InstanceId},
};
use rnmdb_instance::{
    InstanceConfig, InstanceManager, ResourceLimits as UpstreamResourceLimits, ResourceUsage,
    UdfBudget,
};

/// Validated limits recorded in an RNMDB isolated-instance configuration.
///
/// Registration preserves these values for upstream resource-usage checks. It
/// does not attach enforcement to an embedded `LocalSession`; execution paths
/// must explicitly apply deadlines and report resource usage when they are
/// wired to this profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnmdbInstanceResourceLimits {
    max_memory_bytes: usize,
    max_worker_threads: usize,
    max_temp_bytes: usize,
    statement_timeout: Duration,
    max_udf_invocations: usize,
    max_udf_memory_bytes: usize,
}

impl RnmdbInstanceResourceLimits {
    /// The absolute memory ceiling: one tebibyte or the target's `usize` limit.
    pub const MAX_MEMORY_BYTES: u64 = 1_099_511_627_776;
    /// The largest accepted worker declaration.
    pub const MAX_WORKER_THREADS: usize = 256;
    /// The absolute temp ceiling: one tebibyte or the target's `usize` limit.
    pub const MAX_TEMP_BYTES: u64 = 1_099_511_627_776;
    /// The shortest accepted statement deadline.
    pub const MIN_STATEMENT_TIMEOUT: Duration = Duration::from_millis(1);
    /// The longest accepted statement deadline.
    pub const MAX_STATEMENT_TIMEOUT: Duration = Duration::from_secs(3_600);
    /// The largest accepted UDF invocation budget per reported operation.
    pub const MAX_UDF_INVOCATIONS: u64 = 1_000_000;
    /// The largest accepted UDF memory declaration: one gibibyte.
    pub const MAX_UDF_MEMORY_BYTES: u64 = 1_073_741_824;

    /// Creates limits that are finite and representable by the current target.
    ///
    /// A zero temporary-storage budget disables temporary storage. UDFs are
    /// disabled only when both UDF values are zero; otherwise both must be
    /// positive and within their documented maxima.
    pub fn new(
        max_memory_bytes: u64,
        max_worker_threads: usize,
        max_temp_bytes: u64,
        statement_timeout: Duration,
        max_udf_invocations: u64,
        max_udf_memory_bytes: u64,
    ) -> Result<Self, StorageError> {
        let max_memory_bytes = bounded_usize(max_memory_bytes, 1, Self::MAX_MEMORY_BYTES)?;
        let max_worker_threads =
            bounded_native_usize(max_worker_threads, 1, Self::MAX_WORKER_THREADS)?;
        let max_temp_bytes = bounded_usize(max_temp_bytes, 0, Self::MAX_TEMP_BYTES)?;
        validate_timeout(statement_timeout)?;
        validate_udf_pair(max_udf_invocations, max_udf_memory_bytes)?;
        let max_udf_invocations = bounded_usize(max_udf_invocations, 0, Self::MAX_UDF_INVOCATIONS)?;
        let max_udf_memory_bytes =
            bounded_usize(max_udf_memory_bytes, 0, Self::MAX_UDF_MEMORY_BYTES)?;
        Ok(Self {
            max_memory_bytes,
            max_worker_threads,
            max_temp_bytes,
            statement_timeout,
            max_udf_invocations,
            max_udf_memory_bytes,
        })
    }

    /// Returns the declared memory ceiling in bytes.
    #[must_use]
    pub const fn max_memory_bytes(self) -> usize {
        self.max_memory_bytes
    }

    /// Returns the declared worker ceiling.
    #[must_use]
    pub const fn max_worker_threads(self) -> usize {
        self.max_worker_threads
    }

    /// Returns the declared temporary-storage ceiling in bytes.
    #[must_use]
    pub const fn max_temp_bytes(self) -> usize {
        self.max_temp_bytes
    }

    /// Returns the declared statement timeout.
    #[must_use]
    pub const fn statement_timeout(self) -> Duration {
        self.statement_timeout
    }

    /// Returns the declared UDF invocation ceiling.
    #[must_use]
    pub const fn max_udf_invocations(self) -> usize {
        self.max_udf_invocations
    }

    /// Returns the declared UDF memory ceiling in bytes.
    #[must_use]
    pub const fn max_udf_memory_bytes(self) -> usize {
        self.max_udf_memory_bytes
    }

    fn to_upstream(self) -> Result<UpstreamResourceLimits, StorageError> {
        let limits = UpstreamResourceLimits::new(
            self.max_memory_bytes,
            self.max_worker_threads,
            self.max_temp_bytes,
            self.statement_timeout,
        )
        .map_err(map_limit_error)?;
        let udf_budget = UdfBudget::new(self.max_udf_invocations, self.max_udf_memory_bytes);
        Ok(limits.with_udf_budget(udf_budget))
    }
}

impl Default for RnmdbInstanceResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,
            max_worker_threads: 1,
            max_temp_bytes: 0,
            statement_timeout: Duration::from_secs(30),
            max_udf_invocations: 0,
            max_udf_memory_bytes: 0,
        }
    }
}

/// An Ariadnion identity bound to one isolated RNMDB instance configuration.
///
/// Upstream numeric identities are required to be non-zero. The concrete
/// RNMDB configuration remains private so database implementation types do not
/// cross the adapter's public boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct RnmdbInstanceProfile {
    instance: StorageInstanceId,
    upstream_instance_id: NonZeroU64,
    upstream_database_id: NonZeroU64,
    limits: RnmdbInstanceResourceLimits,
    config: InstanceConfig,
}

impl RnmdbInstanceProfile {
    /// Creates an isolated configuration with instance-derived namespaces.
    pub fn new(
        instance: StorageInstanceId,
        upstream_instance_id: NonZeroU64,
        upstream_database_id: NonZeroU64,
        limits: RnmdbInstanceResourceLimits,
    ) -> Result<Self, StorageError> {
        let config = InstanceConfig::isolated(
            InstanceId::new(upstream_instance_id.get()),
            DatabaseId::new(upstream_database_id.get()),
            limits.to_upstream()?,
        );
        Ok(Self {
            instance,
            upstream_instance_id,
            upstream_database_id,
            limits,
            config,
        })
    }

    /// Creates a single-node profile with one shared non-zero numeric suffix.
    pub fn single_node(
        instance: StorageInstanceId,
        upstream_id: NonZeroU64,
    ) -> Result<Self, StorageError> {
        Self::new(
            instance,
            upstream_id,
            upstream_id,
            RnmdbInstanceResourceLimits::default(),
        )
    }

    /// Returns the bounded Ariadnion storage identity.
    #[must_use]
    pub const fn instance(&self) -> &StorageInstanceId {
        &self.instance
    }

    /// Returns the non-zero numeric identity recorded in RNMDB.
    #[must_use]
    pub const fn upstream_instance_id(&self) -> NonZeroU64 {
        self.upstream_instance_id
    }

    /// Returns the non-zero database identity recorded in RNMDB.
    #[must_use]
    pub const fn upstream_database_id(&self) -> NonZeroU64 {
        self.upstream_database_id
    }

    /// Returns the validated declared limits.
    #[must_use]
    pub const fn limits(&self) -> RnmdbInstanceResourceLimits {
        self.limits
    }

    fn upstream_instance_key(&self) -> InstanceId {
        InstanceId::new(self.upstream_instance_id.get())
    }

    fn upstream_config(&self) -> &InstanceConfig {
        &self.config
    }

    pub(crate) fn validate_session_open(&self) -> Result<(), StorageError> {
        self.config
            .check_resource_usage(&ResourceUsage::new(0, 0, 1))
            .map_err(map_usage_error)
    }
}

impl Debug for RnmdbInstanceProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnmdbInstanceProfile")
            .field("instance", &self.instance)
            .field("upstream_instance_id", &self.upstream_instance_id)
            .field("upstream_database_id", &self.upstream_database_id)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// A thread-safe, bounded registry of isolated RNMDB instance profiles.
///
/// RNMDB's `InstanceManager` remains the authority for duplicate instance,
/// database, and generated namespace conflicts. A poisoned registry rejects
/// reads and writes with `STORAGE_UNAVAILABLE`; poisoned state is never
/// recovered or exposed to callers.
pub struct RnmdbInstanceRegistry {
    state: Mutex<RegistryState>,
    max_instances: NonZeroUsize,
}

impl RnmdbInstanceRegistry {
    /// The default maximum number of registered profiles.
    pub const DEFAULT_MAX_INSTANCES: usize = 1_024;
    /// The largest configurable registry bound.
    pub const MAX_INSTANCES: usize = 65_536;

    /// Creates a registry with the default hard instance bound.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RegistryState::default()),
            max_instances: default_instance_limit(),
        }
    }

    /// Creates a registry with a caller-selected hard instance bound.
    pub fn with_max_instances(max_instances: NonZeroUsize) -> Result<Self, StorageError> {
        if max_instances.get() > Self::MAX_INSTANCES {
            return Err(invalid_argument());
        }
        Ok(Self {
            state: Mutex::new(RegistryState::default()),
            max_instances,
        })
    }

    /// Registers one profile after all identity and namespace conflict checks.
    pub fn register(&self, profile: RnmdbInstanceProfile) -> Result<(), StorageError> {
        let mut state = self.lock_state()?;
        let at_capacity = state.profiles.len() >= self.max_instances.get();
        let storage_id = profile.instance().clone();
        let RegistryState { manager, profiles } = &mut *state;
        match profiles.entry(storage_id) {
            Entry::Occupied(_) => Err(StorageError::new(StorageErrorCode::Conflict)),
            Entry::Vacant(_) if at_capacity => {
                Err(StorageError::new(StorageErrorCode::ResourceExhausted))
            }
            Entry::Vacant(entry) => {
                manager
                    .register(profile.upstream_config().clone())
                    .map_err(map_registration_error)?;
                entry.insert(profile);
                Ok(())
            }
        }
    }

    /// Returns a verified profile selected by its Ariadnion storage identity.
    ///
    /// The returned profile is an immutable clone, allowing the registry lock
    /// to be released before any database work begins.
    pub fn profile(
        &self,
        instance: &StorageInstanceId,
    ) -> Result<RnmdbInstanceProfile, StorageError> {
        let state = self.lock_state()?;
        let profile = state
            .profiles
            .get(instance)
            .ok_or_else(|| StorageError::new(StorageErrorCode::NotFound))?;
        verify_manager_entry(&state.manager, profile)?;
        Ok(profile.clone())
    }

    /// Returns the number of registered profiles without recovering poison.
    pub fn registered_instances(&self) -> Result<usize, StorageError> {
        Ok(self.lock_state()?.profiles.len())
    }

    /// Returns the configured hard registry bound.
    #[must_use]
    pub const fn max_instances(&self) -> usize {
        self.max_instances.get()
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, RegistryState>, StorageError> {
        self.state
            .lock()
            .map_err(|_| StorageError::new(StorageErrorCode::Unavailable))
    }
}

impl Default for RnmdbInstanceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct RegistryState {
    manager: InstanceManager,
    profiles: BTreeMap<StorageInstanceId, RnmdbInstanceProfile>,
}

fn bounded_usize(value: u64, minimum: u64, maximum: u64) -> Result<usize, StorageError> {
    if value < minimum || value > maximum {
        return Err(invalid_argument());
    }
    usize::try_from(value).map_err(|_| invalid_argument())
}

fn bounded_native_usize(
    value: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, StorageError> {
    if value < minimum || value > maximum {
        return Err(invalid_argument());
    }
    Ok(value)
}

fn validate_timeout(timeout: Duration) -> Result<(), StorageError> {
    if !(RnmdbInstanceResourceLimits::MIN_STATEMENT_TIMEOUT
        ..=RnmdbInstanceResourceLimits::MAX_STATEMENT_TIMEOUT)
        .contains(&timeout)
    {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_udf_pair(invocations: u64, memory_bytes: u64) -> Result<(), StorageError> {
    if (invocations == 0) != (memory_bytes == 0) {
        return Err(invalid_argument());
    }
    Ok(())
}

fn verify_manager_entry(
    manager: &InstanceManager,
    profile: &RnmdbInstanceProfile,
) -> Result<(), StorageError> {
    let matches = manager
        .get(profile.upstream_instance_key())
        .is_some_and(|config| config == profile.upstream_config());
    if !matches {
        return Err(StorageError::new(StorageErrorCode::Internal));
    }
    Ok(())
}

fn default_instance_limit() -> NonZeroUsize {
    match NonZeroUsize::new(RnmdbInstanceRegistry::DEFAULT_MAX_INSTANCES) {
        Some(limit) => limit,
        None => unreachable_default_limit(),
    }
}

fn unreachable_default_limit() -> NonZeroUsize {
    NonZeroUsize::MIN
}

fn map_limit_error(error: RnovError) -> StorageError {
    let code = match error.kind() {
        ErrorKind::Config | ErrorKind::InvalidInput => StorageErrorCode::InvalidArgument,
        _ => StorageErrorCode::Internal,
    };
    StorageError::new(code)
}

fn map_registration_error(error: RnovError) -> StorageError {
    let code = match error.kind() {
        ErrorKind::InvalidInput => StorageErrorCode::Conflict,
        _ => StorageErrorCode::Internal,
    };
    StorageError::new(code)
}

fn map_usage_error(error: RnovError) -> StorageError {
    let code = match error.kind() {
        ErrorKind::InvalidInput => StorageErrorCode::ResourceExhausted,
        _ => StorageErrorCode::Internal,
    };
    StorageError::new(code)
}

const fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

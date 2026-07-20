use ariadnion_storage_domain::{
    MigrationCatalog, MigrationDescriptor, MigrationPlan, SchemaVersion, StorageError,
    StorageErrorCode,
};

/// The hard upper bound for migrations held by one registry.
pub const MAX_REGISTERED_MIGRATIONS: usize = 1_024;

/// A bounded registry that preserves one validated linear migration catalog.
///
/// Registration is an administrative cold path. Each accepted descriptor is
/// validated together with the complete catalog before it becomes visible, so
/// a duplicate identity, duplicate source version, or version gap never leaves
/// partial registry state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationRegistry {
    max_entries: usize,
    catalog: MigrationCatalog,
}

impl MigrationRegistry {
    /// Creates an empty registry with an explicit local entry limit.
    ///
    /// # Errors
    ///
    /// A zero limit returns [`StorageErrorCode::InvalidArgument`]. A limit above
    /// [`MAX_REGISTERED_MIGRATIONS`] returns
    /// [`StorageErrorCode::ResourceExhausted`].
    pub fn new(max_entries: usize) -> Result<Self, StorageError> {
        validate_registry_limit(max_entries)?;
        let catalog = MigrationCatalog::new(Vec::new())?;
        Ok(Self {
            max_entries,
            catalog,
        })
    }

    /// Registers one immutable migration after validating the resulting chain.
    ///
    /// The registry is unchanged if validation fails. When capacity remains,
    /// duplicate identities or source versions retain the domain catalog's
    /// [`StorageErrorCode::Conflict`] result, while gaps retain
    /// [`StorageErrorCode::MigrationRequired`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageErrorCode::ResourceExhausted`] when the configured
    /// capacity has been reached. All catalog validation errors are propagated
    /// without replacement.
    pub fn register(&mut self, migration: MigrationDescriptor) -> Result<(), StorageError> {
        ensure_capacity(self.len(), self.max_entries)?;
        let mut migrations = self.catalog.migrations().to_vec();
        migrations.push(migration);
        let catalog = MigrationCatalog::new(migrations)?;
        self.catalog = catalog;
        Ok(())
    }

    /// Plans an exact forward version path from the registered catalog.
    ///
    /// # Errors
    ///
    /// Invalid or unsupported version windows retain the stable error returned
    /// by [`MigrationCatalog::plan`].
    pub fn plan(
        &self,
        source: SchemaVersion,
        target: SchemaVersion,
    ) -> Result<MigrationPlan, StorageError> {
        self.catalog.plan(source, target)
    }

    /// Returns the validated immutable catalog view.
    #[must_use]
    pub const fn catalog(&self) -> &MigrationCatalog {
        &self.catalog
    }

    /// Consumes the registry and returns its validated catalog.
    #[must_use]
    pub fn into_catalog(self) -> MigrationCatalog {
        self.catalog
    }

    /// Returns the number of registered migrations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.catalog.migrations().len()
    }

    /// Returns whether the registry contains no migrations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.catalog.migrations().is_empty()
    }

    /// Returns the configured registry capacity.
    #[must_use]
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }
}

fn validate_registry_limit(max_entries: usize) -> Result<(), StorageError> {
    if max_entries == 0 {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    if max_entries > MAX_REGISTERED_MIGRATIONS {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn ensure_capacity(current: usize, maximum: usize) -> Result<(), StorageError> {
    if current >= maximum {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(())
}

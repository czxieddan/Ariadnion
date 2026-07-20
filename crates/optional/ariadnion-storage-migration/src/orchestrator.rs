use ariadnion_core::{CoreError, ErrorCode, RequestContext};
use ariadnion_storage_domain::{
    MigrationCatalog, MigrationExecutorPort, MigrationPlan, MigrationPreflight, MigrationReceipt,
    SchemaVersion, StorageError, StorageErrorCode, StorageInstanceId,
};

use crate::MigrationRegistry;

/// A validated request to migrate into a distinct new storage target.
///
/// The source instance is read-only from this layer's perspective. Target
/// emptiness and source authentication remain adapter-owned preflight checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationRequest {
    source: StorageInstanceId,
    target: StorageInstanceId,
    source_version: SchemaVersion,
    target_version: SchemaVersion,
}

impl MigrationRequest {
    /// Creates a forward migration request for two distinct instances.
    ///
    /// # Errors
    ///
    /// Equal instance identities return [`StorageErrorCode::Conflict`]. A
    /// source version greater than or equal to the target version returns
    /// [`StorageErrorCode::InvalidArgument`].
    pub fn new(
        source: StorageInstanceId,
        target: StorageInstanceId,
        source_version: SchemaVersion,
        target_version: SchemaVersion,
    ) -> Result<Self, StorageError> {
        ensure_distinct_targets(&source, &target)?;
        ensure_forward_window(source_version, target_version)?;
        Ok(Self {
            source,
            target,
            source_version,
            target_version,
        })
    }

    /// Returns the immutable source storage identity.
    #[must_use]
    pub const fn source(&self) -> &StorageInstanceId {
        &self.source
    }

    /// Returns the new target storage identity.
    #[must_use]
    pub const fn target(&self) -> &StorageInstanceId {
        &self.target
    }

    /// Returns the source schema version observed by the caller.
    #[must_use]
    pub const fn source_version(&self) -> SchemaVersion {
        self.source_version
    }

    /// Returns the required target schema version.
    #[must_use]
    pub const fn target_version(&self) -> SchemaVersion {
        self.target_version
    }
}

/// Coordinates strict preflight, new-target application, and verification.
///
/// The orchestrator owns only a validated migration catalog. It delegates all
/// persistence to a [`MigrationExecutorPort`], never supplies arbitrary SQL,
/// and returns a receipt only after the adapter verifies the exact requested
/// source, target, and target version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationOrchestrator {
    catalog: MigrationCatalog,
}

impl MigrationOrchestrator {
    /// Creates an orchestrator from an immutable validated catalog.
    #[must_use]
    pub fn new(catalog: MigrationCatalog) -> Self {
        Self { catalog }
    }

    /// Creates an orchestrator from a completed bounded registry.
    #[must_use]
    pub fn from_registry(registry: MigrationRegistry) -> Self {
        Self::new(registry.into_catalog())
    }

    /// Returns the immutable migration catalog.
    #[must_use]
    pub const fn catalog(&self) -> &MigrationCatalog {
        &self.catalog
    }

    /// Plans the request's exact source-to-target version path.
    ///
    /// # Errors
    ///
    /// Unsupported windows retain the stable error returned by
    /// [`MigrationCatalog::plan`]. No executor method is called.
    pub fn plan(&self, request: &MigrationRequest) -> Result<MigrationPlan, StorageError> {
        self.catalog
            .plan(request.source_version(), request.target_version())
    }

    /// Executes a migration into a preflight-confirmed new target.
    ///
    /// The request context is checked before preflight and again immediately
    /// before mutation. Executor cancellation and storage failures are returned
    /// unchanged. A denied preflight or mismatched verification receipt fails
    /// closed with [`StorageErrorCode::IntegrityFailure`]. The source and target
    /// identities are necessarily distinct, and this layer never requests a
    /// write against the source instance.
    ///
    /// # Errors
    ///
    /// Returns the first stable [`StorageError`] produced by planning, context
    /// checks, or the executor. It returns a receipt only after successful
    /// target verification.
    pub fn execute(
        &self,
        executor: &dyn MigrationExecutorPort,
        request: &MigrationRequest,
        context: &RequestContext,
    ) -> Result<MigrationReceipt, StorageError> {
        let prepared = self.prepare(executor, request, context)?;
        self.apply_and_verify(executor, request, prepared, context)
    }

    fn prepare(
        &self,
        executor: &dyn MigrationExecutorPort,
        request: &MigrationRequest,
        context: &RequestContext,
    ) -> Result<PreparedMigration, StorageError> {
        check_context(context)?;
        let plan = self.plan(request)?;
        let preflight = executor.preflight(request.source(), request.target(), &plan, context)?;
        require_permitted_preflight(&preflight, &plan)?;
        Ok(PreparedMigration { plan, preflight })
    }

    fn apply_and_verify(
        &self,
        executor: &dyn MigrationExecutorPort,
        request: &MigrationRequest,
        prepared: PreparedMigration,
        context: &RequestContext,
    ) -> Result<MigrationReceipt, StorageError> {
        check_context(context)?;
        executor.apply_to_new_target(
            request.source(),
            request.target(),
            &prepared.plan,
            prepared.preflight,
            context,
        )?;
        let receipt = executor.verify_target(
            request.source(),
            request.target(),
            request.target_version(),
            context,
        )?;
        validate_receipt(&receipt, request)?;
        Ok(receipt)
    }
}

struct PreparedMigration {
    plan: MigrationPlan,
    preflight: MigrationPreflight,
}

fn ensure_distinct_targets(
    source: &StorageInstanceId,
    target: &StorageInstanceId,
) -> Result<(), StorageError> {
    if source == target {
        return Err(StorageError::new(StorageErrorCode::Conflict));
    }
    Ok(())
}

fn ensure_forward_window(source: SchemaVersion, target: SchemaVersion) -> Result<(), StorageError> {
    if source >= target {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    Ok(())
}

fn require_permitted_preflight(
    preflight: &MigrationPreflight,
    plan: &MigrationPlan,
) -> Result<(), StorageError> {
    if !preflight.permits(plan) {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn validate_receipt(
    receipt: &MigrationReceipt,
    request: &MigrationRequest,
) -> Result<(), StorageError> {
    let matches_request = receipt.source() == request.source()
        && receipt.target() == request.target()
        && receipt.version() == request.target_version();
    if !matches_request {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(map_context_error)
}

fn map_context_error(error: CoreError) -> StorageError {
    let code = match error.code() {
        ErrorCode::Cancelled => StorageErrorCode::Cancelled,
        ErrorCode::DeadlineExceeded => StorageErrorCode::DeadlineExceeded,
        _ => StorageErrorCode::Internal,
    };
    StorageError::new(code)
}

//! Atomic immutable configuration snapshots with bounded rollback history.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use ariadnion_config_domain::{ConfigDocument, ConfigDraft};
use ariadnion_config_schema::{ConfigSchema, ValidatedConfig, ValidationReport};

/// A publication or rollback failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishError {
    /// Schema validation rejected the proposed document.
    Validation(ValidationReport),
    /// The draft or caller expected another active version.
    VersionConflict {
        /// Version supplied by the draft or rollback caller.
        expected: u64,
        /// Active immutable document version at the swap point.
        actual: u64,
    },
    /// No prior published snapshot is retained.
    NoRollbackSnapshot,
    /// The process-local snapshot generation reached its numeric limit.
    GenerationExhausted,
    /// The immutable document version reached its numeric limit.
    VersionExhausted,
}

/// A cheap immutable view used by read paths without database access.
#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    generation: u64,
    configuration: Arc<ValidatedConfig>,
}

impl ConfigSnapshot {
    /// Returns the process-local atomic generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the validated immutable configuration.
    #[must_use]
    pub fn configuration(&self) -> &ValidatedConfig {
        &self.configuration
    }
}

struct RuntimeState {
    generation: u64,
    active: Arc<ValidatedConfig>,
    previous: Option<Arc<ValidatedConfig>>,
}

/// Publishes validated snapshots under one short critical section.
///
/// The runtime uses one lock with no nested lock acquisition. Readers clone an
/// `Arc` while holding the read lock and perform all later work lock-free. Lock
/// poisoning is recovered by preserving the last complete immutable state.
pub struct ConfigRuntime {
    schema: Arc<ConfigSchema>,
    state: RwLock<RuntimeState>,
}

impl ConfigRuntime {
    /// Creates a runtime after validating the initial document.
    pub fn new(
        schema: Arc<ConfigSchema>,
        initial: ConfigDocument,
    ) -> Result<Self, ValidationReport> {
        let active = Arc::new(schema.validate(initial)?);
        Ok(Self {
            schema,
            state: RwLock::new(RuntimeState {
                generation: 1,
                active,
                previous: None,
            }),
        })
    }

    /// Returns the current immutable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ConfigSnapshot {
        let state = read_state(&self.state);
        ConfigSnapshot {
            generation: state.generation,
            configuration: state.active.clone(),
        }
    }

    /// Validates and atomically publishes a draft.
    ///
    /// Validation occurs before acquiring the write lock. The draft base must
    /// equal the active version at the swap point; otherwise no state changes.
    pub fn publish(&self, draft: ConfigDraft) -> Result<ConfigSnapshot, PublishError> {
        let base_version = draft.base_version();
        let validated = self
            .schema
            .validate(draft.into_document())
            .map_err(PublishError::Validation)?;
        let mut state = write_state(&self.state);
        ensure_version(base_version, state.active.document().version())?;
        let generation = next_generation(state.generation)?;
        let next = Arc::new(validated);
        let previous = std::mem::replace(&mut state.active, next.clone());
        state.previous = Some(previous);
        state.generation = generation;
        Ok(ConfigSnapshot {
            generation,
            configuration: next,
        })
    }

    /// Atomically republishes the retained prior content as a new version.
    ///
    /// The caller must provide the exact active document version. A successful
    /// rollback keeps the replaced content as the next rollback target. The
    /// restored content receives a new monotonically increasing version, so a
    /// previously published version number is never reused.
    pub fn rollback(&self, expected_active: u64) -> Result<ConfigSnapshot, PublishError> {
        let mut state = write_state(&self.state);
        ensure_version(expected_active, state.active.document().version())?;
        let generation = next_generation(state.generation)?;
        let version = next_document_version(state.active.document().version())?;
        let previous = state
            .previous
            .as_ref()
            .cloned()
            .ok_or(PublishError::NoRollbackSnapshot)?;
        let document = previous
            .document()
            .clone_at_version(version)
            .map_err(|_| PublishError::VersionExhausted)?;
        let restored = Arc::new(
            self.schema
                .validate(document)
                .map_err(PublishError::Validation)?,
        );
        let replaced = std::mem::replace(&mut state.active, restored.clone());
        state.previous = Some(replaced);
        state.generation = generation;
        Ok(ConfigSnapshot {
            generation,
            configuration: restored,
        })
    }

    /// Returns the immutable schema used by every publication.
    #[must_use]
    pub fn schema(&self) -> &ConfigSchema {
        &self.schema
    }
}

fn ensure_version(expected: u64, actual: u64) -> Result<(), PublishError> {
    if expected != actual {
        return Err(PublishError::VersionConflict { expected, actual });
    }
    Ok(())
}

fn next_generation(current: u64) -> Result<u64, PublishError> {
    current
        .checked_add(1)
        .ok_or(PublishError::GenerationExhausted)
}

fn next_document_version(current: u64) -> Result<u64, PublishError> {
    current.checked_add(1).ok_or(PublishError::VersionExhausted)
}

fn read_state(lock: &RwLock<RuntimeState>) -> RwLockReadGuard<'_, RuntimeState> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn write_state(lock: &RwLock<RuntimeState>) -> RwLockWriteGuard<'_, RuntimeState> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

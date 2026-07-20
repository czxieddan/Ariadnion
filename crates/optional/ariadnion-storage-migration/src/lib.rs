//! Database-independent migration registration and new-target orchestration.
//!
//! This crate coordinates the migration contracts from
//! `ariadnion-storage-domain`. It does not parse or execute SQL, open storage
//! engines, or implement adapter-specific migration steps. Concrete storage
//! adapters remain responsible for applying immutable migration definitions
//! through [`MigrationExecutorPort`](ariadnion_storage_domain::MigrationExecutorPort).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod orchestrator;
mod registry;

pub use orchestrator::{MigrationOrchestrator, MigrationRequest};
pub use registry::{MAX_REGISTERED_MIGRATIONS, MigrationRegistry};

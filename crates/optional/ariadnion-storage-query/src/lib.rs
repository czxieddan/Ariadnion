//! Database-independent contracts for registered, strongly typed queries.
//!
//! This crate defines immutable query schemas, exact value binding, and fixed
//! result projection. It does not parse SQL, plan statements, or execute a
//! database engine. Adapters receive only registered templates and validated
//! bindings, so request callers cannot supply arbitrary statement text.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod data;
mod error;
mod schema;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, TransactionPort};

pub use data::{
    QueryArgument, QueryBinding, QueryBytes, QueryResult, QueryRow, QueryText, QueryValue,
};
pub use error::{QueryContractError, QueryContractErrorCode};
pub use schema::{
    QueryCatalog, QueryColumnName, QueryId, QueryOperation, QueryParameter, QueryParameterName,
    QueryParameterRole, QueryResultColumn, QueryTemplate, QueryValueType,
};

/// Executes validated registered queries inside an existing transaction.
///
/// Implementations must interpret only the fixed text owned by
/// [`QueryTemplate`], verify that [`QueryBinding::is_for`] returns `true`, and
/// construct output through [`QueryResult::project`]. Cancellation, deadlines,
/// transaction access checks, database planning, and durable writes remain
/// adapter responsibilities.
pub trait FixedQueryExecutorPort: Send + Sync {
    /// Executes one registered query without accepting caller-provided SQL.
    ///
    /// The implementation returns a redacted [`StorageError`] when the
    /// transaction, request context, adapter, or database engine rejects the
    /// operation. A binding/template mismatch must fail before any statement is
    /// sent to the database.
    fn execute(
        &self,
        transaction: &mut dyn TransactionPort,
        template: &QueryTemplate,
        binding: &QueryBinding,
        context: &RequestContext,
    ) -> Result<QueryResult, StorageError>;
}

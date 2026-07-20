//! Bounded diagnostics for compiled-in RNMDB read queries.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, StorageErrorCode, StorageInstanceId};
use rnmdb_cli::CommandOutput;
use rnmdb_sql::ast::Statement;
use rnmdb_sql::parser::parse_statement;

use crate::RnmdbSessionOwner;

const MAX_FIXED_QUERY_BYTES: usize = 16 * 1024;
const MAX_PLAN_TEXT_BYTES: usize = 256 * 1024;

/// An RNMDB read query embedded in production code and parsed before use.
pub struct FixedRnmdbReadQuery {
    sql: &'static str,
}

impl FixedRnmdbReadQuery {
    /// Verifies a single, bounded, compiled-in `SELECT` statement.
    ///
    /// This boundary deliberately accepts only a `'static` string so request
    /// input cannot become an executable query. Binding domain values remains
    /// the responsibility of a typed repository rather than this diagnostic.
    pub fn verify(sql: &'static str) -> Result<Self, StorageError> {
        validate_fixed_query_length(sql)?;
        let statement = parse_statement(sql)
            .map_err(|_| StorageError::new(StorageErrorCode::InvalidArgument))?;
        if !matches!(statement, Statement::Select { .. }) {
            return Err(StorageError::new(StorageErrorCode::InvalidArgument));
        }
        Ok(Self { sql })
    }
}

impl Debug for FixedRnmdbReadQuery {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedRnmdbReadQuery")
            .field("bytes", &self.sql.len())
            .finish_non_exhaustive()
    }
}

/// Upstream planner representation requested for a fixed query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryPlanFormat {
    /// Optimized logical operators.
    Logical,
    /// Logical operators annotated with planner costs.
    Costs,
    /// Selected physical access paths and operators.
    Physical,
}

impl QueryPlanFormat {
    fn command_prefix(self) -> &'static str {
        match self {
            Self::Logical => "EXPLAIN ",
            Self::Costs => "EXPLAIN COSTS ",
            Self::Physical => "EXPLAIN PHYSICAL ",
        }
    }
}

/// Bounded planner output for internal diagnostics and index review.
pub struct QueryPlanDiagnostic {
    format: QueryPlanFormat,
    text: Box<str>,
}

impl QueryPlanDiagnostic {
    /// Returns the planner representation used for this result.
    #[must_use]
    pub const fn format(&self) -> QueryPlanFormat {
        self.format
    }

    /// Returns the bounded upstream plan text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl Debug for QueryPlanDiagnostic {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryPlanDiagnostic")
            .field("format", &self.format)
            .field("bytes", &self.text.len())
            .finish()
    }
}

/// Runs non-analyzing planner diagnostics through one serialized session.
pub struct RnmdbQueryDiagnostics {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbQueryDiagnostics {
    /// Creates diagnostics for one isolated RNMDB instance.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Returns the storage instance whose catalog is used for planning.
    #[must_use]
    pub fn instance(&self) -> &StorageInstanceId {
        self.session.instance()
    }

    /// Produces a bounded plan without running `EXPLAIN ANALYZE`.
    pub fn explain(
        &self,
        query: &FixedRnmdbReadQuery,
        format: QueryPlanFormat,
        context: &RequestContext,
    ) -> Result<QueryPlanDiagnostic, StorageError> {
        let command = build_explain_command(query, format)?;
        let output = self
            .session
            .with_session(context, |session| session.execute(&command))?;
        extract_plan(output, format)
    }
}

fn validate_fixed_query_length(sql: &str) -> Result<(), StorageError> {
    if sql.is_empty() || sql.len() > MAX_FIXED_QUERY_BYTES {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    Ok(())
}

fn build_explain_command(
    query: &FixedRnmdbReadQuery,
    format: QueryPlanFormat,
) -> Result<String, StorageError> {
    let capacity = format
        .command_prefix()
        .len()
        .checked_add(query.sql.len())
        .ok_or_else(|| StorageError::new(StorageErrorCode::ResourceExhausted))?;
    let mut command = String::with_capacity(capacity);
    command.push_str(format.command_prefix());
    command.push_str(query.sql);
    Ok(command)
}

fn extract_plan(
    output: CommandOutput,
    format: QueryPlanFormat,
) -> Result<QueryPlanDiagnostic, StorageError> {
    let CommandOutput::Text(text) = output else {
        return Err(StorageError::new(StorageErrorCode::Internal));
    };
    if text.len() > MAX_PLAN_TEXT_BYTES {
        return Err(StorageError::new(StorageErrorCode::ResourceExhausted));
    }
    Ok(QueryPlanDiagnostic {
        format,
        text: text.into_boxed_str(),
    })
}

//! Bounded diagnostics for compiled-in RNMDB read queries.

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::{
    StorageError, StorageErrorCode, StorageInstanceId, TransactionPort,
};
use ariadnion_storage_query::{
    FixedQueryExecutorPort, QueryArgument, QueryBinding, QueryBytes, QueryContractError,
    QueryContractErrorCode, QueryOperation, QueryParameterRole, QueryResult, QueryTemplate,
    QueryText, QueryValue, QueryValueType,
};
use rnmdb_cli::CommandOutput;
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_sql::ast::{Expr, SelectItem, Statement};
use rnmdb_sql::parser::parse_statement;
use rnmdb_types::{SqlType, SqlValue};
use zeroize::Zeroizing;

use crate::RnmdbSessionOwner;

const MAX_FIXED_QUERY_BYTES: usize = 16 * 1024;
const MAX_PLAN_TEXT_BYTES: usize = 256 * 1024;
const MAX_BOUND_QUERY_BYTES: usize = 2 * 1024 * 1024;
const MAX_QUERY_RESULT_ROWS: usize = 10_000;

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

/// Executes validated fixed read queries through one RNMDB transaction.
pub struct RnmdbFixedQueryExecutor {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbFixedQueryExecutor {
    /// Creates an executor for one serialized RNMDB session.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Returns the storage instance accepted by this executor.
    #[must_use]
    pub fn instance(&self) -> &StorageInstanceId {
        self.session.instance()
    }
}

impl FixedQueryExecutorPort for RnmdbFixedQueryExecutor {
    fn execute(
        &self,
        transaction: &mut dyn TransactionPort,
        template: &QueryTemplate,
        binding: &QueryBinding,
        context: &RequestContext,
    ) -> Result<QueryResult, StorageError> {
        validate_transaction_owner(&self.session, transaction)?;
        validate_read_contract(template, binding)?;
        let tenant = validate_tenant_binding(template, binding, context)?;
        let sql = render_query(template, binding)?;
        validate_rendered_select(&sql, tenant.as_ref())?;
        let output = execute_in_active_transaction(&self.session, &sql, context)?;
        project_query_result(template, output)
    }
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

fn validate_transaction_owner(
    session: &RnmdbSessionOwner,
    transaction: &dyn TransactionPort,
) -> Result<(), StorageError> {
    let same_instance = transaction.instance() == session.instance();
    let same_scope = transaction.scope().same_scope(session.transaction_scope());
    if !same_instance || !same_scope {
        return Err(StorageError::new(StorageErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn validate_read_contract(
    template: &QueryTemplate,
    binding: &QueryBinding,
) -> Result<(), StorageError> {
    if template.operation() != QueryOperation::Read {
        return Err(StorageError::new(StorageErrorCode::Unavailable));
    }
    if !binding.is_for(template) {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_tenant_binding(
    template: &QueryTemplate,
    binding: &QueryBinding,
    context: &RequestContext,
) -> Result<Option<TenantId>, StorageError> {
    let Some(parameter) = template
        .parameters()
        .iter()
        .find(|parameter| parameter.role() == QueryParameterRole::Tenant)
    else {
        return Ok(None);
    };
    let tenant = context
        .principal()
        .map(|principal| principal.tenant_id())
        .ok_or_else(integrity_failure)?;
    let argument = binding
        .arguments()
        .iter()
        .find(|argument| argument.name() == parameter.name())
        .ok_or_else(integrity_failure)?;
    let QueryValue::TenantId(bound_tenant) = argument.value() else {
        return Err(integrity_failure());
    };
    if bound_tenant != tenant {
        return Err(integrity_failure());
    }
    Ok(Some(tenant.clone()))
}

fn render_query(
    template: &QueryTemplate,
    binding: &QueryBinding,
) -> Result<Zeroizing<String>, StorageError> {
    let mut renderer = QueryRenderer::new(template.template());
    while renderer.render_next(binding)? {}
    renderer.finish(binding)
}

struct QueryRenderer<'a> {
    source: &'a str,
    rendered: Zeroizing<String>,
    used: BTreeSet<Box<str>>,
    cursor: usize,
}

impl<'a> QueryRenderer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            rendered: Zeroizing::new(String::with_capacity(source.len())),
            used: BTreeSet::new(),
            cursor: 0,
        }
    }

    fn render_next(&mut self, binding: &QueryBinding) -> Result<bool, StorageError> {
        let Some(relative_start) = self.source[self.cursor..].find("{{") else {
            return Ok(false);
        };
        let start = self.cursor + relative_start;
        reject_unmatched_close(&self.source[self.cursor..start])?;
        push_bounded(&mut self.rendered, &self.source[self.cursor..start])?;
        let (name, next) = placeholder_at(self.source, start)?;
        let argument = find_argument(binding.arguments(), name)?;
        append_query_literal(&mut self.rendered, argument.value())?;
        self.used.insert(argument.name().as_str().into());
        self.cursor = next;
        Ok(true)
    }

    fn finish(mut self, binding: &QueryBinding) -> Result<Zeroizing<String>, StorageError> {
        reject_unmatched_close(&self.source[self.cursor..])?;
        push_bounded(&mut self.rendered, &self.source[self.cursor..])?;
        if self.used.len() != binding.arguments().len() {
            return Err(invalid_argument());
        }
        Ok(self.rendered)
    }
}

fn reject_unmatched_close(value: &str) -> Result<(), StorageError> {
    if value.contains("}}") {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    Ok(())
}

fn placeholder_at(source: &str, start: usize) -> Result<(&str, usize), StorageError> {
    let content_start = start.checked_add(2).ok_or_else(resource_exhausted)?;
    let relative_end = source[content_start..]
        .find("}}")
        .ok_or_else(invalid_argument)?;
    let end = content_start
        .checked_add(relative_end)
        .ok_or_else(resource_exhausted)?;
    let next = end.checked_add(2).ok_or_else(resource_exhausted)?;
    let name = &source[content_start..end];
    if name.is_empty() || name.contains("{{") {
        return Err(invalid_argument());
    }
    Ok((name, next))
}

fn find_argument<'a>(
    arguments: &'a [QueryArgument],
    name: &str,
) -> Result<&'a QueryArgument, StorageError> {
    arguments
        .iter()
        .find(|argument| argument.name().as_str() == name)
        .ok_or_else(invalid_argument)
}

fn append_query_literal(sql: &mut String, value: &QueryValue) -> Result<(), StorageError> {
    match value {
        QueryValue::Boolean(value) => push_bounded(sql, if *value { "TRUE" } else { "FALSE" }),
        QueryValue::Int64(value) => push_bounded(sql, &value.to_string()),
        QueryValue::Text(value) => push_text_literal(sql, value.as_str()),
        QueryValue::TenantId(value) => push_text_literal(sql, value.as_str()),
        QueryValue::Bytes(_) => Err(StorageError::new(StorageErrorCode::Unavailable)),
        _ => Err(StorageError::new(StorageErrorCode::Unavailable)),
    }
}

fn push_text_literal(sql: &mut String, value: &str) -> Result<(), StorageError> {
    let maximum = value
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(2))
        .ok_or_else(resource_exhausted)?;
    ensure_bound(sql.len(), maximum)?;
    sql.push('\'');
    for character in value.chars() {
        if character == '\'' {
            sql.push_str("''");
        } else {
            sql.push(character);
        }
    }
    sql.push('\'');
    Ok(())
}

fn push_bounded(sql: &mut String, value: &str) -> Result<(), StorageError> {
    ensure_bound(sql.len(), value.len())?;
    sql.push_str(value);
    Ok(())
}

fn ensure_bound(current: usize, additional: usize) -> Result<(), StorageError> {
    let total = current
        .checked_add(additional)
        .ok_or_else(resource_exhausted)?;
    if total > MAX_BOUND_QUERY_BYTES {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn validate_rendered_select(sql: &str, tenant: Option<&TenantId>) -> Result<(), StorageError> {
    let statement = parse_statement(sql).map_err(|_| invalid_argument())?;
    let Statement::Select {
        projection,
        selection,
        limit,
        ..
    } = statement
    else {
        return Err(invalid_argument());
    };
    if projection
        .iter()
        .any(|item| matches!(item, SelectItem::Wildcard))
    {
        return Err(invalid_argument());
    }
    validate_select_limit(limit)?;
    require_tenant_predicate(selection.as_ref(), tenant)
}

fn validate_select_limit(limit: Option<usize>) -> Result<(), StorageError> {
    if limit.is_some_and(|value| value > 0 && value <= MAX_QUERY_RESULT_ROWS) {
        return Ok(());
    }
    Err(resource_exhausted())
}

fn require_tenant_predicate(
    selection: Option<&Expr>,
    tenant: Option<&TenantId>,
) -> Result<(), StorageError> {
    let Some(tenant) = tenant else {
        return Ok(());
    };
    if selection.is_some_and(|expr| predicate_guarantees_tenant(expr, tenant)) {
        return Ok(());
    }
    Err(integrity_failure())
}

fn predicate_guarantees_tenant(expr: &Expr, tenant: &TenantId) -> bool {
    let Expr::Binary { left, op, right } = expr else {
        return false;
    };
    if op == "AND" {
        return predicate_guarantees_tenant(left, tenant)
            || predicate_guarantees_tenant(right, tenant);
    }
    op == "=" && tenant_equality(left, right, tenant)
}

fn tenant_equality(left: &Expr, right: &Expr, tenant: &TenantId) -> bool {
    (is_tenant_column(left) && is_tenant_value(right, tenant))
        || (is_tenant_column(right) && is_tenant_value(left, tenant))
}

fn is_tenant_column(expr: &Expr) -> bool {
    match expr {
        Expr::Identifier(name) => name.as_str() == "tenant_id",
        Expr::QualifiedIdentifier { name, .. } => name.as_str() == "tenant_id",
        _ => false,
    }
}

fn is_tenant_value(expr: &Expr, tenant: &TenantId) -> bool {
    matches!(expr, Expr::String(value) if value == tenant.as_str())
}

fn execute_in_active_transaction(
    session: &RnmdbSessionOwner,
    sql: &str,
    context: &RequestContext,
) -> Result<CommandOutput, StorageError> {
    session.with_session(context, |local| {
        if !local.in_transaction() {
            return Err(RnovError::new(
                ErrorKind::Security,
                "fixed query requires an active transaction",
            ));
        }
        local.execute(sql)
    })
}

fn project_query_result(
    template: &QueryTemplate,
    output: CommandOutput,
) -> Result<QueryResult, StorageError> {
    let CommandOutput::Rows(batch) = output else {
        return Err(integrity_failure());
    };
    validate_result_batch(template, &batch)?;
    let rows = batch
        .rows()
        .iter()
        .map(|row| convert_result_row(template, row))
        .collect::<Result<Vec<_>, _>>()?;
    QueryResult::project(template, rows).map_err(map_projection_error)
}

fn validate_result_batch(
    template: &QueryTemplate,
    batch: &VectorBatch,
) -> Result<(), StorageError> {
    if batch.rows().len() > MAX_QUERY_RESULT_ROWS {
        return Err(resource_exhausted());
    }
    if batch.columns().len() != template.result_columns().len() {
        return Err(integrity_failure());
    }
    for (actual, expected) in batch.columns().iter().zip(template.result_columns()) {
        validate_result_column(actual, expected.name().as_str(), expected.value_type())?;
    }
    Ok(())
}

fn validate_result_column(
    actual: &ColumnSchema,
    expected_name: &str,
    expected_type: QueryValueType,
) -> Result<(), StorageError> {
    let data_type = query_sql_type(expected_type)?;
    if actual.name() != expected_name || actual.data_type() != &data_type {
        return Err(integrity_failure());
    }
    Ok(())
}

fn query_sql_type(value_type: QueryValueType) -> Result<SqlType, StorageError> {
    match value_type {
        QueryValueType::Boolean => Ok(SqlType::Bool),
        QueryValueType::Int64 => Ok(SqlType::Int64),
        QueryValueType::Text | QueryValueType::TenantId => Ok(SqlType::Text),
        QueryValueType::Bytes => Ok(SqlType::Bytes),
        _ => Err(StorageError::new(StorageErrorCode::Unavailable)),
    }
}

fn convert_result_row(
    template: &QueryTemplate,
    row: &Row,
) -> Result<Vec<QueryValue>, StorageError> {
    if row.values().len() != template.result_columns().len() {
        return Err(integrity_failure());
    }
    row.values()
        .iter()
        .zip(template.result_columns())
        .map(|(value, column)| convert_result_value(value, column.value_type()))
        .collect()
}

fn convert_result_value(
    value: &SqlValue,
    expected: QueryValueType,
) -> Result<QueryValue, StorageError> {
    match (value, expected) {
        (SqlValue::Bool(value), QueryValueType::Boolean) => Ok(QueryValue::Boolean(*value)),
        (SqlValue::Int64(value), QueryValueType::Int64) => Ok(QueryValue::Int64(*value)),
        (SqlValue::Text(value), QueryValueType::Text) => QueryText::new(value.clone())
            .map(QueryValue::Text)
            .map_err(map_projection_error),
        (SqlValue::Bytes(value), QueryValueType::Bytes) => QueryBytes::new(value)
            .map(QueryValue::Bytes)
            .map_err(map_projection_error),
        (SqlValue::Text(value), QueryValueType::TenantId) => TenantId::parse(value)
            .map(QueryValue::TenantId)
            .map_err(|_| integrity_failure()),
        _ => Err(integrity_failure()),
    }
}

fn map_projection_error(error: QueryContractError) -> StorageError {
    let code = match error.code() {
        QueryContractErrorCode::ResourceExhausted => StorageErrorCode::ResourceExhausted,
        _ => StorageErrorCode::IntegrityFailure,
    };
    StorageError::new(code)
}

const fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

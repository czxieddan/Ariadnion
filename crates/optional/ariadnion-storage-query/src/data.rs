use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use ariadnion_core::TenantId;

use crate::{
    QueryContractError, QueryContractErrorCode, QueryId, QueryParameterName, QueryResultColumn,
    QueryTemplate, QueryValueType,
};

const MAX_TEXT_BYTES: usize = 1024 * 1024;
const MAX_VALUE_BYTES: usize = 1024 * 1024;
const MAX_RESULT_ROWS: usize = 10_000;

/// A bounded UTF-8 query value whose debug representation hides its contents.
#[derive(Clone, Eq, PartialEq)]
pub struct QueryText(Box<str>);

impl QueryText {
    /// Copies text of at most 1 MiB.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, QueryContractError> {
        let value = value.into();
        if value.len() > MAX_TEXT_BYTES {
            return Err(error(QueryContractErrorCode::ResourceExhausted));
        }
        Ok(Self(value))
    }

    /// Returns the bounded text to trusted domain or adapter code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for QueryText {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryText")
            .field("utf8_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Bounded opaque query bytes whose debug representation hides their contents.
#[derive(Clone, Eq, PartialEq)]
pub struct QueryBytes(Box<[u8]>);

impl QueryBytes {
    /// Copies an opaque value of at most 1 MiB.
    pub fn new(value: &[u8]) -> Result<Self, QueryContractError> {
        if value.len() > MAX_VALUE_BYTES {
            return Err(error(QueryContractErrorCode::ResourceExhausted));
        }
        Ok(Self(value.into()))
    }

    /// Returns the bounded bytes to trusted domain or adapter code.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for QueryBytes {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryBytes")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A strongly typed value accepted by query bindings and projections.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum QueryValue {
    /// A Boolean value.
    Boolean(bool),
    /// A signed 64-bit integer.
    Int64(i64),
    /// Bounded UTF-8 text.
    Text(QueryText),
    /// Bounded opaque bytes.
    Bytes(QueryBytes),
    /// A validated Ariadnion tenant identity.
    TenantId(TenantId),
}

impl QueryValue {
    /// Returns the stable schema type of this value.
    #[must_use]
    pub const fn value_type(&self) -> QueryValueType {
        match self {
            Self::Boolean(_) => QueryValueType::Boolean,
            Self::Int64(_) => QueryValueType::Int64,
            Self::Text(_) => QueryValueType::Text,
            Self::Bytes(_) => QueryValueType::Bytes,
            Self::TenantId(_) => QueryValueType::TenantId,
        }
    }
}

impl Debug for QueryValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(value) => formatter.debug_tuple("Boolean").field(value).finish(),
            Self::Int64(value) => formatter.debug_tuple("Int64").field(value).finish(),
            Self::Text(value) => formatter.debug_tuple("Text").field(value).finish(),
            Self::Bytes(value) => formatter.debug_tuple("Bytes").field(value).finish(),
            Self::TenantId(value) => formatter.debug_tuple("TenantId").field(value).finish(),
        }
    }
}

/// One named strongly typed argument supplied to a registered query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryArgument {
    name: QueryParameterName,
    value: QueryValue,
}

impl QueryArgument {
    /// Creates a named typed argument without associating it with raw SQL.
    #[must_use]
    pub const fn new(name: QueryParameterName, value: QueryValue) -> Self {
        Self { name, value }
    }

    /// Returns the stable parameter name.
    #[must_use]
    pub const fn name(&self) -> &QueryParameterName {
        &self.name
    }

    /// Returns the strongly typed value.
    #[must_use]
    pub const fn value(&self) -> &QueryValue {
        &self.value
    }
}

/// An exact validated binding for one registered query identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryBinding {
    query_id: QueryId,
    arguments: Vec<QueryArgument>,
}

impl QueryBinding {
    /// Binds the exact registered parameter key set and validates every type.
    ///
    /// Arguments may arrive in any order and are normalized to parameter-name
    /// order. Missing, unknown, duplicate, or mistyped arguments fail before an
    /// adapter can observe the binding. Text and bytes remain redacted in all
    /// derived debug output.
    pub fn bind(
        template: &QueryTemplate,
        mut arguments: Vec<QueryArgument>,
    ) -> Result<Self, QueryContractError> {
        validate_argument_count(template, &arguments)?;
        validate_unique_argument_names(&arguments)?;
        arguments.sort_by(|left, right| left.name.cmp(&right.name));
        validate_argument_schema(template, &arguments)?;
        Ok(Self {
            query_id: template.id().clone(),
            arguments,
        })
    }

    /// Returns the registered query identity associated with this binding.
    #[must_use]
    pub const fn query_id(&self) -> &QueryId {
        &self.query_id
    }

    /// Returns arguments in deterministic parameter-name order.
    #[must_use]
    pub fn arguments(&self) -> &[QueryArgument] {
        &self.arguments
    }

    /// Returns whether this binding belongs to the supplied fixed template.
    #[must_use]
    pub fn is_for(&self, template: &QueryTemplate) -> bool {
        &self.query_id == template.id()
    }
}

/// One row validated against a registered fixed projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryRow {
    values: Vec<QueryValue>,
}

impl QueryRow {
    /// Returns values in the registered result-column order.
    #[must_use]
    pub fn values(&self) -> &[QueryValue] {
        &self.values
    }
}

/// A bounded result whose rows match one registered projection exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryResult {
    query_id: QueryId,
    columns: Vec<QueryResultColumn>,
    rows: Vec<QueryRow>,
}

impl QueryResult {
    /// Projects typed rows through a template's fixed ordered column schema.
    ///
    /// At most 10,000 rows are accepted. Every row must have the exact column
    /// count and value types declared by the template; no column reordering or
    /// implicit conversion occurs.
    pub fn project(
        template: &QueryTemplate,
        rows: Vec<Vec<QueryValue>>,
    ) -> Result<Self, QueryContractError> {
        validate_result_row_count(&rows)?;
        validate_result_rows(template.result_columns(), &rows)?;
        let rows = rows.into_iter().map(|values| QueryRow { values }).collect();
        Ok(Self {
            query_id: template.id().clone(),
            columns: template.result_columns().to_vec(),
            rows,
        })
    }

    /// Returns the registered query identity that defines this result.
    #[must_use]
    pub const fn query_id(&self) -> &QueryId {
        &self.query_id
    }

    /// Returns columns in their fixed registered order.
    #[must_use]
    pub fn columns(&self) -> &[QueryResultColumn] {
        &self.columns
    }

    /// Returns projected rows in adapter-provided order.
    #[must_use]
    pub fn rows(&self) -> &[QueryRow] {
        &self.rows
    }
}

fn validate_argument_count(
    template: &QueryTemplate,
    arguments: &[QueryArgument],
) -> Result<(), QueryContractError> {
    if arguments.len() != template.parameters().len() {
        return Err(error(QueryContractErrorCode::BindingMismatch));
    }
    Ok(())
}

fn validate_unique_argument_names(arguments: &[QueryArgument]) -> Result<(), QueryContractError> {
    let names = arguments
        .iter()
        .map(QueryArgument::name)
        .collect::<BTreeSet<_>>();
    if names.len() != arguments.len() {
        return Err(error(QueryContractErrorCode::BindingMismatch));
    }
    Ok(())
}

fn validate_argument_schema(
    template: &QueryTemplate,
    arguments: &[QueryArgument],
) -> Result<(), QueryContractError> {
    for (parameter, argument) in template.parameters().iter().zip(arguments) {
        if parameter.name() != argument.name() {
            return Err(error(QueryContractErrorCode::BindingMismatch));
        }
        if parameter.value_type() != argument.value().value_type() {
            return Err(error(QueryContractErrorCode::TypeMismatch));
        }
    }
    Ok(())
}

fn validate_result_row_count(rows: &[Vec<QueryValue>]) -> Result<(), QueryContractError> {
    if rows.len() > MAX_RESULT_ROWS {
        return Err(error(QueryContractErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn validate_result_rows(
    columns: &[QueryResultColumn],
    rows: &[Vec<QueryValue>],
) -> Result<(), QueryContractError> {
    for row in rows {
        validate_result_row(columns, row)?;
    }
    Ok(())
}

fn validate_result_row(
    columns: &[QueryResultColumn],
    row: &[QueryValue],
) -> Result<(), QueryContractError> {
    if columns.len() != row.len() {
        return Err(error(QueryContractErrorCode::ProjectionMismatch));
    }
    for (column, value) in columns.iter().zip(row) {
        if column.value_type() != value.value_type() {
            return Err(error(QueryContractErrorCode::ProjectionMismatch));
        }
    }
    Ok(())
}

const fn error(code: QueryContractErrorCode) -> QueryContractError {
    QueryContractError::new(code)
}

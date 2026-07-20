use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};

use crate::{QueryContractError, QueryContractErrorCode};

const MAX_QUERY_ID_BYTES: usize = 128;
const MAX_FIELD_NAME_BYTES: usize = 64;
const MAX_TEMPLATE_BYTES: usize = 32 * 1024;
const MAX_PARAMETERS: usize = 64;
const MAX_RESULT_COLUMNS: usize = 128;
const MAX_REGISTERED_QUERIES: usize = 1_024;

/// A bounded stable identity for one registered query.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueryId(Box<str>);

impl QueryId {
    /// Parses a non-empty ASCII identity of at most 128 bytes.
    ///
    /// The accepted alphabet is letters, digits, dots, hyphens, underscores,
    /// and colons. Invalid input is never retained in the returned error.
    pub fn parse(value: &str) -> Result<Self, QueryContractError> {
        validate_identifier(value, MAX_QUERY_ID_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for QueryId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded stable parameter name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueryParameterName(Box<str>);

impl QueryParameterName {
    /// Parses a non-empty ASCII parameter name of at most 64 bytes.
    pub fn parse(value: &str) -> Result<Self, QueryContractError> {
        validate_identifier(value, MAX_FIELD_NAME_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated parameter name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for QueryParameterName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded stable result-column name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueryColumnName(Box<str>);

impl QueryColumnName {
    /// Parses a non-empty ASCII result-column name of at most 64 bytes.
    pub fn parse(value: &str) -> Result<Self, QueryContractError> {
        validate_identifier(value, MAX_FIELD_NAME_BYTES)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated result-column name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for QueryColumnName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The persistent effect category declared by a registered query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryOperation {
    /// The query observes data without persistent mutation.
    Read,
    /// The query may create, update, or delete persistent data.
    Write,
}

/// Stable scalar types accepted by query parameters and result columns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QueryValueType {
    /// A Boolean value.
    Boolean,
    /// A signed 64-bit integer.
    Int64,
    /// Bounded UTF-8 text.
    Text,
    /// Bounded opaque bytes.
    Bytes,
    /// A validated Ariadnion tenant identity.
    TenantId,
}

/// The security role assigned to a required query parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryParameterRole {
    /// An ordinary required input value.
    Input,
    /// The required tenant boundary applied by a tenant-scoped query.
    Tenant,
}

/// One required named parameter in a fixed query schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryParameter {
    name: QueryParameterName,
    value_type: QueryValueType,
    role: QueryParameterRole,
}

impl QueryParameter {
    /// Creates a required parameter and validates the tenant role type.
    ///
    /// Tenant parameters must use [`QueryValueType::TenantId`]. All registered
    /// parameters are mandatory because bindings require the exact key set.
    pub fn new(
        name: QueryParameterName,
        value_type: QueryValueType,
        role: QueryParameterRole,
    ) -> Result<Self, QueryContractError> {
        if role == QueryParameterRole::Tenant && value_type != QueryValueType::TenantId {
            return Err(error(QueryContractErrorCode::TypeMismatch));
        }
        Ok(Self {
            name,
            value_type,
            role,
        })
    }

    /// Returns the stable parameter name.
    #[must_use]
    pub const fn name(&self) -> &QueryParameterName {
        &self.name
    }

    /// Returns the required value type.
    #[must_use]
    pub const fn value_type(&self) -> QueryValueType {
        self.value_type
    }

    /// Returns the parameter security role.
    #[must_use]
    pub const fn role(&self) -> QueryParameterRole {
        self.role
    }
}

/// One column in the fixed ordered result projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryResultColumn {
    name: QueryColumnName,
    value_type: QueryValueType,
}

impl QueryResultColumn {
    /// Creates a named result column with a stable value type.
    #[must_use]
    pub const fn new(name: QueryColumnName, value_type: QueryValueType) -> Self {
        Self { name, value_type }
    }

    /// Returns the stable result-column name.
    #[must_use]
    pub const fn name(&self) -> &QueryColumnName {
        &self.name
    }

    /// Returns the required value type.
    #[must_use]
    pub const fn value_type(&self) -> QueryValueType {
        self.value_type
    }
}

/// An immutable registered query with fixed statement text and typed schemas.
#[derive(Clone, Eq, PartialEq)]
pub struct QueryTemplate {
    id: QueryId,
    operation: QueryOperation,
    template: &'static str,
    parameters: Vec<QueryParameter>,
    result_columns: Vec<QueryResultColumn>,
}

impl QueryTemplate {
    /// Registers a compile-time query template and validates all hard bounds.
    ///
    /// The statement must be a non-empty static string no larger than 32 KiB.
    /// Parameter order is normalized by name. Result columns preserve their
    /// declaration order because that order is part of the projection contract.
    /// Duplicate names, excessive schema sizes, and invalid tenant declarations
    /// fail without retaining the rejected statement text.
    pub fn register(
        id: QueryId,
        operation: QueryOperation,
        template: &'static str,
        mut parameters: Vec<QueryParameter>,
        result_columns: Vec<QueryResultColumn>,
    ) -> Result<Self, QueryContractError> {
        validate_template_text(template)?;
        validate_schema_bounds(&parameters, &result_columns)?;
        validate_unique_parameters(&parameters)?;
        validate_unique_columns(&result_columns)?;
        validate_tenant_parameters(operation, &parameters)?;
        parameters.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(Self {
            id,
            operation,
            template,
            parameters,
            result_columns,
        })
    }

    /// Returns the stable query identity.
    #[must_use]
    pub const fn id(&self) -> &QueryId {
        &self.id
    }

    /// Returns the declared read or write category.
    #[must_use]
    pub const fn operation(&self) -> QueryOperation {
        self.operation
    }

    /// Returns the fixed static statement text for an adapter implementation.
    ///
    /// Request-facing code must pass a registered [`QueryId`] and typed values,
    /// never statement text. This accessor exists only for trusted adapters.
    #[must_use]
    pub const fn template(&self) -> &'static str {
        self.template
    }

    /// Returns required parameters in deterministic name order.
    #[must_use]
    pub fn parameters(&self) -> &[QueryParameter] {
        &self.parameters
    }

    /// Returns result columns in the fixed projection order.
    #[must_use]
    pub fn result_columns(&self) -> &[QueryResultColumn] {
        &self.result_columns
    }
}

impl Debug for QueryTemplate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryTemplate")
            .field("id", &self.id)
            .field("operation", &self.operation)
            .field("parameter_count", &self.parameters.len())
            .field("result_column_count", &self.result_columns.len())
            .finish_non_exhaustive()
    }
}

/// A bounded immutable catalog of uniquely identified fixed queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryCatalog {
    templates: Vec<QueryTemplate>,
}

impl QueryCatalog {
    /// Creates a deterministic catalog and rejects duplicate query identities.
    pub fn new(mut templates: Vec<QueryTemplate>) -> Result<Self, QueryContractError> {
        if templates.len() > MAX_REGISTERED_QUERIES {
            return Err(error(QueryContractErrorCode::ResourceExhausted));
        }
        validate_unique_query_ids(&templates)?;
        templates.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Self { templates })
    }

    /// Returns all templates in stable query-identity order.
    #[must_use]
    pub fn templates(&self) -> &[QueryTemplate] {
        &self.templates
    }

    /// Finds a fixed template by its stable identity.
    #[must_use]
    pub fn get(&self, id: &QueryId) -> Option<&QueryTemplate> {
        self.templates
            .binary_search_by(|template| template.id.cmp(id))
            .ok()
            .map(|index| &self.templates[index])
    }
}

fn validate_identifier(value: &str, limit: usize) -> Result<(), QueryContractError> {
    if value.is_empty() || value.len() > limit || !value.is_ascii() {
        return Err(error(QueryContractErrorCode::InvalidArgument));
    }
    if value.bytes().any(is_invalid_identifier_byte) {
        return Err(error(QueryContractErrorCode::InvalidArgument));
    }
    Ok(())
}

fn is_invalid_identifier_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_' | b':')
}

fn validate_template_text(template: &str) -> Result<(), QueryContractError> {
    if template.trim().is_empty() {
        return Err(error(QueryContractErrorCode::InvalidArgument));
    }
    if template.len() > MAX_TEMPLATE_BYTES {
        return Err(error(QueryContractErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn validate_schema_bounds(
    parameters: &[QueryParameter],
    result_columns: &[QueryResultColumn],
) -> Result<(), QueryContractError> {
    if parameters.len() > MAX_PARAMETERS || result_columns.len() > MAX_RESULT_COLUMNS {
        return Err(error(QueryContractErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn validate_unique_parameters(parameters: &[QueryParameter]) -> Result<(), QueryContractError> {
    let names = parameters
        .iter()
        .map(QueryParameter::name)
        .collect::<BTreeSet<_>>();
    validate_unique_count(names.len(), parameters.len())
}

fn validate_unique_columns(columns: &[QueryResultColumn]) -> Result<(), QueryContractError> {
    let names = columns
        .iter()
        .map(QueryResultColumn::name)
        .collect::<BTreeSet<_>>();
    validate_unique_count(names.len(), columns.len())
}

fn validate_unique_query_ids(templates: &[QueryTemplate]) -> Result<(), QueryContractError> {
    let ids = templates
        .iter()
        .map(QueryTemplate::id)
        .collect::<BTreeSet<_>>();
    validate_unique_count(ids.len(), templates.len())
}

fn validate_unique_count(unique: usize, total: usize) -> Result<(), QueryContractError> {
    if unique != total {
        return Err(error(QueryContractErrorCode::Conflict));
    }
    Ok(())
}

fn validate_tenant_parameters(
    operation: QueryOperation,
    parameters: &[QueryParameter],
) -> Result<(), QueryContractError> {
    let tenant_count = parameters
        .iter()
        .filter(|parameter| parameter.role == QueryParameterRole::Tenant)
        .count();
    match operation {
        QueryOperation::Write if tenant_count != 1 => {
            Err(error(QueryContractErrorCode::TenantParameterRequired))
        }
        QueryOperation::Read if tenant_count > 1 => {
            Err(error(QueryContractErrorCode::InvalidArgument))
        }
        QueryOperation::Read | QueryOperation::Write => Ok(()),
    }
}

const fn error(code: QueryContractErrorCode) -> QueryContractError {
    QueryContractError::new(code)
}

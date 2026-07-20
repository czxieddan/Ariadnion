//! Typed creation of reviewed RNMDB index definitions.

use std::fmt::Write;
use std::sync::Arc;

use ariadnion_core::RequestContext;
use ariadnion_storage_domain::{StorageError, StorageErrorCode, StorageInstanceId};
use rnmdb_cli::CommandOutput;
use rnmdb_sql::ast::Statement;
use rnmdb_sql::parser::parse_statement;

use crate::RnmdbSessionOwner;

const MAX_IDENTIFIER_BYTES: usize = 63;
const MAX_INDEX_COLUMNS: usize = 16;

/// RNMDB access method selected for a reviewed index definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnmdbIndexMethod {
    /// Ordered B-tree keys, including bounded composite keys.
    BTree,
    /// Exact-match hash access for one column.
    Hash,
    /// Generalized inverted access for one collection column.
    Gin,
    /// Inverted full-text or value access for one column.
    Inverted,
    /// Generalized search-tree access for one range column.
    Gist,
    /// Block-range summaries for one ordered column.
    Brin,
    /// Block summaries for one supported column.
    Summary,
}

impl RnmdbIndexMethod {
    fn sql_keyword(self) -> &'static str {
        match self {
            Self::BTree => "btree",
            Self::Hash => "hash",
            Self::Gin => "gin",
            Self::Inverted => "inverted",
            Self::Gist => "gist",
            Self::Brin => "brin",
            Self::Summary => "summary",
        }
    }

    fn supports_columns(self, count: usize) -> bool {
        self == Self::BTree || count == 1
    }

    fn supports_unique(self) -> bool {
        matches!(self, Self::BTree | Self::Hash)
    }
}

/// A validated index definition that cannot contain SQL fragments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedIndexDefinition {
    name: Box<str>,
    table: Box<str>,
    columns: Vec<Box<str>>,
    method: RnmdbIndexMethod,
    unique: bool,
}

impl FixedIndexDefinition {
    /// Validates one public-schema index and its bounded column set.
    pub fn new(
        name: &str,
        table: &str,
        columns: &[&str],
        method: RnmdbIndexMethod,
        unique: bool,
    ) -> Result<Self, StorageError> {
        validate_definition_identifiers(name, table, columns)?;
        validate_method_shape(method, unique, columns.len())?;
        Ok(Self {
            name: name.into(),
            table: table.into(),
            columns: columns.iter().map(|column| (*column).into()).collect(),
            method,
            unique,
        })
    }

    /// Returns the stable index name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the indexed public-schema table.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Returns the ordered index columns.
    #[must_use]
    pub fn columns(&self) -> &[Box<str>] {
        &self.columns
    }

    /// Returns the selected upstream access method.
    #[must_use]
    pub const fn method(&self) -> RnmdbIndexMethod {
        self.method
    }

    /// Returns whether duplicate keys are rejected.
    #[must_use]
    pub const fn unique(&self) -> bool {
        self.unique
    }
}

/// Applies validated index definitions through one serialized session.
pub struct RnmdbIndexManager {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbIndexManager {
    /// Creates an index manager for one isolated storage instance.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Returns the storage instance whose catalog will change.
    #[must_use]
    pub fn instance(&self) -> &StorageInstanceId {
        self.session.instance()
    }

    /// Creates exactly one reviewed index definition.
    ///
    /// The command intentionally omits `IF NOT EXISTS`; an existing name must
    /// fail instead of silently accepting an incompatible index definition.
    pub fn create(
        &self,
        definition: &FixedIndexDefinition,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let sql = build_create_index_sql(definition)?;
        validate_generated_statement(&sql)?;
        let output = self
            .session
            .with_session(context, |session| session.execute(&sql))?;
        require_schema_change(output)
    }
}

fn validate_definition_identifiers(
    name: &str,
    table: &str,
    columns: &[&str],
) -> Result<(), StorageError> {
    if !valid_identifier(name) || !valid_identifier(table) {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    if columns.is_empty() || columns.len() > MAX_INDEX_COLUMNS {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    if columns.iter().any(|column| !valid_identifier(column)) {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    Ok(())
}

fn validate_method_shape(
    method: RnmdbIndexMethod,
    unique: bool,
    column_count: usize,
) -> Result<(), StorageError> {
    if !method.supports_columns(column_count) || (unique && !method.supports_unique()) {
        return Err(StorageError::new(StorageErrorCode::InvalidArgument));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= MAX_IDENTIFIER_BYTES
        && (first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn build_create_index_sql(definition: &FixedIndexDefinition) -> Result<String, StorageError> {
    let mut sql = String::with_capacity(256);
    sql.push_str("CREATE ");
    if definition.unique {
        sql.push_str("UNIQUE ");
    }
    write!(
        sql,
        "INDEX {} ON public.{} USING {} (",
        definition.name,
        definition.table,
        definition.method.sql_keyword()
    )
    .map_err(|_| StorageError::new(StorageErrorCode::Internal))?;
    append_columns(&mut sql, &definition.columns);
    sql.push_str(");");
    Ok(sql)
}

fn append_columns(sql: &mut String, columns: &[Box<str>]) {
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push_str(column);
    }
}

fn validate_generated_statement(sql: &str) -> Result<(), StorageError> {
    let statement =
        parse_statement(sql).map_err(|_| StorageError::new(StorageErrorCode::InvalidArgument))?;
    if !matches!(statement, Statement::CreateIndex { .. }) {
        return Err(StorageError::new(StorageErrorCode::Internal));
    }
    Ok(())
}

fn require_schema_change(output: CommandOutput) -> Result<(), StorageError> {
    if output != CommandOutput::SchemaChanged {
        return Err(StorageError::new(StorageErrorCode::Internal));
    }
    Ok(())
}

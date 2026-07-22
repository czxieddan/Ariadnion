//! Bounded canonical AST V1 encoding for migration checksums.

use ariadnion_storage_domain::{MigrationChecksum, StorageError, StorageErrorCode};
use rnmdb_catalog::{IndexMethod, Privilege};
use rnmdb_sql::ast::{
    CaseWhen, ColumnDef, ColumnReference, Expr, GeneratedColumn, Ident, IndexKeyDef, ObjectName,
    Statement,
};
use rnmdb_sql::lexer::{Token, TokenKind, lex};
use rnmdb_sql::parser::parse_statement;
use rnmdb_types::SqlType;
use sha2::{Digest, Sha256};

const CANONICAL_FORMAT: &[u8] = b"ariadnion-migration-ast";
const CANONICAL_VERSION: [u8; 2] = 1_u16.to_be_bytes();
const MAX_MIGRATION_STATEMENTS: usize = 1_024;
const MAX_MIGRATION_SOURCE_BYTES: usize = 1_048_576;
const MAX_TOTAL_MIGRATION_SOURCE_BYTES: usize = 4_194_304;
const MAX_CANONICAL_BYTES: usize = 8_388_608;
const MAX_CANONICAL_COLLECTION_ITEMS: usize = 1_024;
const MAX_EXPRESSION_DEPTH: usize = 64;
const MAX_SQL_TYPE_DEPTH: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Delimiter {
    Parenthesis,
    Bracket,
}

struct PreparseBudget {
    delimiters: Vec<Delimiter>,
    expression_tokens: usize,
    type_wrappers: usize,
    collection_items: usize,
    saw_comma: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct CanonicalAstV1;

impl CanonicalAstV1 {
    pub(super) fn checksum(statements: &[&str]) -> Result<MigrationChecksum, StorageError> {
        validate_migration_sources(statements)?;
        let mut encoder = checksum_encoder(statements.len())?;
        encode_statements(&mut encoder, statements)?;
        Ok(MigrationChecksum::new(
            Sha256::digest(encoder.as_bytes()).into(),
        ))
    }

    pub(super) fn validate(statements: &[&str]) -> Result<(), StorageError> {
        Self::checksum(statements).map(|_checksum| ())
    }
}

fn checksum_encoder(statement_count: usize) -> Result<CanonicalEncoder, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.field(1, CANONICAL_FORMAT)?;
    encoder.field(2, &CANONICAL_VERSION)?;
    encoder.count(3, statement_count)?;
    Ok(encoder)
}

fn encode_statements(
    encoder: &mut CanonicalEncoder,
    statements: &[&str],
) -> Result<(), StorageError> {
    for source in statements {
        encode_one_statement(encoder, source)?;
    }
    Ok(())
}

fn encode_one_statement(encoder: &mut CanonicalEncoder, source: &str) -> Result<(), StorageError> {
    let statement = parse_migration_statement(source)?;
    let encoded = encode_statement(&statement)?;
    encoder.nested(4, encoded)
}

fn validate_migration_sources(statements: &[&str]) -> Result<(), StorageError> {
    if statements.is_empty() {
        return Err(invalid_argument());
    }
    if statements.len() > MAX_MIGRATION_STATEMENTS {
        return Err(resource_exhausted());
    }
    let mut total = 0_usize;
    for source in statements {
        if source.len() > MAX_MIGRATION_SOURCE_BYTES {
            return Err(resource_exhausted());
        }
        total = total
            .checked_add(source.len())
            .ok_or_else(resource_exhausted)?;
        if total > MAX_TOTAL_MIGRATION_SOURCE_BYTES {
            return Err(resource_exhausted());
        }
    }
    Ok(())
}

fn parse_migration_statement(source: &str) -> Result<Statement, StorageError> {
    validate_preparse_statement(source)?;
    parse_statement(source).map_err(|_| integrity_failure())
}

fn validate_preparse_statement(source: &str) -> Result<(), StorageError> {
    // RNMDB's iterative lexer omits comments and emits each string as one token.
    let tokens = lex(source).map_err(|_| integrity_failure())?;
    validate_preparse_budgets(&tokens)?;
    validate_statement_surface(&tokens)
}

fn validate_preparse_budgets(tokens: &[Token]) -> Result<(), StorageError> {
    let mut budget = PreparseBudget::new();
    for index in 0..tokens.len() {
        budget.observe(tokens, index)?;
    }
    budget.finish()
}

impl PreparseBudget {
    const fn new() -> Self {
        Self {
            delimiters: Vec::new(),
            expression_tokens: 0,
            type_wrappers: 0,
            collection_items: 0,
            saw_comma: false,
        }
    }

    fn observe(&mut self, tokens: &[Token], index: usize) -> Result<(), StorageError> {
        update_delimiters(&mut self.delimiters, tokens[index].kind())?;
        self.expression_tokens = increment_if(
            self.expression_tokens,
            increases_expression_depth(tokens, index),
        )?;
        self.type_wrappers =
            increment_if(self.type_wrappers, increases_sql_type_depth(tokens, index))?;
        self.observe_collection_growth(tokens[index].kind())?;
        enforce_preparse_recursion_budget(self.delimiters.len(), self.expression_tokens)?;
        enforce_sql_type_budget(self.type_wrappers)
    }

    fn observe_collection_growth(&mut self, token: &TokenKind) -> Result<(), StorageError> {
        let growth = collection_growth(token, self.saw_comma);
        self.saw_comma |= matches!(token, TokenKind::Comma);
        self.collection_items = increment_by(self.collection_items, growth)?;
        enforce_collection_budget(self.collection_items)
    }

    fn finish(self) -> Result<(), StorageError> {
        if !self.delimiters.is_empty() {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

fn update_delimiters(
    delimiters: &mut Vec<Delimiter>,
    token: &TokenKind,
) -> Result<(), StorageError> {
    match token {
        TokenKind::LeftParen => delimiters.push(Delimiter::Parenthesis),
        TokenKind::LeftBracket => delimiters.push(Delimiter::Bracket),
        TokenKind::RightParen => pop_delimiter(delimiters, Delimiter::Parenthesis)?,
        TokenKind::RightBracket => pop_delimiter(delimiters, Delimiter::Bracket)?,
        _ => {}
    }
    Ok(())
}

fn pop_delimiter(delimiters: &mut Vec<Delimiter>, expected: Delimiter) -> Result<(), StorageError> {
    if delimiters.pop() != Some(expected) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn increases_expression_depth(tokens: &[Token], index: usize) -> bool {
    match tokens[index].kind() {
        TokenKind::Not => !next_token_is_null(tokens, index),
        TokenKind::And
        | TokenKind::Or
        | TokenKind::Union
        | TokenKind::Intersect
        | TokenKind::Except
        | TokenKind::Case
        | TokenKind::Is
        | TokenKind::Between
        | TokenKind::In
        | TokenKind::Like
        | TokenKind::Operator(_)
        | TokenKind::Star => true,
        _ => false,
    }
}

const fn collection_growth(token: &TokenKind, saw_comma: bool) -> usize {
    // The first comma proves two collection items; each later comma adds one.
    match token {
        TokenKind::Comma if saw_comma => 1,
        TokenKind::Comma => 2,
        TokenKind::When => 1,
        _ => 0,
    }
}

fn next_token_is_null(tokens: &[Token], index: usize) -> bool {
    next_token_kind(tokens, index) == Some(&TokenKind::Null)
}

fn increases_sql_type_depth(tokens: &[Token], index: usize) -> bool {
    match tokens[index].kind() {
        TokenKind::LeftBracket => next_token_kind(tokens, index) == Some(&TokenKind::RightBracket),
        TokenKind::Identifier(name) if name == "range" => {
            matches!(next_token_kind(tokens, index), Some(TokenKind::Operator(value)) if value == "<")
        }
        _ => false,
    }
}

fn next_token_kind(tokens: &[Token], index: usize) -> Option<&TokenKind> {
    index
        .checked_add(1)
        .and_then(|next| tokens.get(next))
        .map(Token::kind)
}

fn increment_if(value: usize, condition: bool) -> Result<usize, StorageError> {
    if condition {
        return increment_by(value, 1);
    }
    Ok(value)
}

fn increment_by(value: usize, amount: usize) -> Result<usize, StorageError> {
    value.checked_add(amount).ok_or_else(resource_exhausted)
}

fn enforce_preparse_recursion_budget(
    delimiter_depth: usize,
    expression_tokens: usize,
) -> Result<(), StorageError> {
    let recursion_budget = delimiter_depth
        .checked_add(expression_tokens)
        .ok_or_else(resource_exhausted)?;
    if recursion_budget > MAX_EXPRESSION_DEPTH {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn enforce_sql_type_budget(type_wrappers: usize) -> Result<(), StorageError> {
    if type_wrappers > MAX_SQL_TYPE_DEPTH {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn enforce_collection_budget(collection_items: usize) -> Result<(), StorageError> {
    if collection_items > MAX_CANONICAL_COLLECTION_ITEMS {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn validate_statement_surface(tokens: &[Token]) -> Result<(), StorageError> {
    if !has_supported_statement_prefix(tokens) {
        return Err(integrity_failure());
    }
    if contains_nested_query(tokens) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn has_supported_statement_prefix(tokens: &[Token]) -> bool {
    match token_kind(tokens, 0) {
        Some(TokenKind::Create) => has_supported_create_prefix(tokens),
        Some(TokenKind::Grant) => true,
        _ => false,
    }
}

fn has_supported_create_prefix(tokens: &[Token]) -> bool {
    match token_kind(tokens, 1) {
        Some(TokenKind::Unique) => token_kind(tokens, 2) == Some(&TokenKind::Index),
        Some(TokenKind::Table | TokenKind::Index | TokenKind::Role | TokenKind::Policy) => true,
        _ => false,
    }
}

fn contains_nested_query(tokens: &[Token]) -> bool {
    for (index, token) in tokens.iter().enumerate() {
        if is_nested_query_token(tokens, index, token.kind()) {
            return true;
        }
    }
    false
}

fn is_nested_query_token(tokens: &[Token], index: usize, token: &TokenKind) -> bool {
    match token {
        TokenKind::With => true,
        TokenKind::Select => !is_grant_select(tokens, index),
        _ => false,
    }
}

fn is_grant_select(tokens: &[Token], index: usize) -> bool {
    index == 1 && token_kind(tokens, 0) == Some(&TokenKind::Grant)
}

fn token_kind(tokens: &[Token], index: usize) -> Option<&TokenKind> {
    tokens.get(index).map(Token::kind)
}

fn encode_statement(statement: &Statement) -> Result<Vec<u8>, StorageError> {
    match statement {
        Statement::CreateTable {
            name,
            columns,
            if_not_exists,
        } => encode_create_table(name, columns, *if_not_exists),
        Statement::CreateIndex {
            name,
            table,
            keys,
            method,
            unique,
            if_not_exists,
        } => encode_create_index(name, table, keys, *method, *unique, *if_not_exists),
        Statement::CreateRole {
            name,
            if_not_exists,
        } => encode_create_role(name, *if_not_exists),
        Statement::CreatePolicy {
            name,
            table,
            predicate,
            if_not_exists,
        } => encode_create_policy(name, table, predicate, *if_not_exists),
        Statement::GrantTablePrivilege {
            privilege,
            table,
            role,
        } => encode_grant_table(*privilege, table, role),
        _ => Err(integrity_failure()),
    }
}

fn encode_create_table(
    name: &ObjectName,
    columns: &[ColumnDef],
    if_not_exists: bool,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = statement_encoder(1)?;
    encoder.nested(2, encode_object_name(name)?)?;
    encoder.nested(3, encode_columns(columns)?)?;
    encoder.boolean(4, if_not_exists)?;
    Ok(encoder.finish())
}

fn encode_create_index(
    name: &ObjectName,
    table: &ObjectName,
    keys: &[IndexKeyDef],
    method: IndexMethod,
    unique: bool,
    if_not_exists: bool,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = encode_index_identity(name, table, keys)?;
    encode_index_options(&mut encoder, method, unique, if_not_exists)?;
    Ok(encoder.finish())
}

fn encode_index_identity(
    name: &ObjectName,
    table: &ObjectName,
    keys: &[IndexKeyDef],
) -> Result<CanonicalEncoder, StorageError> {
    let mut encoder = statement_encoder(2)?;
    encoder.nested(2, encode_object_name(name)?)?;
    encoder.nested(3, encode_object_name(table)?)?;
    encoder.nested(4, encode_index_keys(keys)?)?;
    Ok(encoder)
}

fn encode_index_options(
    encoder: &mut CanonicalEncoder,
    method: IndexMethod,
    unique: bool,
    if_not_exists: bool,
) -> Result<(), StorageError> {
    encoder.variant(5, index_method_tag(method))?;
    encoder.boolean(6, unique)?;
    encoder.boolean(7, if_not_exists)
}

fn encode_create_role(name: &Ident, if_not_exists: bool) -> Result<Vec<u8>, StorageError> {
    let mut encoder = statement_encoder(3)?;
    encoder.text(2, name.as_str())?;
    encoder.boolean(3, if_not_exists)?;
    Ok(encoder.finish())
}

fn encode_create_policy(
    name: &Ident,
    table: &ObjectName,
    predicate: &Expr,
    if_not_exists: bool,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = statement_encoder(4)?;
    encoder.text(2, name.as_str())?;
    encoder.nested(3, encode_object_name(table)?)?;
    encoder.nested(4, encode_expr(predicate, 0)?)?;
    encoder.boolean(5, if_not_exists)?;
    Ok(encoder.finish())
}

fn encode_grant_table(
    privilege: Privilege,
    table: &ObjectName,
    role: &Ident,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = statement_encoder(5)?;
    encoder.variant(2, table_privilege_tag(privilege)?)?;
    encoder.nested(3, encode_object_name(table)?)?;
    encoder.text(4, role.as_str())?;
    Ok(encoder.finish())
}

fn statement_encoder(tag: u8) -> Result<CanonicalEncoder, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, tag)?;
    Ok(encoder)
}

fn encode_object_name(name: &ObjectName) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    match name.schema() {
        Some(schema) => {
            encoder.boolean(1, true)?;
            encoder.text(2, schema)?;
        }
        None => encoder.boolean(1, false)?,
    }
    encoder.text(3, name.object())?;
    Ok(encoder.finish())
}

fn encode_columns(columns: &[ColumnDef]) -> Result<Vec<u8>, StorageError> {
    let mut encoder = sequence_encoder(columns.len())?;
    for column in columns {
        encoder.nested(2, encode_column(column)?)?;
    }
    Ok(encoder.finish())
}

fn encode_column(column: &ColumnDef) -> Result<Vec<u8>, StorageError> {
    let mut encoder = encode_column_identity(column)?;
    encode_column_options(&mut encoder, column)?;
    Ok(encoder.finish())
}

fn encode_column_identity(column: &ColumnDef) -> Result<CanonicalEncoder, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(1, column.name.as_str())?;
    encoder.nested(2, encode_sql_type(&column.data_type, 0)?)?;
    encoder.boolean(3, column.nullable)?;
    Ok(encoder)
}

fn encode_column_options(
    encoder: &mut CanonicalEncoder,
    column: &ColumnDef,
) -> Result<(), StorageError> {
    encoder.boolean(4, column.encrypted)?;
    encoder.nested(5, encode_generated(column.generated.as_ref())?)?;
    encoder.nested(6, encode_reference(column.references.as_ref())?)
}

fn encode_generated(value: Option<&GeneratedColumn>) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    match value {
        Some(generated) => {
            encoder.boolean(1, true)?;
            encoder.nested(2, encode_expr(&generated.expr, 0)?)?;
            encoder.boolean(3, generated.stored)?;
        }
        None => encoder.boolean(1, false)?,
    }
    Ok(encoder.finish())
}

fn encode_reference(value: Option<&ColumnReference>) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    match value {
        Some(reference) => {
            encoder.boolean(1, true)?;
            encoder.nested(2, encode_object_name(&reference.table)?)?;
            encoder.text(3, reference.column.as_str())?;
        }
        None => encoder.boolean(1, false)?,
    }
    Ok(encoder.finish())
}

fn encode_index_keys(keys: &[IndexKeyDef]) -> Result<Vec<u8>, StorageError> {
    let mut encoder = sequence_encoder(keys.len())?;
    for key in keys {
        encoder.nested(2, encode_index_key(key)?)?;
    }
    Ok(encoder.finish())
}

fn encode_index_key(key: &IndexKeyDef) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    match key {
        IndexKeyDef::Column(column) => {
            encoder.variant(1, 1)?;
            encoder.text(2, column.as_str())?;
        }
        IndexKeyDef::Expression(expression) => {
            encoder.variant(1, 2)?;
            encoder.nested(2, encode_expr(expression, 0)?)?;
        }
    }
    Ok(encoder.finish())
}

fn index_method_tag(method: IndexMethod) -> u8 {
    match method {
        IndexMethod::BTree => 1,
        IndexMethod::Hash => 2,
        IndexMethod::Gin => 3,
        IndexMethod::Gist => 4,
        IndexMethod::Brin => 5,
    }
}

fn table_privilege_tag(privilege: Privilege) -> Result<u8, StorageError> {
    match privilege {
        Privilege::Select => Ok(1),
        Privilege::Insert => Ok(2),
        Privilege::Update => Ok(3),
        Privilege::Delete => Ok(4),
        Privilege::Execute => Err(integrity_failure()),
    }
}

fn encode_sql_type(data_type: &SqlType, depth: usize) -> Result<Vec<u8>, StorageError> {
    require_depth(depth, MAX_SQL_TYPE_DEPTH)?;
    match data_type {
        SqlType::Bool | SqlType::Int64 | SqlType::UInt64 | SqlType::Float64 | SqlType::Uuid => {
            encode_scalar_sql_type_one(data_type)
        }
        SqlType::Timestamp
        | SqlType::Json
        | SqlType::Text
        | SqlType::Bytes
        | SqlType::HStore
        | SqlType::TextVector => encode_scalar_sql_type_two(data_type),
        SqlType::Array(element) => encode_nested_sql_type(13, element, depth),
        SqlType::Range(element) => encode_nested_sql_type(14, element, depth),
        SqlType::Null => Err(integrity_failure()),
    }
}

fn encode_scalar_sql_type_one(data_type: &SqlType) -> Result<Vec<u8>, StorageError> {
    let tag = match data_type {
        SqlType::Bool => 2,
        SqlType::Int64 => 3,
        SqlType::UInt64 => 4,
        SqlType::Float64 => 5,
        SqlType::Uuid => 6,
        _ => return Err(integrity_failure()),
    };
    encode_variant_only(tag)
}

fn encode_scalar_sql_type_two(data_type: &SqlType) -> Result<Vec<u8>, StorageError> {
    let tag = match data_type {
        SqlType::Timestamp => 7,
        SqlType::Json => 8,
        SqlType::Text => 9,
        SqlType::Bytes => 10,
        SqlType::HStore => 11,
        SqlType::TextVector => 12,
        _ => return Err(integrity_failure()),
    };
    encode_variant_only(tag)
}

fn encode_nested_sql_type(
    tag: u8,
    element: &SqlType,
    depth: usize,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, tag)?;
    encoder.nested(2, encode_sql_type(element, next_depth(depth)?)?)?;
    Ok(encoder.finish())
}

fn encode_expr(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    require_depth(depth, MAX_EXPRESSION_DEPTH)?;
    match expression {
        Expr::Identifier(_)
        | Expr::QualifiedIdentifier { .. }
        | Expr::Integer(_)
        | Expr::Float64(_)
        | Expr::String(_)
        | Expr::Bool(_)
        | Expr::Null => encode_atom_expr(expression),
        Expr::Array(_) | Expr::HStore(_) | Expr::Range { .. } => {
            encode_collection_expr(expression, depth)
        }
        Expr::Binary { .. } | Expr::Unary { .. } | Expr::Not(_) => {
            encode_operator_expr(expression, depth)
        }
        Expr::IsNull { .. }
        | Expr::IsTruth { .. }
        | Expr::IsUnknown { .. }
        | Expr::IsDistinctFrom { .. }
        | Expr::Between { .. }
        | Expr::InList { .. }
        | Expr::Like { .. } => encode_predicate_expr(expression, depth),
        Expr::Coalesce(_)
        | Expr::NullIf { .. }
        | Expr::Case { .. }
        | Expr::Cast { .. }
        | Expr::Call { .. } => encode_function_expr(expression, depth),
        _ => Err(integrity_failure()),
    }
}

fn encode_atom_expr(expression: &Expr) -> Result<Vec<u8>, StorageError> {
    match expression {
        Expr::Identifier(_)
        | Expr::QualifiedIdentifier { .. }
        | Expr::Integer(_)
        | Expr::Float64(_) => encode_atom_expr_one(expression),
        Expr::String(_) | Expr::Bool(_) | Expr::Null => encode_atom_expr_two(expression),
        _ => Err(integrity_failure()),
    }
}

fn encode_atom_expr_one(expression: &Expr) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    match expression {
        Expr::Identifier(value) => encode_ident_atom(&mut encoder, 1, value)?,
        Expr::QualifiedIdentifier { qualifier, name } => {
            encoder.variant(1, 2)?;
            encoder.text(2, qualifier.as_str())?;
            encoder.text(3, name.as_str())?;
        }
        Expr::Integer(value) => encode_integer_atom(&mut encoder, 3, *value)?,
        Expr::Float64(value) => encode_u64_atom(&mut encoder, 4, value.to_bits())?,
        _ => return Err(integrity_failure()),
    }
    Ok(encoder.finish())
}

fn encode_atom_expr_two(expression: &Expr) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    match expression {
        Expr::String(value) => encode_text_atom(&mut encoder, 5, value)?,
        Expr::Bool(value) => encode_bool_atom(&mut encoder, 6, *value)?,
        Expr::Null => encoder.variant(1, 7)?,
        _ => return Err(integrity_failure()),
    }
    Ok(encoder.finish())
}

fn encode_collection_expr(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    match expression {
        Expr::Array(values) => encode_array_expr(values, depth),
        Expr::HStore(entries) => encode_hstore_expr(entries),
        Expr::Range {
            lower,
            upper,
            bounds,
        } => encode_range_expr(lower, upper, *bounds, depth),
        _ => Err(integrity_failure()),
    }
}

fn encode_array_expr(values: &[Expr], depth: usize) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 20)?;
    encoder.nested(2, encode_expr_list(values, next_depth(depth)?)?)?;
    Ok(encoder.finish())
}

fn encode_hstore_expr(entries: &[(String, Option<String>)]) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 21)?;
    encoder.nested(2, encode_hstore_entries(entries)?)?;
    Ok(encoder.finish())
}

fn encode_range_expr(
    lower: &Expr,
    upper: &Expr,
    bounds: rnmdb_sql::ast::RangeLiteralBounds,
    depth: usize,
) -> Result<Vec<u8>, StorageError> {
    let child_depth = next_depth(depth)?;
    let mut encoder = encode_range_bounds(lower, upper, child_depth)?;
    encoder.boolean(4, bounds.lower_inclusive)?;
    encoder.boolean(5, bounds.upper_inclusive)?;
    Ok(encoder.finish())
}

fn encode_range_bounds(
    lower: &Expr,
    upper: &Expr,
    depth: usize,
) -> Result<CanonicalEncoder, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 22)?;
    encoder.nested(2, encode_expr(lower, depth)?)?;
    encoder.nested(3, encode_expr(upper, depth)?)?;
    Ok(encoder)
}

fn encode_operator_expr(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    match expression {
        Expr::Binary { left, op, right } => encode_binary_operator(left, op, right, depth),
        Expr::Unary { op, expr } => encode_unary_operator(op, expr, depth),
        Expr::Not(expr) => encode_not_operator(expr, depth),
        _ => Err(integrity_failure()),
    }
}

fn encode_binary_operator(
    left: &Expr,
    operator: &str,
    right: &Expr,
    depth: usize,
) -> Result<Vec<u8>, StorageError> {
    let child_depth = next_depth(depth)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 30)?;
    encoder.nested(2, encode_expr(left, child_depth)?)?;
    encoder.text(3, operator)?;
    encoder.nested(4, encode_expr(right, child_depth)?)?;
    Ok(encoder.finish())
}

fn encode_unary_operator(
    operator: &str,
    expression: &Expr,
    depth: usize,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 31)?;
    encoder.text(2, operator)?;
    encoder.nested(3, encode_expr(expression, next_depth(depth)?)?)?;
    Ok(encoder.finish())
}

fn encode_not_operator(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 32)?;
    encoder.nested(2, encode_expr(expression, next_depth(depth)?)?)?;
    Ok(encoder.finish())
}

fn encode_predicate_expr(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    match expression {
        Expr::IsNull { .. } | Expr::IsTruth { .. } | Expr::IsUnknown { .. } => {
            encode_unary_predicate_expr(expression, depth)
        }
        Expr::IsDistinctFrom { .. } | Expr::Like { .. } => {
            encode_binary_predicate_expr(expression, depth)
        }
        Expr::Between { .. } | Expr::InList { .. } => {
            encode_range_predicate_expr(expression, depth)
        }
        _ => Err(integrity_failure()),
    }
}

fn encode_unary_predicate_expr(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    let child_depth = next_depth(depth)?;
    let mut encoder = CanonicalEncoder::new();
    let result = match expression {
        Expr::IsNull { expr, negated } => {
            encode_unary_predicate(&mut encoder, 40, expr, *negated, child_depth)
        }
        Expr::IsTruth {
            expr,
            value,
            negated,
        } => encode_truth_predicate(&mut encoder, 41, expr, *value, *negated, child_depth),
        Expr::IsUnknown { expr, negated } => {
            encode_unary_predicate(&mut encoder, 42, expr, *negated, child_depth)
        }
        _ => Err(integrity_failure()),
    };
    result?;
    Ok(encoder.finish())
}

fn encode_binary_predicate_expr(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    let child_depth = next_depth(depth)?;
    let mut encoder = CanonicalEncoder::new();
    let result = match expression {
        Expr::IsDistinctFrom {
            left,
            right,
            negated,
        } => encode_binary_predicate(&mut encoder, 43, left, right, *negated, child_depth),
        Expr::Like {
            expr,
            pattern,
            negated,
        } => encode_binary_predicate(&mut encoder, 46, expr, pattern, *negated, child_depth),
        _ => Err(integrity_failure()),
    };
    result?;
    Ok(encoder.finish())
}

fn encode_range_predicate_expr(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    let child_depth = next_depth(depth)?;
    let mut encoder = CanonicalEncoder::new();
    let result = match expression {
        Expr::Between {
            expr,
            low,
            high,
            negated,
        } => encode_between(&mut encoder, expr, low, high, *negated, child_depth),
        Expr::InList {
            expr,
            values,
            negated,
        } => encode_in_list(&mut encoder, expr, values, *negated, child_depth),
        _ => Err(integrity_failure()),
    };
    result?;
    Ok(encoder.finish())
}

fn encode_function_expr(expression: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    match expression {
        Expr::Coalesce(values) => encode_coalesce(values, depth),
        Expr::NullIf { left, right } => encode_null_if(left, right, depth),
        Expr::Case {
            operand,
            whens,
            else_expr,
        } => encode_case_expr(operand.as_deref(), whens, else_expr.as_deref(), depth),
        Expr::Cast { expr, data_type } => encode_cast(expr, data_type, depth),
        Expr::Call {
            function_id,
            name,
            args,
        } => encode_call_expr(function_id.is_some(), name, args, depth),
        _ => Err(integrity_failure()),
    }
}

fn encode_coalesce(values: &[Expr], depth: usize) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 50)?;
    encoder.nested(2, encode_expr_list(values, next_depth(depth)?)?)?;
    Ok(encoder.finish())
}

fn encode_null_if(left: &Expr, right: &Expr, depth: usize) -> Result<Vec<u8>, StorageError> {
    let child_depth = next_depth(depth)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 51)?;
    encoder.nested(2, encode_expr(left, child_depth)?)?;
    encoder.nested(3, encode_expr(right, child_depth)?)?;
    Ok(encoder.finish())
}

fn encode_case_expr(
    operand: Option<&Expr>,
    whens: &[CaseWhen],
    else_expr: Option<&Expr>,
    depth: usize,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encode_case(&mut encoder, operand, whens, else_expr, next_depth(depth)?)?;
    Ok(encoder.finish())
}

fn encode_cast(
    expression: &Expr,
    data_type: &SqlType,
    depth: usize,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 53)?;
    encoder.nested(2, encode_expr(expression, next_depth(depth)?)?)?;
    encoder.nested(3, encode_sql_type(data_type, 0)?)?;
    Ok(encoder.finish())
}

fn encode_call_expr(
    bound: bool,
    name: &ObjectName,
    args: &[Expr],
    depth: usize,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encode_call(&mut encoder, bound, name, args, next_depth(depth)?)?;
    Ok(encoder.finish())
}

fn encode_ident_atom(
    encoder: &mut CanonicalEncoder,
    tag: u8,
    value: &Ident,
) -> Result<(), StorageError> {
    encoder.variant(1, tag)?;
    encoder.text(2, value.as_str())
}

fn encode_integer_atom(
    encoder: &mut CanonicalEncoder,
    tag: u8,
    value: i64,
) -> Result<(), StorageError> {
    encoder.variant(1, tag)?;
    encoder.field(2, &value.to_be_bytes())
}

fn encode_u64_atom(
    encoder: &mut CanonicalEncoder,
    tag: u8,
    value: u64,
) -> Result<(), StorageError> {
    encoder.variant(1, tag)?;
    encoder.field(2, &value.to_be_bytes())
}

fn encode_text_atom(
    encoder: &mut CanonicalEncoder,
    tag: u8,
    value: &str,
) -> Result<(), StorageError> {
    encoder.variant(1, tag)?;
    encoder.text(2, value)
}

fn encode_bool_atom(
    encoder: &mut CanonicalEncoder,
    tag: u8,
    value: bool,
) -> Result<(), StorageError> {
    encoder.variant(1, tag)?;
    encoder.boolean(2, value)
}

fn encode_hstore_entries(entries: &[(String, Option<String>)]) -> Result<Vec<u8>, StorageError> {
    let mut encoder = sequence_encoder(entries.len())?;
    for (key, value) in entries {
        let mut entry = CanonicalEncoder::new();
        entry.text(1, key)?;
        entry.nested(2, encode_optional_text(value.as_deref())?)?;
        encoder.nested(2, entry.finish())?;
    }
    Ok(encoder.finish())
}

fn encode_optional_text(value: Option<&str>) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    match value {
        Some(value) => {
            encoder.boolean(1, true)?;
            encoder.text(2, value)?;
        }
        None => encoder.boolean(1, false)?,
    }
    Ok(encoder.finish())
}

fn encode_unary_predicate(
    encoder: &mut CanonicalEncoder,
    tag: u8,
    expression: &Expr,
    negated: bool,
    depth: usize,
) -> Result<(), StorageError> {
    encoder.variant(1, tag)?;
    encoder.nested(2, encode_expr(expression, depth)?)?;
    encoder.boolean(3, negated)
}

fn encode_truth_predicate(
    encoder: &mut CanonicalEncoder,
    tag: u8,
    expression: &Expr,
    value: bool,
    negated: bool,
    depth: usize,
) -> Result<(), StorageError> {
    encoder.variant(1, tag)?;
    encoder.nested(2, encode_expr(expression, depth)?)?;
    encoder.boolean(3, value)?;
    encoder.boolean(4, negated)
}

fn encode_binary_predicate(
    encoder: &mut CanonicalEncoder,
    tag: u8,
    left: &Expr,
    right: &Expr,
    negated: bool,
    depth: usize,
) -> Result<(), StorageError> {
    encoder.variant(1, tag)?;
    encoder.nested(2, encode_expr(left, depth)?)?;
    encoder.nested(3, encode_expr(right, depth)?)?;
    encoder.boolean(4, negated)
}

fn encode_between(
    encoder: &mut CanonicalEncoder,
    expression: &Expr,
    low: &Expr,
    high: &Expr,
    negated: bool,
    depth: usize,
) -> Result<(), StorageError> {
    encoder.variant(1, 44)?;
    encoder.nested(2, encode_expr(expression, depth)?)?;
    encoder.nested(3, encode_expr(low, depth)?)?;
    encoder.nested(4, encode_expr(high, depth)?)?;
    encoder.boolean(5, negated)
}

fn encode_in_list(
    encoder: &mut CanonicalEncoder,
    expression: &Expr,
    values: &[Expr],
    negated: bool,
    depth: usize,
) -> Result<(), StorageError> {
    encoder.variant(1, 45)?;
    encoder.nested(2, encode_expr(expression, depth)?)?;
    encoder.nested(3, encode_expr_list(values, depth)?)?;
    encoder.boolean(4, negated)
}

fn encode_case(
    encoder: &mut CanonicalEncoder,
    operand: Option<&Expr>,
    whens: &[CaseWhen],
    else_expr: Option<&Expr>,
    depth: usize,
) -> Result<(), StorageError> {
    encoder.variant(1, 52)?;
    encoder.nested(2, encode_optional_expr(operand, depth)?)?;
    encoder.nested(3, encode_case_whens(whens, depth)?)?;
    encoder.nested(4, encode_optional_expr(else_expr, depth)?)
}

fn encode_case_whens(whens: &[CaseWhen], depth: usize) -> Result<Vec<u8>, StorageError> {
    let mut encoder = sequence_encoder(whens.len())?;
    for when in whens {
        let mut arm = CanonicalEncoder::new();
        arm.nested(1, encode_expr(&when.condition, depth)?)?;
        arm.nested(2, encode_expr(&when.result, depth)?)?;
        encoder.nested(2, arm.finish())?;
    }
    Ok(encoder.finish())
}

fn encode_call(
    encoder: &mut CanonicalEncoder,
    bound: bool,
    name: &ObjectName,
    args: &[Expr],
    depth: usize,
) -> Result<(), StorageError> {
    if bound {
        return Err(integrity_failure());
    }
    encoder.variant(1, 54)?;
    encoder.nested(2, encode_object_name(name)?)?;
    encoder.nested(3, encode_expr_list(args, depth)?)
}

fn encode_optional_expr(expression: Option<&Expr>, depth: usize) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    match expression {
        Some(expression) => {
            encoder.boolean(1, true)?;
            encoder.nested(2, encode_expr(expression, depth)?)?;
        }
        None => encoder.boolean(1, false)?,
    }
    Ok(encoder.finish())
}

fn encode_expr_list(values: &[Expr], depth: usize) -> Result<Vec<u8>, StorageError> {
    let mut encoder = sequence_encoder(values.len())?;
    for value in values {
        encoder.nested(2, encode_expr(value, depth)?)?;
    }
    Ok(encoder.finish())
}

fn encode_variant_only(tag: u8) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, tag)?;
    Ok(encoder.finish())
}

fn sequence_encoder(length: usize) -> Result<CanonicalEncoder, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.count(1, length)?;
    Ok(encoder)
}

fn require_depth(depth: usize, maximum: usize) -> Result<(), StorageError> {
    if depth > maximum {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn next_depth(depth: usize) -> Result<usize, StorageError> {
    depth.checked_add(1).ok_or_else(resource_exhausted)
}

struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), StorageError> {
        let length = u64::try_from(value.len()).map_err(|_| resource_exhausted())?;
        let added = 9_usize
            .checked_add(value.len())
            .ok_or_else(resource_exhausted)?;
        let final_length = self
            .bytes
            .len()
            .checked_add(added)
            .ok_or_else(resource_exhausted)?;
        if final_length > MAX_CANONICAL_BYTES {
            return Err(resource_exhausted());
        }
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn text(&mut self, tag: u8, value: &str) -> Result<(), StorageError> {
        self.field(tag, value.as_bytes())
    }

    fn variant(&mut self, tag: u8, value: u8) -> Result<(), StorageError> {
        self.field(tag, &[value])
    }

    fn boolean(&mut self, tag: u8, value: bool) -> Result<(), StorageError> {
        self.variant(tag, u8::from(value))
    }

    fn count(&mut self, tag: u8, value: usize) -> Result<(), StorageError> {
        if value > MAX_CANONICAL_COLLECTION_ITEMS {
            return Err(resource_exhausted());
        }
        let value = u64::try_from(value).map_err(|_| resource_exhausted())?;
        self.field(tag, &value.to_be_bytes())
    }

    fn nested(&mut self, tag: u8, value: Vec<u8>) -> Result<(), StorageError> {
        self.field(tag, &value)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
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

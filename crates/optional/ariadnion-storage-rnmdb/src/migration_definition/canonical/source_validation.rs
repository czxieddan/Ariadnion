//! Bounded source and lexical validation for canonical migrations.

use ariadnion_storage_domain::StorageError;
use rnmdb_sql::ast::Statement;
use rnmdb_sql::lexer::{Token, TokenKind, lex};
use rnmdb_sql::parser::parse_statement;

use super::{
    MAX_CANONICAL_COLLECTION_ITEMS, MAX_EXPRESSION_DEPTH, MAX_SQL_TYPE_DEPTH, integrity_failure,
    invalid_argument, resource_exhausted,
};

const MAX_MIGRATION_STATEMENTS: usize = 1_024;
const MAX_MIGRATION_SOURCE_BYTES: usize = 1_048_576;
const MAX_TOTAL_MIGRATION_SOURCE_BYTES: usize = 4_194_304;

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

pub(super) fn validate_migration_sources(statements: &[&str]) -> Result<(), StorageError> {
    validate_statement_count(statements)?;
    let mut total = 0_usize;
    for source in statements {
        total = accumulate_source_bytes(total, source)?;
    }
    Ok(())
}

fn validate_statement_count(statements: &[&str]) -> Result<(), StorageError> {
    reject_empty_sources(statements)?;
    enforce_statement_limit(statements.len())
}

fn reject_empty_sources(statements: &[&str]) -> Result<(), StorageError> {
    if statements.is_empty() {
        return Err(invalid_argument());
    }
    Ok(())
}

fn enforce_statement_limit(count: usize) -> Result<(), StorageError> {
    if count > MAX_MIGRATION_STATEMENTS {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn accumulate_source_bytes(total: usize, source: &str) -> Result<usize, StorageError> {
    enforce_source_limit(source.len())?;
    let total = checked_source_total(total, source.len())?;
    enforce_total_source_limit(total)?;
    Ok(total)
}

fn enforce_source_limit(length: usize) -> Result<(), StorageError> {
    if length > MAX_MIGRATION_SOURCE_BYTES {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn checked_source_total(total: usize, length: usize) -> Result<usize, StorageError> {
    total.checked_add(length).ok_or_else(resource_exhausted)
}

fn enforce_total_source_limit(total: usize) -> Result<(), StorageError> {
    if total > MAX_TOTAL_MIGRATION_SOURCE_BYTES {
        return Err(resource_exhausted());
    }
    Ok(())
}

pub(super) fn parse_migration_statement(source: &str) -> Result<Statement, StorageError> {
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
        TokenKind::Identifier(name) => is_range_wrapper(name, next_token_kind(tokens, index)),
        _ => false,
    }
}

fn is_range_wrapper(name: &str, next: Option<&TokenKind>) -> bool {
    name == "range" && matches!(next, Some(TokenKind::Operator(value)) if value == "<")
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
        Some(TokenKind::Alter) => token_kind(tokens, 1) == Some(&TokenKind::Table),
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

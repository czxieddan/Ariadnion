// crates/optional/ariadnion-storage-rnmdb/src/migration_definition/canonical.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Bounded canonical AST V1 encoding for migration checksums.

mod scalar_encoding;
mod source_validation;

use ariadnion_storage_domain::{MigrationChecksum, StorageError, StorageErrorCode};
use rnmdb_catalog::{IndexMethod, Privilege};
use rnmdb_sql::ast::{
    CaseWhen, ColumnDef, ColumnReference, Expr, GeneratedColumn, Ident, IndexKeyDef, ObjectName,
    Statement,
};
use rnmdb_types::SqlType;
use sha2::{Digest, Sha256};

use self::scalar_encoding::{
    encode_atom_expr, encode_scalar_sql_type_one, encode_scalar_sql_type_two,
};
use self::source_validation::{parse_migration_statement, validate_migration_sources};

const CANONICAL_FORMAT: &[u8] = b"ariadnion-migration-ast";
const CANONICAL_VERSION: [u8; 2] = 1_u16.to_be_bytes();
const MAX_CANONICAL_BYTES: usize = 8_388_608;
const MAX_CANONICAL_COLLECTION_ITEMS: usize = 1_024;
const MAX_EXPRESSION_DEPTH: usize = 64;
const MAX_SQL_TYPE_DEPTH: usize = 16;

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
        Statement::AlterTableAddColumn {
            table,
            column,
            if_not_exists,
        } => encode_alter_table_add_column(table, column, *if_not_exists),
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

fn encode_alter_table_add_column(
    table: &ObjectName,
    column: &ColumnDef,
    if_not_exists: bool,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = statement_encoder(6)?;
    encoder.nested(2, encode_object_name(table)?)?;
    encoder.nested(3, encode_column(column)?)?;
    encoder.boolean(4, if_not_exists)?;
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

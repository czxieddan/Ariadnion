//! Canonical scalar SQL type and atom expression encoding.

use ariadnion_storage_domain::StorageError;
use rnmdb_sql::ast::{Expr, Ident};
use rnmdb_types::SqlType;

use super::{CanonicalEncoder, encode_variant_only, integrity_failure};

pub(super) fn encode_scalar_sql_type_one(data_type: &SqlType) -> Result<Vec<u8>, StorageError> {
    let tag = scalar_sql_type_one_tag(data_type).ok_or_else(integrity_failure)?;
    encode_variant_only(tag)
}

fn scalar_sql_type_one_tag(data_type: &SqlType) -> Option<u8> {
    match data_type {
        SqlType::Bool => Some(2),
        SqlType::Int64 => Some(3),
        SqlType::UInt64 => Some(4),
        SqlType::Float64 => Some(5),
        SqlType::Uuid => Some(6),
        _ => None,
    }
}

pub(super) fn encode_scalar_sql_type_two(data_type: &SqlType) -> Result<Vec<u8>, StorageError> {
    let tag = scalar_sql_type_two_tag(data_type).ok_or_else(integrity_failure)?;
    encode_variant_only(tag)
}

fn scalar_sql_type_two_tag(data_type: &SqlType) -> Option<u8> {
    match data_type {
        SqlType::Timestamp => Some(7),
        SqlType::Json => Some(8),
        SqlType::Text => Some(9),
        SqlType::Bytes => Some(10),
        SqlType::HStore => Some(11),
        SqlType::TextVector => Some(12),
        _ => None,
    }
}

pub(super) fn encode_atom_expr(expression: &Expr) -> Result<Vec<u8>, StorageError> {
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
    match expression {
        Expr::Identifier(value) => encode_ident_atom(1, value),
        Expr::QualifiedIdentifier { qualifier, name } => {
            encode_qualified_ident_atom(qualifier, name)
        }
        Expr::Integer(value) => encode_integer_atom(3, *value),
        Expr::Float64(value) => encode_u64_atom(4, value.to_bits()),
        _ => Err(integrity_failure()),
    }
}

fn encode_atom_expr_two(expression: &Expr) -> Result<Vec<u8>, StorageError> {
    match expression {
        Expr::String(value) => encode_text_atom(5, value),
        Expr::Bool(value) => encode_bool_atom(6, *value),
        Expr::Null => encode_variant_only(7),
        _ => Err(integrity_failure()),
    }
}

fn encode_qualified_ident_atom(qualifier: &Ident, name: &Ident) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, 2)?;
    encoder.text(2, qualifier.as_str())?;
    encoder.text(3, name.as_str())?;
    Ok(encoder.finish())
}

fn encode_ident_atom(tag: u8, value: &Ident) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, tag)?;
    encoder.text(2, value.as_str())?;
    Ok(encoder.finish())
}

fn encode_integer_atom(tag: u8, value: i64) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, tag)?;
    encoder.field(2, &value.to_be_bytes())?;
    Ok(encoder.finish())
}

fn encode_u64_atom(tag: u8, value: u64) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, tag)?;
    encoder.field(2, &value.to_be_bytes())?;
    Ok(encoder.finish())
}

fn encode_text_atom(tag: u8, value: &str) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, tag)?;
    encoder.text(2, value)?;
    Ok(encoder.finish())
}

fn encode_bool_atom(tag: u8, value: bool) -> Result<Vec<u8>, StorageError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.variant(1, tag)?;
    encoder.boolean(2, value)?;
    Ok(encoder.finish())
}

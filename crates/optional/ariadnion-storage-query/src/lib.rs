// crates/optional/ariadnion-storage-query/src/lib.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
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

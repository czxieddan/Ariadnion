// crates/optional/ariadnion-storage-rnmdb/src/file_catalog_repository/sql.rs - Rust source for Ariadnion.
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
//! Fixed SQL and strict durable decoding for the file metadata catalog.

use ariadnion_api_files::{
    FileByteLength, FileCatalogRecord, FileDescriptor, FileDisplayName, FileMediaType,
    FileReference,
};
use ariadnion_core::{PrincipalContext, RequestContext};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicBool, Ordering};

use super::evidence::{COMMITTED_OUTCOME, DELETE_KIND, PUBLISH_KIND, decode_fixed_hex, encode_hex};
use super::{FileCatalogCommitmentKeyVersion, FileCatalogCommitmentKeys};
use crate::session::check_context;

const ENTRY_TABLE: &str = "files_catalog_entries";
const OPERATION_TABLE: &str = "files_catalog_operations";
const ENTRY_PROJECTION: &str = "tenant_id, owner_principal_id, reference_hex, display_name, media_type, byte_length, digest_hex";
const OPERATION_PROJECTION: &str = "tenant_id, owner_principal_id, operation_kind, idempotency_lookup_hex, request_commitment_hex, reference_hex, commitment_key_version, outcome";
const MAX_LIST_ROWS: usize = 1_001;

pub(super) struct CatalogDatabaseBoundaryProbe {
    #[cfg(feature = "test-hooks")]
    cancel_after_next: AtomicBool,
}

impl CatalogDatabaseBoundaryProbe {
    pub(super) const fn new() -> Self {
        Self {
            #[cfg(feature = "test-hooks")]
            cancel_after_next: AtomicBool::new(false),
        }
    }

    #[cfg(feature = "test-hooks")]
    pub(super) fn arm_child_cancellation(&self) -> bool {
        self.cancel_after_next
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn after_boundary(&self, context: &RequestContext) -> Result<(), StorageError> {
        #[cfg(feature = "test-hooks")]
        if self.cancel_after_next.swap(false, Ordering::AcqRel) {
            let _cancelled = context.cancellation().cancel();
        }
        check_context(context)
    }
}

pub(super) struct CatalogDatabase<'a> {
    session: &'a mut LocalSession,
    context: &'a RequestContext,
    probe: &'a CatalogDatabaseBoundaryProbe,
}

impl<'a> CatalogDatabase<'a> {
    pub(super) const fn new(
        session: &'a mut LocalSession,
        context: &'a RequestContext,
        probe: &'a CatalogDatabaseBoundaryProbe,
    ) -> Self {
        Self {
            session,
            context,
            probe,
        }
    }

    fn execute<T>(
        &mut self,
        sql: &str,
        project: impl FnOnce(Result<CommandOutput, RnovError>) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        check_context(self.context)?;
        let result = self.session.execute(sql);
        self.probe.after_boundary(self.context)?;
        project(result)
    }
}

pub(super) fn run_transaction<T>(
    session: &mut LocalSession,
    context: &RequestContext,
    probe: &CatalogDatabaseBoundaryProbe,
    operation: impl FnOnce(&mut CatalogDatabase<'_>) -> Result<T, StorageError>,
) -> crate::identity_transaction::IdentityTransactionResult<T> {
    crate::identity_transaction::run_transaction_with_begin_boundary(
        session,
        context,
        || probe.after_boundary(context),
        |session| {
            let mut database = CatalogDatabase::new(session, context, probe);
            operation(&mut database)
        },
    )
}

pub(super) struct OperationEvidence {
    pub(super) commitment: [u8; 32],
    pub(super) reference: FileReference,
    pub(super) key_version: i64,
}

pub(super) fn load_operation(
    database: &mut CatalogDatabase<'_>,
    owner: &PrincipalContext,
    kind: &str,
    lookup: &[u8; 32],
) -> Result<Option<OperationEvidence>, StorageError> {
    validate_operation_kind(kind)?;
    let sql = operation_lookup_sql(owner, kind, lookup);
    let batch = query_rows(database, &sql)?;
    validate_columns(batch.columns(), &operation_columns())?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_operation(row, owner, kind, lookup).map(Some),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn load_entry(
    database: &mut CatalogDatabase<'_>,
    owner: &PrincipalContext,
    reference: &FileReference,
) -> Result<Option<FileDescriptor>, StorageError> {
    let sql = entry_lookup_sql(owner, reference);
    let batch = query_rows(database, &sql)?;
    validate_columns(batch.columns(), &entry_columns())?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_expected_entry(row, owner, reference).map(Some),
        _ => Err(integrity_failure()),
    }
}

pub(super) fn load_visible_entry(
    database: &mut CatalogDatabase<'_>,
    commitments: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    reference: &FileReference,
) -> Result<Option<FileDescriptor>, StorageError> {
    let Some(descriptor) = load_entry(database, owner, reference)? else {
        return Ok(None);
    };
    if load_delete_tombstone(database, commitments, owner, reference)? {
        return Ok(None);
    }
    Ok(Some(descriptor))
}

pub(super) fn list_visible_entries(
    database: &mut CatalogDatabase<'_>,
    commitments: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    after: Option<&FileReference>,
    limit_plus_one: usize,
) -> Result<Vec<FileDescriptor>, StorageError> {
    validate_list_limit(limit_plus_one)?;
    let sql = visible_entry_list_sql(owner, after, limit_plus_one);
    let batch = query_rows(database, &sql)?;
    validate_columns(batch.columns(), &entry_columns())?;
    if batch.rows().len() > limit_plus_one {
        return Err(integrity_failure());
    }
    decode_visible_list(database, commitments, owner, after, batch.rows())
}

pub(super) fn validate_list_tombstones(
    database: &mut CatalogDatabase<'_>,
    commitments: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    after: Option<&FileReference>,
    through: Option<&FileReference>,
) -> Result<(), StorageError> {
    let mut cursor = after.copied();
    loop {
        let sql = delete_operation_batch_sql(owner, cursor.as_ref(), through);
        let batch = query_rows(database, &sql)?;
        validate_columns(batch.columns(), &operation_columns())?;
        let next = validate_tombstone_batch(commitments, owner, cursor.as_ref(), batch.rows())?;
        let Some(next) = next else {
            return Ok(());
        };
        load_delete_tombstone(database, commitments, owner, &next)?;
        cursor = Some(next);
    }
}

pub(super) fn insert_entry(
    database: &mut CatalogDatabase<'_>,
    record: &FileCatalogRecord,
) -> Result<(), StorageError> {
    let sql = insert_entry_sql(record);
    execute_insert(database, &sql)
}

pub(super) fn insert_operation(
    database: &mut CatalogDatabase<'_>,
    owner: &PrincipalContext,
    kind: &str,
    lookup: &[u8; 32],
    commitment: &[u8; 32],
    reference: &FileReference,
    key_version: FileCatalogCommitmentKeyVersion,
) -> Result<(), StorageError> {
    validate_operation_kind(kind)?;
    let sql = insert_operation_sql(owner, kind, lookup, commitment, reference, key_version);
    execute_insert(database, &sql)
}

fn load_delete_tombstone(
    database: &mut CatalogDatabase<'_>,
    commitments: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    reference: &FileReference,
) -> Result<bool, StorageError> {
    let sql = delete_tombstone_sql(owner, reference);
    let batch = query_rows(database, &sql)?;
    validate_columns(batch.columns(), &operation_columns())?;
    match batch.rows() {
        [] => Ok(false),
        [row] => decode_delete_tombstone(row, commitments, owner, reference).map(|_| true),
        _ => Err(integrity_failure()),
    }
}

fn decode_visible_list(
    database: &mut CatalogDatabase<'_>,
    commitments: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    after: Option<&FileReference>,
    rows: &[Row],
) -> Result<Vec<FileDescriptor>, StorageError> {
    let mut previous = after.copied();
    let mut descriptors = Vec::with_capacity(rows.len());
    for row in rows {
        let descriptor = decode_entry(row, owner)?;
        validate_reference_order(previous.as_ref(), descriptor.reference())?;
        if load_delete_tombstone(database, commitments, owner, descriptor.reference())? {
            return Err(integrity_failure());
        }
        previous = Some(*descriptor.reference());
        descriptors.push(descriptor);
    }
    Ok(descriptors)
}

fn decode_operation(
    row: &Row,
    owner: &PrincipalContext,
    kind: &str,
    lookup: &[u8; 32],
) -> Result<OperationEvidence, StorageError> {
    let values = operation_values(row)?;
    let decoded_lookup = decode_fixed_hex(values.lookup)?;
    let reference = FileReference::new(decode_fixed_hex(values.reference)?);
    validate_operation_identity(&values, owner, kind, lookup, &decoded_lookup)?;
    validate_operation_evidence(&values)?;
    Ok(OperationEvidence {
        commitment: decode_fixed_hex(values.commitment)?,
        reference,
        key_version: values.key_version,
    })
}

fn decode_delete_tombstone(
    row: &Row,
    commitments: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    expected_reference: &FileReference,
) -> Result<(), StorageError> {
    let reference = decode_delete_tombstone_reference(row, commitments, owner)?;
    (reference == *expected_reference)
        .then_some(())
        .ok_or_else(integrity_failure)
}

fn decode_delete_tombstone_reference(
    row: &Row,
    commitments: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
) -> Result<FileReference, StorageError> {
    let values = operation_values(row)?;
    let reference = FileReference::new(decode_fixed_hex(values.reference)?);
    let _lookup = decode_fixed_hex(values.lookup)?;
    let _commitment = decode_fixed_hex(values.commitment)?;
    validate_delete_identity(&values, owner, &reference, &reference)?;
    validate_operation_evidence(&values)?;
    super::evidence::commitment_key_for_version(commitments, values.key_version)?;
    Ok(reference)
}

fn validate_tombstone_batch(
    commitments: &FileCatalogCommitmentKeys,
    owner: &PrincipalContext,
    after: Option<&FileReference>,
    rows: &[Row],
) -> Result<Option<FileReference>, StorageError> {
    if rows.len() > MAX_LIST_ROWS {
        return Err(integrity_failure());
    }
    let mut previous = after.copied();
    for row in rows {
        let reference = decode_delete_tombstone_reference(row, commitments, owner)?;
        validate_reference_order(previous.as_ref(), &reference)?;
        previous = Some(reference);
    }
    if rows.len() < MAX_LIST_ROWS {
        return Ok(None);
    }
    previous.ok_or_else(integrity_failure).map(Some)
}

struct OperationValues<'a> {
    tenant: &'a str,
    principal: &'a str,
    kind: &'a str,
    lookup: &'a str,
    commitment: &'a str,
    reference: &'a str,
    key_version: i64,
    outcome: &'a str,
}

fn operation_values(row: &Row) -> Result<OperationValues<'_>, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(principal),
        SqlValue::Text(kind),
        SqlValue::Text(lookup),
        SqlValue::Text(commitment),
        SqlValue::Text(reference),
        SqlValue::Int64(key_version),
        SqlValue::Text(outcome),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    Ok(OperationValues {
        tenant,
        principal,
        kind,
        lookup,
        commitment,
        reference,
        key_version: *key_version,
        outcome,
    })
}

fn validate_operation_identity(
    values: &OperationValues<'_>,
    owner: &PrincipalContext,
    kind: &str,
    expected_lookup: &[u8; 32],
    decoded_lookup: &[u8; 32],
) -> Result<(), StorageError> {
    let valid = values.tenant == owner.tenant_id().as_str()
        && values.principal == owner.principal_id().as_str()
        && values.kind == kind
        && decoded_lookup == expected_lookup;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_delete_identity(
    values: &OperationValues<'_>,
    owner: &PrincipalContext,
    reference: &FileReference,
    expected_reference: &FileReference,
) -> Result<(), StorageError> {
    let valid = values.tenant == owner.tenant_id().as_str()
        && values.principal == owner.principal_id().as_str()
        && values.kind == DELETE_KIND
        && reference == expected_reference;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_operation_evidence(values: &OperationValues<'_>) -> Result<(), StorageError> {
    let valid = values.key_version > 0 && values.outcome == COMMITTED_OUTCOME;
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn decode_expected_entry(
    row: &Row,
    owner: &PrincipalContext,
    expected_reference: &FileReference,
) -> Result<FileDescriptor, StorageError> {
    let descriptor = decode_entry(row, owner)?;
    if descriptor.reference() != expected_reference {
        return Err(integrity_failure());
    }
    Ok(descriptor)
}

fn decode_entry(row: &Row, owner: &PrincipalContext) -> Result<FileDescriptor, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(principal),
        SqlValue::Text(reference),
        SqlValue::Text(display_name),
        SqlValue::Text(media_type),
        SqlValue::Int64(byte_length),
        SqlValue::Text(digest),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    let identity = EntryIdentity {
        tenant,
        principal,
        owner,
    };
    let values = EntryValues {
        reference,
        display_name,
        media_type,
        byte_length: *byte_length,
        digest,
    };
    decode_entry_values(identity, values)
}

struct EntryIdentity<'a> {
    tenant: &'a str,
    principal: &'a str,
    owner: &'a PrincipalContext,
}

struct EntryValues<'a> {
    reference: &'a str,
    display_name: &'a str,
    media_type: &'a str,
    byte_length: i64,
    digest: &'a str,
}

fn decode_entry_values(
    identity: EntryIdentity<'_>,
    values: EntryValues<'_>,
) -> Result<FileDescriptor, StorageError> {
    validate_entry_owner(identity.tenant, identity.principal, identity.owner)?;
    let byte_length = usize::try_from(values.byte_length).map_err(|_| integrity_failure())?;
    let reference = FileReference::new(decode_fixed_hex(values.reference)?);
    let display_name =
        FileDisplayName::new(values.display_name).map_err(|_| integrity_failure())?;
    let media_type = FileMediaType::new(values.media_type).map_err(|_| integrity_failure())?;
    let byte_length = FileByteLength::new(byte_length).map_err(|_| integrity_failure())?;
    let digest = ariadnion_api_files::FileDigest::new(decode_fixed_hex(values.digest)?);
    Ok(FileDescriptor::new(
        reference,
        display_name,
        media_type,
        byte_length,
        digest,
    ))
}

fn validate_entry_owner(
    tenant: &str,
    principal: &str,
    owner: &PrincipalContext,
) -> Result<(), StorageError> {
    let valid = tenant == owner.tenant_id().as_str() && principal == owner.principal_id().as_str();
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn validate_reference_order(
    previous: Option<&FileReference>,
    current: &FileReference,
) -> Result<(), StorageError> {
    let ordered = previous.is_none_or(|previous| previous.as_bytes() < current.as_bytes());
    ordered.then_some(()).ok_or_else(integrity_failure)
}

fn operation_lookup_sql(owner: &PrincipalContext, kind: &str, lookup: &[u8; 32]) -> String {
    let mut sql =
        format!("SELECT {OPERATION_PROJECTION} FROM {OPERATION_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, owner.tenant_id().as_str());
    sql.push_str(" AND owner_principal_id = ");
    push_text_literal(&mut sql, owner.principal_id().as_str());
    sql.push_str(" AND operation_kind = ");
    push_text_literal(&mut sql, kind);
    sql.push_str(" AND idempotency_lookup_hex = ");
    push_text_literal(&mut sql, &encode_hex(lookup));
    sql.push_str(" LIMIT 2;");
    sql
}

fn entry_lookup_sql(owner: &PrincipalContext, reference: &FileReference) -> String {
    let mut sql = format!("SELECT {ENTRY_PROJECTION} FROM {ENTRY_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, owner.tenant_id().as_str());
    sql.push_str(" AND owner_principal_id = ");
    push_text_literal(&mut sql, owner.principal_id().as_str());
    sql.push_str(" AND reference_hex = ");
    push_text_literal(&mut sql, &encode_hex(reference.as_bytes()));
    sql.push_str(" LIMIT 2;");
    sql
}

fn delete_tombstone_sql(owner: &PrincipalContext, reference: &FileReference) -> String {
    let mut sql =
        format!("SELECT {OPERATION_PROJECTION} FROM {OPERATION_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, owner.tenant_id().as_str());
    sql.push_str(" AND owner_principal_id = ");
    push_text_literal(&mut sql, owner.principal_id().as_str());
    sql.push_str(" AND operation_kind = ");
    push_text_literal(&mut sql, DELETE_KIND);
    sql.push_str(" AND reference_hex = ");
    push_text_literal(&mut sql, &encode_hex(reference.as_bytes()));
    sql.push_str(" LIMIT 2;");
    sql
}

fn visible_entry_list_sql(
    owner: &PrincipalContext,
    after: Option<&FileReference>,
    limit: usize,
) -> String {
    let mut sql = format!("SELECT {ENTRY_PROJECTION} FROM {ENTRY_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, owner.tenant_id().as_str());
    sql.push_str(" AND owner_principal_id = ");
    push_text_literal(&mut sql, owner.principal_id().as_str());
    push_after_predicate(&mut sql, after);
    push_tombstone_exclusion(&mut sql, owner);
    sql.push_str(" ORDER BY reference_hex LIMIT ");
    sql.push_str(&limit.to_string());
    sql.push(';');
    sql
}

fn delete_operation_batch_sql(
    owner: &PrincipalContext,
    after: Option<&FileReference>,
    through: Option<&FileReference>,
) -> String {
    let mut sql =
        format!("SELECT {OPERATION_PROJECTION} FROM {OPERATION_TABLE} WHERE tenant_id = ");
    push_text_literal(&mut sql, owner.tenant_id().as_str());
    sql.push_str(" AND owner_principal_id = ");
    push_text_literal(&mut sql, owner.principal_id().as_str());
    sql.push_str(" AND operation_kind = ");
    push_text_literal(&mut sql, DELETE_KIND);
    push_reference_range(&mut sql, after, through);
    sql.push_str(" ORDER BY reference_hex LIMIT ");
    sql.push_str(&MAX_LIST_ROWS.to_string());
    sql.push(';');
    sql
}

fn push_reference_range(
    sql: &mut String,
    after: Option<&FileReference>,
    through: Option<&FileReference>,
) {
    if let Some(reference) = after {
        sql.push_str(" AND reference_hex > ");
        push_text_literal(sql, &encode_hex(reference.as_bytes()));
    }
    if let Some(reference) = through {
        sql.push_str(" AND reference_hex <= ");
        push_text_literal(sql, &encode_hex(reference.as_bytes()));
    }
}

fn push_after_predicate(sql: &mut String, after: Option<&FileReference>) {
    if let Some(reference) = after {
        sql.push_str(" AND reference_hex > ");
        push_text_literal(sql, &encode_hex(reference.as_bytes()));
    }
}

fn push_tombstone_exclusion(sql: &mut String, owner: &PrincipalContext) {
    sql.push_str(" AND NOT EXISTS (SELECT reference_hex FROM ");
    sql.push_str(OPERATION_TABLE);
    sql.push_str(" WHERE tenant_id = ");
    push_text_literal(sql, owner.tenant_id().as_str());
    sql.push_str(" AND owner_principal_id = ");
    push_text_literal(sql, owner.principal_id().as_str());
    sql.push_str(" AND operation_kind = ");
    push_text_literal(sql, DELETE_KIND);
    sql.push_str(" AND outcome = ");
    push_text_literal(sql, COMMITTED_OUTCOME);
    sql.push_str(" AND reference_hex = files_catalog_entries.reference_hex LIMIT 1)");
}

fn insert_entry_sql(record: &FileCatalogRecord) -> String {
    let descriptor = record.descriptor();
    let mut sql = format!("INSERT INTO {ENTRY_TABLE} ({ENTRY_PROJECTION}) VALUES (");
    push_text_literal(&mut sql, record.tenant_id().as_str());
    push_separator_text(&mut sql, record.principal_id().as_str());
    push_separator_text(&mut sql, &encode_hex(descriptor.reference().as_bytes()));
    push_separator_text(&mut sql, descriptor.display_name().as_str());
    push_separator_text(&mut sql, descriptor.media_type().as_str());
    sql.push_str(", ");
    sql.push_str(&descriptor.byte_length().get().to_string());
    push_separator_text(&mut sql, &encode_hex(descriptor.digest().as_bytes()));
    sql.push_str(");");
    sql
}

fn insert_operation_sql(
    owner: &PrincipalContext,
    kind: &str,
    lookup: &[u8; 32],
    commitment: &[u8; 32],
    reference: &FileReference,
    key_version: FileCatalogCommitmentKeyVersion,
) -> String {
    let mut sql = format!("INSERT INTO {OPERATION_TABLE} ({OPERATION_PROJECTION}) VALUES (");
    push_text_literal(&mut sql, owner.tenant_id().as_str());
    push_separator_text(&mut sql, owner.principal_id().as_str());
    push_separator_text(&mut sql, kind);
    push_separator_text(&mut sql, &encode_hex(lookup));
    push_separator_text(&mut sql, &encode_hex(commitment));
    push_separator_text(&mut sql, &encode_hex(reference.as_bytes()));
    sql.push_str(", ");
    sql.push_str(&key_version.get().to_string());
    push_separator_text(&mut sql, COMMITTED_OUTCOME);
    sql.push_str(");");
    sql
}

fn query_rows(database: &mut CatalogDatabase<'_>, sql: &str) -> Result<VectorBatch, StorageError> {
    database.execute(sql, |result| {
        let output = result.map_err(map_query_error)?;
        match output {
            CommandOutput::Rows(batch) => Ok(batch),
            _ => Err(integrity_failure()),
        }
    })
}

fn execute_insert(database: &mut CatalogDatabase<'_>, sql: &str) -> Result<(), StorageError> {
    database.execute(sql, project_insert_result)
}

fn project_insert_result(result: Result<CommandOutput, RnovError>) -> Result<(), StorageError> {
    let output = result.map_err(map_insert_error)?;
    if output != CommandOutput::RowsAffected(1) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn map_insert_error(error: RnovError) -> StorageError {
    if error.kind() == ErrorKind::InvalidInput {
        conflict()
    } else {
        map_query_error(error)
    }
}

fn map_query_error(error: RnovError) -> StorageError {
    let code = match error.kind() {
        ErrorKind::Canceled => StorageErrorCode::Cancelled,
        ErrorKind::Io | ErrorKind::Storage => StorageErrorCode::Unavailable,
        ErrorKind::Config
        | ErrorKind::Corruption
        | ErrorKind::Internal
        | ErrorKind::InvalidInput
        | ErrorKind::NotFound
        | ErrorKind::Security => StorageErrorCode::IntegrityFailure,
    };
    StorageError::new(code)
}

fn validate_columns(
    columns: &[ColumnSchema],
    expected: &[(&str, SqlType)],
) -> Result<(), StorageError> {
    let valid = columns.len() == expected.len()
        && columns.iter().zip(expected).all(|(column, expected)| {
            column.name() == expected.0 && column.data_type() == &expected.1
        });
    valid.then_some(()).ok_or_else(integrity_failure)
}

fn operation_columns() -> [(&'static str, SqlType); 8] {
    [
        ("tenant_id", SqlType::Text),
        ("owner_principal_id", SqlType::Text),
        ("operation_kind", SqlType::Text),
        ("idempotency_lookup_hex", SqlType::Text),
        ("request_commitment_hex", SqlType::Text),
        ("reference_hex", SqlType::Text),
        ("commitment_key_version", SqlType::Int64),
        ("outcome", SqlType::Text),
    ]
}

fn entry_columns() -> [(&'static str, SqlType); 7] {
    [
        ("tenant_id", SqlType::Text),
        ("owner_principal_id", SqlType::Text),
        ("reference_hex", SqlType::Text),
        ("display_name", SqlType::Text),
        ("media_type", SqlType::Text),
        ("byte_length", SqlType::Int64),
        ("digest_hex", SqlType::Text),
    ]
}

fn validate_operation_kind(kind: &str) -> Result<(), StorageError> {
    matches!(kind, PUBLISH_KIND | DELETE_KIND)
        .then_some(())
        .ok_or_else(integrity_failure)
}

fn validate_list_limit(limit: usize) -> Result<(), StorageError> {
    (1..=MAX_LIST_ROWS)
        .contains(&limit)
        .then_some(())
        .ok_or_else(integrity_failure)
}

fn push_separator_text(sql: &mut String, value: &str) {
    sql.push_str(", ");
    push_text_literal(sql, value);
}

fn push_text_literal(sql: &mut String, value: &str) {
    sql.push('\'');
    for character in value.chars() {
        if character == '\'' {
            sql.push_str("''");
        } else {
            sql.push(character);
        }
    }
    sql.push('\'');
}

const fn conflict() -> StorageError {
    StorageError::new(StorageErrorCode::Conflict)
}

const fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

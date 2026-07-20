//! Fixed tenant-scoped statements for encrypted secret references.

use std::sync::Arc;

use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_executor::vector::{ColumnSchema, Row, VectorBatch};
use rnmdb_types::{SqlType, SqlValue};
use zeroize::Zeroizing;

use crate::RnmdbSessionOwner;
use crate::secret_reference::{
    NewSecretReference, SecretKeyVersion, SecretLocator, SecretReference, SecretReferenceId,
    SecretReferenceKind, SecretReferenceUpdate,
};

const REFERENCE_PROJECTION: &str = "tenant_id, reference_id, purpose, locator, key_version";
const REFERENCE_TABLE: &str = "platform_secret_references";

/// Executes only fixed, tenant-scoped secret-reference statements.
pub struct RnmdbSecretReferenceRepository {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbSecretReferenceRepository {
    /// Creates a repository for one serialized embedded session.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Returns the serialized session used by this repository.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }

    /// Inserts one reference for the authenticated request tenant.
    ///
    /// The tenant is sourced only from the request context. A fixed lookup and
    /// insert execute under one serialized RNMDB transaction. Existing
    /// tenant-local identities return [`StorageErrorCode::Conflict`].
    pub fn create(
        &self,
        value: NewSecretReference,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let tenant_id = authenticated_tenant(context)?;
        let lookup = existence_sql(tenant_id, value.reference_id());
        let insert = insert_sql(tenant_id, &value);
        let outcome = self.session.with_session(context, |session| {
            create_in_transaction(session, &lookup, &insert, value.reference_id())
        })?;
        require_created(outcome)
    }

    /// Finds one reference owned by the authenticated request tenant.
    ///
    /// The fixed query includes both tenant and reference predicates. Missing
    /// rows return `Ok(None)` without revealing another tenant's records.
    pub fn find(
        &self,
        reference_id: &SecretReferenceId,
        context: &RequestContext,
    ) -> Result<Option<SecretReference>, StorageError> {
        let tenant_id = authenticated_tenant(context)?;
        let sql = select_sql(tenant_id, reference_id);
        let output = self
            .session
            .with_session(context, |session| session.execute(&sql))?;
        decode_reference(output, tenant_id, reference_id)
    }

    /// Replaces one reference owned by the authenticated request tenant.
    ///
    /// The fixed update includes both tenant and reference predicates and is
    /// durably committed as one transaction. A missing tenant-local identity
    /// returns [`StorageErrorCode::NotFound`].
    pub fn update(
        &self,
        value: SecretReferenceUpdate,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let tenant_id = authenticated_tenant(context)?;
        let sql = update_sql(tenant_id, &value);
        let outcome = self
            .session
            .with_session(context, |session| mutate_in_transaction(session, &sql))?;
        require_mutated(outcome)
    }

    /// Deletes one reference owned by the authenticated request tenant.
    ///
    /// The fixed delete includes both tenant and reference predicates and is
    /// durably committed as one transaction. A missing tenant-local identity
    /// returns [`StorageErrorCode::NotFound`].
    pub fn delete(
        &self,
        reference_id: &SecretReferenceId,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        let tenant_id = authenticated_tenant(context)?;
        let sql = delete_sql(tenant_id, reference_id);
        let outcome = self
            .session
            .with_session(context, |session| mutate_in_transaction(session, &sql))?;
        require_mutated(outcome)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateOutcome {
    Created,
    Existing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationOutcome {
    Applied,
    Missing,
}

fn authenticated_tenant(context: &RequestContext) -> Result<&TenantId, StorageError> {
    let Some(principal) = context.principal() else {
        return Err(integrity_failure());
    };
    Ok(principal.tenant_id())
}

fn create_in_transaction(
    session: &mut LocalSession,
    lookup: &str,
    insert: &str,
    reference_id: &SecretReferenceId,
) -> Result<CreateOutcome, RnovError> {
    session.execute("BEGIN")?;
    let result = create_body(session, lookup, insert, reference_id);
    finish_create_transaction(session, result)
}

fn create_body(
    session: &mut LocalSession,
    lookup: &str,
    insert: &str,
    reference_id: &SecretReferenceId,
) -> Result<CreateOutcome, RnovError> {
    if decode_existence(session.execute(lookup)?, reference_id)? {
        return Ok(CreateOutcome::Existing);
    }
    require_single_change(session.execute(insert)?)?;
    Ok(CreateOutcome::Created)
}

fn finish_create_transaction(
    session: &mut LocalSession,
    result: Result<CreateOutcome, RnovError>,
) -> Result<CreateOutcome, RnovError> {
    match result {
        Ok(CreateOutcome::Created) => commit_with_outcome(session, CreateOutcome::Created),
        Ok(CreateOutcome::Existing) => rollback_with_outcome(session, CreateOutcome::Existing),
        Err(error) => rollback_with_error(session, error),
    }
}

fn mutate_in_transaction(
    session: &mut LocalSession,
    sql: &str,
) -> Result<MutationOutcome, RnovError> {
    session.execute("BEGIN")?;
    let result = mutation_body(session, sql);
    finish_mutation_transaction(session, result)
}

fn mutation_body(session: &mut LocalSession, sql: &str) -> Result<MutationOutcome, RnovError> {
    match session.execute(sql)? {
        CommandOutput::RowsAffected(0) => Ok(MutationOutcome::Missing),
        CommandOutput::RowsAffected(1) => Ok(MutationOutcome::Applied),
        _ => Err(corruption("secret-reference mutation count changed")),
    }
}

fn finish_mutation_transaction(
    session: &mut LocalSession,
    result: Result<MutationOutcome, RnovError>,
) -> Result<MutationOutcome, RnovError> {
    match result {
        Ok(MutationOutcome::Applied) => commit_with_outcome(session, MutationOutcome::Applied),
        Ok(MutationOutcome::Missing) => rollback_with_outcome(session, MutationOutcome::Missing),
        Err(error) => rollback_with_error(session, error),
    }
}

fn commit_with_outcome<T>(session: &mut LocalSession, outcome: T) -> Result<T, RnovError> {
    if let Err(error) = session.execute("COMMIT") {
        return rollback_with_error(session, error);
    }
    Ok(outcome)
}

fn rollback_with_outcome<T>(session: &mut LocalSession, outcome: T) -> Result<T, RnovError> {
    session.execute("ROLLBACK")?;
    Ok(outcome)
}

fn rollback_with_error<T>(session: &mut LocalSession, error: RnovError) -> Result<T, RnovError> {
    if session.in_transaction() {
        session.execute("ROLLBACK")?;
    }
    Err(error)
}

fn require_created(outcome: CreateOutcome) -> Result<(), StorageError> {
    match outcome {
        CreateOutcome::Created => Ok(()),
        CreateOutcome::Existing => Err(StorageError::new(StorageErrorCode::Conflict)),
    }
}

fn require_mutated(outcome: MutationOutcome) -> Result<(), StorageError> {
    match outcome {
        MutationOutcome::Applied => Ok(()),
        MutationOutcome::Missing => Err(StorageError::new(StorageErrorCode::NotFound)),
    }
}

fn decode_reference(
    output: CommandOutput,
    expected_tenant: &TenantId,
    expected_reference: &SecretReferenceId,
) -> Result<Option<SecretReference>, StorageError> {
    let batch = reference_batch(output)?;
    validate_reference_columns(batch.columns())?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_reference_row(row, expected_tenant, expected_reference).map(Some),
        _ => Err(integrity_failure()),
    }
}

fn reference_batch(output: CommandOutput) -> Result<VectorBatch, StorageError> {
    match output {
        CommandOutput::Rows(batch) => Ok(batch),
        _ => Err(integrity_failure()),
    }
}

fn validate_reference_columns(columns: &[ColumnSchema]) -> Result<(), StorageError> {
    let expected = [
        ("tenant_id", SqlType::Text),
        ("reference_id", SqlType::Text),
        ("purpose", SqlType::Text),
        ("locator", SqlType::Text),
        ("key_version", SqlType::Int64),
    ];
    if columns.len() != expected.len() {
        return Err(integrity_failure());
    }
    for (column, (name, data_type)) in columns.iter().zip(expected) {
        if column.name() != name || column.data_type() != &data_type {
            return Err(integrity_failure());
        }
    }
    Ok(())
}

fn decode_reference_row(
    row: &Row,
    expected_tenant: &TenantId,
    expected_reference: &SecretReferenceId,
) -> Result<SecretReference, StorageError> {
    let [
        SqlValue::Text(tenant),
        SqlValue::Text(reference),
        SqlValue::Text(kind),
        SqlValue::Text(locator),
        SqlValue::Int64(key_version),
    ] = row.values()
    else {
        return Err(integrity_failure());
    };
    let tenant_id = TenantId::parse(tenant).map_err(|_| integrity_failure())?;
    let reference_id = SecretReferenceId::parse(reference).map_err(|_| integrity_failure())?;
    verify_decoded_identity(
        &tenant_id,
        &reference_id,
        expected_tenant,
        expected_reference,
    )?;
    let kind = SecretReferenceKind::parse(kind).map_err(|_| integrity_failure())?;
    let locator = SecretLocator::parse(locator).map_err(|_| integrity_failure())?;
    let key_version = SecretKeyVersion::new(*key_version).map_err(|_| integrity_failure())?;
    Ok(SecretReference::from_persisted(
        tenant_id,
        reference_id,
        kind,
        locator,
        key_version,
    ))
}

fn verify_decoded_identity(
    tenant_id: &TenantId,
    reference_id: &SecretReferenceId,
    expected_tenant: &TenantId,
    expected_reference: &SecretReferenceId,
) -> Result<(), StorageError> {
    if tenant_id != expected_tenant || reference_id != expected_reference {
        return Err(integrity_failure());
    }
    Ok(())
}

fn decode_existence(
    output: CommandOutput,
    expected_reference: &SecretReferenceId,
) -> Result<bool, RnovError> {
    let CommandOutput::Rows(batch) = output else {
        return Err(corruption("secret-reference lookup did not return rows"));
    };
    validate_existence_columns(batch.columns())?;
    match batch.rows() {
        [] => Ok(false),
        [row] => validate_existence_row(row, expected_reference).map(|()| true),
        _ => Err(corruption("secret-reference identity is not unique")),
    }
}

fn validate_existence_columns(columns: &[ColumnSchema]) -> Result<(), RnovError> {
    match columns {
        [column] if column.name() == "reference_id" && column.data_type() == &SqlType::Text => {
            Ok(())
        }
        _ => Err(corruption("secret-reference lookup schema changed")),
    }
}

fn validate_existence_row(
    row: &Row,
    expected_reference: &SecretReferenceId,
) -> Result<(), RnovError> {
    match row.values() {
        [SqlValue::Text(reference)] if reference == expected_reference.as_str() => Ok(()),
        _ => Err(corruption("secret-reference lookup identity changed")),
    }
}

fn require_single_change(output: CommandOutput) -> Result<(), RnovError> {
    if output != CommandOutput::RowsAffected(1) {
        return Err(corruption("secret-reference insert count changed"));
    }
    Ok(())
}

fn select_sql(tenant_id: &TenantId, reference_id: &SecretReferenceId) -> Zeroizing<String> {
    let mut sql = Zeroizing::new(format!(
        "SELECT {REFERENCE_PROJECTION} FROM {REFERENCE_TABLE} WHERE tenant_id = "
    ));
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND reference_id = ");
    push_text_literal(&mut sql, reference_id.as_str());
    sql.push(';');
    sql
}

fn existence_sql(tenant_id: &TenantId, reference_id: &SecretReferenceId) -> Zeroizing<String> {
    let mut sql = Zeroizing::new(format!(
        "SELECT reference_id FROM {REFERENCE_TABLE} WHERE tenant_id = "
    ));
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND reference_id = ");
    push_text_literal(&mut sql, reference_id.as_str());
    sql.push(';');
    sql
}

fn insert_sql(tenant_id: &TenantId, value: &NewSecretReference) -> Zeroizing<String> {
    let mut sql = Zeroizing::new(format!(
        "INSERT INTO {REFERENCE_TABLE} (tenant_id, reference_id, purpose, locator, key_version) VALUES ("
    ));
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(", ");
    push_text_literal(&mut sql, value.reference_id().as_str());
    sql.push_str(", ");
    push_text_literal(&mut sql, value.kind().as_str());
    sql.push_str(", ");
    push_text_literal(&mut sql, value.locator().as_str());
    sql.push_str(", ");
    push_i64_literal(&mut sql, value.key_version().get());
    sql.push_str(");");
    sql
}

fn update_sql(tenant_id: &TenantId, value: &SecretReferenceUpdate) -> Zeroizing<String> {
    let mut sql = Zeroizing::new(format!("UPDATE {REFERENCE_TABLE} SET purpose = "));
    push_text_literal(&mut sql, value.kind().as_str());
    sql.push_str(", locator = ");
    push_text_literal(&mut sql, value.locator().as_str());
    sql.push_str(", key_version = ");
    push_i64_literal(&mut sql, value.key_version().get());
    sql.push_str(" WHERE tenant_id = ");
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND reference_id = ");
    push_text_literal(&mut sql, value.reference_id().as_str());
    sql.push(';');
    sql
}

fn delete_sql(tenant_id: &TenantId, reference_id: &SecretReferenceId) -> Zeroizing<String> {
    let mut sql = Zeroizing::new(format!("DELETE FROM {REFERENCE_TABLE} WHERE tenant_id = "));
    push_text_literal(&mut sql, tenant_id.as_str());
    sql.push_str(" AND reference_id = ");
    push_text_literal(&mut sql, reference_id.as_str());
    sql.push(';');
    sql
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

fn push_i64_literal(sql: &mut String, value: i64) {
    sql.push_str(&value.to_string());
}

fn integrity_failure() -> StorageError {
    StorageError::new(StorageErrorCode::IntegrityFailure)
}

fn corruption(message: &'static str) -> RnovError {
    RnovError::new(ErrorKind::Corruption, message)
}

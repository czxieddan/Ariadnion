// crates/optional/ariadnion-storage-rnmdb/src/vault_repository/codec.rs - Vault persistence codecs for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.1 of the
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
// Repository verbatim AHCL copy:                 .ahcl/AHCL-1.1.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                .ahcl/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 .ahcl/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     .ahcl/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; one record applies:
//                                                   .ahcl/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
//
//! Immutable vault mutations, authenticated envelopes, and durable read events.

use ariadnion_account_vault::{
    ENVELOPE_NONCE_BYTES, EncryptedSecretEnvelope, MAX_CIPHERTEXT_BYTES, SecretLease,
    SecretReadRequest, SecretRef, SecretRevokeReceipt, SecretStoreReceipt, SecretStoreRequest,
    VaultKeyVersion, VaultMutationReceipt, VaultRevokeReason, VaultRevokeRequest,
};
use ariadnion_core::{RequestContext, TenantId};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::LocalSession;
use rnmdb_executor::vector::Row;
use rnmdb_types::SqlValue;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{VaultKeyCustody, VaultOperation, new_lease_id, sql};
use crate::identity_transaction::require_active_identity_transaction;
use crate::session::check_context;

const SECRET_PROJECTION: &str = "tenant_id, reference_digest_hex, secret_provider, secret_path, secret_version, secret_purpose, key_version, nonce_hex, ciphertext_hex, envelope_digest_hex, lifecycle_state, created_at, revoked_at, revoke_reason";
const MUTATION_PROJECTION: &str = "tenant_id, mutation_id, request_fingerprint_hex, mutation_kind, reference_digest_hex, secret_provider, secret_path, secret_version, disposition, key_version, revoke_reason, committed_at";

struct StoredSecret {
    envelope: EncryptedSecretEnvelope,
    revoked: bool,
}

struct Mutation {
    fingerprint: String,
    receipt: VaultMutationReceipt,
}

pub(super) fn store(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &SecretStoreRequest,
    digest: &[u8; 32],
    context: &RequestContext,
    custody: &dyn VaultKeyCustody,
) -> Result<SecretStoreReceipt, StorageError> {
    require_active_identity_transaction(local)?;
    let fingerprint = sql::hex(
        &custody
            .mutation_fingerprint(
                tenant,
                request.reference(),
                VaultOperation::Store,
                envelope_digest(request.envelope()).as_bytes(),
            )
            .map_err(custody_storage_error)?,
    );
    if let Some(mutation) = load_mutation(local, tenant, request.reference(), digest, context)? {
        return replay_store(mutation, &fingerprint);
    }
    authenticate_store_request(tenant, request, context, custody)?;
    require_new_secret(local, tenant, request.reference(), digest)?;
    persist_store(local, tenant, request, digest, context, &fingerprint)
}

fn authenticate_store_request(
    tenant: &TenantId,
    request: &SecretStoreRequest,
    context: &RequestContext,
    custody: &dyn VaultKeyCustody,
) -> Result<(), StorageError> {
    check_context(context)?;
    let authenticated = custody
        .decrypt(tenant, request.reference(), request.envelope())
        .map_err(custody_storage_error)?;
    drop(authenticated);
    check_context(context)
}

fn require_new_secret(
    local: &mut LocalSession,
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
) -> Result<(), StorageError> {
    if load_secret(local, tenant, reference, digest)?.is_some() {
        return Err(sql::conflict());
    }
    Ok(())
}

fn persist_store(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &SecretStoreRequest,
    digest: &[u8; 32],
    context: &RequestContext,
    fingerprint: &str,
) -> Result<SecretStoreReceipt, StorageError> {
    let (raw, committed_at) = sql::now()?;
    let receipt = SecretStoreReceipt::new(
        request.reference().clone(),
        request.reference().version(),
        request.envelope().key_version(),
        committed_at,
    );
    insert_secret(local, tenant, request, digest, raw)?;
    insert_mutation(
        local,
        tenant,
        &MutationInsert {
            context,
            reference: request.reference(),
            digest,
            fingerprint,
            kind: "store",
            key: Some(request.envelope().key_version()),
            reason: None,
            committed_at: raw,
        },
    )?;
    Ok(receipt)
}

pub(super) fn revoke(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &VaultRevokeRequest,
    digest: &[u8; 32],
    context: &RequestContext,
    custody: &dyn VaultKeyCustody,
) -> Result<SecretRevokeReceipt, StorageError> {
    require_active_identity_transaction(local)?;
    let fingerprint = sql::hex(
        &custody
            .mutation_fingerprint(
                tenant,
                request.reference(),
                VaultOperation::Revoke,
                reason_label(request.reason()).as_bytes(),
            )
            .map_err(custody_storage_error)?,
    );
    if let Some(mutation) = load_mutation(local, tenant, request.reference(), digest, context)? {
        return replay_revoke(mutation, &fingerprint);
    }
    require_active_secret(local, tenant, request.reference(), digest)?;
    persist_revoke(local, tenant, request, digest, context, &fingerprint)
}

fn require_active_secret(
    local: &mut LocalSession,
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
) -> Result<StoredSecret, StorageError> {
    let stored = load_secret(local, tenant, reference, digest)?
        .ok_or_else(|| StorageError::new(StorageErrorCode::NotFound))?;
    if stored.revoked {
        return Err(StorageError::new(StorageErrorCode::NotFound));
    }
    Ok(stored)
}

fn persist_revoke(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &VaultRevokeRequest,
    digest: &[u8; 32],
    context: &RequestContext,
    fingerprint: &str,
) -> Result<SecretRevokeReceipt, StorageError> {
    let (raw, committed_at) = sql::now()?;
    let statement = format!(
        "UPDATE account_vault_secrets SET lifecycle_state = 'revoked', revoked_at = {}, revoke_reason = {} WHERE tenant_id = {} AND reference_digest_hex = {} AND lifecycle_state = 'active';",
        raw,
        sql::text(reason_label(request.reason())),
        sql::text(tenant.as_str()),
        sql::text(&sql::hex(digest)),
    );
    sql::changed(sql::execute(local, statement)?)?;
    insert_mutation(
        local,
        tenant,
        &MutationInsert {
            context,
            reference: request.reference(),
            digest,
            fingerprint,
            kind: "revoke",
            key: None,
            reason: Some(request.reason()),
            committed_at: raw,
        },
    )?;
    Ok(SecretRevokeReceipt::new(
        request.reference().clone(),
        request.reference().version(),
        committed_at,
    ))
}

pub(super) fn reconcile(
    local: &mut LocalSession,
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
    context: &RequestContext,
) -> Result<Option<VaultMutationReceipt>, StorageError> {
    Ok(load_mutation(local, tenant, reference, digest, context)?.map(|mutation| mutation.receipt))
}

pub(super) fn read(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &SecretReadRequest,
    digest: &[u8; 32],
    context: &RequestContext,
    custody: &dyn VaultKeyCustody,
) -> Result<SecretLease, StorageError> {
    require_active_identity_transaction(local)?;
    let stored = require_active_secret(local, tenant, request.reference(), digest)?;
    check_context(context)?;
    let material = custody
        .decrypt(tenant, request.reference(), &stored.envelope)
        .map_err(custody_storage_error)?;
    check_context(context)?;
    issue_audited_lease(local, tenant, request, digest, context, material)
}

fn issue_audited_lease(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &SecretReadRequest,
    digest: &[u8; 32],
    context: &RequestContext,
    material: ariadnion_account_vault::SecretMaterial,
) -> Result<SecretLease, StorageError> {
    let lease_id = new_lease_id().map_err(custody_storage_error)?;
    check_context(context)?;
    let (raw, issued_at) = sql::now()?;
    let lease = SecretLease::issue(
        request.reference().clone(),
        request.module().clone(),
        lease_id,
        issued_at,
        request.lifetime(),
        material,
    )
    .map_err(custody_storage_error)?;
    let expires = sql::time_encode(lease.expires_at())?;
    let lease_digest = sql::hex(&Sha256::digest(lease.lease_id().as_bytes()));
    insert_access_event(
        local,
        tenant,
        &AccessInsert {
            request,
            digest,
            lease_digest: &lease_digest,
            issued_at: raw,
            expires_at: expires,
        },
    )?;
    Ok(lease)
}

struct AccessInsert<'a> {
    request: &'a SecretReadRequest,
    digest: &'a [u8; 32],
    lease_digest: &'a str,
    issued_at: i64,
    expires_at: i64,
}

fn insert_access_event(
    local: &mut LocalSession,
    tenant: &TenantId,
    access: &AccessInsert<'_>,
) -> Result<(), StorageError> {
    let request = access.request;
    let statement = format!(
        "INSERT INTO account_vault_access_events (tenant_id, event_id, lease_id_digest_hex, reference_digest_hex, module_id, secret_purpose, issued_at, expires_at, outcome, occurred_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, 'issued', {});",
        sql::text(tenant.as_str()),
        sql::text(access.lease_digest),
        sql::text(access.lease_digest),
        sql::text(&sql::hex(access.digest)),
        sql::text(request.module().as_str()),
        sql::text(request.reference().purpose().as_str()),
        access.issued_at,
        access.expires_at,
        access.issued_at,
    );
    sql::changed(sql::execute(local, statement)?)
}

fn insert_secret(
    local: &mut LocalSession,
    tenant: &TenantId,
    request: &SecretStoreRequest,
    digest: &[u8; 32],
    committed_at: i64,
) -> Result<(), StorageError> {
    let reference = request.reference();
    let envelope = request.envelope();
    let key_version = i64::try_from(envelope.key_version().get()).map_err(|_| sql::exhausted())?;
    let nonce = Zeroizing::new(sql::hex(envelope.nonce()));
    let ciphertext = Zeroizing::new(sql::hex(envelope.ciphertext()));
    let statement = format!(
        "INSERT INTO account_vault_secrets (tenant_id, reference_digest_hex, secret_provider, secret_path, secret_version, secret_purpose, key_version, nonce_hex, ciphertext_hex, envelope_digest_hex, lifecycle_state, created_at, revoked_at, revoke_reason) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, 'active', {}, NULL, NULL);",
        sql::text(tenant.as_str()),
        sql::text(&sql::hex(digest)),
        sql::text(reference.provider().as_str()),
        sql::text(reference.path().as_str()),
        sql::text(&reference.version().get().to_string()),
        sql::text(reference.purpose().as_str()),
        key_version,
        sql::text(&nonce),
        sql::text(&ciphertext),
        sql::text(&envelope_digest(envelope)),
        committed_at,
    );
    sql::changed(sql::execute(local, statement)?)
}

struct MutationInsert<'a> {
    context: &'a RequestContext,
    reference: &'a SecretRef,
    digest: &'a [u8; 32],
    fingerprint: &'a str,
    kind: &'a str,
    key: Option<VaultKeyVersion>,
    reason: Option<VaultRevokeReason>,
    committed_at: i64,
}

fn insert_mutation(
    local: &mut LocalSession,
    tenant: &TenantId,
    mutation: &MutationInsert<'_>,
) -> Result<(), StorageError> {
    let key = mutation
        .key
        .map(|value| value.get().to_string())
        .unwrap_or_else(|| "NULL".to_owned());
    let reason = match mutation.reason {
        Some(reason) => sql::text(reason_label(reason)).to_string(),
        None => "NULL".to_owned(),
    };
    let reference = mutation.reference;
    let statement = format!(
        "INSERT INTO account_vault_mutations (tenant_id, mutation_id, request_fingerprint_hex, mutation_kind, reference_digest_hex, secret_provider, secret_path, secret_version, disposition, key_version, revoke_reason, committed_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, 'committed', {}, {}, {});",
        sql::text(tenant.as_str()),
        sql::text(mutation.context.request_id().as_str()),
        sql::text(mutation.fingerprint),
        sql::text(mutation.kind),
        sql::text(&sql::hex(mutation.digest)),
        sql::text(reference.provider().as_str()),
        sql::text(reference.path().as_str()),
        sql::text(&reference.version().get().to_string()),
        key,
        reason,
        mutation.committed_at,
    );
    sql::changed(sql::execute(local, statement)?)
}

fn load_secret(
    local: &mut LocalSession,
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
) -> Result<Option<StoredSecret>, StorageError> {
    let query = format!(
        "SELECT {SECRET_PROJECTION} FROM account_vault_secrets WHERE tenant_id = {} AND reference_digest_hex = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(&sql::hex(digest)),
    );
    let batch = sql::rows(sql::execute(local, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_secret(row, tenant, reference, digest).map(Some),
        _ => Err(sql::integrity()),
    }
}

fn decode_secret(
    row: &Row,
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
) -> Result<StoredSecret, StorageError> {
    let values = row.values();
    if values.len() != 14 {
        return Err(sql::integrity());
    }
    require_reference(&values[0..6], tenant, reference, digest)?;
    let envelope = decode_envelope(&values[6..10])?;
    let revoked = decode_lifecycle(&values[10..14])?;
    Ok(StoredSecret { envelope, revoked })
}

fn decode_envelope(values: &[SqlValue]) -> Result<EncryptedSecretEnvelope, StorageError> {
    let key = decode_key(&values[0])?;
    let nonce = decode_nonce(&values[1])?;
    let ciphertext = decode_ciphertext(&values[2])?;
    let envelope =
        EncryptedSecretEnvelope::new(key, nonce, &ciphertext).map_err(|_| sql::integrity())?;
    if envelope_digest(&envelope) != sql::string(&values[3])? {
        return Err(sql::integrity());
    }
    Ok(envelope)
}

fn decode_key(value: &SqlValue) -> Result<VaultKeyVersion, StorageError> {
    let key = u64::try_from(sql::integer(value)?).map_err(|_| sql::integrity())?;
    VaultKeyVersion::new(key).map_err(|_| sql::integrity())
}

fn decode_ciphertext(value: &SqlValue) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    sql::decode_hex(sql::string(value)?, MAX_CIPHERTEXT_BYTES)
}

fn decode_nonce(value: &SqlValue) -> Result<[u8; ENVELOPE_NONCE_BYTES], StorageError> {
    let nonce = sql::decode_hex(sql::string(value)?, ENVELOPE_NONCE_BYTES)?;
    nonce.as_slice().try_into().map_err(|_| sql::integrity())
}

fn decode_lifecycle(values: &[SqlValue]) -> Result<bool, StorageError> {
    match sql::string(&values[0])? {
        "active" => decode_active_lifecycle(values),
        "revoked" => decode_revoked_lifecycle(values),
        _ => Err(sql::integrity()),
    }
}

fn decode_active_lifecycle(values: &[SqlValue]) -> Result<bool, StorageError> {
    sql::time(&values[1])?;
    if values[2] != SqlValue::Null || values[3] != SqlValue::Null {
        return Err(sql::integrity());
    }
    Ok(false)
}

fn decode_revoked_lifecycle(values: &[SqlValue]) -> Result<bool, StorageError> {
    if sql::time(&values[2])? < sql::time(&values[1])? {
        return Err(sql::integrity());
    }
    decode_reason(sql::string(&values[3])?)?;
    Ok(true)
}

fn load_mutation(
    local: &mut LocalSession,
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
    context: &RequestContext,
) -> Result<Option<Mutation>, StorageError> {
    let query = format!(
        "SELECT {MUTATION_PROJECTION} FROM account_vault_mutations WHERE tenant_id = {} AND mutation_id = {} LIMIT 2;",
        sql::text(tenant.as_str()),
        sql::text(context.request_id().as_str()),
    );
    let batch = sql::rows(sql::execute(local, query)?)?;
    match batch.rows() {
        [] => Ok(None),
        [row] => decode_mutation(row, tenant, reference, digest, context).map(Some),
        _ => Err(sql::integrity()),
    }
}

fn decode_mutation(
    row: &Row,
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
    context: &RequestContext,
) -> Result<Mutation, StorageError> {
    let values = row.values();
    if values.len() != 12 {
        return Err(sql::integrity());
    }
    require_mutation_identity(values, tenant, reference, digest, context)?;
    let fingerprint = decode_fingerprint(&values[2])?;
    let receipt = mutation_receipt(&values[3], &values[9..12], reference)?;
    Ok(Mutation {
        fingerprint,
        receipt,
    })
}

fn require_mutation_identity(
    values: &[SqlValue],
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
    context: &RequestContext,
) -> Result<(), StorageError> {
    sql::require_text(&values[0], tenant.as_str())?;
    sql::require_text(&values[1], context.request_id().as_str())?;
    require_mutation_reference(&values[4..8], reference, digest)?;
    sql::require_text(&values[8], "committed")
}

fn decode_fingerprint(value: &SqlValue) -> Result<String, StorageError> {
    let fingerprint = sql::string(value)?;
    let bytes = sql::decode_hex(fingerprint, 32)?;
    if bytes.len() != 32 {
        return Err(sql::integrity());
    }
    Ok(fingerprint.to_owned())
}

fn mutation_receipt(
    kind: &SqlValue,
    values: &[SqlValue],
    reference: &SecretRef,
) -> Result<VaultMutationReceipt, StorageError> {
    match sql::string(kind)? {
        "store" => decode_store_receipt(values, reference),
        "revoke" => decode_revoke_receipt(values, reference),
        _ => Err(sql::integrity()),
    }
}

fn decode_store_receipt(
    values: &[SqlValue],
    reference: &SecretRef,
) -> Result<VaultMutationReceipt, StorageError> {
    if values[1] != SqlValue::Null {
        return Err(sql::integrity());
    }
    let key = decode_key(&values[0])?;
    let committed_at = sql::time(&values[2])?;
    Ok(VaultMutationReceipt::Stored(SecretStoreReceipt::new(
        reference.clone(),
        reference.version(),
        key,
        committed_at,
    )))
}

fn decode_revoke_receipt(
    values: &[SqlValue],
    reference: &SecretRef,
) -> Result<VaultMutationReceipt, StorageError> {
    if values[0] != SqlValue::Null {
        return Err(sql::integrity());
    }
    decode_reason(sql::string(&values[1])?)?;
    let committed_at = sql::time(&values[2])?;
    Ok(VaultMutationReceipt::Revoked(SecretRevokeReceipt::new(
        reference.clone(),
        reference.version(),
        committed_at,
    )))
}

fn require_reference(
    values: &[SqlValue],
    tenant: &TenantId,
    reference: &SecretRef,
    digest: &[u8; 32],
) -> Result<(), StorageError> {
    sql::require_text(&values[0], tenant.as_str())?;
    require_mutation_reference(&values[1..5], reference, digest)?;
    sql::require_text(&values[5], reference.purpose().as_str())
}

fn require_mutation_reference(
    values: &[SqlValue],
    reference: &SecretRef,
    digest: &[u8; 32],
) -> Result<(), StorageError> {
    require_locator(&values[0], digest)?;
    sql::require_text(&values[1], reference.provider().as_str())?;
    sql::require_text(&values[2], reference.path().as_str())?;
    if sql::unsigned_text(&values[3])? != reference.version().get() {
        return Err(sql::integrity());
    }
    Ok(())
}

fn require_locator(value: &SqlValue, digest: &[u8; 32]) -> Result<(), StorageError> {
    if sql::string(value)? != sql::hex(digest) {
        return Err(sql::conflict());
    }
    Ok(())
}

fn replay_store(mutation: Mutation, fingerprint: &str) -> Result<SecretStoreReceipt, StorageError> {
    if mutation.fingerprint != fingerprint {
        return Err(sql::conflict());
    }
    match mutation.receipt {
        VaultMutationReceipt::Stored(receipt) => Ok(receipt),
        VaultMutationReceipt::Revoked(_) => Err(sql::conflict()),
    }
}

fn replay_revoke(
    mutation: Mutation,
    fingerprint: &str,
) -> Result<SecretRevokeReceipt, StorageError> {
    if mutation.fingerprint != fingerprint {
        return Err(sql::conflict());
    }
    match mutation.receipt {
        VaultMutationReceipt::Revoked(receipt) => Ok(receipt),
        VaultMutationReceipt::Stored(_) => Err(sql::conflict()),
    }
}

fn envelope_digest(envelope: &EncryptedSecretEnvelope) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ariadnion.vault.envelope.v1");
    digest.update(envelope.key_version().get().to_be_bytes());
    digest.update(envelope.nonce());
    digest.update(envelope.ciphertext());
    sql::hex(&digest.finalize())
}

const fn reason_label(reason: VaultRevokeReason) -> &'static str {
    match reason {
        VaultRevokeReason::Operator => "operator",
        VaultRevokeReason::RotationFailure => "rotation_failure",
        VaultRevokeReason::RiskEvent => "risk_event",
    }
}

fn decode_reason(reason: &str) -> Result<VaultRevokeReason, StorageError> {
    match reason {
        "operator" => Ok(VaultRevokeReason::Operator),
        "rotation_failure" => Ok(VaultRevokeReason::RotationFailure),
        "risk_event" => Ok(VaultRevokeReason::RiskEvent),
        _ => Err(sql::integrity()),
    }
}

fn custody_storage_error(error: ariadnion_account_vault::VaultError) -> StorageError {
    let code = match error.code() {
        ariadnion_account_vault::VaultErrorCode::Unavailable => StorageErrorCode::Unavailable,
        ariadnion_account_vault::VaultErrorCode::Cancelled => StorageErrorCode::Cancelled,
        ariadnion_account_vault::VaultErrorCode::DeadlineExceeded => {
            StorageErrorCode::DeadlineExceeded
        }
        _ => StorageErrorCode::IntegrityFailure,
    };
    StorageError::new(code)
}

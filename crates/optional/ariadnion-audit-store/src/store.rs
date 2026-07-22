//! Deterministic append-only audit log verification and export.

use std::collections::BTreeSet;

use ariadnion_audit_domain::{
    AUDIT_CHAIN_DIGEST_VERSION, AuditChainDigest, AuditEvent, AuditSequence,
};
use ariadnion_core::TenantId;

use crate::error::error;
use crate::{AuditStoreError, AuditStoreErrorCode};

/// Maximum number of events returned by one export call.
pub const MAX_AUDIT_EXPORT_EVENTS: usize = 1_024;
const MAX_AUDIT_EXPORT_SPAN: u64 = MAX_AUDIT_EXPORT_EVENTS as u64;
/// Maximum number of events retained by one in-memory verification snapshot.
pub const MAX_AUDIT_SNAPSHOT_EVENTS: usize = 1_024;

/// Durable tenant-local chain position used for bounded append verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditChainHead {
    tenant_id: TenantId,
    last_sequence: Option<AuditSequence>,
    chain_digest_version: Option<u16>,
    chain_digest: Option<AuditChainDigest>,
}

impl AuditChainHead {
    /// Creates an empty chain head for one tenant.
    #[must_use]
    pub fn empty(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            last_sequence: None,
            chain_digest_version: None,
            chain_digest: None,
        }
    }

    /// Creates a chain head from one verified boundary event.
    ///
    /// # Errors
    ///
    /// Returns a digest or version failure when the event is not canonical.
    /// Persistence adapters must authenticate the event's storage before using
    /// the resulting head as a durable continuation anchor.
    pub fn from_event(event: &AuditEvent) -> Result<Self, AuditStoreError> {
        validate_event_digest(event)?;
        Ok(Self {
            tenant_id: event.tenant_id().clone(),
            last_sequence: Some(event.sequence()),
            chain_digest_version: Some(event.chain_digest_version()),
            chain_digest: Some(event.chain_digest()),
        })
    }

    /// Rehydrates a persisted head against its authenticated boundary event.
    ///
    /// The adapter must load both records from authenticated storage and keep
    /// their compare-and-swap update in the same transaction as event append.
    ///
    /// # Errors
    ///
    /// Returns stable failures for unsupported versions, a tenant mismatch,
    /// non-canonical boundary material, or a head that differs from the event.
    pub fn rehydrate(
        tenant_id: TenantId,
        last_sequence: AuditSequence,
        chain_digest_version: u16,
        chain_digest: AuditChainDigest,
        boundary_event: &AuditEvent,
    ) -> Result<Self, AuditStoreError> {
        validate_declared_version(chain_digest_version)?;
        validate_event_digest(boundary_event)?;
        validate_head_boundary(
            &tenant_id,
            last_sequence,
            chain_digest_version,
            chain_digest,
            boundary_event,
        )?;
        Ok(Self {
            tenant_id,
            last_sequence: Some(last_sequence),
            chain_digest_version: Some(chain_digest_version),
            chain_digest: Some(chain_digest),
        })
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the last committed sequence, or none for an empty chain.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<AuditSequence> {
        self.last_sequence
    }

    /// Returns the boundary digest schema version, or none for an empty chain.
    #[must_use]
    pub const fn chain_digest_version(&self) -> Option<u16> {
        self.chain_digest_version
    }

    /// Returns the last committed digest, or none for an empty chain.
    #[must_use]
    pub const fn chain_digest(&self) -> Option<AuditChainDigest> {
        self.chain_digest
    }

    fn next_sequence(&self) -> Result<AuditSequence, AuditStoreError> {
        match self.last_sequence {
            Some(sequence) => sequence
                .next()
                .map_err(|_| error(AuditStoreErrorCode::InvalidArgument)),
            None => Ok(AuditSequence::initial()),
        }
    }

    fn advanced(&self, event: &AuditEvent) -> Self {
        Self {
            tenant_id: self.tenant_id.clone(),
            last_sequence: Some(event.sequence()),
            chain_digest_version: Some(event.chain_digest_version()),
            chain_digest: Some(event.chain_digest()),
        }
    }
}

/// Inclusive sequence bounds for one exact export page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditExportCursor {
    start: AuditSequence,
    end_inclusive: AuditSequence,
}

impl AuditExportCursor {
    /// Creates an export cursor with an exclusive end sequence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreErrorCode::EmptyRange`] when the end is not greater
    /// than the start, or [`AuditStoreErrorCode::InvalidArgument`] when the
    /// exclusive span exceeds 1,024 events.
    pub fn new(
        start: AuditSequence,
        end_exclusive: AuditSequence,
    ) -> Result<Self, AuditStoreError> {
        if end_exclusive.get() <= start.get() {
            return Err(error(AuditStoreErrorCode::EmptyRange));
        }
        let end_inclusive = end_exclusive
            .get()
            .checked_sub(1)
            .and_then(|value| AuditSequence::new(value).ok())
            .ok_or_else(|| error(AuditStoreErrorCode::InvalidArgument))?;
        Self::through(start, end_inclusive)
    }

    /// Creates an export cursor with inclusive start and end sequences.
    ///
    /// Equal bounds select one event, including at `u64::MAX`.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreErrorCode::EmptyRange`] when the end is below the
    /// start, or [`AuditStoreErrorCode::InvalidArgument`] when the inclusive
    /// span exceeds 1,024 events.
    pub fn through(
        start: AuditSequence,
        end_inclusive: AuditSequence,
    ) -> Result<Self, AuditStoreError> {
        validate_export_span(start, end_inclusive)?;
        Ok(Self {
            start,
            end_inclusive,
        })
    }

    /// Returns the inclusive start sequence.
    #[must_use]
    pub const fn start(self) -> AuditSequence {
        self.start
    }

    /// Returns the inclusive end sequence.
    #[must_use]
    pub const fn end_inclusive(self) -> AuditSequence {
        self.end_inclusive
    }

    /// Returns the exclusive end, or none when the inclusive end is `u64::MAX`.
    #[must_use]
    pub fn end_exclusive(self) -> Option<AuditSequence> {
        self.end_inclusive.next().ok()
    }
}

fn validate_export_span(
    start: AuditSequence,
    end_inclusive: AuditSequence,
) -> Result<(), AuditStoreError> {
    let span = end_inclusive
        .get()
        .checked_sub(start.get())
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| error(AuditStoreErrorCode::EmptyRange))?;
    if span > MAX_AUDIT_EXPORT_SPAN {
        return Err(error(AuditStoreErrorCode::InvalidArgument));
    }
    Ok(())
}

/// Immutable ordered snapshot of one tenant audit log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLogSnapshot {
    tenant_id: TenantId,
    events: Box<[AuditEvent]>,
}

impl AuditLogSnapshot {
    /// Creates an empty tenant audit log.
    #[must_use]
    pub fn empty(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            events: Box::from([]),
        }
    }

    /// Creates a snapshot from an already verified ordered event list.
    ///
    /// # Errors
    ///
    /// Returns resource-limit, tenant, duplicate, sequence, chain, digest, or
    /// unsupported-version failures when verification fails.
    pub fn from_events(
        tenant_id: TenantId,
        events: Vec<AuditEvent>,
    ) -> Result<Self, AuditStoreError> {
        validate_batch_size(events.len())?;
        let snapshot = Self {
            tenant_id,
            events: events.into_boxed_slice(),
        };
        verify_audit_chain(&snapshot)?;
        Ok(snapshot)
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the ordered events.
    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Returns the tip event when the log is non-empty.
    #[must_use]
    pub fn tip(&self) -> Option<&AuditEvent> {
        self.events.last()
    }
}

/// Appends one audit event after sequence and chain verification.
///
/// This pure function does not perform durable I/O. Persistence adapters must
/// compare-and-swap the tip sequence and store the accepted snapshot atomically.
///
/// # Errors
///
/// Returns stable redacted failures for resource exhaustion, tenant mismatch,
/// sequence gaps, chain breaks, digest/version failures, or duplicate identities.
pub fn append_audit_event(
    current: &AuditLogSnapshot,
    event: AuditEvent,
) -> Result<AuditLogSnapshot, AuditStoreError> {
    validate_append_capacity(current)?;
    validate_event_tenant(current.tenant_id(), &event)?;
    validate_new_event_id(current, &event)?;
    let head = snapshot_chain_head(current)?;
    verify_audit_batch(&head, std::slice::from_ref(&event))?;
    let mut events = current.events().to_vec();
    events.push(event);
    Ok(AuditLogSnapshot {
        tenant_id: current.tenant_id().clone(),
        events: events.into_boxed_slice(),
    })
}

/// Verifies that a snapshot is a contiguous, tenant-bound hash chain.
///
/// # Errors
///
/// Returns resource-limit, tenant, duplicate, sequence, chain, digest, or
/// unsupported-version failures for any inconsistency.
pub fn verify_audit_chain(snapshot: &AuditLogSnapshot) -> Result<(), AuditStoreError> {
    let head = AuditChainHead::empty(snapshot.tenant_id().clone());
    verify_audit_batch(&head, snapshot.events()).map(|_| ())
}

/// Verifies one bounded event page beginning at a durable chain head.
///
/// Event identities are checked for duplicates within the page. Durable
/// adapters must additionally enforce a unique `(tenant_id, event_id)` key and
/// atomically compare-and-swap the supplied head when committing the page.
///
/// # Errors
///
/// Returns stable redacted failures for resource overflow, tenant mismatch,
/// duplicate identities, sequence gaps or exhaustion, broken links, digest
/// mismatch, an unsupported digest version, or malformed head state.
pub fn verify_audit_batch(
    head: &AuditChainHead,
    events: &[AuditEvent],
) -> Result<AuditChainHead, AuditStoreError> {
    validate_batch_size(events.len())?;
    validate_chain_head(head)?;
    let mut next = head.clone();
    let mut event_ids = BTreeSet::new();
    for event in events {
        if !event_ids.insert(event.id()) {
            return Err(error(AuditStoreErrorCode::DuplicateEvent));
        }
        next = verify_audit_event(&next, event)?;
    }
    Ok(next)
}

/// Exports a bounded sequence window from a verified snapshot.
///
/// # Errors
///
/// Returns verification failures for an invalid snapshot, [`AuditStoreErrorCode::EmptyRange`]
/// when no event is available, or [`AuditStoreErrorCode::IncompleteRange`] when
/// only part of the exact requested range is present.
pub fn export_audit_range(
    snapshot: &AuditLogSnapshot,
    cursor: AuditExportCursor,
) -> Result<Box<[AuditEvent]>, AuditStoreError> {
    verify_audit_chain(snapshot)?;
    let exported: Vec<AuditEvent> = snapshot
        .events()
        .iter()
        .filter(|event| {
            event.sequence().get() >= cursor.start().get()
                && event.sequence().get() <= cursor.end_inclusive().get()
        })
        .cloned()
        .collect();
    validate_export_coverage(&exported, cursor)?;
    Ok(exported.into_boxed_slice())
}

/// Exports one exact verified page beginning at an authenticated chain head.
///
/// The caller must obtain `head` from authenticated durable state and query
/// exactly the cursor range. This function rejects partial pages rather than
/// silently presenting them as complete exports.
///
/// # Errors
///
/// Returns verification failures for an invalid head or event page,
/// [`AuditStoreErrorCode::EmptyRange`] when the page is empty, or
/// [`AuditStoreErrorCode::IncompleteRange`] when page bounds differ from the cursor.
pub fn export_audit_batch(
    head: &AuditChainHead,
    events: &[AuditEvent],
    cursor: AuditExportCursor,
) -> Result<Box<[AuditEvent]>, AuditStoreError> {
    verify_audit_batch(head, events)?;
    validate_export_coverage(events, cursor)?;
    Ok(events.to_vec().into_boxed_slice())
}

fn verify_audit_event(
    head: &AuditChainHead,
    event: &AuditEvent,
) -> Result<AuditChainHead, AuditStoreError> {
    validate_event_tenant(head.tenant_id(), event)?;
    validate_event_sequence(head, event)?;
    validate_previous_digest(head, event)?;
    validate_event_digest(event)?;
    Ok(head.advanced(event))
}

fn validate_chain_head(head: &AuditChainHead) -> Result<(), AuditStoreError> {
    match (
        head.last_sequence,
        head.chain_digest_version,
        head.chain_digest,
    ) {
        (None, None, None) => Ok(()),
        (Some(_), Some(version), Some(_)) => validate_declared_version(version),
        _ => Err(error(AuditStoreErrorCode::InvalidArgument)),
    }
}

fn validate_head_boundary(
    tenant_id: &TenantId,
    last_sequence: AuditSequence,
    chain_digest_version: u16,
    chain_digest: AuditChainDigest,
    boundary_event: &AuditEvent,
) -> Result<(), AuditStoreError> {
    if boundary_event.tenant_id() != tenant_id {
        return Err(error(AuditStoreErrorCode::TenantMismatch));
    }
    if boundary_event.sequence() != last_sequence
        || boundary_event.chain_digest_version() != chain_digest_version
        || boundary_event.chain_digest() != chain_digest
    {
        return Err(error(AuditStoreErrorCode::ChainBreak));
    }
    Ok(())
}

fn validate_batch_size(event_count: usize) -> Result<(), AuditStoreError> {
    if event_count > MAX_AUDIT_SNAPSHOT_EVENTS {
        return Err(error(AuditStoreErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

fn validate_append_capacity(current: &AuditLogSnapshot) -> Result<(), AuditStoreError> {
    if current.events().len() >= MAX_AUDIT_SNAPSHOT_EVENTS {
        return Err(error(AuditStoreErrorCode::ResourceLimitExceeded));
    }
    Ok(())
}

fn validate_new_event_id(
    current: &AuditLogSnapshot,
    event: &AuditEvent,
) -> Result<(), AuditStoreError> {
    if current
        .events()
        .iter()
        .any(|existing| existing.id() == event.id())
    {
        return Err(error(AuditStoreErrorCode::DuplicateEvent));
    }
    Ok(())
}

fn validate_event_tenant(tenant_id: &TenantId, event: &AuditEvent) -> Result<(), AuditStoreError> {
    if event.tenant_id() != tenant_id {
        return Err(error(AuditStoreErrorCode::TenantMismatch));
    }
    Ok(())
}

fn validate_event_sequence(
    head: &AuditChainHead,
    event: &AuditEvent,
) -> Result<(), AuditStoreError> {
    if event.sequence() != head.next_sequence()? {
        return Err(error(AuditStoreErrorCode::SequenceGap));
    }
    Ok(())
}

fn validate_previous_digest(
    head: &AuditChainHead,
    event: &AuditEvent,
) -> Result<(), AuditStoreError> {
    if event.previous_chain_digest() != head.chain_digest() {
        return Err(error(AuditStoreErrorCode::ChainBreak));
    }
    Ok(())
}

fn validate_event_digest(event: &AuditEvent) -> Result<(), AuditStoreError> {
    validate_declared_version(event.chain_digest_version())?;
    if event.recompute_chain_digest() != event.chain_digest() {
        return Err(error(AuditStoreErrorCode::DigestMismatch));
    }
    Ok(())
}

fn validate_declared_version(version: u16) -> Result<(), AuditStoreError> {
    if version != AUDIT_CHAIN_DIGEST_VERSION {
        return Err(error(AuditStoreErrorCode::UnsupportedVersion));
    }
    Ok(())
}

fn validate_export_coverage(
    events: &[AuditEvent],
    cursor: AuditExportCursor,
) -> Result<(), AuditStoreError> {
    let Some((first, last)) = events.first().zip(events.last()) else {
        return Err(error(AuditStoreErrorCode::EmptyRange));
    };
    if first.sequence() != cursor.start() || last.sequence() != cursor.end_inclusive() {
        return Err(error(AuditStoreErrorCode::IncompleteRange));
    }
    Ok(())
}

fn snapshot_chain_head(snapshot: &AuditLogSnapshot) -> Result<AuditChainHead, AuditStoreError> {
    match snapshot.tip() {
        Some(event) => AuditChainHead::from_event(event),
        None => Ok(AuditChainHead::empty(snapshot.tenant_id().clone())),
    }
}

//! Deterministic append-only audit log verification and export.

use ariadnion_audit_domain::{AuditEvent, AuditSequence};
use ariadnion_core::TenantId;

use crate::error::error;
use crate::{AuditStoreError, AuditStoreErrorCode};

/// Maximum number of events returned by one export call.
pub const MAX_AUDIT_EXPORT_EVENTS: usize = 1_024;

/// Inclusive start and exclusive end sequence cursor for export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditExportCursor {
    start: AuditSequence,
    end_exclusive: AuditSequence,
}

impl AuditExportCursor {
    /// Creates an export cursor with an exclusive end sequence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreErrorCode::EmptyRange`] when the end is not greater
    /// than the start, or the inclusive span would exceed the export bound.
    pub fn new(
        start: AuditSequence,
        end_exclusive: AuditSequence,
    ) -> Result<Self, AuditStoreError> {
        if end_exclusive.get() <= start.get() {
            return Err(error(AuditStoreErrorCode::EmptyRange));
        }
        let span = end_exclusive
            .get()
            .checked_sub(start.get())
            .ok_or_else(|| error(AuditStoreErrorCode::InvalidArgument))?;
        if span as usize > MAX_AUDIT_EXPORT_EVENTS {
            return Err(error(AuditStoreErrorCode::InvalidArgument));
        }
        Ok(Self {
            start,
            end_exclusive,
        })
    }

    /// Returns the inclusive start sequence.
    #[must_use]
    pub const fn start(self) -> AuditSequence {
        self.start
    }

    /// Returns the exclusive end sequence.
    #[must_use]
    pub const fn end_exclusive(self) -> AuditSequence {
        self.end_exclusive
    }
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
    /// Returns chain, sequence, tenant, or duplicate failures when verification fails.
    pub fn from_events(
        tenant_id: TenantId,
        events: Vec<AuditEvent>,
    ) -> Result<Self, AuditStoreError> {
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
/// Returns stable redacted failures for tenant mismatch, sequence gaps, chain
/// breaks, or duplicate event identities.
pub fn append_audit_event(
    current: &AuditLogSnapshot,
    event: AuditEvent,
) -> Result<AuditLogSnapshot, AuditStoreError> {
    if event.tenant_id() != current.tenant_id() {
        return Err(error(AuditStoreErrorCode::TenantMismatch));
    }
    if current
        .events()
        .iter()
        .any(|existing| existing.id() == event.id())
    {
        return Err(error(AuditStoreErrorCode::DuplicateEvent));
    }
    validate_append_tip(current, &event)?;
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
/// Returns sequence-gap or chain-break failures for any inconsistency.
pub fn verify_audit_chain(snapshot: &AuditLogSnapshot) -> Result<(), AuditStoreError> {
    let mut previous_chain = None;
    let mut expected_sequence = 1_u64;
    for event in snapshot.events() {
        if event.tenant_id() != snapshot.tenant_id() {
            return Err(error(AuditStoreErrorCode::TenantMismatch));
        }
        if event.sequence().get() != expected_sequence {
            return Err(error(AuditStoreErrorCode::SequenceGap));
        }
        if event.previous_chain_digest() != previous_chain {
            return Err(error(AuditStoreErrorCode::ChainBreak));
        }
        previous_chain = Some(event.chain_digest());
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| error(AuditStoreErrorCode::InvalidArgument))?;
    }
    Ok(())
}

/// Exports a bounded sequence window from a verified snapshot.
///
/// # Errors
///
/// Returns range failures when the cursor is empty or outside the log.
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
                && event.sequence().get() < cursor.end_exclusive().get()
        })
        .cloned()
        .collect();
    if exported.is_empty() {
        return Err(error(AuditStoreErrorCode::EmptyRange));
    }
    Ok(exported.into_boxed_slice())
}

fn validate_append_tip(
    current: &AuditLogSnapshot,
    event: &AuditEvent,
) -> Result<(), AuditStoreError> {
    match current.tip() {
        None => {
            if event.sequence() != AuditSequence::initial() {
                return Err(error(AuditStoreErrorCode::SequenceGap));
            }
            if event.previous_chain_digest().is_some() {
                return Err(error(AuditStoreErrorCode::ChainBreak));
            }
        }
        Some(tip) => {
            let expected = tip
                .sequence()
                .next()
                .map_err(|_| error(AuditStoreErrorCode::InvalidArgument))?;
            if event.sequence() != expected {
                return Err(error(AuditStoreErrorCode::SequenceGap));
            }
            if event.previous_chain_digest() != Some(tip.chain_digest()) {
                return Err(error(AuditStoreErrorCode::ChainBreak));
            }
        }
    }
    Ok(())
}

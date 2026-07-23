//! Replay validation for the append-only user lifecycle history.

use ariadnion_core::{PrincipalId, RequestId};
use ariadnion_storage_domain::StorageError;
use ariadnion_user_domain::{DeletionRecoveryState, User, UserSnapshotState, UserVersion};
use rnmdb_executor::vector::Row;

use super::super::evidence::{LifecycleRecord, SnapshotRecord, TransitionIdentity};
use super::super::integrity_failure;
use super::{
    PersistedLifecycle, VerifiedLifecycle, decode_lifecycle_row, decode_persisted_lifecycle,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum HistoryRecovery {
    Active,
    Suspended,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HistoryState {
    Invited,
    Active,
    Suspended,
    DeletionPending {
        recovery: HistoryRecovery,
        not_before: i64,
    },
    Deleted,
}

#[derive(Clone, Copy)]
struct HistoryEvent<'a> {
    version: UserVersion,
    kind: &'a str,
    occurred_at: i64,
    not_before: Option<i64>,
    recovery_state: Option<&'a str>,
}

struct VerifiedHistoryRow<'a> {
    event: HistoryEvent<'a>,
    actor: PrincipalId,
    request_id: RequestId,
}

fn verified_history_row<'a>(persisted: &PersistedLifecycle<'a>) -> VerifiedHistoryRow<'a> {
    VerifiedHistoryRow {
        event: HistoryEvent::from_persisted(persisted),
        actor: persisted.actor.clone(),
        request_id: persisted.request_id.clone(),
    }
}

fn verified_lifecycle(
    row: VerifiedHistoryRow<'_>,
    state: HistoryState,
) -> Result<VerifiedLifecycle, StorageError> {
    Ok(VerifiedLifecycle {
        version: row.event.version,
        actor: row.actor,
        request_id: row.request_id,
        snapshot: snapshot_after_event(state, row.event)?,
        lifecycle: lifecycle_record(row.event)?,
    })
}

impl<'a> HistoryEvent<'a> {
    fn from_persisted(persisted: &PersistedLifecycle<'a>) -> Self {
        Self {
            version: persisted.version,
            kind: persisted.kind,
            occurred_at: persisted.occurred_at,
            not_before: persisted.not_before,
            recovery_state: persisted.recovery_state,
        }
    }

    fn from_record(version: UserVersion, record: LifecycleRecord) -> Self {
        Self {
            version,
            kind: record.kind,
            occurred_at: record.occurred_at,
            not_before: record.not_before,
            recovery_state: record.recovery_state,
        }
    }
}

pub(super) fn verify_history_rows(
    rows: &[Row],
    identity: &TransitionIdentity,
    current: &User,
) -> Result<Box<[VerifiedLifecycle]>, StorageError> {
    let (first, later) = rows.split_first().ok_or_else(integrity_failure)?;
    decode_lifecycle_row(first, identity)?;
    let first_event = verify_history_row(first, identity, identity.new_version())?;
    let state = target_history_state(identity)?;
    let (state, verified) =
        replay_later_history(later, identity, state, first_event.event.version)?;
    validate_terminal_history_state(state, current.snapshot_state())?;
    Ok(verified)
}

fn replay_later_history(
    rows: &[Row],
    identity: &TransitionIdentity,
    mut state: HistoryState,
    mut expected_version: UserVersion,
) -> Result<(HistoryState, Box<[VerifiedLifecycle]>), StorageError> {
    let mut verified = Vec::with_capacity(rows.len());
    for row in rows {
        expected_version = next_history_version(expected_version)?;
        let event = verify_history_row(row, identity, expected_version)?;
        state = advance_history(state, event.event)?;
        verified.push(verified_lifecycle(event, state)?);
    }
    Ok((state, verified.into_boxed_slice()))
}

fn verify_history_row<'a>(
    row: &'a Row,
    identity: &TransitionIdentity,
    expected_version: UserVersion,
) -> Result<VerifiedHistoryRow<'a>, StorageError> {
    let persisted = decode_persisted_lifecycle(row)?;
    validate_history_identity(&persisted, identity, expected_version)?;
    Ok(verified_history_row(&persisted))
}

fn lifecycle_record(event: HistoryEvent<'_>) -> Result<LifecycleRecord, StorageError> {
    let kind = match event.kind {
        "activated" => "activated",
        "suspended" => "suspended",
        "resumed" => "resumed",
        "deletion_requested" => "deletion_requested",
        "deletion_recovered" => "deletion_recovered",
        "deleted" => "deleted",
        _ => return Err(integrity_failure()),
    };
    Ok(LifecycleRecord {
        kind,
        occurred_at: event.occurred_at,
        not_before: event.not_before,
        recovery_state: static_recovery_state(event.recovery_state)?,
    })
}

fn static_recovery_state(value: Option<&str>) -> Result<Option<&'static str>, StorageError> {
    match value {
        None => Ok(None),
        Some("active") => Ok(Some("active")),
        Some("suspended") => Ok(Some("suspended")),
        Some(_) => Err(integrity_failure()),
    }
}

fn snapshot_after_event(
    state: HistoryState,
    event: HistoryEvent<'_>,
) -> Result<SnapshotRecord, StorageError> {
    match state {
        HistoryState::Invited => Err(integrity_failure()),
        HistoryState::Active => Ok(simple_snapshot("active")),
        HistoryState::Suspended => Ok(simple_snapshot("suspended")),
        HistoryState::Deleted => Ok(simple_snapshot("deleted")),
        HistoryState::DeletionPending {
            recovery,
            not_before,
        } => {
            if event.kind != "deletion_requested" {
                return Err(integrity_failure());
            }
            Ok(SnapshotRecord {
                state: "deletion_pending",
                requested_at: Some(event.occurred_at),
                not_before: Some(not_before),
                recovery_state: Some(recovery_label(recovery)),
            })
        }
    }
}

const fn simple_snapshot(state: &'static str) -> SnapshotRecord {
    SnapshotRecord {
        state,
        requested_at: None,
        not_before: None,
        recovery_state: None,
    }
}

fn validate_history_identity(
    persisted: &PersistedLifecycle<'_>,
    identity: &TransitionIdentity,
    expected_version: UserVersion,
) -> Result<(), StorageError> {
    let valid = &persisted.tenant_id == identity.tenant_id()
        && &persisted.user_id == identity.user_id()
        && persisted.version == expected_version;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn next_history_version(version: UserVersion) -> Result<UserVersion, StorageError> {
    version.next().map_err(|_| integrity_failure())
}

fn target_history_state(identity: &TransitionIdentity) -> Result<HistoryState, StorageError> {
    let target = state_from_snapshot_record(identity.snapshot())?;
    let event = HistoryEvent::from_record(identity.new_version(), identity.lifecycle());
    state_after_target_event(event, target)
}

fn state_after_target_event(
    event: HistoryEvent<'_>,
    target: HistoryState,
) -> Result<HistoryState, StorageError> {
    let valid = match event.kind {
        "activated" => target_is_active(target) && target_activation_is_valid(event),
        "suspended" => target_is_suspended(target) && target_suspension_is_valid(event),
        "resumed" => target_is_active(target) && target_resume_is_valid(event),
        "deletion_requested" => target_pending_is_valid(target, event),
        "deletion_recovered" => target_recovery_is_valid(target, event),
        "deleted" => target_is_deleted(target) && target_deleted_is_valid(event),
        _ => false,
    };
    require_event(valid, target)
}

fn target_activation_is_valid(event: HistoryEvent<'_>) -> bool {
    event.version.get() == 2 && has_no_metadata(event)
}

fn target_suspension_is_valid(event: HistoryEvent<'_>) -> bool {
    version_is_odd(event.version) && has_no_metadata(event)
}

fn target_resume_is_valid(event: HistoryEvent<'_>) -> bool {
    version_is_even(event.version) && event.version.get() >= 4 && has_no_metadata(event)
}

fn target_pending_is_valid(target: HistoryState, event: HistoryEvent<'_>) -> bool {
    let HistoryState::DeletionPending {
        recovery,
        not_before,
    } = target
    else {
        return false;
    };
    let Some(event_not_before) = event.not_before else {
        return false;
    };
    event.kind == "deletion_requested"
        && event_not_before == not_before
        && event.occurred_at < event_not_before
        && event.recovery_state == Some(recovery_label(recovery))
        && pending_version_matches(event.version, recovery)
}

fn target_recovery_is_valid(target: HistoryState, event: HistoryEvent<'_>) -> bool {
    let recovery = match target {
        HistoryState::Active => HistoryRecovery::Active,
        HistoryState::Suspended => HistoryRecovery::Suspended,
        _ => return false,
    };
    event.not_before.is_none()
        && event.recovery_state == Some(recovery_label(recovery))
        && recovered_version_matches(event.version, recovery)
}

fn target_deleted_is_valid(event: HistoryEvent<'_>) -> bool {
    has_no_metadata(event)
}

fn advance_history(
    state: HistoryState,
    event: HistoryEvent<'_>,
) -> Result<HistoryState, StorageError> {
    match state {
        HistoryState::Invited => advance_invited(event),
        HistoryState::Active => advance_active(event),
        HistoryState::Suspended => advance_suspended(event),
        HistoryState::DeletionPending {
            recovery,
            not_before,
        } => advance_pending(event, recovery, not_before),
        HistoryState::Deleted => Err(integrity_failure()),
    }
}

fn advance_invited(event: HistoryEvent<'_>) -> Result<HistoryState, StorageError> {
    require_event(
        event.kind == "activated" && event.version.get() == 2 && has_no_metadata(event),
        HistoryState::Active,
    )
}

fn advance_active(event: HistoryEvent<'_>) -> Result<HistoryState, StorageError> {
    match event.kind {
        "suspended" => require_event(
            version_is_odd(event.version) && has_no_metadata(event),
            HistoryState::Suspended,
        ),
        "deletion_requested" => require_pending_event(event, HistoryRecovery::Active),
        _ => Err(integrity_failure()),
    }
}

fn advance_suspended(event: HistoryEvent<'_>) -> Result<HistoryState, StorageError> {
    match event.kind {
        "resumed" => require_event(
            version_is_even(event.version) && has_no_metadata(event),
            HistoryState::Active,
        ),
        "deletion_requested" => require_pending_event(event, HistoryRecovery::Suspended),
        _ => Err(integrity_failure()),
    }
}

fn advance_pending(
    event: HistoryEvent<'_>,
    recovery: HistoryRecovery,
    not_before: i64,
) -> Result<HistoryState, StorageError> {
    match event.kind {
        "deletion_recovered" => require_recovery_event(event, recovery),
        "deleted" => require_deleted_after_boundary(event, not_before),
        _ => Err(integrity_failure()),
    }
}

fn require_pending_event(
    event: HistoryEvent<'_>,
    recovery: HistoryRecovery,
) -> Result<HistoryState, StorageError> {
    let Some(not_before) = event.not_before else {
        return Err(integrity_failure());
    };
    let valid = event.recovery_state == Some(recovery_label(recovery))
        && not_before > event.occurred_at
        && pending_version_matches(event.version, recovery);
    require_event(
        valid,
        HistoryState::DeletionPending {
            recovery,
            not_before,
        },
    )
}

fn require_recovery_event(
    event: HistoryEvent<'_>,
    recovery: HistoryRecovery,
) -> Result<HistoryState, StorageError> {
    let valid = event.not_before.is_none()
        && event.recovery_state == Some(recovery_label(recovery))
        && recovered_version_matches(event.version, recovery);
    require_event(valid, state_for_recovery(recovery))
}

fn require_deleted_after_boundary(
    event: HistoryEvent<'_>,
    not_before: i64,
) -> Result<HistoryState, StorageError> {
    if event.occurred_at < not_before {
        return Err(integrity_failure());
    }
    target_deleted(event)
}

fn target_deleted(event: HistoryEvent<'_>) -> Result<HistoryState, StorageError> {
    require_event(has_no_metadata(event), HistoryState::Deleted)
}

fn require_event(valid: bool, state: HistoryState) -> Result<HistoryState, StorageError> {
    if valid {
        Ok(state)
    } else {
        Err(integrity_failure())
    }
}

fn state_from_snapshot_record(snapshot: SnapshotRecord) -> Result<HistoryState, StorageError> {
    match snapshot.state {
        "invited" => Ok(HistoryState::Invited),
        "active" => Ok(HistoryState::Active),
        "suspended" => Ok(HistoryState::Suspended),
        "deletion_pending" => {
            let Some(not_before) = snapshot.not_before else {
                return Err(integrity_failure());
            };
            let recovery = decode_history_recovery(snapshot.recovery_state)?;
            Ok(HistoryState::DeletionPending {
                recovery,
                not_before,
            })
        }
        "deleted" => Ok(HistoryState::Deleted),
        _ => Err(integrity_failure()),
    }
}

fn validate_terminal_history_state(
    state: HistoryState,
    snapshot: UserSnapshotState,
) -> Result<(), StorageError> {
    if state == state_from_user_snapshot(snapshot) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn state_from_user_snapshot(snapshot: UserSnapshotState) -> HistoryState {
    match snapshot {
        UserSnapshotState::Invited => HistoryState::Invited,
        UserSnapshotState::Active => HistoryState::Active,
        UserSnapshotState::Suspended => HistoryState::Suspended,
        UserSnapshotState::DeletionPending {
            not_before,
            recovery_state,
            ..
        } => HistoryState::DeletionPending {
            recovery: match recovery_state {
                DeletionRecoveryState::Active => HistoryRecovery::Active,
                DeletionRecoveryState::Suspended => HistoryRecovery::Suspended,
            },
            not_before: not_before.timestamp().unix_seconds(),
        },
        UserSnapshotState::Deleted => HistoryState::Deleted,
    }
}

fn decode_history_recovery(value: Option<&str>) -> Result<HistoryRecovery, StorageError> {
    match value {
        Some("active") => Ok(HistoryRecovery::Active),
        Some("suspended") => Ok(HistoryRecovery::Suspended),
        _ => Err(integrity_failure()),
    }
}

fn state_for_recovery(recovery: HistoryRecovery) -> HistoryState {
    match recovery {
        HistoryRecovery::Active => HistoryState::Active,
        HistoryRecovery::Suspended => HistoryState::Suspended,
    }
}

fn target_is_active(state: HistoryState) -> bool {
    matches!(state, HistoryState::Active)
}

fn target_is_suspended(state: HistoryState) -> bool {
    matches!(state, HistoryState::Suspended)
}

fn target_is_deleted(state: HistoryState) -> bool {
    matches!(state, HistoryState::Deleted)
}

fn has_no_metadata(event: HistoryEvent<'_>) -> bool {
    event.not_before.is_none() && event.recovery_state.is_none()
}

fn pending_version_matches(version: UserVersion, recovery: HistoryRecovery) -> bool {
    match recovery {
        HistoryRecovery::Active => version_is_odd(version),
        HistoryRecovery::Suspended => version_is_even(version),
    }
}

fn recovered_version_matches(version: UserVersion, recovery: HistoryRecovery) -> bool {
    match recovery {
        HistoryRecovery::Active => version_is_even(version),
        HistoryRecovery::Suspended => version_is_odd(version),
    }
}

fn recovery_label(recovery: HistoryRecovery) -> &'static str {
    match recovery {
        HistoryRecovery::Active => "active",
        HistoryRecovery::Suspended => "suspended",
    }
}

fn version_is_even(version: UserVersion) -> bool {
    version.get().is_multiple_of(2)
}

fn version_is_odd(version: UserVersion) -> bool {
    !version_is_even(version)
}

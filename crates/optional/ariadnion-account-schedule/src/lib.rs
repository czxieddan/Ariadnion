// crates/optional/ariadnion-account-schedule/src/lib.rs - Account schedule contracts for Ariadnion.
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
//! Versioned account availability and maintenance schedules.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ariadnion_account_domain::AccountId;
use std::fmt;
use std::sync::{Arc, RwLock};

const SECONDS_PER_DAY: u64 = 86_400;
const MINUTES_PER_DAY: u16 = 1_440;
const MAX_OFFSET_MINUTES: i32 = 1_440;
const MAX_WEEKLY_WINDOWS: usize = 128;
const MAX_MAINTENANCE_WINDOWS: usize = 128;
const MAX_SCHEDULES: usize = 100_000;

/// Stable machine-readable schedule failure codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ScheduleErrorCode {
    /// An argument is malformed or outside its bound.
    InvalidArgument,
    /// A schedule or window collection exceeds its fixed bound.
    LimitExceeded,
    /// An account or window identity appears more than once.
    DuplicateAccount,
    /// A weekly or maintenance window is duplicated.
    DuplicateWindow,
    /// Publication used a stale snapshot version.
    VersionConflict,
    /// A version or timestamp cannot advance safely.
    VersionExhausted,
    /// The authoritative schedule state is unavailable.
    StateUnavailable,
}

impl ScheduleErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ACCOUNT_SCHEDULE_INVALID_ARGUMENT",
            Self::LimitExceeded => "ACCOUNT_SCHEDULE_LIMIT_EXCEEDED",
            Self::DuplicateAccount => "ACCOUNT_SCHEDULE_DUPLICATE_ACCOUNT",
            Self::DuplicateWindow => "ACCOUNT_SCHEDULE_DUPLICATE_WINDOW",
            Self::VersionConflict => "ACCOUNT_SCHEDULE_VERSION_CONFLICT",
            Self::VersionExhausted => "ACCOUNT_SCHEDULE_VERSION_EXHAUSTED",
            Self::StateUnavailable => "ACCOUNT_SCHEDULE_STATE_UNAVAILABLE",
        }
    }
}

impl fmt::Display for ScheduleErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted schedule failure containing only its stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduleError {
    code: ScheduleErrorCode,
}

impl ScheduleError {
    const fn new(code: ScheduleErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ScheduleErrorCode {
        self.code
    }
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ScheduleError {}

/// Version of an immutable published schedule snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScheduleVersion(u64);

impl ScheduleVersion {
    /// Returns the empty snapshot version.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Reconstructs a version from durable state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, ScheduleError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(ScheduleErrorCode::VersionExhausted))
    }
}

/// UTC Unix time in whole seconds.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcSeconds(u64);

impl UtcSeconds {
    /// Creates a UTC Unix timestamp.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Fixed local UTC offset in whole minutes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocalOffsetMinutes(i32);

impl LocalOffsetMinutes {
    /// Creates a bounded signed UTC offset.
    ///
    /// # Errors
    /// Returns [`ScheduleErrorCode::InvalidArgument`] outside ±24 hours.
    pub fn new(value: i32) -> Result<Self, ScheduleError> {
        if !(-MAX_OFFSET_MINUTES..=MAX_OFFSET_MINUTES).contains(&value) {
            Err(error(ScheduleErrorCode::InvalidArgument))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the offset in signed minutes.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

/// Day of week used by a weekly availability window.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Weekday {
    /// Monday.
    Monday,
    /// Tuesday.
    Tuesday,
    /// Wednesday.
    Wednesday,
    /// Thursday.
    Thursday,
    /// Friday.
    Friday,
    /// Saturday.
    Saturday,
    /// Sunday.
    Sunday,
}

impl Weekday {
    fn from_unix_day(day: u64) -> Self {
        match ((day + 3) % 7) as u8 {
            0 => Self::Monday,
            1 => Self::Tuesday,
            2 => Self::Wednesday,
            3 => Self::Thursday,
            4 => Self::Friday,
            5 => Self::Saturday,
            _ => Self::Sunday,
        }
    }
}

/// A local wall-clock minute, with 1,440 reserved for an exclusive day end.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MinuteOfDay(u16);

impl MinuteOfDay {
    /// Creates a minute in the inclusive range `0..=1440`.
    ///
    /// # Errors
    /// Returns [`ScheduleErrorCode::InvalidArgument`] above the day boundary.
    pub fn new(value: u16) -> Result<Self, ScheduleError> {
        if value > MINUTES_PER_DAY {
            Err(error(ScheduleErrorCode::InvalidArgument))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the minute value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A half-open weekly local-time availability window.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScheduleWindow {
    weekday: Weekday,
    start: MinuteOfDay,
    end: MinuteOfDay,
}

impl ScheduleWindow {
    /// Creates a window `[start, end)` on one local weekday.
    ///
    /// # Errors
    /// Returns [`ScheduleErrorCode::InvalidArgument`] for an empty or reversed
    /// interval.
    pub fn new(
        weekday: Weekday,
        start: MinuteOfDay,
        end: MinuteOfDay,
    ) -> Result<Self, ScheduleError> {
        if start >= end {
            return Err(error(ScheduleErrorCode::InvalidArgument));
        }
        Ok(Self {
            weekday,
            start,
            end,
        })
    }

    /// Returns the local weekday.
    #[must_use]
    pub const fn weekday(self) -> Weekday {
        self.weekday
    }

    /// Returns the inclusive local start minute.
    #[must_use]
    pub const fn start(self) -> MinuteOfDay {
        self.start
    }

    /// Returns the exclusive local end minute.
    #[must_use]
    pub const fn end(self) -> MinuteOfDay {
        self.end
    }

    fn contains(self, weekday: Weekday, minute: u16) -> bool {
        self.weekday == weekday && self.start.0 <= minute && minute < self.end.0
    }
}

/// A half-open UTC maintenance interval that overrides weekly availability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MaintenanceWindow {
    start: UtcSeconds,
    end: UtcSeconds,
}

impl MaintenanceWindow {
    /// Creates a UTC interval `[start, end)`.
    ///
    /// # Errors
    /// Returns [`ScheduleErrorCode::InvalidArgument`] for an empty or reversed
    /// interval.
    pub fn new(start: UtcSeconds, end: UtcSeconds) -> Result<Self, ScheduleError> {
        if start >= end {
            return Err(error(ScheduleErrorCode::InvalidArgument));
        }
        Ok(Self { start, end })
    }

    /// Returns the UTC start boundary.
    #[must_use]
    pub const fn start(self) -> UtcSeconds {
        self.start
    }

    /// Returns the UTC exclusive end boundary.
    #[must_use]
    pub const fn end(self) -> UtcSeconds {
        self.end
    }

    fn contains(self, timestamp: UtcSeconds) -> bool {
        self.start <= timestamp && timestamp < self.end
    }
}

/// Immutable availability and maintenance policy for one account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSchedule {
    account_id: AccountId,
    offset: LocalOffsetMinutes,
    weekly_windows: Arc<[ScheduleWindow]>,
    maintenance_windows: Arc<[MaintenanceWindow]>,
}

impl AccountSchedule {
    /// Creates a normalized, bounded account schedule.
    ///
    /// Weekly windows are sorted by weekday and start minute. Maintenance
    /// windows are sorted by UTC start. Exact duplicate windows are rejected.
    ///
    /// # Errors
    /// Returns a stable bound or duplicate error.
    pub fn new(
        account_id: AccountId,
        offset: LocalOffsetMinutes,
        mut weekly_windows: Vec<ScheduleWindow>,
        mut maintenance_windows: Vec<MaintenanceWindow>,
    ) -> Result<Self, ScheduleError> {
        if weekly_windows.len() > MAX_WEEKLY_WINDOWS
            || maintenance_windows.len() > MAX_MAINTENANCE_WINDOWS
        {
            return Err(error(ScheduleErrorCode::LimitExceeded));
        }
        weekly_windows.sort_unstable();
        if weekly_windows.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(error(ScheduleErrorCode::DuplicateWindow));
        }
        maintenance_windows.sort_unstable();
        if maintenance_windows
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(error(ScheduleErrorCode::DuplicateWindow));
        }
        Ok(Self {
            account_id,
            offset,
            weekly_windows: Arc::from(weekly_windows.into_boxed_slice()),
            maintenance_windows: Arc::from(maintenance_windows.into_boxed_slice()),
        })
    }

    /// Returns the scheduled account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the fixed local UTC offset.
    #[must_use]
    pub const fn offset(&self) -> LocalOffsetMinutes {
        self.offset
    }

    /// Returns normalized weekly availability windows.
    #[must_use]
    pub fn weekly_windows(&self) -> &[ScheduleWindow] {
        &self.weekly_windows
    }

    /// Returns normalized UTC maintenance windows.
    #[must_use]
    pub fn maintenance_windows(&self) -> &[MaintenanceWindow] {
        &self.maintenance_windows
    }

    /// Reports whether an account is available at a UTC instant.
    ///
    /// Maintenance intervals take precedence over weekly windows. The fixed
    /// offset avoids hidden host-time-zone or daylight-saving dependencies.
    ///
    /// # Errors
    /// Returns [`ScheduleErrorCode::VersionExhausted`] when applying the offset
    /// would overflow the bounded UTC representation.
    pub fn is_available_at(&self, timestamp: UtcSeconds) -> Result<bool, ScheduleError> {
        if self
            .maintenance_windows
            .iter()
            .copied()
            .any(|window| window.contains(timestamp))
        {
            return Ok(false);
        }
        let local_seconds = shift_utc(timestamp, self.offset)?;
        let day = local_seconds / SECONDS_PER_DAY;
        let minute = ((local_seconds % SECONDS_PER_DAY) / 60) as u16;
        let weekday = Weekday::from_unix_day(day);
        Ok(self
            .weekly_windows
            .iter()
            .copied()
            .any(|window| window.contains(weekday, minute)))
    }
}

/// An immutable, sorted set of account schedules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleSnapshot {
    version: ScheduleVersion,
    schedules: Arc<[AccountSchedule]>,
}

impl ScheduleSnapshot {
    fn new(
        version: ScheduleVersion,
        mut schedules: Vec<AccountSchedule>,
    ) -> Result<Self, ScheduleError> {
        if schedules.len() > MAX_SCHEDULES {
            return Err(error(ScheduleErrorCode::LimitExceeded));
        }
        schedules.sort_unstable_by(|left, right| left.account_id.cmp(&right.account_id));
        if schedules
            .windows(2)
            .any(|pair| pair[0].account_id == pair[1].account_id)
        {
            return Err(error(ScheduleErrorCode::DuplicateAccount));
        }
        Ok(Self {
            version,
            schedules: Arc::from(schedules.into_boxed_slice()),
        })
    }

    /// Returns the immutable snapshot version.
    #[must_use]
    pub const fn version(&self) -> ScheduleVersion {
        self.version
    }

    /// Returns account schedules in canonical account-id order.
    #[must_use]
    pub fn schedules(&self) -> &[AccountSchedule] {
        &self.schedules
    }

    /// Finds one account schedule by identity.
    #[must_use]
    pub fn schedule_for(&self, account_id: &AccountId) -> Option<&AccountSchedule> {
        self.schedules
            .binary_search_by(|schedule| schedule.account_id.cmp(account_id))
            .ok()
            .map(|index| &self.schedules[index])
    }
}

/// Receipt returned after an atomic schedule publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleReceipt {
    version: ScheduleVersion,
    snapshot: Arc<ScheduleSnapshot>,
}

impl ScheduleReceipt {
    /// Returns the newly published version.
    #[must_use]
    pub const fn version(&self) -> ScheduleVersion {
        self.version
    }

    /// Returns the immutable published snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ScheduleSnapshot> {
        Arc::clone(&self.snapshot)
    }
}

/// Read-only schedule snapshot port for routing consumers.
pub trait SchedulePort: Send + Sync {
    /// Returns the latest complete immutable schedule snapshot.
    ///
    /// # Errors
    /// Returns [`ScheduleErrorCode::StateUnavailable`] when the implementation
    /// cannot read its authoritative state.
    fn current_snapshot(&self) -> Result<Arc<ScheduleSnapshot>, ScheduleError>;
}

/// Concurrent schedule publisher with generation-checked atomic replacement.
#[derive(Debug)]
pub struct ScheduleBook {
    snapshot: RwLock<Arc<ScheduleSnapshot>>,
}

impl Default for ScheduleBook {
    fn default() -> Self {
        Self::new()
    }
}

impl ScheduleBook {
    /// Creates an empty schedule book at version zero.
    #[must_use]
    pub fn new() -> Self {
        let snapshot = ScheduleSnapshot {
            version: ScheduleVersion::initial(),
            schedules: Arc::from(Vec::<AccountSchedule>::new().into_boxed_slice()),
        };
        Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
        }
    }

    /// Publishes a complete schedule set after an exact-version check.
    ///
    /// Input validation and sorting complete before the authoritative pointer
    /// is replaced. Readers therefore retain either the old or the new snapshot.
    ///
    /// # Errors
    /// Returns a stable validation, stale-version, overflow, or state error.
    pub fn publish(
        &self,
        expected_version: ScheduleVersion,
        schedules: Vec<AccountSchedule>,
    ) -> Result<ScheduleReceipt, ScheduleError> {
        let mut current = self
            .snapshot
            .write()
            .map_err(|_| error(ScheduleErrorCode::StateUnavailable))?;
        if current.version() != expected_version {
            return Err(error(ScheduleErrorCode::VersionConflict));
        }
        let version = expected_version.next()?;
        let next = Arc::new(ScheduleSnapshot::new(version, schedules)?);
        *current = Arc::clone(&next);
        Ok(ScheduleReceipt {
            version,
            snapshot: next,
        })
    }
}

impl SchedulePort for ScheduleBook {
    fn current_snapshot(&self) -> Result<Arc<ScheduleSnapshot>, ScheduleError> {
        self.snapshot
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| error(ScheduleErrorCode::StateUnavailable))
    }
}

fn shift_utc(timestamp: UtcSeconds, offset: LocalOffsetMinutes) -> Result<u64, ScheduleError> {
    let magnitude = u64::from(offset.0.unsigned_abs())
        .checked_mul(60)
        .ok_or_else(|| error(ScheduleErrorCode::VersionExhausted))?;
    if offset.0 >= 0 {
        timestamp
            .0
            .checked_add(magnitude)
            .ok_or_else(|| error(ScheduleErrorCode::VersionExhausted))
    } else {
        timestamp
            .0
            .checked_sub(magnitude)
            .ok_or_else(|| error(ScheduleErrorCode::InvalidArgument))
    }
}

const fn error(code: ScheduleErrorCode) -> ScheduleError {
    ScheduleError::new(code)
}

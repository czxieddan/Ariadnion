// crates/optional/ariadnion-account-domain/src/lib.rs - Account domain contracts for Ariadnion.
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
//! Strongly typed provider-account metadata, configuration, and lifecycle state.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::num::{NonZeroU32, NonZeroU64};

use ariadnion_core::TenantId;

const MAX_ID_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 160;
const MAX_SECRET_PATH_BYTES: usize = 512;

/// Maximum persisted relative routing weight.
pub const MAX_ROUTING_WEIGHT: u32 = 1 << 20;

/// Stable machine-readable failures returned by account-domain operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AccountDomainErrorCode {
    /// A value is empty, malformed, or outside its documented bound.
    InvalidArgument,
    /// The command was based on a stale account version.
    VersionConflict,
    /// An account version cannot advance without wrapping.
    VersionExhausted,
    /// A configuration version is not the required successor.
    ConfigVersionConflict,
    /// The requested lifecycle transition is not valid from the current state.
    InvalidTransition,
    /// A terminal account received another lifecycle command.
    DeletedTerminal,
}

impl AccountDomainErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ACCOUNT_INVALID_ARGUMENT",
            Self::VersionConflict => "ACCOUNT_VERSION_CONFLICT",
            Self::VersionExhausted => "ACCOUNT_VERSION_EXHAUSTED",
            Self::ConfigVersionConflict => "ACCOUNT_CONFIG_VERSION_CONFLICT",
            Self::InvalidTransition => "ACCOUNT_INVALID_TRANSITION",
            Self::DeletedTerminal => "ACCOUNT_DELETED_TERMINAL",
        }
    }
}

/// A redacted account-domain failure that never retains rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountDomainError {
    code: AccountDomainErrorCode,
}

impl AccountDomainError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: AccountDomainErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> AccountDomainErrorCode {
        self.code
    }
}

impl Display for AccountDomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AccountDomainError {}

macro_rules! bounded_id {
    ($name:ident, $doc:literal, $debug:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses a non-empty ASCII identity of at most 128 bytes.
            ///
            /// # Errors
            /// Returns [`AccountDomainErrorCode::InvalidArgument`] when the
            /// identity is empty, too long, non-ASCII, or contains a disallowed byte.
            pub fn parse(value: &str) -> Result<Self, AccountDomainError> {
                if !valid_id(value) {
                    return Err(error(AccountDomainErrorCode::InvalidArgument));
                }
                Ok(Self(value.into()))
            }

            /// Returns the validated identity.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($debug, "(<opaque>)"))
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

bounded_id!(
    AccountId,
    "A bounded provider-account identity.",
    "AccountId"
);
bounded_id!(ProviderId, "A bounded provider identity.", "ProviderId");
bounded_id!(
    SecretProvider,
    "A bounded secret-provider identity.",
    "SecretProvider"
);
bounded_id!(
    SecretPurpose,
    "A bounded purpose for a secret reference.",
    "SecretPurpose"
);

macro_rules! bounded_text {
    ($name:ident, $doc:literal, $debug:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses a bounded visible ASCII label.
            ///
            /// # Errors
            /// Returns [`AccountDomainErrorCode::InvalidArgument`] for empty,
            /// oversized, non-ASCII, or control-containing values.
            pub fn parse(value: &str) -> Result<Self, AccountDomainError> {
                if !valid_text(value, MAX_LABEL_BYTES) {
                    return Err(error(AccountDomainErrorCode::InvalidArgument));
                }
                Ok(Self(value.into()))
            }

            /// Returns the validated text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($debug, "(<opaque>)"))
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

bounded_text!(
    ProviderLabel,
    "A bounded provider display label.",
    "ProviderLabel"
);
bounded_text!(
    AccountLabel,
    "A bounded account display label.",
    "AccountLabel"
);
bounded_text!(
    ExternalAccountId,
    "A bounded provider-side account identity.",
    "ExternalAccountId"
);
bounded_text!(ModelName, "A bounded provider model selector.", "ModelName");

/// A bounded path within an external secret manager.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretPath(Box<str>);

impl SecretPath {
    /// Parses a non-empty secret-manager path without retaining secret material.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] for empty, oversized,
    /// non-ASCII, or control-containing paths.
    pub fn parse(value: &str) -> Result<Self, AccountDomainError> {
        if !valid_text(value, MAX_SECRET_PATH_BYTES) {
            return Err(error(AccountDomainErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated path to the external secret.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for SecretPath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPath(<redacted>)")
    }
}

impl Display for SecretPath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// A non-zero immutable account aggregate version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountVersion(NonZeroU64);

impl AccountVersion {
    /// Returns the version assigned to a newly provisioned account.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero account version.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, AccountDomainError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(AccountDomainErrorCode::InvalidArgument))
    }

    /// Returns the numeric account version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic account version.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, AccountDomainError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AccountDomainErrorCode::VersionExhausted))
    }
}

/// A non-zero immutable account-configuration version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountConfigVersion(NonZeroU64);

impl AccountConfigVersion {
    /// Returns the first configuration version.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Creates a non-zero configuration version.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, AccountDomainError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(AccountDomainErrorCode::InvalidArgument))
    }

    /// Returns the numeric configuration version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next monotonic configuration version.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::VersionExhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, AccountDomainError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(AccountDomainErrorCode::VersionExhausted))
    }
}

/// A UTC instant represented as signed seconds from the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountUtcTimestamp(i64);

impl AccountUtcTimestamp {
    /// Creates a UTC instant from signed Unix seconds.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Returns signed seconds from the Unix epoch.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }
}

/// Optional half-open UTC interval in which an account configuration is effective.
///
/// A missing start or end leaves that side unbounded. The start is inclusive and
/// the end is exclusive. The fully unbounded default preserves legacy behavior.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AccountEffectiveWindow {
    effective_start: Option<AccountUtcTimestamp>,
    effective_end: Option<AccountUtcTimestamp>,
}

impl AccountEffectiveWindow {
    /// The fully unbounded interval used when no effective boundaries are configured.
    pub const OPEN: Self = Self {
        effective_start: None,
        effective_end: None,
    };

    /// Creates a validated optional effective interval.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] when both boundaries
    /// exist and the start is not strictly earlier than the end.
    pub fn new(
        effective_start: Option<AccountUtcTimestamp>,
        effective_end: Option<AccountUtcTimestamp>,
    ) -> Result<Self, AccountDomainError> {
        if matches!((effective_start, effective_end), (Some(start), Some(end)) if start >= end) {
            return Err(error(AccountDomainErrorCode::InvalidArgument));
        }
        Ok(Self {
            effective_start,
            effective_end,
        })
    }

    /// Returns the inclusive effective-start boundary when configured.
    #[must_use]
    pub const fn effective_start(self) -> Option<AccountUtcTimestamp> {
        self.effective_start
    }

    /// Returns the exclusive effective-end boundary when configured.
    #[must_use]
    pub const fn effective_end(self) -> Option<AccountUtcTimestamp> {
        self.effective_end
    }

    /// Reports whether the supplied UTC instant is inside the half-open interval.
    #[must_use]
    pub fn is_effective_at(self, observed_at: AccountUtcTimestamp) -> bool {
        self.effective_start
            .is_none_or(|start| observed_at >= start)
            && self.effective_end.is_none_or(|end| observed_at < end)
    }
}

impl Default for AccountEffectiveWindow {
    fn default() -> Self {
        Self::OPEN
    }
}

/// Persisted routing priority where lower numeric values are preferred.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoutingPriority(u16);

impl RoutingPriority {
    /// Default priority used by legacy account configuration.
    pub const DEFAULT: Self = Self(0);

    /// Creates a routing priority.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric priority.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for RoutingPriority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Persisted relative routing weight.
///
/// Zero is retained as an explicit policy exclusion rather than being
/// normalized to the default weight.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoutingWeight(u32);

impl RoutingWeight {
    /// Default weight used by legacy account configuration.
    pub const DEFAULT: Self = Self(1);

    /// Creates a routing weight within the binary persisted bound.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] when `value` exceeds
    /// [`MAX_ROUTING_WEIGHT`]. Zero is accepted for explicit policy exclusion.
    pub const fn new(value: u32) -> Result<Self, AccountDomainError> {
        if value > MAX_ROUTING_WEIGHT {
            Err(error(AccountDomainErrorCode::InvalidArgument))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric weight.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for RoutingWeight {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A version of a secret material reference, never the secret itself.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretVersion(NonZeroU64);

impl SecretVersion {
    /// Creates a non-zero secret version.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] for zero.
    pub fn new(value: u64) -> Result<Self, AccountDomainError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| error(AccountDomainErrorCode::InvalidArgument))
    }

    /// Returns the numeric secret version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A capability-neutral pointer to secret material held by another system.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SecretRef {
    provider: SecretProvider,
    path: SecretPath,
    version: SecretVersion,
    purpose: SecretPurpose,
}

impl SecretRef {
    /// Creates a reference containing provider, path, version, and purpose only.
    ///
    /// The constructor never accepts or stores secret bytes, tokens, or plaintext
    /// credentials. The caller remains responsible for authorizing access to the
    /// referenced external secret.
    #[must_use]
    pub const fn new(
        provider: SecretProvider,
        path: SecretPath,
        version: SecretVersion,
        purpose: SecretPurpose,
    ) -> Self {
        Self {
            provider,
            path,
            version,
            purpose,
        }
    }

    /// Returns the external secret-provider identity.
    #[must_use]
    pub const fn provider(&self) -> &SecretProvider {
        &self.provider
    }

    /// Returns the external path, without exposing it through formatting.
    #[must_use]
    pub const fn path(&self) -> &SecretPath {
        &self.path
    }

    /// Returns the external secret version.
    #[must_use]
    pub const fn version(&self) -> SecretVersion {
        self.version
    }

    /// Returns the intended use of the secret.
    #[must_use]
    pub const fn purpose(&self) -> &SecretPurpose {
        &self.purpose
    }
}

impl Debug for SecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRef")
            .field("provider", &"<redacted>")
            .field("path", &"<redacted>")
            .field("version", &self.version)
            .field("purpose", &"<redacted>")
            .finish()
    }
}

/// Provider metadata required to identify and display an upstream service.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProviderMetadata {
    id: ProviderId,
    label: ProviderLabel,
}

impl ProviderMetadata {
    /// Creates validated provider metadata.
    #[must_use]
    pub const fn new(id: ProviderId, label: ProviderLabel) -> Self {
        Self { id, label }
    }

    /// Returns the stable provider identity.
    #[must_use]
    pub const fn id(&self) -> &ProviderId {
        &self.id
    }

    /// Returns the display label.
    #[must_use]
    pub const fn label(&self) -> &ProviderLabel {
        &self.label
    }
}

/// Account metadata independent from credentials and lifecycle state.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AccountMetadata {
    label: AccountLabel,
    external_id: Option<ExternalAccountId>,
}

impl AccountMetadata {
    /// Creates account metadata with an optional provider-side identity.
    #[must_use]
    pub const fn new(label: AccountLabel, external_id: Option<ExternalAccountId>) -> Self {
        Self { label, external_id }
    }

    /// Returns the account display label.
    #[must_use]
    pub const fn label(&self) -> &AccountLabel {
        &self.label
    }

    /// Returns the provider-side identity when one is known.
    #[must_use]
    pub const fn external_id(&self) -> Option<&ExternalAccountId> {
        self.external_id.as_ref()
    }
}

/// Versioned account behavior and credential-reference configuration.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AccountConfig {
    version: AccountConfigVersion,
    secret_ref: SecretRef,
    default_model: Option<ModelName>,
    max_concurrency: NonZeroU32,
    routing_priority: RoutingPriority,
    routing_weight: RoutingWeight,
    effective_window: AccountEffectiveWindow,
}

impl AccountConfig {
    /// Creates a validated account configuration snapshot.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] when the concurrency
    /// limit is zero.
    pub fn new(
        version: AccountConfigVersion,
        secret_ref: SecretRef,
        default_model: Option<ModelName>,
        max_concurrency: u32,
    ) -> Result<Self, AccountDomainError> {
        Self::with_routing(
            version,
            secret_ref,
            default_model,
            max_concurrency,
            RoutingPriority::default(),
            RoutingWeight::default(),
        )
    }

    /// Creates a validated account configuration with explicit routing values.
    ///
    /// The routing values are immutable parts of this configuration version.
    /// A zero weight remains observable so policy can exclude the account.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] when the concurrency
    /// limit is zero. Routing-weight validation occurs in [`RoutingWeight::new`].
    pub fn with_routing(
        version: AccountConfigVersion,
        secret_ref: SecretRef,
        default_model: Option<ModelName>,
        max_concurrency: u32,
        routing_priority: RoutingPriority,
        routing_weight: RoutingWeight,
    ) -> Result<Self, AccountDomainError> {
        let Some(max_concurrency) = NonZeroU32::new(max_concurrency) else {
            return Err(error(AccountDomainErrorCode::InvalidArgument));
        };
        Ok(Self {
            version,
            secret_ref,
            default_model,
            max_concurrency,
            routing_priority,
            routing_weight,
            effective_window: AccountEffectiveWindow::default(),
        })
    }

    /// Attaches the effective interval owned by this configuration version.
    #[must_use]
    pub const fn with_effective_window(mut self, effective_window: AccountEffectiveWindow) -> Self {
        self.effective_window = effective_window;
        self
    }

    /// Returns the configuration version.
    #[must_use]
    pub const fn version(&self) -> AccountConfigVersion {
        self.version
    }

    /// Returns the external secret reference.
    #[must_use]
    pub const fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Returns the optional default model selector.
    #[must_use]
    pub const fn default_model(&self) -> Option<&ModelName> {
        self.default_model.as_ref()
    }

    /// Returns the bounded maximum number of concurrent operations.
    #[must_use]
    pub const fn max_concurrency(&self) -> NonZeroU32 {
        self.max_concurrency
    }

    /// Returns the persisted routing priority.
    #[must_use]
    pub const fn routing_priority(&self) -> RoutingPriority {
        self.routing_priority
    }

    /// Returns the persisted relative routing weight.
    #[must_use]
    pub const fn routing_weight(&self) -> RoutingWeight {
        self.routing_weight
    }

    /// Returns the optional half-open UTC effective interval.
    #[must_use]
    pub const fn effective_window(&self) -> AccountEffectiveWindow {
        self.effective_window
    }
}

impl Debug for AccountConfig {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountConfig")
            .field("version", &self.version)
            .field("secret_ref", &self.secret_ref)
            .field("default_model", &self.default_model)
            .field("max_concurrency", &self.max_concurrency)
            .field("routing_priority", &self.routing_priority)
            .field("routing_weight", &self.routing_weight)
            .field("effective_window", &self.effective_window)
            .finish()
    }
}

/// The complete account lifecycle state set.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AccountStatus {
    /// Credentials and metadata are being provisioned.
    Provisioning,
    /// The account may be selected for provider operations.
    Active,
    /// New provider operations are blocked but the account may resume.
    Suspended,
    /// The account is permanently disabled and may not resume.
    Revoked,
    /// The account record is terminally deleted.
    Deleted,
}

/// A requested version-checked account lifecycle change.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AccountTransitionAction {
    /// Activates a provisioning or suspended account.
    Activate,
    /// Suspends an active account.
    Suspend,
    /// Resumes a suspended account.
    Resume,
    /// Permanently revokes an account.
    Revoke,
    /// Deletes a previously revoked account.
    Delete,
}

/// A lifecycle command coupled to the caller's expected account version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AccountTransitionCommand {
    expected_version: AccountVersion,
    action: AccountTransitionAction,
}

impl AccountTransitionCommand {
    /// Creates a version-checked account lifecycle command.
    #[must_use]
    pub const fn new(expected_version: AccountVersion, action: AccountTransitionAction) -> Self {
        Self {
            expected_version,
            action,
        }
    }

    /// Returns the optimistic version required by this command.
    #[must_use]
    pub const fn expected_version(self) -> AccountVersion {
        self.expected_version
    }

    /// Returns the requested lifecycle action.
    #[must_use]
    pub const fn action(self) -> AccountTransitionAction {
        self.action
    }
}

/// The domain fact emitted by an accepted lifecycle transition.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AccountLifecycleEvent {
    account_id: AccountId,
    from: AccountStatus,
    to: AccountStatus,
    version: AccountVersion,
}

impl AccountLifecycleEvent {
    /// Returns the affected account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the state before the transition.
    #[must_use]
    pub const fn from(&self) -> AccountStatus {
        self.from
    }

    /// Returns the state after the transition.
    #[must_use]
    pub const fn to(&self) -> AccountStatus {
        self.to
    }

    /// Returns the account version assigned by the transition.
    #[must_use]
    pub const fn version(&self) -> AccountVersion {
        self.version
    }
}

/// A validated lifecycle change derived from persisted non-secret account state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountLifecycleChange {
    version: AccountVersion,
    status: AccountStatus,
    event: AccountLifecycleEvent,
}

impl AccountLifecycleChange {
    /// Returns the account version assigned by the lifecycle change.
    #[must_use]
    pub const fn version(&self) -> AccountVersion {
        self.version
    }

    /// Returns the account status assigned by the lifecycle change.
    #[must_use]
    pub const fn status(&self) -> AccountStatus {
        self.status
    }

    /// Returns the immutable lifecycle event emitted by the change.
    #[must_use]
    pub const fn event(&self) -> &AccountLifecycleEvent {
        &self.event
    }
}

/// Applies a lifecycle command to persisted non-secret account state.
///
/// This boundary lets storage adapters validate a lifecycle mutation without
/// loading account configuration or resolving secret references.
///
/// # Errors
/// Returns [`AccountDomainErrorCode::InvalidArgument`] for an impossible
/// deleted-at-initial-version snapshot, or the same stable version and
/// transition errors returned by [`Account::apply`].
pub fn apply_account_lifecycle(
    account_id: &AccountId,
    current_version: AccountVersion,
    current_status: AccountStatus,
    command: AccountTransitionCommand,
) -> Result<AccountLifecycleChange, AccountDomainError> {
    validate_lifecycle_snapshot(current_version, current_status)?;
    if command.expected_version != current_version {
        return Err(error(AccountDomainErrorCode::VersionConflict));
    }
    let status = next_status(current_status, command.action)?;
    let version = current_version.next()?;
    let event = AccountLifecycleEvent {
        account_id: account_id.clone(),
        from: current_status,
        to: status,
        version,
    };
    Ok(AccountLifecycleChange {
        version,
        status,
        event,
    })
}

/// An accepted account transition containing the new snapshot and emitted fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountTransition {
    /// The post-transition account snapshot.
    pub account: Account,
    /// The immutable lifecycle event describing the transition.
    pub event: AccountLifecycleEvent,
}

/// An immutable tenant-owned provider account aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    id: AccountId,
    tenant_id: TenantId,
    provider: ProviderMetadata,
    metadata: AccountMetadata,
    config: AccountConfig,
    version: AccountVersion,
    status: AccountStatus,
}

impl Account {
    /// Creates a newly provisioned account at version one.
    #[must_use]
    pub const fn new(
        id: AccountId,
        tenant_id: TenantId,
        provider: ProviderMetadata,
        metadata: AccountMetadata,
        config: AccountConfig,
    ) -> Self {
        Self {
            id,
            tenant_id,
            provider,
            metadata,
            config,
            version: AccountVersion::initial(),
            status: AccountStatus::Provisioning,
        }
    }

    /// Reconstructs an account from a persisted snapshot.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::InvalidArgument`] when a deleted
    /// account is supplied with an initial version.
    pub fn from_snapshot(
        id: AccountId,
        tenant_id: TenantId,
        provider: ProviderMetadata,
        metadata: AccountMetadata,
        config: AccountConfig,
        version: AccountVersion,
        status: AccountStatus,
    ) -> Result<Self, AccountDomainError> {
        validate_lifecycle_snapshot(version, status)?;
        Ok(Self {
            id,
            tenant_id,
            provider,
            metadata,
            config,
            version,
            status,
        })
    }

    /// Returns the immutable account identity.
    #[must_use]
    pub const fn id(&self) -> &AccountId {
        &self.id
    }

    /// Returns the owning tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns provider metadata.
    #[must_use]
    pub const fn provider(&self) -> &ProviderMetadata {
        &self.provider
    }

    /// Returns account metadata.
    #[must_use]
    pub const fn metadata(&self) -> &AccountMetadata {
        &self.metadata
    }

    /// Returns the active versioned account configuration.
    #[must_use]
    pub const fn config(&self) -> &AccountConfig {
        &self.config
    }

    /// Returns the optimistic account version.
    #[must_use]
    pub const fn version(&self) -> AccountVersion {
        self.version
    }

    /// Returns the current lifecycle status.
    #[must_use]
    pub const fn status(&self) -> AccountStatus {
        self.status
    }

    /// Replaces configuration using an exact successor configuration version.
    ///
    /// # Errors
    /// Returns [`AccountDomainErrorCode::ConfigVersionConflict`] when the
    /// supplied configuration is not the next version, or
    /// [`AccountDomainErrorCode::VersionExhausted`] at the numeric limit.
    pub fn replace_config(
        &self,
        expected_account_version: AccountVersion,
        config: AccountConfig,
    ) -> Result<Self, AccountDomainError> {
        if expected_account_version != self.version {
            return Err(error(AccountDomainErrorCode::VersionConflict));
        }
        let expected_config_version = self.config.version.next()?;
        if config.version != expected_config_version {
            return Err(error(AccountDomainErrorCode::ConfigVersionConflict));
        }
        Ok(Self {
            config,
            version: self.version.next()?,
            ..self.clone()
        })
    }

    /// Applies one version-checked lifecycle action.
    ///
    /// # Errors
    /// Returns a stable error for stale versions, invalid transitions, or a
    /// terminal account. No partial state is returned on failure.
    pub fn apply(
        &self,
        command: AccountTransitionCommand,
    ) -> Result<AccountTransition, AccountDomainError> {
        let change = apply_account_lifecycle(&self.id, self.version, self.status, command)?;
        let account = Self {
            status: change.status,
            version: change.version,
            ..self.clone()
        };
        Ok(AccountTransition {
            account,
            event: change.event,
        })
    }
}

fn validate_lifecycle_snapshot(
    version: AccountVersion,
    status: AccountStatus,
) -> Result<(), AccountDomainError> {
    if status == AccountStatus::Deleted && version == AccountVersion::initial() {
        return Err(error(AccountDomainErrorCode::InvalidArgument));
    }
    Ok(())
}

fn next_status(
    current: AccountStatus,
    action: AccountTransitionAction,
) -> Result<AccountStatus, AccountDomainError> {
    match action {
        AccountTransitionAction::Activate => activate_status(current),
        AccountTransitionAction::Suspend => suspend_status(current),
        AccountTransitionAction::Resume => resume_status(current),
        AccountTransitionAction::Revoke => revoke_status(current),
        AccountTransitionAction::Delete => delete_status(current),
    }
}

fn activate_status(current: AccountStatus) -> Result<AccountStatus, AccountDomainError> {
    match current {
        AccountStatus::Provisioning | AccountStatus::Suspended => Ok(AccountStatus::Active),
        AccountStatus::Deleted => Err(error(AccountDomainErrorCode::DeletedTerminal)),
        _ => Err(error(AccountDomainErrorCode::InvalidTransition)),
    }
}

fn suspend_status(current: AccountStatus) -> Result<AccountStatus, AccountDomainError> {
    match current {
        AccountStatus::Active => Ok(AccountStatus::Suspended),
        AccountStatus::Deleted => Err(error(AccountDomainErrorCode::DeletedTerminal)),
        _ => Err(error(AccountDomainErrorCode::InvalidTransition)),
    }
}

fn resume_status(current: AccountStatus) -> Result<AccountStatus, AccountDomainError> {
    match current {
        AccountStatus::Suspended => Ok(AccountStatus::Active),
        AccountStatus::Deleted => Err(error(AccountDomainErrorCode::DeletedTerminal)),
        _ => Err(error(AccountDomainErrorCode::InvalidTransition)),
    }
}

fn revoke_status(current: AccountStatus) -> Result<AccountStatus, AccountDomainError> {
    match current {
        AccountStatus::Provisioning | AccountStatus::Active | AccountStatus::Suspended => {
            Ok(AccountStatus::Revoked)
        }
        AccountStatus::Deleted => Err(error(AccountDomainErrorCode::DeletedTerminal)),
        _ => Err(error(AccountDomainErrorCode::InvalidTransition)),
    }
}

fn delete_status(current: AccountStatus) -> Result<AccountStatus, AccountDomainError> {
    match current {
        AccountStatus::Revoked => Ok(AccountStatus::Deleted),
        AccountStatus::Deleted => Err(error(AccountDomainErrorCode::DeletedTerminal)),
        _ => Err(error(AccountDomainErrorCode::InvalidTransition)),
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(is_id_byte)
}

fn is_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

fn valid_text(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.is_ascii()
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

const fn error(code: AccountDomainErrorCode) -> AccountDomainError {
    AccountDomainError::new(code)
}

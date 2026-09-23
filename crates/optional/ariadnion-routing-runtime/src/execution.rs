// crates/optional/ariadnion-routing-runtime/src/execution.rs - Final provider execution contracts for Ariadnion.
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

//! Request-scoped execution, physical disposition, and reconciliation evidence.

use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ariadnion_account_domain::{AccountId, ProviderId};
use ariadnion_account_import::{AccountCredentialReferencePort, AccountProjectionPort};
use ariadnion_account_pool::CandidateSelectionPort;
use ariadnion_account_proxy::{AccountProxyProfile, ProxyScheme};
use ariadnion_account_vault::{SecretLease, VaultPort};
use ariadnion_core::RequestContext;
use ariadnion_model_catalog::ModelCatalogPort;
use ariadnion_model_domain::ProviderModelId;
use ariadnion_routing_failover::{CandidateKey, FailureClass, StreamCommitment};
use ariadnion_routing_usage::UsageConfirmationId;

use crate::{
    CircuitProbePort, RoutingRuntimeError, RoutingRuntimeErrorCode, RuntimeMonotonicClock,
};

/// Whether the provider physically accepted a request attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalExecutionAcceptance {
    /// No provider-side execution was accepted, so admission must be released.
    NotAccepted,
    /// The provider accepted execution, so admission must be committed.
    Accepted,
}

/// Request-lifecycle interruption reported by the final provider executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderExecutionInterruption {
    /// The caller or downstream consumer cancelled the request.
    Cancelled,
    /// The overall request deadline expired during provider execution.
    DeadlineExceeded,
}

impl ProviderExecutionInterruption {
    pub(crate) const fn runtime_error_code(self) -> RoutingRuntimeErrorCode {
        match self {
            Self::Cancelled => RoutingRuntimeErrorCode::Cancelled,
            Self::DeadlineExceeded => RoutingRuntimeErrorCode::DeadlineExceeded,
        }
    }
}

/// Final provider execution disposition without response or credential data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderExecutionOutcome {
    /// The provider accepted and completed the physical attempt.
    Accepted {
        /// Whether a client-visible response byte has been emitted.
        commitment: StreamCommitment,
    },
    /// The attempt failed with an explicit physical-acceptance boundary.
    Failed {
        /// Whether the provider physically accepted the attempt.
        acceptance: PhysicalExecutionAcceptance,
        /// Whether a client-visible response byte has been emitted.
        commitment: StreamCommitment,
        /// Stable failure class used by the immutable failover plan.
        failure: FailureClass,
    },
    /// Execution stopped for request cancellation or the overall deadline.
    Interrupted {
        /// Whether the provider physically accepted the attempt.
        acceptance: PhysicalExecutionAcceptance,
        /// Whether a client-visible response byte has been emitted.
        commitment: StreamCommitment,
        /// Stable request-lifecycle reason that must never enter failover.
        interruption: ProviderExecutionInterruption,
    },
}

impl ProviderExecutionOutcome {
    /// Reports one successfully accepted physical execution.
    #[must_use]
    pub const fn accepted(commitment: StreamCommitment) -> Self {
        Self::Accepted { commitment }
    }

    /// Reports one classified failure with an explicit physical disposition.
    ///
    /// # Errors
    /// A first client-visible byte proves that physical execution was accepted;
    /// reporting otherwise returns a stable invariant error.
    pub fn failed(
        acceptance: PhysicalExecutionAcceptance,
        commitment: StreamCommitment,
        failure: FailureClass,
    ) -> Result<Self, RoutingRuntimeError> {
        validate_disposition(acceptance, commitment)?;
        Ok(Self::Failed {
            acceptance,
            commitment,
            failure,
        })
    }

    /// Reports request cancellation or overall deadline expiry during execution.
    ///
    /// Interrupted attempts never enter retry or failover. Admission is committed
    /// when the provider accepted the request and released otherwise.
    ///
    /// # Errors
    /// A first client-visible byte proves that physical execution was accepted;
    /// reporting otherwise returns a stable invariant error.
    pub fn interrupted(
        acceptance: PhysicalExecutionAcceptance,
        commitment: StreamCommitment,
        interruption: ProviderExecutionInterruption,
    ) -> Result<Self, RoutingRuntimeError> {
        validate_disposition(acceptance, commitment)?;
        Ok(Self::Interrupted {
            acceptance,
            commitment,
            interruption,
        })
    }
}

fn validate_disposition(
    acceptance: PhysicalExecutionAcceptance,
    commitment: StreamCommitment,
) -> Result<(), RoutingRuntimeError> {
    if acceptance == PhysicalExecutionAcceptance::NotAccepted
        && commitment == StreamCommitment::FirstByteSent
    {
        return Err(RoutingRuntimeError::from_code(
            RoutingRuntimeErrorCode::InvalidExecutionOutcome,
        ));
    }
    Ok(())
}

pub(crate) fn validate_execution_proxy(
    profile: Option<&AccountProxyProfile>,
) -> Result<(), RoutingRuntimeError> {
    let Some(profile) = profile else {
        return Ok(());
    };
    let endpoint = profile.endpoint();
    let supported = profile.authentication().is_none()
        && (endpoint.is_direct() || endpoint.scheme() == Some(ProxyScheme::Http));
    if !supported {
        return Err(RoutingRuntimeError::from_code(
            RoutingRuntimeErrorCode::UnsupportedProxyProfile,
        ));
    }
    Ok(())
}

pub(crate) fn with_optional_accepted(
    error: RoutingRuntimeError,
    accepted: Option<PhysicalAttemptIdentity>,
) -> RoutingRuntimeError {
    match accepted {
        Some(identity) => error.with_accepted(identity),
        None => error,
    }
}

/// One final-provider request carrying a purpose-bound short lease.
pub struct ProviderExecutionRequest {
    pub(super) candidate: CandidateKey,
    pub(super) account_id: AccountId,
    pub(super) provider_id: ProviderId,
    pub(super) provider_model: ProviderModelId,
    pub(super) proxy_profile: Option<Arc<AccountProxyProfile>>,
    pub(super) usage_confirmation: UsageConfirmationId,
    pub(super) credential: SecretLease,
}

impl ProviderExecutionRequest {
    /// Returns the selected candidate identity.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateKey {
        &self.candidate
    }

    /// Returns the selected provider account.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the selected provider.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the provider-side model selected by the catalog.
    #[must_use]
    pub const fn provider_model(&self) -> &ProviderModelId {
        &self.provider_model
    }

    /// Returns the exact proxy profile approved by the routing decision.
    ///
    /// `None` means the coordinator explicitly permitted a degraded missing
    /// proxy signal. Executors must not independently select another profile.
    #[must_use]
    pub fn proxy_profile(&self) -> Option<&AccountProxyProfile> {
        self.proxy_profile.as_deref()
    }

    /// Returns the immutable identity reserved for later usage confirmation.
    #[must_use]
    pub const fn usage_confirmation_id(&self) -> &UsageConfirmationId {
        &self.usage_confirmation
    }

    /// Borrows the provider HTTP purpose-bound plaintext lease.
    #[must_use]
    pub const fn credential(&self) -> &SecretLease {
        &self.credential
    }

    /// Consumes the request and returns the lease for final HTTP credential injection.
    #[must_use]
    pub fn into_credential(self) -> SecretLease {
        self.credential
    }
}

impl Debug for ProviderExecutionRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderExecutionRequest")
            .field("candidate", &self.candidate)
            .field("account_id", &"<redacted>")
            .field("provider_id", &"<redacted>")
            .field("provider_model", &"<redacted>")
            .field(
                "proxy_profile",
                &self.proxy_profile.as_ref().map(|_| "<configured>"),
            )
            .field("usage_confirmation", &self.usage_confirmation)
            .field("credential", &self.credential)
            .finish()
    }
}

/// Final provider boundary responsible for consuming one lease exactly once.
pub trait ProviderExecutionPort: Send + Sync {
    /// Executes one physical provider request. Every failure must explicitly
    /// state whether physical execution was accepted; ambiguous transport state
    /// must be classified as accepted so admission is never incorrectly released.
    /// Cancellation and overall request deadlines must use
    /// [`ProviderExecutionOutcome::Interrupted`] and never a retryable failure.
    fn execute<'a>(
        &'a self,
        request: ProviderExecutionRequest,
        context: &'a RequestContext,
    ) -> Pin<Box<dyn Future<Output = ProviderExecutionOutcome> + Send + 'a>>;
}

/// Injected durable state, credential, vault, circuit, and clock ports used by the runtime.
///
/// The final provider executor remains request-scoped and is supplied through
/// [`crate::RuntimeRequest`].
#[derive(Clone)]
pub struct RuntimePorts {
    pub(super) account_projection: Arc<dyn AccountProjectionPort>,
    pub(super) pool: Arc<dyn CandidateSelectionPort>,
    pub(super) models: Arc<dyn ModelCatalogPort>,
    pub(super) credentials: Arc<dyn AccountCredentialReferencePort>,
    pub(super) vault: Arc<dyn VaultPort>,
    pub(super) clock: Arc<dyn RuntimeMonotonicClock>,
    pub(super) circuit_probes: Option<Arc<dyn CircuitProbePort>>,
}

impl RuntimePorts {
    /// Groups the required typed ports without a global service container.
    ///
    #[must_use]
    pub const fn new(
        account_projection: Arc<dyn AccountProjectionPort>,
        pool: Arc<dyn CandidateSelectionPort>,
        models: Arc<dyn ModelCatalogPort>,
        credentials: Arc<dyn AccountCredentialReferencePort>,
        vault: Arc<dyn VaultPort>,
        clock: Arc<dyn RuntimeMonotonicClock>,
    ) -> Self {
        Self {
            account_projection,
            pool,
            models,
            credentials,
            vault,
            clock,
            circuit_probes: None,
        }
    }

    /// Injects the authoritative account-circuit probe owner.
    ///
    /// The owner returns `Closed` only for a currently closed circuit and
    /// otherwise issues or rejects a bounded half-open lease before credential
    /// access. A runtime without this port fails closed before credential work.
    #[must_use]
    pub fn with_circuit_probes(mut self, circuit_probes: Arc<dyn CircuitProbePort>) -> Self {
        self.circuit_probes = Some(circuit_probes);
        self
    }
}

impl Debug for RuntimePorts {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimePorts(<injected>)")
    }
}

/// Stable identity of one physically accepted provider attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct PhysicalAttemptIdentity {
    pub(super) usage_confirmation: UsageConfirmationId,
    pub(super) candidate: CandidateKey,
    pub(super) provider_id: ProviderId,
    pub(super) provider_model: ProviderModelId,
    pub(super) proxy_profile: Option<Arc<AccountProxyProfile>>,
}

impl PhysicalAttemptIdentity {
    /// Returns the identity later passed to P8 usage ingestion.
    #[must_use]
    pub const fn usage_confirmation_id(&self) -> &UsageConfirmationId {
        &self.usage_confirmation
    }

    /// Returns the accepted candidate.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateKey {
        &self.candidate
    }

    /// Returns the accepted provider.
    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the accepted provider-side model.
    #[must_use]
    pub const fn provider_model(&self) -> &ProviderModelId {
        &self.provider_model
    }

    /// Returns the proxy profile used by the physical attempt, when one was approved.
    #[must_use]
    pub fn proxy_profile(&self) -> Option<&AccountProxyProfile> {
        self.proxy_profile.as_deref()
    }
}

impl Debug for PhysicalAttemptIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhysicalAttemptIdentity")
            .field("usage_confirmation", &self.usage_confirmation)
            .field("candidate", &self.candidate)
            .field("provider", &"<redacted>")
            .field("provider_model", &"<redacted>")
            .field(
                "proxy_profile",
                &self.proxy_profile.as_ref().map(|_| "<configured>"),
            )
            .finish()
    }
}

/// Successful provider execution and all accepted attempt identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSuccess {
    pub(super) final_attempt: PhysicalAttemptIdentity,
    pub(super) accepted_attempts: Arc<[PhysicalAttemptIdentity]>,
    pub(super) commitment: StreamCommitment,
}

impl RuntimeSuccess {
    /// Returns the final successful physical attempt.
    #[must_use]
    pub const fn final_attempt(&self) -> &PhysicalAttemptIdentity {
        &self.final_attempt
    }

    /// Returns every physically accepted attempt in execution order.
    #[must_use]
    pub fn accepted_attempts(&self) -> &[PhysicalAttemptIdentity] {
        &self.accepted_attempts
    }

    /// Returns the final client-visible stream commitment.
    #[must_use]
    pub const fn commitment(&self) -> StreamCommitment {
        self.commitment
    }
}

/// Why provider execution ended without a successful attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFailureReason {
    /// The immutable retry policy required execution to stop.
    FailoverStopped,
    /// Caller-supplied attempt requests ended before another safe attempt.
    AttemptsExhausted,
}

/// Final failed provider result retaining accepted usage identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFailure {
    pub(super) reason: RuntimeFailureReason,
    pub(super) failure: FailureClass,
    pub(super) commitment: StreamCommitment,
    pub(super) accepted_attempts: Arc<[PhysicalAttemptIdentity]>,
}

impl RuntimeFailure {
    /// Returns why no further attempt was performed.
    #[must_use]
    pub const fn reason(&self) -> RuntimeFailureReason {
        self.reason
    }

    /// Returns the final classified provider failure.
    #[must_use]
    pub const fn failure(&self) -> FailureClass {
        self.failure
    }

    /// Returns the final client-visible stream commitment.
    #[must_use]
    pub const fn commitment(&self) -> StreamCommitment {
        self.commitment
    }

    /// Returns every physically accepted attempt in execution order.
    #[must_use]
    pub fn accepted_attempts(&self) -> &[PhysicalAttemptIdentity] {
        &self.accepted_attempts
    }
}

/// Final expected provider disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeOutcome {
    /// One provider attempt completed successfully.
    Succeeded(RuntimeSuccess),
    /// Provider attempts ended according to retry or capacity rules.
    Failed(RuntimeFailure),
}

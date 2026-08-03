// crates/optional/ariadnion-job-runner/src/admin.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Background projection for the initial administration slice.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_api_admin::{
    AdminCommandReceipt, AdminError, AdminErrorCode, AdminExecutionPort, AdminExecutionRequest,
};
use ariadnion_core::{CancellationToken, RequestContext, RequestId, TenantId, TraceId};
use ariadnion_principal_binding::{
    AuthenticatedPrincipalEvidence, PrincipalAuthenticatorKind, PrincipalAuthenticatorSourceId,
};

/// Maximum bytes accepted in a background lease identity.
pub const MAX_ADMIN_JOB_LEASE_ID_BYTES: usize = 128;

const SUCCEEDED_CODE: &str = "ADMIN_COMMAND_SUCCEEDED";

/// Bounded path-free lease identity used for one background delivery.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdminJobLeaseId(Box<str>);

impl AdminJobLeaseId {
    /// Parses a non-empty path-free ASCII lease identity.
    ///
    /// # Errors
    ///
    /// Returns [`AdminErrorCode::InvalidArgument`] without retaining rejected
    /// input when the value is empty, oversized, or contains unsafe bytes.
    pub fn parse(value: &str) -> Result<Self, AdminError> {
        let valid = !value.is_empty()
            && value.len() <= MAX_ADMIN_JOB_LEASE_ID_BYTES
            && value.is_ascii()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
        if !valid {
            return Err(AdminError::new(AdminErrorCode::InvalidArgument));
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated lease identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AdminJobLeaseId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminJobLeaseId(<opaque>)")
    }
}

/// One bounded background delivery with a mandatory deadline.
pub struct AdminJobEnvelope {
    lease_id: AdminJobLeaseId,
    request_id: RequestId,
    trace_id: TraceId,
    deadline: SystemTime,
    cancellation: CancellationToken,
    execution: AdminExecutionRequest,
}

impl AdminJobEnvelope {
    /// Creates a delivery without accepting tenant, principal, or role input.
    #[must_use]
    pub const fn new(
        lease_id: AdminJobLeaseId,
        request_id: RequestId,
        trace_id: TraceId,
        deadline: SystemTime,
        cancellation: CancellationToken,
        execution: AdminExecutionRequest,
    ) -> Self {
        Self {
            lease_id,
            request_id,
            trace_id,
            deadline,
            cancellation,
            execution,
        }
    }
}

/// Scheduler disposition for one administration job attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminJobDisposition {
    /// The exact command completed and has a durable receipt.
    Complete,
    /// Retry only with the same command and decision identities.
    RetrySameCommand,
    /// Reopen authoritative storage and reconcile the same command identity.
    ReconcileSameCommand,
    /// The stable failure must not be retried automatically.
    Terminal,
}

/// Stable scheduler projection for one administration job attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminJobResult {
    lease_id: AdminJobLeaseId,
    disposition: AdminJobDisposition,
    code: &'static str,
    receipt: Option<AdminCommandReceipt>,
}

impl AdminJobResult {
    fn from_result(
        lease_id: AdminJobLeaseId,
        result: Result<AdminCommandReceipt, AdminError>,
    ) -> Self {
        match result {
            Ok(receipt) => Self {
                lease_id,
                disposition: AdminJobDisposition::Complete,
                code: SUCCEEDED_CODE,
                receipt: Some(receipt),
            },
            Err(error) => Self {
                lease_id,
                disposition: disposition_for(error.code()),
                code: error.code().as_str(),
                receipt: None,
            },
        }
    }

    /// Returns the delivery lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> &AdminJobLeaseId {
        &self.lease_id
    }

    /// Returns the stable scheduler action.
    #[must_use]
    pub const fn disposition(&self) -> AdminJobDisposition {
        self.disposition
    }

    /// Returns the stable administration result code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the durable receipt only after successful execution.
    #[must_use]
    pub const fn receipt(&self) -> Option<&AdminCommandReceipt> {
        self.receipt.as_ref()
    }
}

/// Loads one managed system identity from authoritative durable state.
pub trait ManagedSystemAuthenticatorPort: Send + Sync {
    /// Loads authenticated evidence for one exact durable `System` source.
    ///
    /// Implementations must require an active authenticator link, principal
    /// binding, managed user, organization, and membership at a trusted time.
    /// Returning evidence does not authorize replay: the shared executor
    /// revalidates it, and completion of that validation is the per-request
    /// authentication linearization point before replay lookup. Revocations
    /// completed after that point affect subsequent execution attempts.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted administration error when any required fact is
    /// missing, inactive, expired, mismatched, unavailable, or malformed.
    fn authenticate(
        &self,
        tenant_id: &TenantId,
        source_id: &PrincipalAuthenticatorSourceId,
        context: &RequestContext,
    ) -> Result<AuthenticatedPrincipalEvidence, AdminError>;
}

/// Executes background administration with one durable system authenticator.
pub struct AdminJobRunner {
    executor: Arc<dyn AdminExecutionPort>,
    authenticator: Arc<dyn ManagedSystemAuthenticatorPort>,
    tenant_id: TenantId,
    source_id: PrincipalAuthenticatorSourceId,
}

impl AdminJobRunner {
    /// Creates a runner configured with one durable system-authenticator source.
    #[must_use]
    pub fn new(
        executor: Arc<dyn AdminExecutionPort>,
        authenticator: Arc<dyn ManagedSystemAuthenticatorPort>,
        tenant_id: TenantId,
        source_id: PrincipalAuthenticatorSourceId,
    ) -> Self {
        Self {
            executor,
            authenticator,
            tenant_id,
            source_id,
        }
    }

    /// Executes one delivery while retaining the caller's exact command intent.
    ///
    /// Commit-indeterminate results require a fresh storage owner before the
    /// same command identity is reconciled. The runner never invents a new
    /// command or decision identity for retry.
    #[must_use]
    pub fn run(&self, job: &AdminJobEnvelope) -> AdminJobResult {
        let context = RequestContext::new(
            job.request_id.clone(),
            job.trace_id.clone(),
            None,
            Some(job.deadline),
            job.cancellation.clone(),
        );
        let result = self.authenticate_and_execute(job, &context);
        AdminJobResult::from_result(job.lease_id.clone(), result)
    }

    fn authenticate_and_execute(
        &self,
        job: &AdminJobEnvelope,
        context: &RequestContext,
    ) -> Result<AdminCommandReceipt, AdminError> {
        let evidence =
            self.authenticator
                .authenticate(&self.tenant_id, &self.source_id, context)?;
        validate_system_evidence(&evidence, &self.tenant_id, &self.source_id)?;
        self.executor
            .execute(job.execution.clone(), &evidence, context)
    }
}

fn validate_system_evidence(
    evidence: &AuthenticatedPrincipalEvidence,
    tenant_id: &TenantId,
    source_id: &PrincipalAuthenticatorSourceId,
) -> Result<(), AdminError> {
    if evidence.tenant_id() != tenant_id
        || evidence.authenticator_kind() != PrincipalAuthenticatorKind::System
        || evidence.source_id() != source_id
    {
        return Err(AdminError::new(AdminErrorCode::Unauthenticated));
    }
    Ok(())
}

const fn disposition_for(code: AdminErrorCode) -> AdminJobDisposition {
    match code {
        AdminErrorCode::Unavailable
        | AdminErrorCode::Cancelled
        | AdminErrorCode::DeadlineExceeded => AdminJobDisposition::RetrySameCommand,
        AdminErrorCode::CommitIndeterminate => AdminJobDisposition::ReconcileSameCommand,
        _ => AdminJobDisposition::Terminal,
    }
}

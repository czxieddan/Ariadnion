//! Background projection for the initial administration slice.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_api_admin::{
    AdminCommandReceipt, AdminError, AdminErrorCode, AdminExecutionPort, AdminExecutionRequest,
};
use ariadnion_core::{CancellationToken, PrincipalContext, RequestContext, RequestId, TraceId};

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

/// Executes background administration with one trusted system principal.
pub struct AdminJobRunner {
    executor: Arc<dyn AdminExecutionPort>,
    system_principal: PrincipalContext,
}

impl AdminJobRunner {
    /// Creates a runner with a constructor-injected trusted system principal.
    #[must_use]
    pub fn new(executor: Arc<dyn AdminExecutionPort>, system_principal: PrincipalContext) -> Self {
        Self {
            executor,
            system_principal,
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
            Some(self.system_principal.clone()),
            Some(job.deadline),
            job.cancellation.clone(),
        );
        let result = self.executor.execute(job.execution.clone(), &context);
        AdminJobResult::from_result(job.lease_id.clone(), result)
    }
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

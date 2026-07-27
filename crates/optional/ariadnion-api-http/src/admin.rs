//! HTTP projection for the initial authorized administration slice.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::SystemTime;

use ariadnion_api_admin::{
    AdminActionKind, AdminCommandId, AdminCommandReceipt, AdminError, AdminErrorCode,
    AdminExecutionPort, AdminExecutionRequest, AdminTarget,
};
use ariadnion_core::{
    CancellationToken, ErrorCode, PrincipalContext, RequestContext, RequestId, TraceId,
};
use ariadnion_rbac::{DecisionId, PolicyVersion};
use ariadnion_user_domain::UserId;

/// Maximum encoded request-body size admitted by the administration adapter.
pub const MAX_ENCODED_BODY_BYTES: usize = 16 * 1024;

/// Maximum aggregate encoded header size admitted by the adapter.
pub const MAX_ENCODED_HEADER_BYTES: usize = 32 * 1024;

/// Maximum authorization field size retained during authentication.
pub const MAX_AUTHORIZATION_BYTES: usize = 8 * 1024;

const SUCCEEDED_CODE: &str = "ADMIN_COMMAND_SUCCEEDED";

/// Ephemeral bounded HTTP authorization material.
///
/// Debug output is always redacted and the owned bytes are overwritten on
/// drop. Authentication implementations must not log or retain the slice.
pub struct HttpAuthorization {
    bytes: Box<[u8]>,
}

impl HttpAuthorization {
    /// Parses one non-empty visible-ASCII authorization field.
    ///
    /// # Errors
    ///
    /// Returns [`AdminErrorCode::InvalidArgument`] for an empty, oversized,
    /// non-ASCII, or control-containing value without retaining rejected input.
    pub fn parse(value: &[u8]) -> Result<Self, AdminError> {
        let valid = !value.is_empty()
            && value.len() <= MAX_AUTHORIZATION_BYTES
            && value.iter().all(|byte| matches!(byte, 0x20..=0x7e));
        if !valid {
            return Err(admin_error(AdminErrorCode::InvalidArgument));
        }
        Ok(Self {
            bytes: Box::from(value),
        })
    }

    /// Borrows the credential for immediate authentication.
    ///
    /// Callers must not retain, format, trace, or log the returned bytes.
    #[must_use]
    pub fn credential_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Debug for HttpAuthorization {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpAuthorization(<redacted>)")
    }
}

impl Drop for HttpAuthorization {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Authenticates ephemeral HTTP authorization material.
pub trait HttpAuthenticationPort: Send + Sync {
    /// Produces one trusted principal from an active anonymous request context.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted administration error when authentication
    /// fails or its authoritative dependency is unavailable.
    fn authenticate(
        &self,
        authorization: &HttpAuthorization,
        context: &RequestContext,
    ) -> Result<PrincipalContext, AdminError>;
}

/// Bounded transport metadata propagated into authoritative execution.
pub struct HttpRequestMetadata {
    request_id: RequestId,
    trace_id: TraceId,
    deadline: Option<SystemTime>,
    cancellation: CancellationToken,
}

impl HttpRequestMetadata {
    /// Creates metadata after enforcing encoded body and header limits.
    ///
    /// # Errors
    ///
    /// Returns [`AdminErrorCode::InvalidArgument`] before authentication when
    /// either encoded size exceeds its hard limit.
    pub fn new(
        request_id: RequestId,
        trace_id: TraceId,
        deadline: Option<SystemTime>,
        cancellation: CancellationToken,
        encoded_body_bytes: usize,
        encoded_header_bytes: usize,
    ) -> Result<Self, AdminError> {
        if encoded_body_bytes > MAX_ENCODED_BODY_BYTES
            || encoded_header_bytes > MAX_ENCODED_HEADER_BYTES
        {
            return Err(admin_error(AdminErrorCode::InvalidArgument));
        }
        Ok(Self {
            request_id,
            trace_id,
            deadline,
            cancellation,
        })
    }

    fn anonymous_context(&self) -> RequestContext {
        RequestContext::new(
            self.request_id.clone(),
            self.trace_id.clone(),
            None,
            self.deadline,
            self.cancellation.clone(),
        )
    }
}

/// Validated suspend-user body containing no caller-selected identity facts.
pub struct HttpSuspendUserBody {
    execution: AdminExecutionRequest,
}

impl HttpSuspendUserBody {
    /// Creates a suspend-user intent from bounded protocol fields.
    ///
    /// # Errors
    ///
    /// Returns a stable invalid-argument error for malformed identifiers,
    /// policy versions, targets, or reason codes.
    pub fn new(
        command_id: AdminCommandId,
        decision_id: DecisionId,
        expected_policy_version: PolicyVersion,
        user_id: UserId,
        reason_code: &str,
    ) -> Result<Self, AdminError> {
        let execution = AdminExecutionRequest::new(
            command_id,
            decision_id,
            expected_policy_version,
            AdminActionKind::SuspendUser,
            AdminTarget::User(user_id),
            reason_code,
        )?;
        Ok(Self { execution })
    }
}

/// One complete HTTP suspend-user request.
pub struct HttpSuspendUserRequest {
    metadata: HttpRequestMetadata,
    authorization: HttpAuthorization,
    body: HttpSuspendUserBody,
}

impl HttpSuspendUserRequest {
    /// Combines validated metadata, ephemeral authorization, and body fields.
    #[must_use]
    pub const fn new(
        metadata: HttpRequestMetadata,
        authorization: HttpAuthorization,
        body: HttpSuspendUserBody,
    ) -> Self {
        Self {
            metadata,
            authorization,
            body,
        }
    }
}

/// Framework-independent HTTP administration adapter.
pub struct HttpAdminAdapter {
    executor: Arc<dyn AdminExecutionPort>,
    authentication: Arc<dyn HttpAuthenticationPort>,
}

impl HttpAdminAdapter {
    /// Creates an adapter over shared execution and HTTP authentication ports.
    #[must_use]
    pub fn new(
        executor: Arc<dyn AdminExecutionPort>,
        authentication: Arc<dyn HttpAuthenticationPort>,
    ) -> Self {
        Self {
            executor,
            authentication,
        }
    }

    /// Authenticates and executes one bounded suspend-user request.
    #[must_use]
    pub fn handle_suspend_user(&self, request: HttpSuspendUserRequest) -> HttpAdminResponse {
        let result = self.execute_suspend_user(request);
        HttpAdminResponse::from_result(result)
    }

    fn execute_suspend_user(
        &self,
        request: HttpSuspendUserRequest,
    ) -> Result<AdminCommandReceipt, AdminError> {
        let anonymous = request.metadata.anonymous_context();
        check_context(&anonymous)?;
        let principal = self
            .authentication
            .authenticate(&request.authorization, &anonymous)?;
        let authenticated = authenticated_context(&anonymous, principal);
        self.executor
            .execute(request.body.execution, &authenticated)
    }
}

/// Stable HTTP projection of administration execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpAdminResponse {
    status: u16,
    code: &'static str,
    receipt: Option<AdminCommandReceipt>,
}

impl HttpAdminResponse {
    fn from_result(result: Result<AdminCommandReceipt, AdminError>) -> Self {
        match result {
            Ok(receipt) => Self {
                status: 200,
                code: SUCCEEDED_CODE,
                receipt: Some(receipt),
            },
            Err(error) => Self {
                status: status_for(error.code()),
                code: error.code().as_str(),
                receipt: None,
            },
        }
    }

    /// Returns the stable HTTP status projection.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the stable administration result code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the durable receipt only for successful execution.
    #[must_use]
    pub const fn receipt(&self) -> Option<&AdminCommandReceipt> {
        self.receipt.as_ref()
    }
}

fn authenticated_context(
    anonymous: &RequestContext,
    principal: PrincipalContext,
) -> RequestContext {
    RequestContext::new(
        anonymous.request_id().clone(),
        anonymous.trace_id().clone(),
        Some(principal),
        anonymous.deadline(),
        anonymous.cancellation(),
    )
}

fn check_context(context: &RequestContext) -> Result<(), AdminError> {
    context.check_active().map_err(|error| {
        let code = match error.code() {
            ErrorCode::Cancelled => AdminErrorCode::Cancelled,
            ErrorCode::DeadlineExceeded => AdminErrorCode::DeadlineExceeded,
            _ => AdminErrorCode::IntegrityFailure,
        };
        admin_error(code)
    })
}

const fn status_for(code: AdminErrorCode) -> u16 {
    match code {
        AdminErrorCode::InvalidArgument => 400,
        AdminErrorCode::Unauthenticated => 401,
        AdminErrorCode::AuthorizationDenied
        | AdminErrorCode::TenantMismatch
        | AdminErrorCode::DecisionMismatch => 403,
        AdminErrorCode::Cancelled => 499,
        AdminErrorCode::DeadlineExceeded => 504,
        AdminErrorCode::Conflict => 409,
        AdminErrorCode::Unavailable | AdminErrorCode::CommitIndeterminate => 503,
        _ => 500,
    }
}

const fn admin_error(code: AdminErrorCode) -> AdminError {
    AdminError::new(code)
}

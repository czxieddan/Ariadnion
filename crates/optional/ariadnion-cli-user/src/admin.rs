// crates/optional/ariadnion-cli-user/src/admin.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Strict CLI projection for the initial administration slice.

use std::sync::Arc;

use ariadnion_api_admin::{
    AdminActionKind, AdminCommandId, AdminCommandReceipt, AdminError, AdminErrorCode,
    AdminExecutionPort, AdminExecutionRequest, AdminTarget,
};
use ariadnion_core::RequestContext;
use ariadnion_principal_binding::AuthenticatedPrincipalEvidence;
use ariadnion_rbac::{DecisionId, PolicyVersion};
use ariadnion_user_domain::UserId;

/// Maximum number of arguments accepted by one administration command.
pub const MAX_CLI_ARGUMENTS: usize = 16;

/// Maximum encoded bytes accepted in one argument.
pub const MAX_CLI_ARGUMENT_BYTES: usize = 16 * 1024;

/// Maximum aggregate encoded argument bytes accepted by one invocation.
pub const MAX_CLI_TOTAL_BYTES: usize = 64 * 1024;

const SUCCEEDED_CODE: &str = "ADMIN_COMMAND_SUCCEEDED";

/// Executes strict local CLI commands through shared authorization.
pub struct CliAdminAdapter {
    executor: Arc<dyn AdminExecutionPort>,
}

impl CliAdminAdapter {
    /// Creates an adapter over the sealed administration execution facade.
    #[must_use]
    pub fn new(executor: Arc<dyn AdminExecutionPort>) -> Self {
        Self { executor }
    }

    /// Parses and executes one exact suspend-user invocation.
    ///
    /// Tenant, principal, roles, and authorization decisions are never parsed
    /// from CLI arguments; typed evidence carries authenticated identity.
    #[must_use]
    pub fn execute(
        &self,
        arguments: &[&str],
        evidence: &AuthenticatedPrincipalEvidence,
        context: &RequestContext,
    ) -> CliAdminOutput {
        let result = parse_suspend_user(arguments)
            .and_then(|request| self.executor.execute(request, evidence, context));
        CliAdminOutput::from_result(result)
    }
}

/// Stable CLI projection of administration execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliAdminOutput {
    exit_code: u8,
    code: &'static str,
    receipt: Option<AdminCommandReceipt>,
}

impl CliAdminOutput {
    fn from_result(result: Result<AdminCommandReceipt, AdminError>) -> Self {
        match result {
            Ok(receipt) => Self {
                exit_code: 0,
                code: SUCCEEDED_CODE,
                receipt: Some(receipt),
            },
            Err(error) => Self {
                exit_code: error_exit_code(error.code()),
                code: error.code().as_str(),
                receipt: None,
            },
        }
    }

    /// Returns the stable process exit projection.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_code
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

struct SuspendUserArguments<'arguments> {
    user_id: &'arguments str,
    command_id: &'arguments str,
    decision_id: &'arguments str,
    policy_version: &'arguments str,
    reason_code: &'arguments str,
}

fn parse_suspend_user(arguments: &[&str]) -> Result<AdminExecutionRequest, AdminError> {
    validate_argument_bounds(arguments)?;
    let arguments = parse_suspend_user_grammar(arguments)?;
    build_suspend_user_request(arguments)
}

fn parse_suspend_user_grammar<'arguments>(
    arguments: &[&'arguments str],
) -> Result<SuspendUserArguments<'arguments>, AdminError> {
    let [
        domain,
        action,
        user_id,
        command_flag,
        command_id,
        decision_flag,
        decision_id,
        policy_flag,
        policy_version,
        reason_flag,
        reason_code,
    ] = arguments
    else {
        return Err(invalid_argument());
    };
    validate_grammar(
        domain,
        action,
        command_flag,
        decision_flag,
        policy_flag,
        reason_flag,
    )?;
    Ok(SuspendUserArguments {
        user_id,
        command_id,
        decision_id,
        policy_version,
        reason_code,
    })
}

fn build_suspend_user_request(
    arguments: SuspendUserArguments<'_>,
) -> Result<AdminExecutionRequest, AdminError> {
    let command_id = AdminCommandId::parse(arguments.command_id)?;
    let decision_id = DecisionId::parse(arguments.decision_id).map_err(|_| invalid_argument())?;
    let policy_version = parse_policy_version(arguments.policy_version)?;
    let user_id = UserId::parse(arguments.user_id).map_err(|_| invalid_argument())?;
    AdminExecutionRequest::new(
        command_id,
        decision_id,
        policy_version,
        AdminActionKind::SuspendUser,
        AdminTarget::User(user_id),
        arguments.reason_code,
    )
}

fn validate_grammar(
    domain: &str,
    action: &str,
    command_flag: &str,
    decision_flag: &str,
    policy_flag: &str,
    reason_flag: &str,
) -> Result<(), AdminError> {
    let valid = (
        domain,
        action,
        command_flag,
        decision_flag,
        policy_flag,
        reason_flag,
    ) == (
        "user",
        "suspend",
        "--command-id",
        "--decision-id",
        "--policy-version",
        "--reason",
    );
    valid.then_some(()).ok_or_else(invalid_argument)
}

fn validate_argument_bounds(arguments: &[&str]) -> Result<(), AdminError> {
    if arguments.len() > MAX_CLI_ARGUMENTS {
        return Err(invalid_argument());
    }
    let mut total = 0usize;
    for argument in arguments {
        validate_argument(argument)?;
        total = total
            .checked_add(argument.len())
            .ok_or_else(invalid_argument)?;
    }
    if total > MAX_CLI_TOTAL_BYTES {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_argument(argument: &str) -> Result<(), AdminError> {
    if argument.len() > MAX_CLI_ARGUMENT_BYTES || !argument.is_ascii() {
        return Err(invalid_argument());
    }
    Ok(())
}

fn parse_policy_version(value: &str) -> Result<PolicyVersion, AdminError> {
    let canonical = !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'));
    if !canonical {
        return Err(invalid_argument());
    }
    value
        .parse::<u64>()
        .map_err(|_| invalid_argument())
        .and_then(|version| PolicyVersion::new(version).map_err(|_| invalid_argument()))
}

const fn error_exit_code(code: AdminErrorCode) -> u8 {
    match code {
        AdminErrorCode::InvalidArgument => 2,
        AdminErrorCode::Unauthenticated
        | AdminErrorCode::AuthorizationDenied
        | AdminErrorCode::TenantMismatch
        | AdminErrorCode::DecisionMismatch => 3,
        AdminErrorCode::Conflict => 4,
        AdminErrorCode::Cancelled
        | AdminErrorCode::DeadlineExceeded
        | AdminErrorCode::Unavailable
        | AdminErrorCode::CommitIndeterminate => 75,
        _ => 70,
    }
}

const fn invalid_argument() -> AdminError {
    AdminError::new(AdminErrorCode::InvalidArgument)
}

//! Fail-closed registration of fixed deterministic scalar UDFs.

use std::fmt::{self, Debug, Formatter, Write as _};
use std::sync::Arc;
use std::time::Duration;

use ariadnion_core::{ErrorCode, RequestContext};
use ariadnion_storage_domain::{StorageError, StorageErrorCode};
use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_sql::{
    ast::{CreateFunctionImplementation, Ident, Statement, WasmFunctionBody},
    parser::parse_statement,
};
use rnmdb_types::SqlType;
use rnmdb_udf::{MAX_WASM_MODULE_BYTES, UdfBudget};

use crate::RnmdbSessionOwner;

/// Maximum bytes accepted for a fixed UDF name.
pub const MAX_FIXED_UDF_NAME_BYTES: usize = 64;
/// Maximum scalar arguments supported by the reviewed RNMDB revision.
pub const MAX_FIXED_UDF_ARGUMENTS: usize = 1;
/// Maximum compile input accepted for one fixed Wasm module.
pub const MAX_FIXED_UDF_MODULE_BYTES: usize = MAX_WASM_MODULE_BYTES;
/// Maximum linear-memory budget accepted by this adapter.
pub const MAX_FIXED_UDF_MEMORY_BYTES: usize = 16 * 1024 * 1024;
/// Maximum instruction budget accepted for one scalar invocation.
pub const MAX_FIXED_UDF_INSTRUCTIONS: u64 = 10_000_000;
/// Maximum wall-clock budget accepted for one scalar invocation.
pub const MAX_FIXED_UDF_TIMEOUT_MILLIS: u64 = 1_000;
/// Exact result budget for the currently supported `INT64` result.
pub const FIXED_UDF_RESULT_BYTES: usize = size_of::<i64>();
/// Maximum host imports. The reviewed runtime rejects every compiled import.
pub const MAX_FIXED_UDF_IMPORTS: usize = 0;

const REGISTRATION_SQL_OVERHEAD_BYTES: usize = 512;

/// A scalar value type supported by fixed RNMDB Wasm functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedScalarType {
    /// A signed 64-bit integer.
    Int64,
}

/// A bounded scalar signature declared by production code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedScalarSignature {
    argument_types: &'static [FixedScalarType],
    return_type: FixedScalarType,
}

impl FixedScalarSignature {
    /// Declares a static signature that is validated before registration.
    #[must_use]
    pub const fn new(
        argument_types: &'static [FixedScalarType],
        return_type: FixedScalarType,
    ) -> Self {
        Self {
            argument_types,
            return_type,
        }
    }

    /// Returns the fixed argument types.
    #[must_use]
    pub const fn argument_types(self) -> &'static [FixedScalarType] {
        self.argument_types
    }

    /// Returns the fixed result type.
    #[must_use]
    pub const fn return_type(self) -> FixedScalarType {
        self.return_type
    }
}

/// Explicit resource limits for a fixed scalar UDF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedUdfResourceLimits {
    max_module_bytes: usize,
    max_memory_bytes: usize,
    max_instructions: u64,
    timeout_millis: u64,
    max_result_bytes: usize,
    max_imports: usize,
}

impl FixedUdfResourceLimits {
    /// Declares limits that are checked against adapter and upstream bounds.
    #[must_use]
    pub const fn new(
        max_module_bytes: usize,
        max_memory_bytes: usize,
        max_instructions: u64,
        timeout_millis: u64,
        max_result_bytes: usize,
        max_imports: usize,
    ) -> Self {
        Self {
            max_module_bytes,
            max_memory_bytes,
            max_instructions,
            timeout_millis,
            max_result_bytes,
            max_imports,
        }
    }

    /// Returns the compilation-input limit.
    #[must_use]
    pub const fn max_module_bytes(self) -> usize {
        self.max_module_bytes
    }

    /// Returns the linear-memory limit.
    #[must_use]
    pub const fn max_memory_bytes(self) -> usize {
        self.max_memory_bytes
    }

    /// Returns the instruction limit.
    #[must_use]
    pub const fn max_instructions(self) -> u64 {
        self.max_instructions
    }

    /// Returns the wall-clock limit in milliseconds.
    #[must_use]
    pub const fn timeout_millis(self) -> u64 {
        self.timeout_millis
    }

    /// Returns the result-size limit.
    #[must_use]
    pub const fn max_result_bytes(self) -> usize {
        self.max_result_bytes
    }

    /// Returns the host-import limit.
    #[must_use]
    pub const fn max_imports(self) -> usize {
        self.max_imports
    }
}

/// The immutable capability policy used for fixed scalar UDFs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LockedDownUdfCapabilities;

impl LockedDownUdfCapabilities {
    /// Returns whether filesystem access is permitted.
    #[must_use]
    pub const fn filesystem_allowed(self) -> bool {
        false
    }

    /// Returns whether network access is permitted.
    #[must_use]
    pub const fn network_allowed(self) -> bool {
        false
    }

    /// Returns whether wall-clock access is permitted.
    #[must_use]
    pub const fn clock_allowed(self) -> bool {
        false
    }

    /// Returns whether host randomness is permitted.
    #[must_use]
    pub const fn randomness_allowed(self) -> bool {
        false
    }

    /// Returns whether secret or key access is permitted.
    #[must_use]
    pub const fn secrets_allowed(self) -> bool {
        false
    }
}

/// A production-owned Wasm scalar definition with only static inputs.
///
/// The registration API accepts this type through a `&'static` reference. It
/// never accepts request SQL or request Wasm bytes. Low-trust extensions must
/// use their component boundary rather than this trusted registration path.
pub struct FixedScalarUdfDefinition {
    name: &'static str,
    signature: FixedScalarSignature,
    module_bytes: &'static [u8],
    limits: FixedUdfResourceLimits,
    capabilities: LockedDownUdfCapabilities,
}

impl FixedScalarUdfDefinition {
    /// Declares a static definition for fail-closed validation and registration.
    #[must_use]
    pub const fn new(
        name: &'static str,
        signature: FixedScalarSignature,
        module_bytes: &'static [u8],
        limits: FixedUdfResourceLimits,
    ) -> Self {
        Self {
            name,
            signature,
            module_bytes,
            limits,
            capabilities: LockedDownUdfCapabilities,
        }
    }

    /// Returns the fixed SQL function name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the fixed scalar signature.
    #[must_use]
    pub const fn signature(&self) -> FixedScalarSignature {
        self.signature
    }

    /// Returns the compile-time Wasm asset.
    #[must_use]
    pub const fn module_bytes(&self) -> &'static [u8] {
        self.module_bytes
    }

    /// Returns the declared resource limits.
    #[must_use]
    pub const fn limits(&self) -> FixedUdfResourceLimits {
        self.limits
    }

    /// Returns the immutable denied-by-default capability policy.
    #[must_use]
    pub const fn capabilities(&self) -> LockedDownUdfCapabilities {
        self.capabilities
    }

    /// Validates all adapter bounds without registering or compiling the module.
    ///
    /// Compilation, import inspection, entrypoint validation, and runtime
    /// resource enforcement remain owned by `rnmdb-udf` and are performed by
    /// [`RnmdbScalarUdfRegistrar::register`].
    ///
    /// # Errors
    ///
    /// Returns a stable invalid-argument or resource-exhausted storage error
    /// when a definition is outside the supported boundary.
    pub fn validate(&self) -> Result<(), StorageError> {
        validate_name(self.name)?;
        validate_signature(self.signature)?;
        validate_limits(self.limits)?;
        validate_module(self.module_bytes, self.limits)
    }
}

impl Debug for FixedScalarUdfDefinition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedScalarUdfDefinition")
            .field("name", &self.name)
            .field("signature", &self.signature)
            .field("module_bytes", &self.module_bytes.len())
            .field("limits", &self.limits)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

/// Registers fixed scalar UDFs through one serialized embedded session.
///
/// The reviewed `LocalSession` API does not expose typed UDF registration.
/// This adapter therefore renders one private statement, reparses its exact
/// AST before execution, and exposes no SQL-bearing registration method.
pub struct RnmdbScalarUdfRegistrar {
    session: Arc<RnmdbSessionOwner>,
}

impl RnmdbScalarUdfRegistrar {
    /// Creates a registrar for the sole long-lived RNMDB session owner.
    #[must_use]
    pub fn new(session: Arc<RnmdbSessionOwner>) -> Self {
        Self { session }
    }

    /// Returns the serialized session owner.
    #[must_use]
    pub const fn session(&self) -> &Arc<RnmdbSessionOwner> {
        &self.session
    }

    /// Registers and durably commits one fixed deterministic scalar UDF.
    ///
    /// RNMDB compiles the module, rejects every compiled import, verifies the
    /// `run(i64) -> i64` entrypoint, and enforces memory, instruction, and
    /// timeout limits. Registration never accepts caller-provided SQL or Wasm.
    /// The entire catalog mutation and checkpoint run while the session-owner
    /// mutex is held.
    ///
    /// # Errors
    ///
    /// Returns stable storage errors for cancellation, deadlines, invalid fixed
    /// definitions, resource bounds, sandbox rejection, catalog conflicts, or
    /// durable commit failures. A failed registration is rolled back.
    pub fn register(
        &self,
        definition: &'static FixedScalarUdfDefinition,
        context: &RequestContext,
    ) -> Result<(), StorageError> {
        check_context(context)?;
        definition.validate()?;
        validate_profile_budget(&self.session, definition)?;
        let sql = render_registration_sql(definition)?;
        validate_rendered_registration(&sql, definition)?;
        self.session
            .with_session(context, |session| register_in_transaction(session, &sql))
    }
}

struct ParsedRegistration {
    name: Ident,
    argument_types: Vec<SqlType>,
    return_type: SqlType,
    body: WasmFunctionBody,
}

fn validate_name(name: &str) -> Result<(), StorageError> {
    if name.is_empty() || name.len() > MAX_FIXED_UDF_NAME_BYTES {
        return Err(invalid_argument());
    }
    let Some((first, tail)) = name.as_bytes().split_first() else {
        return Err(invalid_argument());
    };
    if !is_name_start(*first) || tail.iter().copied().any(|byte| !is_name_continue(byte)) {
        return Err(invalid_argument());
    }
    Ok(())
}

const fn is_name_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_lowercase()
}

const fn is_name_continue(byte: u8) -> bool {
    is_name_start(byte) || byte.is_ascii_digit()
}

fn validate_signature(signature: FixedScalarSignature) -> Result<(), StorageError> {
    if signature.argument_types().len() != MAX_FIXED_UDF_ARGUMENTS {
        return Err(invalid_argument());
    }
    if signature.argument_types() != [FixedScalarType::Int64] {
        return Err(invalid_argument());
    }
    if signature.return_type() != FixedScalarType::Int64 {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_limits(limits: FixedUdfResourceLimits) -> Result<(), StorageError> {
    validate_positive_limits(limits)?;
    validate_adapter_maxima(limits)?;
    validate_fixed_output_limits(limits)?;
    UdfBudget::new(
        limits.max_memory_bytes(),
        limits.max_instructions(),
        Duration::from_millis(limits.timeout_millis()),
    )
    .map(|_| ())
    .map_err(crate::session::map_rnmdb_error)
}

fn validate_positive_limits(limits: FixedUdfResourceLimits) -> Result<(), StorageError> {
    if limits.max_module_bytes() == 0 || limits.max_memory_bytes() == 0 {
        return Err(invalid_argument());
    }
    if limits.max_instructions() == 0 || limits.timeout_millis() == 0 {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_adapter_maxima(limits: FixedUdfResourceLimits) -> Result<(), StorageError> {
    if limits.max_module_bytes() > MAX_FIXED_UDF_MODULE_BYTES {
        return Err(invalid_argument());
    }
    if limits.max_memory_bytes() > MAX_FIXED_UDF_MEMORY_BYTES {
        return Err(invalid_argument());
    }
    if limits.max_instructions() > MAX_FIXED_UDF_INSTRUCTIONS {
        return Err(invalid_argument());
    }
    if limits.timeout_millis() > MAX_FIXED_UDF_TIMEOUT_MILLIS {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_fixed_output_limits(limits: FixedUdfResourceLimits) -> Result<(), StorageError> {
    if limits.max_result_bytes() != FIXED_UDF_RESULT_BYTES {
        return Err(invalid_argument());
    }
    if limits.max_imports() != MAX_FIXED_UDF_IMPORTS {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_module(
    module_bytes: &[u8],
    limits: FixedUdfResourceLimits,
) -> Result<(), StorageError> {
    if module_bytes.is_empty() {
        return Err(invalid_argument());
    }
    if module_bytes.len() > limits.max_module_bytes() {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn validate_profile_budget(
    session: &RnmdbSessionOwner,
    definition: &FixedScalarUdfDefinition,
) -> Result<(), StorageError> {
    let limits = session.profile().limits();
    let udf_enabled = limits.max_udf_invocations() > 0 && limits.max_udf_memory_bytes() > 0;
    if !udf_enabled || definition.limits().max_memory_bytes() > limits.max_udf_memory_bytes() {
        return Err(resource_exhausted());
    }
    Ok(())
}

fn render_registration_sql(definition: &FixedScalarUdfDefinition) -> Result<String, StorageError> {
    let capacity = registration_sql_capacity(definition)?;
    let mut sql = String::new();
    sql.try_reserve_exact(capacity)
        .map_err(|_| resource_exhausted())?;
    push_registration_header(&mut sql, definition);
    push_module_hex(&mut sql, definition.module_bytes());
    push_registration_limits(&mut sql, definition.limits())?;
    Ok(sql)
}

fn registration_sql_capacity(definition: &FixedScalarUdfDefinition) -> Result<usize, StorageError> {
    let hex_bytes = definition
        .module_bytes()
        .len()
        .checked_mul(2)
        .ok_or_else(resource_exhausted)?;
    hex_bytes
        .checked_add(definition.name().len())
        .and_then(|value| value.checked_add(REGISTRATION_SQL_OVERHEAD_BYTES))
        .ok_or_else(resource_exhausted)
}

fn push_registration_header(sql: &mut String, definition: &FixedScalarUdfDefinition) {
    sql.push_str("CREATE FUNCTION ");
    sql.push_str(definition.name());
    sql.push_str("(INT64) RETURNS INT64 LANGUAGE wasm AS '");
}

fn push_module_hex(sql: &mut String, module_bytes: &[u8]) {
    for byte in module_bytes {
        sql.push(hex_digit(byte >> 4));
        sql.push(hex_digit(byte & 0x0f));
    }
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '?',
    }
}

fn push_registration_limits(
    sql: &mut String,
    limits: FixedUdfResourceLimits,
) -> Result<(), StorageError> {
    let memory = u64::try_from(limits.max_memory_bytes()).map_err(|_| invalid_argument())?;
    write!(
        sql,
        "' WITH (max_memory_bytes = {memory}, max_instructions = {}, timeout_ms = {})",
        limits.max_instructions(),
        limits.timeout_millis(),
    )
    .map_err(|_| internal_error())
}

fn validate_rendered_registration(
    sql: &str,
    definition: &FixedScalarUdfDefinition,
) -> Result<(), StorageError> {
    let parsed = parse_registration(sql)?;
    validate_parsed_header(&parsed, definition)?;
    validate_parsed_body(&parsed.body, definition)
}

fn parse_registration(sql: &str) -> Result<ParsedRegistration, StorageError> {
    let statement = parse_statement(sql).map_err(|_| invalid_argument())?;
    let Statement::CreateFunction {
        name,
        argument_types,
        return_type,
        implementation,
        if_not_exists,
    } = statement
    else {
        return Err(internal_error());
    };
    if if_not_exists {
        return Err(internal_error());
    }
    let CreateFunctionImplementation::Wasm(body) = implementation else {
        return Err(internal_error());
    };
    Ok(ParsedRegistration {
        name,
        argument_types,
        return_type,
        body,
    })
}

fn validate_parsed_header(
    parsed: &ParsedRegistration,
    definition: &FixedScalarUdfDefinition,
) -> Result<(), StorageError> {
    ensure_generated(parsed.name.as_str() == definition.name())?;
    ensure_generated(parsed.argument_types == [SqlType::Int64])?;
    ensure_generated(parsed.return_type == SqlType::Int64)
}

fn validate_parsed_body(
    body: &WasmFunctionBody,
    definition: &FixedScalarUdfDefinition,
) -> Result<(), StorageError> {
    let limits = definition.limits();
    let memory = u64::try_from(limits.max_memory_bytes()).map_err(|_| internal_error())?;
    ensure_generated(body.module_bytes.as_slice() == definition.module_bytes())?;
    ensure_generated(body.max_memory_bytes == memory)?;
    ensure_generated(body.max_instructions == limits.max_instructions())?;
    ensure_generated(body.timeout_millis == limits.timeout_millis())
}

fn ensure_generated(condition: bool) -> Result<(), StorageError> {
    if condition {
        return Ok(());
    }
    Err(internal_error())
}

fn register_in_transaction(session: &mut LocalSession, sql: &str) -> Result<(), RnovError> {
    session.execute("BEGIN")?;
    let result = execute_registration(session, sql);
    finish_registration(session, result)
}

fn execute_registration(session: &mut LocalSession, sql: &str) -> Result<(), RnovError> {
    match session.execute(sql)? {
        CommandOutput::SchemaChanged => Ok(()),
        _ => Err(RnovError::new(
            ErrorKind::Internal,
            "fixed wasm function registration returned an unexpected result",
        )),
    }
}

fn finish_registration(
    session: &mut LocalSession,
    result: Result<(), RnovError>,
) -> Result<(), RnovError> {
    match result {
        Ok(()) => commit_registration(session),
        Err(error) => rollback_with_error(session, error),
    }
}

fn commit_registration(session: &mut LocalSession) -> Result<(), RnovError> {
    if let Err(error) = session.execute("COMMIT") {
        return rollback_with_error(session, error);
    }
    Ok(())
}

fn rollback_with_error<T>(session: &mut LocalSession, error: RnovError) -> Result<T, RnovError> {
    if session.in_transaction() {
        session.execute("ROLLBACK")?;
    }
    Err(error)
}

fn check_context(context: &RequestContext) -> Result<(), StorageError> {
    context.check_active().map_err(|error| match error.code() {
        ErrorCode::Cancelled => StorageError::new(StorageErrorCode::Cancelled),
        ErrorCode::DeadlineExceeded => StorageError::new(StorageErrorCode::DeadlineExceeded),
        _ => internal_error(),
    })
}

const fn invalid_argument() -> StorageError {
    StorageError::new(StorageErrorCode::InvalidArgument)
}

const fn resource_exhausted() -> StorageError {
    StorageError::new(StorageErrorCode::ResourceExhausted)
}

const fn internal_error() -> StorageError {
    StorageError::new(StorageErrorCode::Internal)
}

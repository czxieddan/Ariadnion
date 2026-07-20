use std::fmt::{self, Display, Formatter};

/// Stable machine-readable failures raised by query contract validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QueryContractErrorCode {
    /// An identifier, static template, or schema field is invalid.
    InvalidArgument,
    /// A catalog or schema contains a duplicate stable identity.
    Conflict,
    /// A configured count or value exceeds its documented hard limit.
    ResourceExhausted,
    /// A write template does not declare exactly one required tenant parameter.
    TenantParameterRequired,
    /// Bound argument names do not exactly match the registered parameter set.
    BindingMismatch,
    /// A bound value does not match its registered stable type.
    TypeMismatch,
    /// A projected row does not match the registered column order and types.
    ProjectionMismatch,
}

impl QueryContractErrorCode {
    /// Returns the stable external machine code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "QUERY_CONTRACT_INVALID_ARGUMENT",
            Self::Conflict => "QUERY_CONTRACT_CONFLICT",
            Self::ResourceExhausted => "QUERY_CONTRACT_RESOURCE_EXHAUSTED",
            Self::TenantParameterRequired => "QUERY_CONTRACT_TENANT_PARAMETER_REQUIRED",
            Self::BindingMismatch => "QUERY_CONTRACT_BINDING_MISMATCH",
            Self::TypeMismatch => "QUERY_CONTRACT_TYPE_MISMATCH",
            Self::ProjectionMismatch => "QUERY_CONTRACT_PROJECTION_MISMATCH",
        }
    }
}

/// A redacted query contract error that never retains rejected input values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryContractError {
    code: QueryContractErrorCode,
}

impl QueryContractError {
    /// Creates an error from a stable machine-readable code.
    #[must_use]
    pub const fn new(code: QueryContractErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> QueryContractErrorCode {
        self.code
    }
}

impl Display for QueryContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for QueryContractError {}

// crates/ariadnion-core/src/error.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Stable core errors and redacted external projections.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

/// Broad error categories used by adapters and observability layers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorCategory {
    /// A caller supplied an invalid value or operation.
    InvalidRequest,
    /// Current state conflicts with the requested operation.
    Conflict,
    /// Work stopped because cancellation or a deadline was observed.
    Interrupted,
    /// A required capability or resource is unavailable.
    Availability,
    /// An invariant failed inside the platform.
    Internal,
}

/// Stable machine-readable error codes exposed by the core crate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ErrorCode {
    /// Input failed bounded parsing or semantic validation.
    InvalidArgument = 0,
    /// Current state conflicts with the requested operation.
    Conflict = 1,
    /// A cancellation request stopped the operation.
    Cancelled = 2,
    /// The operation exceeded its declared deadline.
    DeadlineExceeded = 3,
    /// A required capability or resource is unavailable.
    Unavailable = 4,
    /// A bounded resource budget was exhausted.
    ResourceExhausted = 5,
    /// An internal invariant failed without a safe external explanation.
    Internal = 6,
}

#[derive(Clone, Copy)]
struct ErrorMetadata {
    machine_code: &'static str,
    category: ErrorCategory,
    public_message: &'static str,
}

const ERROR_METADATA: [ErrorMetadata; 7] = [
    ErrorMetadata {
        machine_code: "core.invalid_argument",
        category: ErrorCategory::InvalidRequest,
        public_message: "The request contains an invalid value.",
    },
    ErrorMetadata {
        machine_code: "core.conflict",
        category: ErrorCategory::Conflict,
        public_message: "The requested operation conflicts with current state.",
    },
    ErrorMetadata {
        machine_code: "core.cancelled",
        category: ErrorCategory::Interrupted,
        public_message: "The operation was cancelled.",
    },
    ErrorMetadata {
        machine_code: "core.deadline_exceeded",
        category: ErrorCategory::Interrupted,
        public_message: "The operation exceeded its deadline.",
    },
    ErrorMetadata {
        machine_code: "core.unavailable",
        category: ErrorCategory::Availability,
        public_message: "The requested capability is unavailable.",
    },
    ErrorMetadata {
        machine_code: "core.resource_exhausted",
        category: ErrorCategory::Availability,
        public_message: "A bounded resource budget was exhausted.",
    },
    ErrorMetadata {
        machine_code: "core.internal",
        category: ErrorCategory::Internal,
        public_message: "The platform could not complete the operation.",
    },
];

impl ErrorCode {
    fn metadata(self) -> &'static ErrorMetadata {
        &ERROR_METADATA[self as usize]
    }

    /// Returns the stable machine code.
    #[must_use]
    pub fn machine_code(self) -> &'static str {
        self.metadata().machine_code
    }

    /// Returns the stable machine code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.machine_code()
    }

    /// Returns the broad category associated with this code.
    #[must_use]
    pub fn category(self) -> ErrorCategory {
        self.metadata().category
    }

    /// Returns a stable message that is safe for untrusted callers.
    #[must_use]
    pub fn public_message(self) -> &'static str {
        self.metadata().public_message
    }
}

/// An internal core error whose debug and display output never reveal context.
#[derive(Clone)]
pub struct CoreError {
    code: ErrorCode,
    internal_context: Option<Box<str>>,
}

impl CoreError {
    /// Creates an error from a stable code.
    #[must_use]
    pub fn from_code(code: ErrorCode) -> Self {
        Self {
            code,
            internal_context: None,
        }
    }

    /// Creates an error from a stable code.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self::from_code(code)
    }

    /// Attaches private diagnostic context without exposing it through formatting.
    #[must_use]
    pub fn with_internal_context(mut self, context: impl Into<Box<str>>) -> Self {
        self.internal_context = Some(context.into());
        self
    }

    /// Returns the stable error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the broad error category.
    #[must_use]
    pub fn category(&self) -> ErrorCategory {
        self.code.category()
    }

    /// Reports whether private context is available to a trusted diagnostic sink.
    #[must_use]
    pub fn has_internal_context(&self) -> bool {
        self.internal_context.is_some()
    }

    /// Produces a safe external projection.
    #[must_use]
    pub fn external(&self) -> ExternalError {
        ExternalError::new(self.code)
    }
}

impl Debug for CoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreError")
            .field("code", &self.code)
            .field(
                "internal_context",
                &self.internal_context.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Display for CoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}",
            self.code.machine_code(),
            self.code.public_message()
        )
    }
}

impl Error for CoreError {}

/// A stable error projection safe to serialize or return to an untrusted caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalError {
    code: ErrorCode,
}

impl ExternalError {
    /// Creates a safe projection for the supplied code.
    #[must_use]
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine code.
    #[must_use]
    pub fn machine_code(self) -> &'static str {
        self.code.machine_code()
    }

    /// Returns the safe public message.
    #[must_use]
    pub fn message(self) -> &'static str {
        self.code.public_message()
    }

    /// Returns the underlying stable code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        self.code
    }
}

impl From<&CoreError> for ExternalError {
    fn from(value: &CoreError) -> Self {
        value.external()
    }
}

//! Bounded local CLI administration adapters.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admin;

pub use admin::{
    CliAdminAdapter, CliAdminOutput, MAX_CLI_ARGUMENT_BYTES, MAX_CLI_ARGUMENTS, MAX_CLI_TOTAL_BYTES,
};

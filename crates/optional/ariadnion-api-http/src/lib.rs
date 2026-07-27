//! Bounded framework-independent HTTP administration adapters.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admin;

pub use admin::{
    HttpAdminAdapter, HttpAdminResponse, HttpAuthenticationPort, HttpAuthorization,
    HttpRequestMetadata, HttpSuspendUserBody, HttpSuspendUserRequest, MAX_AUTHORIZATION_BYTES,
    MAX_ENCODED_BODY_BYTES, MAX_ENCODED_HEADER_BYTES,
};

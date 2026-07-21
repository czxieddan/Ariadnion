//! Pure scoped API-key types and deterministic lifecycle transitions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod ids;
mod model;
mod transition;

pub use error::{ApiKeyError, ApiKeyErrorCode};
pub use ids::{ApiKeyId, ApiKeyVersion};
pub use model::{
    ApiKey, ApiKeyIssueRequest, ApiKeyOwner, ApiKeyPrefix, ApiKeyScope, ApiKeySecretDigest,
    ApiKeyState, ApiKeyValidityWindow, MAX_API_KEY_LIFETIME_SECONDS, MAX_API_KEY_SCOPES,
    MAX_OVERLAP_SECONDS, MAX_PREFIX_BYTES, MAX_SCOPE_BYTES, MAX_SECRET_BYTES, MIN_PREFIX_BYTES,
    MIN_SECRET_BYTES,
};
pub use transition::{
    ApiKeyAction, ApiKeyCommand, ApiKeyEvent, ApiKeyEventKind, ApiKeyPresentation, ApiKeyRotation,
    ApiKeyTransition, ApiKeyVerification, issue_api_key, transition_api_key,
    verify_api_key_presentation,
};

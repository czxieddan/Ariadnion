// crates/optional/ariadnion-file-entropy/src/lib.rs - Rust source for Ariadnion.
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
//! Operating-system entropy adapters for opaque durable-file capabilities.
//!
//! This crate keeps OS CSPRNG access at a small composition boundary. It does
//! not retain entropy, counters, clocks, request material, or fallback state.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use ariadnion_api_files::{
    ApiFilesError, ApiFilesErrorCode, BoxFileFuture, FileReference, FileReferenceIssuerPort,
};
use ariadnion_core::RequestContext;
use ariadnion_storage_asset::{AssetStageToken, StageTokenIssuer, StorageError, StorageErrorCode};
use zeroize::Zeroizing;

/// A stateless operating-system CSPRNG adapter for file references and stage tokens.
///
/// Each operation asks the operating system for a fresh fixed-width value. The
/// adapter has no deterministic fallback and exposes entropy failures only as
/// stable redacted availability errors.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatingSystemFileEntropy;

impl OperatingSystemFileEntropy {
    /// Creates a stateless operating-system entropy adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FileReferenceIssuerPort for OperatingSystemFileEntropy {
    fn issue_reference<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileReference, ApiFilesError>> {
        Box::pin(async move {
            ensure_reference_context(context)?;
            let draw_result = draw::<{ FileReference::BYTE_LENGTH }>();
            ensure_reference_context(context)?;
            let bytes = draw_result.map_err(unavailable_file_error)?;
            Ok(FileReference::new(*bytes))
        })
    }
}

impl StageTokenIssuer for OperatingSystemFileEntropy {
    fn issue(&self) -> Result<AssetStageToken, StorageError> {
        let bytes =
            draw::<{ AssetStageToken::BYTE_LENGTH }>().map_err(unavailable_storage_error)?;
        Ok(AssetStageToken::new(*bytes))
    }
}

fn ensure_reference_context(context: &RequestContext) -> Result<(), ApiFilesError> {
    if context.principal().is_none() {
        return Err(ApiFilesError::new(ApiFilesErrorCode::Unauthenticated));
    }
    context.check_active().map_err(ApiFilesError::from)
}

fn draw<const BYTE_LENGTH: usize>() -> Result<Zeroizing<[u8; BYTE_LENGTH]>, ()> {
    #[cfg(feature = "test-hooks")]
    test_hooks::record_draw_attempt();

    let result = draw_bytes();

    #[cfg(feature = "test-hooks")]
    test_hooks::pause_after_draw_attempt();

    result
}

fn draw_bytes<const BYTE_LENGTH: usize>() -> Result<Zeroizing<[u8; BYTE_LENGTH]>, ()> {
    #[cfg(feature = "test-hooks")]
    if test_hooks::take_draw_failure() {
        return Err(());
    }

    let mut bytes = Zeroizing::new([0_u8; BYTE_LENGTH]);
    getrandom::fill(bytes.as_mut()).map_err(|_| ())?;
    Ok(bytes)
}

const fn unavailable_file_error(_: ()) -> ApiFilesError {
    ApiFilesError::new(ApiFilesErrorCode::Unavailable)
}

const fn unavailable_storage_error(_: ()) -> StorageError {
    StorageError::new(StorageErrorCode::Unavailable)
}

/// Deterministic hooks for the ignored external entropy contract suite.
///
/// This module is available only with the non-default `test-hooks` feature. It
/// never provides a production entropy source or a fallback path.
#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::fmt::{self, Debug, Formatter};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex, MutexGuard};

    static DRAW_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FAIL_NEXT_DRAW: AtomicBool = AtomicBool::new(false);
    static DRAW_PAUSE: Mutex<Option<Arc<Barrier>>> = Mutex::new(None);

    /// A redacted two-phase barrier controlling one test-only draw pause.
    pub struct DrawPause {
        barrier: Arc<Barrier>,
    }

    impl DrawPause {
        /// Waits until the entropy worker has completed its draw attempt.
        pub fn wait_until_paused(&self) {
            self.barrier.wait();
        }

        /// Releases the paused entropy worker after test-side state changes.
        pub fn release(&self) {
            self.barrier.wait();
        }
    }

    impl Debug for DrawPause {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("DrawPause(<redacted>)")
        }
    }

    /// Clears all deterministic hook state before one serialized test case.
    pub fn reset() {
        DRAW_COUNT.store(0, Ordering::Release);
        FAIL_NEXT_DRAW.store(false, Ordering::Release);
        *draw_pause_slot() = None;
    }

    /// Returns how many entropy draw attempts reached the adapter seam.
    #[must_use]
    pub fn draw_count() -> usize {
        DRAW_COUNT.load(Ordering::Acquire)
    }

    /// Causes exactly the next entropy draw attempt to fail without OS text.
    pub fn fail_next_draw() {
        FAIL_NEXT_DRAW.store(true, Ordering::Release);
    }

    /// Pauses the worker after the next successful or failed draw attempt.
    ///
    /// The caller must serialize this hook with [`reset`], wait for the worker
    /// through [`DrawPause::wait_until_paused`], and then release it explicitly.
    #[must_use]
    pub fn pause_next_draw() -> DrawPause {
        let barrier = Arc::new(Barrier::new(2));
        *draw_pause_slot() = Some(barrier.clone());
        DrawPause { barrier }
    }

    pub(crate) fn record_draw_attempt() {
        DRAW_COUNT.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn take_draw_failure() -> bool {
        FAIL_NEXT_DRAW.swap(false, Ordering::AcqRel)
    }

    pub(crate) fn pause_after_draw_attempt() {
        let barrier = draw_pause_slot().take();
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
    }

    fn draw_pause_slot() -> MutexGuard<'static, Option<Arc<Barrier>>> {
        match DRAW_PAUSE.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

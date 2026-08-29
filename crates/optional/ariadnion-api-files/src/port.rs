// crates/optional/ariadnion-api-files/src/port.rs - Rust source for Ariadnion.
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
//! Runtime-neutral streaming file service boundaries.

use std::future::Future;
use std::pin::Pin;

use ariadnion_api_domain::{FileDescriptor, FileReference};
use ariadnion_core::RequestContext;

use crate::{
    ApiFilesError, FileAccessTicket, FileAccessTicketGrant, FileAccessTicketIssueReconciliation,
    FileAccessTicketIssueRequest, FileCatalogRecord, FileChunk, FileDeleteReconciliation,
    FileDeleteRequest, FileListPage, FileListRequest, FileUploadReconciliation, FileUploadRequest,
};

/// A boxed asynchronous file operation result.
///
/// Every future returned through a file port is lazy: constructing it performs
/// no I/O or other operation work, and polling performs the work. The future is
/// safe to move between executor workers, borrows its port and all borrowed
/// arguments for at most `'a`, and does not require a particular runtime.
pub type BoxFileFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Issues and reconciles provider-neutral content-read access tickets.
///
/// Every returned future is lazy: construction performs no authentication,
/// entropy, clock, digest, lookup, or cancellation setup. On first poll, the
/// implementation authenticates the context and then checks cancellation and
/// deadline state before entropy or authoritative lookup. Each future owns an
/// independent adapter-local child cancellation token and an active drop guard
/// that cancels only its pending adapter work, never the caller's shared token.
///
/// Durable issue idempotency is scoped to the exact authenticated tenant,
/// principal, and visible idempotency key. A new slot is claimed atomically
/// before entropy or clock access. During recovery-envelope retention, an
/// identical replay returns the original grant without new entropy, newly
/// selected issuance timestamps, or writes; authoritative UTC may be sampled
/// only to enforce retention cutoffs. A changed reference or lifetime returns
/// `Conflict`. The encrypted recovery envelope remains available through the
/// exclusive expiry plus exactly 24 hours. At that boundary, the adapter refuses
/// to open it, zeroizes and removes the encrypted bearer, discards the request
/// commitment, request-commitment key version, and recovery-envelope key
/// version, and retains only the issue-lookup version and digest, terminal
/// cutoff, and committed state in a non-secret terminal marker through expiry
/// plus exactly 30 days. Between those boundaries, issue returns `Conflict` and
/// reconciliation returns `NotFound`; after terminal retirement, reconciliation
/// remains `NotFound` while issue may establish a new slot. Cleanup failure
/// fails closed and cannot extend bearer access beyond its exclusive expiry.
///
/// At most 100,000 unretired issue slots may exist for one tenant across all
/// principals. Pending reservations, live envelopes, explicit no-commit rows,
/// and committed terminal markers all count. A new claim at the limit returns
/// `ResourceExhausted` before entropy, issuance-time sampling, or a durable
/// write. Implementations must not evict an unretired slot, shorten either
/// retention horizon, or substitute an unbounded queue.
pub trait FileAccessTicketIssuerPort: Send + Sync {
    /// Lazily issues one ticket bound to the authenticated tenant, principal,
    /// exact reference, and requested lifetime.
    ///
    /// On a first successful claim, the first poll takes exactly one trusted UTC
    /// sample, floors it toward the past to signed Unix microseconds, and uses
    /// checked signed-microsecond addition of exactly `request.lifetime()` for
    /// expiry. An unrepresentable conversion or addition returns
    /// `InvalidArgument` before durable state commits.
    ///
    /// # Errors
    ///
    /// A pre-commit cancellation or deadline wins. Once the durable commit
    /// boundary begins, a known committed success wins over later context
    /// cancellation, a known durable failure returns that stable failure, and
    /// an unknown outcome returns `CommitIndeterminate`. The latter must be
    /// resolved only by [`Self::reconcile_issue`] with the preserved exact
    /// request and idempotency material.
    ///
    /// Returns a stable redacted authentication, context, conflict, resource,
    /// availability, integrity, or commit-indeterminate failure. Concrete
    /// adapters own the cryptography and persistence while preserving these
    /// observable boundaries.
    fn issue<'a>(
        &'a self,
        request: FileAccessTicketIssueRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileAccessTicketGrant, ApiFilesError>>;

    /// Lazily reconciles an issue whose durable commit outcome was unknown.
    ///
    /// Only the exact original request and idempotency material may resolve the
    /// outcome; a replacement bearer must never be synthesized. Every supplied
    /// authenticated identity, reference, lifetime, or idempotency mismatch
    /// projects to `NotFound` without revealing which field differed. `Committed`
    /// requires an authenticated exact request commitment and a successfully
    /// opened recovery envelope. `NotCommitted` requires an explicit
    /// authoritative no-commit terminal row retained for exactly 30 days from
    /// the first trusted attempt timestamp. If that checked signed-microsecond
    /// cutoff is unrepresentable, issue returns `InvalidArgument` before its
    /// reservation can become durable. Row absence, expiry, cleanup, or a
    /// missing recovery key is `NotFound`, never proof of no commit. Corrupt
    /// recovery material is `IntegrityFailure`.
    ///
    /// Cancellation or deadline wins before authoritative lookup. Once a
    /// committed or no-commit row is known, that result wins over later context
    /// cancellation while commitment verification and envelope opening finish.
    /// Dropping the future cancels only its local open, zeroizes partial
    /// plaintext, and leaves durable state available to another reconciliation.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted authentication, context, not-found, integrity,
    /// or availability failure.
    fn reconcile_issue<'a>(
        &'a self,
        request: &'a FileAccessTicketIssueRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileAccessTicketIssueReconciliation, ApiFilesError>>;
}

/// Verifies a ticket against authoritative tenant, principal, reference,
/// audience, validity, and revocation state.
///
/// The future follows the same lazy first-poll authentication, context check,
/// independent child cancellation, and active drop-guard requirements as issue
/// futures. Each call uses one authoritative lookup and current UTC clock and
/// checks the digest, fixed audience, exact reference, exact tenant and
/// principal, inclusive-issue/exclusive-expiry window, and permanent current
/// revocation state. A stale positive cache cannot authorize a ticket.
pub trait FileAccessTicketVerifierPort: Send + Sync {
    /// Lazily verifies one exact content-read ticket binding.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiFilesErrorCode::Unauthenticated`] for an anonymous
    /// context. Cancellation or deadline wins before authoritative lookup; once
    /// lookup completes, its exact match or negative result wins over later
    /// context cancellation. Every authorization mismatch, including a digest,
    /// audience, reference, identity, validity, malformed-record, or revocation
    /// mismatch, projects to [`crate::ApiFilesErrorCode::NotFound`]. Operational
    /// failures remain stable and redacted.
    fn verify<'a>(
        &'a self,
        ticket: &'a FileAccessTicket,
        reference: &'a FileReference,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>>;
}

/// Issues opaque file references through a runtime-neutral security boundary.
///
/// Every returned [`BoxFileFuture`] is lazy and `Send`: constructing it must not
/// authenticate, inspect context state, access entropy, or perform other work.
/// Polling must authenticate the supplied [`RequestContext`] and check
/// cancellation and deadline state before any entropy access. Implementations
/// must use a cryptographically secure random number generator and must never
/// fall back to counters, clocks, digests, request material, storage keys, or
/// provider identifiers. Catalog insertion is the authoritative collision check;
/// a collision returns [`crate::ApiFilesErrorCode::Conflict`] and never overwrites
/// an existing record.
pub trait FileReferenceIssuerPort: Send + Sync {
    /// Lazily issues one cryptographically random opaque file reference.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted authentication, context, entropy, resource, or
    /// availability failure. Reference collisions are resolved only by the
    /// authoritative catalog insertion boundary.
    fn issue_reference<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileReference, ApiFilesError>>;
}

/// Supplies bounded upload bytes sequentially to a file service.
///
/// Each successful read yields one non-empty bounded [`FileChunk`] or terminal
/// EOF. Implementations must check cancellation and deadline state in the
/// supplied [`RequestContext`] before every actual source read. The first
/// successful `None` makes EOF permanent: later calls must return `None` without
/// checking the context, accessing the source, performing I/O, or causing side effects.
pub trait FileUploadSource: Send {
    /// Lazily reads the next bounded chunk or terminal EOF.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted [`ApiFilesError`] when the context is inactive,
    /// the source fails, or the source violates the bounded chunk contract.
    fn next_chunk<'a>(
        &'a mut self,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<Option<FileChunk>, ApiFilesError>>;
}

/// Receives verified download bytes with explicit sequential backpressure.
///
/// A caller must await each `write_chunk` before supplying the next chunk.
/// `finish` is called exactly once and only after the delivered length and
/// digest match the authoritative descriptor. Any failure after partial
/// delivery terminates the transfer and must never be transparently retried.
pub trait FileDownloadSink: Send {
    /// Lazily writes one verified bounded chunk after the prior write completes.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted [`ApiFilesError`] when the context is inactive,
    /// the sink fails, or sequential delivery cannot continue safely.
    fn write_chunk<'a>(
        &'a mut self,
        chunk: FileChunk,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>>;

    /// Lazily finalizes a fully verified download exactly once.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted [`ApiFilesError`] when the context is inactive
    /// or the sink cannot finalize the verified transfer.
    fn finish<'a>(
        &'a mut self,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>>;
}

/// Provides authenticated, tenant-scoped file operations.
///
/// Every operation must reject an anonymous context as `Unauthenticated` before
/// polling a source or sink or performing work. Possession of a [`FileReference`]
/// is never authorization evidence. Unauthorized, missing, cross-tenant, and
/// tampered reference access are indistinguishable `NotFound` results. Listing
/// is scoped to the authenticated context; foreign or tampered cursors are also
/// `NotFound`.
///
/// Declared and observed length and digest must match before publication or read
/// success, and a partial upload must never become readable. Cancellation or an
/// expired deadline wins until durable commit begins. After a commit attempt has
/// an unknown outcome, `CommitIndeterminate` wins over later cancellation or
/// deadline state and the operation must not be blindly replayed. Only the
/// matching reconciliation method with the same request and idempotency material
/// may resolve that outcome.
pub trait FileServicePort: Send + Sync {
    /// Lazily uploads, verifies, and publishes one complete file.
    ///
    /// # Errors
    ///
    /// Returns stable redacted authentication, visibility, integrity, context,
    /// resource, availability, or indeterminate-commit failures.
    fn upload<'a>(
        &'a self,
        request: FileUploadRequest,
        source: &'a mut dyn FileUploadSource,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDescriptor, ApiFilesError>>;

    /// Lazily resolves an upload whose durable commit outcome was unknown.
    ///
    /// The request must contain exactly the original upload and idempotency
    /// material. This is the only operation permitted to resolve that outcome.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when authentication, request matching,
    /// authoritative lookup, context, or integrity validation fails.
    fn reconcile_upload<'a>(
        &'a self,
        request: &'a FileUploadRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileUploadReconciliation, ApiFilesError>>;

    /// Lazily loads visible authoritative metadata without exposing storage data.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for missing or non-visible references and a stable
    /// redacted error for authentication, context, integrity, or availability failures.
    fn metadata<'a>(
        &'a self,
        reference: &'a FileReference,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDescriptor, ApiFilesError>>;

    /// Lazily lists one authenticated, tenant-scoped metadata page.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for foreign or tampered cursors and a stable redacted
    /// error for authentication, context, integrity, or availability failures.
    fn list<'a>(
        &'a self,
        request: FileListRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileListPage, ApiFilesError>>;

    /// Lazily streams one visible file and returns its verified descriptor.
    ///
    /// The implementation must verify exact length and digest before calling
    /// `finish`. Once any chunk has been delivered, failure terminates the stream
    /// without transparent retry.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for missing or non-visible references and a stable
    /// redacted error for authentication, context, integrity, sink, or availability failures.
    fn content<'a>(
        &'a self,
        reference: &'a FileReference,
        sink: &'a mut dyn FileDownloadSink,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDescriptor, ApiFilesError>>;

    /// Lazily deletes one visible file using its idempotency material.
    ///
    /// # Errors
    ///
    /// Returns stable redacted authentication, visibility, context, availability,
    /// conflict, or indeterminate-commit failures.
    fn delete<'a>(
        &'a self,
        request: FileDeleteRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>>;

    /// Lazily resolves a deletion whose durable commit outcome was unknown.
    ///
    /// The request must contain exactly the original deletion and idempotency
    /// material. This is the only operation permitted to resolve that outcome.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when authentication, request matching,
    /// authoritative lookup, context, or integrity validation fails.
    fn reconcile_delete<'a>(
        &'a self,
        request: &'a FileDeleteRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDeleteReconciliation, ApiFilesError>>;
}

/// Persists authenticated file metadata without content or storage locations.
///
/// A catalog must never receive or retain content bytes or storage paths.
/// `publish` receives an already validated [`FileCatalogRecord`] that binds the
/// exact authenticated owner, upload request, and verified descriptor. `delete`
/// receives the expected descriptor and must compare it with authoritative state
/// to prevent deletion races. The same anonymous, tenant-visibility, cursor,
/// cancellation, deadline, durable-commit, and reconciliation rules documented
/// for [`FileServicePort`] apply here.
pub trait FileCatalogPort: Send + Sync {
    /// Lazily publishes one exact authenticated catalog record.
    ///
    /// Before I/O, an implementation must independently require an authenticated
    /// context and compare its exact principal context with [`FileCatalogRecord::owner`].
    /// An owner mismatch is [`crate::ApiFilesErrorCode::IntegrityFailure`]. The
    /// insert is authoritative: any reference collision is
    /// [`crate::ApiFilesErrorCode::Conflict`] and must never overwrite existing state.
    ///
    /// # Errors
    ///
    /// Returns stable redacted authentication, conflict, integrity, context,
    /// availability, or indeterminate-commit failures.
    fn publish<'a>(
        &'a self,
        record: &'a FileCatalogRecord,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>>;

    /// Lazily resolves an indeterminate metadata publication.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when authentication, request matching,
    /// authoritative lookup, context, or integrity validation fails.
    fn reconcile_publish<'a>(
        &'a self,
        request: &'a FileUploadRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileUploadReconciliation, ApiFilesError>>;

    /// Lazily loads visible authoritative metadata.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for missing or non-visible references and a stable
    /// redacted error for authentication, context, integrity, or availability failures.
    fn metadata<'a>(
        &'a self,
        reference: &'a FileReference,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDescriptor, ApiFilesError>>;

    /// Lazily lists one authenticated, tenant-scoped metadata page.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for foreign or tampered cursors and a stable redacted
    /// error for authentication, context, integrity, or availability failures.
    fn list<'a>(
        &'a self,
        request: FileListRequest,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileListPage, ApiFilesError>>;

    /// Lazily compare-and-deletes exact visible metadata.
    ///
    /// The expected descriptor must match authoritative state before deletion,
    /// preventing a stale request from deleting replaced metadata.
    ///
    /// # Errors
    ///
    /// Returns stable redacted authentication, visibility, conflict, integrity,
    /// context, availability, or indeterminate-commit failures.
    fn delete<'a>(
        &'a self,
        request: &'a FileDeleteRequest,
        expected_descriptor: &'a FileDescriptor,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<(), ApiFilesError>>;

    /// Lazily resolves an indeterminate compare-and-delete operation.
    ///
    /// The exact original request and expected descriptor are required; blind
    /// replay or reconciliation with changed material is forbidden.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when authentication, request matching,
    /// authoritative lookup, context, or integrity validation fails.
    fn reconcile_delete<'a>(
        &'a self,
        request: &'a FileDeleteRequest,
        expected_descriptor: &'a FileDescriptor,
        context: &'a RequestContext,
    ) -> BoxFileFuture<'a, Result<FileDeleteReconciliation, ApiFilesError>>;
}

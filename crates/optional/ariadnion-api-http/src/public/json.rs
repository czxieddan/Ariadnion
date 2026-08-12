// crates/optional/ariadnion-api-http/src/public/json.rs - Bounded native JSON response encoding.
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
//! Shared hard-bounded JSON serialization for native public protocols.

use std::io::{self, Write};

use ariadnion_core::RequestContext;
use axum::body::Bytes;
use serde::Serialize;

use super::protocol::ProtocolFailure;
use super::{ApiHttpError, ApiHttpErrorCode, MAX_PUBLIC_BODY_BYTES};

const JSON_WRITE_CHUNK_BYTES: usize = 16 * 1024;

struct BoundedJsonWriter<'a> {
    bytes: Vec<u8>,
    context: Option<&'a RequestContext>,
}

impl<'a> BoundedJsonWriter<'a> {
    const fn new(context: Option<&'a RequestContext>) -> Self {
        Self {
            bytes: Vec::new(),
            context,
        }
    }

    fn into_bytes(self) -> Bytes {
        Bytes::from(self.bytes)
    }
}

impl Write for BoundedJsonWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        check_context(self.context)?;
        let remaining = MAX_PUBLIC_BODY_BYTES.saturating_sub(self.bytes.len());
        let accepted = buffer.len().min(JSON_WRITE_CHUNK_BYTES).min(remaining);
        if accepted == 0 && !buffer.is_empty() {
            return Err(io::Error::other(
                "native JSON response exceeds its byte limit",
            ));
        }
        self.bytes
            .try_reserve_exact(accepted)
            .map_err(|_| io::Error::other("native JSON response allocation failed"))?;
        self.bytes.extend_from_slice(&buffer[..accepted]);
        check_context(self.context)?;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn serialize_bounded(value: &impl Serialize) -> Result<Bytes, ProtocolFailure> {
    serialize_with_context(value, None)
}

pub(super) fn serialize_bounded_cancellable(
    value: &impl Serialize,
    context: &RequestContext,
) -> Result<Bytes, ProtocolFailure> {
    serialize_with_context(value, Some(context))
}

fn serialize_with_context(
    value: &impl Serialize,
    context: Option<&RequestContext>,
) -> Result<Bytes, ProtocolFailure> {
    let mut writer = BoundedJsonWriter::new(context);
    serde_json::to_writer(&mut writer, value).map_err(|_| internal_failure())?;
    Ok(writer.into_bytes())
}

fn check_context(context: Option<&RequestContext>) -> io::Result<()> {
    context
        .map(RequestContext::check_active)
        .transpose()
        .map_err(|_| io::Error::other("native JSON response context is inactive"))?;
    Ok(())
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

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

use axum::body::Bytes;
use serde::Serialize;

use super::protocol::ProtocolFailure;
use super::{ApiHttpError, ApiHttpErrorCode, MAX_PUBLIC_BODY_BYTES};

struct BoundedJsonWriter {
    bytes: Vec<u8>,
}

impl BoundedJsonWriter {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn into_bytes(self) -> Bytes {
        Bytes::from(self.bytes)
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = MAX_PUBLIC_BODY_BYTES.saturating_sub(self.bytes.len());
        if buffer.len() > remaining {
            return Err(io::Error::other(
                "native JSON response exceeds its byte limit",
            ));
        }
        self.bytes
            .try_reserve_exact(buffer.len())
            .map_err(|_| io::Error::other("native JSON response allocation failed"))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn serialize_bounded(value: &impl Serialize) -> Result<Bytes, ProtocolFailure> {
    let mut writer = BoundedJsonWriter::new();
    serde_json::to_writer(&mut writer, value).map_err(|_| internal_failure())?;
    Ok(writer.into_bytes())
}

const fn internal_failure() -> ProtocolFailure {
    ProtocolFailure::Http(ApiHttpError::new(ApiHttpErrorCode::Internal))
}

// crates/optional/ariadnion-api-stream/src/bridge/receive.rs - Rust source for Ariadnion.
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
//! Bounded receive-task polling for the native SSE bridge.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use ariadnion_api_domain::ServiceStreamEvent;
use ariadnion_api_http::ApiHttpError;
use ariadnion_core::{EventSubscriber, ReceiveOutcome};
use bytes::Bytes;
use tokio::sync::OwnedSemaphorePermit;

use super::{ReceiveTask, SseByteStream};

impl SseByteStream {
    pub(super) fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        let mut receive = match self.receive.take() {
            Some(receive) => receive,
            None => return self.internal_terminal(None),
        };
        match Pin::new(&mut receive).poll(context) {
            Poll::Pending => self.retain_receive(receive),
            Poll::Ready(Ok((subscriber, outcome, permit))) => {
                self.complete_receive(subscriber, outcome, permit)
            }
            Poll::Ready(Err(_)) => self.internal_terminal(None),
        }
    }

    fn retain_receive(
        &mut self,
        receive: ReceiveTask,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        self.receive = Some(receive);
        Poll::Pending
    }

    fn complete_receive(
        &mut self,
        subscriber: EventSubscriber<ServiceStreamEvent>,
        outcome: ReceiveOutcome<ServiceStreamEvent>,
        permit: OwnedSemaphorePermit,
    ) -> Poll<Option<Result<Bytes, ApiHttpError>>> {
        self.subscriber = Some(subscriber);
        self.permit = Some(permit);
        self.handle_outcome(outcome)
    }
}

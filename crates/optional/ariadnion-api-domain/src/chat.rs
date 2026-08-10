// crates/optional/ariadnion-api-domain/src/chat.rs - Chat message contracts for Ariadnion.
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
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Bounded, ordered chat messages independent of public protocol DTOs.

use std::fmt::{self, Debug, Formatter};

use crate::error::{ApiDomainError, invalid_argument, limit_exceeded};

/// Maximum number of messages accepted by one chat request.
pub const MAX_CHAT_MESSAGES: usize = 128;
/// Maximum encoded UTF-8 bytes accepted in one chat message.
pub const MAX_CHAT_MESSAGE_CONTENT_BYTES: usize = 262_144;
/// Maximum aggregate encoded UTF-8 bytes accepted across chat messages.
pub const MAX_CHAT_MESSAGES_BYTES: usize = 1_048_576;

/// The semantic author of one ordered chat message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ChatRole {
    /// An application-supplied instruction with priority over user messages.
    Developer,
    /// A system instruction retained for compatible provider mappings.
    System,
    /// End-user supplied content.
    User,
    /// Assistant content supplied as conversation history.
    Assistant,
}

/// Bounded chat message content whose diagnostics never expose the text.
#[derive(Clone, Eq, PartialEq)]
pub struct ChatMessageContent(Box<str>);

impl ChatMessageContent {
    /// Validates and copies one chat message's text content.
    ///
    /// Empty text is valid. Content must not exceed 262,144 UTF-8 bytes or
    /// contain NUL. Other Unicode text is preserved without normalization.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::LimitExceeded`] when the byte bound
    /// is exceeded and [`crate::ApiDomainErrorCode::InvalidArgument`] for NUL.
    pub fn new(value: &str) -> Result<Self, ApiDomainError> {
        validate_content(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated text to a trusted service implementation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ChatMessageContent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatMessageContent")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// One validated role and content pair in a chat request.
#[derive(Clone, Eq, PartialEq)]
pub struct ChatMessage {
    role: ChatRole,
    content: ChatMessageContent,
}

impl ChatMessage {
    /// Creates a message from an explicit role and validated content.
    #[must_use]
    pub const fn new(role: ChatRole, content: ChatMessageContent) -> Self {
        Self { role, content }
    }

    /// Returns the semantic author role.
    #[must_use]
    pub const fn role(&self) -> ChatRole {
        self.role
    }

    /// Returns the validated message content.
    #[must_use]
    pub const fn content(&self) -> &ChatMessageContent {
        &self.content
    }
}

impl Debug for ChatMessage {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatMessage")
            .field("role", &self.role)
            .field("content", &self.content)
            .finish()
    }
}

/// A nonempty, bounded, ordered chat history.
#[derive(Clone, Eq, PartialEq)]
pub struct ChatMessages {
    messages: Box<[ChatMessage]>,
    encoded_bytes: usize,
}

impl ChatMessages {
    /// Validates and owns one ordered chat history.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApiDomainErrorCode::InvalidArgument`] for an empty
    /// history and [`crate::ApiDomainErrorCode::LimitExceeded`] when the count,
    /// aggregate byte budget, or checked byte sum is exceeded.
    pub fn new(messages: Vec<ChatMessage>) -> Result<Self, ApiDomainError> {
        let encoded_bytes = validate_messages(&messages)?;
        Ok(Self {
            messages: messages.into_boxed_slice(),
            encoded_bytes,
        })
    }

    /// Returns the ordered messages.
    #[must_use]
    pub fn as_slice(&self) -> &[ChatMessage] {
        &self.messages
    }

    /// Returns the number of messages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Returns whether the history is empty.
    ///
    /// Valid instances are never empty; this method supports ordinary slice-like
    /// inspection without requiring callers to depend on that invariant.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Returns aggregate encoded UTF-8 content bytes.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

impl Debug for ChatMessages {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatMessages")
            .field("messages", &self.messages.len())
            .field("encoded_bytes", &self.encoded_bytes)
            .finish_non_exhaustive()
    }
}

fn validate_content(value: &str) -> Result<(), ApiDomainError> {
    if value.len() > MAX_CHAT_MESSAGE_CONTENT_BYTES {
        return Err(limit_exceeded());
    }
    if value.contains('\0') {
        return Err(invalid_argument());
    }
    Ok(())
}

fn validate_messages(messages: &[ChatMessage]) -> Result<usize, ApiDomainError> {
    if messages.is_empty() {
        return Err(invalid_argument());
    }
    if messages.len() > MAX_CHAT_MESSAGES {
        return Err(limit_exceeded());
    }
    let encoded_bytes = checked_message_bytes(messages)?;
    if encoded_bytes > MAX_CHAT_MESSAGES_BYTES {
        return Err(limit_exceeded());
    }
    Ok(encoded_bytes)
}

fn checked_message_bytes(messages: &[ChatMessage]) -> Result<usize, ApiDomainError> {
    messages.iter().try_fold(0usize, |total, message| {
        total
            .checked_add(message.content().as_str().len())
            .ok_or_else(limit_exceeded)
    })
}

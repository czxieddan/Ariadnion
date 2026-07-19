//! Versioned, bounded configuration domain values.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};

use ariadnion_core::{CapabilityId, CoreError, ErrorCode, ModuleVersion};

const MAX_FIELDS: usize = 256;
const MAX_KEY_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 4096;

/// A validated dotted configuration key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConfigKey(Box<str>);

impl ConfigKey {
    /// Parses an ASCII dotted key with a 128-byte upper bound.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        validate_key(value)?;
        Ok(Self(value.into()))
    }

    /// Returns the validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ConfigKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded Unicode text value with control characters rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigText(Box<str>);

impl ConfigText {
    /// Creates a text value of at most 4096 UTF-8 bytes.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_text(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The stable scalar kinds accepted by the initial configuration path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigValueKind {
    /// A boolean value.
    Boolean,
    /// A signed 64-bit integer.
    Integer,
    /// Bounded Unicode text.
    Text,
}

/// A strongly typed scalar configuration value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigValue {
    /// A boolean value.
    Boolean(bool),
    /// A signed 64-bit integer.
    Integer(i64),
    /// Bounded Unicode text.
    Text(ConfigText),
}

impl ConfigValue {
    /// Returns the stable value kind.
    #[must_use]
    pub const fn kind(&self) -> ConfigValueKind {
        match self {
            Self::Boolean(_) => ConfigValueKind::Boolean,
            Self::Integer(_) => ConfigValueKind::Integer,
            Self::Text(_) => ConfigValueKind::Text,
        }
    }
}

/// One key/value field in a configuration document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigField {
    key: ConfigKey,
    value: ConfigValue,
}

impl ConfigField {
    /// Creates a typed field.
    #[must_use]
    pub const fn new(key: ConfigKey, value: ConfigValue) -> Self {
        Self { key, value }
    }

    /// Returns the field key.
    #[must_use]
    pub const fn key(&self) -> &ConfigKey {
        &self.key
    }

    /// Returns the field value.
    #[must_use]
    pub const fn value(&self) -> &ConfigValue {
        &self.value
    }
}

/// An immutable, versioned configuration document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigDocument {
    schema_id: CapabilityId,
    schema_version: ModuleVersion,
    version: u64,
    fields: Vec<ConfigField>,
}

impl ConfigDocument {
    /// Creates a document and rejects duplicate keys or invalid version zero.
    pub fn new(
        schema_id: CapabilityId,
        schema_version: ModuleVersion,
        version: u64,
        mut fields: Vec<ConfigField>,
    ) -> Result<Self, CoreError> {
        validate_document(version, &fields)?;
        fields.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(Self {
            schema_id,
            schema_version,
            version,
            fields,
        })
    }

    /// Returns the schema identity.
    #[must_use]
    pub const fn schema_id(&self) -> &CapabilityId {
        &self.schema_id
    }

    /// Returns the immutable schema version used to interpret this document.
    #[must_use]
    pub const fn schema_version(&self) -> ModuleVersion {
        self.schema_version
    }

    /// Returns the monotonic document version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns fields in deterministic key order.
    #[must_use]
    pub fn fields(&self) -> &[ConfigField] {
        &self.fields
    }

    /// Returns a field by typed key.
    #[must_use]
    pub fn get(&self, key: &ConfigKey) -> Option<&ConfigValue> {
        self.fields
            .binary_search_by(|field| field.key.cmp(key))
            .ok()
            .map(|index| self.fields[index].value())
    }

    /// Copies the same schema and fields into a new immutable version.
    ///
    /// This supports rollback-as-publication without reusing an earlier
    /// version number. Version zero is rejected and the original document is
    /// left unchanged.
    pub fn clone_at_version(&self, version: u64) -> Result<Self, CoreError> {
        if version == 0 {
            return Err(CoreError::from_code(ErrorCode::InvalidArgument)
                .with_internal_context("configuration document version must be positive"));
        }
        Ok(Self {
            schema_id: self.schema_id.clone(),
            schema_version: self.schema_version,
            version,
            fields: self.fields.clone(),
        })
    }
}

/// A draft tied to the exact published version it was derived from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigDraft {
    base_version: u64,
    document: ConfigDocument,
}

impl ConfigDraft {
    /// Creates a draft whose document must be the next version.
    pub fn new(base_version: u64, document: ConfigDocument) -> Result<Self, CoreError> {
        let expected = base_version.checked_add(1).ok_or_else(|| {
            CoreError::from_code(ErrorCode::ResourceExhausted)
                .with_internal_context("configuration version exhausted")
        })?;
        if document.version() != expected {
            return Err(CoreError::from_code(ErrorCode::Conflict)
                .with_internal_context("draft version is not the next published version"));
        }
        Ok(Self {
            base_version,
            document,
        })
    }

    /// Returns the published version used as the draft base.
    #[must_use]
    pub const fn base_version(&self) -> u64 {
        self.base_version
    }

    /// Returns the immutable draft document.
    #[must_use]
    pub const fn document(&self) -> &ConfigDocument {
        &self.document
    }

    /// Consumes the draft and returns its document.
    #[must_use]
    pub fn into_document(self) -> ConfigDocument {
        self.document
    }
}

/// The type of a configuration field change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigChangeKind {
    /// A key was added.
    Added,
    /// A key was removed.
    Removed,
    /// A key retained its identity but changed value.
    Modified,
}

/// One safe configuration change entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigChange {
    key: ConfigKey,
    kind: ConfigChangeKind,
}

impl ConfigChange {
    /// Returns the changed key.
    #[must_use]
    pub const fn key(&self) -> &ConfigKey {
        &self.key
    }

    /// Returns the change kind.
    #[must_use]
    pub const fn kind(&self) -> ConfigChangeKind {
        self.kind
    }
}

/// A deterministic diff that never includes secret values.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigDiff {
    changes: Vec<ConfigChange>,
}

impl ConfigDiff {
    /// Compares two documents by key and value without exposing values.
    #[must_use]
    pub fn between(previous: &ConfigDocument, next: &ConfigDocument) -> Self {
        let mut changes = Vec::new();
        collect_previous_changes(previous, next, &mut changes);
        collect_added_changes(previous, next, &mut changes);
        changes.sort_by(|left, right| left.key.cmp(&right.key));
        Self { changes }
    }

    /// Returns the ordered change entries.
    #[must_use]
    pub fn changes(&self) -> &[ConfigChange] {
        &self.changes
    }
}

fn validate_key(value: &str) -> Result<(), CoreError> {
    if value.is_empty() || value.len() > MAX_KEY_BYTES || !value.is_ascii() {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("configuration key is outside its bound"));
    }
    if value.bytes().any(is_invalid_key_byte) {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("configuration key contains an invalid byte"));
    }
    Ok(())
}

fn is_invalid_key_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_')
}

fn validate_text(value: &str) -> Result<(), CoreError> {
    if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("configuration text is outside its bound"));
    }
    Ok(())
}

fn validate_document(version: u64, fields: &[ConfigField]) -> Result<(), CoreError> {
    if version == 0 || fields.len() > MAX_FIELDS {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("configuration document is outside its bound"));
    }
    let unique = fields
        .iter()
        .map(ConfigField::key)
        .collect::<BTreeSet<_>>();
    if unique.len() != fields.len() {
        return Err(CoreError::from_code(ErrorCode::Conflict)
            .with_internal_context("configuration document contains duplicate keys"));
    }
    Ok(())
}

fn collect_previous_changes(
    previous: &ConfigDocument,
    next: &ConfigDocument,
    changes: &mut Vec<ConfigChange>,
) {
    for field in previous.fields() {
        let kind = match next.get(field.key()) {
            None => Some(ConfigChangeKind::Removed),
            Some(value) if value != field.value() => Some(ConfigChangeKind::Modified),
            Some(_) => None,
        };
        if let Some(kind) = kind {
            changes.push(ConfigChange {
                key: field.key().clone(),
                kind,
            });
        }
    }
}

fn collect_added_changes(
    previous: &ConfigDocument,
    next: &ConfigDocument,
    changes: &mut Vec<ConfigChange>,
) {
    for field in next.fields() {
        if previous.get(field.key()).is_none() {
            changes.push(ConfigChange {
                key: field.key().clone(),
                kind: ConfigChangeKind::Added,
            });
        }
    }
}

//! Versioned configuration schemas and structured validation reports.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeSet;

use ariadnion_config_domain::{ConfigDocument, ConfigKey, ConfigValueKind};
use ariadnion_core::{CapabilityId, CoreError, ErrorCode, ModuleVersion};

const MAX_FIELD_RULES: usize = 256;
const MAX_CROSS_RULES: usize = 128;
const MAX_ISSUES: usize = 256;

/// A typed rule for one known field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldRule {
    key: ConfigKey,
    kind: ConfigValueKind,
    required: bool,
}

impl FieldRule {
    /// Creates a field rule.
    #[must_use]
    pub const fn new(key: ConfigKey, kind: ConfigValueKind, required: bool) -> Self {
        Self {
            key,
            kind,
            required,
        }
    }

    /// Returns the field key.
    #[must_use]
    pub const fn key(&self) -> &ConfigKey {
        &self.key
    }

    /// Returns the required value kind.
    #[must_use]
    pub const fn kind(&self) -> ConfigValueKind {
        self.kind
    }

    /// Returns whether the field is required.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }
}

/// A deterministic cross-field constraint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossFieldRule {
    /// Both fields must be present or absent together.
    RequiresTogether {
        /// The first field participating in the constraint.
        first: ConfigKey,
        /// The second field participating in the constraint.
        second: ConfigKey,
    },
    /// The two fields cannot be present together.
    Conflicts {
        /// The first field participating in the constraint.
        first: ConfigKey,
        /// The second field participating in the constraint.
        second: ConfigKey,
    },
}

/// Stable validation issue codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationIssueCode {
    /// The document targets another schema.
    SchemaMismatch,
    /// The document version is outside the schema's supported major.
    VersionMismatch,
    /// A field is not declared by the schema.
    UnknownField,
    /// A required field is absent.
    MissingField,
    /// A field has the wrong scalar kind.
    TypeMismatch,
    /// A cross-field constraint failed.
    CrossFieldViolation,
    /// The bounded issue report reached its limit.
    IssueLimitReached,
}

/// One safe validation issue without field values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationIssue {
    code: ValidationIssueCode,
    key: Option<ConfigKey>,
}

impl ValidationIssue {
    /// Creates an issue for an optional field key.
    #[must_use]
    pub const fn new(code: ValidationIssueCode, key: Option<ConfigKey>) -> Self {
        Self { code, key }
    }

    /// Returns the stable issue code.
    #[must_use]
    pub const fn code(&self) -> ValidationIssueCode {
        self.code
    }

    /// Returns the affected field key, when applicable.
    #[must_use]
    pub const fn key(&self) -> Option<&ConfigKey> {
        self.key.as_ref()
    }
}

/// A bounded validation failure report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidationReport {
    issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    /// Returns all issues in deterministic validation order.
    #[must_use]
    pub fn issues(&self) -> &[ValidationIssue] {
        &self.issues
    }

    /// Returns whether validation found no issues.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    fn push(&mut self, issue: ValidationIssue) {
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(issue);
            return;
        }
        if let Some(last) = self.issues.last_mut() {
            *last = ValidationIssue::new(ValidationIssueCode::IssueLimitReached, None);
        }
    }
}

/// A document proven to match one immutable schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConfig {
    document: ConfigDocument,
}

impl ValidatedConfig {
    /// Returns the validated document.
    #[must_use]
    pub const fn document(&self) -> &ConfigDocument {
        &self.document
    }

    /// Consumes the wrapper and returns the validated document.
    #[must_use]
    pub fn into_document(self) -> ConfigDocument {
        self.document
    }
}

/// An immutable schema with field and cross-field rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigSchema {
    id: CapabilityId,
    version: ModuleVersion,
    fields: Vec<FieldRule>,
    cross_rules: Vec<CrossFieldRule>,
}

impl ConfigSchema {
    /// Creates a bounded schema and rejects duplicate field rules.
    pub fn new(
        id: CapabilityId,
        version: ModuleVersion,
        mut fields: Vec<FieldRule>,
        cross_rules: Vec<CrossFieldRule>,
    ) -> Result<Self, CoreError> {
        validate_rule_counts(fields.len(), cross_rules.len())?;
        validate_unique_fields(&fields)?;
        validate_cross_keys(&fields, &cross_rules)?;
        fields.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(Self {
            id,
            version,
            fields,
            cross_rules,
        })
    }

    /// Returns the stable schema identity.
    #[must_use]
    pub const fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Returns the schema version.
    #[must_use]
    pub const fn version(&self) -> ModuleVersion {
        self.version
    }

    /// Validates a document and returns structured issues on failure.
    pub fn validate(&self, document: ConfigDocument) -> Result<ValidatedConfig, ValidationReport> {
        let mut report = ValidationReport::default();
        validate_header(self, &document, &mut report);
        validate_fields(self, &document, &mut report);
        validate_required(self, &document, &mut report);
        validate_cross_rules(self, &document, &mut report);
        if report.is_empty() {
            Ok(ValidatedConfig { document })
        } else {
            Err(report)
        }
    }

    fn field_rule(&self, key: &ConfigKey) -> Option<&FieldRule> {
        self.fields
            .binary_search_by(|field| field.key.cmp(key))
            .ok()
            .map(|index| &self.fields[index])
    }
}

fn validate_rule_counts(fields: usize, cross_rules: usize) -> Result<(), CoreError> {
    if fields > MAX_FIELD_RULES || cross_rules > MAX_CROSS_RULES {
        return Err(CoreError::from_code(ErrorCode::ResourceExhausted)
            .with_internal_context("configuration schema rule limit reached"));
    }
    Ok(())
}

fn validate_unique_fields(fields: &[FieldRule]) -> Result<(), CoreError> {
    let unique = fields.iter().map(FieldRule::key).collect::<BTreeSet<_>>();
    if unique.len() != fields.len() {
        return Err(CoreError::from_code(ErrorCode::Conflict)
            .with_internal_context("configuration schema contains duplicate field rules"));
    }
    Ok(())
}

fn validate_cross_keys(
    fields: &[FieldRule],
    cross_rules: &[CrossFieldRule],
) -> Result<(), CoreError> {
    for rule in cross_rules {
        let (first, second) = cross_rule_keys(rule);
        if !contains_field(fields, first) || !contains_field(fields, second) {
            return Err(CoreError::from_code(ErrorCode::InvalidArgument)
                .with_internal_context("cross-field rule references an unknown key"));
        }
    }
    Ok(())
}

fn cross_rule_keys(rule: &CrossFieldRule) -> (&ConfigKey, &ConfigKey) {
    match rule {
        CrossFieldRule::RequiresTogether { first, second }
        | CrossFieldRule::Conflicts { first, second } => (first, second),
    }
}

fn contains_field(fields: &[FieldRule], key: &ConfigKey) -> bool {
    fields.iter().any(|field| field.key() == key)
}

fn validate_header(
    schema: &ConfigSchema,
    document: &ConfigDocument,
    report: &mut ValidationReport,
) {
    if schema.id() != document.schema_id() {
        report.push(ValidationIssue::new(
            ValidationIssueCode::SchemaMismatch,
            None,
        ));
    }
    if schema.version() != document.schema_version() {
        report.push(ValidationIssue::new(
            ValidationIssueCode::VersionMismatch,
            None,
        ));
    }
}

fn validate_fields(
    schema: &ConfigSchema,
    document: &ConfigDocument,
    report: &mut ValidationReport,
) {
    for field in document.fields() {
        let Some(rule) = schema.field_rule(field.key()) else {
            report.push(ValidationIssue::new(
                ValidationIssueCode::UnknownField,
                Some(field.key().clone()),
            ));
            continue;
        };
        if rule.kind() != field.value().kind() {
            report.push(ValidationIssue::new(
                ValidationIssueCode::TypeMismatch,
                Some(field.key().clone()),
            ));
        }
    }
}

fn validate_required(
    schema: &ConfigSchema,
    document: &ConfigDocument,
    report: &mut ValidationReport,
) {
    for rule in &schema.fields {
        if rule.is_required() && document.get(rule.key()).is_none() {
            report.push(ValidationIssue::new(
                ValidationIssueCode::MissingField,
                Some(rule.key().clone()),
            ));
        }
    }
}

fn validate_cross_rules(
    schema: &ConfigSchema,
    document: &ConfigDocument,
    report: &mut ValidationReport,
) {
    for rule in &schema.cross_rules {
        if cross_rule_violated(rule, document) {
            let (first, _) = cross_rule_keys(rule);
            report.push(ValidationIssue::new(
                ValidationIssueCode::CrossFieldViolation,
                Some(first.clone()),
            ));
        }
    }
}

fn cross_rule_violated(rule: &CrossFieldRule, document: &ConfigDocument) -> bool {
    let (first, second) = cross_rule_keys(rule);
    let first_present = document.get(first).is_some();
    let second_present = document.get(second).is_some();
    match rule {
        CrossFieldRule::RequiresTogether { .. } => first_present != second_present,
        CrossFieldRule::Conflicts { .. } => first_present && second_present,
    }
}

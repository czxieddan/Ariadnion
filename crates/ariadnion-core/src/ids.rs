//! Bounded identifiers and contract versions used across module boundaries.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use crate::error::{CoreError, ErrorCode};

const MODULE_ID_LIMIT: usize = 160;
const CAPABILITY_ID_LIMIT: usize = 128;
const CONTEXT_ID_LIMIT: usize = 128;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BoundedId(Box<str>);

impl BoundedId {
    fn parse(value: &str, limit: usize) -> Result<Self, CoreError> {
        validate_common_id(value, limit)?;
        Ok(Self(value.into()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn invalid_id(reason: &'static str) -> CoreError {
    CoreError::from_code(ErrorCode::InvalidArgument).with_internal_context(reason)
}

fn validate_common_id(value: &str, limit: usize) -> Result<(), CoreError> {
    validate_id_shape(value, limit)?;
    validate_id_alphabet(value)?;
    Ok(())
}

fn validate_id_shape(value: &str, limit: usize) -> Result<(), CoreError> {
    if value.is_empty() {
        return Err(invalid_id("identifier is empty"));
    }
    if value.len() > limit {
        return Err(invalid_id("identifier exceeds its byte limit"));
    }
    Ok(())
}

fn validate_id_alphabet(value: &str) -> Result<(), CoreError> {
    if !value.is_ascii() {
        return Err(invalid_id("identifier must be ASCII"));
    }
    if value.bytes().any(is_disallowed_id_byte) {
        return Err(invalid_id("identifier contains a disallowed byte"));
    }
    Ok(())
}

fn is_disallowed_id_byte(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_' | b':')
}

fn validate_dotted_id(value: &str, limit: usize) -> Result<(), CoreError> {
    validate_common_id(value, limit)?;
    let mut segment_count = 0_usize;
    for segment in value.split('.') {
        validate_dotted_segment(segment)?;
        segment_count = segment_count.saturating_add(1);
    }
    if segment_count < 2 {
        return Err(invalid_id("dotted identifier needs at least two segments"));
    }
    Ok(())
}

fn validate_dotted_segment(segment: &str) -> Result<(), CoreError> {
    if segment.is_empty() {
        return Err(invalid_id("dotted identifier contains an empty segment"));
    }
    let starts_with_letter = segment
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_lowercase());
    if !starts_with_letter {
        return Err(invalid_id(
            "dotted identifier segment must start with a letter",
        ));
    }
    if segment.bytes().any(is_disallowed_segment_byte) {
        return Err(invalid_id(
            "dotted identifier segment contains a disallowed byte",
        ));
    }
    Ok(())
}

fn is_disallowed_segment_byte(byte: u8) -> bool {
    !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-' && byte != b'_'
}

/// A validated reverse-domain module identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModuleId(BoundedId);

impl ModuleId {
    /// Parses a reverse-domain identifier with a 160-byte upper bound.
    ///
    /// The value must be ASCII, contain at least two non-empty dotted segments,
    /// start each segment with a lower-case letter, and use only lower-case
    /// letters, digits, hyphens, or underscores. Invalid input returns
    /// [`ErrorCode::InvalidArgument`] without echoing the rejected value.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        validate_dotted_id(value, MODULE_ID_LIMIT)?;
        Ok(Self(BoundedId(value.into())))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ModuleId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ModuleId")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for ModuleId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ModuleId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl AsRef<str> for ModuleId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A validated stable capability identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityId(BoundedId);

impl CapabilityId {
    /// Parses a dotted capability identifier with a 128-byte upper bound.
    ///
    /// The same ASCII and segment rules as [`ModuleId`] apply. Empty, overlong,
    /// malformed, or control-containing values return
    /// [`ErrorCode::InvalidArgument`] without including input in the error.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        validate_dotted_id(value, CAPABILITY_ID_LIMIT)?;
        Ok(Self(BoundedId(value.into())))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for CapabilityId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CapabilityId")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for CapabilityId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CapabilityId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl AsRef<str> for CapabilityId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

macro_rules! define_context_id {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(BoundedId);

        impl $name {
            /// Parses a non-empty ASCII identifier with a 128-byte upper bound.
            ///
            /// Invalid or control-containing input returns
            /// [`ErrorCode::InvalidArgument`] without echoing the value.
            pub fn parse(value: &str) -> Result<Self, CoreError> {
                BoundedId::parse(value, CONTEXT_ID_LIMIT).map(Self)
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = CoreError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
    };
}

define_context_id!(TenantId, "A validated tenant identifier.");
define_context_id!(RequestId, "A validated request correlation identifier.");
define_context_id!(TraceId, "A validated distributed trace identifier.");
define_context_id!(
    PrincipalId,
    "A validated authenticated principal identifier."
);

/// A semantic module implementation version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModuleVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl ModuleVersion {
    /// Creates a semantic module version.
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns the major component.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the minor component.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    /// Returns the patch component.
    #[must_use]
    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl Display for ModuleVersion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for ModuleVersion {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_module_version(value)
    }
}

impl AsRef<ModuleVersion> for ModuleVersion {
    fn as_ref(&self) -> &ModuleVersion {
        self
    }
}

fn parse_module_version(value: &str) -> Result<ModuleVersion, CoreError> {
    let mut components = value.split('.');
    let major = parse_version_component(components.next())?;
    let minor = parse_version_component(components.next())?;
    let patch = parse_version_component(components.next())?;
    if components.next().is_some() {
        return Err(invalid_id("module version has too many components"));
    }
    Ok(ModuleVersion::new(major, minor, patch))
}

fn parse_version_component(component: Option<&str>) -> Result<u16, CoreError> {
    let value = component.ok_or_else(|| invalid_id("module version component is missing"))?;
    if value.is_empty() {
        return Err(invalid_id("module version component is empty"));
    }
    value
        .parse::<u16>()
        .map_err(|_| invalid_id("module version component is invalid"))
}

/// The combined Rust contract and component-world ABI version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AbiVersion {
    rust_contract: ModuleVersion,
    component_world_major: u16,
}

impl AbiVersion {
    /// Creates a combined ABI version.
    #[must_use]
    pub const fn new(rust_contract: ModuleVersion, component_world_major: u16) -> Self {
        Self {
            rust_contract,
            component_world_major,
        }
    }

    /// Returns the Rust contract version.
    #[must_use]
    pub const fn rust_contract(self) -> ModuleVersion {
        self.rust_contract
    }

    /// Returns the component-world major version.
    #[must_use]
    pub const fn component_world_major(self) -> u16 {
        self.component_world_major
    }
}

impl Display for AbiVersion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "rust-{}/wit-{}",
            self.rust_contract, self.component_world_major
        )
    }
}

impl FromStr for AbiVersion {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (rust_part, wit_part) = value
            .strip_prefix("rust-")
            .and_then(|remainder| remainder.split_once("/wit-"))
            .ok_or_else(|| invalid_id("ABI version prefix is invalid"))?;
        let rust_contract = ModuleVersion::from_str(rust_part)?;
        let component_world_major = wit_part
            .parse::<u16>()
            .map_err(|_| invalid_id("ABI component-world version is invalid"))?;
        Ok(Self::new(rust_contract, component_world_major))
    }
}

impl AsRef<AbiVersion> for AbiVersion {
    fn as_ref(&self) -> &AbiVersion {
        self
    }
}

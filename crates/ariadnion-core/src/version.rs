//! Build metadata and compatibility information for the core runtime.

use std::fmt::{self, Display, Formatter};

use crate::ids::{AbiVersion, ModuleVersion};

/// The ABI version consumed by statically linked modules.
pub const CORE_ABI_VERSION: AbiVersion = AbiVersion::new(ModuleVersion::new(1, 0, 0), 1);

/// Identifies where a build timestamp was obtained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildTimeSource {
    /// A reproducible timestamp supplied by the build environment.
    SourceDateEpoch,
    /// An explicit Ariadnion build timestamp supplied by the build environment.
    AriadnionBuildTimestamp,
    /// No timestamp was supplied, so the build remains intentionally unspecified.
    Unavailable,
}

impl BuildTimeSource {
    /// Returns the stable display name for this source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceDateEpoch => "SOURCE_DATE_EPOCH",
            Self::AriadnionBuildTimestamp => "ARIADNION_BUILD_TIMESTAMP",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Immutable metadata compiled into a core binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildInfo {
    package_name: &'static str,
    package_version: &'static str,
    commit: &'static str,
    build_timestamp: Option<&'static str>,
    build_time_source: BuildTimeSource,
}

impl BuildInfo {
    /// Returns metadata compiled from package and reproducible build variables.
    #[must_use]
    pub const fn current() -> Self {
        let (build_timestamp, build_time_source) = build_time_metadata();
        Self {
            package_name: env!("CARGO_PKG_NAME"),
            package_version: env!("CARGO_PKG_VERSION"),
            commit: build_commit(),
            build_timestamp,
            build_time_source,
        }
    }

    /// Returns the package name.
    #[must_use]
    pub const fn package_name(self) -> &'static str {
        self.package_name
    }

    /// Returns the package version.
    #[must_use]
    pub const fn package_version(self) -> &'static str {
        self.package_version
    }

    /// Returns the source commit or `unknown` when no commit was injected.
    #[must_use]
    pub const fn commit(self) -> &'static str {
        self.commit
    }

    /// Returns the operating-system and architecture pair used for the build.
    #[must_use]
    pub fn platform(self) -> String {
        format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
    }

    /// Returns the compiled core ABI version.
    #[must_use]
    pub const fn core_abi_version(self) -> AbiVersion {
        CORE_ABI_VERSION
    }

    /// Returns the reproducible build timestamp, when one was supplied.
    #[must_use]
    pub const fn build_timestamp(self) -> Option<&'static str> {
        self.build_timestamp
    }

    /// Returns the source name used for the build timestamp.
    #[must_use]
    pub const fn build_time_source(self) -> BuildTimeSource {
        self.build_time_source
    }

    /// Returns a stable one-line diagnostic representation.
    #[must_use]
    pub fn diagnostic_line(self) -> String {
        let timestamp = self.build_timestamp.unwrap_or("unknown");
        format!(
            "{} version={} core_abi={} platform={} commit={} build_time_source={} build_time={}",
            self.package_name,
            self.package_version,
            self.core_abi_version(),
            self.platform(),
            self.commit,
            self.build_time_source.as_str(),
            timestamp
        )
    }
}

const fn build_time_metadata() -> (Option<&'static str>, BuildTimeSource) {
    if let Some(value) = source_date_epoch() {
        return (Some(value), BuildTimeSource::SourceDateEpoch);
    }
    if let Some(value) = explicit_build_timestamp() {
        return (Some(value), BuildTimeSource::AriadnionBuildTimestamp);
    }
    (None, BuildTimeSource::Unavailable)
}

const fn build_commit() -> &'static str {
    match option_env!("ARIADNION_BUILD_COMMIT") {
        Some(value) if is_hex_commit(value) => value,
        _ => "unknown",
    }
}

const fn source_date_epoch() -> Option<&'static str> {
    match option_env!("SOURCE_DATE_EPOCH") {
        Some(value) if is_ascii_digits(value, 20) => Some(value),
        _ => None,
    }
}

const fn explicit_build_timestamp() -> Option<&'static str> {
    match option_env!("ARIADNION_BUILD_TIMESTAMP") {
        Some(value) if is_safe_graphic(value, 40) => Some(value),
        _ => None,
    }
}

const fn is_ascii_digits(value: &str, maximum: usize) -> bool {
    if !has_bounded_length(value, 1, maximum) {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
        index += 1;
    }
    true
}

const fn is_safe_graphic(value: &str, maximum: usize) -> bool {
    if !has_bounded_length(value, 1, maximum) {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_graphic() {
            return false;
        }
        index += 1;
    }
    true
}

const fn is_hex_commit(value: &str) -> bool {
    if !has_bounded_length(value, 7, 64) {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_hexdigit() {
            return false;
        }
        index += 1;
    }
    true
}

const fn has_bounded_length(value: &str, minimum: usize, maximum: usize) -> bool {
    value.len() >= minimum && value.len() <= maximum
}

impl Default for BuildInfo {
    fn default() -> Self {
        Self::current()
    }
}

impl Display for BuildInfo {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostic_line())
    }
}

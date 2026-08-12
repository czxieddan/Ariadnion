// tools/ariadnion-xtask/src/rnmdb_policy.rs - Rust source for Ariadnion.
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
//! Strict textual gates for the fixed RNovModularDB AHCL dependency boundary.

const DEPENDENCY_TABLE_HEADER: &str = "[rnmdb_ahcl_dependency]";
const LEGACY_AUTHORIZATION_TABLE_HEADER: &str = "[rnmdb_commercial_authorization]";
const CANONICAL_DEPENDENCY_TABLE: &str = concat!(
    "[rnmdb_ahcl_dependency]\n",
    "selected_license = \"LicenseRef-AHCL-1.0\"\n",
    "license_copy = \"AHCL/AHCL-1.0.md\"\n",
    "additional_restrictions = \"none\"\n",
    "repository = \"https://github.com/czxieddan/RNovModularDB.git\"\n",
    "commit = \"f20040a127a56ec8c37b3398283df36f024a1dd2\"\n",
    "package_prefix = \"rnmdb-\"\n",
    "packages = [\"rnmdb-common\", \"rnmdb-types\", \"rnmdb-sql\", \"rnmdb-planner\", \"rnmdb-executor\", \"rnmdb-txn\", \"rnmdb-index\", \"rnmdb-fts\", \"rnmdb-catalog\", \"rnmdb-storage\", \"rnmdb-udf\", \"rnmdb-security\", \"rnmdb-instance\", \"rnmdb-server\", \"rnmdb-cli\"]\n\n",
);
const POLICY_KEYS: [&str; 7] = [
    "selected_license",
    "license_copy",
    "additional_restrictions",
    "repository",
    "commit",
    "package_prefix",
    "packages",
];
const PACKAGE_MARKERS: [(&str, char); 6] = [
    ("package=\"", '"'),
    ("package='", '\''),
    ("\"package\"=\"", '"'),
    ("\"package\"='", '\''),
    ("'package'=\"", '"'),
    ("'package'='", '\''),
];

pub(crate) fn canonical_dependency_table(content: &str) -> Result<&str, String> {
    validate_no_multiline_strings(content)?;
    let start = find_unique_table_start(content)?;
    let end = find_table_end(content, start);
    let table = &content[start..end];
    if table != CANONICAL_DEPENDENCY_TABLE {
        return Err("RNovModularDB AHCL dependency table is not canonical".into());
    }
    validate_shadow_fragment(&content[..start])?;
    validate_shadow_fragment(&content[end..])?;
    Ok(table)
}

fn validate_no_multiline_strings(content: &str) -> Result<(), String> {
    if content.contains("\"\"\"") || content.contains("'''") {
        return Err("multiline strings are forbidden in the dependency policy".into());
    }
    Ok(())
}

fn find_unique_table_start(content: &str) -> Result<usize, String> {
    let mut matches = content.match_indices(DEPENDENCY_TABLE_HEADER);
    let start = matches
        .next()
        .map(|(index, _)| index)
        .ok_or_else(|| "RNovModularDB AHCL dependency table is missing".to_owned())?;
    if matches.next().is_some() {
        return Err("RNovModularDB AHCL dependency table is duplicated".into());
    }
    if !is_trimmed_line_start(content, start) {
        return Err("RNovModularDB AHCL dependency table header is invalid".into());
    }
    Ok(start)
}

fn is_trimmed_line_start(content: &str, index: usize) -> bool {
    let start = content[..index]
        .rfind('\n')
        .map_or(0, |position| position + 1);
    content[start..index].trim().is_empty()
}

fn find_table_end(content: &str, start: usize) -> usize {
    let header_end = start + DEPENDENCY_TABLE_HEADER.len();
    let mut offset = header_end;
    for line in content[header_end..].split_inclusive('\n') {
        if line.trim_start().starts_with('[') {
            return offset;
        }
        offset += line.len();
    }
    content.len()
}

fn validate_shadow_fragment(content: &str) -> Result<(), String> {
    for line in content.lines() {
        validate_shadow_line(line)?;
    }
    Ok(())
}

fn validate_shadow_line(line: &str) -> Result<(), String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(());
    }
    if is_related_table_header(line) {
        return Err("RNovModularDB AHCL dependency table boundary is invalid".into());
    }
    validate_shadow_assignment(line)
}

fn is_related_table_header(line: &str) -> bool {
    line.starts_with("[rnmdb_ahcl_dependency.")
        || line.starts_with("[[rnmdb_ahcl_dependency")
        || line.starts_with(LEGACY_AUTHORIZATION_TABLE_HEADER)
}

fn validate_shadow_assignment(line: &str) -> Result<(), String> {
    let Some((key, _)) = line.split_once('=') else {
        return Ok(());
    };
    if is_policy_key(key) {
        return Err("RNovModularDB AHCL dependency field is outside its canonical table".into());
    }
    Ok(())
}

fn is_policy_key(key: &str) -> bool {
    let key = key.trim().trim_matches('"').trim_matches('\'');
    POLICY_KEYS.contains(&key)
        || key.contains("rnmdb_ahcl_dependency.")
        || key.contains("rnmdb_commercial_authorization.")
}

pub(crate) fn validate_manifest_dependency_aliases(content: &str) -> Result<(), String> {
    validate_manifest_encoding(content)?;
    for line in content.lines() {
        validate_manifest_line(line)?;
    }
    Ok(())
}

fn validate_manifest_encoding(content: &str) -> Result<(), String> {
    if content.contains('\\') {
        return Err("Cargo manifest escape sequences are forbidden by the dependency gate".into());
    }
    if content.contains("\"\"\"") || content.contains("'''") {
        return Err("Cargo manifest multiline strings are forbidden by the dependency gate".into());
    }
    Ok(())
}

fn validate_manifest_line(line: &str) -> Result<(), String> {
    let line = line.trim_start();
    if line.starts_with('#') {
        return Ok(());
    }
    let compact = compact_manifest_line(line);
    validate_noncanonical_dependency_syntax(&compact)?;
    let Some(package) = find_rnmdb_package_value(line, &compact) else {
        return Ok(());
    };
    validate_direct_dependency_assignment(line, package)
}

fn compact_manifest_line(line: &str) -> String {
    line.chars()
        .filter(|value| !value.is_ascii_whitespace())
        .collect()
}

fn validate_noncanonical_dependency_syntax(line: &str) -> Result<(), String> {
    if is_rnmdb_dependency_table(line) {
        return Err("RNovModularDB dependency tables are forbidden".into());
    }
    let Some((key, _)) = line.split_once('=') else {
        return Ok(());
    };
    if key.contains("rnmdb-") && !is_bare_rnmdb_key(key) {
        return Err("noncanonical RNovModularDB dependency key is forbidden".into());
    }
    Ok(())
}

fn is_rnmdb_dependency_table(line: &str) -> bool {
    let unquoted = line
        .chars()
        .filter(|value| !matches!(value, '\"' | '\''))
        .collect::<String>();
    unquoted.starts_with('[') && unquoted.contains("dependencies.") && unquoted.contains("rnmdb-")
}

fn is_bare_rnmdb_key(key: &str) -> bool {
    key.starts_with("rnmdb-")
        && key
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-')
}

fn find_rnmdb_package_value<'line>(line: &'line str, compact: &str) -> Option<&'line str> {
    find_compact_rnmdb_package_value(line, compact)
}

fn find_compact_rnmdb_package_value<'line>(line: &'line str, compact: &str) -> Option<&'line str> {
    for (marker, quote) in PACKAGE_MARKERS {
        let Some(value) = find_marker_value(compact, marker, quote) else {
            continue;
        };
        return find_original_value(line, value);
    }
    None
}

fn find_marker_value<'content>(
    content: &'content str,
    marker: &str,
    quote: char,
) -> Option<&'content str> {
    let mut remainder = content;
    loop {
        let index = remainder.find(marker)?;
        let prefix = &remainder[..index];
        let tail = &remainder[index + marker.len()..];
        if key_boundary(prefix)
            && let Some(value) = rnmdb_value(tail, quote)
        {
            return Some(value);
        }
        remainder = tail;
    }
}

fn key_boundary(prefix: &str) -> bool {
    match prefix.chars().next_back() {
        None => true,
        Some(value) => !value.is_ascii_alphanumeric() && value != '_' && value != '-',
    }
}

fn rnmdb_value(content: &str, quote: char) -> Option<&str> {
    let end = content.find(quote)?;
    let value = &content[..end];
    value.starts_with("rnmdb-").then_some(value)
}

fn find_original_value<'line>(line: &'line str, compact_value: &str) -> Option<&'line str> {
    line.match_indices(compact_value)
        .map(|(index, value)| &line[index..index + value.len()])
        .next()
}

fn validate_direct_dependency_assignment(line: &str, package: &str) -> Result<(), String> {
    let (key, declaration) = line
        .split_once('=')
        .ok_or_else(|| "RNovModularDB dependency declaration is invalid".to_owned())?;
    let declaration = declaration.trim();
    let direct =
        key.trim() == package && declaration.starts_with('{') && declaration.ends_with('}');
    if !direct {
        return Err("RNovModularDB dependency alias is forbidden".into());
    }
    Ok(())
}

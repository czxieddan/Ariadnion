//! Repository composition commands for independently resolved bundles.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_MANIFEST_BYTES: u64 = 65_536;
const MAX_MODULES: usize = 256;
const MAX_CAPABILITIES: usize = 256;
const MAX_POLICY_BYTES: u64 = 65_536;
const MAX_LOCK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOCK_FILES: usize = 512;

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("ariadnion-xtask: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(arguments: impl Iterator<Item = OsString>) -> Result<String, String> {
    let (command, profile) = parse_arguments(arguments)?;
    if command != "compose" {
        return Err("unsupported command".into());
    }
    compose(&profile)
}

fn parse_arguments(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<(String, String), String> {
    let command = parse_utf8(arguments.next())?;
    let profile = parse_utf8(arguments.next())?;
    if arguments.next().is_some() {
        return Err("too many arguments".into());
    }
    validate_profile(&profile)?;
    Ok((command, profile))
}

fn parse_utf8(value: Option<OsString>) -> Result<String, String> {
    value
        .ok_or_else(|| "missing argument".to_owned())?
        .into_string()
        .map_err(|_| "argument is not valid UTF-8".to_owned())
}

fn validate_profile(profile: &str) -> Result<(), String> {
    if matches!(profile, "edge" | "standard" | "complete") {
        return Ok(());
    }
    Err("unknown composition profile".into())
}

fn compose(profile: &str) -> Result<String, String> {
    let root = repository_root()?;
    let policy = load_dependency_policy(&root)?;
    let modules = scan_modules(&root, &policy)?;
    validate_declared_rnmdb_sources(&root, &policy)?;
    validate_rnmdb_lock_sources(&root, &policy)?;
    let selected = resolve_profile(profile, &modules)?;
    let output = root.join("target").join("compositions").join(profile);
    write_composition(&root, &output, profile, &modules, &selected)?;
    Ok(format!(
        "composition={profile} modules={} manifest={}",
        selected.len(),
        output.join("Cargo.toml").display()
    ))
}

fn repository_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot locate repository root".to_owned())
}

#[derive(Clone)]
struct ModuleMetadata {
    crate_name: String,
    id: String,
    version: Version,
    abi: AbiVersion,
    license: String,
    provides: Vec<Capability>,
    requires: Vec<Capability>,
}

#[derive(Clone, Eq, PartialEq)]
struct Capability {
    id: String,
    version: Version,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    const ZERO: Self = Self {
        major: 0,
        minor: 0,
        patch: 0,
    };
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct AbiVersion {
    rust_contract: Version,
    component_world_major: u16,
}

struct DependencyPolicy {
    core_abi: AbiVersion,
    rnmdb_repository: String,
    rnmdb_commit: String,
    rnmdb_package_prefix: String,
    rnmdb_packages: BTreeSet<String>,
}

fn scan_modules(root: &Path, policy: &DependencyPolicy) -> Result<Vec<ModuleMetadata>, String> {
    let optional = root.join("crates").join("optional");
    let entries = fs::read_dir(optional).map_err(|_| "cannot scan optional crates".to_owned())?;
    let mut manifests = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|_| "cannot read optional crate entry".to_owned())?
            .path()
            .join("module.toml");
        if path.is_file() {
            manifests.push(path);
        }
    }
    manifests.sort();
    if manifests.len() > MAX_MODULES {
        return Err("module scan limit reached".into());
    }
    let modules = manifests
        .into_iter()
        .map(|path| parse_module_manifest(path, policy))
        .collect::<Result<Vec<_>, _>>()?;
    validate_unique_module_ids(&modules)?;
    Ok(modules)
}

fn parse_module_manifest(
    path: PathBuf,
    policy: &DependencyPolicy,
) -> Result<ModuleMetadata, String> {
    let metadata = fs::metadata(&path).map_err(|_| "cannot inspect module manifest".to_owned())?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err("module manifest is too large".into());
    }
    let content = fs::read_to_string(&path)
        .map_err(|_| "module manifest is not readable UTF-8".to_owned())?;
    let crate_name = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .ok_or_else(|| "module crate name is invalid".to_owned())?
        .to_owned();
    let module = ModuleMetadata {
        crate_name,
        id: parse_string_field(&content, "id")?,
        version: parse_version_field(&content, "version")?,
        abi: parse_abi_field(&content)?,
        license: parse_string_field(&content, "license")?,
        provides: parse_capability_array(&content, "provides")?,
        requires: parse_capability_array(&content, "requires")?,
    };
    validate_module_metadata(&module, policy)?;
    validate_crate_manifest(&path, &module)?;
    Ok(module)
}

fn load_dependency_policy(root: &Path) -> Result<DependencyPolicy, String> {
    let path = root
        .join("tools")
        .join("dependency-policy")
        .join("versions.toml");
    let metadata =
        fs::metadata(&path).map_err(|_| "cannot inspect dependency policy".to_owned())?;
    if metadata.len() > MAX_POLICY_BYTES {
        return Err("dependency policy is too large".into());
    }
    let content = fs::read_to_string(path)
        .map_err(|_| "dependency policy is not readable UTF-8".to_owned())?;
    Ok(DependencyPolicy {
        core_abi: parse_abi_value(&parse_string_field(&content, "abi")?)?,
        rnmdb_repository: parse_string_field(&content, "repository")?,
        rnmdb_commit: parse_string_field(&content, "commit")?,
        rnmdb_package_prefix: parse_string_field(&content, "package_prefix")?,
        rnmdb_packages: parse_string_array(&content, "packages")?
            .into_iter()
            .collect(),
    })
}

fn parse_string_array(content: &str, key: &str) -> Result<Vec<String>, String> {
    let value = assignment(content, key)?;
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| format!("invalid {key} array"))?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(str::trim)
        .map(|value| parse_quoted(value).ok_or_else(|| format!("invalid {key} entry")))
        .collect()
}

fn validate_rnmdb_lock_sources(root: &Path, policy: &DependencyPolicy) -> Result<(), String> {
    for lock in collect_lock_files(root)? {
        let content = read_bounded_text(&lock, MAX_LOCK_BYTES, "Cargo lock file")?;
        for package in content.split("[[package]]").skip(1) {
            validate_rnmdb_package(package, policy)?;
        }
    }
    Ok(())
}

fn collect_lock_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut locks = Vec::new();
    add_lock_if_present(&root.join("Cargo.lock"), &mut locks)?;
    collect_child_locks(&root.join("crates").join("optional"), &mut locks)?;
    collect_child_locks(&root.join("bundles"), &mut locks)?;
    collect_child_locks(&root.join("tools"), &mut locks)?;
    locks.sort();
    Ok(locks)
}

fn collect_child_locks(parent: &Path, locks: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(parent).map_err(|_| "cannot scan Cargo lock roots".to_owned())?;
    for entry in entries {
        let path = entry
            .map_err(|_| "cannot read Cargo lock root".to_owned())?
            .path()
            .join("Cargo.lock");
        add_lock_if_present(&path, locks)?;
    }
    Ok(())
}

fn add_lock_if_present(path: &Path, locks: &mut Vec<PathBuf>) -> Result<(), String> {
    if path.is_file() {
        if locks.len() >= MAX_LOCK_FILES {
            return Err("Cargo lock file limit reached".into());
        }
        locks.push(path.to_path_buf());
    }
    Ok(())
}

fn validate_rnmdb_package(package: &str, policy: &DependencyPolicy) -> Result<(), String> {
    let name = parse_string_field(package, "name")?;
    if !name.starts_with(&policy.rnmdb_package_prefix) {
        return Ok(());
    }
    if !policy.rnmdb_packages.contains(&name) {
        return Err("unapproved RNovModularDB package".into());
    }
    let source = parse_string_field(package, "source")
        .map_err(|_| "RNovModularDB package is not pinned to Git".to_owned())?;
    validate_rnmdb_git_source(&source, policy)
}

fn validate_declared_rnmdb_sources(root: &Path, policy: &DependencyPolicy) -> Result<(), String> {
    for manifest in first_party_manifests(root)? {
        let content = read_bounded_text(&manifest, MAX_MANIFEST_BYTES, "crate manifest")?;
        for line in content.lines() {
            validate_rnmdb_dependency_line(line, policy)?;
        }
    }
    Ok(())
}

fn first_party_manifests(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut manifests = vec![root.join("Cargo.toml")];
    collect_child_manifests(&root.join("crates").join("optional"), &mut manifests)?;
    collect_child_manifests(&root.join("bundles"), &mut manifests)?;
    collect_child_manifests(&root.join("tools"), &mut manifests)?;
    manifests.sort();
    Ok(manifests)
}

fn collect_child_manifests(parent: &Path, manifests: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(parent).map_err(|_| "cannot scan Cargo manifests".to_owned())?;
    for entry in entries {
        let path = entry
            .map_err(|_| "cannot read Cargo manifest root".to_owned())?
            .path()
            .join("Cargo.toml");
        if path.is_file() {
            manifests.push(path);
        }
    }
    Ok(())
}

fn validate_rnmdb_dependency_line(line: &str, policy: &DependencyPolicy) -> Result<(), String> {
    let Some((candidate, declaration)) = line.split_once('=') else {
        return Ok(());
    };
    let package = candidate.trim();
    if !package.starts_with(&policy.rnmdb_package_prefix) {
        return Ok(());
    }
    if !policy.rnmdb_packages.contains(package) {
        return Err("unapproved RNovModularDB dependency declaration".into());
    }
    validate_rnmdb_git_declaration(package, declaration, policy)
}

fn validate_rnmdb_git_declaration(
    package: &str,
    declaration: &str,
    policy: &DependencyPolicy,
) -> Result<(), String> {
    let compact = declaration
        .chars()
        .filter(|value| !value.is_ascii_whitespace())
        .collect::<String>();
    let required = [
        format!("git=\"{}\"", policy.rnmdb_repository),
        format!("rev=\"{}\"", policy.rnmdb_commit),
        format!("package=\"{package}\""),
    ];
    for field in required {
        if !compact.contains(&field) {
            return Err("RNovModularDB dependency is not pinned to the approved Git source".into());
        }
    }
    for field in ["path=", "branch=", "tag="] {
        if compact.contains(field) {
            return Err("RNovModularDB dependency uses a forbidden source selector".into());
        }
    }
    Ok(())
}

fn validate_rnmdb_git_source(source: &str, policy: &DependencyPolicy) -> Result<(), String> {
    let source = source
        .strip_prefix("git+")
        .ok_or_else(|| "RNovModularDB package is not from git".to_owned())?;
    let (location, resolved) = source
        .split_once('#')
        .ok_or_else(|| "RNovModularDB source lacks a resolved commit".to_owned())?;
    let (repository, query) = location
        .split_once('?')
        .ok_or_else(|| "RNovModularDB source lacks a revision query".to_owned())?;
    let expected = policy.rnmdb_repository.trim_end_matches('/');
    if repository.trim_end_matches('/') != expected {
        return Err("RNovModularDB repository is not approved".into());
    }
    let revision = format!("rev={}", policy.rnmdb_commit);
    if !query.split('&').any(|part| part == revision) {
        return Err("RNovModularDB revision is not approved".into());
    }
    if !resolved.starts_with(&policy.rnmdb_commit) {
        return Err("RNovModularDB resolved commit is not approved".into());
    }
    Ok(())
}

fn validate_crate_manifest(path: &Path, module: &ModuleMetadata) -> Result<(), String> {
    let manifest = path
        .parent()
        .ok_or_else(|| "module directory is missing".to_owned())?
        .join("Cargo.toml");
    let content = read_bounded_text(&manifest, MAX_MANIFEST_BYTES, "crate manifest")?;
    let package_name = parse_string_field(&content, "name")?;
    let package_version = parse_version_field(&content, "version")?;
    let package_license = parse_string_field(&content, "license")?;
    if package_name != module.crate_name {
        return Err("module crate name differs from Cargo package name".into());
    }
    if package_version != module.version {
        return Err("module version differs from Cargo package version".into());
    }
    if package_license != module.license {
        return Err("module license differs from Cargo package license".into());
    }
    Ok(())
}

fn read_bounded_text(path: &Path, limit: u64, label: &str) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|_| format!("cannot inspect {label}"))?;
    if metadata.len() > limit {
        return Err(format!("{label} is too large"));
    }
    fs::read_to_string(path).map_err(|_| format!("{label} is not readable UTF-8"))
}

fn validate_unique_module_ids(modules: &[ModuleMetadata]) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    for module in modules {
        if !ids.insert(module.id.as_str()) {
            return Err("duplicate module identity".into());
        }
    }
    Ok(())
}

fn parse_string_field(content: &str, key: &str) -> Result<String, String> {
    let value = assignment(content, key)?;
    parse_quoted(value).ok_or_else(|| format!("invalid {key} field"))
}

fn parse_version_field(content: &str, key: &str) -> Result<Version, String> {
    let value = parse_string_field(content, key)?;
    parse_version(&value).map_err(|_| format!("invalid {key} field"))
}

fn parse_abi_field(content: &str) -> Result<AbiVersion, String> {
    let value = parse_string_field(content, "abi")?;
    parse_abi_value(&value)
}

fn parse_abi_value(value: &str) -> Result<AbiVersion, String> {
    parse_abi_version(value).map_err(|_| "invalid abi field".to_owned())
}

fn parse_capability_array(content: &str, key: &str) -> Result<Vec<Capability>, String> {
    let value = assignment(content, key)?;
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| format!("invalid {key} array"))?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    let values = inner.split(',').map(str::trim).collect::<Vec<_>>();
    if values.len() > MAX_CAPABILITIES {
        return Err("capability declaration limit reached".into());
    }
    values
        .into_iter()
        .map(|value| {
            let parsed =
                parse_quoted(value).ok_or_else(|| "invalid capability string".to_owned())?;
            parse_capability(&parsed)
        })
        .collect()
}

fn assignment<'a>(content: &'a str, key: &str) -> Result<&'a str, String> {
    content
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(candidate, _)| candidate.trim() == key)
        .map(|(_, value)| value.trim())
        .ok_or_else(|| format!("missing {key} field"))
}

fn parse_quoted(value: &str) -> Option<String> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .map(str::to_owned)
}

fn parse_capability(value: &str) -> Result<Capability, String> {
    let (id, version) = value
        .split_once('@')
        .ok_or_else(|| "capability is missing a version".to_owned())?;
    validate_identifier(id)?;
    Ok(Capability {
        id: id.to_owned(),
        version: parse_version(version)?,
    })
}

fn parse_version(value: &str) -> Result<Version, String> {
    let mut parts = value.split('.');
    let major = parse_version_part(parts.next())?;
    let minor = parse_version_part(parts.next())?;
    let patch = parse_version_part(parts.next())?;
    if parts.next().is_some() {
        return Err("version has too many components".into());
    }
    Ok(Version {
        major,
        minor,
        patch,
    })
}

fn parse_version_part(value: Option<&str>) -> Result<u16, String> {
    value
        .ok_or_else(|| "version component is missing".to_owned())?
        .parse::<u16>()
        .map_err(|_| "version component is invalid".to_owned())
}

fn parse_abi_version(value: &str) -> Result<AbiVersion, String> {
    let (rust_contract, component_world_major) = value
        .strip_prefix("rust-")
        .and_then(|remainder| remainder.split_once("/wit-"))
        .ok_or_else(|| "ABI version prefix is invalid".to_owned())?;
    Ok(AbiVersion {
        rust_contract: parse_version(rust_contract)?,
        component_world_major: parse_version_part(Some(component_world_major))?,
    })
}

fn validate_module_metadata(
    module: &ModuleMetadata,
    policy: &DependencyPolicy,
) -> Result<(), String> {
    validate_identifier(&module.id)?;
    validate_implementation_version(module.version)?;
    validate_abi_version(module.abi)?;
    if module.abi != policy.core_abi {
        return Err("module ABI is incompatible with the core policy".into());
    }
    if !module.crate_name.starts_with("ariadnion-") {
        return Err("module crate is not first-party".into());
    }
    if module.license != "AGPL-3.0-or-later" {
        return Err("first-party module license is inconsistent".into());
    }
    Ok(())
}

fn validate_implementation_version(version: Version) -> Result<(), String> {
    if version == Version::ZERO {
        return Err("module implementation version must be nonzero".into());
    }
    Ok(())
}

fn validate_abi_version(version: AbiVersion) -> Result<(), String> {
    if version.rust_contract == Version::ZERO || version.component_world_major == 0 {
        return Err("module ABI version must be nonzero".into());
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 160
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err("identifier is invalid".into())
    }
}

fn resolve_profile(profile: &str, modules: &[ModuleMetadata]) -> Result<BTreeSet<usize>, String> {
    let providers = provider_index(modules)?;
    let mut pending = VecDeque::from(profile_requirements(profile));
    let mut selected = BTreeSet::new();
    while let Some(requirement) = pending.pop_front() {
        let index = resolve_provider(&requirement, &providers)?;
        if selected.insert(index) {
            let module = modules
                .get(index)
                .ok_or_else(|| "resolved module index is invalid".to_owned())?;
            pending.extend(module.requires.iter().cloned());
        }
    }
    validate_dependency_cycles(modules, &providers, &selected)?;
    Ok(selected)
}

fn profile_requirements(profile: &str) -> Vec<Capability> {
    match profile {
        "edge" => vec![diagnostics_requirement()],
        "standard" | "complete" => vec![diagnostics_requirement(), storage_requirement()],
        _ => Vec::new(),
    }
}

fn diagnostics_requirement() -> Capability {
    Capability {
        id: "org.ariadnion.diagnostics.read".into(),
        version: Version {
            major: 1,
            minor: 0,
            patch: 0,
        },
    }
}

fn storage_requirement() -> Capability {
    Capability {
        id: "org.ariadnion.storage.relational".into(),
        version: Version {
            major: 1,
            minor: 0,
            patch: 0,
        },
    }
}

fn provider_index(
    modules: &[ModuleMetadata],
) -> Result<BTreeMap<String, (Version, usize)>, String> {
    let mut providers = BTreeMap::new();
    for (index, module) in modules.iter().enumerate() {
        for capability in &module.provides {
            if providers
                .insert(capability.id.clone(), (capability.version, index))
                .is_some()
            {
                return Err("duplicate capability provider".into());
            }
        }
    }
    Ok(providers)
}

fn resolve_provider(
    requirement: &Capability,
    providers: &BTreeMap<String, (Version, usize)>,
) -> Result<usize, String> {
    let (version, index) = providers
        .get(&requirement.id)
        .ok_or_else(|| format!("missing capability {}", requirement.id))?;
    if version.major != requirement.version.major || version < &requirement.version {
        return Err(format!("incompatible capability {}", requirement.id));
    }
    Ok(*index)
}

struct DependencyGraph {
    indegrees: Vec<usize>,
    dependents: Vec<Vec<usize>>,
}

fn validate_dependency_cycles(
    modules: &[ModuleMetadata],
    providers: &BTreeMap<String, (Version, usize)>,
    selected: &BTreeSet<usize>,
) -> Result<(), String> {
    let mut graph = build_dependency_graph(modules, providers, selected)?;
    let mut ready = selected
        .iter()
        .copied()
        .filter(|index| graph.indegrees.get(*index).is_some_and(|value| *value == 0))
        .collect::<VecDeque<_>>();
    let mut resolved = 0_usize;
    while let Some(provider) = ready.pop_front() {
        resolved = resolved.saturating_add(1);
        release_dependents(provider, &mut graph, &mut ready)?;
    }
    if resolved != selected.len() {
        return Err("module dependency cycle detected".into());
    }
    Ok(())
}

fn build_dependency_graph(
    modules: &[ModuleMetadata],
    providers: &BTreeMap<String, (Version, usize)>,
    selected: &BTreeSet<usize>,
) -> Result<DependencyGraph, String> {
    let mut graph = DependencyGraph {
        indegrees: vec![0; modules.len()],
        dependents: vec![Vec::new(); modules.len()],
    };
    for consumer in selected {
        let module = modules
            .get(*consumer)
            .ok_or_else(|| "selected module index is invalid".to_owned())?;
        let dependencies = dependency_providers(module, providers, selected)?;
        set_module_dependencies(*consumer, &dependencies, &mut graph)?;
    }
    Ok(graph)
}

fn dependency_providers(
    module: &ModuleMetadata,
    providers: &BTreeMap<String, (Version, usize)>,
    selected: &BTreeSet<usize>,
) -> Result<BTreeSet<usize>, String> {
    let mut dependencies = BTreeSet::new();
    for requirement in &module.requires {
        let provider = resolve_provider(requirement, providers)?;
        if !selected.contains(&provider) {
            return Err("composition dependency closure is incomplete".into());
        }
        dependencies.insert(provider);
    }
    Ok(dependencies)
}

fn set_module_dependencies(
    consumer: usize,
    dependencies: &BTreeSet<usize>,
    graph: &mut DependencyGraph,
) -> Result<(), String> {
    let indegree = graph
        .indegrees
        .get_mut(consumer)
        .ok_or_else(|| "dependency graph index is invalid".to_owned())?;
    *indegree = dependencies.len();
    for provider in dependencies {
        graph
            .dependents
            .get_mut(*provider)
            .ok_or_else(|| "dependency graph index is invalid".to_owned())?
            .push(consumer);
    }
    Ok(())
}

fn release_dependents(
    provider: usize,
    graph: &mut DependencyGraph,
    ready: &mut VecDeque<usize>,
) -> Result<(), String> {
    let dependents = graph
        .dependents
        .get(provider)
        .ok_or_else(|| "dependency graph index is invalid".to_owned())?;
    for consumer in dependents {
        let remaining = graph
            .indegrees
            .get_mut(*consumer)
            .ok_or_else(|| "dependency graph index is invalid".to_owned())?;
        if *remaining == 0 {
            return Err("dependency graph state is invalid".into());
        }
        *remaining -= 1;
        if *remaining == 0 {
            ready.push_back(*consumer);
        }
    }
    Ok(())
}

fn write_composition(
    root: &Path,
    output: &Path,
    profile: &str,
    modules: &[ModuleMetadata],
    selected: &BTreeSet<usize>,
) -> Result<(), String> {
    fs::create_dir_all(output.join("src"))
        .map_err(|_| "cannot create composition directory".to_owned())?;
    let manifest = render_manifest(root, profile, modules, selected)?;
    let main = format!(
        "fn main() {{ println!(\"composition={profile} modules={}\"); }}\n",
        selected.len()
    );
    write_if_changed(&output.join("Cargo.toml"), manifest.as_bytes())?;
    write_if_changed(&output.join("src").join("main.rs"), main.as_bytes())
}

fn render_manifest(
    root: &Path,
    profile: &str,
    modules: &[ModuleMetadata],
    selected: &BTreeSet<usize>,
) -> Result<String, String> {
    let core = dependency_path(root, &root.join("crates").join("ariadnion-core"))?;
    let mut manifest = format!(
        "[package]\nname = \"ariadnion-composition-{profile}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[workspace]\n\n[dependencies]\nariadnion-core = {{ path = \"{core}\" }}\n"
    );
    for index in selected {
        let module = &modules[*index];
        let path = dependency_path(
            root,
            &root
                .join("crates")
                .join("optional")
                .join(&module.crate_name),
        )?;
        manifest.push_str(&format!(
            "{} = {{ path = \"{}\" }}\n",
            module.crate_name, path
        ));
    }
    Ok(manifest)
}

fn dependency_path(root: &Path, target: &Path) -> Result<String, String> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| "dependency path is outside the repository".to_owned())?;
    Ok(format!(
        "../../../{}",
        relative.to_string_lossy().replace('\\', "/")
    ))
}

fn write_if_changed(path: &Path, content: &[u8]) -> Result<(), String> {
    if fs::read(path).ok().as_deref() == Some(content) {
        return Ok(());
    }
    fs::write(path, content).map_err(|_| "cannot write composition output".to_owned())
}

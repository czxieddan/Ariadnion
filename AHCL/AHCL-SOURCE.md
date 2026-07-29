# Ariadnion Source, History, and Release Mapping

## Public Source Code and Complete Modification History

The canonical public repository is <https://github.com/czxieddan/Ariadnion>. Its complete published Git history can be obtained without registration or payment by running:

```text
git clone https://github.com/czxieddan/Ariadnion.git
```

The canonical branch is `master`. A corresponding source publication or release must identify an immutable full Git commit and, where applicable, an artifact digest. A branch name by itself is not a release mapping.

## Build and reproduction materials

The repository records its Rust toolchain in `rust-toolchain.toml`, formatting policy in `rustfmt.toml`, shared Cargo configuration in `.cargo/config.toml`, and each independently resolved build graph in its `Cargo.toml` and `Cargo.lock`. The root workspace builds the core-only distribution. `bundles/edge/`, `bundles/standard/`, and `bundles/complete/` contain the independent composition manifests and locks. Optional crates retain independent manifests and locks under `crates/optional/`.

Dependency acquisition locations, versions, lock checksums, authorization status, and license-copy mappings are recorded in `AHCL/AHCL-DEPENDENCIES.md`.

## Release mappings

No tagged release, container digest, signed release artifact, or network deployment mapping is identified by current repository evidence as an AHCL release mapping. Each future artifact or operated version must record its exact Git revision, build profile, dependency lock, build parameters, and artifact digest before the corresponding use.

## Public testing-material gap

Repository governance keeps external contract-test source outside production Git under ignored `crates/<crate>/tests/` paths. The existing local Rust, PowerShell, and TOML test sources carry the same AHCL source-file notice as tracked production source, but they remain ignored and untracked. No public, stable acquisition location for those local test assets is currently documented. This notice therefore does not claim that the ignored test assets are publicly available. The project owner must establish a public source-and-history channel for every testing material required by AHCL Sections 1.6(b), 6.1(c), and 8 before a corresponding version is used in a manner that triggers those duties; otherwise that use must cease.

The ignored generated lock file at `crates/optional/ariadnion-api-admin/tests/command_forgery_guard/Cargo.lock` is excluded from source-header insertion because it is Cargo-generated resolution data rather than authored source. It remains part of the unresolved public testing-material gap when needed to reproduce that external test workspace.

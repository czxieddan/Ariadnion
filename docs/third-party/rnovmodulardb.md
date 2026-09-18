# RNovModularDB dependency record

Ariadnion resolves RNovModularDB directly from the repository below:

- Repository: `https://github.com/czxieddan/RNovModularDB.git`
- Reviewed commit: `f35e636f3d32d2d0835a23e6d53fc3437e46707a`
- Cargo selector: full Git `rev`, repeated for every approved `rnmdb-*` package
- Selected license: `LicenseRef-AHCL-1.1`
- Verbatim license copy: `.ahcl/AHCL-1.1.md`
- Upstream Additional Restrictions: none

Ariadnion selects RNMDB's public AHCL 1.1 option at the reviewed repository and
commit. Every approved package uses the canonical HTTPS repository, the same
full revision, and an explicit package name. The integration contains the
complete package set below and does not use a local path, vendor copy, submodule,
branch, tag, or short revision:

- `rnmdb-common`
- `rnmdb-types`
- `rnmdb-sql`
- `rnmdb-planner`
- `rnmdb-executor`
- `rnmdb-txn`
- `rnmdb-index`
- `rnmdb-fts`
- `rnmdb-catalog`
- `rnmdb-storage`
- `rnmdb-udf`
- `rnmdb-security`
- `rnmdb-instance`
- `rnmdb-server`
- `rnmdb-cli`

Composition tooling verifies the selected license, repository URL, requested
revision, resolved commit, package set, and absence of upstream Additional
Restrictions against the fixed dependency policy, manifests, and Cargo lock
files. The human-readable dependency inventory records upstream provenance and
the repository license-copy mapping.

The embedded application path uses one long-lived encrypted local session,
serialized writes, and explicit checkpoints. Database service listeners remain
disabled by default and are not used for communication between Ariadnion
modules.

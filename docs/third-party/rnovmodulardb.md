# RNovModularDB dependency record

Ariadnion resolves RNovModularDB directly from the repository below:

- Repository: `https://github.com/czxieddan/RNovModularDB.git`
- Reviewed commit: `f20040a127a56ec8c37b3398283df36f024a1dd2`
- Cargo selector: full Git `rev`, repeated for every approved `rnmdb-*` package
- Selected license: `LicenseRef-AHCL-1.0`
- Verbatim license copy: `AHCL/AHCL-1.0.md`
- Upstream Additional Restrictions: none

Ariadnion selects RNMDB's public AHCL 1.0 option at the reviewed repository and
commit. The dependency gate requires the complete package set below and rejects
any different repository, revision, package set, alias, local path, vendor copy,
submodule, branch, tag, or short revision:

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

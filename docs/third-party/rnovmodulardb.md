# RNovModularDB dependency record

Ariadnion resolves RNovModularDB directly from the repository below:

- Repository: `https://github.com/czxieddan/RNovModularDB.git`
- Reviewed commit: `f07f1da2c1a193ad3732ee779d228ac8ec3dbffd`
- Cargo selector: full Git `rev`, repeated for every approved `rnmdb-*` package
- License evidence: `LICENSE` at the reviewed repository commit
- Commercial licensing contact: `licensing@aperip.com`

The repository owner explicitly approved this dependency as Ariadnion's only
third-party GPL or AGPL exception. The exception applies only to the reviewed
repository and commit and to these packages:

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

No package-name match alone grants an exception. Composition tooling rejects
local paths, vendor copies, submodules, branches, tags, and short revisions. It
verifies the package set, repository URL, requested revision, and resolved
commit from the declarations and actual Cargo lock files.

The embedded application path uses one long-lived encrypted local session,
serialized writes, and explicit checkpoints. Database service listeners remain
disabled by default and are not used for communication between Ariadnion
modules.

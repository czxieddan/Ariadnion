# RNovModularDB dependency record

Ariadnion embeds RNovModularDB from the repository below:

- Repository: `https://github.com/czxieddan/RNovModularDB/`
- Reviewed commit: `8d2b65ad1ee3ee542e1307c1693bc4de4f7edbee`
- Submodule path: `vendor/RNovModularDB`
- License path: `vendor/RNovModularDB/LICENSE`
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

No package-name match alone grants an exception. Composition tooling verifies
the package set, repository URL, requested revision, and resolved commit from
the actual Cargo lock files before accepting an RNMDB dependency.

The embedded application path uses one long-lived encrypted local session,
serialized writes, and explicit checkpoints. Database service listeners remain
disabled by default and are not used for communication between Ariadnion
modules.

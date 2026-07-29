# RNovModularDB dependency record

Ariadnion resolves RNovModularDB directly from the repository below:

- Repository: `https://github.com/czxieddan/RNovModularDB.git`
- Reviewed commit: `013ec2f48a1dab89997430d72c2b176be2c29d47`
- Cargo selector: full Git `rev`, repeated for every approved `rnmdb-*` package
- Authorization treatment: special commercial authorization from the RNovModularDB project owner
- Public authorization notice: `AHCL/AHCL-SPECIAL-AUTHORIZATIONS.md`
- Authorization contact retained from prior tracked repository evidence: `licensing@aperip.com`

RNMDB is not treated as AGPL for this project. This authorization is a separate
commercial grant rather than a reusable public-license selection. It is
limited to the reviewed repository and commit, these packages, and Ariadnion
itself or forks and extensions that retain and provide a material part of
Ariadnion's service-gateway or operations-platform functionality:

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

Unrelated projects, products, and services and standalone or general-purpose
RNMDB reuse are outside this scope. No package-name match alone establishes
authorization. Composition tooling
rejects local paths, vendor copies, submodules, branches, tags, and short
revisions. It verifies the package set, repository URL, requested revision,
resolved commit, and the public authorization-status record against declarations
and actual Cargo lock files.

The public notice is not the confidential authorization instrument and grants no
right to another project. It deliberately does not claim an authorization
identifier, signature, fee, term, territory, dispute clause, or confidential
evidence that is not present in the repository.

The embedded application path uses one long-lived encrypted local session,
serialized writes, and explicit checkpoints. Database service listeners remain
disabled by default and are not used for communication between Ariadnion
modules.

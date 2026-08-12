# Ariadnion

Ariadnion is a modular service gateway and operations platform written in Rust. Its core runtime builds and runs independently; every other capability is assembled from focused crates as needed.

The name comes from Ariadne's thread: a clear and dependable path connecting the entrances, decisions, and exits of a complex system.

## Design principles

- The core builds and runs independently.
- Explicit types and stable contracts define capability boundaries.
- The complete distribution uses one container, one process, and embedded storage.
- Sensitive configuration is encrypted by default, and critical operations are auditable.
- Frontends, command-line tools, identity, accounts, auditing, and operations evolve independently.

## Source Code, History, and Licenses

The canonical source repository and complete published history are available at <https://github.com/czxieddan/Ariadnion>. Source acquisition, immutable revision, build-material, and release-mapping requirements are documented in [AHCL/AHCL-SOURCE.md](AHCL/AHCL-SOURCE.md).

Ariadnion is licensed under version 1.0 of the Aperip Heimdall Commons License (AHCL 1.0). See [LICENSE](LICENSE), the repository's [verbatim AHCL 1.0 text](AHCL/AHCL-1.0.md), the [project notice](AHCL/AHCL-PROJECT-NOTICE.md), and the [dependency and third-party license inventory](AHCL/AHCL-DEPENDENCIES.md).

One [Additional Restriction](AHCL/AHCL-RESTRICTIONS/INDEX.md), `ARIADNION-AR-2026-001`, is currently effective for this distribution chain and preserves legal notices presented by Ariadnion frontends and command-line interfaces. Its complete terms, scope, effective time, fixed clause digest, historical activation evidence, and the recorded removal of the former `ARIADNION-AR-2026-002` restriction are available under `AHCL/AHCL-RESTRICTIONS/`.

# Ariadnion

Ariadnion is a modular service gateway and operations platform written in Rust. Its core runtime builds and runs independently; every other capability is assembled from focused crates as needed.

The name comes from Ariadne's thread: a clear and dependable path connecting the entrances, decisions, and exits of a complex system.

## Design principles

- The core builds and runs independently.
- Explicit types and stable contracts define capability boundaries.
- The complete distribution uses one container, one process, and embedded storage.
- Sensitive configuration is encrypted by default, and critical operations are auditable.
- Frontends, command-line tools, identity, accounts, auditing, and operations evolve independently.

## Status

The project is in the architecture and implementation planning stage.

## License

Ariadnion is offered under a commercial license and the GNU Affero General Public License. See [LICENSE](LICENSE).

# Ariadnion Resolved License Inventory

This deterministic inventory is generated from every tracked production Cargo lock graph. Package identities are deduplicated by exact name, version, and source. First-party path packages define the resolution boundary but are not third-party records.

## Coverage summary

- Tracked production lockfiles: 43.
- Unique resolved package records: 262.
- First-party path package records: 43.
- External Git package records: 15.
- Registry package records: 204.
- Canonical upstream projects: 119.
- Hash-addressed retained raw evidence files: 133.

Selected alternatives are checked against exact packaged license metadata and `tools/dependency-policy/versions.toml`. A source-specific policy record is shown only when its repository, full resolved commit, and complete package membership match the Cargo graphs.

## Lockfile snapshot

| Lockfile | SHA-256 | Bytes | Package records |
| --- | --- | ---: | ---: |
| `Cargo.lock` | `4690eb01d3b15a1697f2d813c74deb0b9d3a3d3616b4a894700a47c3d6d5b7e0` | 2780 | 13 |
| `bundles/complete/Cargo.lock` | `8c598323fa424401152743612550629f829eb39f510b564d263c431d0b2d88f2` | 58487 | 245 |
| `bundles/edge/Cargo.lock` | `f565d723b2faf01953c3660d2d406ffa5b6e2b2ae1f83a5b95fb8e5773e70ec1` | 3124 | 16 |
| `bundles/standard/Cargo.lock` | `140d57dade1947b21834a16f21701f31e6a03e210a5899f7b26ec9a71ed3878e` | 58487 | 245 |
| `crates/optional/ariadnion-api-admin/Cargo.lock` | `e41a35a8e0a1088bc5f5ffea56abd61fd11a9695849b024e9e8971ee74fa87db` | 15107 | 70 |
| `crates/optional/ariadnion-api-dispatch/Cargo.lock` | `567ff9912807989778b82bc15d2277ade481b05f01a1cf621fdf2ccb7f35582b` | 5263 | 26 |
| `crates/optional/ariadnion-api-domain/Cargo.lock` | `f6a083a6018eafc2676a3cccba14f8650265c1656dfddd6f0fb10b89911e8ba6` | 2879 | 14 |
| `crates/optional/ariadnion-api-http/Cargo.lock` | `83937c455a19bb6ae7c742f86e00bdaebff81f375553d9a0bd17f9978d33a61b` | 14734 | 67 |
| `crates/optional/ariadnion-api-stream/Cargo.lock` | `d74bf2b5ff0fe50233978a11b53350e174e82d5f32bd8c65644007e15b989103` | 15200 | 69 |
| `crates/optional/ariadnion-audit-domain/Cargo.lock` | `a07d38f9022086c57d1dddb06bf97623daaf268865653057287e37889c5baf4e` | 4847 | 23 |
| `crates/optional/ariadnion-audit-store/Cargo.lock` | `1f18d029a762141eea47a81e5b3ebbae2de2f4b8780cffd2817b38de7af684ac` | 5000 | 24 |
| `crates/optional/ariadnion-auth-api-key/Cargo.lock` | `32998c7e6f75c5f04f6d483c6861b7f1016d6b8fcc9fe1d1d63b85bcde38bb7b` | 5048 | 24 |
| `crates/optional/ariadnion-auth-password/Cargo.lock` | `f9433901cff3b08edfcede5b8b2c87a152d6f7023620dac15b87be46c110fe4a` | 6413 | 30 |
| `crates/optional/ariadnion-auth-session/Cargo.lock` | `141e959891d743989b837de56dd13d052f4c981eb53619e1ebbe5523cd6af9e3` | 5048 | 24 |
| `crates/optional/ariadnion-cli-user/Cargo.lock` | `4367a7737763ac0b9bb266109907da293f83e649a701b36a46f15a4822a76071` | 6120 | 30 |
| `crates/optional/ariadnion-compose/Cargo.lock` | `481168f7972de4c2e1625c63316dfbf1908bf20adbd942d496f677b4291abd84` | 2876 | 14 |
| `crates/optional/ariadnion-config-domain/Cargo.lock` | `6f9743a85c703806a573cb0f71608cc62c613decfcd7ac64c2e3afe93c8c1568` | 2882 | 14 |
| `crates/optional/ariadnion-config-runtime/Cargo.lock` | `83d51aafb31b03293716a26d8278484848bcb71f2fb15ba250940e9928203373` | 3152 | 16 |
| `crates/optional/ariadnion-config-schema/Cargo.lock` | `918dc84fbdb182f289f556c237e2c702dbdb91dc3d057893cb8518e1c12bb5a3` | 3012 | 15 |
| `crates/optional/ariadnion-diagnostics/Cargo.lock` | `a8a5c517b481c89ab901fc8901af12ce44a7969f6fc676460c1360c8c5fd6d58` | 2880 | 14 |
| `crates/optional/ariadnion-invitation/Cargo.lock` | `8f509b24479d7ee7332f72e958bc8c63e302963d2e1dc02850610bcfc44db8d1` | 3324 | 17 |
| `crates/optional/ariadnion-job-runner/Cargo.lock` | `a84414340e7c384dc50c2da435bcf2d74bb9f93d673595176271e6d992233431` | 6122 | 30 |
| `crates/optional/ariadnion-organization/Cargo.lock` | `13a32cff1d2f549f3ac32dae9edcd3b0aaa476750e8663e7923a388f44e77f23` | 3007 | 15 |
| `crates/optional/ariadnion-principal-binding/Cargo.lock` | `0cf7cc4b65ac3e8c1a7a64eaba81006d48508fe26affdaba4c06c22b942d51f2` | 5006 | 24 |
| `crates/optional/ariadnion-protocol-openai/Cargo.lock` | `47c1033b4a8899303bef4c04cc28e46141ec3a9f129c5606dbcfdba2996f2012` | 15032 | 68 |
| `crates/optional/ariadnion-provider-dispatch/Cargo.lock` | `1c490c5aa5d9d3393d2be7f2fa741ba99bf066f7d63cd32beddcf34dfd589f9c` | 5659 | 28 |
| `crates/optional/ariadnion-provider-http/Cargo.lock` | `64a51ab016ffea732dbbb93d25abde6b2502f04f5e13bb6af9c3902156e16a7b` | 14318 | 64 |
| `crates/optional/ariadnion-provider-mock/Cargo.lock` | `2ed636ded820586385c5182f3331132b4ec0149aa43514aa049ec8ef0723cb7e` | 3159 | 16 |
| `crates/optional/ariadnion-provider-sdk/Cargo.lock` | `24e963f4489936538cad78288b204992834f6076a0a6ec9a5c48c73179706bac` | 3005 | 15 |
| `crates/optional/ariadnion-rbac/Cargo.lock` | `df0a97517c2bf82b8bec6e8053876e72dbaa9b243a2462740bc01fd1c16d1195` | 3153 | 16 |
| `crates/optional/ariadnion-storage-asset/Cargo.lock` | `f9efc9ea32f27e3e2c0638041d0267e50f1a4a8ca9f8815542d287f116f62344` | 3217 | 16 |
| `crates/optional/ariadnion-storage-backup/Cargo.lock` | `49b49e3ae2cb443661a161d22fe054d3047fc2177e1147c862c07f0eb883a3e1` | 3015 | 15 |
| `crates/optional/ariadnion-storage-domain/Cargo.lock` | `c2c92576caca00c2c9a98a12398e06782a3ff3eb702eee697464942cf141c7f7` | 2883 | 14 |
| `crates/optional/ariadnion-storage-maintenance/Cargo.lock` | `b3eefd6a09adf8f7690f7c2e21693a3ee3dd16334a42c65fc9bd4930163a35f6` | 3020 | 15 |
| `crates/optional/ariadnion-storage-migration/Cargo.lock` | `b13d0afb7c532e55e4d44432ec702ac53a20f853b4b410b4530008e7dc9d0e2c` | 3018 | 15 |
| `crates/optional/ariadnion-storage-outbox/Cargo.lock` | `a03032bc03866517be657779f3dfbc6259f10c8c0526e86012a06147aeb63cd1` | 3218 | 16 |
| `crates/optional/ariadnion-storage-query/Cargo.lock` | `867744f76384f852b3275df7bd81fcaba1403661348a8a07acb4b0e9f1ed90ba` | 3014 | 15 |
| `crates/optional/ariadnion-storage-restore/Cargo.lock` | `dfa5e9c5ee28860069c5df9ad3f0d16f7e369b6a717bff1707c5fe03c5bcfda3` | 3016 | 15 |
| `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` | `14512162ea95f8de0582249f62ba7a5708ca0863d9d5fa631b6b1e816f407140` | 50062 | 209 |
| `crates/optional/ariadnion-storage-upgrade/Cargo.lock` | `490b0470c83513a0736a80ba8c62d6c1a05b59c83064afcf26333bff95211e59` | 3016 | 15 |
| `crates/optional/ariadnion-user-domain/Cargo.lock` | `788edb6fc74c57a895b4880b18d62f2c5e22c6b48aeb778ec8846bab10ec8b92` | 2880 | 14 |
| `crates/optional/ariadnion-user-service/Cargo.lock` | `8ade7ce2c9a43ec6858ab3a7154c40d25d0975f5310902c49071014944bdb8a6` | 3007 | 15 |
| `tools/ariadnion-xtask/Cargo.lock` | `d92bdf45bd4b9a6d0945bd871009f08cd86426dc9391057a1ada10d6e43ec05d` | 159 | 1 |

## Canonical upstream projects

### addr2line

Canonical upstream: <https://github.com/gimli-rs/addr2line>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `addr2line` | `0.26.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `59317f77929f0e679d39364702289274de2f0f0b22cbf50b2b8cff2169a0b27a` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `addr2line 0.26.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/addr2line/0.26.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `addr2line 0.26.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/addr2line/0.26.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/e99d88d232bf57d70f0fb87f6b496d44b6653f99f8a63d250a54c61ea4bcde40.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/e99d88d232bf57d70f0fb87f6b496d44b6653f99f8a63d250a54c61ea4bcde40.txt) (SHA-256 `e99d88d232bf57d70f0fb87f6b496d44b6653f99f8a63d250a54c61ea4bcde40`; 1069 bytes).

### AEADs

Canonical upstream: <https://github.com/RustCrypto/AEADs>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `chacha20poly1305` | `0.11.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `chacha20poly1305 0.11.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/chacha20poly1305/0.11.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `chacha20poly1305 0.11.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/chacha20poly1305/0.11.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b8c6939380a400f53e11923d50fcc4dd2fa1ba8339fd9d04cda38a0251b6c9b0.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b8c6939380a400f53e11923d50fcc4dd2fa1ba8339fd9d04cda38a0251b6c9b0.txt) (SHA-256 `b8c6939380a400f53e11923d50fcc4dd2fa1ba8339fd9d04cda38a0251b6c9b0`; 1082 bytes).

### allocator-api2

Canonical upstream: <https://github.com/zakarumych/allocator-api2>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `allocator-api2` | `0.2.21` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `683d7910e743518b0e34f1186f92494becacb047c7b6bf616c96772180fef923` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `allocator-api2 0.2.21`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/allocator-api2/0.2.21/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/20fe7b00e904ed690e3b9fd6073784d3fc428141dbd10b81c01fd143d0797f58.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/20fe7b00e904ed690e3b9fd6073784d3fc428141dbd10b81c01fd143d0797f58.txt) (SHA-256 `20fe7b00e904ed690e3b9fd6073784d3fc428141dbd10b81c01fd143d0797f58`; 9899 bytes).
- `allocator-api2 0.2.21`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/allocator-api2/0.2.21/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/36516aefdc84c5d5a1e7485425913a22dbda69eb1930c5e84d6ae4972b5194b9.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/36516aefdc84c5d5a1e7485425913a22dbda69eb1930c5e84d6ae4972b5194b9.txt) (SHA-256 `36516aefdc84c5d5a1e7485425913a22dbda69eb1930c5e84d6ae4972b5194b9`; 1046 bytes).

### anyhow

Canonical upstream: <https://github.com/dtolnay/anyhow>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `anyhow` | `1.0.103` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `2a4385e2e34eb35d6b3efe798b9eb88096925d87726c0798709bf56d9ed84af3` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `anyhow 1.0.103`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/anyhow/1.0.103/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `anyhow 1.0.103`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/anyhow/1.0.103/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### arbitrary

Canonical upstream: <https://github.com/rust-fuzz/arbitrary>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `arbitrary` | `1.4.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `c3d036a3c4ab069c7b410a2ce876bd74808d2d0888a82667669f8e783a898bf1` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `arbitrary 1.4.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/arbitrary/1.4.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/15656cc11a8331f28c0986b8ab97220d3e76f98e60ed388b5ffad37dfac4710c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/15656cc11a8331f28c0986b8ab97220d3e76f98e60ed388b5ffad37dfac4710c.txt) (SHA-256 `15656cc11a8331f28c0986b8ab97220d3e76f98e60ed388b5ffad37dfac4710c`; 1074 bytes).
- `arbitrary 1.4.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/arbitrary/1.4.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### argon2

Canonical upstream: <https://github.com/RustCrypto/password-hashes/tree/master/argon2>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `argon2` | `0.5.3` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `argon2 0.5.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/argon2/0.5.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/33f702959c0ea91c08b21b65cf1f08b6c122ec9e6db0b5db784a7b367d942330.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/33f702959c0ea91c08b21b65cf1f08b6c122ec9e6db0b5db784a7b367d942330.txt) (SHA-256 `33f702959c0ea91c08b21b65cf1f08b6c122ec9e6db0b5db784a7b367d942330`; 1082 bytes).
- `argon2 0.5.3`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/argon2/0.5.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).

### async-trait

Canonical upstream: <https://github.com/dtolnay/async-trait>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `async-trait` | `0.1.89` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9035ad2d096bed7955a320ee7e2230574d28fd3c3a0f186cbea1ff3c7eed5dbb` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `async-trait 0.1.89`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/async-trait/0.1.89/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `async-trait 0.1.89`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/async-trait/0.1.89/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### atomic-waker

Canonical upstream: <https://github.com/smol-rs/atomic-waker>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `atomic-waker` | `1.1.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `1505bd5d3d116872e7271a6d4e16d81d0c8570876c8de68093a09ac269d8aac0` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `atomic-waker 1.1.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/atomic-waker/1.1.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `atomic-waker 1.1.2`: crate archive member [`LICENSE-THIRD-PARTY`](https://crates.io/api/v1/crates/atomic-waker/1.1.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6226d0632e2e1a80c23597e964da9812ae193c535fe058154afb034e94167aa5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6226d0632e2e1a80c23597e964da9812ae193c535fe058154afb034e94167aa5.txt) (SHA-256 `6226d0632e2e1a80c23597e964da9812ae193c535fe058154afb034e94167aa5`; 1849 bytes).
- `atomic-waker 1.1.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/atomic-waker/1.1.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### axum

Canonical upstream: <https://github.com/tokio-rs/axum>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `axum` | `0.8.9` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `31b698c5f9a010f6573133b09e0de5408834d0c82f8d7475a89fc1867a71cd90` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `axum-core` | `0.5.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `08c78f31d7b1291f7ee735c1c6780ccde7785daae9a9206026862dab7d8792d1` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `axum-core 0.5.6`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/axum-core/0.5.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/008c87afcd2e626eaf564093250bed06dd7efb5732113264bba3dda8f1c556a1.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/008c87afcd2e626eaf564093250bed06dd7efb5732113264bba3dda8f1c556a1.txt) (SHA-256 `008c87afcd2e626eaf564093250bed06dd7efb5732113264bba3dda8f1c556a1`; 1080 bytes).
- `axum 0.8.9`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/axum/0.8.9/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6a13bc24a100a6812f053879ec51b126b103af7cda6dbf48c4188722da44da9f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6a13bc24a100a6812f053879ec51b126b103af7cda6dbf48c4188722da44da9f.txt) (SHA-256 `6a13bc24a100a6812f053879ec51b126b103af7cda6dbf48c4188722da44da9f`; 1061 bytes).

### bitflags

Canonical upstream: <https://github.com/bitflags/bitflags>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `bitflags` | `2.13.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |

License evidence:

- `bitflags 2.13.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/bitflags/2.13.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb.txt) (SHA-256 `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb`; 1071 bytes).
- `bitflags 2.13.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/bitflags/2.13.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### bumpalo

Canonical upstream: <https://github.com/fitzgen/bumpalo>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `bumpalo` | `3.20.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `72f5acc6cb2ba439de613abc23857ec3d78374d8ed5ac84e9d11336e87da8649` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `bumpalo 3.20.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/bumpalo/3.20.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/65f94e99ddaf4f5d1782a6dae23f35d4293a9a01444a13135a6887017d353cee.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/65f94e99ddaf4f5d1782a6dae23f35d4293a9a01444a13135a6887017d353cee.txt) (SHA-256 `65f94e99ddaf4f5d1782a6dae23f35d4293a9a01444a13135a6887017d353cee`; 1059 bytes).
- `bumpalo 3.20.3`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/bumpalo/3.20.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### bytes

Canonical upstream: <https://github.com/tokio-rs/bytes>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `bytes` | `1.12.1` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `fc652a48c352aef3ea3aed32080501cf3ef6ed5da78602a020c991775b0aff04` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `bytes 1.12.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/bytes/1.12.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/45f522cacecb1023856e46df79ca625dfc550c94910078bd8aec6e02880b3d42.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/45f522cacecb1023856e46df79ca625dfc550c94910078bd8aec6e02880b3d42.txt) (SHA-256 `45f522cacecb1023856e46df79ca625dfc550c94910078bd8aec6e02880b3d42`; 1055 bytes).

### cc-rs

Canonical upstream: <https://github.com/rust-lang/cc-rs>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cc` | `1.2.67` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e17dd265a7d0f31ef544e1b20e03add05d3b45b491b633b10d67145d2acc1a38` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cc` | `1.4.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `5add81bb678e6cb321aff7fa0dc7689ad82b112dbc032cea19f91d6b8e3582b9` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `find-msvc-tools` | `0.1.9` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `cc 1.2.67`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cc/1.2.67/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt) (SHA-256 `378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397`; 1057 bytes).
- `cc 1.4.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cc/1.4.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt) (SHA-256 `378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397`; 1057 bytes).
- `find-msvc-tools 0.1.9`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/find-msvc-tools/0.1.9/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt) (SHA-256 `378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397`; 1057 bytes).
- `cc 1.2.67`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cc/1.2.67/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `cc 1.4.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cc/1.4.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `find-msvc-tools 0.1.9`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/find-msvc-tools/0.1.9/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### cfg-if

Canonical upstream: <https://github.com/rust-lang/cfg-if>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cfg-if` | `1.0.4` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |

License evidence:

- `cfg-if 1.0.4`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cfg-if/1.0.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt) (SHA-256 `378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397`; 1057 bytes).
- `cfg-if 1.0.4`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cfg-if/1.0.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### cfg_aliases

Canonical upstream: <https://github.com/katharostech/cfg_aliases>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cfg_aliases` | `0.2.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `f079e83a288787bcd14a6aea84cee5c87a67c5a3e660c30f557a3d24761b3527` | `MIT` | `MIT` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |

License evidence:

- `cfg_aliases 0.2.2`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cfg_aliases/0.2.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/31b94860253d8ec7b4529f51901044d3b459d6292d996504a36b1bae3a36a812.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/31b94860253d8ec7b4529f51901044d3b459d6292d996504a36b1bae3a36a812.txt) (SHA-256 `31b94860253d8ec7b4529f51901044d3b459d6292d996504a36b1bae3a36a812`; 1076 bytes).

### cobs.rs

Canonical upstream: <https://github.com/jamesmunns/cobs.rs>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cobs` | `0.3.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `0fa961b519f0b462e3a3b4a34b64d119eeaca1d59af726fe450bbba07a9fc0a1` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `cobs 0.3.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cobs/0.3.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08.txt) (SHA-256 `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08`; 11358 bytes).
- `cobs 0.3.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cobs/0.3.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/e0cfa1006a64520633de6bfbf563f5b1bea04ef0c5b73f049681931fa297dda3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/e0cfa1006a64520633de6bfbf563f5b1bea04ef0c5b73f049681931fa297dda3.txt) (SHA-256 `e0cfa1006a64520633de6bfbf563f5b1bea04ef0c5b73f049681931fa297dda3`; 1066 bytes).

### compiler-builtins

Canonical upstream: <https://github.com/rust-lang/compiler-builtins>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `libm` | `0.2.16` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `b6d2cec3eae94f9f509c767b45932f1ada8350c4bdb85af2fcab4a3c14807981` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `libm 0.2.16`: crate archive member [`LICENSE.txt`](https://crates.io/api/v1/crates/libm/0.2.16/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/3823dda7cf046602f4b4e77ec8e227863dc4736037cc85bb33d9f19febe16bb7.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/3823dda7cf046602f4b4e77ec8e227863dc4736037cc85bb33d9f19febe16bb7.txt) (SHA-256 `3823dda7cf046602f4b4e77ec8e227863dc4736037cc85bb33d9f19febe16bb7`; 14088 bytes).

### cpp_demangle

Canonical upstream: <https://github.com/gimli-rs/cpp_demangle>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cpp_demangle` | `0.4.5` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `f2bb79cb74d735044c972aae58ed0aaa9a837e85b01106a54c39e42e97f62253` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `cpp_demangle 0.4.5`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cpp_demangle/0.4.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0.txt) (SHA-256 `7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0`; 1071 bytes).
- `cpp_demangle 0.4.5`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cpp_demangle/0.4.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### crc-catalog

Canonical upstream: <https://github.com/akhilles/crc-catalog>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `crc-catalog` | `2.5.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `217698eaf96b4a3f0bc4f3662aaa55bdf913cd54d7204591faa790070c6d0853` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `crc-catalog 2.5.0`: crate archive member [`LICENSES/MIT.txt`](https://crates.io/api/v1/crates/crc-catalog/2.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/upstream/by-sha256/5ef8fcfb6cccec8fcae043c834099a60c8b7406408db576e026d2b7e67dc5cf5.txt`](THIRD-PARTY-LICENSES/upstream/by-sha256/5ef8fcfb6cccec8fcae043c834099a60c8b7406408db576e026d2b7e67dc5cf5.txt) (SHA-256 `5ef8fcfb6cccec8fcae043c834099a60c8b7406408db576e026d2b7e67dc5cf5`; 1073 bytes).
- `crc-catalog 2.5.0`: crate archive member [`LICENSES/Apache-2.0.txt`](https://crates.io/api/v1/crates/crc-catalog/2.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/upstream/by-sha256/d3cdb764b98283ee7c3a3cea8d374e2a2957322374378d1f3263f4d512741fc3.txt`](THIRD-PARTY-LICENSES/upstream/by-sha256/d3cdb764b98283ee7c3a3cea8d374e2a2957322374378d1f3263f4d512741fc3.txt) (SHA-256 `d3cdb764b98283ee7c3a3cea8d374e2a2957322374378d1f3263f4d512741fc3`; 11346 bytes).

### crc-rs

Canonical upstream: <https://github.com/mrhooray/crc-rs>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `crc` | `3.4.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `5eb8a2a1cd12ab0d987a5d5e825195d372001a4094a0376319d5a0ad71c1ba0d` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `crc 3.4.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/crc/3.4.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/3488679340a49ecc34d342c4009d2dabf76f4a21f12aec2ca99b15805d656544.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/3488679340a49ecc34d342c4009d2dabf76f4a21f12aec2ca99b15805d656544.txt) (SHA-256 `3488679340a49ecc34d342c4009d2dabf76f4a21f12aec2ca99b15805d656544`; 1074 bytes).
- `crc 3.4.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/crc/3.4.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/470355a7eed93fcc4281ec2e0f82ca3b94e7af1e4d83629f91de8cfac34d750e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/470355a7eed93fcc4281ec2e0f82ca3b94e7af1e4d83629f91de8cfac34d750e.txt) (SHA-256 `470355a7eed93fcc4281ec2e0f82ca3b94e7af1e4d83629f91de8cfac34d750e`; 10846 bytes).

### either

Canonical upstream: <https://github.com/rayon-rs/either>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `either` | `1.16.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `91622ff5e7162018101f2fea40d6ebf4a78bbe5a49736a2020649edf9693679e` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `either 1.16.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/either/1.16.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7576269ea71f767b99297934c0b2367532690f8c4badc695edf8e04ab6a1e545.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7576269ea71f767b99297934c0b2367532690f8c4badc695edf8e04ab6a1e545.txt) (SHA-256 `7576269ea71f767b99297934c0b2367532690f8c4badc695edf8e04ab6a1e545`; 1043 bytes).
- `either 1.16.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/either/1.16.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### embedded-hal

Canonical upstream: <https://github.com/rust-embedded/embedded-hal>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `embedded-io` | `0.6.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `edd0f118536f44f5ccd48bcb8b111bdc3de888b58c74639dfb034a357d0f206d` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `embedded-io 0.6.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/embedded-io/0.6.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/47674f8b7d98c232c6f81346c4cfe48933d913a9e257d7a522ad9f42e3dd61e1.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/47674f8b7d98c232c6f81346c4cfe48933d913a9e257d7a522ad9f42e3dd61e1.txt) (SHA-256 `47674f8b7d98c232c6f81346c4cfe48933d913a9e257d7a522ad9f42e3dd61e1`; 1067 bytes).
- `embedded-io 0.6.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/embedded-io/0.6.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### embedded-io

Canonical upstream: <https://github.com/embassy-rs/embedded-io>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `embedded-io` | `0.4.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ef1a6892d9eef45c8fa6b9e0086428a2cca8491aca8f787c534a3d6d0bcb3ced` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `embedded-io 0.4.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/embedded-io/0.4.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/423e1c4900b3fbb41cda3e34530b2597d50c2e61473e18c085756c507e46fe1c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/423e1c4900b3fbb41cda3e34530b2597d50c2e61473e18c085756c507e46fe1c.txt) (SHA-256 `423e1c4900b3fbb41cda3e34530b2597d50c2e61473e18c085756c507e46fe1c`; 1067 bytes).
- `embedded-io 0.4.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/embedded-io/0.4.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### equivalent

Canonical upstream: <https://github.com/indexmap-rs/equivalent>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `equivalent` | `1.0.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `equivalent 1.0.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/equivalent/1.0.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7365cc8878a1d7ce155a58c4ca09c3d7a6be413efa5334a80ea842912b669349.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7365cc8878a1d7ce155a58c4ca09c3d7a6be413efa5334a80ea842912b669349.txt) (SHA-256 `7365cc8878a1d7ce155a58c4ca09c3d7a6be413efa5334a80ea842912b669349`; 1049 bytes).
- `equivalent 1.0.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/equivalent/1.0.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### foldhash

Canonical upstream: <https://github.com/orlp/foldhash>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `foldhash` | `0.2.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `77ce24cb58228fbb8aa041425bb1050850ac19177686ea6e0f41a70416f56fdb` | `Zlib` | `Zlib` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `foldhash 0.2.0`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/foldhash/0.2.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b1181a40b2a7b25cf66fd01481713bc1005df082c53ef73e851e55071b102744.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b1181a40b2a7b25cf66fd01481713bc1005df082c53ef73e851e55071b102744.txt) (SHA-256 `b1181a40b2a7b25cf66fd01481713bc1005df082c53ef73e851e55071b102744`; 856 bytes).

### formats

Canonical upstream: <https://github.com/RustCrypto/formats>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `base64ct` | `1.8.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `2af50177e190e07a26ab74f8b1efbfe2ef87da2116221318cb1c2e82baf7de06` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `const-oid` | `0.10.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `a6ef517f0926dd24a1582492c791b6a4818a4d94e789a334894aa15b0d12f55c` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `base64ct 1.8.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/base64ct/1.8.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/2d1c57bff28344b9e698f51063bc8509799cc4c99a4e0cf2aa3f7e7c3e1f9a9d.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/2d1c57bff28344b9e698f51063bc8509799cc4c99a4e0cf2aa3f7e7c3e1f9a9d.txt) (SHA-256 `2d1c57bff28344b9e698f51063bc8509799cc4c99a4e0cf2aa3f7e7c3e1f9a9d`; 1148 bytes).
- `const-oid 0.10.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/const-oid/0.10.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/73b9dc2e79c7308998dd30296e073aefaefb944a68fb89aa412c23c0edcabcaa.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/73b9dc2e79c7308998dd30296e073aefaefb944a68fb89aa412c23c0edcabcaa.txt) (SHA-256 `73b9dc2e79c7308998dd30296e073aefaefb944a68fb89aa412c23c0edcabcaa`; 1082 bytes).
- `base64ct 1.8.3`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/base64ct/1.8.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `const-oid 0.10.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/const-oid/0.10.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).

### futures-rs

Canonical upstream: <https://github.com/rust-lang/futures-rs>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `futures` | `0.3.32` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8b147ee9d1f6d097cef9ce628cd2ee62288d963e16fb287bd9286455b241382d` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `futures-channel` | `0.3.32` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `07bbe89c50d7a535e539b8c17bc0b49bdb77747034daa8087407d655f3f7cc1d` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `futures-channel` | `0.3.33` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `262590f4fe6afeb0bc83be1daa64e52657fe185690a958af7f3ad0e92085c5ae` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `futures-core` | `0.3.33` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `2cd50c473c80f6d7c3670a752354b8e569b1a7cbfdc0419ec88e5edad85e0dc7` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `futures-io` | `0.3.32` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `cecba35d7ad927e23624b22ad55235f2239cfa44fd10428eecbeba6d6a717718` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `futures-macro` | `0.3.33` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `2d6d3cde68c518367be28956066ddfef33813991b77a55005a69dae04bf3b10b` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-api-stream/Cargo.lock` |
| `futures-sink` | `0.3.32` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `c39754e157331b013978ec91992bde1ac089843443c49cbc7f46150b0fad0893` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `futures-task` | `0.3.32` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `037711b3d59c33004d3856fbdc83b99d4ff37a24768fa1be9ce3538a1cde4393` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `futures-task` | `0.3.33` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `b231ed28831efb4a61a08580c4bc233ec56bc009f4cd8f52da2c3cb97df0c109` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock` |
| `futures-util` | `0.3.32` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `389ca41296e6190b48053de0321d02a77f32f8a5d2461dd38762c0593805c6d6` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `futures-util` | `0.3.33` | direct development; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `a77a90a256fce34da66415271e30f94ee91c57b04b8a2c042d9cf3220179deaa` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock` |

License evidence:

- `futures 0.3.32`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-channel 0.3.32`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-channel/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-channel 0.3.33`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-channel/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-core 0.3.33`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-core/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-io 0.3.32`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-io/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-macro 0.3.33`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-macro/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-sink 0.3.32`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-sink/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-task 0.3.32`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-task/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-task 0.3.33`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-task/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-util 0.3.32`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-util/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures-util 0.3.33`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/futures-util/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427.txt) (SHA-256 `275c491d6d1160553c32fd6127061d7f9606c3ea25abfad6ca3f6ed088785427`; 10874 bytes).
- `futures 0.3.32`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-channel 0.3.32`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-channel/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-channel 0.3.33`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-channel/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-core 0.3.33`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-core/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-io 0.3.32`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-io/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-macro 0.3.33`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-macro/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-sink 0.3.32`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-sink/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-task 0.3.32`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-task/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-task 0.3.33`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-task/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-util 0.3.32`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-util/0.3.32/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).
- `futures-util 0.3.33`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/futures-util/0.3.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd.txt) (SHA-256 `6652c868f35dfe5e8ef636810a4e576b9d663f3a17fb0f5613ad73583e1b88fd`; 1094 bytes).

### generic-array

Canonical upstream: <https://github.com/fizyk20/generic-array>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `generic-array` | `0.14.7` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `generic-array 0.14.7`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/generic-array/0.14.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c09aae9d3c77b531f56351a9947bc7446511d6b025b3255312d3e3442a9a7583.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c09aae9d3c77b531f56351a9947bc7446511d6b025b3255312d3e3442a9a7583.txt) (SHA-256 `c09aae9d3c77b531f56351a9947bc7446511d6b025b3255312d3e3442a9a7583`; 1107 bytes).

### getrandom

Canonical upstream: <https://github.com/rust-random/getrandom>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `getrandom` | `0.2.17` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `getrandom` | `0.4.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `getrandom 0.2.17`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/getrandom/0.2.17/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/42fa16951ce7f24b5a467a40e5b449a1d41e662f97ca779864f053f39e097737.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/42fa16951ce7f24b5a467a40e5b449a1d41e662f97ca779864f053f39e097737.txt) (SHA-256 `42fa16951ce7f24b5a467a40e5b449a1d41e662f97ca779864f053f39e097737`; 1130 bytes).
- `getrandom 0.4.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/getrandom/0.4.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/523a42c25d245dde9c015f882cec7f4555aad883382a6cf19b4b7d9b2cd5419b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/523a42c25d245dde9c015f882cec7f4555aad883382a6cf19b4b7d9b2cd5419b.txt) (SHA-256 `523a42c25d245dde9c015f882cec7f4555aad883382a6cf19b4b7d9b2cd5419b`; 1130 bytes).
- `getrandom 0.2.17`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/getrandom/0.2.17/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/aaff376532ea30a0cd5330b9502ad4a4c8bf769c539c87ffe78819d188a18ebf.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/aaff376532ea30a0cd5330b9502ad4a4c8bf769c539c87ffe78819d188a18ebf.txt) (SHA-256 `aaff376532ea30a0cd5330b9502ad4a4c8bf769c539c87ffe78819d188a18ebf`; 10849 bytes).
- `getrandom 0.4.3`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/getrandom/0.4.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/aaff376532ea30a0cd5330b9502ad4a4c8bf769c539c87ffe78819d188a18ebf.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/aaff376532ea30a0cd5330b9502ad4a4c8bf769c539c87ffe78819d188a18ebf.txt) (SHA-256 `aaff376532ea30a0cd5330b9502ad4a4c8bf769c539c87ffe78819d188a18ebf`; 10849 bytes).

### gimli

Canonical upstream: <https://github.com/gimli-rs/gimli>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `gimli` | `0.33.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `0bf7f043f89559805f8c7cacc432749b2fa0d0a0a9ee46ce47164ed5ba7f126c` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `gimli 0.33.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/gimli/0.33.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0.txt) (SHA-256 `7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0`; 1071 bytes).
- `gimli 0.33.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/gimli/0.33.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### hashbrown

Canonical upstream: <https://github.com/rust-lang/hashbrown>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `hashbrown` | `0.16.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `841d1cc9bed7f9236f321df977030373f4a4163ae1a7dbfe1a51a2c1a51d9100` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `hashbrown` | `0.17.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `hashbrown 0.16.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/hashbrown/0.16.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `hashbrown 0.17.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/hashbrown/0.17.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `hashbrown 0.16.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/hashbrown/0.16.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/ff8f68cb076caf8cefe7a6430d4ac086ce6af2ca8ce2c4e5a2004d4552ef52a2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/ff8f68cb076caf8cefe7a6430d4ac086ce6af2ca8ce2c4e5a2004d4552ef52a2.txt) (SHA-256 `ff8f68cb076caf8cefe7a6430d4ac086ce6af2ca8ce2c4e5a2004d4552ef52a2`; 1060 bytes).
- `hashbrown 0.17.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/hashbrown/0.17.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/ff8f68cb076caf8cefe7a6430d4ac086ce6af2ca8ce2c4e5a2004d4552ef52a2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/ff8f68cb076caf8cefe7a6430d4ac086ce6af2ca8ce2c4e5a2004d4552ef52a2.txt) (SHA-256 `ff8f68cb076caf8cefe7a6430d4ac086ce6af2ca8ce2c4e5a2004d4552ef52a2`; 1060 bytes).

### hashes

Canonical upstream: <https://github.com/RustCrypto/hashes>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `blake2` | `0.10.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `46502ad458c9a52b69d4d4d32775c788b7a1b85e8bc9d482d92250fc0e3f8efe` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `sha2` | `0.10.9` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `sha2` | `0.11.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `sha2 0.11.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/sha2/0.11.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/831e0f43ad0bf014c1c4fec5767aae470434c1d66d6e671be2d823e729063e25.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/831e0f43ad0bf014c1c4fec5767aae470434c1d66d6e671be2d823e729063e25.txt) (SHA-256 `831e0f43ad0bf014c1c4fec5767aae470434c1d66d6e671be2d823e729063e25`; 1196 bytes).
- `blake2 0.10.6`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/blake2/0.10.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/9c768944eb4a0422ca2efc25ea9fb2fb9e7fbd3fdb04e86b87366339cb7466db.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/9c768944eb4a0422ca2efc25ea9fb2fb9e7fbd3fdb04e86b87366339cb7466db.txt) (SHA-256 `9c768944eb4a0422ca2efc25ea9fb2fb9e7fbd3fdb04e86b87366339cb7466db`; 1121 bytes).
- `blake2 0.10.6`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/blake2/0.10.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `sha2 0.10.9`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/sha2/0.10.9/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `sha2 0.11.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/sha2/0.11.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `sha2 0.10.9`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/sha2/0.10.9/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b4eb00df6e2a4d22518fcaa6a2b4646f249b3a3c9814509b22bd2091f1392ff1.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b4eb00df6e2a4d22518fcaa6a2b4646f249b3a3c9814509b22bd2091f1392ff1.txt) (SHA-256 `b4eb00df6e2a4d22518fcaa6a2b4646f249b3a3c9814509b22bd2091f1392ff1`; 1138 bytes).

### heck

Canonical upstream: <https://github.com/withoutboats/heck>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `heck` | `0.5.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `2304e00983f87ffb38b55b444b5e3b60a884b5d30c0fca7d82fe33449bbe55ea` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `heck 0.5.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/heck/0.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0.txt) (SHA-256 `7b63ecd5f1902af1b63729947373683c32745c16a10e8e6292e2e2dcd7e90ae0`; 1071 bytes).
- `heck 0.5.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/heck/0.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### http

Canonical upstream: <https://github.com/hyperium/http>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `http` | `1.5.0` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `918d3568bebf352712bc2ef3d46a8bcf1a75b373be6539de198e9105cbbf9ce0` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `http 1.5.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/http/1.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/8bb1b50b0e5c9399ae33bd35fab2769010fa6c14e8860c729a52295d84896b7a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/8bb1b50b0e5c9399ae33bd35fab2769010fa6c14e8860c729a52295d84896b7a.txt) (SHA-256 `8bb1b50b0e5c9399ae33bd35fab2769010fa6c14e8860c729a52295d84896b7a`; 10835 bytes).
- `http 1.5.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/http/1.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/dc91f8200e4b2a1f9261035d4c18c33c246911a6c0f7b543d75347e61b249cff.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/dc91f8200e4b2a1f9261035d4c18c33c246911a6c0f7b543d75347e61b249cff.txt) (SHA-256 `dc91f8200e4b2a1f9261035d4c18c33c246911a6c0f7b543d75347e61b249cff`; 1059 bytes).

### http-body

Canonical upstream: <https://github.com/hyperium/http-body>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `http-body` | `1.1.0` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ca2a8f2913ee65f60facd6a5905613afaa448497a0230cc41ce022d93290bc2c` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `http-body-util` | `0.1.4` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e9f41fd6a08e4d4ec69df65976da761afd5ad5e58a9d4acb46bd1c953a9e3ff2` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `http-body 1.1.0`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/http-body/1.1.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/248378d0a3383c173fb925f17141b88e71580b3ba17ddc6ac3d2a344683232ab.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/248378d0a3383c173fb925f17141b88e71580b3ba17ddc6ac3d2a344683232ab.txt) (SHA-256 `248378d0a3383c173fb925f17141b88e71580b3ba17ddc6ac3d2a344683232ab`; 1083 bytes).
- `http-body-util 0.1.4`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/http-body-util/0.1.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/248378d0a3383c173fb925f17141b88e71580b3ba17ddc6ac3d2a344683232ab.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/248378d0a3383c173fb925f17141b88e71580b3ba17ddc6ac3d2a344683232ab.txt) (SHA-256 `248378d0a3383c173fb925f17141b88e71580b3ba17ddc6ac3d2a344683232ab`; 1083 bytes).

### httparse

Canonical upstream: <https://github.com/seanmonstar/httparse>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `httparse` | `1.10.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6dbf3de79e51f3d586ab4cb9d5c3e2c14aa28ed23d180cf89b4df0454a69cc87` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `httparse 1.10.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/httparse/1.10.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/391a5396cec6230bfabd4ef4eb2350eb895bc5efce377a2218f5702ed020d3e3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/391a5396cec6230bfabd4ef4eb2350eb895bc5efce377a2218f5702ed020d3e3.txt) (SHA-256 `391a5396cec6230bfabd4ef4eb2350eb895bc5efce377a2218f5702ed020d3e3`; 1063 bytes).
- `httparse 1.10.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/httparse/1.10.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### hybrid-array

Canonical upstream: <https://github.com/RustCrypto/hybrid-array>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `hybrid-array` | `0.4.13` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `818356c5132c1fede50f837ca96afbe78ff42413047f4abb886217845e1b6c8c` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `hybrid-array 0.4.13`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/hybrid-array/0.4.13/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/70c9d40f1f9545c3f133b8a67206e89da850f6468eed072281bb3701514114a9.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/70c9d40f1f9545c3f133b8a67206e89da850f6468eed072281bb3701514114a9.txt) (SHA-256 `70c9d40f1f9545c3f133b8a67206e89da850f6468eed072281bb3701514114a9`; 1082 bytes).
- `hybrid-array 0.4.13`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/hybrid-array/0.4.13/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).

### hyper

Canonical upstream: <https://github.com/hyperium/hyper>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `hyper` | `1.11.0` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `d22053281f852e11534f5198498373cbb59295120a20771d90f7ed1897490a72` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `hyper 1.11.0`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/hyper/1.11.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/2d01890414494742ba4a509fcec8efa40f6d8be22cbd72be7cff08d6fda4ec89.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/2d01890414494742ba4a509fcec8efa40f6d8be22cbd72be7cff08d6fda4ec89.txt) (SHA-256 `2d01890414494742ba4a509fcec8efa40f6d8be22cbd72be7cff08d6fda4ec89`; 1062 bytes).

### hyper-util

Canonical upstream: <https://github.com/hyperium/hyper-util>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `hyper-util` | `0.1.20` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `96547c2556ec9d12fb1578c4eaf448b04993e7fb79cbaad930a656880a6bdfa0` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `hyper-util 0.1.20`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/hyper-util/0.1.20/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/9e0a97848ea543aef745c98e84fde696a9a3e0735538f6daefdd3cb1942effc1.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/9e0a97848ea543aef745c98e84fde696a9a3e0735538f6daefdd3cb1942effc1.txt) (SHA-256 `9e0a97848ea543aef745c98e84fde696a9a3e0735538f6daefdd3cb1942effc1`; 1062 bytes).

### indexmap

Canonical upstream: <https://github.com/indexmap-rs/indexmap>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `indexmap` | `2.14.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `d466e9454f08e4a911e14806c24e16fba1b4c121d1ea474396f396069cf949d9` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `indexmap 2.14.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/indexmap/2.14.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `indexmap 2.14.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/indexmap/2.14.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/ecc269ef87fd38a1d98e30bfac9ba964a9dbd9315c3770fed98d4d7cb5882055.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/ecc269ef87fd38a1d98e30bfac9ba964a9dbd9315c3770fed98d4d7cb5882055.txt) (SHA-256 `ecc269ef87fd38a1d98e30bfac9ba964a9dbd9315c3770fed98d4d7cb5882055`; 1049 bytes).

### itertools

Canonical upstream: <https://github.com/rust-itertools/itertools>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `itertools` | `0.14.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `2b192c782037fadd9cfa75548310488aabdbf3d2da73885b31bd0abd03351285` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `itertools 0.14.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/itertools/0.14.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7576269ea71f767b99297934c0b2367532690f8c4badc695edf8e04ab6a1e545.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7576269ea71f767b99297934c0b2367532690f8c4badc695edf8e04ab6a1e545.txt) (SHA-256 `7576269ea71f767b99297934c0b2367532690f8c4badc695edf8e04ab6a1e545`; 1043 bytes).
- `itertools 0.14.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/itertools/0.14.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### itoa

Canonical upstream: <https://github.com/dtolnay/itoa>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `itoa` | `1.0.18` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `itoa 1.0.18`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/itoa/1.0.18/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `itoa 1.0.18`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/itoa/1.0.18/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### json

Canonical upstream: <https://github.com/serde-rs/json>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `serde_json` | `1.0.150` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e8014e44b4736ed0538adeecded0fce2a272f22dc9578a7eb6b2d9993c74cfb9` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `serde_json 1.0.150`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/serde_json/1.0.150/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `serde_json 1.0.150`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/serde_json/1.0.150/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### leb128fmt

Canonical upstream: <https://github.com/bluk/leb128fmt>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `leb128fmt` | `0.1.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `09edd9e8b54e49e587e4f6295a7d29c3ea94d469cb40ab8ca70b288248a81db2` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `leb128fmt 0.1.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/leb128fmt/0.1.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `leb128fmt 0.1.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/leb128fmt/0.1.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### libc

Canonical upstream: <https://github.com/rust-lang/libc>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `libc` | `0.2.186` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `68ab91017fe16c622486840e4c83c9a37afeff978bd239b5293d61ece587de66` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |
| `libc` | `0.2.188` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `22053b6a34f84abc97f9129e61334f40174659a1b9bd18c970b83db6a9a6348b` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock` |
| `libc` | `0.2.189` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock` |

License evidence:

- `libc 0.2.186`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/libc/0.2.186/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e.txt) (SHA-256 `123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e`; 1066 bytes).
- `libc 0.2.188`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/libc/0.2.188/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e.txt) (SHA-256 `123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e`; 1066 bytes).
- `libc 0.2.189`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/libc/0.2.189/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e.txt) (SHA-256 `123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e`; 1066 bytes).
- `libc 0.2.186`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/libc/0.2.186/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `libc 0.2.188`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/libc/0.2.188/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `libc 0.2.189`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/libc/0.2.189/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### linux-raw-sys

Canonical upstream: <https://github.com/sunfishcode/linux-raw-sys>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `linux-raw-sys` | `0.12.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `linux-raw-sys 0.12.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/linux-raw-sys/0.12.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `linux-raw-sys 0.12.1`: crate archive member [`LICENSE-Apache-2.0_WITH_LLVM-exception`](https://crates.io/api/v1/crates/linux-raw-sys/0.12.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `linux-raw-sys 0.12.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/linux-raw-sys/0.12.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### log

Canonical upstream: <https://github.com/rust-lang/log>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `log` | `0.4.33` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `0ceec5bc11778974d1bcb055b18002eba7f4b3518b6a0081b3af5f21666da9ad` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `log 0.4.33`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/log/0.4.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb.txt) (SHA-256 `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb`; 1071 bytes).
- `log 0.4.33`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/log/0.4.33/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### mach2

Canonical upstream: <https://github.com/JohnTitor/mach2>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mach2` | `0.6.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `dae608c151f68243f2b000364e1f7b186d9c29845f7d2d85bd31b9ad77ad552b` | `BSD-2-Clause OR MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `mach2 0.6.0`: crate archive member [`LICENSE-BSD`](https://crates.io/api/v1/crates/mach2/0.6.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/044983df14c97f2f9570766aaf977b3cdfc4a06cf1f36b776331c5ff89b4fb89.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/044983df14c97f2f9570766aaf977b3cdfc4a06cf1f36b776331c5ff89b4fb89.txt) (SHA-256 `044983df14c97f2f9570766aaf977b3cdfc4a06cf1f36b776331c5ff89b4fb89`; 1320 bytes).
- `mach2 0.6.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/mach2/0.6.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/3f9f0f7e5a5911a8042e32c83ff5d061ce1ffd02e8a207ec2135a44ad73b4191.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/3f9f0f7e5a5911a8042e32c83ff5d061ce1ffd02e8a207ec2135a44ad73b4191.txt) (SHA-256 `3f9f0f7e5a5911a8042e32c83ff5d061ce1ffd02e8a207ec2135a44ad73b4191`; 1077 bytes).
- `mach2 0.6.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/mach2/0.6.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### MACs

Canonical upstream: <https://github.com/RustCrypto/MACs>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `hmac` | `0.12.1` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6c49c37c09c17a53d937dfbb742eb3a961d65a994e6bcdcf37e7399d0cc8ab5e` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `hmac` | `0.13.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `hmac 0.12.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/hmac/0.12.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba.txt) (SHA-256 `9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba`; 1057 bytes).
- `hmac 0.13.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/hmac/0.13.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba.txt) (SHA-256 `9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba`; 1057 bytes).
- `hmac 0.12.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/hmac/0.12.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `hmac 0.13.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/hmac/0.13.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).

### matchit

Canonical upstream: <https://github.com/ibraheemdev/matchit>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `matchit` | `0.8.4` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `47e1ffaa40ddd1f3ed91f717a33c8c0ee23fff369e3aa8772b9605cc1d22f4c3` | `MIT AND BSD-3-Clause` | `BSD-3-Clause AND MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `matchit 0.8.4`: crate archive member [`LICENSE.httprouter`](https://crates.io/api/v1/crates/matchit/0.8.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/162ce11ad71338d0a0c6ebaf5c48af72c6ae237b468859d3656fe2d9ed3f3a85.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/162ce11ad71338d0a0c6ebaf5c48af72c6ae237b468859d3656fe2d9ed3f3a85.txt) (SHA-256 `162ce11ad71338d0a0c6ebaf5c48af72c6ae237b468859d3656fe2d9ed3f3a85`; 1522 bytes).
- `matchit 0.8.4`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/matchit/0.8.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/de701d0618d694feb1af90f02181a1763d9b0bdeb70a3a592781e529077dba65.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/de701d0618d694feb1af90f02181a1763d9b0bdeb70a3a592781e529077dba65.txt) (SHA-256 `de701d0618d694feb1af90f02181a1763d9b0bdeb70a3a592781e529077dba65`; 1071 bytes).

### memchr

Canonical upstream: <https://github.com/BurntSushi/memchr>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `memchr` | `2.8.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98` | `Unlicense OR MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `memchr 2.8.3`: crate archive member [`COPYING`](https://crates.io/api/v1/crates/memchr/2.8.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f.txt) (SHA-256 `01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f`; 126 bytes).
- `memchr 2.8.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/memchr/2.8.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0f96a83840e146e43c0ec96a22ec1f392e0680e6c1226e6f3ba87e0740af850f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0f96a83840e146e43c0ec96a22ec1f392e0680e6c1226e6f3ba87e0740af850f.txt) (SHA-256 `0f96a83840e146e43c0ec96a22ec1f392e0680e6c1226e6f3ba87e0740af850f`; 1081 bytes).
- `memchr 2.8.3`: crate archive member [`UNLICENSE`](https://crates.io/api/v1/crates/memchr/2.8.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c.txt) (SHA-256 `7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c`; 1211 bytes).

### memfd-rs

Canonical upstream: <https://github.com/lucab/memfd-rs>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `memfd` | `0.6.5` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ad38eb12aea514a0466ea40a80fd8cc83637065948eb4a426e4aa46261175227` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `memfd 0.6.5`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/memfd/0.6.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4.txt) (SHA-256 `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`; 11357 bytes).
- `memfd 0.6.5`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/memfd/0.6.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/e5d8f26c5b92d382e7ab2826500e5099a40a7751e92a55bc51c6770933411f9e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/e5d8f26c5b92d382e7ab2826500e5099a40a7751e92a55bc51c6770933411f9e.txt) (SHA-256 `e5d8f26c5b92d382e7ab2826500e5099a40a7751e92a55bc51c6770933411f9e`; 1060 bytes).

### mime

Canonical upstream: <https://github.com/hyperium/mime>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mime` | `0.3.17` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6877bb514081ee2a7ff5ef9de3281f14a4dd4bceac4c09388074a6b5df8a139a` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `mime 0.3.17`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/mime/0.3.17/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `mime 0.3.17`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/mime/0.3.17/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/df9cfd06d8a44d9a671eadd39ffd97f166481da015a30f45dfd27886209c5922.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/df9cfd06d8a44d9a671eadd39ffd97f166481da015a30f45dfd27886209c5922.txt) (SHA-256 `df9cfd06d8a44d9a671eadd39ffd97f166481da015a30f45dfd27886209c5922`; 1058 bytes).

### mio

Canonical upstream: <https://github.com/tokio-rs/mio>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mio` | `1.2.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `30d65c71f1ce40ab09135ce117d742b9f8a19ff91a41a8b57ed50bc2de59c427` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `mio 1.2.2`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/mio/1.2.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/07919255c7e04793d8ea760d6c2ce32d19f9ff02bdbdde3ce90b1e1880929a9b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/07919255c7e04793d8ea760d6c2ce32d19f9ff02bdbdde3ce90b1e1880929a9b.txt) (SHA-256 `07919255c7e04793d8ea760d6c2ce32d19f9ff02bdbdde3ce90b1e1880929a9b`; 1082 bytes).

### nix

Canonical upstream: <https://github.com/nix-rust/nix>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `nix` | `0.31.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d` | `MIT` | `MIT` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |

License evidence:

- `nix 0.31.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/nix/0.31.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/66e3ee1fa7f909ad3c612d556f2a0cdabcd809ad6e66f3b0605015ac64841b70.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/66e3ee1fa7f909ad3c612d556f2a0cdabcd809ad6e66f3b0605015ac64841b70.txt) (SHA-256 `66e3ee1fa7f909ad3c612d556f2a0cdabcd809ad6e66f3b0605015ac64841b70`; 1097 bytes).

### objc2

Canonical upstream: <https://github.com/madsmtm/objc2>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `block2` | `0.6.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `cdeb9d870516001442e364c5220d3574d2da8dc765554b4a617230d33fa58ef5` | `MIT` | `MIT` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |
| `dispatch2` | `0.3.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `1e0e367e4e7da84520dedcac1901e4da967309406d1e51017ae1abfb97adbd38` | `Zlib OR Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |
| `objc2` | `0.6.4` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `3a12a8ed07aefc768292f076dc3ac8c48f3781c8f2d5851dd3d98950e8c5a89f` | `MIT` | `MIT` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |
| `objc2-encode` | `4.1.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ef25abbcd74fb2609453eb695bd2f860d389e457f67dc17cafc8b8cbc89d0c33` | `MIT` | `MIT` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |

License evidence:

- `block2 0.6.2`: immutable upstream file [`LICENSE.md`](https://raw.githubusercontent.com/madsmtm/objc2/b4167b582b2f75f9a1be75495c41b765344fd03c/LICENSE.md) -> [`AHCL/THIRD-PARTY-LICENSES/upstream/by-sha256/7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54.txt`](THIRD-PARTY-LICENSES/upstream/by-sha256/7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54.txt) (SHA-256 `7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54`; 1339 bytes).
- `dispatch2 0.3.1`: immutable upstream file [`LICENSE.md`](https://raw.githubusercontent.com/madsmtm/objc2/8852b424193ca41602281b3d7540d7c8ed51e49a/LICENSE.md) -> [`AHCL/THIRD-PARTY-LICENSES/upstream/by-sha256/7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54.txt`](THIRD-PARTY-LICENSES/upstream/by-sha256/7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54.txt) (SHA-256 `7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54`; 1339 bytes).
- `objc2 0.6.4`: immutable upstream file [`LICENSE.md`](https://raw.githubusercontent.com/madsmtm/objc2/8852b424193ca41602281b3d7540d7c8ed51e49a/LICENSE.md) -> [`AHCL/THIRD-PARTY-LICENSES/upstream/by-sha256/7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54.txt`](THIRD-PARTY-LICENSES/upstream/by-sha256/7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54.txt) (SHA-256 `7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54`; 1339 bytes).
- `objc2-encode 4.1.0`: immutable upstream file [`LICENSE.md`](https://raw.githubusercontent.com/madsmtm/objc2/8d214f5477365ffcbcbb7de058c86ed9a518efb7/LICENSE.md) -> [`AHCL/THIRD-PARTY-LICENSES/upstream/by-sha256/7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54.txt`](THIRD-PARTY-LICENSES/upstream/by-sha256/7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54.txt) (SHA-256 `7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54`; 1339 bytes).

### object

Canonical upstream: <https://github.com/gimli-rs/object>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `object` | `0.39.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `2e5a6c098c7a3b6547378093f5cc30bc54fd361ce711e05293a5cc589562739b` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `object 0.39.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/object/0.39.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0b74dfa0bcee5c420c6b7f67b4b2658f9ab8388c97b8e733975f2cecbdd668a6.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0b74dfa0bcee5c420c6b7f67b4b2658f9ab8388c97b8e733975f2cecbdd668a6.txt) (SHA-256 `0b74dfa0bcee5c420c6b7f67b4b2658f9ab8388c97b8e733975f2cecbdd668a6`; 1064 bytes).
- `object 0.39.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/object/0.39.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### once_cell

Canonical upstream: <https://github.com/matklad/once_cell>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `once_cell` | `1.21.4` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `once_cell 1.21.4`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/once_cell/1.21.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `once_cell 1.21.4`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/once_cell/1.21.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### password-hash

Canonical upstream: <https://github.com/RustCrypto/traits/tree/master/password-hash>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `password-hash` | `0.5.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `346f04948ba92c43e8469c1ee6736c7563d71012b17d40745260fe106aac2166` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `password-hash 0.5.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/password-hash/0.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/233b95ccbf90dc67e32f3e8995c489f6312d9191ebd141a931c3b684f1e3be6d.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/233b95ccbf90dc67e32f3e8995c489f6312d9191ebd141a931c3b684f1e3be6d.txt) (SHA-256 `233b95ccbf90dc67e32f3e8995c489f6312d9191ebd141a931c3b684f1e3be6d`; 1070 bytes).
- `password-hash 0.5.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/password-hash/0.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).

### path-to-error

Canonical upstream: <https://github.com/dtolnay/path-to-error>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `serde_path_to_error` | `0.1.20` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `10a9ff822e371bb5403e391ecd83e182e0e77ba7f6fe0160b795797109d1b457` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `serde_path_to_error 0.1.20`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/serde_path_to_error/0.1.20/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `serde_path_to_error 0.1.20`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/serde_path_to_error/0.1.20/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### pin-project-lite

Canonical upstream: <https://github.com/taiki-e/pin-project-lite>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pin-project-lite` | `0.2.17` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `pin-project-lite 0.2.17`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/pin-project-lite/0.2.17/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594.txt) (SHA-256 `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594`; 10174 bytes).
- `pin-project-lite 0.2.17`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/pin-project-lite/0.2.17/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).

### pki-types

Canonical upstream: <https://github.com/rustls/pki-types>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rustls-pki-types` | `1.15.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `764899a24af3980067ee14bc143654f297b22eaebfe3c7b6b211920a5a59b046` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `rustls-pki-types 1.15.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/rustls-pki-types/1.15.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/45fd05c4865e7c350b98ad7ac50e1b15462d49af4a91e9b0c9dd933dc9a69742.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/45fd05c4865e7c350b98ad7ac50e1b15462d49af4a91e9b0c9dd933dc9a69742.txt) (SHA-256 `45fd05c4865e7c350b98ad7ac50e1b15462d49af4a91e9b0c9dd933dc9a69742`; 10835 bytes).
- `rustls-pki-types 1.15.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/rustls-pki-types/1.15.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/9117d922e667125508dde62b02c1f57ed22f5ad21eb536aa2e2d99e1c796e639.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/9117d922e667125508dde62b02c1f57ed22f5ad21eb536aa2e2d99e1c796e639.txt) (SHA-256 `9117d922e667125508dde62b02c1f57ed22f5ad21eb536aa2e2d99e1c796e639`; 1080 bytes).

### postcard

Canonical upstream: <https://github.com/jamesmunns/postcard>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `postcard` | `1.1.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6764c3b5dd454e283a30e6dfe78e9b31096d9e32036b5d1eaac7a6119ccb9a24` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `postcard 1.1.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/postcard/1.1.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/177540cad091a40e8071db310bc3b6115c4e329a92a234609b60c154b008a888.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/177540cad091a40e8071db310bc3b6115c4e329a92a234609b60c154b008a888.txt) (SHA-256 `177540cad091a40e8071db310bc3b6115c4e329a92a234609b60c154b008a888`; 1063 bytes).
- `postcard 1.1.3`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/postcard/1.1.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### proc-macro2

Canonical upstream: <https://github.com/dtolnay/proc-macro2>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `proc-macro2` | `1.0.106` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8fd00f0bb2e90d81d1044c2b32617f68fcb9fa3bb7640c23e9c748e53fb30934` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `proc-macro2` | `1.0.107` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `proc-macro2 1.0.106`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/proc-macro2/1.0.106/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `proc-macro2 1.0.107`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/proc-macro2/1.0.107/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `proc-macro2 1.0.106`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/proc-macro2/1.0.106/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `proc-macro2 1.0.107`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/proc-macro2/1.0.107/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### quote

Canonical upstream: <https://github.com/dtolnay/quote>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `quote` | `1.0.46` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `dfbc457d0c7a0759a614551b11a6409e5951f6c7537be1f1b7682b9ae9230368` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `quote` | `1.0.47` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `quote 1.0.46`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/quote/1.0.46/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `quote 1.0.47`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/quote/1.0.47/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `quote 1.0.46`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/quote/1.0.46/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `quote 1.0.47`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/quote/1.0.47/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### r-efi

Canonical upstream: <https://github.com/r-efi/r-efi>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `r-efi` | `6.0.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | `MIT` | explicit package license election | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `r-efi 6.0.0`: crate archive member [`AUTHORS`](https://crates.io/api/v1/crates/r-efi/6.0.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/d027e91dbc9cdbb2f1190068e498bd6b61cff022b6a032b191021ba658d96111.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/d027e91dbc9cdbb2f1190068e498bd6b61cff022b6a032b191021ba658d96111.txt) (SHA-256 `d027e91dbc9cdbb2f1190068e498bd6b61cff022b6a032b191021ba658d96111`; 3733 bytes).

### rand

Canonical upstream: <https://github.com/rust-random/rand>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rand` | `0.8.7` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `22f6172bdec972074665ed81ed53b71da00bfc44b65a753cfde883ec4c702a1a` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rand_core` | `0.6.4` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ec0be4795e2f6a28069bec0b5ff3e2ac9bafc99e6a9a7dc3547996c5c816922c` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `rand 0.8.7`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/rand/0.8.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/209fbbe0ad52d9235e37badf9cadfe4dbdc87203179c0899e738b39ade42177b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/209fbbe0ad52d9235e37badf9cadfe4dbdc87203179c0899e738b39ade42177b.txt) (SHA-256 `209fbbe0ad52d9235e37badf9cadfe4dbdc87203179c0899e738b39ade42177b`; 1117 bytes).
- `rand_core 0.6.4`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/rand_core/0.6.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/209fbbe0ad52d9235e37badf9cadfe4dbdc87203179c0899e738b39ade42177b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/209fbbe0ad52d9235e37badf9cadfe4dbdc87203179c0899e738b39ade42177b.txt) (SHA-256 `209fbbe0ad52d9235e37badf9cadfe4dbdc87203179c0899e738b39ade42177b`; 1117 bytes).
- `rand 0.8.7`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/rand/0.8.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/35242e7a83f69875e6edeff02291e688c97caafe2f8902e4e19b49d3e78b4cab.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/35242e7a83f69875e6edeff02291e688c97caafe2f8902e4e19b49d3e78b4cab.txt) (SHA-256 `35242e7a83f69875e6edeff02291e688c97caafe2f8902e4e19b49d3e78b4cab`; 9724 bytes).
- `rand_core 0.6.4`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/rand_core/0.6.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6df43f6f4b5d4587f3d8d71e45532c688fd168afa5fe89d571cb32fa09c4ef51.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6df43f6f4b5d4587f3d8d71e45532c688fd168afa5fe89d571cb32fa09c4ef51.txt) (SHA-256 `6df43f6f4b5d4587f3d8d71e45532c688fd168afa5fe89d571cb32fa09c4ef51`; 10282 bytes).

### rand_core

Canonical upstream: <https://github.com/rust-random/rand_core>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rand_core` | `0.10.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `rand_core 0.10.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/rand_core/0.10.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6df43f6f4b5d4587f3d8d71e45532c688fd168afa5fe89d571cb32fa09c4ef51.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6df43f6f4b5d4587f3d8d71e45532c688fd168afa5fe89d571cb32fa09c4ef51.txt) (SHA-256 `6df43f6f4b5d4587f3d8d71e45532c688fd168afa5fe89d571cb32fa09c4ef51`; 10282 bytes).
- `rand_core 0.10.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/rand_core/0.10.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/8b6e9feec03e7c9a5facb26855cecd31662bf989b636bcfe79521bdf8ac863f0.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/8b6e9feec03e7c9a5facb26855cecd31662bf989b636bcfe79521bdf8ac863f0.txt) (SHA-256 `8b6e9feec03e7c9a5facb26855cecd31662bf989b636bcfe79521bdf8ac863f0`; 1076 bytes).

### regalloc2

Canonical upstream: <https://github.com/bytecodealliance/regalloc2>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `regalloc2` | `0.15.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `de2c52737737f8609e94f975dee22854a2d5c125772d4b1cf292120f4d45c186` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `regalloc2 0.15.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/regalloc2/0.15.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).

### ring

Canonical upstream: <https://github.com/briansmith/ring>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `ring` | `0.17.14` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7` | `Apache-2.0 AND ISC` | `Apache-2.0 AND ISC` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `ring 0.17.14`: crate archive member [`LICENSE-BoringSSL`](https://crates.io/api/v1/crates/ring/0.17.14/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/005fc765ddc5115da796cca915baa9557abae13ff35e0a47c47affc56f6c414d.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/005fc765ddc5115da796cca915baa9557abae13ff35e0a47c47affc56f6c414d.txt) (SHA-256 `005fc765ddc5115da796cca915baa9557abae13ff35e0a47c47affc56f6c414d`; 14870 bytes).
- `ring 0.17.14`: crate archive member [`src/polyfill/once_cell/LICENSE-MIT`](https://crates.io/api/v1/crates/ring/0.17.14/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/6ee2ed6c77710de911761acd5fc1ad1da00f476beb1a7ef27e78c2d1858deafc.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/6ee2ed6c77710de911761acd5fc1ad1da00f476beb1a7ef27e78c2d1858deafc.txt) (SHA-256 `6ee2ed6c77710de911761acd5fc1ad1da00f476beb1a7ef27e78c2d1858deafc`; 1022 bytes).
- `ring 0.17.14`: crate archive member [`third_party/fiat/LICENSE`](https://crates.io/api/v1/crates/ring/0.17.14/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/9eacbcb81be660840c714a560a9d65ba07913db98dd4baf969f78dd499fdd60f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/9eacbcb81be660840c714a560a9d65ba07913db98dd4baf969f78dd499fdd60f.txt) (SHA-256 `9eacbcb81be660840c714a560a9d65ba07913db98dd4baf969f78dd499fdd60f`; 638 bytes).
- `ring 0.17.14`: crate archive member [`src/polyfill/once_cell/LICENSE-APACHE`](https://crates.io/api/v1/crates/ring/0.17.14/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `ring 0.17.14`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/ring/0.17.14/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b3d734001a94efff3579978d953391aa7115f877657d25eb54037a43875d078a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b3d734001a94efff3579978d953391aa7115f877657d25eb54037a43875d078a.txt) (SHA-256 `b3d734001a94efff3579978d953391aa7115f877657d25eb54037a43875d078a`; 499 bytes).
- `ring 0.17.14`: crate archive member [`LICENSE-other-bits`](https://crates.io/api/v1/crates/ring/0.17.14/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/f025ccfb7dfb6bdfedc75ca0f67acc69e6fb4998143d834f7c2f38a29989680f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/f025ccfb7dfb6bdfedc75ca0f67acc69e6fb4998143d834f7c2f38a29989680f.txt) (SHA-256 `f025ccfb7dfb6bdfedc75ca0f67acc69e6fb4998143d834f7c2f38a29989680f`; 731 bytes).

### RNovModularDB

Canonical upstream: <https://github.com/czxieddan/RNovModularDB>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rnmdb-catalog` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-cli` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-common` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-executor` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-fts` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-index` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-instance` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-planner` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-security` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-server` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-sql` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-storage` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-txn` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-types` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `rnmdb-udf` | `0.1.0` | direct runtime; transitive | `git+https://github.com/czxieddan/RNovModularDB.git?rev=f20040a127a56ec8c37b3398283df36f024a1dd2#f20040a127a56ec8c37b3398283df36f024a1dd2` | `not applicable` | `validated internally; selected treatment shown` | `LicenseRef-AHCL-1.0` | dependency policy table [rnmdb_ahcl_dependency] | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

Selected license copy: `AHCL/AHCL-1.0.md`.
Additional restrictions for this dependency selection: `none`.

License evidence:

- `rnmdb-catalog 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-cli 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-common 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-executor 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-fts 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-index 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-instance 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-planner 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-security 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-server 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-sql 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-storage 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-txn 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-types 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).
- `rnmdb-udf 0.1.0`: repository policy record `AHCL/AHCL-1.0.md` -> [`AHCL/AHCL-1.0.md`](AHCL-1.0.md) (SHA-256 `01c51c190a021cedcd072fdb2a7da1857bf5ef9a8770d26104aa472455ac003e`; 63907 bytes).

### rust-base64

Canonical upstream: <https://github.com/marshallpierce/rust-base64>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `base64` | `0.22.1` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `base64 0.22.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/base64/0.22.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### rust-crc32fast

Canonical upstream: <https://github.com/srijs/rust-crc32fast>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `crc32fast` | `1.5.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9481c1c90cbf2ac953f07c8d4a58aa3945c425b7185c9154d67a65e4230da511` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `crc32fast 1.5.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/crc32fast/1.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/61d383b05b87d78f94d2937e2580cce47226d17823c0430fbcad09596537efcf.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/61d383b05b87d78f94d2937e2580cce47226d17823c0430fbcad09596537efcf.txt) (SHA-256 `61d383b05b87d78f94d2937e2580cce47226d17823c0430fbcad09596537efcf`; 1097 bytes).
- `crc32fast 1.5.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/crc32fast/1.5.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08.txt) (SHA-256 `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08`; 11358 bytes).

### rust-ctrlc

Canonical upstream: <https://github.com/Detegr/rust-ctrlc>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `ctrlc` | `3.5.2` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e0b1fab2ae45819af2d0731d60f2afe17227ebb1a1538a236da84c93e9a60162` | `MIT/Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |

License evidence:

- `ctrlc 3.5.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/ctrlc/3.5.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `ctrlc 3.5.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/ctrlc/3.5.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/3481c338b8e2760b5a58e129339501c01e640f7597767f91d1a84e25e68fbdb4.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/3481c338b8e2760b5a58e129339501c01e640f7597767f91d1a84e25e68fbdb4.txt) (SHA-256 `3481c338b8e2760b5a58e129339501c01e640f7597767f91d1a84e25e68fbdb4`; 10836 bytes).

### rust-errno

Canonical upstream: <https://github.com/lambda-fairy/rust-errno>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `errno` | `0.3.14` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `errno 0.3.14`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/errno/0.3.14/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/8764a597675778ddfd4e25f81b08a05dbcf089ac05662df7613fe67f150e3aa2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/8764a597675778ddfd4e25f81b08a05dbcf089ac05662df7613fe67f150e3aa2.txt) (SHA-256 `8764a597675778ddfd4e25f81b08a05dbcf089ac05662df7613fe67f150e3aa2`; 1054 bytes).
- `errno 0.3.14`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/errno/0.3.14/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### rust-fnv

Canonical upstream: <https://github.com/servo/rust-fnv>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `fnv` | `1.0.7` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `3f9eec918d3f24069decb9af1554cad7c880e2da24a9afd88aca000531ab82c1` | `Apache-2.0 / MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `fnv 1.0.7`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/fnv/1.0.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/65fdb6c76cd61612070c066eec9ecdb30ee74fb27859d0d9af58b9f499fd0c3e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/65fdb6c76cd61612070c066eec9ecdb30ee74fb27859d0d9af58b9f499fd0c3e.txt) (SHA-256 `65fdb6c76cd61612070c066eec9ecdb30ee74fb27859d0d9af58b9f499fd0c3e`; 1056 bytes).
- `fnv 1.0.7`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/fnv/1.0.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### rust-phf

Canonical upstream: <https://github.com/rust-phf/rust-phf>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `phf` | `0.11.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `1fd6780a80ae0c52cc120a26a1a42c1ae51b247a253e4e06113d23d2c2edd078` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `phf_generator` | `0.11.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `3c80231409c20246a13fddb31776fb942c38553c51e871f8cbd687a4cfb5843d` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `phf_macros` | `0.11.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `f84ac04429c13a7ff43785d75ad27569f2951ce0ffd30a3321230db2fc727216` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `phf_shared` | `0.11.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `67eabc2ef2a60eb7faa00097bd1ffdb5bd28e62bf39990626a582201b7a754e5` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `phf 0.11.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/phf/0.11.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38.txt) (SHA-256 `0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38`; 1099 bytes).
- `phf_generator 0.11.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/phf_generator/0.11.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38.txt) (SHA-256 `0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38`; 1099 bytes).
- `phf_macros 0.11.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/phf_macros/0.11.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38.txt) (SHA-256 `0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38`; 1099 bytes).
- `phf_shared 0.11.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/phf_shared/0.11.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38.txt) (SHA-256 `0ab4d106b6faac07fb6a051815fd1b4d862d730895e2d7d7358c2f13565e7a38`; 1099 bytes).

### rust-shlex

Canonical upstream: <https://github.com/comex/rust-shlex>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `shlex` | `2.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `shlex 2.0.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/shlex/2.0.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/4455bf75a91154108304cb283e0fea9948c14f13e20d60887cf2552449dea3b1.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/4455bf75a91154108304cb283e0fea9948c14f13e20d60887cf2552449dea3b1.txt) (SHA-256 `4455bf75a91154108304cb283e0fea9948c14f13e20d60887cf2552449dea3b1`; 1092 bytes).
- `shlex 2.0.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/shlex/2.0.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/553fffcd9b1cb158bc3e9edc35da85ca5c3b3d7d2e61c883ebcfa8a65814b583.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/553fffcd9b1cb158bc3e9edc35da85ca5c3b3d7d2e61c883ebcfa8a65814b583.txt) (SHA-256 `553fffcd9b1cb158bc3e9edc35da85ca5c3b3d7d2e61c883ebcfa8a65814b583`; 566 bytes).

### rust-siphash

Canonical upstream: <https://github.com/jedisct1/rust-siphash>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `siphasher` | `1.0.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8ee5873ec9cce0195efcb7a4e9507a04cd49aec9c83d0389df45b1ef7ba2e649` | `MIT/Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `siphasher 1.0.3`: crate archive member [`COPYING`](https://crates.io/api/v1/crates/siphasher/1.0.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c962ee4d1d05ddc138b202b2540219ebc57893fcf97b364852094a9a94ce1365.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c962ee4d1d05ddc138b202b2540219ebc57893fcf97b364852094a9a94ce1365.txt) (SHA-256 `c962ee4d1d05ddc138b202b2540219ebc57893fcf97b364852094a9a94ce1365`; 281 bytes).

### rust-smallvec

Canonical upstream: <https://github.com/servo/rust-smallvec>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `smallvec` | `1.15.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `smallvec 1.15.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/smallvec/1.15.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0b28172679e0009b655da42797c03fd163a3379d5cfa67ba1f1655e974a2a1a9.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0b28172679e0009b655da42797c03fd163a3379d5cfa67ba1f1655e974a2a1a9.txt) (SHA-256 `0b28172679e0009b655da42797c03fd163a3379d5cfa67ba1f1655e974a2a1a9`; 1072 bytes).
- `smallvec 1.15.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/smallvec/1.15.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### rust-url

Canonical upstream: <https://github.com/servo/rust-url>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `percent-encoding` | `2.3.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9b4f627cb1b25917193a259e49bdad08f671f8d9708acfd5fe0a8c1455d87220` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `percent-encoding 2.3.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/percent-encoding/2.3.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `percent-encoding 2.3.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/percent-encoding/2.3.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b38f11f6096706e6de553dabe2a7ed142d59b6fa8c97e290c67496154745cdd5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b38f11f6096706e6de553dabe2a7ed142d59b6fa8c97e290c67496154745cdd5.txt) (SHA-256 `b38f11f6096706e6de553dabe2a7ed142d59b6fa8c97e290c67496154745cdd5`; 1072 bytes).

### rustc-demangle

Canonical upstream: <https://github.com/rust-lang/rustc-demangle>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rustc-demangle` | `0.1.28` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `b74b56ffa8bb2830709a538c2cbcae9aa062db0d2a42563bfb09bdaae44020eb` | `MIT/Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `rustc-demangle 0.1.28`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/rustc-demangle/0.1.28/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt) (SHA-256 `378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397`; 1057 bytes).
- `rustc-demangle 0.1.28`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/rustc-demangle/0.1.28/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### rustc-hash

Canonical upstream: <https://github.com/rust-lang/rustc-hash>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rustc-hash` | `2.1.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6b1e7f9a428571be2dc5bc0505c13fb6bf936822b894ec87abf8a08a4e51742d` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `rustc-hash 2.1.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/rustc-hash/2.1.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/30fefc3a7d6a0041541858293bcbea2dde4caa4c0a5802f996a7f7e8c0085652.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/30fefc3a7d6a0041541858293bcbea2dde4caa4c0a5802f996a7f7e8c0085652.txt) (SHA-256 `30fefc3a7d6a0041541858293bcbea2dde4caa4c0a5802f996a7f7e8c0085652`; 1022 bytes).
- `rustc-hash 2.1.3`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/rustc-hash/2.1.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/95bd3988beee069fa2848f648dab43cc6e0b2add2ad6bcb17360caf749802bcc.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/95bd3988beee069fa2848f648dab43cc6e0b2add2ad6bcb17360caf749802bcc.txt) (SHA-256 `95bd3988beee069fa2848f648dab43cc6e0b2add2ad6bcb17360caf749802bcc`; 9722 bytes).

### rustix

Canonical upstream: <https://github.com/bytecodealliance/rustix>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rustix` | `1.1.4` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `rustix 1.1.4`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/rustix/1.1.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `rustix 1.1.4`: crate archive member [`LICENSE-Apache-2.0_WITH_LLVM-exception`](https://crates.io/api/v1/crates/rustix/1.1.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `rustix 1.1.4`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/rustix/1.1.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### rustls

Canonical upstream: <https://github.com/rustls/rustls>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rustls` | `0.23.41` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6b92b125634d9b795e7beca796cc790df15a7fb38323bf3196fda83292d06b1f` | `Apache-2.0 OR ISC OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `rustls 0.23.41`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/rustls/0.23.41/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/709e3175b4212f7b13aa93971c9f62ff8c69ec45ad8c6532a7e0c41d7a7d6f8c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/709e3175b4212f7b13aa93971c9f62ff8c69ec45ad8c6532a7e0c41d7a7d6f8c.txt) (SHA-256 `709e3175b4212f7b13aa93971c9f62ff8c69ec45ad8c6532a7e0c41d7a7d6f8c`; 1082 bytes).
- `rustls 0.23.41`: crate archive member [`LICENSE-ISC`](https://crates.io/api/v1/crates/rustls/0.23.41/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7cfafc877eccc46c0e346ccbaa5c51bb6b894d2b818e617d970211e232785ad4.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7cfafc877eccc46c0e346ccbaa5c51bb6b894d2b818e617d970211e232785ad4.txt) (SHA-256 `7cfafc877eccc46c0e346ccbaa5c51bb6b894d2b818e617d970211e232785ad4`; 775 bytes).
- `rustls 0.23.41`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/rustls/0.23.41/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### semver

Canonical upstream: <https://github.com/dtolnay/semver>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `semver` | `1.0.28` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `semver 1.0.28`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/semver/1.0.28/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `semver 1.0.28`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/semver/1.0.28/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### serde

Canonical upstream: <https://github.com/serde-rs/serde>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `serde` | `1.0.228` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `serde_core` | `1.0.228` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `41d385c7d4ca58e59fc732af25c3983b67ac852c1a25000afe1175de458b67ad` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `serde_derive` | `1.0.228` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `d540f220d3187173da220f885ab66608367b6574e925011a9353e4badda91d79` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `serde 1.0.228`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/serde/1.0.228/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `serde_core 1.0.228`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/serde_core/1.0.228/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `serde_derive 1.0.228`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/serde_derive/1.0.228/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `serde 1.0.228`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/serde/1.0.228/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `serde_core 1.0.228`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/serde_core/1.0.228/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `serde_derive 1.0.228`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/serde_derive/1.0.228/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### slab

Canonical upstream: <https://github.com/tokio-rs/slab>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `slab` | `0.4.12` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `0c790de23124f9ab44544d7ac05d60440adc586479ce501c1d6d7da3cd8c9cf5` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `slab 0.4.12`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/slab/0.4.12/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/8ce0830173fdac609dfb4ea603fdc002c2f4af0dc9b1a005653f5da9cf534b18.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/8ce0830173fdac609dfb4ea603fdc002c2f4af0dc9b1a005653f5da9cf534b18.txt) (SHA-256 `8ce0830173fdac609dfb4ea603fdc002c2f4af0dc9b1a005653f5da9cf534b18`; 1055 bytes).

### socket2

Canonical upstream: <https://github.com/rust-lang/socket2>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `socket2` | `0.6.5` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `socket2 0.6.5`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/socket2/0.6.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397.txt) (SHA-256 `378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397`; 1057 bytes).
- `socket2 0.6.5`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/socket2/0.6.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### stable_deref_trait

Canonical upstream: <https://github.com/storyyeller/stable_deref_trait>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `stable_deref_trait` | `1.2.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6ce2be8dc25455e1f91df71bfa12ad37d7af1092ae736f3a6cd0e37bc7810596` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `stable_deref_trait 1.2.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/stable_deref_trait/1.2.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/5e05b024f653a5ce199e77cbbbd42fb5553562ec714b819421ed0c3e552a75d7.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/5e05b024f653a5ce199e77cbbbd42fb5553562ec714b819421ed0c3e552a75d7.txt) (SHA-256 `5e05b024f653a5ce199e77cbbbd42fb5553562ec714b819421ed0c3e552a75d7`; 1056 bytes).
- `stable_deref_trait 1.2.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/stable_deref_trait/1.2.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### stream-ciphers

Canonical upstream: <https://github.com/RustCrypto/stream-ciphers>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `chacha20` | `0.10.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `d524456ba66e72eb8b115ff89e01e497f8e6d11d78b70b1aa13c0fbd97540a81` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `chacha20 0.10.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/chacha20/0.10.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `chacha20 0.10.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/chacha20/0.10.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b8c6939380a400f53e11923d50fcc4dd2fa1ba8339fd9d04cda38a0251b6c9b0.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b8c6939380a400f53e11923d50fcc4dd2fa1ba8339fd9d04cda38a0251b6c9b0.txt) (SHA-256 `b8c6939380a400f53e11923d50fcc4dd2fa1ba8339fd9d04cda38a0251b6c9b0`; 1082 bytes).

### subtle

Canonical upstream: <https://github.com/dalek-cryptography/subtle>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `subtle` | `2.6.1` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292` | `BSD-3-Clause` | `BSD-3-Clause` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `subtle 2.6.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/subtle/2.6.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/d1fc1bc0d155df60b2e7705b6b2ae02a05c96f948e1cec6e2fb86360b09f346b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/d1fc1bc0d155df60b2e7705b6b2ae02a05c96f948e1cec6e2fb86360b09f346b.txt) (SHA-256 `d1fc1bc0d155df60b2e7705b6b2ae02a05c96f948e1cec6e2fb86360b09f346b`; 1582 bytes).

### syn

Canonical upstream: <https://github.com/dtolnay/syn>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `syn` | `2.0.119` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `syn` | `3.0.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `53e9bae58849f64dfa4f5d5ae372c8341f7305f82a3868709269343628b659a3` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `syn 2.0.119`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/syn/2.0.119/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `syn 3.0.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/syn/3.0.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `syn 2.0.119`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/syn/2.0.119/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `syn 3.0.3`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/syn/3.0.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### sync_wrapper

Canonical upstream: <https://github.com/Actyx/sync_wrapper>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `sync_wrapper` | `1.0.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `0bf256ce5efdfa370213c1dabab5935a12e49f2c58d15e9eac2870d3b4f27263` | `Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `sync_wrapper 1.0.2`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/sync_wrapper/1.0.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594.txt) (SHA-256 `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594`; 10174 bytes).

### target-lexicon

Canonical upstream: <https://github.com/bytecodealliance/target-lexicon>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `target-lexicon` | `0.13.5` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `adb6935a6f5c20170eeceb1a3835a49e12e19d792f6dd344ccc76a985ca5a6ca` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `target-lexicon 0.13.5`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/target-lexicon/0.13.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).

### termcolor

Canonical upstream: <https://github.com/BurntSushi/termcolor>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `termcolor` | `1.4.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `06794f8f6c5c898b3275aebefa6b8a1cb24cd2c6c79397ab15774837a0bc5755` | `Unlicense OR MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `termcolor 1.4.1`: crate archive member [`COPYING`](https://crates.io/api/v1/crates/termcolor/1.4.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f.txt) (SHA-256 `01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f`; 126 bytes).
- `termcolor 1.4.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/termcolor/1.4.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0f96a83840e146e43c0ec96a22ec1f392e0680e6c1226e6f3ba87e0740af850f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0f96a83840e146e43c0ec96a22ec1f392e0680e6c1226e6f3ba87e0740af850f.txt) (SHA-256 `0f96a83840e146e43c0ec96a22ec1f392e0680e6c1226e6f3ba87e0740af850f`; 1081 bytes).
- `termcolor 1.4.1`: crate archive member [`UNLICENSE`](https://crates.io/api/v1/crates/termcolor/1.4.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c.txt) (SHA-256 `7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c`; 1211 bytes).

### thiserror

Canonical upstream: <https://github.com/dtolnay/thiserror>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `thiserror` | `2.0.18` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `4288b5bcbc7920c07a1149a35cf9590a2aa808e0bc1eafaade0b80947865fbc4` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `thiserror-impl` | `2.0.18` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ebc4ee7f67670e9b64d05fa4253e753e016c6c95ff35b89b7941d6b856dec1d5` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `thiserror 2.0.18`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/thiserror/2.0.18/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `thiserror-impl 2.0.18`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/thiserror-impl/2.0.18/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `thiserror 2.0.18`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/thiserror/2.0.18/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `thiserror-impl 2.0.18`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/thiserror-impl/2.0.18/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).

### tokio

Canonical upstream: <https://github.com/tokio-rs/tokio>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tokio` | `1.52.3` | direct runtime; direct development; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8fc7f01b389ac15039e4dc9531aa973a135d7a4135281b12d7c1bc79fd57fffe` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `tokio-macros` | `2.7.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `78773a2a397f451582ce068015985c33193cf6dea8b74d2a639fe457b2f07b0e` | `MIT` | `MIT` | declared metadata and dependency policy | `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `tokio-macros 2.7.2`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/tokio-macros/2.7.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/0b83dc40cba89b9922bb84b0a9c7d2768ce37c1d7e138b7424fd4549915778c9.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/0b83dc40cba89b9922bb84b0a9c7d2768ce37c1d7e138b7424fd4549915778c9.txt) (SHA-256 `0b83dc40cba89b9922bb84b0a9c7d2768ce37c1d7e138b7424fd4549915778c9`; 1102 bytes).
- `tokio 1.52.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/tokio/1.52.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/253cd04c6714889df2d32f3f64d669179a1c95c76ac43c40882c52eb06bc3552.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/253cd04c6714889df2d32f3f64d669179a1c95c76ac43c40882c52eb06bc3552.txt) (SHA-256 `253cd04c6714889df2d32f3f64d669179a1c95c76ac43c40882c52eb06bc3552`; 1070 bytes).

### tokio-rustls

Canonical upstream: <https://github.com/rustls/tokio-rustls>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tokio-rustls` | `0.26.4` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `1729aa945f29d91ba541258c8df89027d5792d85a8841fb65e8bf0f4ede4ef61` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `tokio-rustls 0.26.4`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/tokio-rustls/0.26.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/cc117d90b498b32b11a886f279b359da16a73c3b01efbb2f5cc004b20262334e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/cc117d90b498b32b11a886f279b359da16a73c3b01efbb2f5cc004b20262334e.txt) (SHA-256 `cc117d90b498b32b11a886f279b359da16a73c3b01efbb2f5cc004b20262334e`; 10832 bytes).
- `tokio-rustls 0.26.4`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/tokio-rustls/0.26.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/e20fa2b8e0a2565f24a792b94b4bf4b6c2b9d36f781d8a9516e218a036e6677a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/e20fa2b8e0a2565f24a792b94b4bf4b6c2b9d36f781d8a9516e218a036e6677a.txt) (SHA-256 `e20fa2b8e0a2565f24a792b94b4bf4b6c2b9d36f781d8a9516e218a036e6677a`; 1056 bytes).

### tower

Canonical upstream: <https://github.com/tower-rs/tower>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tower` | `0.5.3` | direct development; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ebe5ef63511595f1344e2d5cfa636d973292adc0eec1f0ad45fae9f0851ab1d4` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `tower-layer` | `0.3.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `121c2a6cda46980bb0fcd1647ffaf6cd3fc79a013de288782836f6df9c48780e` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `tower-service` | `0.3.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8df9b6e13f2d32c91b9bd719c00d1958837bc7dec474d94952798cc8e69eeec3` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `tower 0.5.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/tower/0.5.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482.txt) (SHA-256 `4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482`; 1062 bytes).
- `tower-layer 0.3.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/tower-layer/0.3.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482.txt) (SHA-256 `4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482`; 1062 bytes).
- `tower-service 0.3.3`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/tower-service/0.3.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482.txt) (SHA-256 `4249c8e6c5ebb85f97c77e6457c6fafc1066406eb8f1ef61e796fbdc5ff18482`; 1062 bytes).

### traits

Canonical upstream: <https://github.com/RustCrypto/traits>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `aead` | `0.6.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `1973cfbc1a2daf9cf550e74e1f088c28e7f7d8c1e1418fb6c9dc5184b7e84c99` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cipher` | `0.5.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e8cf2a2c93cd704877c0858356ed03480ff301ee950b43f1cbe4573b088bfa6c` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `crypto-common` | `0.1.7` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `78c8292055d1c1df0cce5d180393dc8cce0abec0a7102adb6c7b1eef6016d60a` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `crypto-common` | `0.2.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `digest` | `0.10.7` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `digest` | `0.11.3` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `universal-hash` | `0.6.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `f4987bdc12753382e0bec4a65c50738ffaabc998b9cdd1f952fb5f39b0048a96` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `aead 0.6.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/aead/0.6.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/33b32a251d445c5c03a634e64c53314c55540fc367fabdd45d9b6c8f260c028c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/33b32a251d445c5c03a634e64c53314c55540fc367fabdd45d9b6c8f260c028c.txt) (SHA-256 `33b32a251d445c5c03a634e64c53314c55540fc367fabdd45d9b6c8f260c028c`; 1117 bytes).
- `crypto-common 0.1.7`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/crypto-common/0.1.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/3521672491a3479422d5fe1aca6645dd2984090f85da6e5205abfb18fb7a6897.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/3521672491a3479422d5fe1aca6645dd2984090f85da6e5205abfb18fb7a6897.txt) (SHA-256 `3521672491a3479422d5fe1aca6645dd2984090f85da6e5205abfb18fb7a6897`; 1065 bytes).
- `cipher 0.5.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cipher/0.5.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/950d712c518a02fcb7cff96950aee304a1cc5283361712c980ea21e8d6d669a5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/950d712c518a02fcb7cff96950aee304a1cc5283361712c980ea21e8d6d669a5.txt) (SHA-256 `950d712c518a02fcb7cff96950aee304a1cc5283361712c980ea21e8d6d669a5`; 1070 bytes).
- `digest 0.10.7`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/digest/0.10.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba.txt) (SHA-256 `9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba`; 1057 bytes).
- `cipher 0.5.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cipher/0.5.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `crypto-common 0.1.7`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/crypto-common/0.1.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `crypto-common 0.2.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/crypto-common/0.2.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `digest 0.10.7`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/digest/0.10.7/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `digest 0.11.3`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/digest/0.11.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `universal-hash 0.6.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/universal-hash/0.6.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `digest 0.11.3`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/digest/0.11.3/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/af59cea35d7f5e2777a713b8d155d65efa2c339eb43f3c14e868c6ac8506edad.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/af59cea35d7f5e2777a713b8d155d65efa2c339eb43f3c14e868c6ac8506edad.txt) (SHA-256 `af59cea35d7f5e2777a713b8d155d65efa2c339eb43f3c14e868c6ac8506edad`; 1103 bytes).
- `aead 0.6.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/aead/0.6.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b1cf9a3333ca78152b859012cd4a804156e5243e9ca20ad1df7327ba5ea7405c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b1cf9a3333ca78152b859012cd4a804156e5243e9ca20ad1df7327ba5ea7405c.txt) (SHA-256 `b1cf9a3333ca78152b859012cd4a804156e5243e9ca20ad1df7327ba5ea7405c`; 10850 bytes).
- `crypto-common 0.2.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/crypto-common/0.2.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/d2e7ec5355c96eeade56b09187ceb48a6a30299da3ce7531a66d3d11405ab963.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/d2e7ec5355c96eeade56b09187ceb48a6a30299da3ce7531a66d3d11405ab963.txt) (SHA-256 `d2e7ec5355c96eeade56b09187ceb48a6a30299da3ce7531a66d3d11405ab963`; 1070 bytes).
- `universal-hash 0.6.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/universal-hash/0.6.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/efa52eb70a774b62c50cf50f5e57e2625c29d375d09b91132f4f020e47b9944e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/efa52eb70a774b62c50cf50f5e57e2625c29d375d09b91132f4f020e47b9944e.txt) (SHA-256 `efa52eb70a774b62c50cf50f5e57e2625c29d375d09b91132f4f020e47b9944e`; 1070 bytes).

### try-lock

Canonical upstream: <https://github.com/seanmonstar/try-lock>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `try-lock` | `0.2.5` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e421abadd41a4225275504ea4d6566923418b7f05506fbc9c0fe86ba7396114b` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `try-lock 0.2.5`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/try-lock/0.2.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c816a0749cdc6bf062a5111c159723de51b2bfac66a1dac2655abd9e6b1583eb.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c816a0749cdc6bf062a5111c159723de51b2bfac66a1dac2655abd9e6b1583eb.txt) (SHA-256 `c816a0749cdc6bf062a5111c159723de51b2bfac66a1dac2655abd9e6b1583eb`; 1096 bytes).

### typenum

Canonical upstream: <https://github.com/paholg/typenum>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `typenum` | `1.20.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `typenum 1.20.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/typenum/1.20.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/516b24e051bf5630880ebbd55c40a25ce9552ebaf8970a53e8976eb70e522406.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/516b24e051bf5630880ebbd55c40a25ce9552ebaf8970a53e8976eb70e522406.txt) (SHA-256 `516b24e051bf5630880ebbd55c40a25ce9552ebaf8970a53e8976eb70e522406`; 10835 bytes).
- `typenum 1.20.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/typenum/1.20.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a825bd853ab71619a4923d7b4311221427848070ff44d990da39b0b274c1683f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a825bd853ab71619a4923d7b4311221427848070ff44d990da39b0b274c1683f.txt) (SHA-256 `a825bd853ab71619a4923d7b4311221427848070ff44d990da39b0b274c1683f`; 1083 bytes).
- `typenum 1.20.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/typenum/1.20.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/db11fec9946737df39ca3898d9cd8c10ec6f6c3a884a6802b0ad0b81b4e8f23a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/db11fec9946737df39ca3898d9cd8c10ec6f6c3a884a6802b0ad0b81b4e8f23a.txt) (SHA-256 `db11fec9946737df39ca3898d9cd8c10ec6f6c3a884a6802b0ad0b81b4e8f23a`; 17 bytes).

### unicode-ident

Canonical upstream: <https://github.com/dtolnay/unicode-ident>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `unicode-ident` | `1.0.24` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75` | `(MIT OR Apache-2.0) AND Unicode-3.0` | `Apache-2.0 AND Unicode-3.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `unicode-ident 1.0.24`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/unicode-ident/1.0.24/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `unicode-ident 1.0.24`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/unicode-ident/1.0.24/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a.txt) (SHA-256 `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`; 9723 bytes).
- `unicode-ident 1.0.24`: crate archive member [`LICENSE-UNICODE`](https://crates.io/api/v1/crates/unicode-ident/1.0.24/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/f7db81051789b729fea528a63ec4c938fdcb93d9d61d97dc8cc2e9df6d47f2a1.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/f7db81051789b729fea528a63ec4c938fdcb93d9d61d97dc8cc2e9df6d47f2a1.txt) (SHA-256 `f7db81051789b729fea528a63ec4c938fdcb93d9d61d97dc8cc2e9df6d47f2a1`; 1995 bytes).

### universal-hashes

Canonical upstream: <https://github.com/RustCrypto/universal-hashes>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `poly1305` | `0.9.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `6e2d0073b297041425c7c3df6eb4792d598a15323fe63346852b092eca02904c` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `poly1305 0.9.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/poly1305/0.9.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `poly1305 0.9.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/poly1305/0.9.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b67acfaaf787b346e1d3bf7654b4fabfd20360fdeb4351cc5e9d624147824527.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b67acfaaf787b346e1d3bf7654b4fabfd20360fdeb4351cc5e9d624147824527.txt) (SHA-256 `b67acfaaf787b346e1d3bf7654b4fabfd20360fdeb4351cc5e9d624147824527`; 1082 bytes).

### untrusted

Canonical upstream: <https://github.com/briansmith/untrusted>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `untrusted` | `0.9.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1` | `ISC` | `ISC` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `untrusted 0.9.0`: crate archive member [`LICENSE.txt`](https://crates.io/api/v1/crates/untrusted/0.9.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7abd9b6960dcf7d4d0a48606a5b71bfe37d472db68d70637f3a58a56785f1621.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7abd9b6960dcf7d4d0a48606a5b71bfe37d472db68d70637f3a58a56785f1621.txt) (SHA-256 `7abd9b6960dcf7d4d0a48606a5b71bfe37d472db68d70637f3a58a56785f1621`; 769 bytes).

### utils

Canonical upstream: <https://github.com/RustCrypto/utils>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `block-buffer` | `0.10.4` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `3078c7629b62d3f0439517fa394996acacc5cbc91c5a20d8c658e77abd503a71` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `block-buffer` | `0.12.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cmov` | `0.5.4` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `0c9ea0ac24bc397ab3c98583a3c9ba74fa56b09a4449bbe172b9b1ddb016027a` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cpufeatures` | `0.2.17` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cpufeatures` | `0.3.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `ctutils` | `0.4.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `7d5515a3834141de9eafb9717ad39eea8247b5674e6066c404e8c4b365d2a29e` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `inout` | `0.2.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `4250ce6452e92010fdf7268ccc5d14faa80bb12fc741938534c58f16804e03c7` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `zeroize` | `1.9.0` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` | `Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `cmov 0.5.4`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cmov/0.5.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/70c9d40f1f9545c3f133b8a67206e89da850f6468eed072281bb3701514114a9.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/70c9d40f1f9545c3f133b8a67206e89da850f6468eed072281bb3701514114a9.txt) (SHA-256 `70c9d40f1f9545c3f133b8a67206e89da850f6468eed072281bb3701514114a9`; 1082 bytes).
- `zeroize 1.9.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/zeroize/1.9.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/8c7516d4b27b1e495be5e38b612298b63de48d05f49cdac94f70f3cd70f8864b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/8c7516d4b27b1e495be5e38b612298b63de48d05f49cdac94f70f3cd70f8864b.txt) (SHA-256 `8c7516d4b27b1e495be5e38b612298b63de48d05f49cdac94f70f3cd70f8864b`; 1082 bytes).
- `ctutils 0.4.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/ctutils/0.4.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/91585c36e4fb9ab4ca0d3dfac5d66d3c0c62cc51f640a0e1196542daf2267eae.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/91585c36e4fb9ab4ca0d3dfac5d66d3c0c62cc51f640a0e1196542daf2267eae.txt) (SHA-256 `91585c36e4fb9ab4ca0d3dfac5d66d3c0c62cc51f640a0e1196542daf2267eae`; 1082 bytes).
- `block-buffer 0.12.1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/block-buffer/0.12.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/98181e7249d0c01737645ec982499ce99a0f07eb8f7d625b8840d799d10dbc01.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/98181e7249d0c01737645ec982499ce99a0f07eb8f7d625b8840d799d10dbc01.txt) (SHA-256 `98181e7249d0c01737645ec982499ce99a0f07eb8f7d625b8840d799d10dbc01`; 1082 bytes).
- `inout 0.2.2`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/inout/0.2.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a07fcacc3c60de4dc0fab10ac9d6aaba7379974e28451c99da7f7df09c25b28c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a07fcacc3c60de4dc0fab10ac9d6aaba7379974e28451c99da7f7df09c25b28c.txt) (SHA-256 `a07fcacc3c60de4dc0fab10ac9d6aaba7379974e28451c99da7f7df09c25b28c`; 1115 bytes).
- `block-buffer 0.10.4`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/block-buffer/0.10.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `block-buffer 0.12.1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/block-buffer/0.12.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `cpufeatures 0.2.17`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cpufeatures/0.2.17/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `cpufeatures 0.3.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cpufeatures/0.3.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `inout 0.2.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/inout/0.2.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5.txt) (SHA-256 `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`; 10849 bytes).
- `cpufeatures 0.2.17`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cpufeatures/0.2.17/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/ae9baa7beea910273c2f384c2a6b721fb7bd02bda3436074a1072e4ee689f985.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/ae9baa7beea910273c2f384c2a6b721fb7bd02bda3436074a1072e4ee689f985.txt) (SHA-256 `ae9baa7beea910273c2f384c2a6b721fb7bd02bda3436074a1072e4ee689f985`; 1082 bytes).
- `cpufeatures 0.3.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/cpufeatures/0.3.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/ae9baa7beea910273c2f384c2a6b721fb7bd02bda3436074a1072e4ee689f985.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/ae9baa7beea910273c2f384c2a6b721fb7bd02bda3436074a1072e4ee689f985.txt) (SHA-256 `ae9baa7beea910273c2f384c2a6b721fb7bd02bda3436074a1072e4ee689f985`; 1082 bytes).
- `cmov 0.5.4`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/cmov/0.5.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt) (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`; 11358 bytes).
- `ctutils 0.4.2`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/ctutils/0.4.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt) (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`; 11358 bytes).
- `zeroize 1.9.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/zeroize/1.9.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt) (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`; 11358 bytes).
- `block-buffer 0.10.4`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/block-buffer/0.10.4/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/d5c22aa3118d240e877ad41c5d9fa232f9c77d757d4aac0c2f943afc0a95e0ef.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/d5c22aa3118d240e877ad41c5d9fa232f9c77d757d4aac0c2f943afc0a95e0ef.txt) (SHA-256 `d5c22aa3118d240e877ad41c5d9fa232f9c77d757d4aac0c2f943afc0a95e0ef`; 1082 bytes).

### version_check

Canonical upstream: <https://github.com/SergioBenitez/version_check>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `version_check` | `0.9.5` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `0b928f33d975fc6ad9f86c8f283853ad26bdd5b10b7f1542aa2fa15e2289105a` | `MIT/Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `version_check 0.9.5`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/version_check/0.9.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).
- `version_check 0.9.5`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/version_check/0.9.5/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/b7e650f3fce5c53249d1cdc608b54df156a97edd636cf9d23498d0cfe7aec63e.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/b7e650f3fce5c53249d1cdc608b54df156a97edd636cf9d23498d0cfe7aec63e.txt) (SHA-256 `b7e650f3fce5c53249d1cdc608b54df156a97edd636cf9d23498d0cfe7aec63e`; 1085 bytes).

### want

Canonical upstream: <https://github.com/seanmonstar/want>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `want` | `0.3.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `bfa7760aed19e106de2c7c0b581b509f2f25d3dacaf737cb82ac61bc6d760b0e` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `want 0.3.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/want/0.3.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a65f5d0a945d267751344c95665945b90c030ea107faf5c85d518929886187da.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a65f5d0a945d267751344c95665945b90c030ea107faf5c85d518929886187da.txt) (SHA-256 `a65f5d0a945d267751344c95665945b90c030ea107faf5c85d518929886187da`; 1063 bytes).

### wasi

Canonical upstream: <https://github.com/bytecodealliance/wasi>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `wasi` | `0.11.1+wasi-snapshot-preview1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ccf3ec651a847eb01de73ccad15eb7d99f80485de043efb2f370cd654f4ea44b` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `wasi 0.11.1+wasi-snapshot-preview1`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/wasi/0.11.1+wasi-snapshot-preview1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `wasi 0.11.1+wasi-snapshot-preview1`: crate archive member [`LICENSE-Apache-2.0_WITH_LLVM-exception`](https://crates.io/api/v1/crates/wasi/0.11.1+wasi-snapshot-preview1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasi 0.11.1+wasi-snapshot-preview1`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/wasi/0.11.1+wasi-snapshot-preview1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### wasm-encoder

Canonical upstream: <https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wasm-encoder>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `wasm-encoder` | `0.251.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `5a879a421bd17c528b74721b2abf4c62e8f1d1889c2ba8c3c50d02deaf2ce395` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `wasm-encoder 0.251.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/wasm-encoder/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `wasm-encoder 0.251.0`: crate archive member [`LICENSE-Apache-2.0_WITH_LLVM-exception`](https://crates.io/api/v1/crates/wasm-encoder/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasm-encoder 0.251.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/wasm-encoder/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### wasmparser

Canonical upstream: <https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wasmparser>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `wasmparser` | `0.251.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `437970b35b1a85cfde9c74b2398352d8d653f3bd8e3a3db0c063ea8f5b4b36ff` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `wasmparser 0.251.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/wasmparser/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `wasmparser 0.251.0`: crate archive member [`LICENSE-Apache-2.0_WITH_LLVM-exception`](https://crates.io/api/v1/crates/wasmparser/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmparser 0.251.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/wasmparser/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### wasmprinter

Canonical upstream: <https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wasmprinter>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `wasmprinter` | `0.251.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8798c1a699bd25648b6708eefe94d97c6f9891febb94b42cca1f7a4b086ea64e` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `wasmprinter 0.251.0`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/wasmprinter/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).
- `wasmprinter 0.251.0`: crate archive member [`LICENSE-Apache-2.0_WITH_LLVM-exception`](https://crates.io/api/v1/crates/wasmprinter/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmprinter 0.251.0`: crate archive member [`LICENSE-APACHE`](https://crates.io/api/v1/crates/wasmprinter/0.251.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.txt) (SHA-256 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`; 10847 bytes).

### Wasmtime

Canonical upstream: <https://github.com/bytecodealliance/wasmtime>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cranelift-assembler-x64` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e06aeba2c965fc446d13c56a6ccb2631b78445d7544543dd9a25289977630914` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-assembler-x64-meta` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ee2d2dde4ec1352715595b5cfa6fe2e5b8ebb9da3457b3ee8db0aa2808c069aa` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-bforest` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `03b4982ef9fa54ec9eee841e891e7ddc5434be1250e88de31572e000c888f30b` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-bitset` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `529143118c4eeb58c39ecb02319557d512be6c61348486422974ab8e3906b8a8` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-codegen` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `b7780677247ad3577e3a6a3ebf43f39b325a11d6393db72b2c9968a910d4d13d` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-codegen-meta` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ac9645250416cbf92454fe61160e17e026e0ce405906a54500b114f923ddffc9` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-codegen-shared` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `20ee8d222ff0fd3681791979afbf88586ac9f49010d3db96b3cbe4c96759aee3` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-control` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `591abe6f5312bd2c4220f1b3bead56c2ad00257c52668015ba013b85dcf2a17a` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-entity` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `a5300c49cf940526fe771517b3b3eabd5d0ff164ee61698579cf403fe8d3af3c` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-frontend` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `da4adbf760207fdbbe130f1191cce01cdef66831a9f648b1f39ff2800d126d45` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-isle` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8315b21ff018226a42a60a4702c2dd75f6447cac26e9bca622e14c22088c2ff5` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-native` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `d506ef23a60715bde451b06620b14402166ded3b648454fccbf04f3e46a4aa70` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `cranelift-srcgen` | `0.133.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `48ed47e602652e3410f9387fc0db70fefadcee4d78a78881421aabcab4e26b89` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `pulley-interpreter` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `38b92604caae1a1899b6a5b54967289dd538177c626004c91accf9d0ec7e4a12` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `pulley-macros` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `5a7ac85c0bb3fb351f10d531230aaa5e366b46d7c4e5328e5f02801d6dac1165` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `c4213d2f019a5e44aa8a61d8826dd33a505bff79f749b14a8bafd67321cb9351` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-environ` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `d45863de41977ec6453e859cf843d456fa3fcb45a659b66d16e794f90ec4f5b7` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-internal-component-util` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `819ad5abd5822a22dbf4014475cdfd1fe790707761cd732d74aaa3ba4d5ba489` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-internal-core` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `3fc28372e36eaf8cf70faa83b5779137f7e99c8d18569a125d1580e735cc9e4d` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-internal-cranelift` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `a433efc6e35112a5457e1dc8bc4d8d39820ac7722267e89bc04e5df641f32124` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-internal-fiber` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `18a1d3a39d0d210f6b8574ee96a4315e0a14c67f3a1fc3cd5372cb10d2fb4422` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-internal-jit-debug` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9f667288cb4dfa68a4639ffac4d5628535dda64ebdc2b990526efb12b30ba803` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-internal-jit-icache-coherence` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `eba651d44ab0faad4c58106b3adb45068189fb65ef50f0c404b6d9e3bf81a357` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-internal-unwinder` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `2ecc52563b0558af2a7487eb710de07cc4532564b55528876129238e83118cb1` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |
| `wasmtime-internal-versioned-export-macros` | `46.0.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `e747f4a074699ba1b4e4d841fb263f9b7df5bd1555181c4752bf5990d21ba676` | `Apache-2.0 WITH LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `cranelift-assembler-x64 0.133.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-assembler-x64-meta 0.133.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-bforest 0.133.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cranelift-bforest/0.133.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-bitset 0.133.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-codegen 0.133.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cranelift-codegen/0.133.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-codegen-meta 0.133.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cranelift-codegen-meta/0.133.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-codegen-shared 0.133.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cranelift-codegen-shared/0.133.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-control 0.133.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cranelift-control/0.133.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-entity 0.133.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cranelift-entity/0.133.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-frontend 0.133.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cranelift-frontend/0.133.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-isle 0.133.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-native 0.133.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/cranelift-native/0.133.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `cranelift-srcgen 0.133.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `pulley-interpreter 46.0.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `pulley-macros 46.0.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime 46.0.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/wasmtime/46.0.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-environ 46.0.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/wasmtime-environ/46.0.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-internal-component-util 46.0.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-internal-core 46.0.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-internal-cranelift 46.0.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/wasmtime-internal-cranelift/46.0.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-internal-fiber 46.0.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/wasmtime-internal-fiber/46.0.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-internal-jit-debug 46.0.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-internal-jit-icache-coherence 46.0.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-internal-unwinder 46.0.1`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/wasmtime-internal-unwinder/46.0.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).
- `wasmtime-internal-versioned-export-macros 46.0.1`: immutable upstream file [`LICENSE`](https://raw.githubusercontent.com/bytecodealliance/wasmtime/823d1b8f251494a06288194d0df746191f535ff7/LICENSE) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5.txt) (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`; 12243 bytes).

### webpki

Canonical upstream: <https://github.com/rustls/webpki>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `rustls-webpki` | `0.103.13` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `61c429a8649f110dddef65e2a5ad240f747e85f7758a6bccc7e5777bd33f756e` | `ISC` | `ISC` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `rustls-webpki 0.103.13`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/rustls-webpki/0.103.13/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/5b698ca13897be3afdb7174256fa1574f8c6892b8bea1a66dd6469d3fe27885a.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/5b698ca13897be3afdb7174256fa1574f8c6892b8bea1a66dd6469d3fe27885a.txt) (SHA-256 `5b698ca13897be3afdb7174256fa1574f8c6892b8bea1a66dd6469d3fe27885a`; 916 bytes).

### webpki-roots

Canonical upstream: <https://github.com/rustls/webpki-roots>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `webpki-roots` | `1.0.8` | direct runtime; transitive | `registry+https://github.com/rust-lang/crates.io-index` | `bf85cb06032201fa7c6f829d7db5a7e5aa45bcc0655327713065f6f0576731bf` | `CDLA-Permissive-2.0` | `CDLA-Permissive-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `webpki-roots 1.0.8`: crate archive member [`LICENSE`](https://crates.io/api/v1/crates/webpki-roots/1.0.8/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8.txt) (SHA-256 `e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8`; 2371 bytes).

### winapi-util

Canonical upstream: <https://github.com/BurntSushi/winapi-util>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `winapi-util` | `0.1.11` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `c2a7b1c03c876122aa43f3020e6c3c3ee5c05081c9a00739faf7503aeba10d22` | `Unlicense OR MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `winapi-util 0.1.11`: crate archive member [`COPYING`](https://crates.io/api/v1/crates/winapi-util/0.1.11/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f.txt) (SHA-256 `01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f`; 126 bytes).
- `winapi-util 0.1.11`: crate archive member [`UNLICENSE`](https://crates.io/api/v1/crates/winapi-util/0.1.11/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c.txt) (SHA-256 `7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c`; 1211 bytes).
- `winapi-util 0.1.11`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/winapi-util/0.1.11/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/cb3c929a05e6cbc9de9ab06a4c57eeb60ca8c724bef6c138c87d3a577e27aa14.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/cb3c929a05e6cbc9de9ab06a4c57eeb60ca8c724bef6c138c87d3a577e27aa14.txt) (SHA-256 `cb3c929a05e6cbc9de9ab06a4c57eeb60ca8c724bef6c138c87d3a577e27aa14`; 1081 bytes).

### windows-rs

Canonical upstream: <https://github.com/microsoft/windows-rs>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `windows-link` | `0.2.1` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |
| `windows-sys` | `0.52.0` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `282be5f36a8ce781fad8c8ae18fa3f9beff57ec1b52cb3de0789201425d9a33d` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows-sys` | `0.61.2` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `Cargo.lock`; `bundles/complete/Cargo.lock`; `bundles/edge/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-dispatch/Cargo.lock`; `crates/optional/ariadnion-api-domain/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-audit-domain/Cargo.lock`; `crates/optional/ariadnion-audit-store/Cargo.lock`; `crates/optional/ariadnion-auth-api-key/Cargo.lock`; `crates/optional/ariadnion-auth-password/Cargo.lock`; `crates/optional/ariadnion-auth-session/Cargo.lock`; `crates/optional/ariadnion-cli-user/Cargo.lock`; `crates/optional/ariadnion-compose/Cargo.lock`; `crates/optional/ariadnion-config-domain/Cargo.lock`; `crates/optional/ariadnion-config-runtime/Cargo.lock`; `crates/optional/ariadnion-config-schema/Cargo.lock`; `crates/optional/ariadnion-diagnostics/Cargo.lock`; `crates/optional/ariadnion-invitation/Cargo.lock`; `crates/optional/ariadnion-job-runner/Cargo.lock`; `crates/optional/ariadnion-organization/Cargo.lock`; `crates/optional/ariadnion-principal-binding/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-provider-dispatch/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock`; `crates/optional/ariadnion-provider-mock/Cargo.lock`; `crates/optional/ariadnion-provider-sdk/Cargo.lock`; `crates/optional/ariadnion-rbac/Cargo.lock`; `crates/optional/ariadnion-storage-asset/Cargo.lock`; `crates/optional/ariadnion-storage-backup/Cargo.lock`; `crates/optional/ariadnion-storage-domain/Cargo.lock`; `crates/optional/ariadnion-storage-maintenance/Cargo.lock`; `crates/optional/ariadnion-storage-migration/Cargo.lock`; `crates/optional/ariadnion-storage-outbox/Cargo.lock`; `crates/optional/ariadnion-storage-query/Cargo.lock`; `crates/optional/ariadnion-storage-restore/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock`; `crates/optional/ariadnion-storage-upgrade/Cargo.lock`; `crates/optional/ariadnion-user-domain/Cargo.lock`; `crates/optional/ariadnion-user-service/Cargo.lock` |
| `windows-targets` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `9b724f72796e036ab90c1021d4780d4d3d648aca59e491e6b98e725b84e99973` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows_aarch64_gnullvm` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `32a4622180e7a0ec044bb555404c800bc9fd9ec262ec147edd5989ccd0c02cd3` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows_aarch64_msvc` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `09ec2a7bb152e2252b53fa7803150007879548bc709c039df7627cabbd05d469` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows_i686_gnu` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `8e9b5ad5ab802e97eb8e295ac6720e509ee4c243f69d781394014ebfe8bbfa0b` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows_i686_gnullvm` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `0eee52d38c090b3caa76c563b86c3a4bd71ef1a819287c19d586d7334ae8ed66` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows_i686_msvc` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `240948bc05c5e7c6dabba28bf89d89ffce3e303022809e73deaefe4f6ec56c66` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows_x86_64_gnu` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `147a5c80aabfbf0c7d901cb5895d1de30ef2907eb21fbbab29ca94c5b08b1a78` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows_x86_64_gnullvm` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `24d5b23dc417412679681396f2b49f3de8c1473deb516bd34410872eff51ed0d` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |
| `windows_x86_64_msvc` | `0.52.6` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `589f6da84c646204747d1270a2a5661ea66ed1cced2631d546fdfb155959f9ec` | `MIT OR Apache-2.0` | `Apache-2.0` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-provider-http/Cargo.lock` |

License evidence:

- `windows-link 0.2.1`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows-link/0.2.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows-sys 0.52.0`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows-sys/0.52.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows-sys 0.61.2`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows-sys/0.61.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows-targets 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows-targets/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows_aarch64_gnullvm 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows_aarch64_gnullvm/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows_aarch64_msvc 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows_aarch64_msvc/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows_i686_gnu 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows_i686_gnu/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows_i686_gnullvm 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows_i686_gnullvm/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows_i686_msvc 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows_i686_msvc/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows_x86_64_gnu 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows_x86_64_gnu/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows_x86_64_gnullvm 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows_x86_64_gnullvm/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows_x86_64_msvc 0.52.6`: crate archive member [`license-apache-2.0`](https://crates.io/api/v1/crates/windows_x86_64_msvc/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b.txt) (SHA-256 `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`; 11351 bytes).
- `windows-link 0.2.1`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows-link/0.2.1/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows-sys 0.52.0`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows-sys/0.52.0/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows-sys 0.61.2`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows-sys/0.61.2/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows-targets 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows-targets/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows_aarch64_gnullvm 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows_aarch64_gnullvm/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows_aarch64_msvc 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows_aarch64_msvc/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows_i686_gnu 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows_i686_gnu/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows_i686_gnullvm 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows_i686_gnullvm/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows_i686_msvc 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows_i686_msvc/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows_x86_64_gnu 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows_x86_64_gnu/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows_x86_64_gnullvm 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows_x86_64_gnullvm/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).
- `windows_x86_64_msvc 0.52.6`: crate archive member [`license-mit`](https://crates.io/api/v1/crates/windows_x86_64_msvc/0.52.6/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383.txt) (SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`; 1141 bytes).

### zmij

Canonical upstream: <https://github.com/dtolnay/zmij>

| Package | Version | Roles | Exact source | Cargo checksum | Declared license | Selected license | Selection basis | Lockfiles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `zmij` | `1.0.23` | transitive | `registry+https://github.com/rust-lang/crates.io-index` | `29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b` | `MIT` | `MIT` | declared metadata and dependency policy | `bundles/complete/Cargo.lock`; `bundles/standard/Cargo.lock`; `crates/optional/ariadnion-api-admin/Cargo.lock`; `crates/optional/ariadnion-api-http/Cargo.lock`; `crates/optional/ariadnion-api-stream/Cargo.lock`; `crates/optional/ariadnion-protocol-openai/Cargo.lock`; `crates/optional/ariadnion-storage-rnmdb/Cargo.lock` |

License evidence:

- `zmij 1.0.23`: crate archive member [`LICENSE-MIT`](https://crates.io/api/v1/crates/zmij/1.0.23/download) -> [`AHCL/THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt`](THIRD-PARTY-LICENSES/crates.io/by-sha256/23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3.txt) (SHA-256 `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`; 1023 bytes).

## Integrity rules

- Lockfile and evidence hashes cover exact repository bytes without text normalization.
- Dependency roles are aggregated across all tracked graphs; a package can be both direct and transitive in different graphs.
- Registry evidence is discovered by hashing every extracted package file and matching the retained content-addressed blobs.
- Immutable upstream aliases use full commits, never branches or tags.
- Git dependencies retain their exact Cargo source, resolved commit, package membership, and lockfile occurrences.
